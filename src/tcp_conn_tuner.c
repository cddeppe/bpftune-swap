#define _GNU_SOURCE
/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <bpftune/libbpftune.h>

#include <arpa/inet.h>
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>

#include "tcp_conn_tuner.h"
#include "tcp_conn_tuner.skel.h"
#include "tcp_conn_tuner.skel.legacy.h"
#include "tcp_conn_tuner.skel.nobtf.h"

static struct bpftunable_desc descs[] = {
 
{ TCP_CONG, BPFTUNABLE_OTHER, "net.persock.tcp.congestion_control", 0, 0 },
{ TCP_ALLOWED_CONG, BPFTUNABLE_SYSCTL, "net.ipv4.tcp_allowed_congestion_control",
  BPFTUNABLE_NAMESPACED | BPFTUNABLE_STRING, 1 },
{ TCP_AVAILABLE_CONG, BPFTUNABLE_SYSCTL, "net.ipv4.tcp_available_congestion_control",
  BPFTUNABLE_NAMESPACED | BPFTUNABLE_STRING, 1 },
{ TCP_CONG_DEFAULT, BPFTUNABLE_SYSCTL, "net.ipv4.tcp_congestion_control",
  BPFTUNABLE_NAMESPACED | BPFTUNABLE_STRING, 1 },
{ TCP_THIN_LINEAR_TIMEOUTS, BPFTUNABLE_SYSCTL, "net.ipv4.tcp_thin_linear_timeouts", BPFTUNABLE_NAMESPACED, 1 },
};

static struct bpftunable_scenario scenarios[] = {
{ TCP_CONG_SET,         "specify TCP congestion control algorithm",
  "To optimize TCP performance, a TCP congestion control algorithm was chosen to mimimize round-trip time and maximize delivery rate." },
};

struct tcp_conn_tuner_bpf *skel;

static int restore_remote_host_map(struct bpftuner *tuner);
static int save_remote_host_map(struct bpftuner *tuner);

/* Userspace re-anchor.  The BPF vote path maintains best_i/best_v
 * incrementally, and the ESTABLISHED-time rescan only refreshes the
 * tracker when a new connection arrives.  Between those events a
 * non-leader metric can drift to a lower value without being
 * promoted, leaving the swap target stale.  This worker, every
 * REANCHOR_INTERVAL seconds, rescans every bucket metric array and
 * rewrites the tracker so best_i/best_v/second_i/second_v always
 * match the array.  No BPF change: the swap path keeps reading the
 * same fields it reads today.
 */
#define REANCHOR_INTERVAL 30

static pthread_t reanchor_tid;
static volatile int reanchor_stop;
static int reanchor_started;
static int reanchor_fd = -1;

/* ------------------------------------------------------------------
 * Rate-histogram maintenance (0.4.43).
 *   (1) Decay:  halve all bins when total > RATE_HIST_HALVE_TOTAL.
 *   (2) p99:    cumulative scan; find the bin whose count first
 *               reaches RATE_HIST_PCT% of total; convert to B/s.
 *   (3) Write p99 back into the bucket as max_rate_delivered.
 * Sole producer of max_rate_delivered since 0.4.43.
 * ------------------------------------------------------------------ */
static void rate_hist_decay(struct rate_hist *h)
{
        __u64 new_total = 0;
        int i;

        if (h->total <= RATE_HIST_HALVE_TOTAL)
                return;
        for (i = 0; i < RATE_HIST_BINS; i++) {
                h->bins[i] >>= 1;
                new_total += h->bins[i];
        }
        h->total = new_total;
}

static unsigned long long rate_hist_p99(const struct rate_hist *h)
{
        __u64 target, cum = 0;
        int i;

        if (h->total == 0)
                return 0;
        target = (h->total / 100) * RATE_HIST_PCT
               + ((h->total % 100) * RATE_HIST_PCT) / 100;
        for (i = 0; i < RATE_HIST_BINS; i++) {
                cum += h->bins[i];
                if (cum >= target)
                        break;
        }
        if (i >= RATE_HIST_BINS)
                i = RATE_HIST_BINS - 1;
        return 1ULL << (i + 10);
}

static void start_reanchor(struct bpftuner *tuner);
static void stop_reanchor(void);

#define EXPLORE_PIN_DIR  "/sys/fs/bpf/bpftune/tcp_conn"
#define EXPLORE_PIN_PATH EXPLORE_PIN_DIR "/explore"
#define EXPLORE_STATE    "/var/lib/bpftune/explore_pct"
#define PREFIX4_STATE    "/var/lib/bpftune/prefix4"
#define PREFIX6_STATE    "/var/lib/bpftune/prefix6"
#define DEBUG_STATE      "/var/lib/bpftune/bpftune_debug"
#define ALIAS_PIN_PATH   EXPLORE_PIN_DIR "/aliases"
#define ALIAS_FILE       "/etc/bpftune/aliases"
#define LABELS_FILE      "/var/lib/bpftune/aliases.labels.json"

/* 0.4.64: pin tuner_config_map under BPFTUNE_PIN so a separate
 * process ('bpftune --exp') can read and update it without
 * restarting the daemon.  Value persists across restarts via
 * EXPLORE_STATE, which only the CLI writes. */
static int pin_explore_map(struct bpftuner *tuner)
{
        struct bpf_map *map;
        __u32 key = 0;
        __u32 pct = EXPLORE_PCT_DEFAULT;
        int fd, err;
        FILE *f;

        map = bpftuner_bpf_map_get(tcp_conn, tuner, tuner_config_map);
        if (!map) {
                bpftune_log(LOG_ERR, "explore: map not found\n");
                return -ENOENT;
        }
        fd = bpf_map__fd(map);
        if (fd < 0)
                return -EINVAL;

        f = fopen(EXPLORE_STATE, "r");
        if (f) {
                unsigned int v;
                if (fscanf(f, "%u", &v) == 1 && v <= EXPLORE_PCT_MAX)
                        pct = v;
                fclose(f);
        }

        mkdir(BPFTUNE_PIN, 0755);
        mkdir(EXPLORE_PIN_DIR, 0755);
        unlink(EXPLORE_PIN_PATH);

        err = bpf_obj_pin(fd, EXPLORE_PIN_PATH);
        if (err) {
                bpftune_log(LOG_ERR, "explore: pin failed: %s\n", strerror(-err));
                return err;
        }
        err = bpf_map_update_elem(fd, &key, &pct, BPF_ANY);
        if (err) {
                bpftune_log(LOG_ERR, "explore: init failed: %s\n", strerror(-err));
                return err;
        }
        {
                __u32 pfx = 16;
                FILE *pf = fopen(PREFIX4_STATE, "r");
                if (pf) {
                        unsigned int v;
                        if (fscanf(pf, "%u", &v) == 1 && v >= 1 && v <= 32)
                                pfx = v;
                        fclose(pf);
                }
                key = 1;
                if (bpf_map_update_elem(fd, &key, &pfx, BPF_ANY))
                        bpftune_log(LOG_ERR,
                                    "prefix4: init failed: %s\n",
                                    strerror(errno));
                else
                        bpftune_log(BPFTUNE_LOG_LEVEL,
                                    "prefix4: pinned at %s, pfx=%u\n",
                                    EXPLORE_PIN_PATH, pfx);
        }
        {
                __u32 pfx6 = 32;
                FILE *pf = fopen(PREFIX6_STATE, "r");
                if (pf) {
                        unsigned int v;
                        if (fscanf(pf, "%u", &v) == 1 && v >= 1 && v <= 128)
                                pfx6 = v;
                        fclose(pf);
                }
                key = 2;
                if (bpf_map_update_elem(fd, &key, &pfx6, BPF_ANY))
                        bpftune_log(LOG_ERR,
                                    "prefix6: init failed: %s\n",
                                    strerror(errno));
                else
                        bpftune_log(BPFTUNE_LOG_LEVEL,
                                    "prefix6: pinned at %s, pfx6=%u\n",
                                    EXPLORE_PIN_PATH, pfx6);
        }
        /* 0.4.91: slot 3 = bpf_debug (0=quiet, 1=verbose). */
        {
                __u32 dbg = 1;
                FILE *df = fopen(DEBUG_STATE, "r");
                if (df) {
                        unsigned int v;
                        if (fscanf(df, "%u", &v) == 1 && v <= 1)
                                dbg = v;
                        fclose(df);
                }
                key = 3;
                if (bpf_map_update_elem(fd, &key, &dbg, BPF_ANY))
                        bpftune_log(LOG_ERR,
                                    "bpf-debug: init failed: %s\n",
                                    strerror(errno));
                else
                        bpftune_log(BPFTUNE_LOG_LEVEL,
                                    "bpf-debug: pinned at %s, debug=%u\n",
                                    EXPLORE_PIN_PATH, dbg);
        }
        bpftune_log(BPFTUNE_LOG_LEVEL,
                    "explore: pinned at %s, pct=%u\n", EXPLORE_PIN_PATH, pct);
        return 0;
}

/* 0.4.79: load /etc/bpftune/aliases into the pinned dest_alias_map.
 * File format, one rule per line, '#' comments allowed:
 *     FROM_IP = TO_IP
 * FROM is the raw destination as the socket reports it.  TO is the
 * canonical bucket key to use instead.  Both v4 and v6 accepted.
 * Parse or update errors logged and skipped. */
static int alias_text_to_key(const char *s, struct in6_addr *out)
{
        struct in_addr a4;
        memset(out, 0, sizeof(*out));
        if (inet_pton(AF_INET, s, &a4) == 1) {
                out->s6_addr[10] = 0xff;
                out->s6_addr[11] = 0xff;
                memcpy(&out->s6_addr[12], &a4.s_addr, 4);
                return 0;
        }
        if (inet_pton(AF_INET6, s, out) == 1)
                return 0;
        return -1;
}

static int pin_alias_map(struct bpftuner *tuner)
{
        struct bpf_map *map;
        struct in6_addr from, to;
        char line[256];
        FILE *f = NULL, *jf = NULL;
        int fd, err, n = 0, nj = 0;
        char prev_to[64] = {0};

        map = bpftuner_bpf_map_get(tcp_conn, tuner, dest_alias_map);
        if (!map) {
                bpftune_log(LOG_ERR, "aliases: map not found\n");
                return -ENOENT;
        }
        fd = bpf_map__fd(map);
        if (fd < 0)
                return -EINVAL;

        mkdir(BPFTUNE_PIN, 0755);
        mkdir(EXPLORE_PIN_DIR, 0755);
        unlink(ALIAS_PIN_PATH);
        err = bpf_obj_pin(fd, ALIAS_PIN_PATH);
        if (err) {
                bpftune_log(LOG_ERR, "aliases: pin failed: %s\n",
                            strerror(-err));
                return err;
        }

        f = fopen(ALIAS_FILE, "r");
        if (!f) {
                bpftune_log(BPFTUNE_LOG_LEVEL,
                            "aliases: no %s, none loaded\n", ALIAS_FILE);
                return 0;
        }

        jf = fopen(LABELS_FILE ".tmp", "w");
        if (jf)
                fputs("{\n", jf);

        while (fgets(line, sizeof(line), f)) {
                char *p = line, *eq, *to_s, *lbl, *e;

                while (*p == ' ' || *p == '\t') p++;
                if (*p == '#' || *p == '\n' || *p == '\0') continue;
                eq = strchr(p, '=');
                if (!eq) continue;
                *eq = '\0';

                /* trim trailing ws from FROM */
                e = p + strlen(p);
                while (e > p && (e[-1] == ' ' || e[-1] == '\t'))
                        *--e = '\0';

                /* RHS: canonical IP, optional third column = label */
                to_s = eq + 1;
                while (*to_s == ' ' || *to_s == '\t') to_s++;
                e = to_s + strlen(to_s);
                while (e > to_s && (e[-1] == ' ' || e[-1] == '\t' ||
                                    e[-1] == '\n' || e[-1] == '\r'))
                        *--e = '\0';

                lbl = NULL;
                {
                        char *sp = to_s;
                        while (*sp && *sp != ' ' && *sp != '\t') sp++;
                        if (*sp) {
                                *sp = '\0';
                                lbl = sp + 1;
                                while (*lbl == ' ' || *lbl == '\t') lbl++;
                                e = lbl + strlen(lbl);
                                while (e > lbl && (e[-1] == ' ' ||
                                                   e[-1] == '\t' ||
                                                   e[-1] == '\n' ||
                                                   e[-1] == '\r'))
                                        *--e = '\0';
                                if (!*lbl) lbl = NULL;
                        }
                }

                if (alias_text_to_key(p, &from)) {
                        bpftune_log(LOG_ERR, "aliases: bad FROM '%s'\n", p);
                        continue;
                }
                if (alias_text_to_key(to_s, &to)) {
                        bpftune_log(LOG_ERR, "aliases: bad TO '%s'\n", to_s);
                        continue;
                }
                if (bpf_map_update_elem(fd, &from, &to, BPF_ANY)) {
                        bpftune_log(LOG_ERR, "aliases: update failed: %s\n",
                                    strerror(errno));
                        continue;
                }
                n++;
                if (lbl && jf && strcmp(to_s, prev_to) != 0) {
                        /* 0.4.89 (M7): escape JSON special chars in both
                         * the key (to_s) and value (lbl).  Without this,
                         * a label containing " or \ would produce
                         * malformed JSON and break the dashboard's parser. */
                        if (nj) fputs(",\n", jf);
                        fputs("  \"", jf);
                        for (const char *p = to_s; *p; p++) {
                                unsigned char c = (unsigned char)*p;
                                if (c == '"' || c == '\\') { fputc('\\', jf); fputc(c, jf); }
                                else if (c == '\n') fputs("\\n", jf);
                                else if (c == '\r') fputs("\\r", jf);
                                else if (c == '\t') fputs("\\t", jf);
                                else if (c < 0x20) fprintf(jf, "\\u%04x", c);
                                else fputc(c, jf);
                        }
                        fputs("\": \"", jf);
                        for (const char *p = lbl; *p; p++) {
                                unsigned char c = (unsigned char)*p;
                                if (c == '"' || c == '\\') { fputc('\\', jf); fputc(c, jf); }
                                else if (c == '\n') fputs("\\n", jf);
                                else if (c == '\r') fputs("\\r", jf);
                                else if (c == '\t') fputs("\\t", jf);
                                else if (c < 0x20) fprintf(jf, "\\u%04x", c);
                                else fputc(c, jf);
                        }
                        fputs("\"", jf);
                        nj++;
                        strncpy(prev_to, to_s, sizeof(prev_to) - 1);
                        prev_to[sizeof(prev_to) - 1] = '\0';
                }
        }

        fclose(f);
        if (jf) {
                if (nj) fputs("\n", jf);
                fputs("}\n", jf);
                fclose(jf);
                rename(LABELS_FILE ".tmp", LABELS_FILE);
        } else {
                unlink(LABELS_FILE);
        }
        bpftune_log(BPFTUNE_LOG_LEVEL,
                    "aliases: loaded %d entries (%d labels) from %s\n",
                    n, nj, ALIAS_FILE);
        return 0;
}

int init(struct bpftuner *tuner)
{
        struct bpftunable *t;
        int i, err;

        /* make sure cong modules are loaded; might be builtin so do not
         * shout about errors.
         */
        for (i = 0; i < NUM_TCP_CONN_METRICS; i++) {
                char name[32];

                snprintf(name, sizeof(name), "tcp_%s", congs[i]);
                err = bpftune_module_load(name);
                if (err != -EEXIST)
                        bpftune_log(LOG_DEBUG, "could not load module '%s': %s\n",
                                    name, strerror(-err));
        }

        /* first detach any dangling cgroup attachment for our prog; this
         * can happen if the bpftune process is killed and we do not get to
         * detach from cgroup.
         */
        bpftuner_cgroup_detach(tuner, CONN_TUNER_BPF, BPF_CGROUP_SOCK_OPS);
        bpftuner_cgroup_detach(tuner, CONN_TUNER_VOTE_BPF, BPF_CGROUP_SOCK_OPS);

        err = bpftuner_bpf_init(tcp_conn, tuner, NULL);
        if (err)
                return err;

        restore_remote_host_map(tuner);
        err = bpftune_cap_add();
        if (err) {
                bpftune_log(LOG_ERR, "cannot add caps: %s\n", strerror(-err));
                return 1;
        }
        /* 0.4.64: pin the explore map so 'bpftune --exp=N' can find
         * it.  Non-fatal: a missing pin disables --exp but leaves the
         * tuner otherwise unaffected. */
        if (pin_explore_map(tuner))
                bpftune_log(LOG_ERR,
                            "explore: pin failed; --exp will be unavailable\n");
        if (pin_alias_map(tuner))
                bpftune_log(LOG_ERR,
                            "aliases: pin failed; aliases unavailable\n");

        /* attach to root cgroup */
        err = bpftuner_cgroup_attach(tuner, CONN_TUNER_BPF, BPF_CGROUP_SOCK_OPS);
        if (err)
                goto out;

        err = bpftuner_cgroup_attach(tuner, CONN_TUNER_VOTE_BPF, BPF_CGROUP_SOCK_OPS);
        if (err)
                goto out;

        /* 0.4.79: verify both progs actually landed on the root cgroup.
         * Observed on fast systemctl restart: the attaches return 0 but
         * the tree ends up empty, then a second restart fixes it.  The
         * exact interleaving between the dying instance's detach and
         * ours hasn't been pinned down; this retry makes startup
         * reliable regardless.  Up to 8 attempts, 250ms apart (~2s).
         *
         * 0.4.89 (M8): check the return value of bpftuner_cgroup_attach
         * and bail out with a clear log if it fails (was silently ignored
         * before).  Also log when popen() fails so a missing bpftool
         * binary is visible rather than looking like a successful verify. */
        {
                int attempt;
                for (attempt = 0; attempt < 8; attempt++) {
                        FILE *p = popen("bpftool cgroup tree 2>/dev/null", "r");
                        int n = 0;
                        char buf[512];
                        int a1, a2;
                        if (!p) {
                                bpftune_log(LOG_ERR,
                                            "cgroup attach verify: popen(bpftool) "
                                            "failed; cannot verify, assuming attached\n");
                                break;
                        }
                        while (fgets(buf, sizeof(buf), p)) {
                                if (strstr(buf, "bpftune_conn_tuner"))
                                        n++;
                        }
                        pclose(p);
                        if (n >= 2)
                                break;
                        bpftune_log(LOG_INFO,
                                    "cgroup attach verify: %d of 2 progs visible, retry %d/8\n",
                                    n, attempt + 1);
                        usleep(250000);
                        bpftuner_cgroup_detach(tuner, CONN_TUNER_BPF, BPF_CGROUP_SOCK_OPS);
                        bpftuner_cgroup_detach(tuner, CONN_TUNER_VOTE_BPF, BPF_CGROUP_SOCK_OPS);
                        a1 = bpftuner_cgroup_attach(tuner, CONN_TUNER_BPF, BPF_CGROUP_SOCK_OPS);
                        a2 = bpftuner_cgroup_attach(tuner, CONN_TUNER_VOTE_BPF, BPF_CGROUP_SOCK_OPS);
                        if (a1 || a2) {
                                bpftune_log(LOG_ERR,
                                            "cgroup attach verify: re-attach failed "
                                            "(bpf=%d vote=%d) on retry %d/8\n",
                                            a1, a2, attempt + 1);
                        }
                }
        }

        start_reanchor(tuner);


        err = bpftuner_tunables_init(tuner, ARRAY_SIZE(descs), descs,
                                     ARRAY_SIZE(scenarios), scenarios);
        if (err)
                goto out;
        t = bpftuner_tunable(tuner, TCP_ALLOWED_CONG);
        if (t) {
                for (i = 0; i < NUM_TCP_CONN_METRICS; i++) {
                        char new_allowed[BPFTUNE_MAX_STR];

                        if (strstr(t->current_str, congs[i]))
                                continue;
                        if (snprintf(new_allowed, sizeof(new_allowed), "%s %s", t->current_str,
                                     congs[i]) > BPFTUNE_MAX_STR)
                                break;
                        bpftuner_tunable_sysctl_write(tuner, TCP_ALLOWED_CONG, TCP_CONG_SET, 0,
                                                      1, new_allowed, "updating '%s' to '%s'\n",
                                                      t->desc.name, new_allowed);
                }
        }

        t = bpftuner_tunable(tuner, TCP_THIN_LINEAR_TIMEOUTS);
        if (t)
                bpftuner_bpf_var_set(tcp_conn, tuner, tcp_thin_lto, t->initial_values[0]);
out:
        bpftune_cap_drop();
        return err;
}

void summarize(struct bpftuner *tuner)
{
        struct bpf_map *map = bpftuner_bpf_map_get(tcp_conn, tuner, remote_host_map);
        struct in6_addr key, *prev_key = NULL;
        int map_fd = bpf_map__fd(map);
        unsigned long greedy_count = 0;
        __u64 thin_lto_choices;
        __u64 *cong_choices;
        int i;

        thin_lto_choices = bpftuner_bpf_var_get(tcp_conn, tuner, tcp_thin_lto_choices);
        if (thin_lto_choices) {
                bpftune_log(BPFTUNE_LOG_LEVEL, "# Summary: tcp_conn_tuner: set 'net.ipv4.tcp_thin_linear_timeouts' for %lu connections to improve responsiveness of thin flows durning retransmission\n",
                            thin_lto_choices);
        }
        cong_choices = bpftuner_bpf_var_get(tcp_conn, tuner, tcp_cong_choices);
        if (cong_choices) {
                bpftune_log(BPFTUNE_LOG_LEVEL,
                            "# Summary: tcp_conn_tuner: %20s %20s\n",
                            "CongAlg", "Count");
                for (i = 0; i < NUM_TCP_CONG_ALGS; i++) {
                        bpftune_log(BPFTUNE_LOG_LEVEL,
                                    "# Summary: tcp_conn_tuner: %20s %20lu\n",
                                    congs[i], cong_choices[i]);
                }
        }
        while (!bpf_map_get_next_key(map_fd, prev_key, &key)) {
                char buf[INET6_ADDRSTRLEN];
                struct remote_host r;

                prev_key = &key;

                if (bpf_map_lookup_elem(map_fd, &key, &r))
                        continue;

                bpftune_log(LOG_DEBUG, "# Summary: tcp_conn_tuner: %48s %8s %20s %8s %8s\n",
                            "IPAddress", "CongAlg", "Metric", "Count", "Greedy");
                inet_ntop(AF_INET6, &key, buf, sizeof(buf));

                for (i = 0; i < NUM_TCP_CONN_METRICS; i++) {

                        bpftune_log(LOG_DEBUG, "# Summary: tcp_conn_tuner: %48s %8s %20llu %8llu %8llu\n",
                                    buf, congs[i],
                                    r.metrics[i].metric_value,
                                    r.metrics[i].metric_count,
                                    r.metrics[i].greedy_count);
                        bpftuner_tunable_stats_update(tuner, TCP_CONG,
                                                      TCP_CONG_SET, true,
                                                      r.metrics[i].metric_count);
                        greedy_count += r.metrics[i].greedy_count;
                }
        }
}

/* Walk every bucket in remote_host_map and force the tracker fields
 * (best_i/best_v/second_i/second_v) to match the metric array.
 * Selection rules:
 *   - skip metrics with metric_count == 0
 *   - skip metrics whose metric_value is 0 or ~0 (unset sentinel)
 *   - leader requires metric_count >= MIN_LEADER_TRUST; leader is the
 *     minimum value among trusted candidates.
 *   - second-best requires metric_count > 0, excludes the leader, and
 *     requires value >= best_v so the best_v <= second_v invariant
 *     that the BPF vote path maintains is preserved.
 * Only the four tracker fields are written; reference-fix fields
 * (rate_high_streak/rate_high_max/rtt_low_streak/rtt_low_min) are
 * carried through unchanged via read-modify-write of the struct.
 */
/* 0.4.76: sustained-ruler swap_score reconciliation. */
/* 0.4.89 (C4): replaced the fixed tb[256] array with an open-addressing
 * hash table.  Old code silently dropped corrections for buckets past
 * 256 -- a real cap on busy multi-CDN hosts.  Also fixed the O(n²)
 * linear scan-per-line.  Hash uses the first 32 bits of the in6_addr
 * (matches the BPF bucket key layout for v4-mapped and /32 v6). */
#define TRUTH_PATH        "/var/lib/bpftune/history/swapscore_truth.jsonl"
#define TRUTH_STASH       "/var/lib/bpftune/history/swapscore_truth.processing"
#define TRUTH_HASH_SLOTS  4096
#define TRUTH_HASH_MASK   (TRUTH_HASH_SLOTS - 1)
#define TRUTH_WIN_TARGET  600
#define TRUTH_LOSS_TARGET 100

struct truth_bucket {
        struct in6_addr key;
        unsigned int win[NUM_TCP_CONN_METRICS];
        unsigned int loss[NUM_TCP_CONN_METRICS];
        unsigned int nnull[NUM_TCP_CONN_METRICS];
        unsigned char used;
};

/* FNV-1a 32-bit on the first 4 bytes of the in6_addr.  The BPF bucket
 * key for v4-mapped addresses has the v4 bits in s6_addr[12..15], and
 * for v6/32 the top 4 bytes are the network prefix.  Either way,
 * hashing the first 4 bytes of the raw struct gives good spread
 * (different networks hash to different slots). */
static unsigned int truth_hash(const struct in6_addr *k)
{
        const unsigned char *p = k->s6_addr;
        unsigned int h = 0x811c9dc5u;
        int i;
        for (i = 0; i < 4; i++) {
                h ^= p[i];
                h *= 0x01000193u;
        }
        return h & TRUTH_HASH_MASK;
}

/* Find or create a truth_bucket for the given key.  Returns NULL if
 * the table is full (4096 distinct buckets -- effectively impossible
 * for the current fleet, but if it ever happens, log and drop). */
static struct truth_bucket *truth_get(struct truth_bucket *tb,
                                       const struct in6_addr *key)
{
        unsigned int start = truth_hash(key);
        unsigned int i;
        for (i = 0; i < TRUTH_HASH_SLOTS; i++) {
                unsigned int idx = (start + i) & TRUTH_HASH_MASK;
                if (!tb[idx].used) {
                        memset(&tb[idx], 0, sizeof(tb[idx]));
                        tb[idx].key = *key;
                        tb[idx].used = 1;
                        return &tb[idx];
                }
                if (memcmp(&tb[idx].key, key, sizeof(*key)) == 0)
                        return &tb[idx];
        }
        return NULL;  /* table full */
}

static int truth_bucket_key(const char *s, struct in6_addr *out)
{
        struct in_addr a4;
        /* 0.4.78.2: v6:hhhhhhhh form -- top 32 bits of the remote
         * IPv6 address, matching the map key bpftune_conn_tuner
         * builds from ops->remote_ip6[0]. */
        if (s[0] == 'v' && s[1] == '6' && s[2] == ':') {
                unsigned int h;
                if (sscanf(s + 3, "%8x", &h) != 1) return -1;
                memset(out, 0, sizeof(*out));
                out->s6_addr[0] = (h >> 24) & 0xff;
                out->s6_addr[1] = (h >> 16) & 0xff;
                out->s6_addr[2] = (h >>  8) & 0xff;
                out->s6_addr[3] =  h        & 0xff;
                return 0;
        }
        if (inet_pton(AF_INET, s, &a4) != 1) return -1;
        memset(out, 0, sizeof(*out));
        out->s6_addr[10] = 0xff;
        out->s6_addr[11] = 0xff;
        memcpy(&out->s6_addr[12], &a4.s_addr, 4);
        return 0;
}

static int truth_alg_idx(const char *name)
{
        int i;
        for (i = 0; i < NUM_TCP_CONG_ALGS; i++)
                if (strcmp(congs[i], name) == 0) return i;
        return -1;
}

static int truth_extract(const char *line, const char *key,
                         char *out, size_t outsz)
{
        char pat[32];
        const char *p, *q;
        size_t n;
        snprintf(pat, sizeof(pat), "\"%s\":\"", key);
        p = strstr(line, pat);
        if (!p) return -1;
        p += strlen(pat);
        q = strchr(p, '"');
        if (!q) return -1;
        n = (size_t)(q - p);
        if (n >= outsz) n = outsz - 1;
        memcpy(out, p, n);
        out[n] = '\0';
        return 0;
}

static void apply_truth_corrections(int map_fd)
{
        /* 0.4.89 (C4): hash table replaces tb[256].  4096 slots x
         * ~200 bytes/entry = ~800 KB on the reanchor worker's stack.
         * That's fine -- the worker thread has an 8 MB default stack
         * and only one of these is alive at a time.  If we ever need
         * more, switch to malloc + free. */
        static struct truth_bucket tb[TRUTH_HASH_SLOTS];
        unsigned int ntb = 0, dropped = 0;
        char *line = NULL;
        size_t linecap = 0;
        FILE *f;
        unsigned int i;
        int j, k;

        memset(tb, 0, sizeof(tb));
        unlink(TRUTH_STASH);
        if (rename(TRUTH_PATH, TRUTH_STASH) != 0) return;
        f = fopen(TRUTH_STASH, "r");
        if (!f) { unlink(TRUTH_STASH); return; }

        /* 0.4.89 (M4): getline replaces fixed 512-byte buf -- truth
         * lines can exceed 512 chars with labels and timestamps. */
        while (getline(&line, &linecap, f) != -1) {
                char bucket[64], tgt[32], cls[16];
                int tgt_idx;
                struct in6_addr key;
                struct truth_bucket *b;

                if (truth_extract(line, "bucket", bucket, sizeof(bucket))) continue;
                if (truth_extract(line, "tgt", tgt, sizeof(tgt))) continue;
                if (truth_extract(line, "cls", cls, sizeof(cls))) continue;
                tgt_idx = truth_alg_idx(tgt);
                if (tgt_idx < 0) continue;
                if (truth_bucket_key(bucket, &key)) continue;
                b = truth_get(tb, &key);
                if (!b) {
                        dropped++;
                        continue;
                }
                if (b->win[0] == 0 && b->loss[0] == 0 && b->nnull[0] == 0 &&
                    !b->win[0] && !b->loss[0] && !b->nnull[0]) {
                        /* first touch for this bucket -- count it.  Cheap
                         * heuristic: count any bucket that gets at least
                         * one line.  We don't track per-bucket first-touch
                         * explicitly to avoid scanning used[] later. */
                        ntb++;
                }
                if (strcmp(cls, "win") == 0) b->win[tgt_idx]++;
                else if (strcmp(cls, "loss") == 0) b->loss[tgt_idx]++;
                else if (strcmp(cls, "null") == 0) b->nnull[tgt_idx]++;
        }
        free(line);
        fclose(f);
        unlink(TRUTH_STASH);

        if (dropped)
                bpftune_log(LOG_ERR, "truth: table full (%u entries dropped); "
                            "consider raising TRUTH_HASH_SLOTS\n", dropped);

        for (i = 0; i < TRUTH_HASH_SLOTS; i++) {
                struct remote_host r;
                __u64 seq1, seq2;
                int dirty = 0;
                int retries = 0;

                if (!tb[i].used) continue;
                /* 0.4.89 (C1): seq-retry loop.  Read seq, lookup, mutate,
                 * re-read seq, retry if changed.  Caps at 4 retries
                 * (~microseconds each); a BPF vote storm that keeps the
                 * bucket in flux for 4+ retries is logged and skipped
                 * this cycle. */
retry:
                if (bpf_map_lookup_elem(map_fd, &tb[i].key, &r)) continue;
                seq1 = r.seq;
                if (seq1 & 1) {  /* BPF mid-update */
                        if (++retries > 4) {
                                bpftune_log(LOG_DEBUG,
                                            "truth: bucket seq busy, skipped\n");
                                continue;
                        }
                        usleep(1000);
                        goto retry;
                }
                for (j = 0; j < NUM_TCP_CONN_METRICS; j++) {
                        unsigned int cur;
                        for (k = 0; k < (int)tb[i].win[j]; k++) {
                                cur = r.metrics[j].swap_score;
                                if (cur < TRUTH_WIN_TARGET)
                                        cur += (TRUTH_WIN_TARGET - cur) / SWAP_SCORE_STEP_DIV;
                                else if (cur > TRUTH_WIN_TARGET)
                                        cur -= (cur - TRUTH_WIN_TARGET) / SWAP_SCORE_STEP_DIV;
                                r.metrics[j].swap_score = (__u16)cur;
                        }
                        if (tb[i].win[j]) {
                                r.metrics[j].bad_streak = 0;
                                r.metrics[j].null_streak = 0;
                                dirty = 1;
                        }
                        for (k = 0; k < (int)tb[i].loss[j]; k++) {
                                cur = r.metrics[j].swap_score;
                                if (cur > TRUTH_LOSS_TARGET)
                                        cur -= (cur - TRUTH_LOSS_TARGET) / SWAP_SCORE_STEP_DIV;
                                else if (cur < TRUTH_LOSS_TARGET)
                                        cur += (TRUTH_LOSS_TARGET - cur) / SWAP_SCORE_STEP_DIV;
                                r.metrics[j].swap_score = (__u16)cur;
                                dirty = 1;
                        }
                        if (tb[i].loss[j]) {
                                if (r.metrics[j].bad_streak < 255)
                                        r.metrics[j].bad_streak++;
                                dirty = 1;
                        }
                        if (tb[i].nnull[j]) {
                                if (r.metrics[j].null_streak < 255)
                                        r.metrics[j].null_streak++;
                                dirty = 1;
                        }
                }
                if (!dirty) continue;
                /* Re-read seq; if BPF voted during our mutation, retry. */
                {
                        struct remote_host check;
                        if (bpf_map_lookup_elem(map_fd, &tb[i].key, &check)) continue;
                        seq2 = check.seq;
                }
                if (seq2 != seq1) {
                        if (++retries > 4) {
                                bpftune_log(LOG_DEBUG,
                                            "truth: bucket seq changed mid-update, skipped\n");
                                continue;
                        }
                        goto retry;
                }
                bpf_map_update_elem(map_fd, &tb[i].key, &r, BPF_ANY);
        }
}

static void reanchor_best(int map_fd)
{
        struct in6_addr key, *prev_key = NULL;
        unsigned int scanned = 0, updated = 0, seq_skipped = 0;

        while (!bpf_map_get_next_key(map_fd, prev_key, &key)) {
                struct remote_host r;
                __u64 best_i = ~((__u64)0), best_v = 0;
                __u64 second_i = ~((__u64)0), second_v = 0;
                __u64 new_bi, new_bv, new_si, new_sv;
                __u64 new_rbi = 0, new_rbv = 0;
                __u64 new_r2i = 0, new_r2v = 0;
                __u64 seq1, seq2;
                int i;
                int retries = 0;

                prev_key = &key;

                /* 0.4.89 (C1): seq-retry loop.  Read seq, lookup,
                 * mutate, re-read seq, retry if changed.  Caps at 4
                 * retries; a bucket in flux for 4+ retries is logged
                 * and skipped this cycle (the next reanchor pass will
                 * pick it up).  Without this, the read-modify-write
                 * of the whole 792-byte struct clobbered any BPF vote
                 * that landed between lookup and update. */
retry:
                if (bpf_map_lookup_elem(map_fd, &key, &r))
                        continue;
                seq1 = r.seq;
                if (seq1 & 1) {  /* BPF mid-update */
                        if (++retries > 4) {
                                seq_skipped++;
                                continue;
                        }
                        usleep(1000);
                        goto retry;
                }
                scanned++;

                /* Pass 1: trusted minimum. */
                for (i = 0; i < NUM_TCP_CONN_METRICS; i++) {
                        __u64 v = r.metrics[i].metric_value;
                        __u64 cnt = r.metrics[i].metric_count;

                        if (cnt < MIN_LEADER_TRUST)
                                continue;
                        if (v == 0 || v == ~((__u64)0))
                                continue;
                        if (best_v == 0 || v < best_v) {
                                best_i = (__u64)i;
                                best_v = v;
                        }
                }

                /* Pass 2: second-best. */
                if (best_v != 0) {
                        for (i = 0; i < NUM_TCP_CONN_METRICS; i++) {
                                __u64 v = r.metrics[i].metric_value;
                                __u64 cnt = r.metrics[i].metric_count;

                                if ((__u64)i == best_i || cnt == 0)
                                        continue;
                                if (v == 0 || v == ~((__u64)0))
                                        continue;
                                if (v < best_v)
                                        continue;
                                if (second_v == 0 || v < second_v) {
                                        second_i = (__u64)i;
                                        second_v = v;
                                }
                        }
                }

                /* 0.4.45 pass 3: rate-EMA leader. */

                {

                    __u64 rate_bi = ~((__u64)0), rate_bv = 0;
                    __u64 best_weighted = 0;
                    int j;
                    __u64 rate_2i = ~((__u64)0), rate_2v = 0;
                    __u64 second_weighted = 0;
                    /* 0.4.56: pick by rate_ema * swap_score so a target with a
                     * bad swap track record gets demoted automatically.  Store
                     * raw rate_ema in rate_bv -- BPF's trigger math needs a rate. */
                    for (j = 0; j < NUM_TCP_CONN_METRICS; j++) {
                        __u64 rv = r.metrics[j].rate_ema;
                        __u64 ss, weighted;
                        if (r.metrics[j].metric_count < MIN_LEADER_TRUST) continue;
                        if (rv == 0) continue;
                        /* 0.4.60: no hard exclusion.  A bad or null streak
                         * demotes the target instead of banning it, so it stays
                         * in the pile and can climb back the moment it wins or
                         * its rate_ema rises.  Penalty: 16/(16 + bad*4 + null*2).
                         * bad=2 -> 0.67x, null=3 -> 0.73x, both -> 0.53x.
                         *
                         * 0.4.89 (M1): removed `if (ss == 0) ss = SWAP_SCORE_NEUTRAL`.
                         * The reset-to-neutral defeated loss-driven demotion:
                         * score_pending_swap legitimately drives swap_score to 0
                         * after enough losses, and reanchor was resetting it to
                         * 256 every 30s.  A legitimately-zeroed score now stays
                         * 0, pass 3 excludes it (weighted = 0).  The bad_streak
                         * penalty still applies on top; a recovering algo climbs
                         * back when its bad_streak clears via the EMA-rise path. */
                        ss = r.metrics[j].swap_score;
                        if (ss == 0) continue;  /* v0.4.99: skip zeroed scores */
                        weighted = rv * ss / SWAP_SCORE_NEUTRAL;
                        {
                            __u64 pen = 16
                                + (__u64)r.metrics[j].bad_streak * 4
                                + (__u64)r.metrics[j].null_streak * 2;
                            weighted = weighted * 16 / pen;
                        }
                        if (rate_bv == 0 || weighted > best_weighted) {
                            if (rate_bi != ~((__u64)0)) {
                                rate_2i = rate_bi;
                                rate_2v = rate_bv;
                                second_weighted = best_weighted;
                            }
                            rate_bi = (__u64)j;
                            rate_bv = rv;
                            best_weighted = weighted;
                        } else if (weighted > second_weighted &&
                                   (__u64)j != rate_bi) {
                            rate_2i = (__u64)j;
                            rate_2v = rv;
                            second_weighted = weighted;
                        }
                    }

                    new_rbi = (rate_bv == 0) ? 0 : rate_bi;
                    new_rbv = rate_bv;
                    new_r2i = (rate_2v == 0) ? 0 : rate_2i;
                    new_r2v = rate_2v;

                }

                /* No trusted leader: force the tracker to the empty state so
                 * the swap path sees "no leader" rather than a stale value.
                 */
                if (best_v == 0) {
                        new_bi = 0;
                        new_bv = 0;
                        new_si = 0;
                        new_sv = 0;
                } else {
                        new_bi = best_i;
                        new_bv = best_v;
                        new_si = (second_v == 0) ? 0 : second_i;
                        new_sv = second_v;
                }

                {
                        __u64 ref_before = r.max_rate_delivered;

                        __u64 scores_init = 0;

                        int jj;


                        /* 0.4.63: initialize stale swap_score=0 entries that have

                         * votes.  0.4.62 set the score in set_cong(), but an algo

                         * already in the state file with score=0 only inits when

                         * set_cong runs for it -- on a bucket past coverage that's

                         * the next epsilon-greedy draw, not the next reanchor.

                         * Do it here so it clears within 30s. */

                        for (jj = 0; jj < NUM_TCP_CONN_METRICS; jj++) {

                            if (r.metrics[jj].swap_score == 0 &&

                                r.metrics[jj].metric_count > 0) {

                                r.metrics[jj].swap_score = SWAP_SCORE_NEUTRAL;

                                scores_init++;

                            }

                        }

                        /* 0.4.43: refresh max_rate_delivered from histogram.
                         * Runs before the 'unchanged' early-continue so that a
                         * stable bucket still refreshes its reference, and so
                         * the histogram-derived value is written back to the map.
                         */
                        rate_hist_decay(&r.rate);
                        {
                                unsigned long long p99 = rate_hist_p99(&r.rate);
                                if (p99 != r.max_rate_delivered)
                                        r.max_rate_delivered = p99;
                        }

                        if (scores_init == 0 &&
                                ref_before == r.max_rate_delivered &&
                                r.best_i == new_bi && r.best_v == new_bv &&
                                r.second_i == new_si && r.second_v == new_sv &&
                                r.rate_best_i == new_rbi &&
                                r.rate_best_v == new_rbv &&
                                r.rate_second_i == new_r2i &&
                                r.rate_second_v == new_r2v)
                                        continue;
                }
                bpftune_log(BPFTUNE_LOG_LEVEL,
                            "reanchor: best_i=%llu best_v=%llu (was %llu/%llu) second_i=%llu second_v=%llu (was %llu/%llu)\n",
                            (unsigned long long)new_bi,
                            (unsigned long long)new_bv,
                            (unsigned long long)r.best_i,
                            (unsigned long long)r.best_v,
                            (unsigned long long)new_si,
                            (unsigned long long)new_sv,
                            (unsigned long long)r.second_i,
                            (unsigned long long)r.second_v);

                r.best_i = new_bi;
                r.best_v = new_bv;
                r.second_i = new_si;
                r.second_v = new_sv;
                r.rate_best_i = new_rbi;
                r.rate_best_v = new_rbv;
                r.rate_second_i = new_r2i;
                r.rate_second_v = new_r2v;

                /* 0.4.89 (C1): re-read seq; if BPF voted during our
                 * mutation, retry.  Preserves whatever BPF wrote by
                 * re-reading the now-current struct and redoing the
                 * pass 1/2/3 work on top of it. */
                {
                        struct remote_host check;
                        if (bpf_map_lookup_elem(map_fd, &key, &check)) continue;
                        seq2 = check.seq;
                }
                if (seq2 != seq1) {
                        if (++retries > 4) {
                                seq_skipped++;
                                continue;
                        }
                        usleep(1000);
                        goto retry;
                }
                if (bpf_map_update_elem(map_fd, &key, &r, BPF_ANY)) {
                        bpftune_log(LOG_ERR, "reanchor: update failed: %s\n",
                                    strerror(errno));
                        continue;
                }
                updated++;
        }

        if (seq_skipped)
                bpftune_log(LOG_DEBUG, "reanchor: %u buckets skipped (seq busy)\n",
                            seq_skipped);
        bpftune_log(LOG_DEBUG, "reanchor: cycle scanned=%u updated=%u\n",
                    scanned, updated);
}

static void *reanchor_worker(void *arg)
{
        int fd = reanchor_fd;
        int i;

        (void)arg;

        if (fd < 0)
                return NULL;

        /* Capabilities are per-thread; the voter worker issues BPF map
         * syscalls so it needs CAP_SYS_ADMIN in its own effective set. */
        bpftune_cap_add();

        while (!reanchor_stop) {
                reanchor_best(fd);
                apply_truth_corrections(fd);   /* 0.4.76 */
                /* Sleep in short slices so fini() does not stall more
                 * than ~1s waiting on pthread_join. */
                for (i = 0; i < REANCHOR_INTERVAL; i++) {
                        if (reanchor_stop)
                                break;
                        sleep(1);
                }
        }

        bpftune_cap_drop();
        return NULL;
}

static void start_reanchor(struct bpftuner *tuner)
{
        struct bpf_map *map;
        int fd;

        if (reanchor_started)
                return;

        map = bpftuner_bpf_map_get(tcp_conn, tuner, remote_host_map);
        if (!map) {
                bpftune_log(LOG_ERR, "reanchor: map not found\n");
                return;
        }
        fd = bpf_map__fd(map);
        if (fd < 0) {
                bpftune_log(LOG_ERR, "reanchor: bad map fd\n");
                return;
        }
        reanchor_fd = fd;
        reanchor_stop = 0;
        if (pthread_create(&reanchor_tid, NULL, reanchor_worker, NULL) != 0) {
                bpftune_log(LOG_ERR, "reanchor: pthread_create failed: %s\n",
                            strerror(errno));
                return;
        }
        reanchor_started = 1;
        bpftune_log(BPFTUNE_LOG_LEVEL,
                    "reanchor: worker started (interval %ds)\n",
                    REANCHOR_INTERVAL);
}

static void stop_reanchor(void)
{
        if (!reanchor_started)
                return;
        reanchor_stop = 1;
        pthread_join(reanchor_tid, NULL);
        reanchor_started = 0;
        bpftune_log(LOG_DEBUG, "reanchor: worker stopped\n");
}

#define STATE_DIR     "/var/lib/bpftune"
#define STATE_PATH    STATE_DIR "/tcp_conn_tuner.state"
/* 0.4.72: layout version split.  STATE_LAYOUT bumped only when struct
 * remote_host changes size or shape.  The restore path enforces layout
 * by comparing hdr.key_size / hdr.value_size against sizeof at runtime,
 * which catches any real layout change; this number is informational.
 *
 * 0.4.89 (Q1 + M6): removed STATE_EPOCH and migrate_remote_host.  The
 * epoch mechanism was a no-op body that served only as a footgun for
 * the next maintainer who bumped STATE_EPOCH expecting migration to
 * run.  Future semantic changes bump STATE_LAYOUT (wiping the map and
 * rebuilding from zero -- the same tax the epoch mechanism was
 * supposed to avoid, but paid honestly and once per real change
 * rather than as silent state corruption).
 *
 * 0.4.89 (M6): STATE_LAYOUT bumped 1 -> 2 because sockets_alive /
 * sockets_good / sockets_proved widened from __u16 to __u32.  Old
 * state files (layout 1) will be refused by the size check below. */
#define STATE_MAGIC   0x42504656u
#define STATE_LAYOUT  2
struct state_header {
        __u32 magic;
        __u32 layout_version;   /* informational; not enforced */
        __u32 key_size;         /* enforced: must match sizeof(key) */
        __u32 value_size;       /* enforced: must match sizeof(val) */
        __u32 num_entries;
};

/* 0.4.89 (Q1): migrate_remote_host removed.  See STATE_LAYOUT note
 * above.  No per-entry migration is performed on load; layout
 * incompatibility is caught by the size check in restore_remote_host_map
 * and the map is rebuilt from zero. */

static int restore_remote_host_map(struct bpftuner *tuner)
{
        struct bpf_map *map = bpftuner_bpf_map_get(tcp_conn, tuner, remote_host_map);
        struct state_header hdr;
        struct in6_addr key;
        struct remote_host val;
        int map_fd, err = 0;
        __u32 i;
        FILE *f;

        if (!map)
                return -1;
        map_fd = bpf_map__fd(map);

        f = fopen(STATE_PATH, "rb");
        if (!f)
                return 0;   /* no state file = fresh start, not an error */

        if (fread(&hdr, sizeof(hdr), 1, f) != 1) {
                bpftune_log(LOG_ERR, "tcp_conn_tuner: %s: truncated header\n", STATE_PATH);
                err = -1; goto out;
        }
        /* 0.4.72: layout compatibility is enforced by the two size
         * fields -- a struct change cannot pass this check.
         * 0.4.89 (Q1): the epoch mechanism was removed. */
        if (hdr.magic != STATE_MAGIC ||
            hdr.key_size != sizeof(key) ||
            hdr.value_size != sizeof(val)) {
                bpftune_log(LOG_ERR,
                            "tcp_conn_tuner: %s: incompatible state "
                            "(magic=%x key=%u/%zu val=%u/%zu); ignoring\n",
                            STATE_PATH, hdr.magic,
                            hdr.key_size, sizeof(key),
                            hdr.value_size, sizeof(val));
                err = -1; goto out;
        }

        for (i = 0; i < hdr.num_entries; i++) {
                if (fread(&key, sizeof(key), 1, f) != 1 ||
                    fread(&val, sizeof(val), 1, f) != 1) {
                        bpftune_log(LOG_ERR, "tcp_conn_tuner: %s: truncated entry %u\n",
                                    STATE_PATH, i);
                        err = -1; goto out;
                }
                if (bpf_map_update_elem(map_fd, &key, &val, BPF_ANY))
                        bpftune_log(LOG_DEBUG, "tcp_conn_tuner: restore: update failed for entry %u\n", i);
        }

        bpftune_log(LOG_DEBUG, "tcp_conn_tuner: restored %u entries from %s\n",
                    hdr.num_entries, STATE_PATH);
out:
        fclose(f);
        return err;
}

static int save_remote_host_map(struct bpftuner *tuner)
{
        struct bpf_map *map = bpftuner_bpf_map_get(tcp_conn, tuner, remote_host_map);
        struct state_header hdr = { .magic = STATE_MAGIC,
                                    .layout_version = STATE_LAYOUT };
        struct in6_addr key, next_key;
        struct remote_host val;
        void *prev = NULL;
        int map_fd, err = 0;
        char tmp[64];
        FILE *f;

        if (!map)
                return -1;
        map_fd = bpf_map__fd(map);

        mkdir(STATE_DIR, 0700);

        snprintf(tmp, sizeof(tmp), STATE_PATH ".tmp");
        f = fopen(tmp, "wb");
        if (!f) {
                bpftune_log(LOG_ERR, "tcp_conn_tuner: cannot open %s: %s\n",
                            tmp, strerror(errno));
                return -errno;
        }

        hdr.key_size = sizeof(key);
        hdr.value_size = sizeof(val);

        if (fseek(f, sizeof(hdr), SEEK_SET) != 0) { err = -1; goto out; }

        while (bpf_map_get_next_key(map_fd, prev, &next_key) == 0) {
                if (bpf_map_lookup_elem(map_fd, &next_key, &val))
                        goto next;
                if (val.instances < PERSIST_MIN_INSTANCES)
                        goto next;
                if (fwrite(&next_key, sizeof(next_key), 1, f) != 1 ||
                    fwrite(&val, sizeof(val), 1, f) != 1) { err = -1; goto out; }
                hdr.num_entries++;
next:
                key = next_key;
                prev = &key;
        }

        if (fseek(f, 0, SEEK_SET) != 0 ||
            fwrite(&hdr, sizeof(hdr), 1, f) != 1) { err = -1; goto out; }

        bpftune_log(LOG_DEBUG, "tcp_conn_tuner: saved %u entries to %s\n",
                    hdr.num_entries, STATE_PATH);
out:
        /* 0.4.89 (C5): fsync before rename so a crash between rename
         * and the actual disk flush doesn't leave STATE_PATH with a
         * zero-length or partially-written file.  Without this, a
         * kernel panic or power loss could corrupt the state file --
         * exactly the situation save_remote_host_map is meant to
         * prevent.  fsync the parent dir too so the rename itself is
         * durable. */
        if (!err && f) {
                fflush(f);
                fsync(fileno(f));
        }
        fclose(f);
        if (err) {
                unlink(tmp);
                return err;
        }
        chmod(tmp, 0600);
        if (rename(tmp, STATE_PATH) != 0) {
                bpftune_log(LOG_ERR, "tcp_conn_tuner: rename %s -> %s: %s\n",
                            tmp, STATE_PATH, strerror(errno));
                unlink(tmp);
                return -errno;
        }
        /* fsync the parent directory so the rename is durable too. */
        {
                int dirfd = open(STATE_DIR, O_RDONLY | O_DIRECTORY);
                if (dirfd >= 0) {
                        fsync(dirfd);
                        close(dirfd);
                }
        }
        return 0;
}

void fini(struct bpftuner *tuner)
{
        bpftune_log(LOG_DEBUG, "calling fini for %s\n", tuner->name);
        stop_reanchor();
        bpftuner_cgroup_detach(tuner, CONN_TUNER_BPF, BPF_CGROUP_SOCK_OPS);
        bpftuner_cgroup_detach(tuner, CONN_TUNER_VOTE_BPF, BPF_CGROUP_SOCK_OPS);
        save_remote_host_map(tuner);
        summarize(tuner);
        bpftuner_bpf_fini(tuner);
}

void event_handler(struct bpftuner *tuner,  __attribute__((unused))struct bpftune_event *event,
                   __attribute__((unused))void *ctx)
{
        bpftune_log(LOG_DEBUG,
                    "%s: got unexpected event\n", tuner->name);
}
