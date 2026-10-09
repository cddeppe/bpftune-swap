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
{ TCP_CONG_SET,		"specify TCP congestion control algorithm",
  "To optimize TCP performance, a TCP congestion control algorithm was chosen to mimimize round-trip time and maximize delivery rate." },
};

struct tcp_conn_tuner_bpf *skel;

int tcp_iter_fd;

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
	bpftune_log(BPFTUNE_LOG_LEVEL,
		    "explore: pinned at %s, pct=%u\n", EXPLORE_PIN_PATH, pct);
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

	/* attach to root cgroup */
	err = bpftuner_cgroup_attach(tuner, CONN_TUNER_BPF, BPF_CGROUP_SOCK_OPS);
	if (err)
		goto out;

	err = bpftuner_cgroup_attach(tuner, CONN_TUNER_VOTE_BPF, BPF_CGROUP_SOCK_OPS);
	if (err)
		goto out;

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
static void reanchor_best(int map_fd)
{
	struct in6_addr key, *prev_key = NULL;
	unsigned int scanned = 0, updated = 0;

	while (!bpf_map_get_next_key(map_fd, prev_key, &key)) {
		struct remote_host r;
		__u64 best_i = ~((__u64)0), best_v = 0;
		__u64 second_i = ~((__u64)0), second_v = 0;
		__u64 new_bi, new_bv, new_si, new_sv;
		__u64 new_rbi = 0, new_rbv = 0;
		__u64 new_r2i = 0, new_r2v = 0;
		int i;

		prev_key = &key;

		if (bpf_map_lookup_elem(map_fd, &key, &r))
			continue;
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
		         * bad=2 -> 0.67x, null=3 -> 0.73x, both -> 0.53x. */
		        ss = r.metrics[j].swap_score;
		        if (ss == 0) ss = SWAP_SCORE_NEUTRAL;
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

		if (bpf_map_update_elem(map_fd, &key, &r, BPF_ANY)) {
			bpftune_log(LOG_ERR, "reanchor: update failed: %s\n",
				    strerror(errno));
			continue;
		}
		updated++;
	}

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
#define STATE_MAGIC   0x42504654u
#define STATE_VERSION 18
struct state_header {
        __u32 magic;
        __u32 version;
        __u32 key_size;
        __u32 value_size;
        __u32 num_entries;
        __u32 reserved;
};

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
        if (hdr.magic != STATE_MAGIC || hdr.version != STATE_VERSION ||
            hdr.key_size != sizeof(key) || hdr.value_size != sizeof(val)) {
                bpftune_log(LOG_ERR,
                            "tcp_conn_tuner: %s: stale or mismatched state (magic=%x ver=%u); ignoring\n",
                            STATE_PATH, hdr.magic, hdr.version);
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
        struct state_header hdr = { .magic = STATE_MAGIC, .version = STATE_VERSION };
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
