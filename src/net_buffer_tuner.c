/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2023, Oracle and/or its affiliates. */

#include <bpftune/libbpftune.h>
#include <bpftune/corr.h>
#include "net_buffer_tuner.h"
#include "net_buffer_tuner.skel.h"
#include "net_buffer_tuner.skel.legacy.h"
#include "net_buffer_tuner.skel.nobtf.h"

#include <limits.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>

struct tcp_buffer_tuner_bpf *skel;

/* v0.4.106: runtime-configurable cap for netdev_budget_usecs.
 * Default is NETDEV_BUDGET_USECS_MAX (50ms) for bulk workloads.
 * Overridden to NETDEV_BUDGET_USECS_LATENCY_MAX (8ms) if a
 * latency-sensitive proxy (xray/v2ray/nginx/sing-box) is detected
 * at init time. Also overridable via env var
 * BPFTUNE_NETDEV_BUDGET_USECS_MAX for manual control. */
static long netdev_budget_usecs_max = NETDEV_BUDGET_USECS_MAX;
static bool latency_sensitive = false;

/* v0.4.106: rate-limit the "at cap" log message to once per minute
 * so it doesn't spam every 2-4 minutes forever. */
static time_t last_cap_log_sec = 0;

static struct bpftunable_desc descs[] = {
{ NETDEV_MAX_BACKLOG,   BPFTUNABLE_SYSCTL, "net.core.netdev_max_backlog",
                                                                0, 1 },
{ FLOW_LIMIT_CPU_BITMAP,
                        BPFTUNABLE_SYSCTL, "net.core.flow_limit_cpu_bitmap",
                                                                0, 1 },
{ NETDEV_BUDGET,        BPFTUNABLE_SYSCTL, "net.core.netdev_budget",
                                                                0, 1 },
{ NETDEV_BUDGET_USECS,  BPFTUNABLE_SYSCTL, "net.core.netdev_budget_usecs",
                                                                0, 1 },
{ HIGH_ORDER_ALLOC_DISABLE, BPFTUNABLE_SYSCTL, "net.core.high_order_alloc_disable",
                                                                0, 1 },
};

static struct bpftunable_scenario scenarios[] = {
{ NETDEV_MAX_BACKLOG_INCREASE,  "need to increase max backlog size",
        "Need to increase backlog size to prevent drops for faster connection" },
{ FLOW_LIMIT_CPU_SET,           "need to set per-cpu bitmap value",
        "Need to set flow limit per-cpu to prioritize small flows" },
{ NETDEV_BUDGET_INCREASE,       "need to increase # of packets processed per NAPI poll",
        "Need to increase number of packets processed across network devices during NAPI poll to use all of net.core.netdev_budget_usecs" },
{ NETDEV_BUDGET_DECREASE,       "need to decrease # of packets processed per NAPI poll",
        "Need to decrease netdev_budget[_usecs] since the ratio of time spent waiting to run versus time spent running for tasks has increased as we have increased netdev budget.  This indicates either our budget increases directly let to increased wait times for other tasks, or that general load has increased; either way spending too much time in NAPI processing will hurt system performance." },
{ HIGH_ORDER_ALLOC_ENABLE, "need to enable high-order allocation for skb page frags",
        "On pre-5.14 kernels setting net.core.high_order_alloc_disable=1 reduced contention, but disabling high-order allocations lowers performance with little benefit now that frags are allocated on a pre-cpu basis and contention is minimized." }
};

/* v0.4.106: workload detection — scan /proc/PID/comm for known
 * latency-sensitive proxy processes. If found, the tuner caps
 * netdev_budget_usecs at NETDEV_BUDGET_USECS_LATENCY_MAX (8ms)
 * instead of the default 50ms, to prevent NAPI softirq from
 * monopolizing the CPU and causing jitter in proxied streams.
 *
 * Returns true if a latency-sensitive proxy is running. */
static bool workload_is_latency_sensitive(void)
{
        DIR *d;
        struct dirent *e;
        bool found = false;

        d = opendir("/proc");
        if (!d)
                return false;

        while ((e = readdir(d)) != NULL) {
                char path[64];
                char buf[256];
                int fd, n;

                /* skip non-numeric entries (not PIDs) */
                if (e->d_name[0] < '0' || e->d_name[0] > '9')
                        continue;

                snprintf(path, sizeof(path), "/proc/%s/comm", e->d_name);
                fd = open(path, O_RDONLY);
                if (fd < 0)
                        continue;
                n = read(fd, buf, sizeof(buf) - 1);
                close(fd);
                if (n <= 0)
                        continue;
                buf[n] = '\0';

                /* check for known latency-sensitive proxy processes */
                if (strstr(buf, "xray") || strstr(buf, "v2ray") ||
                    strstr(buf, "sing-box") || strstr(buf, "nginx") ||
                    strstr(buf, "haproxy")) {
                        found = true;
                        break;
                }
        }
        closedir(d);
        return found;
}

int init(struct bpftuner *tuner)
{
        long cpu_bitmap = 0;
        long max_backlog = 0;
        long budget = 0;
        long budget_usecs = 0;
        long high_order_alloc_disable = 0;
        unsigned int kernel_version = 0;
        int err;

        /* v0.4.106: detect latency-sensitive workloads at init time.
         * If a proxy like xray/v2ray/nginx is running, cap
         * netdev_budget_usecs at 8ms to avoid NAPI softirq jitter. */
        const char *env_max = getenv("BPFTUNE_NETDEV_BUDGET_USECS_MAX");
        if (env_max) {
                netdev_budget_usecs_max = atol(env_max);
                bpftune_log(LOG_INFO,
                    "net_buffer: netdev_budget_usecs cap = %ld (from env var)\n",
                    netdev_budget_usecs_max);
        } else if (workload_is_latency_sensitive()) {
                latency_sensitive = true;
                netdev_budget_usecs_max = NETDEV_BUDGET_USECS_LATENCY_MAX;
                bpftune_log(LOG_INFO,
                    "net_buffer: latency-sensitive proxy detected, capping netdev_budget_usecs at %d usec\n",
                    NETDEV_BUDGET_USECS_LATENCY_MAX);
        }

        bpftune_sysctl_read(0, "net.core.flow_limit_cpu_bitmap", &cpu_bitmap);
        bpftune_sysctl_read(0, "net.core.netdev_max_backlog", &max_backlog);
        bpftune_sysctl_read(0, "net.core.netdev_budget", &budget);
        bpftune_sysctl_read(0, "net.core.netdev_budget_usecs", &budget_usecs);
        bpftune_sysctl_read(0, "net.core.high_order_alloc_disable", &high_order_alloc_disable);

        err = bpftuner_bpf_open(net_buffer, tuner);
        if (err)
                return err;
        err = bpftuner_bpf_load(net_buffer, tuner, NULL);
        if (err)
                return err;
        bpftuner_bpf_var_set(net_buffer, tuner, flow_limit_cpu_bitmap,
                             cpu_bitmap);
        bpftuner_bpf_var_set(net_buffer, tuner, netdev_max_backlog,
                             max_backlog);
        bpftuner_bpf_var_set(net_buffer, tuner, netdev_budget,
                             budget);
        bpftuner_bpf_var_set(net_buffer, tuner, netdev_budget_usecs,
                             budget_usecs);

        bpftuner_bpf_sample_add(net_buffer, tuner, drop_sample);
        bpftuner_bpf_sample_add(net_buffer, tuner, napi_complete_sample);
        err = bpftuner_bpf_attach(net_buffer, tuner);
        if (err)
                return err;

        err = bpftuner_tunables_init(tuner, NET_BUFFER_NUM_TUNABLES, descs,
                                     ARRAY_SIZE(scenarios), scenarios);
        if (!err && high_order_alloc_disable) {
                kernel_version = bpf_object__kversion(tuner->obj);
                bpftune_log(LOG_DEBUG, "high_order %ld got kver %d\n", high_order_alloc_disable, kernel_version);
                if (kernel_version >= KERNEL_VERSION(5, 14, 0)) {
                        high_order_alloc_disable = 0;
                        bpftuner_tunable_sysctl_write(tuner,
                                                      HIGH_ORDER_ALLOC_DISABLE,
                                                      HIGH_ORDER_ALLOC_ENABLE,
                                                      0,
                                                      1,
                                                      &high_order_alloc_disable,
"To maximize performance, set net.core.high_order_alloc_disable=0 on more recent kernel since it is not needed as contention in high-order allocs is not present\n");
                }
        }
        return err;
}

void fini(struct bpftuner *tuner)
{
        bpftune_log(LOG_DEBUG, "calling fini for %s\n", tuner->name);
        bpftuner_bpf_fini(tuner);
}

void event_handler(struct bpftuner *tuner,
                   struct bpftune_event *event,
                   __attribute__((unused))void *ctx)
{
        long new, budget_usecs, budget_usecs_new;
        int scenario = event->scenario_id;
        struct corr c = { 0 };
        long double corr = 0;
        const char *tunable;
        struct corr_key key;
        int id, ret;

        /* netns cookie not supported; ignore */
        if (event->netns_cookie == (unsigned long)-1)
                return;

        id = event->update[0].id;
        tunable = bpftuner_tunable_name(tuner, id);
        if (!tunable) {
                bpftune_log(LOG_DEBUG, "unknown tunable [%d] for net_buffer_tuner\n", id);
                return;
        }
        switch (id) {
        case NETDEV_MAX_BACKLOG:
                ret = bpftuner_tunable_sysctl_write(tuner, id, scenario,
                                                    event->netns_cookie, 1,
                                                    (long int *)event->update[0].new,
"Due to excessive drops, change %s from (%ld) -> (%ld)\n",
                                                    tunable,
                                                    event->update[0].old[0],
                                                    event->update[0].new[0]);
                if (!ret) {
                        /* update value of netdev_max_backlog for BPF program */
                        bpftuner_bpf_var_set(net_buffer, tuner, netdev_max_backlog,
                                             event->update[0].new[0]);
                }
                break;
        case FLOW_LIMIT_CPU_BITMAP:
                bpftuner_tunable_sysctl_write(tuner, id, scenario, 
                                              event->netns_cookie, 1,
                                              (long int *)event->update[0].new,
"To prioritize small flows, change %s from (%ld) -> (%ld)\n",
                                              tunable,
                                              event->update[0].old[0],
                                              event->update[0].new[0]);
                break;
        case NETDEV_BUDGET:
                new = event->update[0].new[0];
                if (new > INT_MAX)
                        break;
                budget_usecs = bpftuner_bpf_var_get(net_buffer, tuner,
                                                    netdev_budget_usecs);
                budget_usecs_new = BPFTUNE_GROW_BY_DELTA(budget_usecs);

                /* v0.4.106 Fix 6: shrink step size when close to cap
                 * to avoid overshoot. Use half the normal step. */
                if (budget_usecs > netdev_budget_usecs_max / 2) {
                        budget_usecs_new = budget_usecs +
                                (budget_usecs >> (BPFTUNE_BITSHIFT + 2));
                }

                /* v0.4.106 Fix 1: MOVED corr update + decrease check
                 * ABOVE the cap check. Previously the cap check broke
                 * out of the handler BEFORE the decrease path could
                 * run, making the decrease effectively dead code
                 * when at the cap — exactly when you need it most. */

                /* (1) Always refresh the corr map so the decrease
                 *     path can see correlation even when at cap. */
                ret = bpftune_sched_wait_run_percent_read();
                bpftune_log(LOG_DEBUG, "sched wait-run percent : %d\n", ret);
                if (ret > 0) {
                        key.id = (__u64)id;
                        key.netns_cookie = event->netns_cookie;
                        if (corr_update_user(tuner->corr_map_fd, key.id,
                                             key.netns_cookie,
                                             (__u64)new, (__u64)ret))
                                bpftune_log(LOG_DEBUG, "corr map fd %d update failed %d\n",
                                            tuner->corr_map_fd, errno);
                }

                /* (2) Default direction = increase; corr-based flip
                 *     to decrease. This now runs BEFORE the cap check. */
                if (ret > 0 && !bpf_map_lookup_elem(tuner->corr_map_fd, &key, &c)) {
                        corr = corr_compute(&c);
                        bpftune_log(LOG_DEBUG, "covar for '%s' netns %ld (new %ld): %LF; corr %LF\n",
                                    tunable, key.netns_cookie, new,
                                    covar_compute(&c), corr);
                        if (corr > CORR_THRESHOLD) {
                                new = BPFTUNE_SHRINK_BY_DELTA(event->update[0].old[0]);
                                budget_usecs_new = BPFTUNE_SHRINK_BY_DELTA(budget_usecs);
                                scenario = NETDEV_BUDGET_DECREASE;
                        }
                }

                /* (3) v0.4.106 Fix 1+2: cap check — when at cap and
                 *     still in INCREASE scenario, force a SHRINK
                 *     instead of log+break. This walks the value
                 *     back down instead of being stuck at the cap
                 *     forever. Rate-limited log to avoid spam. */
                if (scenario == NETDEV_BUDGET_INCREASE &&
                    budget_usecs_new > netdev_budget_usecs_max) {
                        time_t now_sec = time(NULL);
                        if (now_sec - last_cap_log_sec > 60) {
                                bpftune_log(LOG_INFO,
                                    "net_buffer: netdev_budget_usecs at cap %ld; shrinking from %ld to reduce NAPI latency\n",
                                    netdev_budget_usecs_max, budget_usecs);
                                last_cap_log_sec = now_sec;
                        }
                        budget_usecs_new = BPFTUNE_SHRINK_BY_DELTA(budget_usecs);
                        new = BPFTUNE_SHRINK_BY_DELTA(event->update[0].old[0]);
                        scenario = NETDEV_BUDGET_DECREASE;
                }

                /* v0.4.106: if latency-sensitive workload and we're
                 * trying to grow beyond the latency cap, suppress. */
                if (latency_sensitive && scenario == NETDEV_BUDGET_INCREASE &&
                    budget_usecs >= netdev_budget_usecs_max) {
                        /* already at the latency cap — don't grow further */
                        break;
                }

                ret = bpftuner_tunable_sysctl_write(tuner, id, scenario,
                                                    event->netns_cookie, 1,
                                                    (long int *)&new,
"To maximize # packets processed per NAPI cycle, change %s from (%ld) -> (%ld)\n",
                                                    tunable,
                                                    event->update[0].old[0],
                                                    new);
                if (!ret) {
                        /* update value of netdev_budget for BPF program */
                        bpftuner_bpf_var_set(net_buffer, tuner, netdev_budget,
                                             new);
                        /* need to also update budget_usecs since both
                         * limit netdev budget and reaching either limit
                         * triggers time_squeeze.
                         */
                        ret = bpftuner_tunable_sysctl_write(tuner,
                                                            NETDEV_BUDGET_USECS,
                                                            scenario,
                                                            event->netns_cookie,
                                                            1,
                                                            &budget_usecs_new,
"To maximize # packets processed per NAPI cycle, change netdev_budget_usecs from (%ld) -> (%ld)\n",
                                                            budget_usecs,
                                                            budget_usecs_new);
                        if (!ret)
                                bpftuner_bpf_var_set(net_buffer, tuner,
                                                     netdev_budget_usecs,
                                                     budget_usecs_new);
                }
                break;
        }
}
