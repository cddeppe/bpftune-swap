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

#include <bpftune/bpftune.bpf.h>

#include "tcp_conn_tuner.h"

_Static_assert(sizeof(struct remote_host) <= 1024,
               "remote_host too large for BPF memset");

#define TCP_THIN_LINEAR_TIMEOUTS        16

__u64 tcp_cong_choices[NUM_TCP_CONG_ALGS];

long long tcp_thin_lto = 0;

/* 0.4.91: debug toggle.  Stored in tuner_config_map slot 3 (not a
 * BPF global) so the CLI can update it live via 'bpftune --bpf-debug=N'
 * without restarting the daemon.  BPF reads it from the map on every
 * ESTABLISHED and vote, and updates this local variable.  Default 1
 * (verbose, matching pre-0.4.89 behavior).  Set to 0 to silence all
 * bpf_printk calls. */
__u32 bpftune_debug = 1;

BPF_MAP_DEF(remote_host_map, BPF_MAP_TYPE_LRU_HASH, struct in6_addr, struct remote_host, 4096, 0);

BPF_MAP_DEF(sk_storage_map, BPF_MAP_TYPE_SK_STORAGE, int, struct conn_state, 0, BPF_F_NO_PREALLOC);

BPF_MAP_DEF(midsamp_map, BPF_MAP_TYPE_SK_STORAGE, int, __u64, 0, BPF_F_NO_PREALLOC);

/* 0.4.64: runtime config map.  Pinned by the userspace daemon so
 * 'bpftune --exp=N', --prefix4=N, --prefix6=N, --bpf-debug=N can
 * update values live without restarting.
 * slot 0 = exp_pct, slot 1 = prefix4, slot 2 = prefix6,
 * slot 3 = bpf_debug (0=quiet, 1=verbose). */
BPF_MAP_DEF(tuner_config_map, BPF_MAP_TYPE_ARRAY, __u32, __u32, 6, 0);

/* 0.4.79: alias table.  Key is the raw destination as it arrives
 * from the socket (v4-mapped or v6/32 top bits); value is the
 * canonical bucket key to use instead.  Lets multiple public IPs
 * that the operator knows are the same physical destination share
 * one bucket.  Loaded from /etc/bpftune/aliases at daemon start. */
BPF_MAP_DEF(dest_alias_map, BPF_MAP_TYPE_HASH, struct in6_addr,
            struct in6_addr, 1024, 0);

/* per-CPU scratch buffer used to initialize new remote_host entries without
 * placing a >512B struct temporary on the BPF stack (NUM_TCP_CONG_ALGS=16
 * makes struct remote_host 792 bytes, exceeding the 512-byte stack limit).
 */
BPF_MAP_DEF(remote_host_scratch, BPF_MAP_TYPE_PERCPU_ARRAY, __u32,
            struct remote_host, 1, 0);

/* if we have not looked up the host >= REMOTE_HOST_MIN_INSTANCES, return NULL.
 * This ensures we only apply RL to hosts with which we have multiple
 * interactions.
 */
static __always_inline struct remote_host *get_remote_host(struct in6_addr *key,
                                                           bool initial)
{
        __u32 zero = 0;
        struct remote_host *remote_host;
        struct remote_host *scratch;

        remote_host = bpf_map_lookup_elem(&remote_host_map, key);
        if (remote_host) {
                if (initial) {
                        /* 0.4.89 (C1): seq-wrap the instances++ so
                         * reanchor's read-modify-write sees the change. */
                        __sync_fetch_and_add(&remote_host->seq, 1);
                        __sync_fetch_and_add(&remote_host->instances, 1);
                        __sync_fetch_and_add(&remote_host->seq, 1);
                }
        } else {
                /* Use per-CPU scratch to avoid a >512B stack temporary.
                 * bpf_map_update_elem copies sizeof(*scratch) bytes from
                 * the kernel-memory scratch buffer into the hash map.
                 */
                scratch = bpf_map_lookup_elem(&remote_host_scratch, &zero);
                if (!scratch)
                        return NULL;
                __builtin_memset(scratch, 0, sizeof(*scratch));
                scratch->instances = 1;
                bpf_map_update_elem(&remote_host_map, key, scratch, BPF_ANY);
                return NULL;
        }
        if (remote_host->instances < REMOTE_HOST_MIN_INSTANCES)
                return NULL;
        return remote_host;
}

/* 0.4.64: explore with probability pct% (0=never, 100=always).
 * Percent-native so both endpoints are exact; that matters when
 * --exp=0 or --exp=100 is used for a controlled trial. */
static __always_inline int
epsilon_greedy_pct(__u32 greedy_state, __u32 num_states, __u32 pct)
{
        __u32 r = bpf_get_prandom_u32();

    if (pct < 100 && (r % 100) >= pct)
                return greedy_state;
        r = bpf_get_prandom_u32();
        return r % num_states;
}

/* 0.4.66: number of votes a freshly-assigned socket is protected
 * from being swapped, as a function of the current explore rate.
 *
 * The protection exists so a rare exploration pick gets a chance
 * to prove itself before the swap engine second-guesses it.  That
 * logic inverts when exploration is most of the traffic: at
 * --exp=100 every socket is a pick, so a fixed 3-vote window
 * protects the entire population and the swap engine never fires.
 *
 * Linear ramp: full 3 votes at the original pct<=5, zero votes at
 * pct>=100.  Read live from tuner_config_map so a --exp change
 * applies consistently to all sockets immediately. */
static __always_inline __u32 explore_protect_votes(void)
{
        __u32 zero = 0;
        __u32 pct = EXPLORE_PCT_DEFAULT;
        __u32 *p = bpf_map_lookup_elem(&tuner_config_map, &zero);
        if (p)
                pct = *p;
        if (pct > EXPLORE_PCT_MAX)
                pct = EXPLORE_PCT_MAX;
        if (pct >= 100)
                return 0;
        return (EXPLORE_PROTECT_VOTES * (100 - pct)) / 95;
}

/* 0.4.79: v4 bucket prefix, read live from tuner_config_map[1].
 * Default 16 = the 0.4.55 /16 merge.  Changing --prefix4 only
 * affects NEW sockets' keys; existing buckets keep their key and
 * their accumulated scores/streaks. */
static __always_inline __u32 bucket_prefix4(void)
{
        __u32 key = 1;
        __u32 pfx = 16;
        __u32 *p = bpf_map_lookup_elem(&tuner_config_map, &key);
        if (p)
                pfx = *p;
        if (pfx < 1)  pfx = 1;
        if (pfx > 32) pfx = 32;
        return pfx;
}
/* 0.4.92: proof thresholds, read live from tuner_config_map[4] and [5].
 * Defaults: PROOF_GOOD_BPS (30 Mbps = 3750000), PROOF_PROVED_BPS (100 Mbps = 12500000).
 * Users can customize via the dashboard /api/config endpoint. */
static __always_inline __u64 get_proof_good_bps(void)
{
    __u32 key = 4;
    __u32 *p = bpf_map_lookup_elem(&tuner_config_map, &key);
    if (p && *p > 0)
        return (__u64)*p;
    return PROOF_GOOD_BPS;
}

static __always_inline __u64 get_proof_proved_bps(void)
{
    __u32 key = 5;
    __u32 *p = bpf_map_lookup_elem(&tuner_config_map, &key);
    if (p && *p > 0)
        return (__u64)*p;
    return PROOF_PROVED_BPS;
}

/* 0.4.79: v6 bucket prefix, read live from tuner_config_map[2].
 * Default 32 = the 0.4.56 /32 merge. */
static __always_inline __u32 bucket_prefix6(void)
{
        __u32 key = 2;
        __u32 pfx = 32;
        __u32 *p = bpf_map_lookup_elem(&tuner_config_map, &key);
        if (p)
                pfx = *p;
        if (pfx < 1)   pfx = 1;
        if (pfx > 128) pfx = 128;
        return pfx;
}


static __noinline void bucket_key_apply_prefix(struct in6_addr *key)
{
        if (key->s6_addr32[2] == bpf_htonl(0xffff)) {
                __u32 pfx = bucket_prefix4();
                __u32 ip_host = bpf_ntohl(key->s6_addr32[3]);
                __u32 mask = pfx ? (0xffffffffu << (32 - pfx)) : 0;
                key->s6_addr32[3] = bpf_htonl(ip_host & mask);
                return;
        }
        /* 0.4.79: v6 side.  pfx 1-128; zero everything after. */
        {
                __u32 pfx = bucket_prefix6();
                __u32 word = pfx / 32;
                __u32 bits = pfx % 32;
                int i;
                for (i = 0; i < 4; i++) {
                        if ((__u32)i < word)
                                continue;
                        if ((__u32)i == word) {
                                if (bits == 0) {
                                        key->s6_addr32[i] = 0;
                                } else {
                                        __u32 m = 0xffffffffu << (32 - bits);
                                        __u32 h = bpf_ntohl(key->s6_addr32[i]);
                                        key->s6_addr32[i] = bpf_htonl(h & m);
                                }
                        } else {
                                key->s6_addr32[i] = 0;
                        }
                }
        }
}

/* 0.4.79: prefer an alias if the operator has declared one for
 * this exact raw destination; otherwise fall through to prefix. */
static __noinline void bucket_key_alias_or_prefix(struct in6_addr *key)
{
        struct in6_addr *a = bpf_map_lookup_elem(&dest_alias_map, key);
        if (a) {
                *key = *a;
                return;
        }
        bucket_key_apply_prefix(key);
        /* 0.4.79: second lookup, this time on the prefix-masked
         * key.  A prefix-form entry in /etc/bpftune/aliases (e.g.
         * "2603:c020:0:0:0:0:0:0 = 89.168.0.0") folds an entire
         * /32 into one canonical bucket.  Exact-address entries
         * still match first, so a specific override inside the
         * range still works. */
        a = bpf_map_lookup_elem(&dest_alias_map, key);
        if (a) {
                *key = *a;
        }
}

static __noinline int set_cong(struct bpf_sock_ops *ops,
                                    struct remote_host *remote_host,
                                    __u8 i)
{
        int ret;

        ret = bpf_setsockopt(ops, SOL_TCP, TCP_CONGESTION, (void *)congs[i],
                             sizeof(congs[i]));
        if (ret)
                return ret;
        /* 0.4.89 (C6): atomic increment; was plain `++` which races
         * across CPUs and undercounts. */
        __sync_fetch_and_add(&tcp_cong_choices[i & (NUM_TCP_CONG_ALGS - 1)], 1);
        /* update state */
        struct bpf_sock *sk = ops->sk;
        struct conn_state *statep;

        if (!sk)
                return 0;
        statep = bpf_sk_storage_get(&sk_storage_map, sk, 0,
                                    BPF_SK_STORAGE_GET_F_CREATE);
        if (statep) {
                /* 0.4.86: init swap_target to 0xff on fresh storage.
                 * Fresh sk_storage is zeroed, so swap_target == 0 (cubic).
                 * score_pending_swap checks for 0xff, so it did not early-return
                 * on fresh sockets.  Every fresh socket triggered score_pending_swap
                 * with tgt=0 (cubic), and if cur_alg != 0, ratio_q was forced to 0
                 * (catastrophic loss for cubic).  This is why cubic was
                 * disproportionately punished. */
                if (statep->last_swap_at == 0) {
                        statep->swap_target = 0xff;
                }
                /* 0.4.44: count socket against alg on first contact. */
                __u8 idx = i & (NUM_TCP_CONG_ALGS - 1);
                __u64 bit = 1ULL << idx;
                if (remote_host && !(statep->touched_bitmap & bit)) {
                        statep->touched_bitmap |= bit;
                        /* 0.4.89 (C1): seq-wrap the proof-counter bump. */
                        __sync_fetch_and_add(&remote_host->seq, 1);
                        remote_host->metrics[idx].sockets_alive++;
                        /* 0.4.62: initialize swap_score to neutral the first time
                         * this algorithm runs on this bucket.  Makes the map
                         * self-describing -- 0 never appears for an untested alg,
                         * so picker and dashboard both trust the raw field. */
                        if (remote_host->metrics[idx].swap_score == 0)
                                remote_host->metrics[idx].swap_score =
                                        SWAP_SCORE_NEUTRAL;
                        __sync_fetch_and_add(&remote_host->seq, 1);
                }
                statep->state = (__u64)i;
                statep->bad_checkpoints = 0;
                /* 0.4.54: exploration pick = neither leader. */
                if (remote_host &&
                    (__u64)i != (remote_host->best_i & (NUM_TCP_CONG_ALGS - 1)) &&
                    (__u64)i != (remote_host->rate_best_i & (NUM_TCP_CONG_ALGS - 1)))
                        statep->exploring = 1;
                else
                        statep->exploring = 0;
                statep->votes_on_alg = 0;
        }
        return 0;
}

__u64 tcp_thin_lto_choices;

SEC("sockops")
int bpftune_conn_tuner(struct bpf_sock_ops *ops)
{
    int cb_flags = BPF_SOCK_OPS_STATE_CB_FLAG|BPF_SOCK_OPS_RETRANS_CB_FLAG|BPF_SOCK_OPS_RTT_CB_FLAG;
    /* 0.4.91: read debug flag from tuner_config_map slot 3 so the
     * CLI can toggle it live via 'bpftune --bpf-debug=0'. */
    {
        __u32 dk = 3;
        __u32 *dv = bpf_map_lookup_elem(&tuner_config_map, &dk);
        if (dv) bpftune_debug = *dv;
    }
    struct remote_host *remote_host;
    struct in6_addr raddr = {};
    struct in6_addr *key = &raddr;
    struct bpf_sock *sk = ops->sk;
    struct conn_state *statep = NULL;

    switch (ops->op) {
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        bpf_sock_ops_cb_flags_set(ops, cb_flags);
        /* 0.4.92fix: clear stale swap_target=0xff from a previous passive
         * connection on the same socket (socket reuse). Without this, an
         * active connection on a reused socket would be incorrectly skipped
         * by the passive-skip check below, causing missing estab events
         * and missing bucket labels on proofs. */
        if (sk) {
            statep = bpf_sk_storage_get(&sk_storage_map, sk, 0, 0);
            if (statep && statep->swap_target == 0xff)
                statep->swap_target = 0;
        }
        break;
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        bpf_sock_ops_cb_flags_set(ops, cb_flags);
        /* 0.4.101: passive connections (incoming to xray/nginx on 443)
         * MUST go through set_cong() — in this topology the VPS is the
         * SENDER (pushing video downstream to home clients), so the
         * local CC controls the send rate. The 0.4.92 assumption
         * ("server is receiver") was wrong for proxy traffic.
         *
         * We still create statep here so it exists when the vote
         * handler runs, but we do NOT set swap_target=0xff — that
         * was the flag that caused line 380 to skip all tracking. */
        if (sk) {
            statep = bpf_sk_storage_get(&sk_storage_map, sk, 0,
                                        BPF_SK_STORAGE_GET_F_CREATE);
        }
        break;
    case BPF_SOCK_OPS_RETRANS_CB:
        if (ops->total_retrans > (ops->segs_out >> DROP_SHIFT)) {
            if (sk)
                statep = bpf_sk_storage_get(&sk_storage_map, sk, 0, 0);
            if (!statep && !tcp_thin_lto) {
                int one = 1;
                if (!bpf_setsockopt(ops, SOL_TCP, TCP_THIN_LINEAR_TIMEOUTS,
                                    &one, sizeof(one)))
                    /* 0.4.89 (C6): atomic increment; was plain `++`. */
                    __sync_fetch_and_add(&tcp_thin_lto_choices, 1);
            }
        }
        return 1;
    default:
        return 1;
    }

    /* 0.4.92: skip all tracking for passive (incoming) connections */
    if (statep && statep->swap_target == 0xff)
        return 1;

    if (!sk)
        return 1;
    /* 0.4.94: detect IPv4-mapped IPv6 (::ffff:0:0/96) — happens when a
     * dual-stack AF_INET6 socket (the Linux default with IPV6_V6ONLY=0)
     * connects to an IPv4 peer.  Without this, v4-in-v6 connections
     * bypass the AF_INET path and get bucketed under ::/32 (all-zero
     * after prefix6 masking), lumping every v4 peer into a single
     * useless bucket.  Fold to v4 here so the same peer shares its
     * bucket regardless of which socket family the app used. */
    bool is_v4_mapped = false;
    __u32 v4_addr_from_v6 = 0;
    if (ops->family == AF_INET) {
        __u32 ip4 = bpf_ntohl(ops->remote_ip4);
        /* 0.4.95: skip RFC 1918 + special-use v4 ranges.  These are
         * either loopback, link-local, private LAN, or documentation
         * ranges — none of them benefit from congestion-control
         * tuning (they're either local or never route over the
         * internet).  Previously only 127.0.0.0/8 + 169.254.0.0/16
         * were skipped, so LAN traffic showed up in the dashboard
         * as '192.168.0.0' or '10.0.0.0' buckets — useless noise. */
        if ((ip4 & 0xff000000) == 0x7f000000) return 1;  /* 127.0.0.0/8 loopback */
        if ((ip4 & 0xffff0000) == 0xa9fe0000) return 1;  /* 169.254.0.0/16 link-local */
        if ((ip4 & 0xff000000) == 0x0a000000) return 1;  /* 10.0.0.0/8 private */
        if ((ip4 & 0xfff00000) == 0xac100000) return 1;  /* 172.16.0.0/12 private */
        if ((ip4 & 0xffff0000) == 0xc0a80000) return 1;  /* 192.168.0.0/16 private */
        if ((ip4 & 0xffff0000) == 0xc0000000) return 1;  /* 0.0.0.0/16 reserved */
        if ((ip4 & 0xffff0000) == 0xc000a800) return 1;  /* 192.0.2.0/24 documentation */
        if ((ip4 & 0xffff0000) == 0xc6120000) return 1;  /* 198.18.0.0/15 benchmark */
        if ((ip4 & 0xfffffe00) == 0xc6336400) return 1;  /* 198.51.100.0/24 documentation */
        if ((ip4 & 0xffff0000) == 0xcb007100) return 1;  /* 203.0.113.0/24 documentation */
    } else if (ops->family == AF_INET6) {
        if (ops->remote_ip6[0] == 0 && ops->remote_ip6[1] == 0 && ops->remote_ip6[2] == 0 && ops->remote_ip6[3] == bpf_htonl(1)) return 1;
        if ((ops->remote_ip6[0] & bpf_htonl(0xffc00000)) == bpf_htonl(0xfe800000)) return 1;
        /* 0.4.95: skip IPv6 ULA (fc00::/7), multicast (ff00::/8), and
         * documentation (2001:db8::/32).  These are either private or
         * not routable on the public internet. */
        if ((ops->remote_ip6[0] & bpf_htonl(0xfe000000)) == bpf_htonl(0xfc000000)) return 1;
        if ((ops->remote_ip6[0] & bpf_htonl(0xff000000)) == bpf_htonl(0xff000000)) return 1;
        if (ops->remote_ip6[0] == bpf_htonl(0x20010db8)) return 1;
        /* 0.4.94: IPv4-mapped IPv6 (::ffff:a.b.c.d).  remote_ip6[2]
         * in network byte order is 0xffff0000 when read as __u32,
         * but we compare against bpf_htonl(0xffff) which is the
         * network-byte-order form of 0x0000ffff.  Both are equal on
         * any endian CPU because bpf_htonl handles the swap. */
        if (ops->remote_ip6[0] == 0 && ops->remote_ip6[1] == 0 &&
            ops->remote_ip6[2] == bpf_htonl(0xffff)) {
            is_v4_mapped = true;
            v4_addr_from_v6 = ops->remote_ip6[3];
            /* 0.4.95: apply the same RFC 1918 + special-use v4 filter
             * to the v4 address extracted from v4-in-v6 form.  Without
             * this, LAN traffic over a dual-stack socket would slip
             * past the AF_INET filter above. */
            __u32 ip4 = bpf_ntohl(v4_addr_from_v6);
            if ((ip4 & 0xff000000) == 0x7f000000) return 1;
            if ((ip4 & 0xffff0000) == 0xa9fe0000) return 1;
            if ((ip4 & 0xff000000) == 0x0a000000) return 1;
            if ((ip4 & 0xfff00000) == 0xac100000) return 1;
            if ((ip4 & 0xffff0000) == 0xc0a80000) return 1;
            if ((ip4 & 0xffff0000) == 0xc0000000) return 1;
            if ((ip4 & 0xffff0000) == 0xc000a800) return 1;
            if ((ip4 & 0xffff0000) == 0xc6120000) return 1;
            if ((ip4 & 0xfffffe00) == 0xc6336400) return 1;
            if ((ip4 & 0xffff0000) == 0xcb007100) return 1;
        }
    }
    switch (ops->family) {
    case AF_INET:
        /* 0.4.79: don't pre-mask; bucket_key_apply_prefix() applies
         * the configured prefix (default 16 = old /16 behavior). */
        key->s6_addr32[2] = bpf_htonl(0xffff);
        key->s6_addr32[3] = ops->remote_ip4;
        break;
    case AF_INET6:
        if (is_v4_mapped) {
            /* 0.4.94: route v4-in-v6 through the v4 bucket path so
             * the same peer shares a bucket regardless of socket
             * family.  bucket_key_apply_prefix will use prefix4
             * (default /16) since s6_addr32[2] is 0xffff. */
            key->s6_addr32[2] = bpf_htonl(0xffff);
            key->s6_addr32[3] = v4_addr_from_v6;
        } else {
            /* 0.4.79: keep the full address; bucket_key_apply_prefix()
             * masks to the configured prefix6 (default 32 = the old /32). */
            key->s6_addr32[0] = ops->remote_ip6[0];
            key->s6_addr32[1] = ops->remote_ip6[1];
            key->s6_addr32[2] = ops->remote_ip6[2];
            key->s6_addr32[3] = ops->remote_ip6[3];
        }
        break;
    default:
        return 1;
    }
    bucket_key_alias_or_prefix(key);
    remote_host = get_remote_host(key, true);
    if (!remote_host)
        return 1;

    {
        __u64 metric_min = ~((__u64)0x0);
        __u8 i, minindex = 0, s;

        if (remote_host->selection_count < 2 * NUM_TCP_CONN_METRICS) {
            __u8 forced = remote_host->selection_count & (NUM_TCP_CONN_METRICS - 1);
            /* 0.4.89 (C1): seq-wrap selection_count++. */
            __sync_fetch_and_add(&remote_host->seq, 1);
            remote_host->selection_count++;
            __sync_fetch_and_add(&remote_host->seq, 1);
            if (set_cong(ops, remote_host, forced)) {
                remote_host->metrics[forced].metric_value = ~((__u64)0);
            } else {
                if (bpftune_debug)
                /* 0.4.94: for v4-in-v6 connections, ops->remote_ip4 is 0
                 * (the kernel only fills it for AF_INET).  Log the v4
                 * address we extracted from remote_ip6[3] instead so the
                 * dashboard's cdest map gets the right dest= field. */
                bpf_printk("estab cookie=%llu alg=%u forced=1 dest=%u dest6=%u dest6b=%u",
                           bpf_get_socket_cookie(ops), (__u32)forced,
                           is_v4_mapped ? (__u32)bpf_ntohl(v4_addr_from_v6) : (__u32)bpf_ntohl(ops->remote_ip4),
                           (__u32)bpf_ntohl(ops->remote_ip6[0]), (__u32)bpf_ntohl(ops->remote_ip6[1]));
            }
            return 1;
        }

        {
            __u64 min2 = ~((__u64)0);
            for (i = 0; i < NUM_TCP_CONN_METRICS; i++) {
                __u64 v = remote_host->metrics[i].metric_value;
                /* Sentinel metrics (0 unset, ~0 poisoned) may win
                 * the min loop here and be reported as minindex,
                 * but the consumer below checks metric_count > 0
                 * and the vote path guards with v != 0 && v != ~0.
                 * A skip filter here blew the verifier to the 1M
                 * instruction limit (16-way unrolled loop,
                 * unprovable ranges), so it is intentionally omitted.
                 * (v0.4.102: restored this v0.4.98 comment — the
                 * v0.4.99 skip filter caused E2BIG load failure.) */
                if (v < metric_min) {
                    min2 = metric_min;
                    metric_min = v;
                    minindex = i;
                } else if (v < min2) {
                    min2 = v;
                }
            }
            minindex &= (NUM_TCP_CONN_METRICS - 1);
            /* Re-anchor the swap-target tracker to the true best on every
             * ESTABLISHED.  The incremental update in the vote path only
             * compares best vs second, so a third algorithm can drift into
             * a lower position without ever being promoted through the
             * pair.  No new variables — the loop already found minindex
             * and metric_min; we just persist them. */
            if (remote_host->metrics[minindex].metric_count > 0 &&
                metric_min != 0 && metric_min != ~((__u64)0)) {
                __sync_fetch_and_add(&remote_host->seq, 1);
                remote_host->best_i = minindex;
                remote_host->best_v = metric_min;
                __sync_fetch_and_add(&remote_host->seq, 1);
            } else {
                __sync_fetch_and_add(&remote_host->seq, 1);
                remote_host->best_v = 0;
                __sync_fetch_and_add(&remote_host->seq, 1);
            }
            {
                __u32 zero = 0;
                __u32 pct = EXPLORE_PCT_DEFAULT;
                __u32 *pctp = bpf_map_lookup_elem(&tuner_config_map, &zero);
                if (pctp)
                    pct = *pctp;
                if (pct > EXPLORE_PCT_MAX)
                    pct = EXPLORE_PCT_MAX;
                /* 0.4.22 tight-bucket boost: at --exp=100 the boost
                 * is a no-op because pct is already 100. */
                if ((min2 == ~((__u64)0) || metric_min * 5 > min2 * 4) &&
                    pct < EXPLORE_BOOST_PCT)
                    pct = EXPLORE_BOOST_PCT;
                s = epsilon_greedy_pct(minindex, NUM_TCP_CONN_METRICS, pct);
            }

            s &= (NUM_TCP_CONG_ALGS - 1);
            if (set_cong(ops, remote_host, s)) {
                remote_host->metrics[s].metric_value = ~((__u64)0);
            } else {
                if (bpftune_debug)
                bpf_printk("estab cookie=%llu alg=%u forced=0 dest=%u dest6=%u dest6b=%u",
                           bpf_get_socket_cookie(ops), (__u32)s,
                           is_v4_mapped ? (__u32)bpf_ntohl(v4_addr_from_v6) : (__u32)bpf_ntohl(ops->remote_ip4),
                           (__u32)bpf_ntohl(ops->remote_ip6[0]), (__u32)bpf_ntohl(ops->remote_ip6[1]));
            }
        }
    }
    return 1;
}

/* 0.4.56: score the pending swap once >=60s have elapsed.  Cur rate
 * vs the captured pre-swap rate sets target alg's swap_score; 256 is
 * neutral.  Called from the vote path.
 *
 * 0.4.89: also called from the close path if elapsed >= 30s (C3).
 * Closes the gap where a socket swapped then closed before its next
 * segment-rung vote -- the pending swap was never scored.
 *
 * 0.4.89 (Q3): the score/streak update logic is now in
 * apply_swap_outcome() in the header; this function computes ratio_q
 * per its gating rules and delegates. */
static __noinline void
score_pending_swap(struct bpf_sock_ops *ops, struct remote_host *rh,
                   struct conn_state *statep, __u64 now,
                   __u8 cur_alg)
{
        __u8 tgt;
        __u64 pre, elapsed, ratio_q;

        if (statep->swap_target == 0xff) return;
        /* 0.4.84: use rate_ema as fallback when pre_swap_rate=0
         * (app-limited connections). Without this, the swap is
         * never scored and swap_score stays at default 256. */
        elapsed = now - statep->last_swap_at;
        if (elapsed < SWAP_OUTCOME_MIN_RNAL_NS) return;

        tgt = (__u8)(statep->swap_target & (NUM_TCP_CONG_ALGS - 1));
        if (statep->pre_swap_rate == 0) {
                /* 0.4.86: convert rate_ema from 100KB/s units to B/s.
                 * rate_ema is stored as rate_delivered / RATE_EMA_BYTES_PER_UNIT
                 * (100000).  post_swap_rate_max is in raw B/s.  Without
                 * conversion, ratio was ~100000x too high -> always a win. */
                pre = (__u64)rh->metrics[tgt].rate_ema * RATE_EMA_BYTES_PER_UNIT;
                if (pre == 0) return;
        } else {
                pre = statep->pre_swap_rate;
        }
        /* 0.4.65: if the socket is no longer on the pending target,
         * the swap was rejected before the 60s window opened.  Force
         * the ratio to loss-class regardless of the current rate.
         * This closes the case where a socket swapped A->B at T=0 and
         * B->C at T=30: without this check, the T+60 sample would read
         * C's rate and attribute it to B. */
        if (cur_alg != tgt) {
                ratio_q = 0;
        } else {
                ratio_q = pre ? (statep->post_swap_rate_max * SWAP_SCORE_NEUTRAL) / pre : 0;
                if (ratio_q > 1024) ratio_q = 1024;
        }

        /* 0.4.90: if post_swap_rate_max is 0, the rate window never
         * populated post-swap (app-limited, idle, or short-lived socket).
         * Scoring this as a loss (ratio_q=0) hammers scores to near-zero
         * during cold start.  Skip — the swap has no measurable outcome.
         * swap_target stays pending; the next vote will retry with more
         * data.  If the socket closes, C3 will retry on close. */
        if (statep->post_swap_rate_max == 0 && cur_alg == tgt) {
                if (bpftune_debug)
                        bpf_printk("swapscore cookie=%llu tgt=%u skip (no post-swap rate)",
                                   bpf_get_socket_cookie(ops), (__u32)tgt);
                return;
        }

        /* 0.4.89 (C1 + Q3): seq-wrap the delegated swap-outcome update. */
        __sync_fetch_and_add(&rh->seq, 1);
        apply_swap_outcome(rh, tgt, ratio_q);
        __sync_fetch_and_add(&rh->seq, 1);
        if (bpftune_debug)
                bpf_printk("swapscore cookie=%llu tgt=%u ratio=%llu bad=%u null=%u",
                           bpf_get_socket_cookie(ops), (__u32)tgt, ratio_q,
                           (__u32)rh->metrics[tgt].bad_streak,
                           (__u32)rh->metrics[tgt].null_streak);
        statep->swap_target = 0xff;
        statep->pre_swap_rate = 0;
}

/* 0.4.65: called from a swap site when we are about to replace an
 * earlier pending swap that had not yet been scored.  Fewer than 60s
 * elapsed since the previous swap, so the rate-ratio gate in
 * score_pending_swap would refuse to fire.  The fact that the socket
 * is being swapped away is itself the outcome: the previous target
 * was rejected.  Attribute an immediate loss-class update to it.
 *
 * The caller always overwrites statep->swap_target and pre_swap_rate
 * with the new pending values right after this call, so no clearing
 * is done here.
 *
 * 0.4.89 (M2): dropped the unused cur_rate parameter; the function
 * uses post_swap_rate_max (the peak across the post-swap window),
 * not a momentary rate.
 *
 * 0.4.89 (Q3): score/streak update delegated to apply_swap_outcome.
 * Note: score_pending_rejected caps ratio_q at 230 if <30s elapsed
 * (the "last chance" gate), so the win path in apply_swap_outcome
 * (ratio_q >= 282) only fires if >=30s elapsed AND the socket
 * happened to deliver >110% of pre-swap -- rare for a rejected swap
 * but possible.
 *
 * 0.4.89 (M3): the 30s threshold here vs 180s in score_pending_swap
 * is intentional.  score_pending_swap scores a COMPLETED swap
 * (socket stayed on the target); 180s lets slow-start settle.
 * score_pending_rejected scores a PREEMPTED swap (socket left the
 * target); 30s is the "last chance" -- if at least 30s of post-swap
 * data exists, use the actual ratio; otherwise force loss-class. */
static __noinline void
score_pending_rejected(struct bpf_sock_ops *ops, struct remote_host *rh,
                       struct conn_state *statep, __u64 now)
{
        __u8 tgt;
        __u64 pre, ratio_q;

        if (statep->swap_target == 0xff) return;
        if (statep->pre_swap_rate == 0)  return;

        pre = statep->pre_swap_rate;
        tgt = (__u8)(statep->swap_target & (NUM_TCP_CONG_ALGS - 1));

        /* Force loss-class.  Cap at 230 (ratio <= 0.9) even if the
         * current rate happens to look high; the socket leaving the
         * target is the signal, not the momentary rate. */
        ratio_q = pre ? (statep->post_swap_rate_max * SWAP_SCORE_NEUTRAL) / pre : 0;
        /* 0.4.90: if post_swap_rate_max is 0, no measurable rate was
         * produced before the socket was swapped away.  Treat as null
         * (ratio_q=256) rather than loss — the swap was inconclusive. */
        if (statep->post_swap_rate_max == 0)
                ratio_q = SWAP_SCORE_NEUTRAL;
        /* 0.4.82: last-chance — use actual ratio if >=30s elapsed */
        if ((now - statep->last_swap_at) < LAST_CHANCE_MIN_NS)
                if (ratio_q > 230) ratio_q = 230;

        /* 0.4.89 (C1 + Q3): seq-wrap the delegated swap-outcome update. */
        __sync_fetch_and_add(&rh->seq, 1);
        apply_swap_outcome(rh, tgt, ratio_q);
        __sync_fetch_and_add(&rh->seq, 1);

        if (bpftune_debug)
                bpf_printk("swapscore-reject cookie=%llu tgt=%u ratio=%llu bad=%u null=%u",
                           bpf_get_socket_cookie(ops), (__u32)tgt, ratio_q,
                           (__u32)rh->metrics[tgt].bad_streak);
}

SEC("sockops")
int bpftune_conn_tuner_vote(struct bpf_sock_ops *ops)
{
    struct remote_host *remote_host;
    struct in6_addr raddr = {};
    struct in6_addr *key = &raddr;
    struct bpf_sock *sk = ops->sk;
    struct tcp_sock *tp = NULL;
    struct conn_state *statep = NULL;
    __u64 *nextp;
    __u64 segs, next;
    struct tcp_sock *tps;
    __u64 smin, savg, srate, srate_raw, smss, sinter;
    __u64 metric, min_rtt, avg_rtt, rate_interval_us, rate_delivered, mss;
    __u64 sustained_bps;
    struct tcp_conn_metric *m;
    bool greedy = true;
    __u8 s;
    bool is_close;
    __u64 now;
    bool allow_ref = false;
    __u64 tc_progress = 0;

    /* 0.4.91: read debug flag from tuner_config_map slot 3 so the
     * CLI can toggle it live via 'bpftune --bpf-debug=0'. */
    {
        __u32 dk = 3;
        __u32 *dv = bpf_map_lookup_elem(&tuner_config_map, &dk);
        if (dv) bpftune_debug = *dv;
    }

    switch (ops->op) {
    case BPF_SOCK_OPS_RTT_CB: {
        bool time_check = false;
        if (!sk)
            return 1;
        tps = bpf_skc_to_tcp_sock(sk);
        if (!tps)
            return 1;
        nextp = bpf_sk_storage_get(&midsamp_map, sk, 0,
                                   BPF_SK_STORAGE_GET_F_CREATE);
        if (!nextp)
            return 1;
        next = *nextp;
        if (!next)
            next = 1000;
        segs = (__u64)ops->segs_out + (__u64)ops->segs_in;
        if (segs < next) {
            /* Not at a segment checkpoint.  Time-based vote: fires when
             * 60s have elapsed and the socket advanced since last check.
             * Keeps long-lived sockets responsive once they are past
             * the 1M segment rung (where nextp is ~0). */
            statep = bpf_sk_storage_get(&sk_storage_map, sk, 0, 0);
            if (!statep)
                return 1;
            now = bpf_ktime_get_ns();
            if (now - statep->last_time_check < T_TIME_CHECK_NS ||
                segs < statep->time_check_segs + TIME_CHECK_MIN_SEGS)
                return 1;
            tc_progress = segs - statep->time_check_segs;
            statep->last_time_check = now;
            statep->time_check_segs = segs;
            time_check = true;
            /* Vote fires at TIME_CHECK_MIN_SEGS (1000) but the
             * reference only moves at REF_TIME_CHECK_MIN_SEGS (2000):
             * control-plane sockets cannot sustain that. */
            allow_ref = (tc_progress >= REF_TIME_CHECK_MIN_SEGS);
        }
        if (!time_check) {
            smin = (__u64)tps->rtt_min.s[0].v;
            savg = (__u64)(tps->srtt_us >> 3);
            sinter = (__u64)tps->rate_interval_us;
            srate_raw = (__u64)tps->rate_delivered;
            smss = (__u64)tps->mss_cache;
            srate = sinter ? (srate_raw * smss * 1000000ULL) / sinter : 0;
            {
                /* 0.4.46: include the current alg so userspace can
                 * credit this srate sample directly, without joining
                 * through a possibly-stale recent met line.  statep
                 * is not yet populated on this code path, so look it
                 * up here. */
                struct conn_state *sp_al = bpf_sk_storage_get(&sk_storage_map, sk, 0, 0);
                int alg_idx = sp_al ? (int)(sp_al->state & (NUM_TCP_CONG_ALGS - 1)) : -1;
                if (bpftune_debug)
                bpf_printk("midsamp cookie=%llu port=%u rport=%u alg=%d thr=%llu segs=%llu smin=%llu savg=%llu srate=%llu",
                           bpf_get_socket_cookie(ops), ops->local_port, bpf_ntohl(ops->remote_port),
                           alg_idx, next, segs, smin, savg, srate);
            }
            switch (next) {
            case 1000:   *nextp = 5000;    break;
            case 5000:   *nextp = 10000;   break;
            case 10000:  *nextp = 25000;   break;
            case 25000:  *nextp = 100000;  break;
            case 100000: *nextp = 500000;  break;
            case 500000: *nextp = 1000000; break;
            default:     *nextp = ~((__u64)0);
            }
            if (next < METRIC_TRIGGER_SEGS)
                return 1;
            /* Segment-rung vote: next >= METRIC_TRIGGER_SEGS (10K),
             * so the socket demonstrated sustained transfer. */
            allow_ref = true;
        }
        break;
    }
    case BPF_SOCK_OPS_STATE_CB: {
        int state = ops->args[1];
        switch (state) {
        case BPF_TCP_FIN_WAIT1:
        case BPF_TCP_CLOSE_WAIT:
            break;
        default:
            return 1;
        }
        break;
    }
    default:
        return 1;
    }

    if (!sk)
        return 1;
    tp = bpf_skc_to_tcp_sock(sk);
    /* 0.4.94: detect IPv4-mapped IPv6 (see comment in active_estab path). */
    bool is_v4_mapped = false;
    __u32 v4_addr_from_v6 = 0;
    if (ops->family == AF_INET) {
        __u32 ip4 = bpf_ntohl(ops->remote_ip4);
        /* 0.4.95: skip RFC 1918 + special-use v4 ranges (see active_estab). */
        if ((ip4 & 0xff000000) == 0x7f000000) return 1;
        if ((ip4 & 0xffff0000) == 0xa9fe0000) return 1;
        if ((ip4 & 0xff000000) == 0x0a000000) return 1;
        if ((ip4 & 0xfff00000) == 0xac100000) return 1;
        if ((ip4 & 0xffff0000) == 0xc0a80000) return 1;
        if ((ip4 & 0xffff0000) == 0xc0000000) return 1;
        if ((ip4 & 0xffff0000) == 0xc000a800) return 1;
        if ((ip4 & 0xffff0000) == 0xc6120000) return 1;
        if ((ip4 & 0xfffffe00) == 0xc6336400) return 1;
        if ((ip4 & 0xffff0000) == 0xcb007100) return 1;
    } else if (ops->family == AF_INET6) {
        if (ops->remote_ip6[0] == 0 && ops->remote_ip6[1] == 0 && ops->remote_ip6[2] == 0 && ops->remote_ip6[3] == bpf_htonl(1)) return 1;
        if ((ops->remote_ip6[0] & bpf_htonl(0xffc00000)) == bpf_htonl(0xfe800000)) return 1;
        /* 0.4.95: skip ULA + multicast + documentation (see active_estab). */
        if ((ops->remote_ip6[0] & bpf_htonl(0xfe000000)) == bpf_htonl(0xfc000000)) return 1;
        if ((ops->remote_ip6[0] & bpf_htonl(0xff000000)) == bpf_htonl(0xff000000)) return 1;
        if (ops->remote_ip6[0] == bpf_htonl(0x20010db8)) return 1;
        if (ops->remote_ip6[0] == 0 && ops->remote_ip6[1] == 0 &&
            ops->remote_ip6[2] == bpf_htonl(0xffff)) {
            is_v4_mapped = true;
            v4_addr_from_v6 = ops->remote_ip6[3];
            /* 0.4.95: apply RFC 1918 + special-use filter to v4-in-v6 form. */
            __u32 ip4 = bpf_ntohl(v4_addr_from_v6);
            if ((ip4 & 0xff000000) == 0x7f000000) return 1;
            if ((ip4 & 0xffff0000) == 0xa9fe0000) return 1;
            if ((ip4 & 0xff000000) == 0x0a000000) return 1;
            if ((ip4 & 0xfff00000) == 0xac100000) return 1;
            if ((ip4 & 0xffff0000) == 0xc0a80000) return 1;
            if ((ip4 & 0xffff0000) == 0xc0000000) return 1;
            if ((ip4 & 0xffff0000) == 0xc000a800) return 1;
            if ((ip4 & 0xffff0000) == 0xc6120000) return 1;
            if ((ip4 & 0xfffffe00) == 0xc6336400) return 1;
            if ((ip4 & 0xffff0000) == 0xcb007100) return 1;
        }
    }
    switch (ops->family) {
    case AF_INET:
        /* 0.4.79: raw; helper applies the configured prefix. */
        key->s6_addr32[2] = bpf_htonl(0xffff);
        key->s6_addr32[3] = ops->remote_ip4;
        break;
    case AF_INET6:
        if (is_v4_mapped) {
            /* 0.4.94: route v4-in-v6 through the v4 bucket path. */
            key->s6_addr32[2] = bpf_htonl(0xffff);
            key->s6_addr32[3] = v4_addr_from_v6;
        } else {
            /* 0.4.79: keep the full address; bucket_key_apply_prefix()
             * masks to the configured prefix6 (default 32 = the old /32). */
            key->s6_addr32[0] = ops->remote_ip6[0];
            key->s6_addr32[1] = ops->remote_ip6[1];
            key->s6_addr32[2] = ops->remote_ip6[2];
            key->s6_addr32[3] = ops->remote_ip6[3];
        }
        break;
    default:
        return 1;
    }
    bucket_key_alias_or_prefix(key);
    remote_host = get_remote_host(key, false);
    if (!remote_host)
        return 1;
    if (!tp)
        return 1;

    is_close = (ops->op == BPF_SOCK_OPS_STATE_CB);
    statep = bpf_sk_storage_get(&sk_storage_map, sk, 0, 0);
    if (!statep)
        return 1;
    /* 0.4.97: REVERTED v0.4.96's passive skip in the vote path.
     * v0.4.96 added 'if (!is_close && statep->swap_target == 0xff) return 1;'
     * here, which skipped ALL vote processing for passive connections.
     * This caused the busiest hosts (mostly passive/incoming traffic
     * to xray/nginx) to show ZERO proofs in the dashboard — a serious
     * regression.
     *
     * The original v0.4.92 passive skip in active_estab (line 380) is
     * KEPT — it prevents estab events from being logged for passive
     * connections, which is correct (no dest info to capture).
     *
     * The 'proofs show empty dest' bug was actually fixed by:
     *   1. cookie_dest.json persistence (v0.9.0 dashboard) — cookies
     *      from old estab events survive log rotation
     *   2. Log rotation after deploy — clears old passive-connection
     *      proofs that had no estab events
     *   3. New active connections populate cookie_dest.json naturally
     *
     * So passive connections SHOULD fire proofs — they're valid
     * measurements of "did this algorithm achieve high rate?"
     * The dest for passive connections won't be in cookie_dest.json
     * (no estab event), but that's OK — the dashboard shows
     * '(unknown)' for those, which is better than not showing them
     * at all. */
        /* 0.4.44: decrement proof counters once per socket.
         * Only runs on STATE_CB close (is_close).  Placed before the
         * METRIC_MIN_SEGS / origin-facing early returns below so that
         * short-lived and receive-dominant sockets decrement too --
         * otherwise the sockets we most care about never decrement.
         * cleaned flag is idempotent across the FIN_WAIT1 /
         * CLOSE_WAIT double-fire. */
        if (is_close && !statep->cleaned) {
                /* Shift accumulator: constant step (bit <<= 1 per
                 * iteration) rather than a variable shift amount.
                 * #pragma unroll flattens to 16 straight-line blocks.
                 * Close is a cold path so the size is fine. */
                __u64 bit = 1;
                /* 0.4.89 (C1): seq-wrap the whole close-decrement loop.
                 * One seq pair around the 16-iter loop is enough -- the
                 * intermediate state is never read by userspace mid-loop
                 * (reanchor reads the whole struct atomically via lookup). */
                __sync_fetch_and_add(&remote_host->seq, 1);
                for (int b = 0; b < NUM_TCP_CONG_ALGS; b++) {
                        /* Guarded decrement: if the remote_host entry was
                         * LRU-evicted + recreated while this socket lived,
                         * its counters were reset to 0; an unguarded --
                         * would wrap to 2^64-1.  Guard costs nothing in
                         * the common case. */
                        if ((statep->touched_bitmap & bit) &&
                            remote_host->metrics[b].sockets_alive > 0)
                                remote_host->metrics[b].sockets_alive--;
                        if ((statep->good_bitmap & bit) &&
                            remote_host->metrics[b].sockets_good > 0)
                                remote_host->metrics[b].sockets_good--;
                        if ((statep->proved_bitmap & bit) &&
                            remote_host->metrics[b].sockets_proved > 0)
                                remote_host->metrics[b].sockets_proved--;
                        bit <<= 1;
                }
                __sync_fetch_and_add(&remote_host->seq, 1);
                statep->cleaned = 1;
        }
    s = statep->state & (NUM_TCP_CONG_ALGS - 1);
    if ((__u64)tp->segs_out + tp->segs_in < METRIC_MIN_SEGS)
        return 1;
    /* 0.4.42: skip sockets where we are primarily receiving.  On an
     * origin-facing socket the tuner receives video from a CDN and
     * only sends requests and ACKs; the local CC state does not
     * control the download rate, so a vote there scores on a
     * quantity the algorithm did not set and a swap cannot help.
     * Measured 2026-09-16: 57.7% of swaps were origin-facing; on
     * 2026-09-17 morning, 88%.
     *
     * Uses data_segs_* not segs_*.  segs_out counts pure ACKs, and
     * on a receiving socket ACKs dominate segs_out, so the first cut
     * (segs_out * 4 < segs_in) never fired -- 0.4.41 measured 95.5%
     * origin-facing post-deploy, unchanged from before the gate.
     * data_segs_out excludes ACKs and measures actual data direction:
     * origin socket segs_out=2709/segs_in=9564 but
     * data_segs_out=126/data_segs_in=9492; client socket the mirror.
     * Client-facing sockets have data_segs_out >= data_segs_in. */
    /* 0.4.67: port gate reverted.
     *
     * 0.4.64 filtered remote_port==443 || 80 to skip origin-facing
     * sockets, assuming VPS initiates to the CDN.  On this topology
     * the CLIENT-FACING socket is VPS->home:443, so the port test
     * dropped every socket we wanted to tune; the swap rate was
     * unchanged from 5% to 100% explore because the client side
     * never reached the vote path.
     *
     * Falls back to the 0.4.42 data_segs direction heuristic: VPS
     * sends video down (data_segs_out high) on the socket to home,
     * receives video on the socket from the CDN (data_segs_in high).
     * That leaked ~9% when measured in the 0.4.63 window -- real,
     * but two orders of magnitude better than dropping the client
     * side.  Any future direction test MUST be validated against
     * this topology: remote_port is not a reliable discriminator
     * when the VPS is the server on 443. */
    if ((__u64)tp->data_segs_out * 4 < (__u64)tp->data_segs_in)
        return 1;
    if (is_close && bpftune_debug)
        bpf_printk("closport cookie=%llu port=%u rport=%u alg=%u segs=%llu",
                   bpf_get_socket_cookie(ops), ops->local_port,
                   bpf_ntohl(ops->remote_port),
                   (__u32)(statep->state & (NUM_TCP_CONG_ALGS - 1)),
                   (__u64)tp->segs_out + tp->segs_in);
    /* 0.4.89 (C3): score the pending swap on close if >=30s elapsed.
     * Without this, a socket that swapped then closed before its next
     * segment-rung vote was never scored -- the pending swap_target
     * stayed at the un-scored value, swap_score and streaks weren't
     * updated.  Uses the 30s gate (LAST_CHANCE_MIN_NS) matching
     * score_pending_rejected's last-chance window; score_pending_swap
     * internally re-checks the 180s gate (SWAP_OUTCOME_MIN_RNAL_NS)
     * and early-returns if <180s, so we need the 30s outer gate to
     * catch the 30-180s window where score_pending_swap itself would
     * refuse.  For <30s, the swap is too fresh to score -- skip.
     *
     * Note: score_pending_swap uses the cur_alg != tgt check to force
     * loss-class if the socket moved away from the target.  On close,
     * cur_alg is whatever the socket ended on, which may or may not
     * be the pending target.  The check still works correctly. */
    if (is_close && statep->swap_target != 0xff) {
        __u64 close_now = bpf_ktime_get_ns();
        if (close_now - statep->last_swap_at >= LAST_CHANCE_MIN_NS)
            score_pending_swap(ops, remote_host, statep, close_now, s);
    }
    if (is_close &&
        (__u64)tp->segs_out + tp->segs_in >= METRIC_TRIGGER_SEGS)
        return 1;
    min_rtt = (__u64)tp->rtt_min.s[0].v;
    avg_rtt = (__u64)(tp->srtt_us >> 3);
    /* v0.4.103: Record min_rtt for ALL connections — including
     * receive-only (YouTube, etc.) — BEFORE the direction gate below.
     * This gives the route monitor real RTT data from actual connections
     * for all destinations, not just the ones where the VPS is the sender.
     * One comparison + one assignment. No swapping, no metric accumulation. */
    if (min_rtt > 0 && (!remote_host->min_rtt || min_rtt < remote_host->min_rtt))
        remote_host->min_rtt = min_rtt;
    rate_interval_us = (__u64)tp->rate_interval_us;
    mss = (__u64)tp->mss_cache;
    /* 0.4.71: two distinct signals.
     *
     *   sustained_bps  = bytes acked+received / wall clock.  Health.
     *   Feeds last_rate_bps (util gate, swap trigger), the score
     *   update, and the composite metric.
     *
     *   rate_delivered = (tp->rate_delivered * mss) / rate_interval_us.
     *   Capability.  Feeds rate_ema (bucket leaderboard, pass-3 target
     *   pick) and the proof counters.  May go stale on a quiet socket;
     *   its job is what the algorithm has proven it can do, not what
     *   the socket is doing right now. */
    {
        __u64 now_ns = bpf_ktime_get_ns();
        __u64 bytes_total = (__u64)tp->bytes_acked +
                            (__u64)tp->bytes_received;
        if (statep && statep->rate_win_ts_ns) {
            __u64 elapsed = now_ns - statep->rate_win_ts_ns;
            if (elapsed >= RATE_WIN_MIN_NS) {
                __u64 bytes_delta = bytes_total - statep->rate_win_bytes;
                sustained_bps = (bytes_delta * 1000000000ULL) / elapsed;
                statep->rate_win_ts_ns = now_ns;
                statep->rate_win_bytes = bytes_total;
            } else {
                sustained_bps = statep->last_rate_bps;
            }
        } else {
            if (statep) {
                statep->rate_win_ts_ns = now_ns;
                statep->rate_win_bytes = bytes_total;
            }
            sustained_bps = 0;
        }
    }
    {
        __u64 rd = (__u64)tp->rate_delivered;
        rate_delivered = rate_interval_us ?
            (rd * mss * 1000000ULL) / rate_interval_us : 0;
    }

        /* 0.4.44: proof tracking.  Non-close votes only.  If the
         * socket's delivered rate crosses a tier on the alg it is
         * currently running, mark the (socket, alg) bit and bump the
         * per-alg counter.  Bits are per-alg so a swap does not have
         * to reset anything -- each alg the socket has ever touched
         * keeps its own bit, and the close handler decrements them
         * all. */
        /* 0.4.102: removed the v0.4.100 touched_bitmap gate. It is no
         * longer needed because the v0.4.101 fix removed the
         * swap_target=0xff mark from the passive-estab handler, so
         * set_cong() now runs for passive connections (VPS→Home
         * sender topology). This means statep->state is set
         * correctly for all connections, and touched_bitmap is
         * always non-zero when a proof fires. */
        if (!is_close) {
                __u64 bit = 1ULL << (s & (NUM_TCP_CONG_ALGS - 1));
                if (rate_delivered >= get_proof_proved_bps() && !(statep->proved_bitmap & bit)) {
                        statep->proved_bitmap |= bit;
                        /* 0.4.89 (C1): seq-wrap proof-counter bump. */
                        __sync_fetch_and_add(&remote_host->seq, 1);
                        remote_host->metrics[s].sockets_proved++;
                        if (!(statep->good_bitmap & bit)) {
                                statep->good_bitmap |= bit;
                                remote_host->metrics[s].sockets_good++;
                        }
                        __sync_fetch_and_add(&remote_host->seq, 1);
                        if (bpftune_debug)
                                bpf_printk("proof cookie=%llu alg=%d rate=%llu tier=2 dest=%u dest6=%u dest6b=%u",
                                   bpf_get_socket_cookie(ops), s, rate_delivered,
                                   is_v4_mapped ? (__u32)bpf_ntohl(v4_addr_from_v6) : (__u32)bpf_ntohl(ops->remote_ip4),
                                   (__u32)bpf_ntohl(ops->remote_ip6[0]), (__u32)bpf_ntohl(ops->remote_ip6[1]));
                } else if (rate_delivered >= get_proof_good_bps() && !(statep->good_bitmap & bit)) {
                        statep->good_bitmap |= bit;
                        /* 0.4.89 (C1): seq-wrap proof-counter bump. */
                        __sync_fetch_and_add(&remote_host->seq, 1);
                        remote_host->metrics[s].sockets_good++;
                        __sync_fetch_and_add(&remote_host->seq, 1);
                        if (bpftune_debug)
                                bpf_printk("proof cookie=%llu alg=%d rate=%llu tier=1 dest=%u dest6=%u dest6b=%u",
                                   bpf_get_socket_cookie(ops), s, rate_delivered,
                                   is_v4_mapped ? (__u32)bpf_ntohl(v4_addr_from_v6) : (__u32)bpf_ntohl(ops->remote_ip4),
                                   (__u32)bpf_ntohl(ops->remote_ip6[0]), (__u32)bpf_ntohl(ops->remote_ip6[1]));
                }
        }
    /* 0.4.53: raw delivered rate on every vote.
     * midsamp only fires on rung crossings; sockets past the last
     * rung only vote via the 60s time-check and had no raw rate
     * for post-swap measurement.  This companion line carries it
     * for every vote. */
    {
        __u64 _sinter = (__u64)tp->rate_interval_us;
        __u64 _sraw   = (__u64)tp->rate_delivered;
        __u64 _smss   = (__u64)tp->mss_cache;
        __u64 _srate  = _sinter ? (_sraw * _smss * 1000000ULL) / _sinter : 0;
        if (bpftune_debug)
                bpf_printk("srate cookie=%llu alg=%u srate=%llu",
                   bpf_get_socket_cookie(ops), s, _srate);
    }

    m = &remote_host->metrics[s];

    {
        __u64 rtt_term = 0, rate_term = 0, loss_term = 0;
        __u64 heal_rtt = 0, heal_rate = 0;
        metric = tcp_metric_calc(remote_host, min_rtt, avg_rtt, sustained_bps,
                                 allow_ref,
                                 &rtt_term, &rate_term, &heal_rtt, &heal_rate);
        {
            __u64 __rtx = (__u64)tp->total_retrans;
            __u64 __sout = (__u64)tp->segs_out;
            __u64 loss_bp = __sout ? (__rtx * 10000) / __sout : 0;
            if (loss_bp > LOSS_CAP_BP)
                loss_bp = LOSS_CAP_BP;
            loss_term = (loss_bp * LOSS_SCALE) / LOSS_CAP_BP;
            metric += loss_term;
        }
        if (bpftune_debug)
                bpf_printk("met cookie=%llu rport=%u alg=%d segs=%llu val=%llu rtt=%llu rate=%llu loss=%llu smrtt=%llu bmrtt=%llu avgrtt=%llu",
                   bpf_get_socket_cookie(ops), bpf_ntohl(ops->remote_port),
                   s, (__u64)tp->segs_out + tp->segs_in, metric, rtt_term, rate_term,
                   loss_term, min_rtt, remote_host->min_rtt, avg_rtt);
        /* 0.4.39 diagnostic: window state at vote time.  When
         * packets_out << snd_cwnd the app is not filling the
         * cwnd-permitted window -- the app_limited case the live
         * trace showed dominant.  Votes in that state under-report
         * the algorithm: delivery_rate reflects the app, not the
         * path.  The met line above is at the 12-argument printk
         * limit, so this lives on its own line and joins by cookie.
         * No metric logic change; diagnostic only. */
        if (bpftune_debug)
                bpf_printk("cwnd cookie=%llu snd_cwnd=%llu pkts_out=%llu",
                   bpf_get_socket_cookie(ops),
                   (__u64)tp->snd_cwnd, (__u64)tp->packets_out);
        if (heal_rtt && bpftune_debug)
            bpf_printk("heal_rtt smrtt=%llu newref=%llu",
                       (unsigned long long)min_rtt,
                       (unsigned long long)heal_rtt);
        if (heal_rate && bpftune_debug)
            bpf_printk("heal_rate rate=%llu newref=%llu",
                       (unsigned long long)rate_delivered,
                       (unsigned long long)heal_rate);
    }

    now = bpf_ktime_get_ns();

    if (statep && !is_close) {
        /* Shift the short-trend history.  prev is the previous
         * vote's metric; hist_1/hist_2 hold the two before that.
         * Filter the 0/~0 sentinels so a poisoned sample does not
         * poison the window. */
        {
            __u64 prev = statep->last_metric;
            if (prev != 0 && prev != ~((__u64)0)) {
                statep->hist_2 = statep->hist_1;
                statep->hist_1 = prev;
            }
        }
        statep->last_metric = metric;
        statep->last_rate_bps = sustained_bps;
        if (sustained_bps > statep->post_swap_rate_max)
            statep->post_swap_rate_max = sustained_bps;
        score_pending_swap(ops, remote_host, statep, bpf_ktime_get_ns(),
                           (__u8)s);
        statep->votes_on_alg++;
        /* Track the best reading this socket has ever produced, and
         * which algorithm it was on at the time.  Used by the freeze
         * path once enough swaps have accumulated.  Skip the ~0
         * poisoned-metric sentinel and the 0 (unset) sentinel. */
        if (metric != 0 && metric != ~((__u64)0) &&
            (statep->best_seen_metric == 0 ||
             metric < statep->best_seen_metric)) {
            statep->best_seen_metric = metric;
            statep->best_seen_alg = s;
        }
        /* 0.4.78: parallel best-by-rate on the same socket.  Uses
         * rate_delivered (burst), matching the capability signal
         * the leaderboard and proof counters rely on. */
        if (rate_delivered > 0 &&
            rate_delivered > statep->best_seen_srate) {
            statep->best_seen_srate = rate_delivered;
            statep->best_seen_srate_alg = s;
        }
    }

    /* 0.4.97: (passive swap skip was here in v0.4.96 but removed —
     * see comment above. Passive connections now go through the
     * full vote path including swap decisions, matching v0.4.91
     * behavior. The swap engine naturally won't fire for passive
     * connections because their rate_ema stays low (server is the
     * receiver, not the sender).) */

    {
        __u64 best_alt = ~((__u64)0);
        __u8 best_alt_i = 0;

        __u8 mt_alt_i = 0;

        __u8 swap_tgt = 0xff;  /* v0.4.99: 0xff = no valid target (was 0 = cubic) */

        if (remote_host->best_v != 0 && remote_host->best_v != ~((__u64)0)) {
            if (s != remote_host->best_i) {
                /* Socket on non-leader: target the leader. */
                __u8 bi = (__u8)(remote_host->best_i & (NUM_TCP_CONN_METRICS - 1));
                if (remote_host->metrics[bi].metric_count >= MIN_LEADER_TRUST) {
                    best_alt = remote_host->best_v;
                    best_alt_i = bi;
                }
            } else if (remote_host->second_v != 0 && remote_host->second_v != ~((__u64)0)) {
                /* Socket on leader but leader struggling for THIS socket:
                 * target second-best.  Since second_v >= best_v, the
                 * 1.25x margin bar is naturally higher here, so this
                 * only fires when the gap between top two is small and
                 * the socket is clearly worse than either. */
                __u8 si = (__u8)(remote_host->second_i & (NUM_TCP_CONN_METRICS - 1));
                if (remote_host->metrics[si].metric_count >= MIN_LEADER_TRUST) {
                    best_alt = remote_host->second_v;
                    best_alt_i = si;
                }
            }
        }
        if (best_alt != ~((__u64)0) && best_alt < m->metric_value)
            greedy = false;
        mt_alt_i = best_alt_i;
        swap_tgt = best_alt_i;
        /* 0.4.56: score-weighted target is picked by userspace in the
         * reanchor (rate_best_i).  BPF just reads it.  Keeping the
         * multiply/select out of the vote path; the 16-way loop with
         * div blows the 1M insn verifier limit. */
        if (remote_host->rate_best_v != 0) {
            __u8 rt = (__u8)(remote_host->rate_best_i & (NUM_TCP_CONN_METRICS - 1));
            if (rt != s && remote_host->metrics[rt].rate_ema > 0) {
                swap_tgt = rt;
            } else if (rt == s && remote_host->rate_second_v != 0) {
                __u8 r2 = (__u8)(remote_host->rate_second_i &
                                 (NUM_TCP_CONN_METRICS - 1));
                if (r2 != s && remote_host->metrics[r2].rate_ema > 0)
                    swap_tgt = r2;
            }
        }

        if (statep && !is_close) {
            /* 0.4.71: rate_ok removed.  Pass 3 already enforces
             * MIN_LEADER_TRUST, the bad_streak/null_streak penalty,
             * and the score term.  Two pickers disagreeing on the
             * basis of the metric (rate_ema vs weighted score) meant
             * the gate blocked rescues the picker intended. */
            /* 0.4.50: skip swaps on sockets not using their window.
             * Weekend data: 60% of swaps fired at util<10%; 42% had
             * pkts_out<=1.  Those sockets were idle; no algorithm
             * change can help them.  Same threshold the vote path
             * already uses (METRIC_MIN_UTIL_PCT). */
            /* 0.4.72: restored.  Pass 3 picks by weighted score
             * (rate_ema * swap_score / 256 * penalty); this gate
             * uses raw rate_ema.  When the score makes a lower-
             * raw-rate algorithm the leader, this vetoes the swap
             * to it -- deliberate: a target whose capability is
             * below the source's is not a rescue, regardless of
             * its historical win record.  Removed in 0.4.71 on the
             * theory that pass 3's score is sufficient; data on
             * 2026-09-24 shows the blocked class loss rate is 15%
             * vs 8% for swaps that pass, so the filter is real. */
            bool rate_ok = true;
            if (remote_host->rate_best_v > 0 &&
                remote_host->metrics[swap_tgt].rate_ema <
                remote_host->metrics[s].rate_ema)
                rate_ok = false;

            bool util_ok = true;
            if (tp->snd_cwnd > 0 &&
                (__u64)tp->packets_out * 100 < (__u64)tp->snd_cwnd * METRIC_MIN_UTIL_PCT)
                util_ok = false;

            /* Flat-socket gate (0.4.37).  Data: over 340 swaps flat
             * sockets win 7.9% / null 90.6% / loss 1.6% -- the win
             * rate is inside the metric's noise band.  The moderate
             * tier selects for flat (78.5% of its fires vs 21.9% in
             * desperate).  Suppress the swap when the socket's own
             * last three samples are flat.  Only the moderate tier
             * is gated; the desperate tier still fires because the
             * socket is 2x off the leader regardless of shape. */
            /* Classify flat over the valid subset of {last_metric,
             * hist_1, hist_2}.  Require at least two valid samples.
             *
             * SWAP_BAD_FIRST=2 fires the first moderate swap after two
             * consecutive bad votes.  On a fresh socket or one whose
             * history was just zeroed by a swap, hist_2 is still 0 at
             * that moment, so a strict three-sample gate can never
             * fire -- which is exactly what happened in 0.4.37.  Data
             * from the 09-14 + 09-15 logs (pre-gate): 2sample-flat
             * wins 9-10%, same population as 3sample-flat (7.9%).
             * 2sample-nonflat wins 45-50% and is naturally excluded
             * by the max/min check.  1sample cannot form a ratio and
             * falls through. */
            bool is_flat = false;
            {
                __u64 v0 = statep->last_metric;
                __u64 v1 = statep->hist_1;
                __u64 v2 = statep->hist_2;
                __u64 mn = 0, mx = 0;
                int n = 0;
                if (v0 != 0 && v0 != ~((__u64)0)) {
                    mn = v0; mx = v0; n = 1;
                }
                if (v1 != 0 && v1 != ~((__u64)0)) {
                    if (n == 0) { mn = v1; mx = v1; }
                    else { if (v1 < mn) mn = v1; if (v1 > mx) mx = v1; }
                    n++;
                }
                if (v2 != 0 && v2 != ~((__u64)0)) {
                    if (n == 0) { mn = v2; mx = v2; }
                    else { if (v2 < mn) mn = v2; if (v2 > mx) mx = v2; }
                    n++;
                }
                if (n >= 2 && mx * 100 < mn * 110)
                    is_flat = true;
            }
            /* 0.4.41: classify a socket that is already in motion
             * (falling on its own, or oscillating) so we do not reset
             * cwnd mid-motion.  Two shapes, same reason:
             *
             *   falling  -- the socket's own metric is dropping, i.e.
             *               its delivered rate is lifting.  The classic
             *               shape of an ABR probe: the player requested
             *               a higher rendition and the socket is
             *               climbing to meet it.  A swap here shows a
             *               brief dip to the ABR measurement window
             *               and gets the higher rendition reverted.
             *
             *   oscillating -- the metric is bouncing.  A cwnd reset
             *               mid-oscillation makes the next swing worse
             *               rather than better.
             *
             * Measured on client-facing swaps (2026-09-16 + 09-17):
             * falling n=6 win 0%  loss 33%;  oscillating n=17 win
             * 12% loss 24%.  Both below the tier baseline (~34% d=1).
             *
             * Requires at least two valid samples.  Falling requires a
             * >=5% drop between the last two; oscillating requires
             * >10% spread and neither the rising nor falling shape.
             * Single-sample sockets fall through (nothing to judge).
             * After the origin gate above, every socket reaching this
             * point is sending-dominant, so no client-side check is
             * needed here. */
            bool is_moving = false;
            {
                __u64 v0 = statep->last_metric;
                __u64 v1 = statep->hist_1;
                __u64 v2 = statep->hist_2;
                bool ok0 = (v0 != 0 && v0 != ~((__u64)0));
                bool ok1 = (v1 != 0 && v1 != ~((__u64)0));
                bool ok2 = (v2 != 0 && v2 != ~((__u64)0));
                /* falling: last two valid samples, latest down >=5% */
                if (ok0 && ok1 && v1 * 105 > v0 * 100)
                    is_moving = true;
                /* oscillating: three valid samples with >10% spread and
                 * no monotonic direction */
                if (!is_moving && ok0 && ok1 && ok2) {
                    __u64 mn = v0, mx = v0;
                    if (v1 < mn) mn = v1;
                    if (v1 > mx) mx = v1;
                    if (v2 < mn) mn = v2;
                    if (v2 > mx) mx = v2;
                    if (mx * 100 >= mn * 110) {
                        bool rising = (v2 < v1 && v1 < v0);
                        bool falling = (v2 > v1 && v1 > v0);
                        if (!rising && !falling)
                            is_moving = true;
                    }
                }
            }
        /* 0.4.54: rate-based.  socket under 66% of leader.
         * 0.4.89 (Q2): factored into socket_under_pct_of_leader();
         * the old form was `last_rate_bps * 150 < rate_best_v * 100000 * 100`
         * where the *100 and /150 cancel to a 2/3 ratio. */
            bool margin_met = socket_under_pct_of_leader(
                statep->last_rate_bps,
                (__u16)(remote_host->rate_best_v & 0xffff), 66);
            /* Post-freeze, "desperate" is judged relative to this
             * socket's own best_seen_metric rather than the bucket
             * leader.  A frozen socket that stays at ~best_seen (even
             * if far above the bucket best_v) is not broken -- no
             * algorithm will move it, and swapping just costs a cwnd
             * reset for nothing.  Only a genuine collapse --
             * last_metric >= best_seen * 2 -- reopens the desperate
             * tier for a frozen socket.  Pre-freeze behavior is
             * unchanged: bucket-relative 2x still fires immediately. */
            bool desperate_post = (statep->last_metric * 100 >=
                                   statep->best_seen_metric * 200);
            /* 0.4.89 (Q2): desperate requires margin_met AND socket
             * under 25% of leader.  The old form was
             * `last_rate_bps * 4 < rate_best_v * 100000` which is
             * equivalent to socket_under_pct_of_leader(..., 25). */
            bool desperate = (margin_met &&
                              socket_under_pct_of_leader(
                                  statep->last_rate_bps,
                                  (__u16)(remote_host->rate_best_v & 0xffff), 25) &&
                              (!statep->frozen || desperate_post));

            /* Settle window: fixed minimum gap between swaps on one
             * socket.  Historically split (60s moderate / 10s
             * desperate), but the moderate path always arrived with
             * persist_bad already >= 2 -- 60s was unreachable in
             * practice.  10s is >= 300 RTT on a 30ms path, enough
             * for the new algorithm to settle, and the 2-bad-check
             * requirement above already prevents thrash. */
            __u64 _settle_ns = (s == ALG_BBR_INDEX || swap_tgt == ALG_BBR_INDEX) ? T_SETTLE_NS * 2 : T_SETTLE_NS;
            /* 0.4.86: use _settle_ns so BBR gets the doubled settle
             * window.  Regression in 0.4.81 final. */
            bool settle_expired = (now >= statep->last_swap_at + _settle_ns);

            __u64 eff_ref = remote_host->max_rate_delivered;
            if (eff_ref < REF_FLOOR_BPS)
                eff_ref = REF_FLOOR_BPS;
            bool slow_vs_ref = (statep->last_rate_bps > 0 &&
                                eff_ref > 0 &&
                                statep->last_rate_bps * 100 <
                                eff_ref * SLOW_VS_REF_PCT);

            /* 0.4.52: slow-vs-leader.  Uses the rate directly, bypassing
             * the composite.  A swap that raises throughput fills the
             * bottleneck queue; the induced RTT rise masks the win.
             * 0.4.89 (Q2): factored into socket_under_pct_of_leader();
             * the old form was `last_rate_bps * 100 < rate_best_v * 100000 * RATE_TRIGGER_PCT`
             * which is socket_under_pct_of_leader(..., RATE_TRIGGER_PCT). */
            bool slow_vs_leader = socket_under_pct_of_leader(
                statep->last_rate_bps,
                (__u16)(remote_host->rate_best_v & 0xffff),
                RATE_TRIGGER_PCT);

            /* 0.4.54: exploration protection. */

            bool protected_exploring = (statep->exploring &&
                                        statep->votes_on_alg <
                                        explore_protect_votes());


            if (!settle_expired) {
                /* settle window -- wait */
            } else if (swap_tgt == s) {
                /* 0.4.57: already on the best target for this
                 * bucket.  A no-op swap still resets cwnd and
                 * counts toward freeze (cookie 45881 swapped
                 * cubic->cubic three times then froze). */
            } else if (protected_exploring) {
                /* exploring, not enough votes on the alg yet */
            } else if (desperate && rate_ok && util_ok) {
                /* Desperate tier fires regardless of frozen. */
                __u64 bc_fire = statep->bad_checkpoints;
                __u64 ac = remote_host->metrics[s].metric_count;
                __u8 from_i = s;
                __u8 to_i = swap_tgt;
                if (!set_cong(ops, remote_host, swap_tgt)) {
                    statep->swap_count++;
                    statep->last_swap_at = now;
                    /* 0.4.89 (C2): reset the sustained-rate window so the
                     * next measurement starts at the swap boundary.  Without
                     * this, the first sustained_bps sample after a swap
                     * straddles the swap point -- mixing pre-swap and
                     * post-swap bytes -- and can inflate post_swap_rate_max
                     * if the pre-swap alg was carrying a higher rate. */
                    statep->rate_win_ts_ns = now;
                    statep->rate_win_bytes = (__u64)tp->bytes_acked + (__u64)tp->bytes_received;
                    statep->last_metric = 0;
                    score_pending_rejected(ops, remote_host, statep, now);
                    statep->pre_swap_rate = statep->last_rate_bps;
                    statep->post_swap_rate_max = 0;
                    statep->swap_target = swap_tgt;
                    statep->last_rate_bps = 0;
                    statep->hist_1 = 0;
                    statep->hist_2 = 0;
                    statep->bad_checkpoints = 0;
                    if (bpftune_debug)
                    bpf_printk("swap cookie=%llu from=%u to=%u bc=%llu ac=%llu d=1 mt=%u rb=%u dest=%u dest6=%u dest6b=%u",
                               bpf_get_socket_cookie(ops), from_i, to_i,
                               bc_fire, ac, (__u32)mt_alt_i, (__u32)swap_tgt, is_v4_mapped ? (__u32)bpf_ntohl(v4_addr_from_v6) : (__u32)bpf_ntohl(ops->remote_ip4),
                               (__u32)bpf_ntohl(ops->remote_ip6[0]), (__u32)bpf_ntohl(ops->remote_ip6[1]));
                    if (bpftune_debug)
                    bpf_printk("swapctx cookie=%llu d=1 cwnd=%llu ssthresh=%llu pkts=%llu wnd_out=%llu on_ldr=%u swaps=%llu app_lim=%u util=%llu",
                               bpf_get_socket_cookie(ops),
                               (__u64)tp->snd_cwnd, (__u64)tp->snd_ssthresh,
                               (__u64)tp->packets_out, (__u64)tp->snd_wnd,
                               (__u32)(s == remote_host->best_i),
                               statep->swap_count,
                               (__u32)tp->rate_app_limited,
                               (__u64)(tp->snd_cwnd ? ((__u64)tp->packets_out * 100 / tp->snd_cwnd) : 0));
                }
            } else if (slow_vs_ref && rate_ok && util_ok && !statep->frozen) {
                if (statep->swap_count >= FREEZE_AFTER_SWAPS) {
                    int fret = 0;
                    /* 0.4.78: prefer the rate best over the metric best.  The
                     * metric dip the socket hit may have been an rtt or loss
                     * artifact, not an algorithm-quality signal. */
                    __u64 tgt = (statep->best_seen_srate > 0)
                              ? statep->best_seen_srate_alg
                              : statep->best_seen_alg;
                    tgt &= (NUM_TCP_CONG_ALGS - 1);
                    __u8 tgt8 = (__u8)tgt;
                    if ((statep->best_seen_metric != 0 ||
                         statep->best_seen_srate != 0) && tgt8 != s)
                        fret = set_cong(ops, remote_host, tgt8);
                    if (bpftune_debug)
                    bpf_printk("freeze cookie=%llu from=%u to=%u bsrate=%llu ret=%d dest=%u dest6=%u dest6b=%u",
                               bpf_get_socket_cookie(ops), s, tgt8, statep->best_seen_srate, fret, is_v4_mapped ? (__u32)bpf_ntohl(v4_addr_from_v6) : (__u32)bpf_ntohl(ops->remote_ip4),
                               (__u32)bpf_ntohl(ops->remote_ip6[0]), (__u32)bpf_ntohl(ops->remote_ip6[1]));
                    statep->frozen = 1;
                    statep->last_swap_at = now;
                    /* 0.4.89 (C2): reset the sustained-rate window so the
                     * next measurement starts at the swap boundary.  Without
                     * this, the first sustained_bps sample after a swap
                     * straddles the swap point -- mixing pre-swap and
                     * post-swap bytes -- and can inflate post_swap_rate_max
                     * if the pre-swap alg was carrying a higher rate. */
                    statep->rate_win_ts_ns = now;
                    statep->rate_win_bytes = (__u64)tp->bytes_acked + (__u64)tp->bytes_received;
                    statep->last_metric = 0;
                    score_pending_rejected(ops, remote_host, statep, now);
                    statep->pre_swap_rate = statep->last_rate_bps;
                    statep->post_swap_rate_max = 0;
                    statep->swap_target = tgt8;
                    statep->last_rate_bps = 0;
                    statep->hist_1 = 0;
                    statep->hist_2 = 0;
                    statep->bad_checkpoints = 0;
                } else {
                    __u64 ac = remote_host->metrics[s].metric_count;
                    __u8 from_i = s;
                    __u8 to_i = swap_tgt;
                    if (!set_cong(ops, remote_host, swap_tgt)) {
                        statep->swap_count++;
                        statep->last_swap_at = now;
                    /* 0.4.89 (C2): reset the sustained-rate window so the
                     * next measurement starts at the swap boundary.  Without
                     * this, the first sustained_bps sample after a swap
                     * straddles the swap point -- mixing pre-swap and
                     * post-swap bytes -- and can inflate post_swap_rate_max
                     * if the pre-swap alg was carrying a higher rate. */
                    statep->rate_win_ts_ns = now;
                    statep->rate_win_bytes = (__u64)tp->bytes_acked + (__u64)tp->bytes_received;
                        statep->last_metric = 0;

                        /* 0.4.56: stage pre-swap rate and target for scoring. */
                        score_pending_rejected(ops, remote_host, statep, now);
                        statep->pre_swap_rate = statep->last_rate_bps;
                        statep->post_swap_rate_max = 0;
                        statep->swap_target = swap_tgt;
                        statep->last_rate_bps = 0;
                        statep->hist_1 = 0;
                        statep->hist_2 = 0;
                        statep->bad_checkpoints = 0;
                        if (bpftune_debug)
                        bpf_printk("swap cookie=%llu from=%u to=%u bc=%llu ac=%llu d=2 mt=%u rb=%u dest=%u dest6=%u dest6b=%u",
                                   bpf_get_socket_cookie(ops), from_i, to_i,
                                   (__u64)0, ac, (__u32)mt_alt_i, (__u32)swap_tgt, is_v4_mapped ? (__u32)bpf_ntohl(v4_addr_from_v6) : (__u32)bpf_ntohl(ops->remote_ip4),
                                   (__u32)bpf_ntohl(ops->remote_ip6[0]), (__u32)bpf_ntohl(ops->remote_ip6[1]));
                        if (bpftune_debug)
                        bpf_printk("swapctx cookie=%llu d=2 cwnd=%llu ssthresh=%llu pkts=%llu wnd_out=%llu on_ldr=%u swaps=%llu app_lim=%u util=%llu",
                                   bpf_get_socket_cookie(ops),
                                   (__u64)tp->snd_cwnd, (__u64)tp->snd_ssthresh,
                                   (__u64)tp->packets_out, (__u64)tp->snd_wnd,
                                   (__u32)(s == remote_host->best_i),
                                   statep->swap_count, (__u32)tp->rate_app_limited,
                                   (__u64)(tp->snd_cwnd ? ((__u64)tp->packets_out * 100 / tp->snd_cwnd) : 0));
                    }
                }
            } else if (slow_vs_leader && rate_ok && util_ok && !statep->frozen) {
                if (statep->swap_count >= FREEZE_AFTER_SWAPS) {
                    int fret = 0;
                    /* 0.4.78: prefer the rate best over the metric best.  The
                     * metric dip the socket hit may have been an rtt or loss
                     * artifact, not an algorithm-quality signal. */
                    __u64 tgt = (statep->best_seen_srate > 0)
                              ? statep->best_seen_srate_alg
                              : statep->best_seen_alg;
                    tgt &= (NUM_TCP_CONG_ALGS - 1);
                    __u8 tgt8 = (__u8)tgt;
                    if ((statep->best_seen_metric != 0 ||
                         statep->best_seen_srate != 0) && tgt8 != s)
                        fret = set_cong(ops, remote_host, tgt8);
                    if (bpftune_debug)
                    bpf_printk("freeze cookie=%llu from=%u to=%u bsrate=%llu ret=%d dest=%u dest6=%u dest6b=%u",
                               bpf_get_socket_cookie(ops), s, tgt8, statep->best_seen_srate, fret, is_v4_mapped ? (__u32)bpf_ntohl(v4_addr_from_v6) : (__u32)bpf_ntohl(ops->remote_ip4),
                               (__u32)bpf_ntohl(ops->remote_ip6[0]), (__u32)bpf_ntohl(ops->remote_ip6[1]));
                    statep->frozen = 1;
                    statep->last_swap_at = now;
                    /* 0.4.89 (C2): reset the sustained-rate window so the
                     * next measurement starts at the swap boundary.  Without
                     * this, the first sustained_bps sample after a swap
                     * straddles the swap point -- mixing pre-swap and
                     * post-swap bytes -- and can inflate post_swap_rate_max
                     * if the pre-swap alg was carrying a higher rate. */
                    statep->rate_win_ts_ns = now;
                    statep->rate_win_bytes = (__u64)tp->bytes_acked + (__u64)tp->bytes_received;
                    statep->last_metric = 0;
                    score_pending_rejected(ops, remote_host, statep, now);
                    statep->pre_swap_rate = statep->last_rate_bps;
                    statep->post_swap_rate_max = 0;
                    statep->swap_target = tgt8;
                    statep->last_rate_bps = 0;
                    statep->hist_1 = 0;
                    statep->hist_2 = 0;
                    statep->bad_checkpoints = 0;
                } else {
                    __u64 ac = remote_host->metrics[s].metric_count;
                    __u8 from_i = s;
                    __u8 to_i = swap_tgt;
                    if (!set_cong(ops, remote_host, swap_tgt)) {
                        statep->swap_count++;
                        statep->last_swap_at = now;
                    /* 0.4.89 (C2): reset the sustained-rate window so the
                     * next measurement starts at the swap boundary.  Without
                     * this, the first sustained_bps sample after a swap
                     * straddles the swap point -- mixing pre-swap and
                     * post-swap bytes -- and can inflate post_swap_rate_max
                     * if the pre-swap alg was carrying a higher rate. */
                    statep->rate_win_ts_ns = now;
                    statep->rate_win_bytes = (__u64)tp->bytes_acked + (__u64)tp->bytes_received;
                        statep->last_metric = 0;

                        /* 0.4.56: stage pre-swap rate and target for scoring. */
                        score_pending_rejected(ops, remote_host, statep, now);
                        statep->pre_swap_rate = statep->last_rate_bps;
                        statep->post_swap_rate_max = 0;
                        statep->swap_target = swap_tgt;
                        statep->last_rate_bps = 0;
                        statep->hist_1 = 0;
                        statep->hist_2 = 0;
                        statep->bad_checkpoints = 0;
                        if (bpftune_debug)
                        bpf_printk("swap cookie=%llu from=%u to=%u bc=%llu ac=%llu d=3 mt=%u rb=%u dest=%u dest6=%u dest6b=%u",
                                   bpf_get_socket_cookie(ops), from_i, to_i,
                                   (__u64)0, ac, (__u32)mt_alt_i, (__u32)swap_tgt, is_v4_mapped ? (__u32)bpf_ntohl(v4_addr_from_v6) : (__u32)bpf_ntohl(ops->remote_ip4),
                                   (__u32)bpf_ntohl(ops->remote_ip6[0]), (__u32)bpf_ntohl(ops->remote_ip6[1]));
                        if (bpftune_debug)
                        bpf_printk("swapctx cookie=%llu d=3 cwnd=%llu ssthresh=%llu pkts=%llu wnd_out=%llu on_ldr=%u swaps=%llu app_lim=%u util=%llu",
                                   bpf_get_socket_cookie(ops),
                                   (__u64)tp->snd_cwnd, (__u64)tp->snd_ssthresh,
                                   (__u64)tp->packets_out, (__u64)tp->snd_wnd,
                                   (__u32)(s == remote_host->best_i),
                                   statep->swap_count, (__u32)tp->rate_app_limited,
                                   (__u64)(tp->snd_cwnd ? ((__u64)tp->packets_out * 100 / tp->snd_cwnd) : 0));
                    }
                }
            } else if (margin_met && !statep->frozen) {
                if (statep->swap_count >= FREEZE_AFTER_SWAPS) {
                    /* FREEZE: go to the algorithm on which this socket
                     * looked best, then stop trying. */
                    int fret = 0;
                    /* 0.4.78: prefer the rate best over the metric best.  The
                     * metric dip the socket hit may have been an rtt or loss
                     * artifact, not an algorithm-quality signal. */
                    __u64 tgt = (statep->best_seen_srate > 0)
                              ? statep->best_seen_srate_alg
                              : statep->best_seen_alg;
                    tgt &= (NUM_TCP_CONG_ALGS - 1);
                    __u8 tgt8 = (__u8)tgt;
                    if ((statep->best_seen_metric != 0 ||
                         statep->best_seen_srate != 0) && tgt8 != s)
                        fret = set_cong(ops, remote_host, tgt8);
                    if (bpftune_debug)
                    bpf_printk("freeze cookie=%llu from=%u to=%u bsrate=%llu ret=%d dest=%u dest6=%u dest6b=%u",
                               bpf_get_socket_cookie(ops), s, tgt8, statep->best_seen_srate, fret, is_v4_mapped ? (__u32)bpf_ntohl(v4_addr_from_v6) : (__u32)bpf_ntohl(ops->remote_ip4),
                               (__u32)bpf_ntohl(ops->remote_ip6[0]), (__u32)bpf_ntohl(ops->remote_ip6[1]));
                    if (bpftune_debug)
                    bpf_printk("swapctx cookie=%llu d=f cwnd=%llu ssthresh=%llu pkts=%llu wnd_out=%llu on_ldr=%u swaps=%llu app_lim=%u util=%llu",
                               bpf_get_socket_cookie(ops),
                               (__u64)tp->snd_cwnd, (__u64)tp->snd_ssthresh,
                               (__u64)tp->packets_out, (__u64)tp->snd_wnd,
                               (__u32)(s == remote_host->best_i),
                               statep->swap_count,
                               (__u32)tp->rate_app_limited,
                               (__u64)(tp->snd_cwnd ? ((__u64)tp->packets_out * 100 / tp->snd_cwnd) : 0));
                    statep->frozen = 1;
                    statep->last_swap_at = now;
                    /* 0.4.89 (C2): reset the sustained-rate window so the
                     * next measurement starts at the swap boundary.  Without
                     * this, the first sustained_bps sample after a swap
                     * straddles the swap point -- mixing pre-swap and
                     * post-swap bytes -- and can inflate post_swap_rate_max
                     * if the pre-swap alg was carrying a higher rate. */
                    statep->rate_win_ts_ns = now;
                    statep->rate_win_bytes = (__u64)tp->bytes_acked + (__u64)tp->bytes_received;
                    statep->last_metric = 0;
                    score_pending_rejected(ops, remote_host, statep, now);
                    statep->pre_swap_rate = statep->last_rate_bps;
                    statep->post_swap_rate_max = 0;
                    statep->swap_target = tgt8;
                    statep->last_rate_bps = 0;
                    statep->hist_1 = 0;
                    statep->hist_2 = 0;
                    statep->bad_checkpoints = 0;
                } else {
                    /* Normal-tier swap. */
                    statep->bad_checkpoints++;
                    {
                        __u64 needed = (statep->swap_count == 0) ? SWAP_BAD_FIRST : SWAP_BAD_LATER;
                        if (statep->bad_checkpoints >= needed) {
                            __u64 bc_fire = statep->bad_checkpoints;
                            __u64 ac = remote_host->metrics[s].metric_count;
                            __u8 from_i = s;
                            __u8 to_i = swap_tgt;
                            if (is_flat || is_moving) {
                                /* Flat: at own plateau, algorithm is
                                 * not the limiter.  Moving: socket is
                                 * recovering (falling) or bouncing
                                 * (oscillating) on its own -- a cwnd
                                 * reset would interrupt that, not help
                                 * it.  Either way do not swap; reset
                                 * the bad-check count so the socket
                                 * must re-demonstrate rather than
                                 * firing the moment the motion stops. */
                                statep->bad_checkpoints = 0;
                            } else if (!rate_ok) {
                                /* target rate below source; skip swap */
                                statep->bad_checkpoints = 0;
                            } else if (!util_ok) {
                                /* socket not using window; skip swap */
                                statep->bad_checkpoints = 0;
                            } else if (!set_cong(ops, remote_host, swap_tgt)) {
                                statep->swap_count++;
                                statep->last_swap_at = now;
                    /* 0.4.89 (C2): reset the sustained-rate window so the
                     * next measurement starts at the swap boundary.  Without
                     * this, the first sustained_bps sample after a swap
                     * straddles the swap point -- mixing pre-swap and
                     * post-swap bytes -- and can inflate post_swap_rate_max
                     * if the pre-swap alg was carrying a higher rate. */
                    statep->rate_win_ts_ns = now;
                    statep->rate_win_bytes = (__u64)tp->bytes_acked + (__u64)tp->bytes_received;
                                statep->last_metric = 0;

                                /* 0.4.56: stage pre-swap rate and target for scoring. */
                                score_pending_rejected(ops, remote_host, statep, now);
                                statep->pre_swap_rate = statep->last_rate_bps;
                                statep->post_swap_rate_max = 0;
                                statep->swap_target = swap_tgt;
                                statep->last_rate_bps = 0;
                                statep->hist_1 = 0;
                                statep->hist_2 = 0;
                                statep->bad_checkpoints = 0;
                                if (bpftune_debug)
                                bpf_printk("swap cookie=%llu from=%u to=%u bc=%llu ac=%llu d=0 mt=%u rb=%u dest=%u dest6=%u dest6b=%u",
                                           bpf_get_socket_cookie(ops), from_i, to_i,
                                           bc_fire, ac, (__u32)mt_alt_i, (__u32)swap_tgt, is_v4_mapped ? (__u32)bpf_ntohl(v4_addr_from_v6) : (__u32)bpf_ntohl(ops->remote_ip4),
                                           (__u32)bpf_ntohl(ops->remote_ip6[0]), (__u32)bpf_ntohl(ops->remote_ip6[1]));
                                if (bpftune_debug)
                                bpf_printk("swapctx cookie=%llu d=0 cwnd=%llu ssthresh=%llu pkts=%llu wnd_out=%llu on_ldr=%u swaps=%llu app_lim=%u util=%llu",
                                           bpf_get_socket_cookie(ops),
                                           (__u64)tp->snd_cwnd, (__u64)tp->snd_ssthresh,
                                           (__u64)tp->packets_out, (__u64)tp->snd_wnd,
                                           (__u32)(s == remote_host->best_i),
                                           statep->swap_count,
                                           (__u32)tp->rate_app_limited,
                                           (__u64)(tp->snd_cwnd ? ((__u64)tp->packets_out * 100 / tp->snd_cwnd) : 0));
                            }
                        }
                    }
                }
            } else {
                statep->bad_checkpoints = 0;
            }
        } else if (statep) {
            statep->bad_checkpoints = 0;
        }
    }

    {
        /* 0.4.40: skip the EMA update for app-limited votes.
         * A vote where the socket is not using its window
         * measures the app's supplied rate, not the algorithm's
         * capability.  BBR is exempt (rate-based, snd_cwnd
         * deliberately large).  If snd_cwnd is 0 there is no
         * signal; allow the update rather than leave the metric
         * permanently unranked. */
        bool do_update = false;
        if (s == ALG_BBR_INDEX || tp->snd_cwnd == 0) {
            do_update = true;
        } else {
            /* util >= METRIC_MIN_UTIL_PCT, expressed without a
             * 64-bit divide (the verifier chokes on variable /
             * variable).  packets_out >= snd_cwnd * threshold/100. */
            if ((__u64)tp->packets_out * 100 >=
                (__u64)tp->snd_cwnd * METRIC_MIN_UTIL_PCT)
                do_update = true;
        }
        if (do_update) {
            /* 0.4.89 (C1): seq-wrap the entire metric_value + rate_ema
             * + tracker update.  One seq pair around the whole block
             * is sufficient -- reanchor reads the whole struct, so it
             * either sees all of these updates or none. */
            __sync_fetch_and_add(&remote_host->seq, 1);
            /* 0.4.45 rate EMA */
            {
                __u64 r100k = rate_delivered / RATE_EMA_BYTES_PER_UNIT;
                if (r100k > 65535) r100k = 65535;
                if (m->rate_ema == 0) {
                    m->rate_ema = (__u16)r100k;
                } else {
                    __u16 old_ema = m->rate_ema;
                    m->rate_ema = (__u16)(((__u32)m->rate_ema * 15 + (__u32)r100k) >> RATE_EMA_SHIFT);
                    /* 0.4.58: rising throughput on this alg is evidence
                     * conditions changed for it.  Re-admit it as a swap
                     * target -- clear the bad_streak. */
                    if (m->rate_ema > old_ema) {
                        if (m->bad_streak)
                            m->bad_streak = 0;
                        if (m->null_streak)
                            m->null_streak = 0;
                    }
                }
            }
            /* 0.4.89 (Q4): special-case the first sample after the
             * poisoned ~0 sentinel.  The EMA formula
             * `m->metric_value -= (m->metric_value - metric) / __div`
             * happens to produce the right answer when __div=1 (because
             * ~0 - (~0 - metric) = metric in unsigned arithmetic), but
             * with __div > 1 it produces a still-huge value that passes
             * the v != ~0 filter below and enters the best_v tracker
             * as a poisoned large value.  Replace the poison with the
             * actual metric on the first real vote. */
            __u64 __div = m->metric_count + 1;
            if (__div > METRIC_AVG_CAP)
                __div = METRIC_AVG_CAP;
            if (m->metric_value == ~((__u64)0)) {
                m->metric_value = metric;
            } else if (metric > m->metric_value) {
                m->metric_value += (metric - m->metric_value) / __div;
            } else {
                m->metric_value -= (m->metric_value - metric) / __div;
            }
            /* 0.4.89 (M5): bounds note -- rate_ema is __u16 (max 65535),
             * swap_score capped at 1024 (line ~530/585).  The weighted
             * product rv * ss <= 65535 * 1024 = 67M, *16 = 1.07B, well
             * under __u64 max.  If either bound is ever widened, audit
             * the reanchor pass-3 multiplication for overflow. */
        }
    }
    {
        __u64 v = m->metric_value;
        if (v != 0 && v != ~((__u64)0)) {
            /* 0.4.89 (C1): seq-wrap the tracker update -- best_i/best_v
             * /second_i/second_v are read by reanchor and written here. */
            __sync_fetch_and_add(&remote_host->seq, 1);
            if (s == remote_host->best_i) {
                remote_host->best_v = v;
            } else if (s == remote_host->second_i) {
                remote_host->second_v = v;
            } else if (remote_host->best_v == 0 || v < remote_host->best_v) {
                remote_host->second_i = remote_host->best_i;
                remote_host->second_v = remote_host->best_v;
                remote_host->best_i = s;
                remote_host->best_v = v;
            } else if (remote_host->second_v == 0 || v < remote_host->second_v) {
                remote_host->second_i = s;
                remote_host->second_v = v;
            }
            if (remote_host->best_v != 0 && remote_host->second_v != 0 &&
                remote_host->second_v < remote_host->best_v) {
                __u64 ti = remote_host->best_i;
                __u64 tv = remote_host->best_v;
                remote_host->best_i = remote_host->second_i;
                remote_host->best_v = remote_host->second_v;
                remote_host->second_i = ti;
                remote_host->second_v = tv;
            }
            __sync_fetch_and_add(&remote_host->seq, 1);
        }
    }
    /* 0.4.89 (C1): metric_count and greedy_count are also read by
     * reanchor (pass 1/2/3 use metric_count for MIN_LEADER_TRUST).
     * Seq-wrap so the read sees a consistent pair. */
    __sync_fetch_and_add(&remote_host->seq, 1);
    m->metric_count++;
    if (greedy)
        m->greedy_count++;
    __sync_fetch_and_add(&remote_host->seq, 1);
    return 1;
}

