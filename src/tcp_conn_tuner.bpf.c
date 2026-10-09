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

#define TCP_THIN_LINEAR_TIMEOUTS	16

__u64 tcp_cong_choices[NUM_TCP_CONG_ALGS];

long long tcp_thin_lto = 0;

BPF_MAP_DEF(remote_host_map, BPF_MAP_TYPE_LRU_HASH, struct in6_addr, struct remote_host, 4096, 0);

BPF_MAP_DEF(sk_storage_map, BPF_MAP_TYPE_SK_STORAGE, int, struct conn_state, 0, BPF_F_NO_PREALLOC);

BPF_MAP_DEF(midsamp_map, BPF_MAP_TYPE_SK_STORAGE, int, __u64, 0, BPF_F_NO_PREALLOC);

/* 0.4.64: runtime config map.  Currently a single __u32 at key 0:
 * exploration percent for fresh sockets.  Pinned by the userspace
 * daemon so 'bpftune --exp=N' can update it live. */
BPF_MAP_DEF(tuner_config_map, BPF_MAP_TYPE_ARRAY, __u32, __u32, 1, 0);

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
		if (initial)
			remote_host->instances++;
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

static __always_inline int set_cong(struct bpf_sock_ops *ops,
                                    struct remote_host *remote_host,
                                    __u8 i)
{
	int ret;

	ret = bpf_setsockopt(ops, SOL_TCP, TCP_CONGESTION, (void *)congs[i],
	                     sizeof(congs[i]));
	if (ret)
		return ret;
	tcp_cong_choices[i & (NUM_TCP_CONG_ALGS - 1)]++;
	/* update state */
	struct bpf_sock *sk = ops->sk;
	struct conn_state *statep;

	if (!sk)
		return 0;
	statep = bpf_sk_storage_get(&sk_storage_map, sk, 0,
	                            BPF_SK_STORAGE_GET_F_CREATE);
	if (statep) {
		/* 0.4.44: count socket against alg on first contact. */
		__u8 idx = i & (NUM_TCP_CONG_ALGS - 1);
		__u64 bit = 1ULL << idx;
		if (remote_host && !(statep->touched_bitmap & bit)) {
			statep->touched_bitmap |= bit;
			remote_host->metrics[idx].sockets_alive++;
			/* 0.4.62: initialize swap_score to neutral the first time
			 * this algorithm runs on this bucket.  Makes the map
			 * self-describing -- 0 never appears for an untested alg,
			 * so picker and dashboard both trust the raw field. */
			if (remote_host->metrics[idx].swap_score == 0)
				remote_host->metrics[idx].swap_score =
					SWAP_SCORE_NEUTRAL;
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
    struct remote_host *remote_host;
    struct in6_addr raddr = {};
    struct in6_addr *key = &raddr;
    struct bpf_sock *sk = ops->sk;
    struct conn_state *statep = NULL;

    switch (ops->op) {
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        bpf_sock_ops_cb_flags_set(ops, cb_flags);
        break;
    case BPF_SOCK_OPS_RETRANS_CB:
        if (ops->total_retrans > (ops->segs_out >> DROP_SHIFT)) {
            if (sk)
                statep = bpf_sk_storage_get(&sk_storage_map, sk, 0, 0);
            if (!statep && !tcp_thin_lto) {
                int one = 1;
                if (!bpf_setsockopt(ops, SOL_TCP, TCP_THIN_LINEAR_TIMEOUTS,
                                    &one, sizeof(one)))
                    tcp_thin_lto_choices++;
            }
        }
        return 1;
    default:
        return 1;
    }

    if (!sk)
        return 1;
    if (ops->family == AF_INET) {
        __u32 ip4 = bpf_ntohl(ops->remote_ip4);
        if ((ip4 & 0xff000000) == 0x7f000000) return 1;
        if ((ip4 & 0xffff0000) == 0xa9fe0000) return 1;
    } else if (ops->family == AF_INET6) {
        if (ops->remote_ip6[0] == 0 && ops->remote_ip6[1] == 0 && ops->remote_ip6[2] == 0 && ops->remote_ip6[3] == bpf_htonl(1)) return 1;
        if ((ops->remote_ip6[0] & bpf_htonl(0xffc00000)) == bpf_htonl(0xfe800000)) return 1;
    }
    switch (ops->family) {
    case AF_INET:
        key->s6_addr32[2] = bpf_htonl(0xffff);
        key->s6_addr32[3] = ops->remote_ip4 & bpf_htonl(0xFFFF0000)   /* 0.4.55: /16 merge */;
        break;
    case AF_INET6:
        key->s6_addr32[0] = ops->remote_ip6[0];  /* 0.4.56: /32 */
        key->s6_addr32[1] = 0;
        key->s6_addr32[2] = 0;
        key->s6_addr32[3] = 0;
        break;
    default:
        return 1;
    }
    remote_host = get_remote_host(key, true);
    if (!remote_host)
        return 1;

    {
        __u64 metric_min = ~((__u64)0x0);
        __u8 i, minindex = 0, s;

        if (remote_host->selection_count < 2 * NUM_TCP_CONN_METRICS) {
            __u8 forced = remote_host->selection_count & (NUM_TCP_CONN_METRICS - 1);
            remote_host->selection_count++;
            if (set_cong(ops, remote_host, forced)) {
                remote_host->metrics[forced].metric_value = ~((__u64)0);
            } else {
                bpf_printk("estab cookie=%llu alg=%u forced=1 dest=%u",
                           bpf_get_socket_cookie(ops), (__u32)forced,
                           (__u32)bpf_ntohl(ops->remote_ip4));
            }
            return 1;
        }

        {
            __u64 min2 = ~((__u64)0);
            for (i = 0; i < NUM_TCP_CONN_METRICS; i++) {
                __u64 v = remote_host->metrics[i].metric_value;
                /* Sentinel metrics (0 unset, ~0 poisoned) may win
                 * the min loop here and be reported as minindex,
                 * but both consumers check before writing: the
                 * ESTABLISHED path requires metric_count > 0, and
                 * the vote path tracker update is guarded by its
                 * own v != 0 && v != ~0 test.  A skip filter here
                 * blew the verifier to the 1M instruction limit
                 * (16-way unrolled loop, unprovable ranges), so it
                 * is intentionally omitted. */
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
            if (remote_host->metrics[minindex].metric_count > 0) {
                remote_host->best_i = minindex;
                remote_host->best_v = metric_min;
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
                bpf_printk("estab cookie=%llu alg=%u forced=0 dest=%u",
                           bpf_get_socket_cookie(ops), (__u32)s,
                           (__u32)bpf_ntohl(ops->remote_ip4));
            }
        }
    }
    return 1;
}

/* 0.4.56: score the pending swap once >=60s have elapsed.  Cur rate
 * vs the captured pre-swap rate sets target alg's swap_score; 256 is
 * neutral.  Called from the vote path. */
static __always_inline void
score_pending_swap(struct bpf_sock_ops *ops, struct remote_host *rh,
                   struct conn_state *statep, __u64 now, __u64 cur_rate,
                   __u8 cur_alg)
{
        __u8 tgt;
        __u64 pre, elapsed, ratio_q;

        if (statep->swap_target == 0xff) return;
        if (statep->pre_swap_rate == 0)  return;
        elapsed = now - statep->last_swap_at;
        if (elapsed < SWAP_OUTCOME_MIN_RNAL_NS) return;

        pre = statep->pre_swap_rate;
        tgt = (__u8)(statep->swap_target & (NUM_TCP_CONG_ALGS - 1));
        /* 0.4.65: if the socket is no longer on the pending target,
         * the swap was rejected before the 60s window opened.  Force
         * the ratio to loss-class regardless of the current rate.
         * This closes the case where a socket swapped A->B at T=0 and
         * B->C at T=30: without this check, the T+60 sample would read
         * C's rate and attribute it to B. */
        if (cur_alg != tgt) {
                ratio_q = 0;
        } else {
                ratio_q = (cur_rate * SWAP_SCORE_NEUTRAL) / pre;
                if (ratio_q > 1024) ratio_q = 1024;
        }

        /* read-modify-write u16 field via pointer cast */
        {
                __u16 cur16 = rh->metrics[tgt].swap_score;
                __u32 cur32 = cur16 ? cur16 : SWAP_SCORE_NEUTRAL;
                /* 0.4.60: asymmetric scoring.  Wins move by 1/16
                 * (unchanged).  Nulls pull toward neutral 256 by
                 * 1/4 so a high score cannot coast through
                 * inactivity.  Losses pull toward the observed
                 * ratio by 1/2 -- bigger misses drop the score more.
                 * No signed division; take the unsigned difference,
                 * then add or subtract based on which is larger. */
                if (ratio_q >= 282) {
                        if (ratio_q >= cur32) {
                                __u32 step = (__u32)(ratio_q - cur32) / SWAP_SCORE_STEP_DIV;
                                cur32 += step;
                        } else {
                                __u32 drop = (__u32)(cur32 - ratio_q) / SWAP_SCORE_STEP_DIV;
                                cur32 = (drop > cur32) ? 0 : cur32 - drop;
                        }
                } else if (ratio_q > 230) {
                        if (cur32 > SWAP_SCORE_NEUTRAL) {
                                __u32 drop = (cur32 - SWAP_SCORE_NEUTRAL) / SWAP_SCORE_NULL_DIV;
                                cur32 = (drop > cur32) ? 0 : cur32 - drop;
                        } else if (cur32 < SWAP_SCORE_NEUTRAL) {
                                __u32 step = (SWAP_SCORE_NEUTRAL - cur32) / SWAP_SCORE_NULL_DIV;
                                cur32 += step;
                        }
                } else {
                        if (ratio_q >= cur32) {
                                __u32 step = (__u32)(ratio_q - cur32) / SWAP_SCORE_LOSS_DIV;
                                cur32 += step;
                        } else {
                                __u32 drop = (__u32)(cur32 - ratio_q) / SWAP_SCORE_LOSS_DIV;
                                cur32 = (drop > cur32) ? 0 : cur32 - drop;
                        }
                }
                if (cur32 > 1024) cur32 = 1024;
                rh->metrics[tgt].swap_score = (__u16)cur32;
        }
        /* 0.4.58: consecutive failed swaps to this alg.  Two in a
         * row is a pattern; a later rising rate_ema clears it in the
         * vote path.  Win/null clears; loss increments. */
        /* 0.4.59: ratio_q = post/pre * 256.  Three outcomes:
         *   <= 230   loss  (ratio <= 0.9)   -> bad_streak++
         *   >= 282   win   (ratio >= 1.1)   -> both = 0
         *   between  null  (no change)      -> null_streak++
         * A null isn't proof of failure but it isn't a win either --
         * three in a row and the target gets excluded. */
        if (ratio_q <= 230) {
                if (rh->metrics[tgt].bad_streak < 255)
                        rh->metrics[tgt].bad_streak++;
        } else if (ratio_q >= 282) {
                rh->metrics[tgt].bad_streak = 0;
                rh->metrics[tgt].null_streak = 0;
        } else {
                if (rh->metrics[tgt].null_streak < 255)
                        rh->metrics[tgt].null_streak++;
        }
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
 * is done here. */
static __always_inline void
score_pending_rejected(struct bpf_sock_ops *ops, struct remote_host *rh,
                       struct conn_state *statep, __u64 now, __u64 cur_rate)
{
        __u8 tgt;
        __u64 pre, ratio_q;
        __u16 cur16;
        __u32 cur32;

        if (statep->swap_target == 0xff) return;
        if (statep->pre_swap_rate == 0)  return;

        pre = statep->pre_swap_rate;
        tgt = (__u8)(statep->swap_target & (NUM_TCP_CONG_ALGS - 1));

        /* Force loss-class.  Cap at 230 (ratio <= 0.9) even if the
         * current rate happens to look high; the socket leaving the
         * target is the signal, not the momentary rate. */
        ratio_q = (cur_rate * SWAP_SCORE_NEUTRAL) / pre;
        if (ratio_q > 230) ratio_q = 230;

        cur16 = rh->metrics[tgt].swap_score;
        cur32 = cur16 ? cur16 : SWAP_SCORE_NEUTRAL;
        if (ratio_q >= cur32) {
                __u32 step = (__u32)(ratio_q - cur32) / SWAP_SCORE_LOSS_DIV;
                cur32 += step;
        } else {
                __u32 drop = (__u32)(cur32 - ratio_q) / SWAP_SCORE_LOSS_DIV;
                cur32 = (drop > cur32) ? 0 : cur32 - drop;
        }
        if (cur32 > 1024) cur32 = 1024;
        rh->metrics[tgt].swap_score = (__u16)cur32;

        if (rh->metrics[tgt].bad_streak < 255)
                rh->metrics[tgt].bad_streak++;

        bpf_printk("swapscore-reject cookie=%llu tgt=%u ratio=%llu bad=%u",
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
    struct tcp_conn_metric *m;
    bool greedy = true;
    __u8 s;
    bool is_close;
    __u64 now;
    bool allow_ref = false;
    __u64 tc_progress = 0;

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
    if (ops->family == AF_INET) {
        __u32 ip4 = bpf_ntohl(ops->remote_ip4);
        if ((ip4 & 0xff000000) == 0x7f000000) return 1;
        if ((ip4 & 0xffff0000) == 0xa9fe0000) return 1;
    } else if (ops->family == AF_INET6) {
        if (ops->remote_ip6[0] == 0 && ops->remote_ip6[1] == 0 && ops->remote_ip6[2] == 0 && ops->remote_ip6[3] == bpf_htonl(1)) return 1;
        if ((ops->remote_ip6[0] & bpf_htonl(0xffc00000)) == bpf_htonl(0xfe800000)) return 1;
    }
    switch (ops->family) {
    case AF_INET:
        key->s6_addr32[2] = bpf_htonl(0xffff);
        key->s6_addr32[3] = ops->remote_ip4 & bpf_htonl(0xFFFF0000);
        break;
    case AF_INET6:
        key->s6_addr32[0] = ops->remote_ip6[0];  /* 0.4.56: /32 */
        key->s6_addr32[1] = 0;
        key->s6_addr32[2] = 0;
        key->s6_addr32[3] = 0;
        break;
    default:
        return 1;
    }
    remote_host = get_remote_host(key, false);
    if (!remote_host)
        return 1;
    if (!tp)
        return 1;

    is_close = (ops->op == BPF_SOCK_OPS_STATE_CB);
    statep = bpf_sk_storage_get(&sk_storage_map, sk, 0, 0);
    if (!statep)
        return 1;
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
    if (is_close)
        bpf_printk("closport cookie=%llu port=%u rport=%u alg=%u segs=%llu",
                   bpf_get_socket_cookie(ops), ops->local_port,
                   bpf_ntohl(ops->remote_port),
                   (__u32)(statep->state & (NUM_TCP_CONG_ALGS - 1)),
                   (__u64)tp->segs_out + tp->segs_in);
    if (is_close &&
        (__u64)tp->segs_out + tp->segs_in >= METRIC_TRIGGER_SEGS)
        return 1;
    min_rtt = (__u64)tp->rtt_min.s[0].v;
    avg_rtt = (__u64)(tp->srtt_us >> 3);
    rate_interval_us = (__u64)tp->rate_interval_us; /* printk only */
    mss = (__u64)tp->mss_cache;
    /* 0.4.69: sustained rate = bytes acked+received / wall-clock time.
     * Was: (tp->rate_delivered * mss * 1e6) / tp->rate_interval_us.
     * That kernel estimate updates on ACK arrival and can hold a
     * value from minutes ago; measured divergence on heavy against
     * actual segment movement was 37x on a steady socket and 2500x
     * on a stalled one.  Every downstream signal (last_rate_bps,
     * d=1/d=3 thresholds, rate_ema, swap_score) reads this value. */
    {
        __u64 now_ns = bpf_ktime_get_ns();
        __u64 bytes_total = (__u64)tp->bytes_acked +
                            (__u64)tp->bytes_received;
        if (statep && statep->rate_win_ts_ns) {
            __u64 elapsed = now_ns - statep->rate_win_ts_ns;
            if (elapsed >= RATE_WIN_MIN_NS) {
                __u64 bytes_delta = bytes_total - statep->rate_win_bytes;
                rate_delivered = (bytes_delta * 1000000000ULL) / elapsed;
                statep->rate_win_ts_ns = now_ns;
                statep->rate_win_bytes = bytes_total;
            } else {
                rate_delivered = statep->last_rate_bps;
            }
        } else {
            if (statep) {
                statep->rate_win_ts_ns = now_ns;
                statep->rate_win_bytes = bytes_total;
            }
            rate_delivered = 0;
        }
    }

	/* 0.4.44: proof tracking.  Non-close votes only.  If the
	 * socket's delivered rate crosses a tier on the alg it is
	 * currently running, mark the (socket, alg) bit and bump the
	 * per-alg counter.  Bits are per-alg so a swap does not have
	 * to reset anything -- each alg the socket has ever touched
	 * keeps its own bit, and the close handler decrements them
	 * all. */
	if (!is_close) {
		__u64 bit = 1ULL << (s & (NUM_TCP_CONG_ALGS - 1));
		if (rate_delivered >= PROOF_PROVED_BPS && !(statep->proved_bitmap & bit)) {
			statep->proved_bitmap |= bit;
			remote_host->metrics[s].sockets_proved++;
			if (!(statep->good_bitmap & bit)) {
				statep->good_bitmap |= bit;
				remote_host->metrics[s].sockets_good++;
			}
			bpf_printk("proof cookie=%llu alg=%d rate=%llu tier=2",
			           bpf_get_socket_cookie(ops), s, rate_delivered);
		} else if (rate_delivered >= PROOF_GOOD_BPS && !(statep->good_bitmap & bit)) {
			statep->good_bitmap |= bit;
			remote_host->metrics[s].sockets_good++;
			bpf_printk("proof cookie=%llu alg=%d rate=%llu tier=1",
			           bpf_get_socket_cookie(ops), s, rate_delivered);
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
        bpf_printk("srate cookie=%llu alg=%u srate=%llu",
                   bpf_get_socket_cookie(ops), s, _srate);
    }

    m = &remote_host->metrics[s];

    {
        __u64 rtt_term = 0, rate_term = 0, loss_term = 0;
        __u64 heal_rtt = 0, heal_rate = 0;
        metric = tcp_metric_calc(remote_host, min_rtt, avg_rtt, rate_delivered,
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
        bpf_printk("cwnd cookie=%llu snd_cwnd=%llu pkts_out=%llu",
                   bpf_get_socket_cookie(ops),
                   (__u64)tp->snd_cwnd, (__u64)tp->packets_out);
        if (heal_rtt)
            bpf_printk("heal_rtt smrtt=%llu newref=%llu",
                       (unsigned long long)min_rtt,
                       (unsigned long long)heal_rtt);
        if (heal_rate)
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
        statep->last_rate_bps = rate_delivered;
        score_pending_swap(ops, remote_host, statep, bpf_ktime_get_ns(), rate_delivered,
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
    }

    {
        __u64 best_alt = ~((__u64)0);
        __u8 best_alt_i = 0;

        __u8 mt_alt_i = 0;

        __u8 swap_tgt = 0;

        if (remote_host->best_v != 0) {
            if (s != remote_host->best_i) {
                /* Socket on non-leader: target the leader. */
                __u8 bi = (__u8)(remote_host->best_i & (NUM_TCP_CONN_METRICS - 1));
                if (remote_host->metrics[bi].metric_count >= MIN_LEADER_TRUST) {
                    best_alt = remote_host->best_v;
                    best_alt_i = bi;
                }
            } else if (remote_host->second_v != 0) {
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
            /* 0.4.49: block a swap to a target whose rate_ema on this
             * bucket is lower than the source's.  Observed cookie 16102:
             * nv(rate_ema=13) -> reno(rate_ema=3) because reno was the
             * only alg to pass MIN_LEADER_TRUST; socket died at 12% loss. */
            bool rate_ok = true;
            if (remote_host->rate_best_v > 0 &&
                remote_host->metrics[swap_tgt].rate_ema <
                remote_host->metrics[s].rate_ema)
                rate_ok = false;
            /* 0.4.50: skip swaps on sockets not using their window.
             * Weekend data: 60% of swaps fired at util<10%; 42% had
             * pkts_out<=1.  Those sockets were idle; no algorithm
             * change can help them.  Same threshold the vote path
             * already uses (METRIC_MIN_UTIL_PCT). */
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
            /* 0.4.54: rate-based.  socket under 66% of leader. */
            bool margin_met = (remote_host->rate_best_v > 0 &&
                               statep->last_rate_bps > 0 &&
                               statep->last_rate_bps * 150 <
                               remote_host->rate_best_v * 100000ULL * 100);
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
            bool desperate = (margin_met &&
                              statep->last_rate_bps * 400 <
                              remote_host->rate_best_v * 100000ULL * 100 &&
                              (!statep->frozen || desperate_post));

            /* Settle window: fixed minimum gap between swaps on one
             * socket.  Historically split (60s moderate / 10s
             * desperate), but the moderate path always arrived with
             * persist_bad already >= 2 -- 60s was unreachable in
             * practice.  10s is >= 300 RTT on a 30ms path, enough
             * for the new algorithm to settle, and the 2-bad-check
             * requirement above already prevents thrash. */
            bool settle_expired = (now >= statep->last_swap_at + T_SETTLE_NS);

            __u64 eff_ref = remote_host->max_rate_delivered;
            if (eff_ref < REF_FLOOR_BPS)
                eff_ref = REF_FLOOR_BPS;
            bool slow_vs_ref = (statep->last_rate_bps > 0 &&
                                eff_ref > 0 &&
                                statep->last_rate_bps * 100 <
                                eff_ref * SLOW_VS_REF_PCT);

            /* 0.4.52: slow-vs-leader.  Uses the rate directly, bypassing
             * the composite.  A swap that raises throughput fills the
             * bottleneck queue; the induced RTT rise masks the win. */
            bool slow_vs_leader = (statep->last_rate_bps > 0 &&
                                   remote_host->rate_best_v > 0 &&
                                   statep->last_rate_bps * 100 <
                                   remote_host->rate_best_v * 100000 * RATE_TRIGGER_PCT);

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
                    statep->last_metric = 0;
                    score_pending_rejected(ops, remote_host, statep, now, statep->last_rate_bps);
                    statep->pre_swap_rate = statep->last_rate_bps;
                    statep->swap_target = swap_tgt;
                    statep->last_rate_bps = 0;
                    statep->hist_1 = 0;
                    statep->hist_2 = 0;
                    statep->bad_checkpoints = 0;
                    bpf_printk("swap cookie=%llu from=%u to=%u bc=%llu ac=%llu d=1 mt=%u rb=%u dest=%u",
                               bpf_get_socket_cookie(ops), from_i, to_i,
                               bc_fire, ac, (__u32)mt_alt_i, (__u32)swap_tgt, (__u32)bpf_ntohl(ops->remote_ip4));
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
                    __u64 tgt = statep->best_seen_alg & (NUM_TCP_CONG_ALGS - 1);
                    __u8 tgt8 = (__u8)tgt;
                    if (statep->best_seen_metric != 0 && tgt8 != s)
                        fret = set_cong(ops, remote_host, tgt8);
                    bpf_printk("freeze cookie=%llu from=%u to=%u ret=%d dest=%u",
                               bpf_get_socket_cookie(ops), s, tgt8, fret, (__u32)bpf_ntohl(ops->remote_ip4));
                    statep->frozen = 1;
                    statep->last_swap_at = now;
                    statep->last_metric = 0;
                    score_pending_rejected(ops, remote_host, statep, now, statep->last_rate_bps);
                    statep->pre_swap_rate = statep->last_rate_bps;
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
                        statep->last_metric = 0;

                        /* 0.4.56: stage pre-swap rate and target for scoring. */
                        score_pending_rejected(ops, remote_host, statep, now, statep->last_rate_bps);
                        statep->pre_swap_rate = statep->last_rate_bps;
                        statep->swap_target = swap_tgt;
                        statep->last_rate_bps = 0;
                        statep->hist_1 = 0;
                        statep->hist_2 = 0;
                        statep->bad_checkpoints = 0;
                        bpf_printk("swap cookie=%llu from=%u to=%u bc=%llu ac=%llu d=2 mt=%u rb=%u dest=%u",
                                   bpf_get_socket_cookie(ops), from_i, to_i,
                                   (__u64)0, ac, (__u32)mt_alt_i, (__u32)swap_tgt, (__u32)bpf_ntohl(ops->remote_ip4));
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
                    __u64 tgt = statep->best_seen_alg & (NUM_TCP_CONG_ALGS - 1);
                    __u8 tgt8 = (__u8)tgt;
                    if (statep->best_seen_metric != 0 && tgt8 != s)
                        fret = set_cong(ops, remote_host, tgt8);
                    bpf_printk("freeze cookie=%llu from=%u to=%u ret=%d dest=%u",
                               bpf_get_socket_cookie(ops), s, tgt8, fret, (__u32)bpf_ntohl(ops->remote_ip4));
                    statep->frozen = 1;
                    statep->last_swap_at = now;
                    statep->last_metric = 0;
                    score_pending_rejected(ops, remote_host, statep, now, statep->last_rate_bps);
                    statep->pre_swap_rate = statep->last_rate_bps;
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
                        statep->last_metric = 0;

                        /* 0.4.56: stage pre-swap rate and target for scoring. */
                        score_pending_rejected(ops, remote_host, statep, now, statep->last_rate_bps);
                        statep->pre_swap_rate = statep->last_rate_bps;
                        statep->swap_target = swap_tgt;
                        statep->last_rate_bps = 0;
                        statep->hist_1 = 0;
                        statep->hist_2 = 0;
                        statep->bad_checkpoints = 0;
                        bpf_printk("swap cookie=%llu from=%u to=%u bc=%llu ac=%llu d=3 mt=%u rb=%u dest=%u",
                                   bpf_get_socket_cookie(ops), from_i, to_i,
                                   (__u64)0, ac, (__u32)mt_alt_i, (__u32)swap_tgt, (__u32)bpf_ntohl(ops->remote_ip4));
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
                    __u64 tgt = statep->best_seen_alg & (NUM_TCP_CONG_ALGS - 1);
                    __u8 tgt8 = (__u8)tgt;
                    if (statep->best_seen_metric != 0 && tgt8 != s)
                        fret = set_cong(ops, remote_host, tgt8);
                    bpf_printk("freeze cookie=%llu from=%u to=%u ret=%d dest=%u",
                               bpf_get_socket_cookie(ops), s, tgt8, fret, (__u32)bpf_ntohl(ops->remote_ip4));
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
                    statep->last_metric = 0;
                    score_pending_rejected(ops, remote_host, statep, now, statep->last_rate_bps);
                    statep->pre_swap_rate = statep->last_rate_bps;
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
                                statep->last_metric = 0;

                                /* 0.4.56: stage pre-swap rate and target for scoring. */
                                score_pending_rejected(ops, remote_host, statep, now, statep->last_rate_bps);
                                statep->pre_swap_rate = statep->last_rate_bps;
                                statep->swap_target = swap_tgt;
                                statep->last_rate_bps = 0;
                                statep->hist_1 = 0;
                                statep->hist_2 = 0;
                                statep->bad_checkpoints = 0;
                                bpf_printk("swap cookie=%llu from=%u to=%u bc=%llu ac=%llu d=0 mt=%u rb=%u dest=%u",
                                           bpf_get_socket_cookie(ops), from_i, to_i,
                                           bc_fire, ac, (__u32)mt_alt_i, (__u32)swap_tgt, (__u32)bpf_ntohl(ops->remote_ip4));
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
        __u64 __div = m->metric_count + 1;
            if (__div > METRIC_AVG_CAP)
                __div = METRIC_AVG_CAP;
            if (metric > m->metric_value)
                m->metric_value += (metric - m->metric_value) / __div;
            else
                m->metric_value -= (m->metric_value - metric) / __div;
        }
    }
    {
        __u64 v = m->metric_value;
        if (v != 0 && v != ~((__u64)0)) {
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
        }
    }
    m->metric_count++;
    if (greedy)
        m->greedy_count++;
    return 1;
}

