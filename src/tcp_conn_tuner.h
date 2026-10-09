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

#include <bpftune/bpftune.h>

enum tcp_cong_tunables {
    TCP_CONG,
    TCP_ALLOWED_CONG,
    TCP_AVAILABLE_CONG,
    TCP_CONG_DEFAULT,
    TCP_THIN_LINEAR_TIMEOUTS
};

enum tcp_cong_scenarios {
    TCP_CONG_SET,
};

#define CONG_MAXNAME 16

#define CONN_TUNER_BPF "bpftune_conn_tuner"
#define CONN_TUNER_VOTE_BPF "bpftune_conn_tuner_vote"

/* Expanded to 16 algorithms (must be a power of two for bitmask logic) */
enum tcp_states {
    TCP_STATE_CONG_CUBIC,
    TCP_STATE_CONG_BBR,
    TCP_STATE_CONG_HTCP,
    TCP_STATE_CONG_DCTCP,
    TCP_STATE_CONG_SCALABLE,
    TCP_STATE_CONG_VEGAS,
    TCP_STATE_CONG_VENO,
    TCP_STATE_CONG_WESTWOOD,
    TCP_STATE_CONG_RENO,
    TCP_STATE_CONG_ILLINOIS,
    TCP_STATE_CONG_YEAH,
    TCP_STATE_CONG_LP,
    TCP_STATE_CONG_BIC,
    TCP_STATE_CONG_HIGHSPEED,
    TCP_STATE_CONG_HYBLA,
    TCP_STATE_CONG_NV,
    NUM_TCP_CONG_ALGS
};

/* match order of enum tcp_states */
const char congs[NUM_TCP_CONG_ALGS][CONG_MAXNAME] = {
    "cubic", "bbr", "htcp", "dctcp",
    "scalable", "vegas", "veno", "westwood",
    "reno", "illinois", "yeah", "lp",
    "bic", "highspeed", "hybla", "nv"
};

#define RATE_HIST_BINS        32
#define RATE_HIST_HALVE_TOTAL 100000ULL
#define RATE_HIST_PCT         99

/* 0.4.44 proof thresholds (bytes/sec).  "Good" = a rate that carries
 * 4K-class video; "proved" = 8K-class.  Converted from client-side
 * Mbps figures / 8.  A socket is scored per (socket, alg) at the
 * moment it first crosses each tier while running that alg. */
#define PROOF_GOOD_BPS   3750000ULL    /*  30 Mbps */
#define PROOF_PROVED_BPS 12500000ULL   /* 100 Mbps */

/*
 * Log2-binned delivered-rate histogram.  Bin i covers
 *   [2^i KB/s, 2^(i+1) KB/s).
 * Each vote increments one bin.  The userspace reanchor worker
 * decays the histogram when total > RATE_HIST_HALVE_TOTAL, computes
 * p99, and writes the result as max_rate_delivered.  BPF never reads
 * the bins; it only appends.
 */
struct rate_hist {
	__u32 bins[RATE_HIST_BINS];
	__u64 total;
};

struct conn_state {
    __u64 state;
    __u64 swap_count;
    __u64 bad_checkpoints;
    __u64 last_swap_at;      /* ns; settle windows computed per tick */
    __u64 last_metric;       /* most recent metric sample; 0 = unset */
    __u64 last_rate_bps;     /* most recent delivered rate, bytes/sec; 0 = unset */
    __u64 last_time_check;   /* ns of last 60s-cadence vote */
    __u64 time_check_segs;   /* segments at last time check */
    __u64 best_seen_metric;  /* lowest metric seen on this socket */
    __u64 best_seen_alg;     /* algorithm it was running then */
    __u64 frozen;            /* 1 = no more swaps on this socket */
    /* 0.4.54: exploring=1 when assigned alg is neither leader. votes_on_alg counts votes on that alg; reset at every set_cong. */
    __u64 exploring;
    __u64 votes_on_alg;
    /* Short-trend history.  Along with last_metric these give the
     * socket's own last three samples.  Used by the flat-socket
     * gate in the moderate swap tier (0.4.37): if max/min over the
     * three is < 1.10 the current algorithm is not moving the
     * socket, and a swap cannot help.  Reset to 0 on every swap
     * (shape across an algorithm change is not meaningful). */
    __u64 hist_1;
    __u64 hist_2;
	/* 0.4.44 proof tracking.  One bit per algorithm.  touched is set
	 * on first contact with an alg (initial selection or swap-in);
	 * good / proved are set the first time the socket's delivered
	 * rate crosses the matching tier while on that alg.  cleaned is
	 * a one-shot flag so the close decrement runs exactly once even
	 * if STATE_CB fires on multiple transitions. */
	__u64 touched_bitmap;
	__u64 good_bitmap;
	__u64 proved_bitmap;
	__u64 cleaned;


	/* 0.4.56: pending-swap scoring. */

	__u64 pre_swap_rate;

	__u64 swap_target;

	/* 0.4.68/0.4.69: rolling window for sustained-rate computation.
	 * rate_win_ts_ns == 0 means the window has not been seeded
	 * (socket's first vote).  rate_win_bytes is
	 * bytes_acked + bytes_received at that boundary.  (0.4.68 used
	 * segs_out+segs_in, which undercounted GSO super-segments.) */
	__u64 rate_win_ts_ns;
	__u64 rate_win_bytes;
};

struct tcp_conn_metric {
    __u64 state_flags;
    __u64 greedy_count;
    __u64 metric_count;
    __u64 metric_value;
	/* 0.4.44 proof tracking.  sockets_alive counts sockets currently
	 * on this alg; decremented at socket close for every alg the
	 * socket ever touched.  sockets_good / sockets_proved count the
	 * subset that crossed each tier at some point while on this alg. */
	__u16 sockets_alive;
	__u16 sockets_good;
	__u16 sockets_proved;

	/* 0.4.45: rate EMA in 100KB/s units; swap target reads it. */

	__u16 rate_ema;
	__u16 swap_score;
	__u8  bad_streak;   /* 0.4.58: consecutive failed swaps to this alg */
	__u8  null_streak;  /* 0.4.59: consecutive null swaps to this alg */
};

#define NUM_TCP_CONN_METRICS NUM_TCP_CONG_ALGS

/* 0.4.64: runtime-tunable exploration percentage.  Stored in
 * tuner_config_map at key 0.  BPF reads it at ESTABLISHED;
 * 'bpftune --exp=N' writes it via the pinned fd. */
#define EXPLORE_PCT_DEFAULT       5

/* 0.4.68: rolling window for the sustained-rate computation.
 * The tuner used to read tp->rate_delivered, a burst estimate
 * that can be stale by minutes.  last_rate_bps is now derived
 * from actual segment movement over >= this window. */
#define RATE_WIN_MIN_NS  (500ULL * 1000000ULL)
#define EXPLORE_PCT_MAX           100
#define EXPLORE_BOOST_PCT         25

struct tcp_conn_event_data {
    struct in6_addr raddr;
    __u64 state_flags;
    __u64 rate_delivered;
    __u64 min_rtt;
    __u64 metric;
};

struct remote_host {
    __u64 min_rtt;
    __u64 max_rate_delivered;
    __u64 instances;
    __u64 selection_count;
    /* Incremental best and 2nd-best across metrics; refreshed on every
     * vote.  best_v == 0 means unset.  Vote path reads these for a
     * live swap target without a 16-iter loop. */
    __u64 best_i;
    __u64 best_v;
    __u64 second_i;
    __u64 second_v;

    /* 0.4.45: rate-EMA leader for swap target; 0 = unset. */

    __u64 rate_best_i;

    __u64 rate_best_v;
    /* 0.4.70: second-best rate target.  Used as a fallback when
     * the socket is already on the rate leader and the leader is
     * failing for this socket.  Same units as rate_best_v. */
    __u64 rate_second_i;
    __u64 rate_second_v;
    /* Reference-refresh streak state.  A single far-better-than-
     * reference reading is treated as an outlier; REF_HIGH_STREAK_N
     * in a row promote the reference to the best of the streak.
     * Frozen while allow_ref_update is false (control-plane votes). */
    __u64 rtt_low_streak;	/* RTT side -- unchanged this release */
    __u64 rtt_low_min;
    struct rate_hist rate;   /* rate side: histogram replaces streaks */
    struct tcp_conn_metric metrics[NUM_TCP_CONN_METRICS];
};

#define REMOTE_HOST_MIN_INSTANCES 4
#define DROP_SHIFT 6
#define RTT_SCALE 1000000
/* cap the RTT deviation term so one anomalously-low
 * measurement cannot permanently poison the metric. */
#define RTT_DEVIATION_CAP 8
/* Match the throughput term's ceiling to the RTT term's (which is
 * RTT_SCALE * RTT_DEVIATION_CAP = 8000000).  Without this, RTT could
 * contribute up to 8x more than throughput to the summed metric,
 * making the throughput term effectively decorative even though it's
 * now producing real values. */
#define DELIVERY_SCALE 8000000
/* Loss term: penalizes retransmits as a fraction of our sent
 * segments.  LOSS_CAP_BP is the loss rate in basis points that
 * earns the full penalty; above it the term saturates.  200 = 2%. */
#define LOSS_CAP_BP   200
#define LOSS_SCALE    8000000
#define METRIC_MIN_SEGS 100
#define METRIC_TRIGGER_SEGS 10000
#define METRIC_AVG_CAP 32

/* 0.4.51: if a socket delivers under SLOW_VS_REF_PCT percent of the
 * bucket reference, it is stuck regardless of what the leader scores.
 * Fires on the first vote -- the 3-10 minute stuck-window on a
 * struggling stream cannot produce two votes to clear the moderate
 * tier's 2-consecutive-bad requirement. */
#define SLOW_VS_REF_PCT 10
#define RATE_TRIGGER_PCT 50

/* 0.4.56: floor per-bucket reference used by d2.  Mobile buckets at
 * 4 Mbps ref make "10% of ref" 0.4 Mbps, which nothing trips. */
#define REF_FLOOR_BPS           2000000ULL

/* 0.4.56: per-(bucket,alg) swap outcome score.  256 neutral; target
 * picker computes rate_ema * score / 256 so a repeatedly-failing alg
 * loses the race automatically. */
#define SWAP_SCORE_NEUTRAL       256
#define SWAP_SCORE_STEP_DIV      16
/* 0.4.60: asymmetric divisors.  Wins keep the slow /16 EMA.  Nulls
 * pull toward neutral at /4 so a high score can't coast through
 * inactivity.  Losses pull toward the observed ratio at /2 so a
 * bad miss drops the score quickly. */
#define SWAP_SCORE_NULL_DIV      4
#define SWAP_SCORE_LOSS_DIV      2
/* 0.4.58: two consecutive failed swaps is a pattern; three costs too
 * much.  Rising rate_ema on a later vote clears this -- network
 * conditions changed, re-admit as a target. */
#define SWAP_BAD_STREAK_TRUST    2
/* 0.4.59: three consecutive nulls (no change either way) is not
 * chance.  A null costs a cwnd reset and proves nothing. */
#define SWAP_NULL_STREAK_TRUST   3
#define SWAP_OUTCOME_MIN_RNAL_NS (60ULL * 1000000000ULL)

/* 0.4.51: if a socket delivers under SLOW_VS_REF_PCT percent of the
 * bucket reference, it is stuck regardless of what the leader scores.
 * Fires on the first vote -- the 3-10 minute stuck-window on a
 * struggling stream cannot produce two votes to clear the moderate
 * tier's 2-consecutive-bad requirement. */
#define SLOW_VS_REF_PCT 10
/* 0.4.45: rate EMA decay shift; divide-by-16, ~16-vote half life. */
#define RATE_EMA_SHIFT          4
/* 0.4.45: rate EMA units.  u16 max ~= 6.5 GB/s. */
#define RATE_EMA_BYTES_PER_UNIT 100000ULL
/* 0.4.40: utilization gate on the bucket EMA update.  A vote
 * where the socket is not filling its cwnd-permitted window
 * measures the rate the app supplied, not the rate the
 * algorithm permitted; scoring the algorithm on it ranks on a
 * quantity the algorithm did not set.  Measured on the heavy
 * host 2026-09-16: median util 0.08-0.10, ~50% of votes under
 * 0.10, only ~5% above 0.50.  BBR is exempt (rate-based, keeps
 * snd_cwnd large by design and paces separately). */
#define METRIC_MIN_UTIL_PCT 10
#define ALG_BBR_INDEX 1
/* Mid-socket swap policy.  Compare the current algorithm bucket EMA
 * against the best alternative bucket EMA - not a single socket
 * sample against an average.  If the ratio holds for SWAP_AFTER_BAD
 * consecutive checkpoints and the socket has not already swapped
 * MAX_SWAPS times, move it.  After a swap, suppress re-judgement
 * for T_SETTLE_NS: tcp_reinit_congestion_control resets cwnd and
 * ssthresh, so early samples on the new algorithm are a cold start. */
#define SWAP_MARGIN_PCT 150     /* last_metric >= best_alt * 150 / 100 fires */
#define SWAP_BAD_FIRST      2   /* checkpoints before first swap */
#define SWAP_BAD_LATER 2   /* checkpoints before subsequent swaps */
/* After this many swaps, freeze: go to the algorithm on which
 * this socket performed best, and stop trying.  A socket that
 * has cycled through this many algorithms and stayed bad has a
 * path or app problem that no algorithm can fix. */
#define FREEZE_AFTER_SWAPS 4
#define SWAP_BAD_DESPERATE_PCT 200  /* 2.0x leader -> immediate fire */
#define MIN_LEADER_TRUST 10 /* min votes before targeting a leader */
#define SWAP_MAX       2
#define T_SETTLE_NS     (10ULL * 1000000000ULL)  /* minimum gap between swaps on one socket */

/* 0.4.54: minimum votes cast on an exploring algorithm before the socket can be swapped away. */
#define EXPLORE_PROTECT_VOTES 3
#define T_TIME_CHECK_NS  (60ULL * 1000000000ULL)  /* supplementary vote cadence */
#define TIME_CHECK_MIN_SEGS 1000  /* require progress between checks */

/* Minimum instances before a bucket is written to the persistent
 * state file.  One-off destinations never accumulate enough samples
 * to be worth persisting; recurring paths (CDN, tunnel) do. */
#define PERSIST_MIN_INSTANCES 8
/* Reject reference updates that are more than this factor better
 * than the current reference (lower for min_rtt, higher for
 * max_rate).  A single unusually-fast or slow socket must not be
 * able to permanently anchor the reference to a value the rest of
 * the traffic cannot reach.  Progressive improvements (each step
 * within the factor) still apply. */
#define REF_OUTLIER_FACTOR 2
/* Healing: raise the floor / lower the ceiling toward observed
 * values when traffic consistently disagrees with the reference.
 * Guards against a poisoned reference that cannot self-correct.
 * A socket must be REF_HEAL_FACTOR away from the reference to
 * trigger; each triggering socket moves 1/REF_HEAL_DIV of the gap.
 * Healthy traffic (ratio ~1) never triggers this. */
#define REF_HEAL_FACTOR 3
#define REF_HEAL_DIV 16

/* Reference-update gate.  Segment-rung votes (>= 10K segments)
 * demonstrate sustained throughput and pass naturally.  Time-check
 * votes still fire at TIME_CHECK_MIN_SEGS, but may only move the
 * references when the socket has advanced by REF_TIME_CHECK_MIN_SEGS
 * (~390 Kbps sustained).  Control-plane traffic (DNS, keepalive,
 * ctrl-API) never comes close, so it cannot drift the references in
 * either direction. */
#define REF_TIME_CHECK_MIN_SEGS  2000
/* Consecutive far-better-than-reference readings that promote the
 * reference.  One anomalous reading is still rejected;
 * REF_HIGH_STREAK_N in a row are treated as evidence and promote the
 * reference to the max of the rate streak / min of the rtt streak. */
#define REF_HIGH_STREAK_N        5

/* The metric we calcuate compares current connection min_rtt and rate_delivered to
 * the min rtt and max rate delivered we have observed for the remote host.
 * The idea is that we want to reward congestion control algorithms that minimize
 * RTT and maximize delivery rate, as these are operating at the bottleneck
 * bandwitdh, which is the optimal operating mode.  This does not unduly favour
 * a particular algorithm in practice it seems, and choices can fluctuate over
 * time.  One concern is that the delivery rate is rather low and does not
 * fluctuate much - we see 1 most often for delivery rate.  Our cost function
 * rates rtt deviation and delivery rate deviation equally however; this may
 * need to be tweaked.
 *
 * Cost function is
 *
 * (conn_min_rtt - min_rtt)        +  (max_delivery_rate - delivery_rate)
 *  -----------------------           -----------------------------------
 *  overall min rtt                    overall_max_delivery_rate
 *
 *
 * Both of these are scaled by RTT_SCALE, DELIVERY_SCALE to ensure we get integer
 * values.  Note we do not need to square values because both are asymmetric;
 * a connection min_rtt > overall_min_rtt is bad, while a delivery_rate < overall
 * max delivery rate is bad.  As a result a higher cost here is a problem, and
 * we pick action (congestion algorithm) with minimum cost.
 *
 * Metrics are updated using standard reinforcement learning update;
 *
 * new_estimate = old_estimate + learning_rate * (reward - old_estimate)
 */
static __always_inline __u64 tcp_metric_calc(struct remote_host *r,
                                             __u64 min_rtt,
                                             __u64 avg_rtt,
                                             __u64 rate_delivered,
                                             bool allow_ref_update,
                                             __u64 *rtt_term_out,
                                             __u64 *rate_term_out,
                                             __u64 *heal_rtt_out,
                                             __u64 *heal_rate_out)
{
        __u64 metric = 0;
        __u64 rtt_term = 0;
        __u64 rate_term = 0;
        __u64 heal_rtt = 0;
        __u64 heal_rate = 0;

        if (allow_ref_update) {
                /* min_rtt: single far-low reading is an outlier;
                 * REF_HIGH_STREAK_N in a row promote to the min of
                 * the streak.  Progressive improvements (below ref
                 * but within REF_OUTLIER_FACTOR) accepted directly. */
                if (!r->min_rtt) {
                        r->min_rtt = min_rtt;
                        r->rtt_low_streak = 0;
                        r->rtt_low_min = 0;
                } else if (min_rtt < r->min_rtt / REF_OUTLIER_FACTOR) {
                        r->rtt_low_streak++;
                        if (r->rtt_low_min == 0 || min_rtt < r->rtt_low_min)
                                r->rtt_low_min = min_rtt;
                        if (r->rtt_low_streak >= REF_HIGH_STREAK_N) {
                                r->min_rtt = r->rtt_low_min;
                                r->rtt_low_streak = 0;
                                r->rtt_low_min = 0;
                        }
                } else if (min_rtt < r->min_rtt) {
                        r->min_rtt = min_rtt;
                        r->rtt_low_streak = 0;
                        r->rtt_low_min = 0;
                } else {
                        r->rtt_low_streak = 0;
                        r->rtt_low_min = 0;
                        if (min_rtt > r->min_rtt * REF_HEAL_FACTOR) {
                                r->min_rtt += (min_rtt - r->min_rtt) / REF_HEAL_DIV;
                                heal_rtt = r->min_rtt;
                        }
                }

                                /* max_rate_delivered: histogram append (0.4.43).
                 *
                 * BPF no longer writes max_rate_delivered.  Each vote appends
                 * to a log2-binned histogram; the userspace reanchor worker
                 * recomputes p99 every 30s and writes the result back.  The
                 * old bucket-scoped streak counter could never fire on a
                 * bucket with thousands of instances, so the reference only
                 * fell.  Histogram is population-scale-invariant.
                 */
                if (rate_delivered > 0) {
                    __u64 kb = rate_delivered >> 10;
                    if (kb > 0) {
                        __u32 idx = 0;
                        __u64 k = kb;
                        if (k >> 32) { idx += 32; k >>= 32; }
                        if (k >> 16) { idx += 16; k >>= 16; }
                        if (k >> 8)  { idx += 8;  k >>= 8;  }
                        if (k >> 4)  { idx += 4;  k >>= 4;  }
                        if (k >> 2)  { idx += 2;  k >>= 2;  }
                        if (k >> 1)  { idx += 1; }
                        if (idx > RATE_HIST_BINS - 1)
                            idx = RATE_HIST_BINS - 1;
                        r->rate.bins[idx]++;
                        r->rate.total++;
                    }
                }
        }
        if (r->min_rtt) {
                __u64 dev = avg_rtt > r->min_rtt ? avg_rtt - r->min_rtt : 0;
                __u64 cap = (__u64)r->min_rtt * RTT_DEVIATION_CAP;
                if (dev > cap)
                        dev = cap;
                rtt_term = (dev * RTT_SCALE) / r->min_rtt;
                metric += rtt_term;
        }
        if (r->max_rate_delivered) {
                /* Guard against negative: if this socket beat the
                 * reference without updating it (outlier rejection),
                 * treat it as perfect rather than giving a bonus. */
                if (rate_delivered < r->max_rate_delivered)
                        rate_term = ((r->max_rate_delivered - rate_delivered)
                                     * DELIVERY_SCALE) / r->max_rate_delivered;
                metric += rate_term;
        }
        if (rtt_term_out)
                *rtt_term_out = rtt_term;
        if (rate_term_out)
                *rate_term_out = rate_term;
        if (heal_rtt_out)
                *heal_rtt_out = heal_rtt;
        if (heal_rate_out)
                *heal_rate_out = heal_rate;
        return metric;
}
