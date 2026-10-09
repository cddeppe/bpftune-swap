# BPFTUNE FORK — HANDOFF

Custom fork of Oracle's bpftune. Adds 16 congestion-control algorithms,
per-destination learned state with persistence, and fixes for upstream
metric bugs. Goal: work on mixed-workload hosts (multiple path classes
per gateway), not just single-path datacenters.

## Repo & fleet

- Fork: https://github.com/cddeppe/bpftune  (active branch: `main`)
- `diag/metric-terms` is a stale pointer (fast-forwarded into `main`).
- Latest commit: `3e621b1` (0.4.45)
- Latest release: 0.4.45

| Role | Arch | Version | Notes |
|------|------|---------|-------|
| Heavy-traffic (xray/YouTube) | aarch64 | **0.4.45** | capture -> /var/log/bpftune-met-YYYY-MM-DD.log |
| Builder | amd64 | **0.4.45** | runs git push origin |
| Target | amd64 | **0.4.45** | mostly idle |
| Builder | aarch64 | **0.4.45** | builds arm64 |
| shared mount: /mnt/backup/ holds .debs |

Verify: `dpkg-query -W -f='${Package} ${Version}\n' bpftune`




## SESSION 2026-09-18 (morning) — 0.4.45 swap target uses rate EMA

Replaces the composite-metric swap TARGET with a per-algorithm rate
exponential moving average.  Trigger conditions unchanged — still
`margin_met` / `desperate` versus the metric leaderboard.  Only the
destination of a mid-socket swap changed.

Why: on the home bucket the composite metric's top-5 span is ~3
points, and the metric drifts by more than that within an hour.
The metric leaderboard is not stable enough to pick a swap target
from.  The rate signal has a 3.7x spread (105-390 Mbps on the same
bucket) and held its ranking overnight.  Metric stays as the
initial-connect prior; rate takes over as the swap target.

Implementation:
- `tcp_conn_metric`: `rate_ema` (__u16, 100 KB/s units), updated on
  each non-app-limited vote (same `do_update` gate as the metric
  EMA), 1/16 decay per update (~16-vote half life)
- `remote_host`: `rate_best_i`, `rate_best_v`, computed by the
  userspace reanchor (pass 3), same `MIN_LEADER_TRUST` gate
- BPF swap path reads `rate_best_i` when set, falls back to metric
  `best_i` otherwise
- swap printk gains `mt=<metric-would-have-picked>` and
  `rb=<rate-picked>`, both as algorithm names
- `midsamp` printk gains `alg=N` so userspace can credit rate
  samples directly without joining through a stale met line
- `_Static_assert(sizeof(struct remote_host) <= 1024, ...)` —
  0.4.44 lesson
- STATE_VERSION 14 -> 15

Deployed 2026-09-18 07:31 UTC on all four hosts.  No divergence
between `mt` and `rb` in the first 30 minutes: both leaderboards
currently agree on the top algorithm (scalable on CLIENT-IP).
Divergence will only show when metric-leader and rate-leader pick
different #1s on the same bucket.  Log carries both fields, so a
swap-outcome-by-mt-vs-rb analysis is possible once the tail fills.

Open from this session, NOT fixed:
- swap win rate 20% (client-facing, n=216), null 71%, loss 8%.
  Consistent with the pre-0.4.45 rate — target selection was not
  the only problem.
- cookie churn: `5x+=11 max=28` in the current tail.  One socket
  swapped 28 times.  Unchanged from 0.4.43.
- 40% of swaps have no post-swap vote within 300 s.  An earlier
  dashboard window (60 s) under-measured this; the true rate is
  20/71/8, not the 33/60/7 the shorter window showed.  Analysis
  fix, no code fix.
- origin gate leak: post-0.4.42, origin-facing swaps still fire
  occasionally.  Sample origin socket 1166 segs / snd_cwnd=14 /
  pkts_out=0; data_segs ratio had not differentiated at eval time.
  Root cause still not identified.  Aggregate rate is now 3/219 in
  the log tail, down from ~80% pre-0.4.41 — the gate mostly works,
  residual leak is real.

## SESSION 2026-09-17 (night) — 0.4.43 histogram reference + 0.4.44 proof counters

Two releases shipped after the evening STOP section.  Both are
cleanup around the swap engine's input signal, not changes to swap
logic.  The swap engine itself is unchanged from 0.4.42.

### 0.4.43 — histogram-based delivered-rate reference

Replaced the bucket-scoped `rate_high_streak` state machine with a
per-vote log2-binned histogram of delivered rate.  32 bins, KB/s
units, population decay halves all bins when total > 100000, p99
recomputed by the userspace reanchor every 30 s.  Fixes the
population-scaling failure: on a bucket with thousands of instances
no socket could produce 5 consecutive high readings without another
socket resetting the shared counter, so the reference slid
monotonically downward (heavy host: 63.7M -> 45.4M -> 4.5M over
nine hours).  With the ref collapsed, rate_term was 0 for every
socket and metric_value ~= rtt_term, so all downstream ranking was
RTT-only and every swap decision was a consequence of a broken
input.

STATE_VERSION 12 -> 13.

Verified post-deploy on the heavy host: reference held at 67.1M
across three reads over ~10 min.  Client-facing rate progression
monotonic (1000/5000/10000/25000/100000: 7.5M/16.8M/18.9M/24.4M/
33.0M).  Under the collapsed reference the 100K mean had been 3.0M.

### 0.4.44 — per-alg proof counters

Added per-(bucket, alg) counters tracking how many sockets ever
delivered at 4K-class (>=30 Mbps, "good") or 8K-class (>=100 Mbps,
"proved") rates while on that algorithm.  Purpose: separate the
tuner's composite-metric ranking from an independent "actually
demonstrated speed" ranking so the two can be compared.  They do
not agree — on 09-17 evening the metric leaderboard ranked htcp #1
on the home bucket while the proof leaderboard ranked vegas #1.
That disagreement is the whole justification for 0.4.45.

Implementation:
- `tcp_conn_metric`: `sockets_alive`, `sockets_good`,
  `sockets_proved` (__u16 each)
- `conn_state`: `touched_bitmap`, `good_bitmap`, `proved_bitmap`,
  `cleaned` — one bit per algorithm per socket
- `set_cong()` now takes `remote_host`, bumps `sockets_alive` on
  first contact with an algorithm
- counters incremented live; decremented once at socket close for
  every algorithm the socket ever touched (bitmap-driven, idempotent)
- STATE_VERSION 13 -> 14

Struct size nearly hit the 1024-byte BPF memset ceiling in
`get_remote_host()`.  First build failed on
`__builtin_memset(...) is not supported` at ~1176 bytes.  Shrinking
the three counters from __u64 to __u16 brought it back under.  0.4.45
adds a `_Static_assert(sizeof(struct remote_host) <= 1024, ...)` so
the next growth fails loudly at compile time, not with a cryptic
memset error.

Proof events live on 09-18 morning: 12-15 algorithms represented on
the home bucket.  vegas leads on event count and max tier-2 rate,
but the log-joined `avg_Mbps` shows yeah and reno at 3x vegas on
sustained rate.  That's the opening of 0.4.45.

## SESSION 2026-09-17 (morning) - origin-side swaps cannot help

Discovered while investigating whether the d=1 win rate decline
across 09-14 (40.3%) -> 09-15 (31.9%) -> 09-16 (26.1%) was real.
It is partly a population artifact.

### The finding

On 09-16, of 239 swaps in the heavy log, 138 (57.7%) were on
origin-facing sockets.  On 09-17 morning, 22 of 25 (88%) were.

Origin-facing sockets are ones where the proxy is receiving data
(video from a CDN).  Congestion control on such a socket controls
how fast the *proxy sends HTTP requests and ACKs* upstream -- NOT
how fast the CDN sends data down.  A swap on an origin-facing
socket changes a CC state variable that does not influence the
flow being tuned.  It cannot improve anything.

The tuner treats every socket identically.  No direction filter
exists in the vote path:

    grep -nE "local_port|remote_port|segs_in|segs_out" \
         src/tcp_conn_tuner.bpf.c

local_port and remote_port appear only inside bpf_printk.  The
vote path fires on BPF_SOCK_OPS_RTT_CB for any full socket, gated
only on tp->segs_out + tp->segs_in >= METRIC_MIN_SEGS -- total
segments in both directions, no directional weighting.

The metric calculation makes this worse: the vote trigger is a
sum of both directions, but rate_delivered / rate_interval_us is
a measure of *our sending rate*.  On an origin-facing socket that
quantity is small and unrelated to how fast the CDN delivers to
us.  The metric is measuring the wrong direction there.

### Why this matters

- Aggregate d=1 win% is dominated by origin-side swaps whose
  outcome is structurally fixed.  The 26.1% (09-16) and 20.0%
  (09-17 morning) readings are not swap quality -- they are
  mostly noise over a population where nothing can change.
- Client-facing-only d=1 win% is the number to read for 0.4.40
  validation.  n was 1 on 09-17 morning, too small.
- bucket-leaders.py shows origin buckets (142.251.*, 2606:1a40:3::1,
  etc.) whose leaderboard entries are meaningless.  We have been
  looking at some of those for days.

### Proposed fix (NOT shipped)

One conditional at the top of the vote path:

    if ((__u64)tp->segs_out * 4 < (__u64)tp->segs_in)
        return 1;

No loop, no variable division, verifier-safe.  Removes ~60-90% of
swaps on a large class of sockets where swaps cannot win.

Do NOT ship on top of the in-flight 0.4.40 test.  0.4.40's outcome
test has to close first, otherwise a d=1 change cannot be
attributed to either release.

### Reading swaps from now on

Use tools/swap-outcomes-bydir.py (added with this entry).  It
splits the day's swaps into client-facing (rport != 443) and
origin-facing (rport == 443) and reports each tier's win/null/loss.
Read the client-facing row.

### Backing data

09-16 full day:
    total 239
    client-facing  101 (42.3%)   d=0=8  d=1=93
    origin-facing  138 (57.7%)   d=0=7  d=1=131

09-17 07:23 UTC (partial):
    total  25
    client-facing   3 (12.0%)
    origin-facing  22 (88.0%)    d=0=0  d=1=19 win=15.8%
    client d=1: n=1 (not meaningful)

### Home bucket spread: 09-17 morning regression

Home bucket spread 50.7% (deploy+2h) -> 57.6% -> 65.6% during
09-16 evening, then 29.0% NARROW at 07:23 09-17.  The worst
value (lp=8144453) was byte-identical between the evening and
morning readings -- lp's EMA had not been updated since the last
evening vote.  The spread narrowed because the best rose
(htcp=6.3M vs veno=4.9M), not because the worst moved.

Not enough data to conclude.  Possibilities: morning traffic is a
different population; the cwnd-bound votes cluster on the home
bucket and homogenize; lp's filtered vote count is too low to
move the EMA.  Re-check after a full day of 0.4.40 traffic.  If
spread stays below 40%, treat 0.4.40 with suspicion.

## SESSION 2026-09-17 (evening) - 0.4.40-0.4.42: swap engine needs a fresh look

Read this first. Three releases (0.4.40, 0.4.41, 0.4.42) in one
session.  Each was defensible on its own reasoning; the pattern is
that none resolved the underlying uncertainty, and each added a
confound to the next measurement.  This is the handoff.

### Fleet (end of session)

All four hosts on 0.4.42.  Latest commit f11fb63.

### What shipped today, what it did

**0.4.40 — util gate on the bucket EMA.**
Skip the metric_value EMA update when the socket is using <10% of
its cwnd (packets_out*100 < snd_cwnd*10).  Rationale: 0.4.39's
diagnostic showed ~50% of votes came from sockets not using their
window; those score the algorithm on a rate the app supplied, not
the rate the algorithm permitted.

Observed (client-facing only, midsamp, rport != 443):
    09-16 vs 09-17 at 5K/10K/25K/100K thresholds: +20-25%
    1K: +4% (expected; slow-start physics dominate)
Effect held as sample grew through 09-17; did not collapse.

**0.4.41 — origin gate + moving-socket suppression.**
(1) Vote path skips sockets where segs_out*4 < segs_in.
(2) Moderate-tier swap suppressed on falling/oscillating
    client-facing sockets.

Origin gate did NOT work: 95.5% of swaps post-deploy were still
origin-facing.  See 0.4.42.

**0.4.42 — origin gate uses data_segs_*, not segs_*.**
segs_out includes pure ACKs; on a receiving socket ACKs dominate,
so the ratio stayed above threshold and the gate never fired.
Switched to data_segs_out/data_segs_in (excludes ACKs).

Leak persists.  Sample origin swap: 1166 segments, snd_cwnd=14,
pkts_out=0.  The data_segs ratio had not differentiated at
evaluation time even at >1000 segments; the check may not have a
reliable signal on short HTTPS exchanges.  Root cause NOT
identified.

### Hard facts (verified, do not re-derive)

1. Tracker reanchor (0.4.36): works.  Home bucket matches array.

2. Flat gate (0.4.38): fires as designed.  d=0 fires ~47/day ->
   ~7.7/day.  Matched prediction.

3. Metric is blind on ~50% of votes.  Cwnd-bound (util >= 10%)
   is ~5-10% of client-facing votes; app-limited (<10%) is ~50%.

4. Origin-facing was ~80% of swaps pre-0.4.41 (88% on some
   morning windows).  Post-0.4.42 leak at low volume (n=2 at last
   check).  The population is real; the gate does not fully stop it.

5. Client-facing rate progression (midsamp, rport != 443) is the
   closest proxy we have to the ABR decision input.  Use it as the
   primary user-visible metric; the swap-outcome tallies are
   contaminated and small-n.

6. Home bucket spread across all 16 algorithms: 30-65% most
   readings, 65.6% peak, 29-51% post-0.4.40.  Far below what a
   genuine algorithmic difference would produce.  Metric
   discriminates weakly.

### Unanswerable from this setup

1. **Did the aggregate improve?**  Day-over-day is confounded by
   traffic mix and time of day.  A/B impossible (one traffic
   source).  Same-host alternation too slow for 5-20% effects.

2. **Do client-facing swaps help?**  Clean sample ~20/day.  Never
   measured with n large enough to trust.

3. **Is the tuner causing ABR to settle lower over the day?**
   Client-side quality (rendition, buffer) is not visible from
   any host we control.  Pattern (streams settle to 1080p and only
   recover on manual override) is consistent with either ABR
   hysteresis unrelated to us, or our swaps perturbing ABR probes.
   Cannot distinguish without client-side telemetry.

4. **Can the metric rank algorithms under this workload?**  Util
   gate widened the spread modestly and unstably.

### The decision the next agent should make

Not "does 0.4.42 work" -- should the mid-socket swap engine
exist at all?

- Keep: desperate tier wins ~34% aggregate.  But contaminated by
  origin-side swaps whose outcome is structurally fixed.
- Disable: four releases refining it, no user-visible effect
  demonstrated.  Fires 50-100 swaps/day.
- Middle ground: keep connect-time algorithm selection
  (coverage-based, already working), disable mid-socket swaps
  until a clean measurement exists.  Removes the entire class of
  confounds; loses whatever the swaps actually provide (unknown).

### What would actually help

1. Add data_segs_out and data_segs_in to the cwnd diagnostic
   printk.  Required to verify or reject the origin gate; the
   ratio is currently invisible.  One-line printk change.

2. One uninterrupted week of the current build, no changes.  If
   ABR settle-lower is tuner-caused, it becomes visible in
   client-facing rate progression over 5-7 days.  Any further
   code change destroys the observation window.

3. A client-side probe.  If a small agent could report YouTube's
   chosen rendition and buffer health, the ABR-perturbation
   question becomes directly answerable.  Out of scope for the
   kernel tuner but the only path to a definitive answer.

### Do NOT re-derive

- Metric is app-limited on ~50% of votes; that dilutes ranking.
- Origin-facing swaps cannot help; ~80% of swaps were origin-side.
- Client-facing filtering required for every analysis.
- Flat gate works.  Tracker reanchor works.
- Day-over-day comparisons of this workload cannot resolve
  sub-20% effects.

### Notes for the next session

- `tools/swap-outcomes-bydir.py` splits swaps by direction.  Use
  it.  `tools/swap-effectsize.py` does NOT filter by direction and
  reports misleading aggregate numbers on the current workload.
- `tools/bucket-spread.py` shows the full 16-algorithm spread;
  bucket-leaders.py truncates to top-3 and was hiding the story.
- 3-arg heredoc `python3 - <<'PYEOF'` breaks under paste.  Write
  the script to a file with `cat > /tmp/x.py <<'PYEOF'` and run
  it as a separate command.
- `rm -f src/*.skel.h src/*.bpf.o src/*.o` before `make clean` is
  mandatory; the Makefile's .skel.h regeneration does not depend
  on .bpf.o.

## SESSION 2026-09-16 (late) - 0.4.39 diagnostic + 0.4.40 util gate

Followed the 2026-09-16 discovery that the live trace showed the
kernel app_limited flag on ~96% of sockets.  Turned that into a
per-vote measurement, then a fix.

### 0.4.39 - diagnostic printk (snd_cwnd / packets_out)

Added a second printk to the vote path:

    cwnd cookie=N snd_cwnd=X pkts_out=Y

Joined by cookie to the existing met line.  Split across two lines
because the met line is already at the 12-argument limit.  No
metric logic change, no struct change, no state change.

Result, four samples over ~40 minutes on heavy:

    paired votes    app-limited      cwnd-bound
    117             47.0%            6.0%
    274             53.6%            5.1%
    435             50.1%            4.8%

Mean median utilization ~0.08-0.10.  Half of all votes are cast by
sockets using <10% of their cwnd-permitted window.  Stable across
4x the sample.  Per-algorithm not readable yet (n too small) but
the aggregate confirms: most votes measure the rate the app
supplied, not the algorithm's capability.  That is exactly the
dilution that explains the 34-65% spread between best and worst
algorithm on busy buckets, versus the 200%+ a genuine algorithmic
difference would show.

### 0.4.40 - utilization gate on the EMA update

Skip the bucket metric_value EMA update for votes where

    packets_out * 100 < snd_cwnd * METRIC_MIN_UTIL_PCT   (10)

BBR is exempt (rate-based, snd_cwnd deliberately large by design).
snd_cwnd == 0 (no window info on the hook) is allowed.  metric_count
still increments; coverage / MIN_LEADER_TRUST semantics unchanged.

Verifier: ESTABLISHED 15242/1083 unchanged; vote 3860/267 ->
3875/271.  Cost of the gate is +15 insns.

### Both fixes were preceded by verifier-limit failures

The first 0.4.40 draft also skipped sentinel metrics (0 / ~0) in
the ESTABLISHED min loop.  That blew the vote program to the
1M instruction limit -- 21034 states, 79x the 267-state baseline.
The 16-way unrolled min loop cannot tolerate a per-iteration
branch with unprovable value ranges.  Reverted.  Both consumers
of minindex already check the value sentinel or metric_count
before use, so no filter was needed in the first place.

Lesson for future work: the ESTABLISHED min loop and any 16-way
unrolled code are verifier-fragile.  Do not add per-iteration
branches.  Verify with bpftool load before assuming.

### Falsification checkpoint (written before the 09-17 data lands)

0.4.40 is a bet on structural reasoning, not a measured
improvement.  The reasoning: votes where the socket is not using
its window rank algorithms on a quantity they did not set;
skipping those from the EMA should sharpen the ranking.

Test on the 09-17 log against the 09-16 post-gate window:

  - expect the 34-65% best/worst spread on home-bucket
    leaderboards to widen toward 100%+ if cwnd-bound votes
    discriminate algorithms
  - expect moderate-tier swap win% not to fall
  - expect desperate-tier win% not to fall

If swap outcomes get worse on 09-17, revert 0.4.40 alone.
0.4.38/0.4.39 stay regardless.

If outcomes and spread are both unchanged, cwnd-bound votes do
not discriminate either -- the metric is at its floor for this
workload and we need a different observable.

### Deployed

heavy and aarch64 builder on 0.4.40 as of 2026-09-16 18:21 UTC.
569 met / 569 cwnd post-restart, vote path confirmed live.
vps-3959 on 0.4.39, 0.4.40 .deb staged on /mnt/backup.
ip-172-26-13-90 (idle amd64 target) still on 0.4.38.

### Diagnostic value: done

The 0.4.39 cwnd printk has served its purpose.  0.4.41 should
stop emitting it (or rate-limit it) to keep log size down.

## SESSION 2026-09-15 (late night) -- 0.4.38: 0.4.37 flat-gate never fired

0.4.37 shipped the flat-socket gate on the moderate tier.  Verified
three hours later on the heavy host: it did not engage.

### Symptom

Post-0.4.37 d=0 fires in a ~3h window: 7.  Pre-gate baseline was
~47/day, so ~5.9 per 3h; under the design's expected 78% suppression
the prediction was ~1.3.  Observed 7 -- 5x above the prediction.
All 7 classified null (0% win).  5 of the 7 were classified `flat`
by tools/swap-trend.py.  Firing on flat sockets is exactly what
0.4.37 was supposed to prevent.

### Root cause

SWAP_BAD_FIRST=2 fires the first moderate swap after two consecutive
bad votes.  is_flat required all three of {last_metric, hist_1,
hist_2} to be valid.  On a fresh socket -- or one whose history was
zeroed by a prior swap -- hist_2 is still 0 at the moment the swap
fires.  n == 3 was literally unreachable on the first swap of every
socket, which is most moderate swaps.

Confirmed in the raw log: every offending cookie shows exactly two
`met` lines immediately preceding the `swap` line.  (3697: 2 met
then swap; 3726: 2 met then swap; 3731's three separate swaps each
preceded by exactly 2 met lines.)

### Fix: require n >= 2, not n == 3

Bin swaps by sample count on the current algorithm over the
09-14 + 09-15 pre-gate logs:

    class            n     win%
    2sample-flat    85     ~10%     <- gate now catches
    2sample-nonflat 17     ~48%     <- max/min check excludes
    1sample        218     ~38%     <- insufficient, falls through
    3sample         57     mixed    <- unchanged

2sample-flat is the same population as 3sample-flat by win rate
(both ~10%), well below what the moderate tier should target.
2sample-nonflat keeps a 45-50% win rate and is not suppressed.
1sample cannot form a ratio and stays "insufficient" per the
original design.

### Verifier

    ESTABLISHED  amd64 15242 / 1083   unchanged
                   arm64 17851 / 1218   unchanged
    vote         amd64 3395 / 223 -> 3918 / 264
                   arm64  2707 /  181 (0.4.36) -> 4022 / 296

The n>=2 form unrolls into three independent slot-validity checks,
larger than the 0.4.37 && chain, but still trivial against budget.

### Deployed

All four hosts on 0.4.38 as of 2026-09-15 ~17:00 UTC.  Home bucket
verified matching array post-deploy (instances 1093,
best_i=12 / best_v=4680454 = trusted-min, MATCH True).

### Verification pending (same protocol as 0.4.37)

Post-0.4.38, expect d=0 at ~1.3/hr on the heavy host.  Full-day
check against the 09-16 log:

    metric           pre-gate    predicted
    d=0 fires/day      ~47          ~10
    d=0 win%          11.7%        ~30%
    d=1 fires/day     ~247        unchanged

If d=0 is still >=2/hr, the n>=2 change also is not reaching the
decision and the problem is gate placement, not the threshold.  If
d=0 drops but win% stays near 12%, the shape signal itself was
overfit and 0.4.37 + 0.4.38 get reverted together.

## SESSION 2026-09-15 (night) — 0.4.37 flat-socket gate on moderate tier

Follow-through on the two diagnostics earlier tonight.  The design
was settled by the short-trend analysis; this session implemented it.

### What shipped

Struct conn_state gains hist_1/hist_2 (two u64).  Along with the
existing last_metric these are the socket's own last three samples.
Vote path shifts them (sentinel-filtered); swap path resets both on
every exit (desperate, freeze, moderate).  Moderate-tier swap now
checks:

    max(v0, v1, v2) * 100 < min(v0, v1, v2) * 110  ->  is_flat
    if (is_flat) suppress; else set_cong()

Desperate is unchanged: it fires on the 2x rule regardless of shape.
A socket with fewer than three samples has not been judged yet, and
is not suppressed.

### Why this shape

Recap from the earlier diagnostic: flat sockets win 7.9% on swap
(90.6% null).  The moderate tier's catchment is 78.5% flat vs 21.9%
in desperate, because a deteriorating socket climbs through
1.5x-2.0x fast and trips 2x, while a flat socket sits at a fixed
ratio and trips the 2-bad-check rule eventually.  Gating on
"is the socket's own number moving" separates the two without
touching the thresholds or the metric.

### Expected effect (to be measured 09-16)

    tier          fires/day   win%     current
    moderate          47      ~30%     11.8%
    desperate        247      ~35%     unchanged

Falsification test: if d=0 fires drop as expected but win% stays
near 12%, the gate is filtering the wrong fires and we revert.
Run tools/swap-effectsize.py on 09-16 and compare.

### Verifier

    ESTABLISHED  15242 / 1083   unchanged
    vote          2984 /  190  ->  3395 / 223

+411 insns, +33 states.  The flat check is on the hot path but small.

### No state-format change

hist_1/hist_2 live in sk_storage only.  The persisted tcp_conn_tuner
.state file holds struct remote_host; nothing in it depends on
conn_state.  STATE_VERSION stays at 12, no state file delete on
deploy.  Verified by grep: the state functions touch remote_host
only.

### Deployed

All four hosts on 0.4.37 as of 2026-09-15 17:29 UTC (vps-3959 and
ip-172-26-13-90 amd64; heavy and aarch64 builder arm64).  Home-bucket
tracker still matches array post-deploy (verified via the same dump
used for 0.4.36).

### Not touched

- Swap tier thresholds (1.5x / 2.0x) unchanged.
- Desperate tier unchanged.
- Insufficient-history sockets unchanged.
- The metric itself unchanged.

## DIAGNOSTIC 2026-09-15 (later) — short-trend signal validates; flat = do not swap

Follow-up to the effect-size analysis.  We tested whether the shape of
a socket's own metric over its last few votes predicts whether a swap
will help.  It does, decisively.

### Method

For each swap in the 09-14 + 09-15 met logs, take the socket's own
last N metric samples before the swap, classify by shape:

    flat          max/min < 1.10 over the window
    rising        >= 70% of steps increase
    falling       >= 70% of steps decrease
    oscillating   none of the above
    insufficient  fewer than N pre-samples in the log

Bin the outcome (big_win / mod_win / null / loss) by class.

### Result (N=3, 340 swaps)

    class          n     win%   null%   loss%
    flat         127     7.9%   90.6%    1.6%
    rising        19    57.9%   36.8%    5.3%
    falling       11    27.3%   72.7%    0.0%
    oscillating   18    16.7%   66.7%   16.7%
    insufficient 165    42.4%   50.3%    7.3%

Flat is dead: 7.9% win, 90.6% null.  A flat socket has demonstrated
that its current algorithm is not moving it; a swap has ~1/12 chance
of helping, and that 1/12 is inside the metric's own noise band.

Rising is a strong positive signal (57.9%).  Sockets that are
deteriorating are exactly the ones a swap should target.

N=3, 4, 6 give the same qualitative picture.  Threshold is robust.

Not a lifespan confound: window spans are median 80s (flat), 130s
(rising), 139s (oscillating) at N=3, 220s (oscillating) at N=6.
Class is a shape property, not a socket-age artifact.

### The moderate tier selects for flat

    tier             flat%   non-flat%
    moderate (d=0)   78.5%      21.5%
    desperate (d=1)  21.9%      78.1%

A socket that is deteriorating climbs through the 1.5x-2.0x band
quickly and trips the desperate bar at 2.0x.  A socket that is flat
sits at some fixed ratio forever and eventually trips moderate on the
2-bad-check rule.  The moderate tier is what flat sockets reach, by
construction.  This fully explains why it has been reading as a coin
flip -- the tier's catchment, not its logic, is broken.

### Recommendation

Suppress flat swaps in the MODERATE tier only.

    moderate          current    minus flat
    n                     93          20
    win%                11.8%         30%
    win:loss            2.75:1       1.5:1
    fires/day             47          ~10

The 78% reduction in moderate fires is worth the small loss of
flat-class "wins" (7.9% rate, inside noise).  The cwnd resets avoided
are real; the wins lost are not.

Do NOT gate:
  - desperate.  Its flat subpopulation is 21.9%, much smaller, and the
    "this socket is clearly bad" principle stands even without
    history.
  - insufficient.  42.4% win rate, the single largest source of real
    wins besides rising.  These are the socket's first "is this
    algorithm working?" verdict -- history is unavailable, not absent
    for good reason.

### Implementation sketch (not done)

Two u64 in conn_state to hold the last two metric samples (last_metric
already holds the current one) plus a u64 sample counter.  On each
vote: shift, update counter.  Gate:

    if (sample_count >= 3 &&
        max3 / min3 < 1.10 &&
        <we are in the moderate tier>)
            suppress swap

Reset the shift register on swap (algorithm changed; history across
the change is not meaningful).

Cost: conn_state grows 80 -> 104 bytes.  STATE_VERSION bump required.

Not implemented.  Design is settled; implementation is next-session
work.

## DIAGNOSTIC 2026-09-15 (late) — effect-size analysis; moderate tier is a null-firer

After 0.4.36 shipped and the tracker read correctly, we looked at why
the moderate tier (1.5x - 2.0x) has read as a coin flip IMP/WRS since
0.4.30.  It is not a coin flip; it is mostly a null-mover, and the
IMP/WRS counter was hiding that.

### sign-IMP was measuring noise

The IMP/WRS counter sign-tests post/pre against 1.0.  The metric's own
noise band spans ~+-5-10%, so the ~2/3 of swaps that land in the
0.9-1.1 ratio band get labeled by sign alone -- post=5,000,001 vs
pre=5,000,000 is a "WRS", the reverse is an "IMP".  Those observations
carry no information about the swap.

Re-bin by effect size:

    ratio          label        meaning
    < 0.5          big_win      algorithm unlocked the pipe
    0.5 - 0.9      mod_win      solid improvement
    0.9 - 1.1      null         no meaningful change (noise)
    1.1 - 1.5      mod_loss     real regression
    1.5 - 2.0      big_loss     clear regression
    > 2.0          severe_loss  severe regression

Over the 09-14 and 09-15 logs, 340 observed swaps:

    bin            n       pct
    big_win        49      14.4%
    mod_win        48      14.1%
    null          225      66.2%
    mod_loss       17       5.0%
    big_loss        1       0.3%
    severe_loss     0       0.0%

    old sign test : IMP=219 (64.4%)  WRS=121 (35.6%)
    effect-size   : win=97 (28.5%)   null=225 (66.2%)  loss=18 (5.3%)

The sign-IMP counter overstates the real win rate by ~2.3x.  Every
"moderate 50% IMP" / "desperate 67% IMP" reading we have cited since
0.4.30 was comparing signed noise against a 1.0 boundary.  sign-IMP
is retired as a metric; use effect-size bins.

### The tiers are doing very different things

    tier               n     win%    null%   loss%   win:loss
    moderate (d=0)     93    11.8%   83.9%   4.3%      2.7:1
    desperate (d=1)   247    34.8%   59.5%   5.7%      6.1:1

Desperate is doing its job: it wins 3x as often per fire at the same
loss rate.  Moderate fires ~47 swaps/day to produce ~5.5 real
improvements and ~2 real regressions, and every one of those 47
fires costs a cwnd reset and injects a sample into the bucket EMAs
that feed the tracker.  The moderate tier is a net drag, not a
neutral: the ratio is positive but the sample count and cwnd cost
are not.

### Regressions do not cluster

18 losses >1.1 across the two days span (from,to) pairs 4->13, 13->3,
6->9, 13->11, 5->3, 3->6, 6->3, 12->5, 7->6, 2->11, 10->12, 8->3,
15->12, 15->6.  No pair appears twice.  A direction gate on the
algorithm pair is not supported by this data.

### 0.4.36 did not change the tier's win rate

Timestamp-split today's log at the 0.4.36 deploy (heavy host boot
wall 1789385486 = monotonic 0; deploy at monotonic 94887):

    tier   window     n    win%   null%   loss%
    d=0    pre       36    11.1%   88.9%    0.0%
    d=0    post      13     7.7%   92.3%    0.0%
    d=1    pre      125    31.2%   62.4%    6.4%
    d=1    post      55    36.4%   61.8%    1.8%

Moderate n=13 post-fix -> one event, not interpretable.  Desperate
trends marginally better on both win and loss, but n=55 means the
1.8% loss is one observation.  Honest read: the tracker fix corrected
the swap DESTINATION; the moderate tier's problem was never the
destination, it is WHETHER to fire.  Orthogonal problems.

### Rejected: per-socket best_seen as a moderate-tier fire gate

The idea of suppressing moderate swaps when the socket is at its own
demonstrated best was tested against 09-15 data.  For each swap,
pre / alltime_low for that socket:

    hr_bucket      n     win%
    1.00-1.05    200    63.0% (sign)  <- 87% of all swaps
    1.05-1.10      9    55.6%
    1.10-1.20      4    50.0%
    1.20-1.50     11    72.7%
    1.50-2.00      2   100.0%
    3.00+          3   100.0%

87% of swaps fire with pre/alltime_low ~ 1.00 -- the socket is at its
own floor.  That floor is the best the CURRENT algorithm could do;
after a swap the socket can go 10x lower (cookie 2880: 5.45M -> 19K).
So alltime_low is not a ceiling and using it as a fire gate would
suppress almost every swap, wins included.  Do NOT implement this.

Note: this does NOT resolve the existing best_seen outlier item for
the POST-FREEZE REOPEN gate (last_metric >= best_seen * 2), which is
a different question -- it decides whether a frozen socket should
re-enter the desperate tier, not whether a moderate swap should fire.
That item remains open below.

### Proposed next step: a fire-time signal from short trend

The one signal in reach that could plausibly separate the 12% real
moderate wins from the 84% nulls, without new kernel access, is the
shape of the socket's own metric over its last few checkpoints:

  - flat at X for N checkpoints  -> at path plateau, don't swap
  - oscillating X <-> 2X         -> variation present, algorithm
                                    might still be limiter
  - monotonically rising         -> deteriorating, current alg
                                    is failing this socket

needs: last 3-5 metric samples per socket, already available if
conn_state keeps two more numbers.  NOT YET DESIGNED.  Do not code
this without first establishing, from existing logs, whether short-
trend actually separates the win rows from the null rows.

### Tools

tools/swap-effectsize.py re-bins a day of met log swaps by effect
size (the analysis above).  tools/swap-trend.py classifies each
socket's own trajectory at swap time; see the short-trend section.
The per-socket headroom computation that rejected the best_seen
fire gate was a one-off; its logic is described above and in the
short-trend section, but the script itself was not kept.

## SESSION 2026-09-15 (evening) — 0.4.36 userspace re-anchor

The health check exposed a real tracker bug on the home bucket
CLIENT-IP.  Observed dump (67 instances, several algorithms with
4-5 votes each -- not a fresh bucket):

    best_i=2 (htcp)  best_v=1,798,336
    second_i=1 (bbr) second_v=6,368,457
    alg=3 (dctcp) n=5 val=608,817   <- true minimum, ignored

Three problems: the tracker was 3x off, second_i == best_i in an
earlier dump (structurally impossible), and both candidates had
multiple votes so this was not a small-sample artifact.

Root cause.  The tracker is maintained in two places, both
event-driven: (a) the vote path incrementally promotes non-leaders
when they vote and their value drops below best_v, (b) the
ESTABLISHED-time rescan (0.4.27) rescans the metric array but only
fires on new connections.  Between an ESTABLISHED and the next one,
a non-leader EMA can drift down without triggering the promote
path.  Dctcp reached 608K with n=5 and was never promoted.  The
tracker is guaranteed consistent with the array only at the instant
ESTABLISHED runs.

Why not fix it in BPF.  Tried an inline 16-way unrolled scan in the
vote path (draft attempt).  Verifier exploded: 222,524 insns /
20,363 states (from 2,984 / 190).  Loads, but would slow every
socket and leave no headroom.  Backed out.

The fix.  Userspace re-anchor in the daemon
(src/tcp_conn_tuner.c).  A worker thread sleeps 30s, walks every
bucket in remote_host_map, and writes the correct
best_i/best_v/second_i/second_v back via bpf_map_update_elem.
Read-modify-write: reference-fix fields (rate_high_streak/max,
rtt_low_streak/min) and every other field carried through unchanged.

Selection rules mirror the BPF side:
- skip metric_count == 0 and metric_value 0 / ~0 sentinel
- leader: minimum value among metrics with metric_count >=
  MIN_LEADER_TRUST (3)
- second: metric_count > 0, excludes the leader, requires value
  >= best_v so the best_v <= second_v invariant the vote path
  maintains is preserved
- if no trusted leader: force best_i/best_v/second_i/second_v = 0
  so the swap path sees "no leader" instead of stale values

The BPF program is unchanged.  The swap decision keeps reading
best_i/second_i exactly as before.

Wiring.  pthread_create from init() after both cgroup attaches
succeed; pthread_join from fini() before save_remote_host_map.
Worker takes its own thread caps (caps are per-thread).  Sleep is
sliced at 1s so fini() does not stall.

Constants.  REANCHOR_INTERVAL 30 in tcp_conn_tuner.c.  Anchored to
the same MIN_LEADER_TRUST the BPF side uses.

No STATE_VERSION bump (v12 unchanged), no state file delete needed
on deploy.

Verifier numbers, unchanged from 0.4.35:
    ESTABLISHED 15242 / 1083
    vote         2984 / 190
(arm64 builder reports 17851 / 1218 and 2707 / 181 -- per-arch
verifier counting; no BPF source changed so these are the same as
whatever 0.4.35 produced there.)

Verification on the heavy host, two dumps 60s apart, identical:
    instances=182 best_i=3 best_v=2923333 second_i=4 second_v=3241955
      alg=3 n=23 val=2923333
      alg=4 n=2  val=3241955
best_i points at the trusted minimum, second_i is distinct, and
second_v >= best_v.  Stable across the two reads; the worker writes
only when values change so there is no churn.

Deployed to all four hosts.

Not touched this session (still open):
- best_seen_metric outlier problem.  A socket whose single best
  sample was a lucky quiet moment refuses post-freeze swaps forever
  because the gate is last_metric >= best_seen * 2.  Observed on
  cookie 2927 (15 swaps despite freeze).  Candidate: signal-average
  instead of extremum for best_seen_metric.  NOTE: this is the
  POST-FREEZE REOPEN gate, distinct from the per-socket fire gate
  that the late-2026-09-15 diagnostic rejected (see that section).
- ~~Moderate tier null-firer~~ -- 0.4.37 shipped the flat-gate but
  it never fired (n==3 unreachable on first swaps).  0.4.38 relaxed
  to n>=2.  Verification against the 09-16 log pending: expect d=0
  fires ~47 -> ~10/day and win% ~12% -> ~30%; revert 0.4.37+0.4.38
  together if win% stays at 12%.  See the 0.4.38 section.
- Prefix bucketing for mobile IPv6 (carrier rotates within /48s and
  /60s).  Would need configurable prefix length.  Not started.
- GitHub release pages for 0.4.30 through 0.4.36 -- tags exist,
  pages do not.  Cosmetic.

## SESSION 2026-09-15 (afternoon) — 0.4.33 to 0.4.35

Three follow-up releases after the reference-drift fix, addressing
swap-churn behavior observed in the 0.4.32 data.  All four hosts on
0.4.35; STATE_VERSION 12 (state file deleted on deploy).

### 0.4.33 — shorter settle for desperate and persistent-bad sockets

Settle was uniformly 60s.  Split into T_SETTLE_NORMAL_NS (60s) and
T_SETTLE_DESPERATE_NS (10s), selected by whether the socket was
desperate (>= 2x leader) or had accumulated persist_bad >= 2.
Intent: a stuck long-lived socket should not wait a full minute
between swap attempts.

### 0.4.34 — moderate margin 1.25x -> 1.50x; post-freeze uses
socket's own best

Two changes driven by the day's health check:

1. Moderate tier margin raised from 1.25x to 1.50x.  Data: on
   buckets where the top algorithms were within ~10% (TIGHT x1.0/
   x1.1), the 1.25-1.50 band was inside the metric's noise.  Over
   one day that band produced 12 IMP / 15 WRS -- worse than a coin
   flip.  The new floor keeps the tier for meaningful 1.50-2.00
   cases.

2. Post-freeze desperate tier now judges against the socket's own
   best_seen_metric (x2 threshold), not the bucket leader.  Data:
   frozen socket cookie 2927 cycled eight times through bic / veno /
   illinois / highspeed / htcp while every algorithm produced 12-14M.
   The socket was at its own path ceiling, not algorithm-limited.
   The bucket-relative 2x test kept firing because bucket best_v was
   5.6M (other sockets ran faster on the same path).  Pre-freeze
   behavior unchanged: bucket-relative 2x still fires immediately.

### 0.4.35 — collapse the split settle into one constant

Traced 0.4.33's settle logic and found the 60s branch was dead code:
any moderate swap requires SWAP_BAD_FIRST/LATER = 2 consecutive
above-margin checks, which is exactly the condition that sets
persist_bad >= 2.  So every swap took the 10s branch; T_SETTLE_NORMAL_NS
was unreachable.  Removed persist_bad, PERSIST_BAD_THRESHOLD, and the
two split constants.  Single T_SETTLE_NS = 10s.  The 2-bad-check
requirement above already prevents thrash; 10s is >= 300 RTT on a
30ms path.

### Verifier numbers across the three

| release | ESTABLISHED | vote |
|---------|-------------|------|
| 0.4.32  | 15242 / 1083 | 2982 / 188 |
| 0.4.33  | 15242 / 1083 | 2899 / 186 |
| 0.4.34  | 15242 / 1083 | 3173 / 207 |
| 0.4.35  | 15242 / 1083 | 2984 / 190 |

The 0.4.35 cleanup removed the persist_bad logic and its branches;
the vote program is smaller than 0.4.32.  Well within budget.

### What we know now (from the health check)

- Desperate tier (>= 2x leader) IMP/WRS ~ 67% -- doing its job.
- Moderate tier at 1.25x IMP/WRS ~ 44% -- worse than a coin flip.
  That is the case 0.4.34 fixes.
- Reference drift is fixed: home bucket max_rate_delivered recovered
  from 1.68M to 48-60M and holds.
- Freeze fires correctly (3 in a day).
- Multi-swap sockets (cookie 2927 at 9 swaps, 2192 at 6) were the
  churn case 0.4.34 bounds.  Watch whether they collapse to <=4
  after 0.4.35.

### Still open

- Best_seen_metric clamp: a socket whose best_seen is a one-off quiet
  moment (unrealistically low) will refuse post-freeze swaps even
  when the socket is genuinely degraded.  Deferred pending log
  evidence that the case occurs.
- Post-freeze swap target: currently best_alt_i (bucket-relative).
  Could in principle select an algorithm this socket already tried.
  Watch for a frozen socket bouncing between two algorithms.
- Prefix bucketing (0.4.36 candidate): mobile-carrier IPv6 rotates
  within /48s and /60s.  Bucketing by prefix would stop re-learning
  on rotation.  Needs configurable prefix length; operator-dependent.


## SESSION 2026-09-15 — 0.4.32 reference-drift fix

Reference updates gated on sustained-transfer evidence; streak promotion
fixes up-lock.  All four hosts on 0.4.32; state file deleted on deploy
(STATE_VERSION 9 -> 10).

### The bug

Home bucket CLIENT-IP max_rate_delivered pinned at 1,683,564 (~1.68
Mbps).  Yesterday 15-33 Mbps.  Overnight, no streaming, dragged down.

Two failure modes, same root:

1. Down-drift.  Control-plane traffic (DNS ~1 segment, SSH keepalive ~2,
   ctrl-API ~50) delivers 88K-350K.  Its heal-down rule (rate < ref/3)
   pulled max_rate_delivered toward those rates.
2. Up-lock.  Once collapsed, real traffic at 5-10 Mbps sat above
   ref * 2 = 3.36 Mbps, so the outlier-rejection rule refused it.
   No population could raise the ref.

Consequence: rate_term = (max_rate_delivered - rate_delivered) /
max_rate_delivered, clamped to >= 0, was zero for every socket on that
bucket.  Leaderboards since the collapse were RTT-only.

### The fix (three parts, shipped together)

1. Gate.  Reference updates only apply when the socket demonstrated
   sustained transfer.  Segment-rung votes (>= 10K segments) pass
   naturally.  Time-check votes still fire at TIME_CHECK_MIN_SEGS (1000,
   ~24 KB/s) but the ref only moves at the new REF_TIME_CHECK_MIN_SEGS
   (2000, ~390 Kbps sustained).  Control sockets never reach 2000.
2. Streak promotion.  Consecutive readings above ref * 2 (rate) or below
   ref / 2 (rtt) accumulate.  At REF_HIGH_STREAK_N (5) in a row, promote
   the ref to the max (rate) or min (rtt) of the streak.  Single
   anomalous readings are still rejected.
3. Heal-down gated too.  Both heal-up (rtt) and heal-down (rate) only
   run when the gate is open.

struct remote_host gained rate_high_streak, rate_high_max, rtt_low_streak,
rtt_low_min.

### Design decisions left implicit by the brief

- STATE_CB (close-path) votes get allow_ref = false.  They are neither
  segment-rung nor time-check and cannot build a streak of 5 anyway.
- When allow_ref_update == false, the streak counters are frozen too.
  Otherwise a control-plane reading would reset a data socket's streak
  and "5 in a row" would rarely fire on mixed buckets.

### Verifier numbers (0.4.32)

- ESTABLISHED: 15,242 insns / 1,083 total / 224 peak.
- Vote: 2,982 insns / 188 total / 185 peak.

The vote program got SMALLER (was ~3,457 / ~234).  Verifier collapsed the
gated ref block to fewer states than the old parallel if/else chain.  Not
a regression.

### Verification on the heavy host (2026-09-15)

Deploy at 07:51 UTC, state deleted, all four hosts on 0.4.32.  One video,
bpftool map dump polled once per minute:

| t (UTC) | min_rtt | max_rate_delivered | instances |
|---------|---------|--------------------|-----------|
| 07:52   | 0       | 0                  | 15        |
| 07:53   | 28664   | 22.4M              | 27        |
| 07:54   | 28664   | 96.6M              | 27        |
| 07:56   | 28664   | 87.7M              | 32        |
| 07:57   | 28664   | 96.6M              | 35        |
| 07:58   | 28664   | 92.1M              | 36        |
| 08:00   | 28664   | 92.1M              | 41        |
| 08:01   | 28664   | 87.1M              | 45        |
| 08:02   | 28479   | 78.0M              | 47        |

Ref 0 -> 78M in 10 minutes.  +/-10% oscillation is the gated heal-down
path reacting to momentary low-momentum sockets.  instances grew 15 -> 47
with the ref stable: the gate filtered the small-socket traffic that used
to drag it.

bucket-leaders.py home bucket: dctcp=4.1M(n27) leads lp=6.6M(n1) and
scalable=6.8M(n3).  LEAD (x1.6).  Those values need a live rate_term;
RTT-only cannot produce them.

### Watch-list

- Does max_rate_delivered recover to 15-33M on subsequent quiet-then-busy
  cycles, or does it settle wherever the last streak left it?
- Streak threshold (5) too aggressive on bursty paths?  If ref
  over-promotes then heals down repeatedly, consider 7-10.
- REF_TIME_CHECK_MIN_SEGS (2000) lets too much legitimate low-bandwidth
  traffic move the ref?  If a 1M-long-lived chat stream holds ref low,
  raise it.


## SESSION 2026-09-14 — 0.4.29 continuous monitoring, branch cleanup

All four hosts on 0.4.29.  State file deleted on deploy (STATE_VERSION
7 -> 8).  Observation window restarts.

### What changed
- Time-based supplementary vote: every 60s, if segs advanced by
  >= 1000, run the vote + swap decision even without a segment
  checkpoint.  Long sockets (past 1M segments) now get evaluated
  continuously instead of never.
- Settle window 5s -> 60s.  Rate limiter, not a total cap.
- SWAP_MAX removed.  Sockets can swap as often as needed, at most once
  per minute.
- New second-best branch: when a socket is on best_i and best_i is
  worse than second_i by 1.25x for this socket, swap to second_i.
  Because second_v >= best_v, this threshold is naturally stricter than
  the normal case; it should fire rarely.

### Why
The observation earlier today caught a socket running bbr at 4.9M that
was swapped to veno and settled at 363K.  That confirmed the mechanism
can produce large improvements.  But three of four swaps produced no
post-swap vote -- they fired at 10K and the sockets closed before 25K.
The time-check exists so that long sockets which previously went
unmonitored past 1M segments get continuous attention.

### Branch state
main is now the working branch.  diag/metric-terms is a stale pointer at
the same commit.  Future commits go to main; pull with `git pull --rebase
origin main` on the builders.

### What to read after 24-72h
- Is the time-check firing?  Count met cookie lines -- should be
  noticeably higher than 0.4.28.
- Are swaps more frequent on long sockets?  `swap cookie` count should
  be higher, especially on sockets with segs > 1M.
- Are swaps improving sockets?  Compare swapped-socket metric drop
  against the ~8% natural drift on non-swapped sockets.
- Does the second-best branch fire at all?  If yes, is it firing on
  genuine "leader struggling" cases or producing thrash between the
  top two?

## SESSION 2026-09-14 — 0.4.28 loss term, forced-BBR removed

Tag pending.  All four hosts deployed with state reset.  Previous freeze
data (through 2026-09-14) was on the 2-term metric and is NOT comparable;
observation window restarts from 2026-09-14.

### What changed

1. Metric now has three terms: rtt_term + rate_term + loss_term.
   loss_term = min(retrans/segs_out, LOSS_CAP_BP=200 [2.00%]) / LOSS_CAP_BP
   * LOSS_SCALE (8M, same ceiling as the other two).  The met log line
   gains a loss= field.

2. Removed the hardcoded forced-BBR rescue in RETRANS_CB.  It switched
   any socket above ~1.56% loss to BBR and cleared its RTT_CB flag, so
   lossy sockets could never vote for any other algorithm — the metric
   couldn't learn which algorithm handles loss best.  With loss now in
   the metric, the tuner learns this.  Kept: the TCP_THIN_LINEAR_TIMEOUTS
   opt-in for lossy sockets.

3. STATE_VERSION 6 -> 7.  State file deleted on every host.
   Verifier: ESTABLISHED 15238 insns / 1083 states, vote 3055 / 209.

### Observation setup

- /var/log/bpftune-met-YYYY-MM-DD.log on heavy host: continuous met log
  capture (was /tmp/met.*.log previously; moved to /var/log so it
  survives reboots).
- Cron /etc/cron.d/bpftune-loss-hist (heavy host): 04:10 daily, writes
  a histogram of loss= values from the previous day to
  /var/log/bpftune-loss-hist-YYYY-MM-DD.txt.
- Existing daily leaderboard snapshot (04:05) and the 4-slice JSON dump
  (bpftune-tod cron, 00/06/12/18:05) continue.

### What to read after 24-48h

Histogram at /var/log/bpftune-loss-hist-DATE.txt:

- Mostly loss=0 → the loss term is inert on this traffic; its removal of
  forced-BBR was a cleanup, not a functional change.
- Spread from 0 to 8,000,000 → the term is doing work; some sockets
  penalized.
- Saturated at 8,000,000 → 2% cap is too low; raise LOSS_CAP_BP.

LOSS_CAP_BP and LOSS_SCALE are principled guesses, not derived from
data.  Tune after the distribution is observed.

### Question this session is answering

Does the removal of forced-BBR change which algorithms win on lossy
buckets?  If the leaderboards are identical to what they would have
been with forced-BBR, the change was neutral and the shortcut wasn't
actually costing anything.  If buckets that previously showed BBR
winning now show something else (or tie more), the shortcut was
biasing the results and we've learned something.

The freeze previously scheduled to end 2026-09-21 now effectively ends
2026-09-21 with the caveat that its first day's data is post-change.

## SESSION 2026-09-14 — 0.4.27 tracker re-anchor shipped

Tag `0.4-27-custom`, all four hosts active.  Freeze resumes until 2026-09-21.

### What 0.4.27 fixes

Bug found in 0.4.25/0.4.26: the incremental tracker in the vote path
only compared best_i against second_i on each vote.  A third algorithm
could drift into a lower position without ever being promoted through
the pair, so best_i ended up pointing at the #2 algorithm while the
top-3 output on the tool showed the true #1.  Observed on the fleet as
`best_i=cubic` disagreeing with a top-3 whose first entry was westwood.

Fix: at the end of the ESTABLISHED selection loop, persist that loop's
own minindex and metric_min into remote_host->best_i/best_v.  Both
values are already computed by the loop — no new variables, no verifier
cost.  State count went 1077 -> 1087.

### Why not the more obvious fixes

- Explicit min2index tracking: blew the 1M insn verifier budget.  State
  count 1077 -> 23392.  The verifier's state explosion is driven by the
  number of variables live across loop iterations, not instruction
  count.
- Userspace re-anchor via bpf_map_update_elem: designed but not built.
  Would require a periodic hook in the daemon; the tuner ops struct
  (struct bpftuner in include/bpftune/bpftune.h) has init/fini/
  event_handler/summarize slots but no periodic slot.  bpftune.c:490
  has the mainloop (bpftune_ring_buffer_poll, interval=100).  Adding a
  periodic slot is the cleaner long-term design but not necessary given
  the ESTABLISHED re-anchor fits.

### Verification

Heavy host after deploy: best_i and top-3 leader agree exactly on 6 of
7 buckets.  The seventh shows both at 4.4M on a one-decimal display —
either a genuine tie or a rounding ambiguity, not a real mismatch.

### State file note

0.4.27 did NOT require a state-file delete.  struct remote_host layout
is unchanged from 0.4.26; only additional writes go into existing
fields.

### The 0.4.26 swap behavioral data

Between 0.4.26 and 0.4.27, on the heavy host:
- 6 swaps fired in a 15-minute window
- All 6 targeted the current bucket leader (algo=8, reno)
- Zero cases of "swap a socket off the leader" — the downgrade-branch
  removal holds
- No thrash pattern

The question that remains open: does the swap *improve* the socket's
own performance afterward?  Cookie-tagged met lines make this
measurable.  Sample set is not yet large enough to say.

### Freeze window

2026-09-14 through 2026-09-21.  Daily at 04:00 a snapshot; 04:05 a
leaderboard dump to /var/log/bpftune-leaders/.  On 2026-09-21:

    ls -la /var/log/bpftune-leaders/
    for f in /var/log/bpftune-leaders/*.txt; do echo "== $f"; head -10 "$f"; done

Look for: home-IP leader stable by day 2-3; mid-traffic buckets trend
toward one leader; low-traffic tail neutral.  If high-traffic buckets
churn, first thing to look at is threshold values in
tcp_conn_tuner.h (SWAP_MARGIN_PCT, MIN_LEADER_TRUST).

### Watch-list for the freeze

- All buckets showed `TIGHT (x1.0)` — the metric's discrimination across
  algorithms on busy buckets is low.  Either the algorithms genuinely
  perform similarly on these paths, or the metric isn't picking up the
  differences.  Worth a direct look at rtt_term and rate_term separately
  across the 16 algorithms for one busy bucket.
- Orphan BPF programs and duplicate maps can accumulate across deploys
  (found two on ip-172-26-13-90, one on vps-3959, from pre-0.4.18 and
  ad-hoc starts).  Weekly check:
      sudo bpftool prog show 2>/dev/null | grep -cE 'name .*conn_tuner'
      sudo bpftool map show name remote_host_map 2>&1 | grep -c 'name'
  Expected: 2 programs, 1 map.  Anything higher means an orphan.

## SESSION 2026-09-14 — 0.4.25 and 0.4.26 mid-socket swap

Reconstructed 2026-09-14 from session memory; several intermediate
iterations are lost to a force-push cycle.  The key shipped changes and
the reasoning that produced them are captured below.

### 0.4.25 — mid-socket swap, live tracker

Goal: rescue a socket that drew a bad algorithm without waiting for it
to close.  A 30-minute video should not be stuck on a bad choice for
its entire life because exploration rolled the dice badly at
ESTABLISHED.

Design landed on:
- Trigger in RTT_CB when the socket's own metric sample (last_metric)
  is >= 1.25x the current best alternative (SWAP_MARGIN_PCT=125),
  sustained for two consecutive checkpoints (SWAP_BAD_BEFORE=2).
- Swap bounded by SWAP_MAX=2 and a 5-second settle window
  (T_SETTLE_NS) after any successful swap, to avoid thrashing on
  cold-start readings from tcp_reinit_congestion_control.
- Attribution: the swap executes via bpf_setsockopt(TCP_CONGESTION);
  subsequent checkpoints read statep->state and credit the new
  algorithm automatically.
- sk_storage_map value type changed __u64 -> struct conn_state carrying
  {state, swap_count, bad_checkpoints, settle_until, last_metric,
  pending_swap}.  STATE_VERSION 4 -> 5.

First implemented as three sockops programs (conn_tuner,
conn_tuner_vote, conn_tuner_swap) with a pending_swap flag passing
between vote and swap.  Split because the merged version blew the 1M
insn verifier budget: a 16-iteration loop adjacent to two live
map_value pointers plus helper calls causes state explosion.
Snapshotting best_alt_i at ESTABLISHED removed all loops from the vote
path.  Tags 0.4-25-custom.

### 0.4.26 — merge back, four fixes

Traces from 0.4.25 on the heavy host showed:
- 6 swaps in a 15-minute window targeting the current leader
- Zero downgrades (no socket moved off the leader)
- But: the target was `highspeed` on a socket whose bucket leader was
  `illinois` — best_alt_i was snapshot at ESTABLISHED and never
  refreshed.

Fixes in 0.4.26:

1. Merge vote+swap back to a single RTT_CB program.  Inline set_cong
   removes the pending_swap field and the cross-program queue; swaps
   fire in the same RTT_CB event.  Program count 3 -> 2.  Safe because
   neither program has loops after the snapshot removal.

2. METRIC_TRIGGER_SEGS back to 10000.  The 5K experiment biased the
   metric: every socket's 5K sample is roughly 10x lower than its 25K
   sample (no queueing yet, no delivery rate yet), so 5K samples
   dominated the leader ranking and cubic took over on n=1.

3. MIN_LEADER_TRUST=3.  A leader needs at least 3 votes before it can
   be a swap target.  Directly addresses the n=1 leader case.

4. No downgrade branch.  A socket already on best_i has no better
   target and is skipped.  Previously the code targeted second_i in
   that case — a strict downgrade that could thrash the socket between
   best and second-best.

5. SWAP_BAD_FIRST=1, SWAP_BAD_LATER=2.  First rescue fires on a single
   bad checkpoint (faster for 30s+ videos); subsequent swaps need two.

6. Live tracker: best_i/best_v/second_i/second_v on struct remote_host,
   refreshed on every vote via an incremental update.  Replaces the
   ESTABLISHED snapshot (best_alt_i removed from conn_state).

STATE_VERSION 5 -> 6.  Tags 0.4-26-custom.  Verified: 6 swaps in
15 minutes, all targeting the current leader with a 3.3x margin,
zero downgrades, no thrash.

## SESSION 2026-09-13 (FINAL) — 0.4.23 coverage fix, 0.4.24 long-socket voting

Fleet on 0.4.24.  Tags `0.4-23-custom`, `0.4-24-custom`.  Freeze in effect
until 2026-09-20 — no code changes to the tuner during that window.

### 0.4.23 — coverage counts selections, not votes

Bug found after 0.4.22 shipped: the coverage loop gated on per-alg
metric_count, which only increments when a socket votes.  Sockets that
never vote did not advance the coverage pointer, so the same algorithm
was assigned to every new connection until one of its sockets happened
to vote.  Observed on heavy host: cubic 149, htcp 99, bbr 84, indices
6-15 at zero.  Round-robin was not happening.

Fix: add __u64 selection_count to struct remote_host, increment on every
ESTABLISHED, force-pick (selection_count & 15) while selection_count <
32.  STATE_VERSION 3 -> 4.  Verified post-deploy: instances=102,
selection_count=32, vote distribution spread across all 16 algs.

### 0.4.24 — long-lived sockets vote more

A socket that survives to 1M segments now casts 5 votes (10K/25K/100K/
500K/1M) instead of 1.  Before this, a 30-min video and a 200 ms TLS
handshake contributed equally — wrong, since the long socket has been
tested against the network and the short one barely finished slow
start.  Below 10K: printk only.  METRIC_AVG_CAP=32 bounds a 5-vote
socket to ~15%% of an algo mean, so it cannot drown the pack.

Change: `if (next != METRIC_TRIGGER_SEGS)` -> `if (next <` in the RTT_CB
walker.  One-line fix.

### Freeze — 2026-09-13 through 2026-09-20

Crons running on all four hosts:
- 04:00 daily: stop/start bpftune (forces save_remote_host_map)
- 04:05 daily: bucket-leaders.py output to /var/log/bpftune-leaders/

On 2026-09-20, read the seven daily leaderboard files:

    ls -la /var/log/bpftune-leaders/

What to look for:
- Home IP (CLIENT-IP): leader should stabilize by day 2-3 and stay.
- Mid-traffic destinations: should trend toward a single leader.
- Low-traffic tail: neutral is correct, not a bug.

If high-traffic buckets churn across the week, the margin-gate
threshold (25%% lead requirement) is the first knob to tune.

### Do NOT during freeze

- Change the tuner without evidence from the freeze window.
- Re-derive the rl_update 25%%-step root cause (verified 0.4.21).
- Re-attempt margin gate as second loop (verifier budget).
- Reconstruct metric_value from /tmp/met.log (bmrtt drift).

---

## SESSION 2026-09-13 (FINAL 0.4.22 draft) — historical

Fleet on 0.4.22. Tag `0.4-22-custom`. GitHub release published.

### What 0.4.22 changed

- Margin-gated exploitation: if leader is not >=25%% ahead of 2nd,
  boost exploration from 1/20 to 1/4 until the winner is clear.
- Coverage lowered 5 -> 2 (bounded cost 32 sockets/bucket, not 80).
- Tie-break machinery removed to fit the 1M-instruction verifier
  limit.  Ties resolve by lowest index.

### Why coverage went back to 2

Coverage=5 needed 80 sockets per bucket.  On the fleet map the vast
majority of buckets have <20 connections total, so most destinations
would stay in permanent round-robin and never learn.  Coverage=2
establishes a first-pass distribution; the margin gate then decides
whether to commit.  Low-traffic buckets stay neutral by design —
that is the correct answer when there is not enough information.

### Freeze

No code changes to the tuner until at least 2026-09-20.  Observe:

- High-traffic buckets (home IP, active CDNs): leader should
  settle and stay settled.
- Mid-traffic buckets: should gradually prefer one algorithm.
- Low-traffic buckets: neutral is fine, that is the design.

If behavior is clearly wrong at the end of the window, the next
change has a well-defined target.  If it is right, work is done.

### Do NOT

- Change the tuner without evidence from the freeze window.
- Re-derive the 0.4.21 root cause (rl_update 25%% step, verified).
- Re-attempt margin gate as a second loop (verifier rejects).
- Reconstruct metric_value from /tmp/met.log (bmrtt drift).

---

## SESSION 2026-09-13 (LATEST) — 0.4.21 metric averaging + cold-start

Version **0.4.21**, heavy host only (fleet rollout pending). Tag pending.

### Root cause found

metric_value was updated via rl_update with BPFTUNE_BITSHIFT=2, i.e. a
25% step per observation.  Effective memory ~4 samples regardless of
metric_count.  Home-bucket leader churn on CLIENT-IP (bbr 5.8M ->
7.59M over 5 votes) was this step, not path drift.  Verified by -r 0
drop-in: step became 1/64, matching the exact delta seen in the map.

### Fixes shipped on 0.4.21

1. metric_value -> count-based incremental mean, divisor min(count+1,
   METRIC_AVG_CAP=32).  Early observations move the value a lot, later
   ones settle it.  Verified: bbr 5->6 moved by (obs-value)/6 exactly.
2. Skip 127.0.0.0/8, 169.254.0.0/16, ::1, fe80::/10 at bucket-key.
3. Add remote_port to midsamp and closport printks (fixes 443 pairing).
4. Remove dead per-alg min_rtt/max_rate_delivered; STATE_VERSION=3.
5. Cold-start coverage: force-sample least-sampled alg until every alg
   has >= 5 votes, then normal epsilon-greedy.  Bounded (<=80 sockets).

### What we learned about cold-start

Coverage=2 was tried first.  Result: illinois raced to n=25 while nv
held the best log mean but was stuck at n=6.  Greedy exits coverage at
n=2, where the mean is mostly noise, so it commits to whichever alg
sampled lucky first.  Coverage=5 keeps the distribution flat (observed: 16
algs all between 4 and 7 after 30 min), then greedy resumes.

Margin-gated exploitation (raise epsilon to 1/4 while leader is not
>=20% ahead of 2nd) was attempted and REJECTED by the verifier: the
second 16-iteration loop pushed the program over the 1,000,000-
instruction limit.  Not viable without restructuring.

### Verification method (important)

Do NOT reconstruct metric_value from /tmp/met.log.  Bucket min_rtt
drifts mid-run so bmrtt filters miss votes, and trace_pipe drops
events under load.  Correct method: take two map dumps minutes
apart and solve V2 = V1 + (obs - V1)/(N+1) for each alg that gained
a vote.

### 0.4.22 scope (from tonight)

- Near-tie leader rotation.  When top algs are within ~12%, greedy
  oscillates between them without converging.  Margin gate would fix
  it but needs a non-loop implementation or verifier headroom.
- Vote weighting: long-lived sockets vote once then go silent; a
  30-min video and a 200ms handshake both contribute one vote.
  Options: re-vote at 100K/1M checkpoints, or weight by bytes.
- Tool: multi-netns column, n>=3 verdict gate, group no-closes rows.
- RFC1918 / VPC gateway filter (172.16/12 etc) not yet applied.

---

## SESSION 2026-09-13 (HISTORICAL) — fixed-size metric sampling (0.4.20)
Version **0.4.20**, all four hosts. Tag `0.4-20-custom`.

Sockets cast their metric vote exactly once at 10000 segments
(METRIC_TRIGGER_SEGS in tcp_conn_tuner.h). Previous behavior was
close-only — a 200-segment health check and a 500,000-segment video
transfer weighted equally in bucket ranking.

RTT_CB falls through to shared metric-update at 10K; STATE_CB skips the
vote for sockets that already voted; closport printk moved before the
skip gate so close-event pairing survives. RETRANS_CB-promoted sockets
(forced BBR) abstain.

Verified on heavy host, 10-min YouTube stream: 25 midsamp thr=10000
fires, 23 met votes >= 10000, 33 close-path votes (< 10000). Archived
to /tmp/met.0.4.19.log, /tmp/met.0.4.20.log.

Open for 0.4.21: short closes still vote with equal weight (33 vs 23).
Options: (a) weight by segment count, (b) raise trigger, (c) require N
trigger votes per bucket. Prototype (a) and (c).

---

## SESSION 2026-09-13 (HISTORICAL) — mid-flight diagnostic (0.4.19)
Version **0.4.19**, heavy host only. Superseded by 0.4.20.

### What's live
Two diagnostics run concurrently:
- `met alg=N segs=X val=V rtt=R rate=RT smrtt=S bmrtt=B avgrtt=A` — close-time (STATE_CB).
- `midsamp port=P thr=T segs=N smin=M savg=A srate=R` — fires at 1K/5K/25K/100K/500K/1M segment crossings (RTT_CB).
- `closport port=P segs=N` — close-time tag for pairing.

### Problem being diagnosed
Close-only sampling misses long-lived sockets (video streams). The tuner learns
mostly from short control traffic. Need to know: is a fixed-size checkpoint
representative, and at what size does the metric converge?

### Confirmed finding
Queueing delay (`savg - smin`) grows with socket size:
- 1000-1500 segs → ~10-13K µs
- 5000-6800 segs → ~19-20K µs

Metric's RTT term measures "how big was the socket," not algorithm quality.
Fixed-size sampling is justified.

### Known limitation
`ops->local_port` is 443 for all home connections → midsamp and closport can't
pair. Next patch: add `ops->remote_port` to both.

### Next step
Let a YouTube stream run 10 minutes, then:
    sudo grep -c 'midsamp' /tmp/met.log
    sudo grep 'midsamp' /tmp/met.log | awk '{for(i=1;i<=NF;i++){if($i~/^thr=/){split($i,a,"="); print a[2]}}}' | sort -n | uniq -c
    sudo head -3 /tmp/met.log
- 25K+ checkpoints present → long sockets captured, design fixed-size sampling
- only 1K/5K present → long sockets missed, that's the next investigation
- LOST EVENTS in trace header → increase /sys/kernel/tracing/buffer_size_kb

---

## SESSION 2026-09-12 (HISTORY) — metric correctness overhaul
Versions **0.4.10 through 0.4.14**.

### Bugs fixed
1. Rate term was inert — `rate_delivered` computed as bytes/µs, truncated to 0 or 1
   for most connections. Throughput half contributed nothing. Fixed in 0.4.8 by
   scaling to bytes/sec — this was the initially silent fix that 0.4.14's diagnostic
   surfaced.
2. Small sockets (16-36 segments) were pinning the bucket's `min_rtt` to 144µs
   while real traffic saw ~30,000µs, so every real socket hit the RTT cap. Fixed
   in **0.4.12** with `METRIC_MIN_SEGS=100` filter.
3. Rate term was frozen per algorithm — `m->max_rate_delivered` (all-time best)
   was passed instead of the current socket's rate. Fixed in **0.4.13**.
4. RTT term was min-vs-min, path-constant (all 16 algorithms within ±5%). Fixed
   in **0.4.14** by switching to queueing delay: `avg_rtt - bucket_min_rtt`.

### Verified
- 0.4.13: heal mechanisms fire — `heal_rtt` 11, `heal_rate` 154 events/h.
- 0.4.14: RTT term produces algorithm-dependent values with ~1M spread vs
  <250K gaps between top-3 algorithms — the balanced design works.

---

## SESSION 2026-09-13 (continued) — 0.4.15 through 0.4.19

- **0.4.15** outlier rejection — `REF_OUTLIER_FACTOR 2`, reject reference
  updates >2× better than current. Stops cascading drops from one fast socket.
- **0.4.16** reference healing — when a socket is >`REF_HEAL_FACTOR`(3)× away
  from reference, drift it 1/`REF_HEAL_DIV`(16) of the gap. Both directions.
  Convergence verified in live trace.
- **0.4.17** heal-event diagnostics — `heal_rtt` / `heal_rate` printks placed in
  the BPF caller, not the shared header (bpf_printk doesn't exist in userspace).
- **0.4.18 — destination keying.** Bucket key changed from next-hop gateway to
  remote host IP (`ops->remote_ip4` / `ops->remote_ip6`). Map type `HASH` →
  `LRU_HASH`, size 1024 → 4096. Added `PERSIST_MIN_INSTANCES=8` filter.
  `STATE_VERSION` 1 → 2 (old gateway-keyed state is auto-rejected on load).
  **Effect: 2 buckets per host → 100+ per busy host, per-path decisions now real.**
- **0.4.19** mid-flight sampling diagnostic via `BPF_SOCK_OPS_RTT_CB` (this session's live work).

---

## Version history (compact)

- **0.4-2 to 0.4-5**: 16-algo expansion, persistence + `-x` reset, three upstream
  bug fixes (cdg metric loop, IPv4 no-gateway pollution, IPv6 fall-through).
- **0.4-6 to 0.4-8**: cdg→nv in algorithm list, throughput term meaningful,
  RTT_DEVIATION_CAP=8.
- **0.4-9**: dpkg version string changed from `0-1` to `0.4.9` — permanently
  resolves apt-downgrade race against distro's `0.0~git*`. `apt-mark hold` no
  longer strictly required.
- **0.4.10 → 0.4.14**: metric correctness (rate-live, threshold, queueing RTT).
  Diagnostics added incrementally.
- **0.4.15 → 0.4.19**: outlier rejection, reference healing, heal diagnostics,
  destination keying, mid-flight diagnostic.
- **0.4-20**: fixed-size metric sampling.  Sockets vote once at 10K segments
  instead of only at close.
- **0.4-21**: `metric_value` → count-based incremental mean (replaces the
  25%%-step `rl_update` that caused leader churn).  Cold-start coverage.
  Pollution filter (127/8, 169.254/16, fe80::/10).  `remote_port` on midsamp
  and closport.
- **0.4-22**: margin-gated exploitation; coverage 5→2; tie-break switch
  dropped to fit the verifier.
- **0.4-23**: coverage counts SELECTIONS, not votes.  Fixes a bug where the
  same algorithm was assigned until one of its sockets happened to vote.
- **0.4-24**: vote at every checkpoint (10K..1M).  Long-lived sockets now
  carry more weight than short ones.
- **0.4-25**: mid-socket swap.  Trigger moved from rank-at-assign to live
  socket metric vs live bucket leader.  Live `best_i`/`second_i` on remote_host.
- **0.4-26**: merged vote+swap back to one RTT_CB program (3→2).  `MIN_LEADER_TRUST=3`;
  no downgrade branch; `SWAP_BAD_FIRST=1`, `SWAP_BAD_LATER=2`.

---

## Bugs fixed (single list, dedup)

Upstream (unchanged code inherited from oracle/bpftune):
1. IPv4 no-gateway bucket pollution (`rt_gw4=0` collides with `::ffff:0.0.0.0`)
2. IPv6 no-gateway fall-through (`break` instead of `return` in switch)
3. Rate term bytes/µs truncation
4. Rate term passed alg-best instead of current socket's rate

Self-inflicted (from the 16-algorithm expansion we added):
5. cdg metric loop — kernel rejects cdg from `bpf_setsockopt`; the failure path
   wasn't checked, so cdg's metric stayed at 0 and won every comparison.
   Note: the unchecked-return pattern is inherited from upstream, but the
   manifestation is ours — upstream ships 4 algorithms that all set
   successfully on this kernel, so the bug could not fire there.  It became
   real the moment we added cdg.

---

## Build / install / deploy

### Build
    cd /root/bpftune
    make clean                              # MANDATORY — stale objects bite
    dpkg-buildpackage -b -us -uc
    # produces ../bpftune_<version>_<arch>.deb

### Verify before install
    sudo rm -f /sys/fs/bpf/test_tcp_conn
    sudo bpftool prog load src/tcp_conn_tuner.bpf.o /sys/fs/bpf/test_tcp_conn
    echo exit=$?
    sudo rm -f /sys/fs/bpf/test_tcp_conn
Silent output + `exit=0` = verifier accepted.

### Deploy — state-file rule (READ CAREFULLY)
- **Metric-semantics change** (key type, reference semantics, version bump):
  DELETE the state file between stop and start. Example: 0.4.18 destination keying.
      sudo systemctl stop bpftune
      sudo rm -f /var/lib/bpftune/tcp_conn_tuner.state
      sudo dpkg -i <deb>; sudo systemctl start bpftune
- **Diagnostic-only or bugfix** (no semantic change): DO NOT delete state.
      sudo systemctl stop bpftune
      sudo dpkg -i <deb>; sudo systemctl start bpftune

### State file
`/var/lib/bpftune/tcp_conn_tuner.state` — 24B header (magic/version/sizes/count)
+ N×808B entries. Version checked on load; mismatch → ignored. Saved on
`fini()`, atomic write (tmp + rename).

### Trace capture
    sudo pkill -f 'cat /sys/kernel/tracing/trace_pipe'
    sudo mv /tmp/met.log /tmp/met.log.<prev>          # rotate
    sudo sh -c 'nohup cat /sys/kernel/tracing/trace_pipe > /tmp/met.log 2>&1 & echo pid=$!'
    echo 32768 | sudo tee /sys/kernel/tracing/buffer_size_kb
Only ONE reader at a time.

---

## Architecture

### Bucket key (as of 0.4.18)
`ops->remote_ip4` or `ops->remote_ip6` — the remote destination host.
Previously the next-hop gateway: 2 buckets per host, everything collapsed into
one IPv4 bucket. Now: 100+ buckets per busy host, each with its own RTT floor
and rate ceiling.

### Metric
    metric = rtt_term + rate_term          (lower wins)
    rtt_term  = (avg_rtt - bucket_min_rtt) / bucket_min_rtt * RTT_SCALE
                avg_rtt = tp->srtt_us >> 3 (µs), capped at
                RTT_DEVIATION_CAP(8) × RTT_SCALE
    rate_term = (bucket_max_rate - socket_rate) / bucket_max_rate * DELIVERY_SCALE
    RTT_SCALE = 1_000_000,  DELIVERY_SCALE = 8_000_000

### Reference update rules (0.4.15 + 0.4.16)
- New low `min_rtt`: accept unless more than `REF_OUTLIER_FACTOR`(2)× better
  than current.
- If `min_rtt` > `REF_HEAL_FACTOR`(3)× reference: drift up by 1/`REF_HEAL_DIV`(16)
  of the gap.
- Mirror rules for `max_rate` (reject huge spikes, heal downward).

### Persistence
Only buckets with `instances >= PERSIST_MIN_INSTANCES` (8) are written to state.
Recurring destinations survive; one-offs don't.

---

## Known kernel behavior

### cdg is permanently unusable from BPF
Kernel hardcodes rejection in `net/core/filter.c:sol_tcp_sockopt_congestion()`:
    /* "cdg" is the only cc that alloc a ptr in inet_csk_ca area.
     * The bpf-tcp-cc may overwrite this ptr after switching to cdg. */
    if (*optlen >= sizeof("cdg") - 1 && !strncmp("cdg", optval, *optlen))
        return -ENOTSUPP;
Not a fork bug. Handled by 0.4-5's `set_cong()` return-value check.

### Two summary blocks (per-netns, not a bug)
`bpftune -q summary` emits one CongAlg block per netns. Systemd sandboxes
(polkitd etc.) each get their own netns. `ip netns list` won't show them;
`lsns -t net` will.

### Multi-netns map dump
`bpftool map dump name remote_host_map` returns every map with that name across
every netns. `tools/bucket-leaders.py` flattens them — needs a map-ID column.

---

## Tools
`tools/bucket-leaders.py` — top-3 algorithms per bucket with sample counts.
`tools/swap-effectsize.py` — bin swaps by effect size (win/null/loss).
`tools/swap-outcomes-bydir.py` — split swaps by direction; read client-facing.
`tools/swap-trend.py` — classify each socket's trajectory at swap time.

Fetched on target hosts by SHA-pinned URL (branch name has a slash, so
`raw.githubusercontent.com/<branch>/...` doesn't work):
    sudo curl -sSLf https://raw.githubusercontent.com/cddeppe/bpftune/<SHA>/tools/bucket-leaders.py -o /usr/local/bin/bucket-leaders.py
    sudo curl -sSLf https://raw.githubusercontent.com/cddeppe/bpftune/<SHA>/tools/swap-effectsize.py -o /usr/local/bin/swap-effectsize.py
    sudo curl -sSLf https://raw.githubusercontent.com/cddeppe/bpftune/<SHA>/tools/swap-trend.py -o /usr/local/bin/swap-trend.py
    sudo curl -sSLf https://raw.githubusercontent.com/cddeppe/bpftune/<SHA>/tools/swap-outcomes-bydir.py -o /usr/local/bin/swap-outcomes-bydir.py
    sudo chmod +x /usr/local/bin/bucket-leaders.py /usr/local/bin/swap-effectsize.py /usr/local/bin/swap-trend.py /usr/local/bin/swap-outcomes-bydir.py /usr/local/bin/bucket-spread.py

## Known operational issues (cumulative)

### bpftune stays active but cgroup sock_ops silently detach

Observed 2026-09-17 morning on the heavy host.  `systemctl is-active
bpftune` returned `active`, no journal entry, no error.  Effect:
bpftune stopped affecting any socket for ~23 minutes before
discovery.  Recovery: `systemctl restart bpftune`.

Diagnosis: `sudo bpftool cgroup tree 2>/dev/null | grep -c -i
conn_tuner` returns 0 when detached, 2 when healthy.

Not root-caused.  Watch for this on any session where a host looks
healthy but the map counts stop moving.

## Open questions
1. Reference drift churn — home bucket `max_rate` moves 7M→47M across reads,
   leaders flip. Healing helps but doesn't stabilize busy buckets.
2. Fixed-size vs time-based trigger for long-socket sampling (informs this session).
3. Link-local filter — 169.254.x.x and fe80::/10 don't need CC tuning.
4. ~~Branch merge to `main` + 0.4.20 release~~ — done.
5. ~~Add `remote_port` to `midsamp` / `closport`~~ — done in 0.4.21.
6. Does the mid-socket swap actually help?  Six swaps on 2026-09-14 targeted
   the current bucket leader with a clean margin; no thrash observed.
   Post-swap improvement is committed to the log (cookie= on met lines) but
   not yet quantified across many sockets.
7. Short-video rescue — sub-15s videos cannot accumulate the checkpoints
   needed before close.  Physics limit, not a design gap.

## Working style (things that bite us)
- **User switches hosts manually.** Give commands for whichever host they're on and
  label clearly. Never tell them to SSH.
- **Heredocs with literal tabs mangle on paste.** Use `\t` escapes inside Python
  strings, or avoid tabs entirely.
- **Every patch script must assert before writing.** Anchor count, uniqueness,
  abort on mismatch. Half-applied edits are worse than clean failures.
- **Verify actual file content before editing.** `sed -n 'A,Bp' file | cat -A` first.
- **`make clean` before every build.** Non-negotiable.
- **SHA-pinned URLs** for target hosts without a repo clone.
- **Cross-arch releases build in parallel.** Both builders share
  the mount.  Kick off amd64 and arm64 compiles simultaneously,
  then deploy all four hosts from the mount.  0.4.38 was built
  serially and wasted ~10 minutes of wall clock.
- **`rm -f src/*.skel.h src/*.bpf.o src/*.o` before `make clean`.**
  The Makefile's .skel.h regeneration does not depend on .bpf.o;
  a stale .skel.h embeds the previous bytecode into the .so and
  the new change never reaches the running daemon.  Hit on 0.4.38
  and 0.4.39.  Non-negotiable.

- **Bump `debian/changelog` BEFORE the build, not after.**
  `dpkg-buildpackage` does not verify that the changelog version
  matches the source tree.  Build 0.4.64 source with the 0.4.63
  changelog and you get `bpftune_0.4.63_amd64.deb` containing
  0.4.64 code -- no error, no warning, silent version mismatch.
  This has cost a wasted rebuild on every agent session so far.
  Sequence: (1) edit `debian/changelog`, (2) `make clean` + the
  `rm -f` just above, (3) `dpkg-buildpackage`, (4) `ls ../bpftune_*.deb`
  and confirm the filename carries the new version.  Root fix when
  someone has time: a `debian/rules` guard that fails the build when
  the changelog version and the source disagree.  Non-negotiable.
