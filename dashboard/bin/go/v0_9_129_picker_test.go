package main

// v0_9_129_picker_test.go — regression tests for the frozen swap target
// (stale rate_best_i) fixed by the collector-side picker writeback.
//
// Incident (2026-11-06): swaps kept targeting illinois for hours while
// the leaderboard showed hybla as the leader. rate_best_i / rate_best_v
// — the target the BPF trigger reads — have exactly one writer: the
// tuner's reanchor worker. That thread captured the remote_host_map fd
// at tuner init and never refreshed it after the mid-run BPF re-init
// (the same reload behind the v0.9.128 corpse/live map pair), so the
// LIVE map's tracker never re-anchored: BPF kept updating metrics around
// a tracker frozen at its state-restore value. The collector, recomputing
// the pick from the same map's fresh metrics, showed the true leader.
//
// The incident bucket (exact numbers from the host): hybla rate_ema=107
// / 14 votes vs cubic 84 / 63 vs illinois 73 / 15. All three are trusted
// (>= MIN_LEADER_TRUST); the recompute must pick hybla, and the frozen
// tracker (illinois) must be repaired. The roundtrip case proves the
// repaired bucket is a fixed point — bit-exact with the C, so a resumed
// tuner-side reanchor and the collector writeback never fight.

import (
	"encoding/binary"
	"testing"
)

// metricSpec describes one tcp_conn_metric slot for buildBucket.
type metricSpec struct {
	votes     int
	value     uint64 // metric_value (u64; 0 / ~0 = unset sentinel)
	rateEMA   int    // 100KB/s units (u16)
	swapScore int    // 256 = neutral (u16)
	bad, null int    // streaks (u8)
}

// buildBucket builds a raw 1024-byte remote_host_map value. tracker
// seeds prefix fields by name; specs seeds metric slots by alg index.
func buildBucket(t *testing.T, tracker map[string]uint64, specs map[int]metricSpec) []byte {
	t.Helper()
	buf := make([]byte, sizeofRemoteHost)
	offs := map[string]int{
		"min_rtt": offMinRtt, "max_rate_delivered": offMaxRateDelivered,
		"instances": offInstances, "selection_count": offSelectionCount,
		"best_i": offBestI, "best_v": offBestV,
		"second_i": offSecondI, "second_v": offSecondV,
		"rate_best_i": offRateBestI, "rate_best_v": offRateBestV,
		"rate_second_i": offRateSecondI, "rate_second_v": offRateSecondV,
		"rtt_low_streak": offRttLowStreak, "rtt_low_min": offRttLowMin,
	}
	for k, v := range tracker {
		off, ok := offs[k]
		if !ok {
			t.Fatalf("buildBucket: unknown tracker field %q", k)
		}
		binary.LittleEndian.PutUint64(buf[off:], v)
	}
	for i, s := range specs {
		if i < 0 || i >= numTCPConnMetrics {
			t.Fatalf("buildBucket: alg index %d out of range", i)
		}
		b := metricBase(i)
		binary.LittleEndian.PutUint64(buf[b+offMetricCount:], uint64(s.votes))
		binary.LittleEndian.PutUint64(buf[b+offMetricValue:], s.value)
		binary.LittleEndian.PutUint16(buf[b+offMetricRateEMA:], uint16(s.rateEMA))
		binary.LittleEndian.PutUint16(buf[b+offMetricSwapScore:], uint16(s.swapScore))
		buf[b+offMetricBadStreak] = byte(s.bad)
		buf[b+offMetricNullStreak] = byte(s.null)
	}
	return buf
}

// trackerField reads one of the 8 tracker prefix fields back out.
func trackerField(t *testing.T, buf []byte, name string) uint64 {
	t.Helper()
	offs := map[string]int{
		"best_i": offBestI, "best_v": offBestV,
		"second_i": offSecondI, "second_v": offSecondV,
		"rate_best_i": offRateBestI, "rate_best_v": offRateBestV,
		"rate_second_i": offRateSecondI, "rate_second_v": offRateSecondV,
	}
	off, ok := offs[name]
	if !ok {
		t.Fatalf("trackerField: unknown field %q", name)
	}
	return binary.LittleEndian.Uint64(buf[off:])
}

// THE regression: the incident bucket with a tracker frozen at illinois
// (its state-restore value). The recompute must re-anchor rate_best_* to
// hybla — what the leaderboard was showing all along — and the applied
// result must be a fixed point of the formula (frozen-tracker roundtrip).
func TestIncidentBucketFrozenTrackerReanchorsToHybla(t *testing.T) {
	buf := buildBucket(t, map[string]uint64{
		// Frozen tracker as restored from the pre-reload state file:
		// illinois leading on both signals, cubic second.
		"best_i": 9, "best_v": 2_500_000,
		"second_i": 0, "second_v": 3_000_000,
		"rate_best_i": 9, "rate_best_v": 73,
	}, map[int]metricSpec{
		0:  {votes: 63, value: 3_000_000, rateEMA: 84, swapScore: 256},  // cubic
		9:  {votes: 15, value: 2_500_000, rateEMA: 73, swapScore: 256},  // illinois
		14: {votes: 14, value: 2_800_000, rateEMA: 107, swapScore: 256}, // hybla
	})

	oc := computeReanchor(buf)

	// Pass 1: trusted minimum of the metric values = illinois (2.5M).
	if oc.bestI != 9 || oc.bestV != 2_500_000 {
		t.Fatalf("pass 1: best = %d/%d, want illinois(9)/2500000", oc.bestI, oc.bestV)
	}
	// Pass 2: min trusted-value among the rest, >= best_v: hybla 2.8M
	// (cubic 3.0M is higher, so second-best is hybla).
	if oc.secondI != 14 || oc.secondV != 2_800_000 {
		t.Fatalf("pass 2: second = %d/%d, want hybla(14)/2800000", oc.secondI, oc.secondV)
	}
	// Pass 3: hybla 107 > cubic 84 > illinois 73 at neutral scores and
	// clean streaks — the leaderboard's leader. rate_best_v stores the
	// RAW rate_ema; the BPF trigger math needs a rate.
	if oc.rateBestI != 14 || oc.rateBestV != 107 {
		t.Fatalf("pass 3: rate_best = %d/%d, want hybla(14)/107 — tracker still frozen at illinois(9)/73",
			oc.rateBestI, oc.rateBestV)
	}
	if oc.rateSecondI != 0 || oc.rateSecondV != 84 {
		t.Fatalf("pass 3: rate_second = %d/%d, want cubic(0)/84", oc.rateSecondI, oc.rateSecondV)
	}
	if len(oc.scoreInits) != 0 {
		t.Fatalf("scoreInits = %v, want none (all scores non-zero)", oc.scoreInits)
	}

	// The frozen tracker must not read as unchanged…
	if reanchorUnchanged(buf, oc) {
		t.Fatal("frozen tracker must not read as unchanged")
	}
	// …and the writeback repairs it.
	applyReanchor(buf, oc)
	if got := trackerField(t, buf, "rate_best_i"); got != 14 {
		t.Fatalf("after writeback rate_best_i = %d, want 14 (hybla)", got)
	}
	if got := trackerField(t, buf, "rate_best_v"); got != 107 {
		t.Fatalf("after writeback rate_best_v = %d, want 107", got)
	}
	if got := trackerField(t, buf, "rate_second_i"); got != 0 {
		t.Fatalf("after writeback rate_second_i = %d, want 0 (cubic)", got)
	}

	// Frozen-tracker roundtrip: the repaired bucket is a fixed point of
	// the formula — a resumed tuner-side reanchor computes the identical
	// values, so the two writers are conflict-free.
	oc2 := computeReanchor(buf)
	if !reanchorUnchanged(buf, oc2) {
		t.Fatalf("repaired bucket must be a fixed point, got drift: %+v", oc2)
	}
}

// The v0.4.99 zero-score skip and the 0.4.63 stale-score init, exactly
// as the tuner runs them: a legitimately-zeroed score is EXCLUDED from
// this cycle's pick (not treated as neutral 256 — pre-0.4.99 semantics
// would have picked cubic 90 over hybla 80), and is re-initialized to
// 256 in the same write so it competes again from the next cycle on.
func TestZeroScoreSkipAndStaleScoreInit(t *testing.T) {
	buf := buildBucket(t, nil, map[int]metricSpec{
		0:  {votes: 63, value: 3_000_000, rateEMA: 90, swapScore: 0},   // cubic: zeroed score
		14: {votes: 14, value: 2_800_000, rateEMA: 80, swapScore: 256}, // hybla
	})

	oc := computeReanchor(buf)
	if oc.rateBestI != 14 || oc.rateBestV != 80 {
		t.Fatalf("rate_best = %d/%d, want hybla(14)/80 — cubic must be skipped (v0.4.99 zero-score skip), not treated as neutral 256",
			oc.rateBestI, oc.rateBestV)
	}
	if len(oc.scoreInits) != 1 || oc.scoreInits[0] != 0 {
		t.Fatalf("scoreInits = %v, want [0] (cubic: score 0 with 63 votes)", oc.scoreInits)
	}

	applyReanchor(buf, oc)
	if got := binary.LittleEndian.Uint16(buf[metricBase(0)+offMetricSwapScore:]); got != swapScoreNeutral {
		t.Fatalf("cubic swap_score after writeback = %d, want %d (0.4.63 init)", got, swapScoreNeutral)
	}

	// Next cycle: with the score re-initialized, cubic (90) beats hybla (80).
	oc2 := computeReanchor(buf)
	if oc2.rateBestI != 0 || oc2.rateBestV != 90 {
		t.Fatalf("after 0.4.63 init, rate_best = %d/%d, want cubic(0)/90", oc2.rateBestI, oc2.rateBestV)
	}
	if len(oc2.scoreInits) != 0 {
		t.Fatalf("scoreInits after init = %v, want none", oc2.scoreInits)
	}
}

// The 0.4.60 demotion penalty is integer math, bit-exact with the C:
// weighted = rate_ema * swap_score/256 * 16/(16 + bad*4 + null*2).
// bad=2 → 16/24 → a 100-EMA alg scores 66 and loses to a clean 80-EMA.
func TestBadStreakPenaltyDemotesInIntegerMath(t *testing.T) {
	buf := buildBucket(t, nil, map[int]metricSpec{
		0:  {votes: 63, value: 3_000_000, rateEMA: 100, swapScore: 256, bad: 2}, // cubic, demoted
		14: {votes: 14, value: 2_800_000, rateEMA: 80, swapScore: 256},          // hybla, clean
	})
	oc := computeReanchor(buf)
	// cubic: 100*256/256 = 100; pen = 16+8 = 24; 100*16/24 = 66 (u64 div).
	// hybla: 80. The demoted leader loses.
	if oc.rateBestI != 14 || oc.rateBestV != 80 {
		t.Fatalf("rate_best = %d/%d, want hybla(14)/80 — bad_streak=2 must demote cubic 100 to 66",
			oc.rateBestI, oc.rateBestV)
	}
	if oc.rateSecondI != 0 || oc.rateSecondV != 100 {
		t.Fatalf("rate_second = %d/%d, want cubic(0)/100 (raw rate, demoted rank)", oc.rateSecondI, oc.rateSecondV)
	}
}

// No trusted leader (all counts < MIN_LEADER_TRUST): the whole tracker,
// including the rate pair, is forced to the empty state so the swap path
// sees "no leader" rather than a stale target.
func TestNoTrustedLeaderEmptiesTracker(t *testing.T) {
	buf := buildBucket(t, map[string]uint64{
		"rate_best_i": 14, "rate_best_v": 107, // stale from before
	}, map[int]metricSpec{
		14: {votes: 9, value: 2_800_000, rateEMA: 107, swapScore: 256}, // hybla, only 9 votes
	})
	oc := computeReanchor(buf)
	if oc.bestI != 0 || oc.bestV != 0 || oc.secondI != 0 || oc.secondV != 0 ||
		oc.rateBestI != 0 || oc.rateBestV != 0 || oc.rateSecondI != 0 || oc.rateSecondV != 0 {
		t.Fatalf("tracker must be forced to the empty state, got %+v", oc)
	}
	if reanchorUnchanged(buf, oc) {
		t.Fatal("stale tracker with no trusted leader must not read as unchanged")
	}
	applyReanchor(buf, oc)
	if got := trackerField(t, buf, "rate_best_i"); got != 0 {
		t.Fatalf("rate_best_i after writeback = %d, want 0 (empty state)", got)
	}
	if got := trackerField(t, buf, "rate_best_v"); got != 0 {
		t.Fatalf("rate_best_v after writeback = %d, want 0 (empty state)", got)
	}
}

// The leaderboard pick highlight (renderMetric in dashboard.js) enforces
// the picker's own eligibility with the threshold carried via meta.json
// (min_leader_trust = MIN_LEADER_TRUST = 10). This pins the exact rule.
func TestPickerEligibleMatchesLeaderboardGate(t *testing.T) {
	if !pickerEligible(14, 256, 107) {
		t.Fatal("hybla in the incident bucket (14 votes, score 256, rate 107) must be eligible")
	}
	if pickerEligible(9, 256, 107) {
		t.Fatal("9 votes < min_leader_trust (10) must be ineligible")
	}
	if pickerEligible(63, 0, 84) {
		t.Fatal("zero swap score must be ineligible (v0.4.99 skip)")
	}
	if pickerEligible(63, 256, 0) {
		t.Fatal("zero rate must be ineligible")
	}
}

// keyArgsFromRaw feeds mapLookupBytes / mapUpdateBytes — hex roundtrip.
func TestKeyArgsFromRaw(t *testing.T) {
	key := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 82, 37, 36, 1}
	args := keyArgsFromRaw(key)
	if len(args) != 16 {
		t.Fatalf("len(args) = %d, want 16", len(args))
	}
	want := "52" // 82 = 0x52 — first v4 byte of the key
	if args[12] != want {
		t.Fatalf("args[12] = %q, want %q", args[12], want)
	}
}
