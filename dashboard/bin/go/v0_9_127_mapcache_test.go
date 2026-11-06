package main

import (
	"testing"
	"time"
)

// v0.9.127 regression tests: the count-based bpfMapCache served a stale
// merged snapshot whenever the remote_host_map entry COUNT was stable,
// even though the daemon updates rate_ema/metric_count/streaks/swap_score
// IN PLACE. Result: the leaderboard froze while swaps/proofs (log-driven)
// stayed live.

func mapCacheResetState() {
	bpfMapCache = nil
	bpfMapCacheErr = nil
	bpfMapCacheSize = 0
	bpfMapCacheAt = time.Time{}
}

func singleEntryRaw(rateEMA int) map[string]interface{} {
	metrics := make([]interface{}, 16)
	metrics[0] = map[string]interface{}{"rate_ema": rateEMA, "metric_count": 5}
	val := map[string]interface{}{"instances": 3, "metrics": metrics}
	key := map[string]interface{}{"in6_u": map[string]interface{}{
		"u6_addr8": []interface{}{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 1, 2, 3, 4},
	}}
	return map[string]interface{}{"formatted": map[string]interface{}{
		"key": key, "value": val,
	}}
}

func firstCubicEMA(out []hostEntry) int {
	if len(out) == 0 {
		return -1
	}
	mets, _ := out[0].V["metrics"].([]interface{})
	if len(mets) == 0 {
		return -1
	}
	m0, _ := mets[0].(map[string]interface{})
	if m0 == nil {
		return -1
	}
	return toInt(m0["rate_ema"])
}

// TestMergeReflectsInPlaceValueUpdates: two cycles with the SAME entry
// count but different in-place values must yield different output.
// Guards against re-introducing a count-based early return anywhere in
// the fresh-read path.
func TestMergeReflectsInPlaceValueUpdates(t *testing.T) {
	oldMode := collectorMode.CacheBPFMap
	collectorMode.CacheBPFMap = true
	defer func() { collectorMode.CacheBPFMap = oldMode; mapCacheResetState() }()
	mapCacheResetState()

	out1, err := mergeBPFMapEntries([]map[string]interface{}{singleEntryRaw(100)})
	if err != nil {
		t.Fatalf("cycle 1 merge: %v", err)
	}
	if got := firstCubicEMA(out1); got != 100 {
		t.Fatalf("cycle 1 cubic rate_ema = %d, want 100", got)
	}

	// Cycle 2: daemon updated rate_ema in place (100 -> 500).
	// Same entry count — the old count-based cache would have returned
	// the cycle-1 snapshot here.
	out2, err := mergeBPFMapEntries([]map[string]interface{}{singleEntryRaw(500)})
	if err != nil {
		t.Fatalf("cycle 2 merge: %v", err)
	}
	if got := firstCubicEMA(out2); got != 500 {
		t.Fatalf("v0.9.127 REGRESSION: cycle 2 cubic rate_ema = %d, want 500 — in-place update lost (stale snapshot served)", got)
	}
}

// TestFallbackCacheIsTTLBounded: mergeBPFMapEntries must refresh
// bpfMapCacheAt when it caches, so the bpftool-fork fallback path's
// count-based shortcut expires after bpfMapCacheTTL instead of serving
// a frozen snapshot forever.
func TestFallbackCacheIsTTLBounded(t *testing.T) {
	oldMode := collectorMode.CacheBPFMap
	collectorMode.CacheBPFMap = true
	defer func() { collectorMode.CacheBPFMap = oldMode; mapCacheResetState() }()
	mapCacheResetState()

	if _, err := mergeBPFMapEntries([]map[string]interface{}{singleEntryRaw(100)}); err != nil {
		t.Fatalf("merge: %v", err)
	}
	if bpfMapCache == nil {
		t.Fatal("bpfMapCache not populated by merge")
	}
	if time.Since(bpfMapCacheAt) >= bpfMapCacheTTL {
		t.Fatal("bpfMapCacheAt not refreshed by merge — fallback cache never valid (perf regression)")
	}

	// Simulate an aged cache: the fallback gate must now be closed,
	// forcing a fresh dump on the next readBPFMap call.
	bpfMapCacheAt = time.Now().Add(-2 * bpfMapCacheTTL)
	if time.Since(bpfMapCacheAt) < bpfMapCacheTTL {
		t.Fatal("aged bpfMapCacheAt still within TTL — TTL bound not effective, fallback can serve stale data forever")
	}
}
