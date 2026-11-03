package main

// bpf_reader_cache_test.go — regression test for the frozen-leaderboard
// fix (v0.9.117).
//
// The v0.9.33 count-match cache returned the same merged map snapshot
// whenever the BPF map ENTRY COUNT was unchanged.  Map VALUES
// (swap_score, rate_ema, streaks) change every vote without changing the
// count, so on a stable host the leaderboard froze until a collector
// restart.  The cache is now only valid for the bpftool fallback AND
// only for 60 seconds.
//
// These tests pin bpfMapCacheFresh()'s contract so the stale-serving
// behaviour cannot come back unnoticed.

import (
	"testing"
	"time"
)

func TestBpfMapCacheFresh(t *testing.T) {
	// Save and restore all globals touched.
	oldCache := bpfMapCache
	oldErr := bpfMapCacheErr
	oldSize := bpfMapCacheSize
	oldAt := bpfMapCacheAt
	oldMode := collectorMode
	t.Cleanup(func() {
		bpfMapCache = oldCache
		bpfMapCacheErr = oldErr
		bpfMapCacheSize = oldSize
		bpfMapCacheAt = oldAt
		collectorMode = oldMode
	})

	collectorMode.CacheBPFMap = true

	// 1. No cache -> never fresh.
	bpfMapCache = nil
	bpfMapCacheAt = time.Now()
	if bpfMapCacheFresh(5) {
		t.Fatal("empty cache must not be served")
	}

	// 2. Fresh cache with matching entry count -> served.
	bpfMapCache = []hostEntry{{Addr: "x"}}
	bpfMapCacheSize = 5
	bpfMapCacheAt = time.Now()
	if !bpfMapCacheFresh(5) {
		t.Fatal("fresh cache with matching count must be served")
	}

	// 3. Entry count mismatch -> never served (map restructured).
	if bpfMapCacheFresh(6) {
		t.Fatal("count mismatch must not be served")
	}

	// 4. TTL: older than 60s -> not served even with matching count.
	//    This is the frozen-leaderboard guard: values may have changed
	//    every vote while the count stood still.
	bpfMapCacheAt = time.Now().Add(-61 * time.Second)
	if bpfMapCacheFresh(5) {
		t.Fatal("cache older than 60s must not be served (frozen-leaderboard bug)")
	}

	// 5. Just inside the TTL -> served.
	bpfMapCacheAt = time.Now().Add(-59 * time.Second)
	if !bpfMapCacheFresh(5) {
		t.Fatal("cache inside TTL must be served")
	}

	// 6. Caching disabled -> never served.
	collectorMode.CacheBPFMap = false
	bpfMapCacheAt = time.Now()
	if bpfMapCacheFresh(5) {
		t.Fatal("cache disabled must not be served")
	}
}
