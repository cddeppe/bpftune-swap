package main

// v0_9_126_writeback_test.go — regression tests for the v0.9.126 write-path
// fixes (see streak_writeback.go / config_handler.go / health_check.go):
//
//  1. mask detection is not poisoned by alias targets (fallback path)
//  2. stale-FD EBADF detection works on %w-wrapped errors
//  3. odd-seq torn-read guard on the C1 re-lookup
//
// The PRIMARY mask source (tuner_config_map slots 1/2 via the pinned map)
// needs a real BPF map and is therefore exercised only on a live host; the
// exclusion fallback below is what runs when the pin is unavailable.

import (
        "errors"
        "fmt"
        "net"
        "testing"
        "time"

        "golang.org/x/sys/unix"
)

// withMaskBits restores maskBitsV4/V6 after the test.
func withMaskBits(t *testing.T, v4, v6 int) {
        t.Helper()
        oldV4, oldV6 := maskBitsV4, maskBitsV6
        maskBitsV4, maskBitsV6 = v4, v6
        t.Cleanup(func() { maskBitsV4, maskBitsV6 = oldV4, oldV6 })
}

// TestExcludeAliasTargetKeys: alias TARGETS (stored verbatim by the daemon's
// bucket_key_alias_or_prefix) must be dropped from the key-scan, while
// ordinary masked bucket keys survive.
func TestExcludeAliasTargetKeys(t *testing.T) {
        aliases := map[string]string{
                "104.18.77.3": "104.16.9.9", // exact-form entry (raw fold)
                "104.18.0.0":  "104.16.9.9", // prefix-form entry (masked fold)
        }
        v4 := [][]byte{
                {104, 18, 0, 0}, // masked bucket key (daemon /16)
                {8, 8, 0, 0},    // masked bucket key
                {104, 16, 9, 9}, // ALIAS TARGET — stored verbatim, unaligned
        }
        got := excludeAliasTargetKeys(v4, false, aliases)
        if len(got) != 2 {
                t.Fatalf("expected 2 keys after exclusion, got %d: %v", len(got), got)
        }
        for _, k := range got {
                if k[0] == 104 && k[1] == 16 && k[2] == 9 && k[3] == 9 {
                        t.Fatalf("alias target 104.16.9.9 was not excluded: %v", got)
                }
        }

        // v6: 16-byte keys, one of which is an alias target.
        v6aliases := map[string]string{"2001:db8:1::5": "2606:1a40:99::"}
        v6 := [][]byte{
                net.ParseIP("2606:1a40::").To16(),    // masked /32 bucket key
                net.ParseIP("2606:1a40:99::").To16(), // ALIAS TARGET — verbatim
        }
        got6 := excludeAliasTargetKeys(v6, true, v6aliases)
        if len(got6) != 1 {
                t.Fatalf("expected 1 v6 key after exclusion, got %d", len(got6))
        }
        if string(got6[0]) != string(net.ParseIP("2606:1a40::").To16()) {
                t.Fatalf("wrong key survived exclusion: %v", got6[0])
        }

        // No aliases → passthrough.
        if got := excludeAliasTargetKeys(v4, false, nil); len(got) != 3 {
                t.Fatalf("empty alias map must pass keys through, got %d", len(got))
        }
}

// TestMaskDetectionNotPoisonedByAliasTargets — the bug-1 regression test.
// Unfiltered, the verbatim alias target 104.16.9.9 drives the inference to
// /32 (the poison). With the exclusion, the daemon's /16 is recovered.
func TestMaskDetectionNotPoisonedByAliasTargets(t *testing.T) {
        aliases := map[string]string{"104.18.77.3": "104.16.9.9"}
        v4 := [][]byte{
                {104, 18, 0, 0},
                {8, 8, 0, 0},
                {104, 16, 9, 9}, // alias target
        }

        // Document the poison: unfiltered keys → /32 (all trailing bytes not zero
        // at /8, /16, /24).
        withMaskBits(t, 16, 32)
        applyMaskDetection(v4, nil)
        if maskBitsV4 != 32 {
                t.Fatalf("sanity: unfiltered keys should infer /32 (the poison), got /%d", maskBitsV4)
        }

        // The fix: filtered keys → /16.
        withMaskBits(t, 16, 32)
        applyMaskDetection(excludeAliasTargetKeys(v4, false, aliases), nil)
        if maskBitsV4 != 16 {
                t.Fatalf("filtered keys should infer /16, got /%d", maskBitsV4)
        }

        // All keys alias targets → no v4 keys left → mask unchanged (defaults
        // stand; the pinned-map primary path supplies the real value on live
        // hosts).
        withMaskBits(t, 16, 32)
        applyMaskDetection(excludeAliasTargetKeys([][]byte{{104, 16, 9, 9}}, false, aliases), nil)
        if maskBitsV4 != 16 {
                t.Fatalf("no inferable keys must leave the default, got /%d", maskBitsV4)
        }
}

// TestErrorsIsDetectsWrappedEBADF — the bug-2 regression test.
// bpfMapLookupElem/bpfMapUpdateElem wrap the errno with %w; the old
// `err == unix.EBADF` comparison could never match (proved here), so the FD
// cache was never invalidated after a tuner restart.
func TestErrorsIsDetectsWrappedEBADF(t *testing.T) {
        wrapped := fmt.Errorf("BPF_MAP_LOOKUP_ELEM: %w", unix.EBADF)
        if wrapped == unix.EBADF {
                t.Fatal("sanity: wrapped error must NOT be == unix.EBADF (the old dead check)")
        }
        if !errors.Is(wrapped, unix.EBADF) {
                t.Fatal("errors.Is must detect EBADF through the %w wrapper")
        }
        // Non-EBADF wrapped errors must not match.
        other := fmt.Errorf("BPF_MAP_LOOKUP_ELEM: %w", unix.ENOENT)
        if errors.Is(other, unix.EBADF) {
                t.Fatal("errors.Is must not report EBADF for ENOENT")
        }
}

// TestInvalidateMapCaches — the per-id FD cache and the map-ID list cache
// are dropped, so the next cycle re-resolves via `bpftool map show`.
func TestInvalidateMapCaches(t *testing.T) {
        cachedMapFDs = map[int]int{223: 42, 282: 43}
        maskCacheMu.Lock()
        cachedMapIDs = []int{282, 223}
        mapIDCacheAt = time.Now()
        maskCacheMu.Unlock()

        invalidateMapCaches()

        if len(cachedMapFDs) != 0 {
                t.Fatalf("cachedMapFDs not cleared: %v", cachedMapFDs)
        }
        maskCacheMu.Lock()
        ids, at := cachedMapIDs, mapIDCacheAt
        maskCacheMu.Unlock()
        if len(ids) != 0 {
                t.Fatalf("cachedMapIDs not cleared: %v", ids)
        }
        if !at.IsZero() {
                t.Fatalf("mapIDCacheAt not reset: %v", at)
        }
}

// TestWritebackSeqCheck — the bug-3 regression test (torn-read guard).
func TestWritebackSeqCheck(t *testing.T) {
        cases := []struct {
                orig, fresh uint64
                wantSkip    bool
                desc        string
        }{
                {4, 4, false, "even, unchanged — proceed"},
                {6, 6, false, "even, unchanged — proceed"},
                {4, 6, true, "seq changed — kernel updated mid-cycle"},
                {5, 5, true, "odd seq (kernel mid-update) — torn read"},
                {7, 7, true, "odd seq (kernel mid-update) — torn read"},
                {5, 7, true, "odd AND changed — torn read"},
                {0, 0, false, "zero seq, even — proceed"},
        }
        for _, tc := range cases {
                skip, reason := writebackSeqCheck(tc.orig, tc.fresh)
                if skip != tc.wantSkip {
                        t.Errorf("%s: writebackSeqCheck(%d,%d) skip=%v want %v (reason %q)",
                                tc.desc, tc.orig, tc.fresh, skip, tc.wantSkip, reason)
                }
                if skip && reason == "" {
                        t.Errorf("%s: skip reason must be non-empty", tc.desc)
                }
        }
}
