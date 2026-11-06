package main

// v0_9_131_hardening_test.go — regression tests for the three v0.9.131
// hardening fixes (all collector-side; the tuner is untouched):
//
//  1. Log-tail cache memory bound: total cached bytes ≤ budget (was
//     per-FILE budget × ~15 logrotate files ≈ 15× budget), .gz rotations
//     skipped, entries for vanished files purged — with the join output
//     still byte-identical (trim mirrors join accounting; regrow covers
//     allowance growth after copytruncate).
//  2. Writeback map fds are closed at cycle end / on invalidation (was:
//     dropped without close → leaked fd numbers AND pinned destroyed
//     maps' kernel memory for the life of the collector).
//  3. Sustained-outcome cache evicts FIFO (was: random map-iteration
//     delete — a fresh outcome could be discarded while a stale one
//     survived).

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// ---------------------------------------------------------------------------
// 1a. Budget bound + .gz skip + output identity
// ---------------------------------------------------------------------------

func TestLogTailCacheBudgetBoundedSkipsGz(t *testing.T) {
	dir := t.TempDir()
	oldGlob := logGlobPattern
	logGlobPattern = filepath.Join(dir, "bpftune-met-live.log*")
	defer func() { logGlobPattern = oldGlob; resetTailCacheForTest() }()
	resetTailCacheForTest()

	base := time.Now().Add(-time.Hour).Truncate(time.Second)
	// 15 uncompressed files × ~36KB each; budget 64KB → without the trim
	// pass the cache would hold 15 × 36KB ≈ 540KB for a 64KB budget.
	for i := 0; i <= 14; i++ {
		name := "bpftune-met-live.log"
		if i > 0 {
			name = fmt.Sprintf("bpftune-met-live.log.%d", i)
		}
		perfWriteFile(t, filepath.Join(dir, name),
			strings.Repeat(fmt.Sprintf("f%02d-line\n", i), 4000),
			base.Add(time.Duration(15-i)*time.Minute))
	}
	// A compressed rotation must be ignored entirely (newest mtime, so if
	// the skip regressed its bytes would lead the join and be caught).
	gzPath := filepath.Join(dir, "bpftune-met-live.log.2.gz")
	gzBytes := []byte{0x1f, 0x8b, 0x08, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03}
	if err := os.WriteFile(gzPath, gzBytes, 0644); err != nil {
		t.Fatal(err)
	}
	os.Chtimes(gzPath, base.Add(30*time.Minute), base.Add(30*time.Minute))

	const budget = 64 * 1024
	got := readLogTailCached(budget)
	if got == "" {
		t.Fatal("empty tail")
	}
	if strings.ContainsRune(got, 0x1f) || strings.Contains(got, "\x00") {
		t.Fatal("tail contains raw .gz bytes — compressed rotations must be skipped")
	}
	// Identity vs the reference (which also skips .gz).
	if want := readLogTail(budget); got != want {
		t.Fatalf("tail mismatch: got len=%d want len=%d", len(got), len(want))
	}

	// Total cached bytes must be ≤ budget.
	tailMu.Lock()
	total := 0
	for _, fc := range tailFiles {
		total += len(fc.chunk)
	}
	_, hasGz := tailFiles[gzPath]
	tailMu.Unlock()
	if total > int(budget) {
		t.Fatalf("cached %d bytes for a %d-byte budget (per-file cap bug)", total, budget)
	}
	if hasGz {
		t.Fatal(".gz rotation was cached")
	}

	// Warm read: unchanged files, still identical.
	if got2 := readLogTailCached(budget); got2 != got {
		t.Fatal("warm read differs from cold read")
	}
}

// ---------------------------------------------------------------------------
// 1b. copytruncate: live file shrinks → older files' allowance grows →
//     the join must regrow trimmed chunks (byte-identity with the
//     untrimmed-cache behaviour).
// ---------------------------------------------------------------------------

func TestLogTailCacheTrimThenTruncateRegrows(t *testing.T) {
	dir := t.TempDir()
	oldGlob := logGlobPattern
	logGlobPattern = filepath.Join(dir, "bpftune-met-live.log*")
	defer func() { logGlobPattern = oldGlob; resetTailCacheForTest() }()
	resetTailCacheForTest()

	base := time.Now().Add(-time.Hour).Truncate(time.Second)
	perfWriteFile(t, filepath.Join(dir, "bpftune-met-live.log"),
		strings.Repeat("new-line\n", 2000), base.Add(2*time.Minute)) // 16KB
	perfWriteFile(t, filepath.Join(dir, "bpftune-met-live.log.1"),
		strings.Repeat("mid-line\n", 2000), base.Add(time.Minute)) // 16KB

	const budget = 20 * 1024 // < live+mid: mid gets trimmed to ~4KB
	first := readLogTailCached(budget)
	if want := readLogTail(budget); first != want {
		t.Fatalf("cold: got len=%d want len=%d", len(first), len(want))
	}
	tailMu.Lock()
	mid := tailFiles[filepath.Join(dir, "bpftune-met-live.log.1")]
	midLen := len(mid.chunk)
	tailMu.Unlock()
	if midLen >= 16*1024 {
		t.Fatalf("mid chunk not trimmed: %d bytes", midLen)
	}

	// copytruncate: the live log is truncated in place to a tiny file.
	// mid's allowance now covers its full 16KB — the join must regrow.
	perfWriteFile(t, filepath.Join(dir, "bpftune-met-live.log"),
		"tiny\n", base.Add(3*time.Minute))
	second := readLogTailCached(budget)
	if want := readLogTail(budget); second != want {
		t.Fatalf("after truncate: got len=%d want len=%d", len(second), len(want))
	}
	if !strings.Contains(second, strings.Repeat("mid-line\n", 100)) {
		t.Fatal("regrow path did not restore mid-line bytes after truncate")
	}
}

// ---------------------------------------------------------------------------
// 1c. vanished files are purged from the cache
// ---------------------------------------------------------------------------

func TestLogTailCachePurgesVanishedFiles(t *testing.T) {
	dir := t.TempDir()
	oldGlob := logGlobPattern
	logGlobPattern = filepath.Join(dir, "bpftune-met-live.log*")
	defer func() { logGlobPattern = oldGlob; resetTailCacheForTest() }()
	resetTailCacheForTest()

	base := time.Now().Add(-time.Hour).Truncate(time.Second)
	live := filepath.Join(dir, "bpftune-met-live.log")
	old1 := filepath.Join(dir, "bpftune-met-live.log.1")
	perfWriteFile(t, live, strings.Repeat("new\n", 100), base.Add(2*time.Minute))
	perfWriteFile(t, old1, strings.Repeat("old1\n", 100), base.Add(time.Minute))
	readLogTailCached(1 << 20)

	tailMu.Lock()
	_, has := tailFiles[old1]
	tailMu.Unlock()
	if !has {
		t.Fatal("setup: .1 not cached")
	}

	os.Remove(old1)
	readLogTailCached(1 << 20)
	tailMu.Lock()
	_, has = tailFiles[old1]
	n := len(tailFiles)
	tailMu.Unlock()
	if has {
		t.Fatal("vanished file still cached")
	}
	if n != 1 {
		t.Fatalf("cache holds %d entries, want 1 (live only)", n)
	}
}

// ---------------------------------------------------------------------------
// 2. fd close (real fds, raw syscalls — no os.File wrappers, so no
//    finalizer double-close or fd-reuse hazards in the test process)
// ---------------------------------------------------------------------------

func TestCloseMapFDsClosesRealFDs(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "fdsrc")
	if err := os.WriteFile(tmp, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	fds := make([]int, 3)
	for i := range fds {
		fd, err := unix.Open(tmp, unix.O_RDONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		fds[i] = fd
	}
	cachedMapFDs = map[int]int{9001: fds[0], 9002: fds[1], 9003: fds[2]}
	defer func() { cachedMapFDs = map[int]int{} }()

	closeMapFDs()

	if len(cachedMapFDs) != 0 {
		t.Fatalf("cache not emptied: %v", cachedMapFDs)
	}
	for i, fd := range fds {
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != unix.EBADF {
			t.Fatalf("fd %d (index %d) not closed: fstat err=%v", fd, i, err)
		}
	}
}

// ---------------------------------------------------------------------------
// 3. FIFO outcome cache eviction
// ---------------------------------------------------------------------------

func TestOutcomeCacheFIFOEviction(t *testing.T) {
	sustainedOutcomeMu.Lock()
	sustainedOutcomeCache = map[string]string{}
	sustainedOutcomeOrder = nil
	sustainedOutcomeMu.Unlock()
	defer func() {
		sustainedOutcomeMu.Lock()
		sustainedOutcomeCache = map[string]string{}
		sustainedOutcomeOrder = nil
		sustainedOutcomeMu.Unlock()
	}()

	for i := 0; i < 1005; i++ {
		setCachedOutcome(int64(i), float64(i), "win")
	}

	sustainedOutcomeMu.RLock()
	n := len(sustainedOutcomeCache)
	oldestAlive := sustainedOutcomeCache["0:0.000000"]  // first inserted — must be evicted
	fifthAlive := sustainedOutcomeCache["4:4.000000"]   // 5 oldest must be gone
	newest := sustainedOutcomeCache["1004:1004.000000"] // last inserted — must survive
	mid := sustainedOutcomeCache["500:500.000000"]      // middle — must survive
	orderLen := len(sustainedOutcomeOrder)
	sustainedOutcomeMu.RUnlock()

	if n != 1000 || orderLen != 1000 {
		t.Fatalf("cache/order size = %d/%d, want 1000/1000", n, orderLen)
	}
	if oldestAlive != "" || fifthAlive != "" {
		t.Fatalf("FIFO violated: oldest entries survived (%q, %q)", oldestAlive, fifthAlive)
	}
	if newest != "win" || mid != "win" {
		t.Fatalf("recent entries evicted: newest=%q mid=%q", newest, mid)
	}

	// Re-setting an existing key must not grow the order slice.
	setCachedOutcome(1004, 1004, "loss")
	sustainedOutcomeMu.RLock()
	orderLen = len(sustainedOutcomeOrder)
	val := sustainedOutcomeCache["1004:1004.000000"]
	sustainedOutcomeMu.RUnlock()
	if orderLen != 1000 {
		t.Fatalf("order slice grew on re-set: %d", orderLen)
	}
	if val != "loss" {
		t.Fatalf("re-set did not update value: %q", val)
	}
}
