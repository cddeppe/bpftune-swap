package main

// label_persist_test.go — LABEL-SANDBOX-1 regression suite.
//
// Simulates the EXACT scenario the user hits: add a label via the UI's
// POST /api/labels handler, then simulate a dashboard restart, then
// verify the label is still there.
//
// Prior isolated tests (TestLabelsPersistAcrossSaveAndLoad,
// TestLabelsPersistViaHTTPHandler, TestLabelsPersistUnderConcurrentLoad
// in regression_test.go) all PASS — yet the user still loses labels
// after restart in production. The bug must be in a code path those
// tests don't exercise. This file adds six new scenarios:
//
//   1. TestLabelPersistsAcrossSimulatedRestart
//      Mimics main.go:454-493 POST flow exactly, then resets the
//      labelsHolder cache (mirrors a fresh process), then verifies
//      loadLabels() returns the new label.
//
//   2. TestLabelPOSTMultipleIPsSequentially
//      User moves 5 different IPs to buckets, one POST at a time
//      (rapid UI clicks, no restart between them). Verifies all 5
//      land on disk.
//
//   3. TestLabelPOSTConcurrentRaceCondition
//      10 concurrent POSTs (Promise.all-style). Catches concurrent
//      map read+write races between saveLabels's json.MarshalIndent
//      and the labelsHolder cache mutation.
//
//   4. TestLabelPOSTAfterPreExistingLoad
//      Cache is populated by an earlier loadLabels() (e.g. from the
//      COLLECT pipeline), THEN a POST adds a new label. Verifies the
//      new label is saved alongside existing ones.
//
//   5. TestLabelPOSTWithin30sTTLWindow
//      v0.9.96 added a 30s TTL to mtimeCache.get (MEMFIX-1 Fix 3).
//      Test that 5 rapid POSTs within the 30s TTL window don't lose
//      data — loadLabels() returns the cached (already-mutated) map.
//
//   6. TestLabelDoesNotDisappearFromStaleCache
//      Specific scenario where the cache might return stale data
//      after saveLabels. Loads {A,B,C:bucket1}, POSTs A=bucket2,
//      POSTs B=bucket3, verifies disk has A=bucket2, B=bucket3,
//      C=bucket1.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// resetLabelsHolderCache zeroes the package-level labelsHolder so the
// next loadLabels() call is a guaranteed cache miss (mirrors a freshly-
// started dashboard process where the mtimeCache struct is zero-valued).
func resetLabelsHolderCache() {
	labelsHolder.mu.Lock()
	labelsHolder.val = nil
	labelsHolder.mtime = time.Time{}
	labelsHolder.lastStat = time.Time{}
	labelsHolder.mu.Unlock()
}

// pointLabelsFileAtTemp redirects the package-level labelsFile var at
// a temp file and returns a restorer func (call via defer). All
// saveLabels/loadLabels calls then read/write the temp file.
func pointLabelsFileAtTemp(t *testing.T, path string) func() {
	t.Helper()
	old := labelsFile
	labelsFile = path
	return func() { labelsFile = old }
}

// writeInitialLabels marshals m to disk at path with 2-space indent
// (mirrors saveLabels's format).
func writeInitialLabels(t *testing.T, path string, m map[string]string) {
	t.Helper()
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatalf("marshal initial labels: %v", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write initial labels %s: %v", path, err)
	}
}

// readDiskLabels reads+unmarshals path into a fresh map. Fatal on error.
func readDiskLabels(t *testing.T, path string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal %s: %v (raw=%.300s)", path, err, string(raw))
	}
	if m == nil {
		m = map[string]string{}
	}
	return m
}

// ----------------------------------------------------------------------------
// Test 1: TestLabelPersistsAcrossSimulatedRestart
// ----------------------------------------------------------------------------

// TestLabelPersistsAcrossSimulatedRestart mimics main.go:454-493 POST
// /api/labels flow exactly: canonicalize IP -> loadLabels -> mutate ->
// saveLabels. Then resets the labelsHolder cache (mirrors a fresh
// process), calls loadLabels() again, and asserts the new label AND
// all pre-existing labels are returned.
func TestLabelPersistsAcrossSimulatedRestart(t *testing.T) {
	tmpDir := t.TempDir()
	labelsPath := filepath.Join(tmpDir, "aliases.labels.json")
	defer pointLabelsFileAtTemp(t, labelsPath)()

	// Seed the file with labels the user says DO persist (the kind
	// that already survived a prior restart).
	initialLabels := map[string]string{
		"76.76.2.0":  "vps-us",
		"76.76.10.0": "vps-us",
	}
	writeInitialLabels(t, labelsPath, initialLabels)

	// === SIMULATE POST /api/labels (main.go:454-493) ===
	ip := "104.18.0.0"
	label := "home-sco"

	// Fresh process = zero-valued mtimeCache.
	resetLabelsHolderCache()

	// 1. (Read request body — skipped, we have ip+label directly.)
	// 2. Canonicalize IP (main.go:463).
	ip = canonBucketWithPrefix(ip, prefix4Value(), prefix6Value())
	// 3. Load labels (main.go:465).
	labels := loadLabels()
	// 4. Modify (main.go:469).
	labels[ip] = label
	// 5. Save (main.go:471).
	saveLabels(labels)

	// === VERIFY file was written correctly ===
	disk := readDiskLabels(t, labelsPath)
	if disk[ip] != label {
		t.Errorf("after saveLabels, disk has %s=%q, want %q", ip, disk[ip], label)
	}
	if disk["76.76.2.0"] != "vps-us" {
		t.Errorf("after saveLabels, existing label 76.76.2.0=%q, want vps-us", disk["76.76.2.0"])
	}

	// === SIMULATE RESTART ===
	resetLabelsHolderCache()

	// (initSQLite / ensureSystemHealth / ensureCookieDestLoaded at
	// startup are no-ops for labels — they don't touch labelsHolder.)

	// === VERIFY loadLabels returns the new label after restart ===
	loaded := loadLabels()
	if loaded[ip] != label {
		t.Errorf("after restart, loadLabels returned %s=%q, want %q", ip, loaded[ip], label)
	}
	if loaded["76.76.2.0"] != "vps-us" {
		t.Errorf("after restart, existing label 76.76.2.0=%q, want vps-us", loaded["76.76.2.0"])
	}
	if len(loaded) != 3 {
		t.Errorf("after restart, loadLabels count=%d, want 3 (2 existing + 1 new); got %v", len(loaded), loaded)
	}
	t.Logf("PersistsAcrossSimulatedRestart: %d labels survived restart (incl new %q=%q)", len(loaded), ip, label)
}

// ----------------------------------------------------------------------------
// Test 2: TestLabelPOSTMultipleIPsSequentially
// ----------------------------------------------------------------------------

// TestLabelPOSTMultipleIPsSequentially simulates the user moving 5
// different IPs to buckets, one POST at a time (rapid UI clicks, no
// restart between them). The labelsHolder cache is populated by the
// first POST; subsequent POSTs hit the cache and mutate the SAME
// in-memory map. Verifies all 5 labels land on disk.
func TestLabelPOSTMultipleIPsSequentially(t *testing.T) {
	tmpDir := t.TempDir()
	labelsPath := filepath.Join(tmpDir, "aliases.labels.json")
	defer pointLabelsFileAtTemp(t, labelsPath)()

	// Start with empty labels file.
	writeInitialLabels(t, labelsPath, map[string]string{})
	resetLabelsHolderCache()

	posts := []struct{ ip, label string }{
		{"1.2.3.0", "bucket-a"},
		{"5.6.7.0", "bucket-b"},
		{"9.10.11.0", "bucket-c"},
		{"13.14.15.0", "bucket-a"},
		{"17.18.19.0", "bucket-b"},
	}

	// Simulate 5 sequential POSTs (rapid UI clicks, no sleep).
	for _, p := range posts {
		ip := canonBucketWithPrefix(p.ip, prefix4Value(), prefix6Value())
		labels := loadLabels()
		labels[ip] = p.label
		saveLabels(labels)
	}

	// Verify ALL 5 are in the file.
	disk := readDiskLabels(t, labelsPath)
	for _, p := range posts {
		ip := canonBucketWithPrefix(p.ip, prefix4Value(), prefix6Value())
		if disk[ip] != p.label {
			t.Errorf("after 5 sequential POSTs, disk has %s=%q, want %q (full disk=%v)", ip, disk[ip], p.label, disk)
		}
	}
	if len(disk) != 5 {
		t.Errorf("after 5 sequential POSTs, disk has %d entries, want 5 (full disk=%v)", len(disk), disk)
	}
	t.Logf("POSTMultipleIPsSequentially: all 5 labels persisted (disk=%v)", disk)
}

// ----------------------------------------------------------------------------
// Test 3: TestLabelPOSTConcurrentRaceCondition
// ----------------------------------------------------------------------------

// TestLabelPOSTConcurrentRaceCondition simulates CONCURRENT POSTs
// (multiple in-flight at once, like Promise.all in JS). 10 goroutines
// each POST a different IP. Each goroutine calls loadLabels() -> mutate
// -> saveLabels(). Since loadLabels() returns the SAME cached map
// reference (c.val), all 10 goroutines mutate the SAME map AND
// json.MarshalIndent iterates that map — classic concurrent map
// read+write race. May panic, may silently produce partial JSON, may
// drop entries. Asserts all 10 land on disk.
func TestLabelPOSTConcurrentRaceCondition(t *testing.T) {
	tmpDir := t.TempDir()
	labelsPath := filepath.Join(tmpDir, "aliases.labels.json")
	defer pointLabelsFileAtTemp(t, labelsPath)()

	writeInitialLabels(t, labelsPath, map[string]string{})
	resetLabelsHolderCache()

	const N = 10
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			ip := fmt.Sprintf("%d.0.0.0", n+1)
			ip = canonBucketWithPrefix(ip, prefix4Value(), prefix6Value())
			labels := loadLabels()
			labels[ip] = fmt.Sprintf("bucket-%d", n)
			saveLabels(labels)
		}(i)
	}
	wg.Wait()

	// Verify — how many labels are actually on disk?
	disk := readDiskLabels(t, labelsPath)
	t.Logf("after %d concurrent POSTs, disk has %d labels (expected %d): %v", N, len(disk), N, disk)
	if len(disk) < N {
		t.Errorf("RACE CONDITION: only %d of %d concurrent POSTs persisted (disk=%v)", len(disk), N, disk)
	}
	// Spot-check a couple of entries.
	for _, n := range []int{0, 5, 9} {
		ip := canonBucketWithPrefix(fmt.Sprintf("%d.0.0.0", n+1), prefix4Value(), prefix6Value())
		want := fmt.Sprintf("bucket-%d", n)
		if disk[ip] != want {
			t.Errorf("concurrent POST: disk has %s=%q, want %q", ip, disk[ip], want)
		}
	}
}

// ----------------------------------------------------------------------------
// Test 4: TestLabelPOSTAfterPreExistingLoad
// ----------------------------------------------------------------------------

// TestLabelPOSTAfterPreExistingLoad simulates: COLLECT pipeline (or
// another HTTP request) calls loadLabels() first, populating the
// cache. THEN a POST adds a new label. Verifies the new label is saved
// alongside the existing ones (i.e., the cache's pre-existing state
// doesn't cause data loss).
func TestLabelPOSTAfterPreExistingLoad(t *testing.T) {
	tmpDir := t.TempDir()
	labelsPath := filepath.Join(tmpDir, "aliases.labels.json")
	defer pointLabelsFileAtTemp(t, labelsPath)()

	initial := map[string]string{
		"1.1.1.0": "existing-a",
		"2.2.2.0": "existing-b",
	}
	writeInitialLabels(t, labelsPath, initial)
	resetLabelsHolderCache()

	// 1. Load labels first (populates cache, mirroring a prior
	//    longestPrefixLabel call from the COLLECT pipeline).
	_ = loadLabels()

	// 2. POST a new label.
	ip := canonBucketWithPrefix("99.99.99.0", prefix4Value(), prefix6Value())
	labels := loadLabels()
	labels[ip] = "new-bucket"
	saveLabels(labels)

	// 3. Verify existing + new are both on disk.
	disk := readDiskLabels(t, labelsPath)
	if disk[ip] != "new-bucket" {
		t.Errorf("after POST, disk has %s=%q, want new-bucket (disk=%v)", ip, disk[ip], disk)
	}
	if disk["1.1.1.0"] != "existing-a" {
		t.Errorf("after POST, existing label 1.1.1.0=%q, want existing-a (disk=%v)", disk["1.1.1.0"], disk)
	}
	if disk["2.2.2.0"] != "existing-b" {
		t.Errorf("after POST, existing label 2.2.2.0=%q, want existing-b (disk=%v)", disk["2.2.2.0"], disk)
	}
	if len(disk) != 3 {
		t.Errorf("after POST, disk has %d entries, want 3 (disk=%v)", len(disk), disk)
	}
	t.Logf("POSTAfterPreExistingLoad: existing + new persisted (disk=%v)", disk)
}

// ----------------------------------------------------------------------------
// Test 5: TestLabelPOSTWithin30sTTLWindow
// ----------------------------------------------------------------------------

// TestLabelPOSTWithin30sTTLWindow exercises the v0.9.96 mtimeCache
// 30s TTL (MEMFIX-1 Fix 3). After the first loadLabels() populates
// the cache, subsequent loadLabels() calls within 30s return the
// cached val (without re-stat'ing the file). 5 rapid POSTs, each
// within 30s of the previous. Verifies all 5 land on disk.
//
// This catches the regression where saveLabels writes the file but
// the cache's `mtime` field isn't updated, so a stale cache could
// theoretically return the pre-mutation map. (In practice, the cache
// returns the SAME map reference that the POST handler just mutated,
// so this should pass — but we lock it in.)
func TestLabelPOSTWithin30sTTLWindow(t *testing.T) {
	tmpDir := t.TempDir()
	labelsPath := filepath.Join(tmpDir, "aliases.labels.json")
	defer pointLabelsFileAtTemp(t, labelsPath)()

	initial := map[string]string{
		"50.50.50.0": "anchor",
	}
	writeInitialLabels(t, labelsPath, initial)
	resetLabelsHolderCache()

	// 1. Load labels (populates cache, starts TTL).
	_ = loadLabels()

	// 2. POST 5 new labels, each within 30s of the previous.
	for i := 0; i < 5; i++ {
		ip := canonBucketWithPrefix(fmt.Sprintf("%d.0.0.0", i+100), prefix4Value(), prefix6Value())
		labels := loadLabels() // within TTL — returns cached val
		labels[ip] = "new"
		saveLabels(labels)
		// No sleep — within TTL window.
	}

	// 3. Verify all 5 are on disk (plus the anchor).
	disk := readDiskLabels(t, labelsPath)
	if disk["50.50.50.0"] != "anchor" {
		t.Errorf("after 5 TTL-window POSTs, anchor 50.50.50.0=%q, want anchor (disk=%v)", disk["50.50.50.0"], disk)
	}
	for i := 0; i < 5; i++ {
		ip := canonBucketWithPrefix(fmt.Sprintf("%d.0.0.0", i+100), prefix4Value(), prefix6Value())
		if disk[ip] != "new" {
			t.Errorf("after 5 TTL-window POSTs, disk has %s=%q, want new (disk=%v)", ip, disk[ip], disk)
		}
	}
	if len(disk) != 6 {
		t.Errorf("after 5 TTL-window POSTs, disk has %d entries, want 6 (disk=%v)", len(disk), disk)
	}
	t.Logf("POSTWithin30sTTLWindow: all 5 TTL-window POSTs persisted (disk=%v)", disk)
}

// ----------------------------------------------------------------------------
// Test 6: TestLabelDoesNotDisappearFromStaleCache
// ----------------------------------------------------------------------------

// TestLabelDoesNotDisappearFromStaleCache tests the SPECIFIC scenario
// where the cache might return stale data after saveLabels.
//
// Setup: {A: bucket1, B: bucket1, C: bucket1} on disk.
//  1. loadLabels() populates cache with {A, B, C}.
//  2. POST: change A to bucket2 (modifies the cached map + writes
//     the modified map to disk).
//  3. POST: change B to bucket3. This is where the bug fires if
//     loadLabels() returns a stale cached map (missing A=bucket2)
//     — the second saveLabels would write {A: bucket1, B: bucket3,
//     C: bucket1}, LOSING the A=bucket2 change.
//  4. Verify disk has A=bucket2, B=bucket3, C=bucket1.
func TestLabelDoesNotDisappearFromStaleCache(t *testing.T) {
	tmpDir := t.TempDir()
	labelsPath := filepath.Join(tmpDir, "aliases.labels.json")
	defer pointLabelsFileAtTemp(t, labelsPath)()

	initial := map[string]string{
		"A": "bucket1",
		"B": "bucket1",
		"C": "bucket1",
	}
	writeInitialLabels(t, labelsPath, initial)
	resetLabelsHolderCache()

	// 1. Load labels (populates cache with {A, B, C}).
	got := loadLabels()
	t.Logf("initial labels: %v", got)

	// 2. POST: change A to bucket2.
	got["A"] = "bucket2"
	saveLabels(got)

	// 3. POST: change B to bucket3 (this is where the bug fires
	//    if the cache is stale).
	labels := loadLabels()
	t.Logf("labels after 2nd loadLabels: %v", labels)
	if labels["A"] != "bucket2" {
		t.Errorf("STALE CACHE: loadLabels returned A=%q after saveLabels set A=bucket2 (labels=%v)", labels["A"], labels)
	}
	labels["B"] = "bucket3"
	saveLabels(labels)

	// 4. Verify disk has: A=bucket2, B=bucket3, C=bucket1.
	disk := readDiskLabels(t, labelsPath)
	if disk["A"] != "bucket2" {
		t.Errorf("after 2nd POST, disk lost A=bucket2 (got %q; full disk=%v)", disk["A"], disk)
	}
	if disk["B"] != "bucket3" {
		t.Errorf("after 2nd POST, disk has B=%q, want bucket3 (full disk=%v)", disk["B"], disk)
	}
	if disk["C"] != "bucket1" {
		t.Errorf("after 2nd POST, disk lost C=bucket1 (got %q; full disk=%v)", disk["C"], disk)
	}
	t.Logf("DoesNotDisappearFromStaleCache: A=bucket2, B=bucket3, C=bucket1 all on disk (disk=%v)", disk)
}
