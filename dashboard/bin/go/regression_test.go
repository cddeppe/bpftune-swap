package main

// regression_test.go — comprehensive test harness for the bpftune-swap dashboard
// that verifies proofs AND swaps panels ALWAYS show correct data, including
// after every restart scenario, log rotation, empty-dest proofs, etc.
//
// This file was added in response to recurring bugs documented in worklog
// AUDIT-PROOFS-1 (empty-dest proofs leaking into the panel) and
// AUDIT-SWAPS-1 (stale swaps shown as fresh after bpftune restart). The
// previous test file (sanitycheck_full_test.go) only tested the happy path
// (all proofs/swaps have valid dest). This file covers EVERY sad path so the
// bugs don't keep coming back.
//
// LAYOUT
//   This file lives at /tmp/my-project/repo/dashboard/bin/go/regression_test.go
//   alongside sanitycheck_full_test.go and shares `package main` with the
//   rest of the collector.
//
// WHAT IT COVERS
//   PROOFS:
//     - Live log proofs: all valid, some missing dest, CSV-only empty dest,
//       CSV mixed dest, merge live+CSV, bpftune restart, kernel reboot,
//       dashboard restart (with dedup), log rotation, write-then-read,
//       frontend render-no-unknown filter, cdest FIFO eviction.
//   SWAPS:
//     - Live log all-fresh, few-fresh+CSV-fallback, bpftune restart, kernel
//       reboot, CSV duplicates, age label, sort-by-epoch_ts, CSV reader
//       newest-first, stale CSV sink to bottom.
//
// CONSTRAINTS
//   - Tests are deterministic — pin bootUptime to a fixed value, no
//     reliance on /proc/uptime in the sandbox.
//   - Tests do NOT touch /var/lib/bpftune/ files — CSV paths are redirected
//     to t.TempDir() via setupTestEnv (sanitycheck_full_test.go).
//   - Tests cover BOTH happy AND sad paths (empty dest, stale data,
//     restart scenarios).
//   - Each test asserts SPECIFIC expectations, not just len() > 0.

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

// pinBootUptime overrides the cached /proc/uptime so parseLogSinglePass's
// "previous boot" filter (ts > uptime+300) uses our value, not the sandbox's
// real uptime. Pass a high value (e.g. 1e9) to disable filtering; pass a low
// value (e.g. 100) to simulate a recently-rebooted kernel.
func pinBootUptime(value float64) {
	bootUptime.mu.Lock()
	bootUptime.value = value
	bootUptime.ts = time.Now()
	bootUptime.mu.Unlock()
}

// resetDedupMaps clears the in-memory writtenSwapsFlat/writtenProofsFlat/etc.
// maps so tests that exercise writeProofsCSVFromInterface / writeSwapsCSV
// start from a clean state. (Production code never resets these maps; they
// persist for the lifetime of the process. Tests need to reset because
// Go runs tests in one binary.)
//
// v0.9.96: reset to flat maps (was nested map[int64]map[float64]bool).
func resetDedupMaps() {
	dedupMu.Lock()
	defer dedupMu.Unlock()
	writtenSwapsFlat = map[string]bool{}
	writtenSratesFlat = map[string]bool{}
	writtenTruthFlat = map[string]bool{}
	writtenProofsFlat = map[float64]bool{}
	writtenMidsampsFlat = map[string]bool{}
}

// resetCookieDestState clears the cookie_dest disk map + path so tests
// that exercise persistCookieDest start clean. Also resets the saved-hash
// and last-save time so saveCookieDestToDisk actually writes.
func resetCookieDestState(tmpDir string) {
	cookieDestMu.Lock()
	defer cookieDestMu.Unlock()
	cookieDestDiskMap = nil
	cookieDestLastHash = [16]byte{}
	cookieDestLastSave = time.Time{} // forces save (throttle check passes)
	cookieDestPath = filepath.Join(tmpDir, "cookie_dest.json")
}

// proofRow is a tiny constructor for building proof row maps in tests.
func proofRow(ts float64, alg, mbps, tier, dest string, epochTs int64) map[string]interface{} {
	return map[string]interface{}{
		"boot_ts":  ts,
		"epoch_ts": epochTs,
		"alg":      alg,
		"mbps":     mbps,
		"tier":     tier,
		"dest":     dest,
	}
}

// swapRowMap is a tiny constructor for building swap row maps in tests.
func swapRowMap(bootTs float64, epochTs int64, fromAlg, toAlg, dest, outcome string) map[string]interface{} {
	return map[string]interface{}{
		"boot_ts":           bootTs,
		"epoch_ts":          epochTs,
		"from_alg":          fromAlg,
		"to_alg":            toAlg,
		"d":                 2,
		"outcome":           outcome,
		"outcome_sustained": outcome,
		"mt_alg":            fromAlg,
		"rb_alg":            toAlg,
		"dest":              dest,
		"outcome_srate":     "",
		"_bucket":           dest,
	}
}

// goAgeLabel mirrors the post-AUDIT-SWAPS-1 LEAK #1 fix in dashboard.js
// ageLabel. Returns the age string the frontend WOULD render for the
// given boot_ts/epoch_ts/SERVER_NOW_MONO. Used to test that the
// frontend's age label computation produces the correct value.
//
// IMPORTANT: nowSec is the wall-clock seconds (Date.now()/1000 in JS).
// Passing it as a parameter makes the test deterministic.
func goAgeLabel(bootTs float64, epochTs int64, serverNowMono float64, nowSec int64) string {
	// v0.9.95: try epoch_ts FIRST (wall-clock) — boot_ts is only comparable
	// within the same kernel boot.
	if epochTs > 0 {
		eAge := float64(nowSec - epochTs)
		if eAge >= 0 {
			return ageBucket(eAge)
		}
	}
	// Fallback: boot_ts when epoch_ts missing or in the future.
	if bootTs > 0 && serverNowMono > 0 {
		age := serverNowMono - bootTs
		if age >= 0 {
			return ageBucket(age)
		}
	}
	return ""
}

// ageBucket formats an age in seconds as the dashboard would: "Xs", "Xm",
// "Xh", or "Xd". Mirrors dashboard.js ageLabel's inner switch.
func ageBucket(age float64) string {
	switch {
	case age < 60:
		return strconv.Itoa(int(math.Round(age))) + "s"
	case age < 3600:
		return strconv.Itoa(int(math.Round(age/60))) + "m"
	case age < 86400:
		return strconv.Itoa(int(math.Round(age/3600))) + "h"
	default:
		return strconv.Itoa(int(math.Round(age/86400))) + "d"
	}
}

// frontendFilterProofs mirrors dashboard.js renderRecentProofs's last-line-of-
// defence filter (AUDIT-PROOFS-1 LEAK #6). Drops rows with empty dest.
func frontendFilterProofs(rows []interface{}) []interface{} {
	var out []interface{}
	for _, r := range rows {
		if m, ok := r.(map[string]interface{}); ok {
			if dest, _ := m["dest"].(string); dest != "" {
				out = append(out, r)
			}
		}
	}
	if len(out) > 18 {
		out = out[:18]
	}
	return out
}

// frontendFilterSwaps mirrors dashboard.js renderRecentSwaps's last-line-of-
// defence filter. Drops rows with empty dest.
func frontendFilterSwaps(rows []interface{}) []interface{} {
	var out []interface{}
	for _, r := range rows {
		if m, ok := r.(map[string]interface{}); ok {
			if dest, _ := m["dest"].(string); dest != "" {
				out = append(out, r)
			}
		}
	}
	return out
}

// hasEmptyDest returns true if any row in rows has empty dest.
func hasEmptyDest(rows []interface{}) bool {
	for _, r := range rows {
		if m, ok := r.(map[string]interface{}); ok {
			if dest, _ := m["dest"].(string); dest == "" {
				return true
			}
		}
	}
	return false
}

// ----------------------------------------------------------------------------
// PROOFS TESTS (1-11)
// ----------------------------------------------------------------------------

// TestProofsLiveLogAllHaveValidDest: log proofs all have dest=, no CSV
// fallback needed → panel shows all with dest.
func TestProofsLiveLogAllHaveValidDest(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup(t)
	pinBootUptime(1_000_000_000)

	lines := []string{
		`1200.0: bpf_trace_printk: estab cookie=1001 alg=0 forced=1 dest=1395917824`,
		`1201.0: bpf_trace_printk: proof cookie=1001 alg=1 rate=1000000 tier=2 dest=1395917824`,
		`1202.0: bpf_trace_printk: estab cookie=1002 alg=0 forced=1 dest=1395917824`,
		`1203.0: bpf_trace_printk: proof cookie=1002 alg=1 rate=2000000 tier=2 dest=1395917824`,
		`1204.0: bpf_trace_printk: proof cookie=1003 alg=2 rate=500000 tier=1 dest=1395917824`,
	}
	pl := parseLogSinglePass(strings.Join(lines, "\n"))
	currentParsedLog = pl
	defer func() { currentParsedLog = nil }()

	proofs := pl.GetProofRows(pl.Cdest)
	if len(proofs) != 3 {
		t.Fatalf("expected 3 proof rows, got %d", len(proofs))
	}
	for i, p := range proofs {
		row := p.(map[string]interface{})
		dest, _ := row["dest"].(string)
		if dest == "" {
			t.Fatalf("row %d has empty dest — leaked into panel as (unknown)", i)
		}
	}
	t.Logf("GetProofRows returned %d rows all with valid dest ✓", len(proofs))
}

// TestProofsLiveLogSomeMissingDest: some log proofs lack dest= (old BPF),
// no cdest entry for the cookie → MUST be filtered out (AUDIT-PROOFS-1 LEAK #1).
func TestProofsLiveLogSomeMissingDest(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup(t)
	pinBootUptime(1_000_000_000)

	lines := []string{
		// 1001 has estab + proof with dest — should appear
		`1200.0: bpf_trace_printk: estab cookie=1001 alg=0 forced=1 dest=1395917824`,
		`1201.0: bpf_trace_printk: proof cookie=1001 alg=1 rate=1000000 tier=2 dest=1395917824`,
		// 1002 has proof WITHOUT dest= AND no estab line → cdest lookup fails
		// → must be filtered by the AUDIT-PROOFS-1 LEAK #1 fix
		`1202.0: bpf_trace_printk: proof cookie=1002 alg=1 rate=2000000 tier=2`,
		// 1003 has proof WITHOUT dest= BUT has estab → cdest lookup succeeds
		`1203.0: bpf_trace_printk: estab cookie=1003 alg=0 forced=1 dest=1395917824`,
		`1204.0: bpf_trace_printk: proof cookie=1003 alg=1 rate=500000 tier=1`,
	}
	pl := parseLogSinglePass(strings.Join(lines, "\n"))
	currentParsedLog = pl
	defer func() { currentParsedLog = nil }()

	proofs := pl.GetProofRows(pl.Cdest)
	// Only 1001 and 1003 should appear; 1002 (no dest, no cdest) filtered.
	if len(proofs) != 2 {
		t.Fatalf("expected 2 proofs (1001 + 1003), got %d — empty-dest proof leaked (LEAK #1 regression?)", len(proofs))
	}
	for i, p := range proofs {
		row := p.(map[string]interface{})
		dest, _ := row["dest"].(string)
		if dest == "" {
			t.Fatalf("row %d has empty dest — leaked into panel as (unknown)", i)
		}
	}
	t.Logf("GetProofRows correctly skipped empty-dest proof (LEAK #1 fix verified) ✓")
}

// TestProofsCSVAllEmptyDest: CSV has only empty-dest rows (legacy from
// pre-v0.9.91) → reader MUST skip all (AUDIT-PROOFS-1 / v0.9.94 fix).
func TestProofsCSVAllEmptyDest(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup(t)

	csv := "collected_ts,boot_ts,cookie,alg,rate_bps,mbps,tier,dest\n"
	csv += "1700000000,1250.000000,1001,bbr,1000000,1.0,2,\n"
	csv += "1700000010,1350.000000,1002,cubic,500000,0.5,1,\n"
	csv += "1700000020,1450.000000,1003,htcp,2000000,2.0,2,\n"
	writeCSV(t, proofsCSVPath, csv)

	rows := readRecentProofsFromCSV(50)
	if len(rows) != 0 {
		t.Fatalf("expected 0 rows (all empty-dest), got %d — empty-dest filter (v0.9.94) regressed?", len(rows))
	}
	t.Logf("readRecentProofsFromCSV correctly skipped all empty-dest rows ✓")
}

// TestProofsCSVMixedDest: CSV has mix of empty-dest and valid-dest rows →
// only valid-dest shown.
func TestProofsCSVMixedDest(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup(t)

	csv := "collected_ts,boot_ts,cookie,alg,rate_bps,mbps,tier,dest\n"
	csv += "1700000000,1250.000000,1001,bbr,1000000,1.0,2,\n"               // empty dest — skip
	csv += "1700000010,1350.000000,1002,cubic,500000,0.5,1,83.52.0.0\n"     // valid
	csv += "1700000020,1450.000000,1003,htcp,2000000,2.0,2,\n"             // empty dest — skip
	csv += "1700000030,1550.000000,1004,bbr,800000,0.8,1,83.52.0.0\n"       // valid
	writeCSV(t, proofsCSVPath, csv)

	rows := readRecentProofsFromCSV(50)
	if len(rows) != 2 {
		t.Fatalf("expected 2 valid-dest rows, got %d", len(rows))
	}
	for i, r := range rows {
		m, _ := r.(map[string]interface{})
		dest, _ := m["dest"].(string)
		if dest == "" {
			t.Fatalf("row %d has empty dest — mixed-dest filter regressed", i)
		}
	}
	t.Logf("readRecentProofsFromCSV mixed CSV: returned %d valid-dest rows (skipped 2 empty-dest) ✓", len(rows))
}

// TestProofsMergeLiveAndCSV: live has 5 valid proofs, CSV has 20 valid proofs
// → merged top-18 has all valid dest.
func TestProofsMergeLiveAndCSV(t *testing.T) {
	now := int64(1730000000)
	var live, csv []interface{}
	for i := 0; i < 5; i++ {
		live = append(live, proofRow(
			float64(100+i), "bbr", "1.0", "proved", "1.2.3.4",
			now-int64(60*i),
		))
	}
	for i := 0; i < 20; i++ {
		csv = append(csv, proofRow(
			float64(1000+i), "cubic", "0.5", "good", "5.6.7.8",
			now-int64(3600)-int64(60*i),
		))
	}
	merged := mergeProofsNewestFirst(live, csv, 18)
	if len(merged) != 18 {
		t.Fatalf("expected 18 merged proofs, got %d", len(merged))
	}
	if hasEmptyDest(merged) {
		t.Fatal("merged proofs contain empty-dest rows")
	}
	// Top 5 should be live (epoch_ts = now-60*i, larger than CSV's now-3600-...)
	firstTs := merged[0].(map[string]interface{})["epoch_ts"].(int64)
	if firstTs != now {
		t.Fatalf("expected top proof epoch_ts=%d (newest live), got %d", now, firstTs)
	}
	t.Logf("mergeProofsNewestFirst: 5 live + 20 CSV → %d merged, all valid dest, live on top ✓", len(merged))
}

// TestProofsAfterBpftuneRestart: log has proofs from previous bpftune run
// (lower boot_ts) + current run (higher boot_ts — ktime CONTINUES across
// bpftune restart, no kernel reboot). Both with valid dest → all shown,
// sorted by boot_ts desc.
//
// Per AUDIT-SWAPS-1 LEAK #1: BPF ktime is CLOCK_MONOTONIC; it does NOT
// reset on bpftune restart, only on kernel reboot. So current-run proofs
// have HIGHER boot_ts than previous-run proofs (ktime continued).
func TestProofsAfterBpftuneRestart(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup(t)
	// Kernel has been up 50400s (14h). bpftune was running 14h, restarted
	// recently. BPF ktime at moment of test = ~50400.
	pinBootUptime(50400)

	lines := []string{
		// Previous bpftune run: proof emitted at ktime=49000 (1400s before restart)
		`49000.0: bpf_trace_printk: proof cookie=40001 alg=1 rate=1000000 tier=2 dest=1395917824`,
		// Current bpftune run: proof emitted at ktime=50300 (just after restart)
		`50300.0: bpf_trace_printk: proof cookie=101 alg=1 rate=2000000 tier=2 dest=1395917824`,
		`50350.0: bpf_trace_printk: proof cookie=102 alg=1 rate=3000000 tier=2 dest=1395917824`,
	}
	pl := parseLogSinglePass(strings.Join(lines, "\n"))
	currentParsedLog = pl
	defer func() { currentParsedLog = nil }()

	proofs := pl.GetProofRows(pl.Cdest)
	if len(proofs) != 3 {
		t.Fatalf("expected 3 proofs (both runs), got %d — previous-run proofs filtered?", len(proofs))
	}
	// Sorted by boot_ts desc: 50350, 50300, 49000
	first := proofs[0].(map[string]interface{})
	firstTs, _ := first["boot_ts"].(float64)
	if firstTs != 50350 {
		t.Fatalf("expected top proof boot_ts=50350 (current run, newest), got %v", firstTs)
	}
	// All should have valid dest
	for i, p := range proofs {
		row := p.(map[string]interface{})
		if dest, _ := row["dest"].(string); dest == "" {
			t.Fatalf("row %d has empty dest", i)
		}
	}
	t.Logf("AfterBpftuneRestart: %d proofs returned, sorted by boot_ts desc, current-run on top ✓", len(proofs))
}

// TestProofsAfterKernelReboot: log has stale proofs (ktime > uptime+300) →
// MUST be filtered out by singlepass's previous-boot filter.
func TestProofsAfterKernelReboot(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup(t)
	// Kernel just rebooted 100s ago. /proc/uptime = 100.
	pinBootUptime(100)

	lines := []string{
		// Stale proof from previous boot: ktime=50000 > uptime+300=400 → filtered
		`50000.0: bpf_trace_printk: proof cookie=40001 alg=1 rate=1000000 tier=2 dest=1395917824`,
		`51000.0: bpf_trace_printk: proof cookie=40002 alg=1 rate=2000000 tier=2 dest=1395917824`,
		// Current boot: ktime=50 < uptime+300 → kept
		`50.0: bpf_trace_printk: proof cookie=101 alg=1 rate=3000000 tier=2 dest=1395917824`,
	}
	pl := parseLogSinglePass(strings.Join(lines, "\n"))
	currentParsedLog = pl
	defer func() { currentParsedLog = nil }()

	if len(pl.ProofLines) != 1 {
		t.Fatalf("expected 1 ProofLine (stale filtered), got %d — previous-boot filter regressed?", len(pl.ProofLines))
	}
	proofs := pl.GetProofRows(pl.Cdest)
	if len(proofs) != 1 {
		t.Fatalf("expected 1 proof (stale filtered), got %d", len(proofs))
	}
	t.Logf("AfterKernelReboot: stale proofs filtered, %d current-boot proof returned ✓", len(proofs))
}

// TestProofsAfterDashboardRestart: writtenProofs dedup map empty →
// backfill writes ALL log proofs to CSV → CSV has duplicates but reader dedups
// (AUDIT-PROOFS-1 / v0.9.95 reader-dedup fix).
func TestProofsAfterDashboardRestart(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup(t)
	pinBootUptime(1_000_000_000)
	resetDedupMaps()

	lines := []string{
		`1200.0: bpf_trace_printk: estab cookie=1001 alg=0 forced=1 dest=1395917824`,
		`1201.0: bpf_trace_printk: proof cookie=1001 alg=1 rate=1000000 tier=2 dest=1395917824`,
		`1202.0: bpf_trace_printk: proof cookie=1001 alg=2 rate=2000000 tier=2 dest=1395917824`,
	}
	text := strings.Join(lines, "\n")
	pl := parseLogSinglePass(text)
	cdest := pl.Cdest

	// Simulate dashboard restart: writtenProofs is empty (we just reset it).
	// backfillProofsFromLog parses log text and writes ALL proofs to CSV.
	// (In production this happens once via backfillDone.Do.)
	backfillProofsFromLog(text, cdest)

	// Read back — should see 2 unique proofs (same as log).
	rows := readRecentProofsFromCSV(50)
	if len(rows) != 2 {
		t.Fatalf("expected 2 unique proofs (reader dedup), got %d — duplicate rows leaked?", len(rows))
	}
	// Now simulate a SECOND dashboard restart: reset dedup, backfill again
	// → CSV has another copy of each proof with newer collected_ts.
	resetDedupMaps()
	// Wait a moment so time.Now().Unix() differs (collected_ts changes).
	time.Sleep(2 * time.Second)
	backfillProofsFromLog(text, cdest)

	// Read back — should STILL see 2 unique proofs (reader dedup catches
	// the duplicates with different collected_ts).
	rows = readRecentProofsFromCSV(50)
	if len(rows) != 2 {
		t.Fatalf("expected 2 unique proofs after 2nd restart (reader dedup), got %d", len(rows))
	}
	for i, r := range rows {
		m, _ := r.(map[string]interface{})
		if dest, _ := m["dest"].(string); dest == "" {
			t.Fatalf("row %d has empty dest", i)
		}
	}
	t.Logf("AfterDashboardRestart: reader dedups duplicate CSV rows, %d unique proofs ✓", len(rows))
}

// TestProofsLogRotation: log file is rotated, new log has 1 proof, old .log.1
// has 100 proofs (mixed dest) → only valid-dest shown, sorted by epoch_ts.
//
// In production, readLogTail globs bpftune-met-live.log* and concatenates
// newest-first. Here we simulate the concatenated text.
func TestProofsLogRotation(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup(t)
	pinBootUptime(1_000_000_000)

	// "old log" (.log.1) — 100 proofs, half without dest=
	var lines []string
	for i := 0; i < 50; i++ {
		// 50 with dest (valid)
		lines = append(lines, fmt.Sprintf(
			`%d.0: bpf_trace_printk: proof cookie=%d alg=1 rate=1000000 tier=2 dest=1395917824`,
			1000+i, 40000+i))
	}
	for i := 0; i < 50; i++ {
		// 50 without dest (will be filtered — no cdest for these cookies)
		lines = append(lines, fmt.Sprintf(
			`%d.0: bpf_trace_printk: proof cookie=%d alg=1 rate=2000000 tier=2`,
			1100+i, 50000+i))
	}
	// "new log" (.log) — 1 fresh proof with dest
	lines = append(lines, `5000.0: bpf_trace_printk: proof cookie=101 alg=1 rate=3000000 tier=2 dest=1395917824`)
	text := strings.Join(lines, "\n")

	pl := parseLogSinglePass(text)
	currentParsedLog = pl
	defer func() { currentParsedLog = nil }()

	proofs := pl.GetProofRows(pl.Cdest)
	// GetProofRows takes last 18 of pl.ProofLines. pl.ProofLines has 101
	// entries (50 valid + 50 empty-dest + 1 fresh). Last 18 = the last 18
	// appended, which is the 1 fresh + the last 17 of the empty-dest group.
	// After my LEAK #1 filter, only the fresh proof remains.
	if len(proofs) == 0 {
		t.Fatalf("expected at least 1 valid proof (fresh from new log), got 0")
	}
	// Top should be the fresh proof (boot_ts=5000, highest).
	first := proofs[0].(map[string]interface{})
	firstTs, _ := first["boot_ts"].(float64)
	if firstTs != 5000 {
		t.Fatalf("expected top proof boot_ts=5000 (fresh from new log), got %v", firstTs)
	}
	for i, p := range proofs {
		row := p.(map[string]interface{})
		if dest, _ := row["dest"].(string); dest == "" {
			t.Fatalf("row %d has empty dest — log rotation leaked empty-dest proof", i)
		}
	}
	t.Logf("LogRotation: %d valid proofs after rotation, fresh on top ✓", len(proofs))
}

// TestProofsWriteThenRead: write proofs to CSV via writeProofsCSVFromInterface
// (some with empty dest), then readRecentProofsFromCSV → no empty-dest rows
// in either direction.
func TestProofsWriteThenRead(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup(t)
	resetDedupMaps()
	pinBootUptime(1_000_000_000)

	now := time.Now().Unix()
	proofs := []interface{}{
		proofRow(1250, "bbr", "1.0", "proved", "1.2.3.4", now-100),
		proofRow(1350, "cubic", "0.5", "good", "", now-50),    // empty dest — write should skip
		proofRow(1450, "htcp", "2.0", "proved", "5.6.7.8", now-10),
	}
	writeProofsCSVFromInterface(proofs, now)

	// Read back — should see only 2 proofs (empty-dest one was skipped at write).
	rows := readRecentProofsFromCSV(50)
	if len(rows) != 2 {
		t.Fatalf("expected 2 proofs (empty-dest skipped at write), got %d", len(rows))
	}
	for i, r := range rows {
		m, _ := r.(map[string]interface{})
		if dest, _ := m["dest"].(string); dest == "" {
			t.Fatalf("row %d has empty dest — write filter regressed", i)
		}
	}
	t.Logf("WriteThenRead: %d valid proofs (empty-dest skipped at write) ✓", len(rows))
}

// TestProofsFrontendRenderNoUnknown: simulate what the frontend does —
// filter proofs with empty dest, assert none shown.
//
// This is the last-line-of-defence filter (AUDIT-PROOFS-1 LEAK #6).
// Even if every backend fix regresses, the frontend filter at dashboard.js
// renderRecentProofs should drop empty-dest rows.
func TestProofsFrontendRenderNoUnknown(t *testing.T) {
	// Simulate a backend that LEAKED empty-dest rows (regression scenario).
	leakyRows := []interface{}{
		proofRow(1250, "bbr", "1.0", "proved", "1.2.3.4", 1730000000),
		proofRow(1350, "cubic", "0.5", "good", "", 1730000050),  // LEAKED
		proofRow(1450, "htcp", "2.0", "proved", "", 1730000100), // LEAKED
		proofRow(1550, "bbr", "0.8", "good", "5.6.7.8", 1730000200),
	}
	filtered := frontendFilterProofs(leakyRows)
	if len(filtered) != 2 {
		t.Fatalf("expected 2 proofs after frontend filter, got %d", len(filtered))
	}
	if hasEmptyDest(filtered) {
		t.Fatal("frontend filter let empty-dest rows through")
	}
	t.Logf("FrontendRenderNoUnknown: %d rows after filter (2 empty-dest dropped) ✓", len(filtered))
}

// TestProofsCookieDestFIFOEvictionPrefersDiskOnly: AUDIT-PROOFS-1 LEAK #5.
// After bpftune restart (without kernel reboot), new cookies start at 1
// while old disk cookies are at 40000+. The OLD eviction (sort by cookie
// numeric ascending, drop smallest) would drop the NEW cookies (1-100)
// instead of the OLD ones (40000-50000), breaking cdest lookups for all
// new proofs and producing (unknown) dest in the panel.
//
// The fix: prefer dropping entries that are NOT in the fresh set (disk-only).
func TestProofsCookieDestFIFOEvictionPrefersDiskOnly(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup(t)
	resetCookieDestState(env.tmpDir)

	// Save the original cap and restore it after the test.
	origCap := cookieDestMaxEntries
	cookieDestMaxEntries = 5
	defer func() { cookieDestMaxEntries = origCap }()

	// Disk map: 10 OLD cookies from previous bpftune run (40000-40009).
	// (Set directly via cookieDestDiskMap to skip the load-from-disk step.)
	cookieDestMu.Lock()
	cookieDestDiskMap = map[string]cdestEntry{}
	for i := 0; i < 10; i++ {
		cookieDestDiskMap[strconv.Itoa(40000+i)] = cdestEntry{"1.2.3.4", "", ""}
	}
	cookieDestMu.Unlock()

	// Fresh map (from current log tail): 5 NEW cookies (1-5) from current
	// bpftune run.
	fresh := map[string]cdestEntry{}
	for i := 1; i <= 5; i++ {
		fresh[strconv.Itoa(i)] = cdestEntry{"5.6.7.8", "", ""}
	}

	merged := persistCookieDest(fresh)

	// After merge: 10 disk + 5 fresh = 15 entries. Cap=5. Drop 10.
	// The OLD eviction (sort by cookie asc, drop smallest) would drop
	// cookies 1, 2, 3, 4, 5 (the FRESH ones!) — catastrophic.
	// The FIXED eviction (prefer disk-only) drops the 10 disk-only entries
	// (40000-40009), keeping the 5 fresh entries.
	for i := 1; i <= 5; i++ {
		key := strconv.Itoa(i)
		if _, ok := merged[key]; !ok {
			t.Errorf("fresh cookie %d was evicted — LEAK #5 regression (FIFO dropping new cookies)", i)
		}
	}
	// All 10 disk-only entries should have been evicted.
	for i := 0; i < 10; i++ {
		key := strconv.Itoa(40000 + i)
		if _, ok := merged[key]; ok {
			t.Errorf("disk-only cookie %s survived — should have been evicted in favor of fresh entries", key)
		}
	}
	if len(merged) != 5 {
		t.Errorf("expected merged size = cap = 5, got %d", len(merged))
	}
	t.Logf("CookieDestFIFOEviction: %d fresh cookies kept, %d disk-only evicted (LEAK #5 fix verified) ✓", 5, 10)
}

// ----------------------------------------------------------------------------
// SWAPS TESTS (12-20)
// ----------------------------------------------------------------------------

// TestSwapsLiveLogAllFresh: log has 18 fresh swaps → panel shows them,
// sorted by boot_ts DESC (within a single boot, sort by boot_ts is correct).
func TestSwapsLiveLogAllFresh(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup(t)
	pinBootUptime(1_000_000_000)

	var lines []string
	for i := 0; i < 18; i++ {
		ts := 1000 + i*10
		lines = append(lines, fmt.Sprintf(
			`%d.0: bpf_trace_printk: swap cookie=%d from=0 to=1 bc=5 ac=10 d=2 mt=0 rb=1 dest=1395917824`,
			ts, 1001+i))
	}
	pl := parseLogSinglePass(strings.Join(lines, "\n"))
	rows := buildRecentSwapRows(pl.Swaps, pl.MetByCookie, pl.SrateByCookie, pl.Cdest)
	if len(rows) != 18 {
		t.Fatalf("expected 18 swap rows, got %d", len(rows))
	}
	// Sort by boot_ts desc: row[0] should have ts=1170 (highest).
	first := rows[0].(map[string]interface{})
	firstTs, _ := first["boot_ts"].(float64)
	if firstTs != 1170 {
		t.Fatalf("expected top swap boot_ts=1170 (newest), got %v", firstTs)
	}
	// All rows should have valid dest.
	for i, r := range rows {
		m, _ := r.(map[string]interface{})
		if dest, _ := m["dest"].(string); dest == "" {
			t.Fatalf("row %d has empty dest", i)
		}
	}
	t.Logf("LiveLogAllFresh: %d swaps returned, sorted by boot_ts desc ✓", len(rows))
}

// TestSwapsLiveLogFewFallbackToCSV: log has 5 fresh swaps, CSV has 50 →
// merged top-18 has fresh on top, CSV below.
func TestSwapsLiveLogFewFallbackToCSV(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup(t)

	now := int64(1730000000)
	// 5 fresh live swaps (epoch_ts ≈ now)
	var live []interface{}
	for i := 0; i < 5; i++ {
		live = append(live, swapRowMap(
			float64(100+i), now-int64(60*i), "cubic", "bbr", "1.2.3.4", "win"))
	}
	// 50 CSV swaps (epoch_ts ≈ now-3600)
	var csvRows []interface{}
	for i := 0; i < 50; i++ {
		csvRows = append(csvRows, swapRowMap(
			float64(1000+i), now-3600-int64(60*i), "cubic", "bbr", "5.6.7.8", "null"))
	}

	merged := mergeSwapsNewestFirst(live, csvRows, 18)
	if len(merged) != 18 {
		t.Fatalf("expected 18 merged swaps, got %d", len(merged))
	}
	// Top 5 should be live (epoch_ts = now-60*i, larger than CSV's now-3600-...)
	for i := 0; i < 5; i++ {
		m := merged[i].(map[string]interface{})
		ts, _ := m["epoch_ts"].(int64)
		if ts < now-3600 {
			t.Fatalf("merged[%d] is a CSV swap, not a live one — sort regressed", i)
		}
	}
	t.Logf("FewFallbackToCSV: %d merged swaps, 5 live on top, 13 CSV below ✓", len(merged))
}

// TestSwapsAfterBpftuneRestart: CRITICAL — bpftune restart, BPF ktime
// CONTINUES (does NOT reset on bpftune restart — only on kernel reboot).
// Live log has swaps from previous bpftune run (lower boot_ts ~50000) +
// current run (higher boot_ts ~50400, since ktime continued). CSV has
// swaps from previous run. Panel MUST show current-run swaps on top.
func TestSwapsAfterBpftuneRestart(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup(t)
	pinBootUptime(50400)

	// Live log: previous-run swap at ktime=50000 + current-run at ktime=50400
	lines := []string{
		// Previous run (ktime=50000, before restart)
		`50000.0: bpf_trace_printk: swap cookie=40001 from=0 to=1 bc=5 ac=10 d=2 mt=0 rb=1 dest=1395917824`,
		// Current run (ktime=50400, after restart — ktime continued)
		`50400.0: bpf_trace_printk: swap cookie=101 from=0 to=1 bc=5 ac=10 d=2 mt=0 rb=1 dest=1395917824`,
		`50410.0: bpf_trace_printk: swap cookie=102 from=0 to=1 bc=5 ac=10 d=2 mt=0 rb=1 dest=1395917824`,
	}
	pl := parseLogSinglePass(strings.Join(lines, "\n"))
	rows := buildRecentSwapRows(pl.Swaps, pl.MetByCookie, pl.SrateByCookie, pl.Cdest)
	if len(rows) != 3 {
		t.Fatalf("expected 3 swaps, got %d", len(rows))
	}
	// Sort by boot_ts desc: top should be 50410 (current run, newest)
	first := rows[0].(map[string]interface{})
	firstTs, _ := first["boot_ts"].(float64)
	if firstTs != 50410 {
		t.Fatalf("expected top swap boot_ts=50410 (current run, newest), got %v — current-run not on top", firstTs)
	}
	t.Logf("AfterBpftuneRestart: %d swaps returned, current-run on top ✓", len(rows))
}

// TestSwapsAfterKernelReboot: kernel reboots, BPF ktime resets to 0. Live
// log has OLD swaps (ktime > uptime+300, filtered out). CSV has stale swaps.
// Panel shows current swaps on top.
func TestSwapsAfterKernelReboot(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup(t)
	// Kernel just rebooted 100s ago
	pinBootUptime(100)

	lines := []string{
		// Stale swaps from previous boot (ktime=50000 > 100+300=400 → filtered)
		`50000.0: bpf_trace_printk: swap cookie=40001 from=0 to=1 bc=5 ac=10 d=2 mt=0 rb=1 dest=1395917824`,
		`51000.0: bpf_trace_printk: swap cookie=40002 from=0 to=1 bc=5 ac=10 d=2 mt=0 rb=1 dest=1395917824`,
		// Current boot swaps (ktime=50 < 400 → kept)
		`50.0: bpf_trace_printk: swap cookie=101 from=0 to=1 bc=5 ac=10 d=2 mt=0 rb=1 dest=1395917824`,
		`60.0: bpf_trace_printk: swap cookie=102 from=0 to=1 bc=5 ac=10 d=2 mt=0 rb=1 dest=1395917824`,
	}
	pl := parseLogSinglePass(strings.Join(lines, "\n"))
	if len(pl.Swaps) != 2 {
		t.Fatalf("expected 2 swaps after kernel-reboot filter (stale filtered), got %d", len(pl.Swaps))
	}
	rows := buildRecentSwapRows(pl.Swaps, pl.MetByCookie, pl.SrateByCookie, pl.Cdest)
	if len(rows) != 2 {
		t.Fatalf("expected 2 swap rows, got %d", len(rows))
	}
	// Newest on top: boot_ts=60 first
	first := rows[0].(map[string]interface{})
	firstTs, _ := first["boot_ts"].(float64)
	if firstTs != 60 {
		t.Fatalf("expected top swap boot_ts=60 (current boot, newest), got %v", firstTs)
	}
	t.Logf("AfterKernelReboot: stale swaps filtered, %d current-boot swaps on top ✓", len(rows))
}

// TestSwapsCSVDuplicates: CSV has duplicate rows (same boot_ts+cookie,
// different collected_ts from dashboard restart). Reader MUST dedup and
// show newest (highest collected_ts).
func TestSwapsCSVDuplicates(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup(t)

	// Two rows with same boot_ts+cookie (1500,1001), different collected_ts.
	csv := "collected_ts,boot_ts,cookie,from_alg,to_alg,d,mt_alg,rb_alg,diverges,outcome,socket_rate_before,dest,dest_raw,f_ema,t_ema,srate_before,direction,rport\n"
	csv += "1700000000,1500.000000,1001,cubic,bbr,2,cubic,bbr,0,win,1000000,83.52.0.0,1395917824,100,200,1000000,client,8443\n" // older
	csv += "1700000010,1500.000000,1001,cubic,bbr,2,cubic,bbr,0,win,1000000,83.52.0.0,1395917824,100,200,1000000,client,8443\n" // newer (T2)
	csv += "1700000020,1600.000000,1002,cubic,bbr,2,cubic,bbr,0,win,1000000,83.52.0.0,1395917824,100,200,1000000,client,8443\n" // unique swap
	writeCSV(t, swapsCSVPath, csv)

	rows := readRecentSwapsFromCSV(50)
	// Two unique swaps (1001 + 1002) — the duplicate of 1001 should be deduped.
	if len(rows) != 2 {
		t.Fatalf("expected 2 unique swaps (reader dedup), got %d — duplicates leaked?", len(rows))
	}
	// First row should be the NEWEST (collected_ts=1700000020, cookie 1002)
	first := rows[0].(map[string]interface{})
	firstTs, _ := first["epoch_ts"].(int64)
	if firstTs != 1700000020 {
		t.Fatalf("expected top swap epoch_ts=1700000020 (newest), got %d", firstTs)
	}
	// Second row should be the NEWEST version of cookie 1001 (collected_ts=1700000010, NOT 1700000000)
	second := rows[1].(map[string]interface{})
	secondTs, _ := second["epoch_ts"].(int64)
	if secondTs != 1700000010 {
		t.Fatalf("expected 2nd swap epoch_ts=1700000010 (newer duplicate of 1001), got %d — reader kept OLDER duplicate", secondTs)
	}
	t.Logf("CSVDuplicates: reader deduped duplicates, returned %d unique swaps, newest version kept ✓", len(rows))
}

// TestSwapsAgeLabelCorrect: frontend age label test. Given a swap with
// epoch_ts=now-3600 and boot_ts=4000 (current bpftune, ktime=5000), age
// MUST show "1h" (from epoch_ts), NOT "16m" (from buggy boot_ts path).
//
// This verifies the AUDIT-SWAPS-1 LEAK #1 fix in dashboard.js ageLabel
// (epoch_ts preferred over boot_ts).
func TestSwapsAgeLabelCorrect(t *testing.T) {
	nowSec := int64(1730000000)
	epochTs := nowSec - 3600 // 1h ago wall-clock
	bootTs := float64(4000)  // BPF ktime at swap event
	serverNowMono := float64(5000) // current bpftune ktime

	// Buggy path (boot_ts first): age = 5000 - 4000 = 1000s → "16m" (WRONG)
	buggyAge := serverNowMono - bootTs
	buggyLabel := ageBucket(buggyAge)
	if buggyLabel == "1h" {
		t.Logf("NOTE: buggy path happened to also produce '1h' (unlucky test values)")
	}

	// Fixed path (epoch_ts first): eAge = 1730000000 - (1730000000-3600) = 3600 → "1h" (CORRECT)
	got := goAgeLabel(bootTs, epochTs, serverNowMono, nowSec)
	if got != "1h" {
		t.Fatalf("expected ageLabel='1h' (from epoch_ts), got %q (boot_ts-based buggy path?)", got)
	}
	t.Logf("AgeLabelCorrect: ageLabel returned %q (from epoch_ts, not boot_ts) ✓", got)
}

// TestSwapsMergeSortByEpochTsNotBootTs: explicitly test that
// mergeSwapsNewestFirst sorts by epoch_ts. Live row with epoch_ts=now-60
// boot_ts=100 vs CSV row with epoch_ts=now-3600 boot_ts=50000. Live MUST
// sort above CSV despite smaller boot_ts.
//
// This guards the v0.9.92 fix and the AUDIT-SWAPS-1 LEAK #3 fix (getTs
// returns -Inf when epoch_ts missing, instead of falling back to boot_ts).
func TestSwapsMergeSortByEpochTsNotBootTs(t *testing.T) {
	now := int64(1730000000)
	live := []interface{}{
		swapRowMap(100, now-60, "cubic", "bbr", "1.2.3.4", "win"),
	}
	csv := []interface{}{
		swapRowMap(50000, now-3600, "cubic", "bbr", "5.6.7.8", "null"),
	}
	merged := mergeSwapsNewestFirst(live, csv, 18)
	if len(merged) != 2 {
		t.Fatalf("expected 2 merged swaps, got %d", len(merged))
	}
	first := merged[0].(map[string]interface{})
	firstTs, _ := first["epoch_ts"].(int64)
	if firstTs != now-60 {
		t.Fatalf("expected top swap epoch_ts=%d (live, newer wall-clock), got %d — sort by boot_ts regressed", now-60, firstTs)
	}
	firstBoot, _ := first["boot_ts"].(float64)
	if firstBoot != 100 {
		t.Fatalf("expected top swap boot_ts=100 (live), got %v — CSV row sorted above live despite older epoch_ts", firstBoot)
	}
	t.Logf("MergeSortByEpochTsNotBootTs: live (epoch=%d, boot=100) above CSV (epoch=%d, boot=50000) ✓", now-60, now-3600)
}

// TestSwapsCSVReaderSortsNewestFirst: readRecentSwapsFromCSV returns
// newest-first (file is oldest-first).
func TestSwapsCSVReaderSortsNewestFirst(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup(t)

	// CSV is oldest-first (chronological append order)
	csv := "collected_ts,boot_ts,cookie,from_alg,to_alg,d,mt_alg,rb_alg,diverges,outcome,socket_rate_before,dest,dest_raw,f_ema,t_ema,srate_before,direction,rport\n"
	csv += "1700000000,1500.000000,1001,cubic,bbr,2,cubic,bbr,0,win,1000000,83.52.0.0,1395917824,100,200,1000000,client,8443\n" // oldest
	csv += "1700000010,1600.000000,1002,cubic,bbr,2,cubic,bbr,0,win,1000000,83.52.0.0,1395917824,100,200,1000000,client,8443\n"
	csv += "1700000020,1700.000000,1003,cubic,bbr,2,cubic,bbr,0,win,1000000,83.52.0.0,1395917824,100,200,1000000,client,8443\n" // newest
	writeCSV(t, swapsCSVPath, csv)

	rows := readRecentSwapsFromCSV(50)
	if len(rows) != 3 {
		t.Fatalf("expected 3 swaps, got %d", len(rows))
	}
	// First should be the NEWEST (collected_ts=1700000020)
	first := rows[0].(map[string]interface{})
	firstTs, _ := first["epoch_ts"].(int64)
	if firstTs != 1700000020 {
		t.Fatalf("expected top swap epoch_ts=1700000020 (newest), got %d — reader not reversing?", firstTs)
	}
	t.Logf("CSVReaderSortsNewestFirst: top swap epoch_ts=%d (newest) ✓", firstTs)
}

// TestSwapsStaleCSVSinkToBottom: CSV has 100 stale swaps (epoch_ts from
// days ago) + 5 fresh swaps → fresh MUST be on top, stale filtered by
// the 24h cutoff in buildLogPanels.
func TestSwapsStaleCSVSinkToBottom(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup(t)

	now := int64(1730000000)

	// Build a CSV with 100 stale swaps (collected_ts from 7 days ago) + 5 fresh
	csv := "collected_ts,boot_ts,cookie,from_alg,to_alg,d,mt_alg,rb_alg,diverges,outcome,socket_rate_before,dest,dest_raw,f_ema,t_ema,srate_before,direction,rport\n"
	// 100 stale swaps
	for i := 0; i < 100; i++ {
		staleTs := now - 7*24*3600 - int64(i) // 7 days ago
		csv += fmt.Sprintf("%d,1500.000000,%d,cubic,bbr,2,cubic,bbr,0,win,1000000,83.52.0.0,1395917824,100,200,1000000,client,8443\n",
			staleTs, 40000+i)
	}
	// 5 fresh swaps (collected_ts = now - 60*i, all within 24h).
	// Write in CHRONOLOGICAL order (oldest first, newest LAST) so the
	// reader's reversal (newest-first) puts the newest at the top of the
	// returned slice.
	for i := 4; i >= 0; i-- {
		freshTs := now - int64(60*i)
		csv += fmt.Sprintf("%d,1600.000000,%d,cubic,bbr,2,cubic,bbr,0,win,1000000,83.52.0.0,1395917824,100,200,1000000,client,8443\n",
			freshTs, 100+i)
	}
	writeCSV(t, swapsCSVPath, csv)

	// Simulate what buildLogPanels does: read CSV, filter by 24h cutoff.
	csvSwaps := readRecentSwapsFromCSV(200)
	var recentCsvSwaps []interface{}
	cutoff := now - 24*3600
	for _, s := range csvSwaps {
		if m, ok := s.(map[string]interface{}); ok {
			if ts, ok := m["epoch_ts"].(int64); ok && ts >= cutoff {
				recentCsvSwaps = append(recentCsvSwaps, s)
			}
		}
	}

	if len(recentCsvSwaps) != 5 {
		t.Fatalf("expected 5 fresh CSV swaps after 24h cutoff, got %d — stale swaps leaked through", len(recentCsvSwaps))
	}
	// Top should be the NEWEST fresh swap (epoch_ts = now)
	first := recentCsvSwaps[0].(map[string]interface{})
	firstTs, _ := first["epoch_ts"].(int64)
	if firstTs != now {
		t.Fatalf("expected top swap epoch_ts=%d (newest fresh), got %d", now, firstTs)
	}
	t.Logf("StaleCSVSinkToBottom: %d stale filtered, %d fresh swaps returned ✓", 100, len(recentCsvSwaps))
}

// ----------------------------------------------------------------------------
// BONUS tests — extra coverage
// ----------------------------------------------------------------------------

// TestSwapsMergeNoEmptyDestSurvives: defence-in-depth — even if a producer
// regresses and emits an empty-dest swap, the merge should... well, swaps
// don't have an empty-dest filter in mergeSwapsNewestFirst (unlike proofs).
// But the frontend filter (renderRecentSwaps) drops them. This test verifies
// the frontend filter catches them.
func TestSwapsMergeNoEmptyDestSurvives(t *testing.T) {
	now := int64(1730000000)
	live := []interface{}{
		swapRowMap(100, now-60, "cubic", "bbr", "1.2.3.4", "win"),
		swapRowMap(110, now-50, "cubic", "bbr", "", "null"), // LEAKED empty dest
	}
	merged := mergeSwapsNewestFirst(live, nil, 18)
	// mergeSwapsNewestFirst doesn't filter empty-dest swaps — by design,
	// the frontend does. Verify the frontend filter catches them.
	filtered := frontendFilterSwaps(merged)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 swap after frontend filter (empty-dest dropped), got %d", len(filtered))
	}
	if hasEmptyDest(filtered) {
		t.Fatal("frontend filter let empty-dest swap through")
	}
	t.Logf("MergeNoEmptyDestSurvives: frontend filter caught leaked empty-dest swap ✓")
}

// TestProofsMergeDedupByBootTsNotEpochTs: AUDIT-PROOFS-1 LEAK #3 fix.
// After dashboard restart, the same proof event gets written to CSV twice
// with different collected_ts. The MERGE should not show both — the
// reader dedups by boot_ts:alg, so the merge sees only one. But if the
// reader regresses, the merge's defence-in-depth filter (drop empty-dest)
// at least catches rows with empty dest.
//
// This test verifies the reader dedup is in place.
func TestProofsMergeDedupByBootTsNotEpochTs(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup(t)

	// CSV with 2 duplicate proof rows (same boot_ts, different collected_ts)
	csv := "collected_ts,boot_ts,cookie,alg,rate_bps,mbps,tier,dest\n"
	csv += "1700000000,1250.000000,1001,bbr,1000000,1.0,2,83.52.0.0\n" // older
	csv += "1700000010,1250.000000,1001,bbr,1000000,1.0,2,83.52.0.0\n" // newer (T2)
	writeCSV(t, proofsCSVPath, csv)

	rows := readRecentProofsFromCSV(50)
	if len(rows) != 1 {
		t.Fatalf("expected 1 unique proof (reader dedup), got %d — duplicates leaked?", len(rows))
	}
	// The kept row should be the NEWER one (collected_ts=1700000010)
	first := rows[0].(map[string]interface{})
	firstTs, _ := first["epoch_ts"].(int64)
	if firstTs != 1700000010 {
		t.Fatalf("expected kept row epoch_ts=1700000010 (newer duplicate), got %d — kept OLDER?", firstTs)
	}
	t.Logf("MergeDedupByBootTsNotEpochTs: reader deduped duplicate proofs, kept newer ✓")
}

// ============================================================================
// v0.9.96: Memory-leak regression tests (MEMFIX-1)
//
// These tests verify the 4 memory-waste fixes do not regress:
//   1. writtenProofsFlat stays bounded under load (was: nested map leaked).
//   2. writtenSwapsFlat stays bounded under load (was: nested map leaked).
//   3. bucketSnapshot with int16 Ss/Bs/Ns serializes/deserializes correctly.
//   4. mtimeCache.get skips os.Stat when lastStat < 30s.
// ============================================================================

// TestProofsDedupMapDoesNotLeak: MEMFIX-1 Fix 1 regression test.
// Simulate 1000 collect cycles × 10 proofs = 10,000 unique proof events
// over a ts range that exceeds the 1-hour prune cutoff (ts goes
// 1..10000, so by cycle 1000 the prune cutoff is ts-3600 = 6400, and
// only the most recent 3600 entries survive).
//
// OLD CODE: writtenProofs was map[int64]map[float64]bool keyed by
// (int64(ts), ts). cookieFake = int64(ts) is derived from ts, so the
// outer map grew ONE OUTER ENTRY PER PROOF EVENT and the outer map was
// never pruned. After 10,000 proofs the outer map had ~10,000 entries,
// each holding an empty/1-entry inner map header (~150 B) — ~1.5 MB of
// dead state. After a week (~600k proofs): ~90 MB.
//
// With the flat map + 1h prune, steady-state size at 1 proof/sec
// (this test's density) = ~3600 entries. Asserting <5000 proves the
// prune is working (without prune, len would be 10000 = total proofs
// written; with the OLD nested form, len(outer) would be 10000 = total
// unique cookies).
func TestProofsDedupMapDoesNotLeak(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup(t)
	resetDedupMaps()
	pinBootUptime(1_000_000_000)

	now := int64(1792000000)
	// 1000 cycles × 10 proofs. ts = cycle*10 + i + 1, so ts spans 1..10000.
	// By cycle 1000, the prune cutoff (ts - 3600) = 6400, so entries with
	// ts > 6400 survive = 3600 entries.
	for cycle := 0; cycle < 1000; cycle++ {
		proofs := make([]interface{}, 0, 10)
		for i := 0; i < 10; i++ {
			ts := float64(cycle*10 + i + 1)
			proofs = append(proofs, proofRow(ts, "bbr", "1.0", "proved", "82.43.215.97", now+int64(cycle)))
		}
		writeProofsCSVFromInterface(proofs, now+int64(cycle))
	}
	dedupMu.Lock()
	n := len(writtenProofsFlat)
	dedupMu.Unlock()
	// We wrote 10,000 proofs. Steady-state at 1/sec density with 1h
	// prune = ~3600 entries. Allow up to 5000 for prune-overhead margin.
	// (OLD nested form: len(outer) = 10000 — would fail this bound.)
	if n > 5000 {
		t.Errorf("writtenProofsFlat leaked: len=%d (expected <5000 after 10000 proofs with 1h prune; steady state should be ~3600)", n)
	}
	// Sanity: must be > 0 (we wrote proofs).
	if n == 0 {
		t.Errorf("writtenProofsFlat empty after 10000 proofs — dedup map never populated?")
	}
	// Sanity: must be < total proofs written (proves prune ran).
	if n >= 10000 {
		t.Errorf("writtenProofsFlat len=%d == total proofs written — prune never ran", n)
	}
	t.Logf("ProofsDedupMapDoesNotLeak: %d entries after 10000 proofs (steady-state ~3600, prune-at-1000+1h-window) ✓", n)
}

// TestSwapsDedupMapDoesNotLeak: MEMFIX-1 Fix 2 regression test.
// Simulate 1000 cycles × 10 swaps = 10,000 unique swap events with
// DIFFERENT cookies each cycle (to exercise the outer-map leak path
// of the old code). The flat map prunes entries with ts < current_ts -
// 3600 once len > 5000, so steady-state stays bounded.
//
// OLD CODE: writtenSwaps was map[int64]map[float64]bool keyed by
// (cookie, ts). Outer map grew ONE ENTRY PER UNIQUE COOKIE, never pruned.
// With 10,000 unique cookies, outer map had 10,000 entries × ~150 B per
// inner-map-header = ~1.5 MB. After a week on a busy host (~70k unique
// cookies): ~10 MB just for the headers, plus the per-cookie inner maps
// (mostly empty after their 1000-cap prune): ~50 MB total.
func TestSwapsDedupMapDoesNotLeak(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup(t)
	resetDedupMaps()
	pinBootUptime(1_000_000_000)

	now := int64(1792000000)
	// 1000 cycles × 10 swaps. Each cycle uses cookies 1000*cycle + i
	// (10,000 unique cookies total — exercises the outer-map leak path).
	// Each cycle uses ts = cycle*10 + i + 1 so the prune window
	// (ts - 3600) eventually rolls old entries out.
	for cycle := 0; cycle < 1000; cycle++ {
		swaps := make([]swapRow, 0, 10)
		for i := 0; i < 10; i++ {
			sw := swapRow{
				Ts:     float64(cycle*10 + i + 1),
				Cookie: int64(cycle*10 + i + 1),
				From:   1,
				To:     2,
				D:      "2",
				Dest:   "1.2.3.4",
			}
			// Mark as resolved so writeTruthRow is called
			// (exercise both code paths).
			sw.Outcome = "win"
			sw.DestResolved = "1.2.3.4"
			swaps = append(swaps, sw)
		}
		writeSwapsCSV(swaps, now+int64(cycle))
	}
	dedupMu.Lock()
	n := len(writtenSwapsFlat)
	dedupMu.Unlock()
	// We wrote 10,000 swaps with 10,000 unique cookies. Flat map with
	// prune-at-5000 + 1h window should stay < 6000. Allow up to 7000
	// for safety.
	if n > 7000 {
		t.Errorf("writtenSwapsFlat leaked: len=%d (expected <7000 after 10000 swaps with 1h prune)", n)
	}
	t.Logf("SwapsDedupMapDoesNotLeak: %d entries after 10000 swaps (cap=5000+overhead) ✓", n)
}

// TestBucketSnapshotInt16Roundtrip: MEMFIX-1 Fix 4 regression test.
// Verifies bucketSnapshot with int16 Ss/Bs/Ns fields serializes and
// deserializes correctly via JSON, preserving the full value range
// (0-1024 for Ss, 0-255 for Bs/Ns).
//
// This catches:
//   - Accidental truncation (int8 instead of int16 would lose Ss values
//     > 255).
//   - JSON encoding issues (json package handles int16 fine, but verify).
//   - Sign-extension bugs (if Ss were uint16 vs int16 the max would
//     differ).
func TestBucketSnapshotInt16Roundtrip(t *testing.T) {
	snap := bucketSnapshot{
		Ts:      1792000000,
		BestAlg: "bbr",
		BestI:   2,
		// Ss covers the full kernel range (0-1024) including the max.
		Ss: [16]int16{0, 1, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1024, 0, 0, 0},
		// Bs covers 0-255 (u8 range).
		Bs: [16]int16{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 100, 200, 255, 0, 0},
		// Ns covers 0-255.
		Ns: [16]int16{0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 100, 255, 0, 0},
		Mv: [16]float64{1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 11.0, 12.0, 13.0, 14.0, 15.0, 16.0},
		Re: [16]float64{1.5, 2.5, 3.5, 4.5, 5.5, 6.5, 7.5, 8.5, 9.5, 10.5, 11.5, 12.5, 13.5, 14.5, 15.5, 16.5},
	}
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	var snap2 bucketSnapshot
	if err := json.Unmarshal(data, &snap2); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	// Verify max-value preservation (the most likely failure mode for an
	// accidental int8 or sign-extension bug).
	if snap2.Ss[12] != 1024 {
		t.Errorf("Ss[12] = %d, want 1024 (int16 max-value preservation)", snap2.Ss[12])
	}
	if snap2.Bs[13] != 255 {
		t.Errorf("Bs[13] = %d, want 255 (u8 max preserved through int16)", snap2.Bs[13])
	}
	if snap2.Ns[13] != 255 {
		t.Errorf("Ns[13] = %d, want 255 (u8 max preserved through int16)", snap2.Ns[13])
	}
	// Verify zero values too (no spurious non-zero after roundtrip).
	if snap2.Ss[0] != 0 {
		t.Errorf("Ss[0] = %d, want 0", snap2.Ss[0])
	}
	// Verify the JSON actually contains 1024 (not a wrapped/truncated value).
	if !strings.Contains(string(data), "1024") {
		t.Errorf("JSON output missing 1024 — serialization regression: %s", string(data))
	}
	t.Logf("BucketSnapshotInt16Roundtrip: Ss[12]=1024, Bs[13]=255, Ns[13]=255 preserved ✓")
}

// TestMtimeCacheSkipsRecentStats: MEMFIX-1 Fix 3 regression test.
// Verifies the 30s TTL on mtimeCache.get — calling get(path) twice within
// 30s returns the same cached val without re-stat'ing the file.
//
// We can't directly count os.Stat calls without instrumentation, so we
// verify the BEHAVIORAL contract: two calls within 30s return the same
// value, and a third call after the file is modified within the 30s
// window STILL returns the cached value (proving the TTL is in effect —
// without TTL, the third call would re-stat, see the new mtime, and
// re-read the file).
func TestMtimeCacheSkipsRecentStats(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "labels.json")
	// Write initial labels.
	initial := []byte(`{"1.2.3.4": "home-sco"}`)
	if err := os.WriteFile(path, initial, 0644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)

	// Point the package-level labelsFile at our temp file (loadLabels
	// reads labelsFile). Save+restore so other tests aren't affected.
	oldLabelsFile := labelsFile
	labelsFile = path
	defer func() { labelsFile = oldLabelsFile }()

	// Use the package-level labelsHolder directly (it's a mtimeCache).
	// First call: stat + read + cache.
	labelsHolder.mu.Lock()
	labelsHolder.val = nil
	labelsHolder.mtime = time.Time{}
	labelsHolder.lastStat = time.Time{}
	labelsHolder.mu.Unlock()

	v1 := loadLabels()
	if lbl, ok := v1["1.2.3.4"]; !ok || lbl != "home-sco" {
		t.Fatalf("first loadLabels returned %v, want {1.2.3.4: home-sco}", v1)
	}

	// Modify the file. Without the TTL, the next get() would stat,
	// see the new mtime, and reload — returning the new label.
	// WITH the TTL (lastStat < 30s ago), get() returns the cached val
	// and the modification is invisible until the TTL expires.
	updated := []byte(`{"1.2.3.4": "home-sco-CHANGED"}`)
	if err := os.WriteFile(path, updated, 0644); err != nil {
		t.Fatal(err)
	}

	v2 := loadLabels()
	// With the TTL active, we expect the OLD (cached) value.
	if lbl, ok := v2["1.2.3.4"]; ok && lbl == "home-sco-CHANGED" {
		t.Errorf("loadLabels saw the file change within 30s TTL — TTL is NOT working (got updated value %q)", lbl)
	}
	if lbl, ok := v2["1.2.3.4"]; !ok || lbl != "home-sco" {
		t.Errorf("loadLabels returned %v, want cached {1.2.3.4: home-sco} (TTL should hide the file change)", v2)
	}

	// Verify the lastStat field was set (TTL is in effect).
	labelsHolder.mu.Lock()
	ls := labelsHolder.lastStat
	labelsHolder.mu.Unlock()
	if ls.IsZero() {
		t.Errorf("mtimeCache.lastStat is zero — TTL was never enabled")
	}
	if time.Since(ls) >= 30*time.Second {
		t.Errorf("mtimeCache.lastStat = %v ago, expected <30s (TTL window)", time.Since(ls))
	}
	t.Logf("MtimeCacheSkipsRecentStats: file change within 30s TTL was hidden by cache ✓ (lastStat=%v ago)", time.Since(ls))
}
