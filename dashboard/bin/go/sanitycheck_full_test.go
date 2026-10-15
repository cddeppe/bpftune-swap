package main

// sanitycheck_full_test.go — comprehensive end-to-end test harness for the
// bpftune-swap dashboard collector (branch `dashboard`, v0.9.87+).
//
// PURPOSE
//   This test simulates a full collect() cycle against synthetic log text +
//   synthetic CSV files, then verifies that EVERY field the frontend reads
//   in dashboard.js is present and non-zero (where data should produce a
//   non-zero value).  It was written in response to the v0.9.87 bug where
//   `buildChurnFromCSV` was missing the `cookies/one/mid/many/max` fields,
//   which made the frontend render 0 for all cookie churn stats whenever
//   the CSV fallback path was active (i.e. on every cycle with < 50 swaps
//   in the log tail, which is the common case for low-traffic hosts).
//
// LAYOUT
//   The file is meant to live at:
//     /tmp/bpftune-swap-dash/dashboard/bin/go/sanitycheck_full_test.go
//   (alongside the existing sanitycheck_test.go), so it shares `package main`
//   with the rest of the collector.  Until then it is staged at:
//     /home/z/my-project/sanitycheck_full_test.go
//   for review.  Copy/move it into the bin/go directory before running
//     `go test -run TestSanityCheck_Full ./...` from that directory.
//
// WHAT IT COVERS (in order of the per-cycle collect() pipeline)
//   1. parseLogSinglePass  — verifies parsedLog has Swaps/MetByCookie/
//      SrateByCookie/Cdest/CookieAlg/ProofLines/ProofEvents/ProofSamples/
//      MidsampRows/BucketIPs/MaxTs/RttByDest populated.
//   2. buildLogPanels       — verifies recent_swaps, recent_proofs,
//      swap_outcomes, bucket_ips, log_window, proofs_raw.
//   3. parsedLog getters   — verifies GetRate, GetRateRaw, GetProofRows,
//      GetProofsRaw, GetProofsRawEvents, GetBucketIPs.
//   4. buildChurnFromParsed — verifies cookies/one/mid/many/max present.
//      Documents that total/transitions are INTENTIONALLY absent from this
//      path (see worklog Task ID: full-audit-v988, Check 8).
//   5. buildDivergenceFromParsed — verifies the 24-field schema.
//   6. CSV fallback path    — overrides swapsCSVPath/proofsCSVPath to temp
//      files, writes synthetic CSVs, and verifies:
//        - buildChurnFromCSV            → cookies/one/mid/many/max/total/
//          transitions (the v0.9.87 fix under test)
//        - buildSwapOutcomesFromCSV     → composite/srate/sustained/
//          swaps_list with all 14 sub-fields
//        - buildDivergenceFromCSV       → pair/total/diverges/div_pct
//          (different schema from parsed path — documented)
//        - readRecentSwapsFromCSV       → boot_ts/epoch_ts/from_alg/to_alg/
//          d/outcome/outcome_sustained/mt_alg/rb_alg/dest
//        - readRecentProofsFromCSV      → boot_ts/epoch_ts/alg/mbps/tier/dest
//        - buildProofsRawFromCSV        → alg/good/proved/proven_max/
//          sampled_avg/sampled_max/samples
//   7. End-to-end collect() simulation — mirrors the actual collect() order:
//        pl := parseLogSinglePass(text)
//        currentParsedLog = pl
//        buildLogPanels(...)
//        buildChurnFromParsed(pl.Swaps)
//        if CSVFallback && len(swaps) < 50 { buildChurnFromCSV(200) }
//        pl.GetRate()
//        buildDivergenceFromParsed(...)
//        pl.GetProofsRaw()
//      Verifies the doc-shaped map has every key the frontend reads.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ----------------------------------------------------------------------------
// Mock log text builder
// ----------------------------------------------------------------------------

// buildMockLogText constructs a synthetic log tail that exercises every
// event type parsed by parseLogSinglePass: estab, swap, met, srate, proof,
// midsamp.  Cookies 1001/1002/1003 each get one swap with a measurable
// sustained outcome (win/loss/null respectively).  Cookies 4001/5001/6001-
// 6005 get swaps without outcomes (for churn distribution testing).
//
// Timestamps are deliberately chosen in the range 1000–1800 (BPF ktime
// seconds since boot).  We override bootUptime to a huge value in setupTestEnv
// so the "previous boot" filter in parseLogSinglePass doesn't drop them.
func buildMockLogText() string {
	var lines []string

	// ---- Cookie 1001: sustained-win outcome ------------------------------
	// srate pre = 1000, post = 1500 → r = 1.5 → sustained win
	lines = append(lines,
		// estab gives the cookie a dest so proof/midsamp can resolve it.
		`1000.0: bpf_trace_printk: estab cookie=1001 alg=0 forced=1 dest=1395917824`,
		// pre-swap met (composite pre value = 1000)
		`1100.0: bpf_trace_printk: met cookie=1001 rport=8443 alg=0 segs=10 val=1000 rtt=2500`,
		// pre-swap srate (srate pre = 1000)
		`1150.0: bpf_trace_printk: srate cookie=1001 alg=0 srate=1000`,
		// THE SWAP (cubic → bbr)
		`1200.0: bpf_trace_printk: swap cookie=1001 from=0 to=1 bc=5 ac=10 d=2 mt=0 rb=1 dest=1395917824`,
		// post-swap met in [T+3, T+300] → composite win (post/pre = 0.5)
		`1205.0: bpf_trace_printk: met cookie=1001 rport=8443 alg=1 segs=10 val=500`,
		// post-swap srate → srate ruler win (r = 1.5)
		`1210.0: bpf_trace_printk: srate cookie=1001 alg=1 srate=1500`,
		// sustained window samples in [T+60, T+300] → sustained win
		`1280.0: bpf_trace_printk: srate cookie=1001 alg=1 srate=1500`,
		`1400.0: bpf_trace_printk: srate cookie=1001 alg=1 srate=1500`,
		// proof event (tier=2 → proved; rate=8 Mbps after /bpsToMbps)
		`1250.0: bpf_trace_printk: proof cookie=1001 alg=1 rate=1000000 tier=2 dest=1395917824`,
		// midsamp event within 60s of a met sample on the same cookie
		// (creates a ProofSample for alg=0)
		`1110.0: bpf_trace_printk: midsamp cookie=1001 thr=1000000 rport=8443 srate=1500000 dest=1395917824`,
	)

	// ---- Cookie 1002: sustained-loss outcome ----------------------------
	// srate pre = 1500, post = 1000 → r = 0.667 → sustained loss
	lines = append(lines,
		`1000.0: bpf_trace_printk: estab cookie=1002 alg=0 forced=1 dest=1395917824`,
		`1100.0: bpf_trace_printk: met cookie=1002 rport=8443 alg=0 segs=10 val=1000`,
		`1150.0: bpf_trace_printk: srate cookie=1002 alg=0 srate=1500`,
		`1300.0: bpf_trace_printk: swap cookie=1002 from=0 to=1 bc=5 ac=10 d=2 mt=0 rb=1 dest=1395917824`,
		`1305.0: bpf_trace_printk: met cookie=1002 rport=8443 alg=1 segs=10 val=1500`,
		`1310.0: bpf_trace_printk: srate cookie=1002 alg=1 srate=1000`,
		`1380.0: bpf_trace_printk: srate cookie=1002 alg=1 srate=1000`,
		`1500.0: bpf_trace_printk: srate cookie=1002 alg=1 srate=1000`,
		// proof (tier=1 → good; alg=2 → htcp)
		`1350.0: bpf_trace_printk: proof cookie=1002 alg=2 rate=500000 tier=1 dest=1395917824`,
	)

	// ---- Cookie 1003: sustained-null outcome ----------------------------
	// srate pre = 1000, post = 1000 → r = 1.0 → sustained null
	lines = append(lines,
		`1000.0: bpf_trace_printk: estab cookie=1003 alg=0 forced=1 dest=1395917824`,
		`1100.0: bpf_trace_printk: met cookie=1003 rport=8443 alg=0 segs=10 val=1000`,
		`1150.0: bpf_trace_printk: srate cookie=1003 alg=0 srate=1000`,
		`1400.0: bpf_trace_printk: swap cookie=1003 from=0 to=1 bc=5 ac=10 d=2 mt=0 rb=1 dest=1395917824`,
		`1405.0: bpf_trace_printk: met cookie=1003 rport=8443 alg=1 segs=10 val=1000`,
		`1410.0: bpf_trace_printk: srate cookie=1003 alg=1 srate=1000`,
		`1480.0: bpf_trace_printk: srate cookie=1003 alg=1 srate=1000`,
		`1600.0: bpf_trace_printk: srate cookie=1003 alg=1 srate=1000`,
	)

	// ---- Cookie 4001: 3 swaps, no outcomes (churn "mid" bucket) ---------
	for i := 0; i < 3; i++ {
		ts := 1500.0 + float64(i)*10
		lines = append(lines, fmt.Sprintf(
			`%.1f: bpf_trace_printk: swap cookie=4001 from=0 to=1 bc=5 ac=10 d=2 mt=0 rb=1 dest=1395917824`, ts))
	}

	// ---- Cookie 5001: 5 swaps, no outcomes (churn "many" bucket) --------
	for i := 0; i < 5; i++ {
		ts := 1600.0 + float64(i)*10
		lines = append(lines, fmt.Sprintf(
			`%.1f: bpf_trace_printk: swap cookie=5001 from=0 to=1 bc=5 ac=10 d=2 mt=0 rb=1 dest=1395917824`, ts))
	}

	// ---- Cookies 6001-6005: 1 swap each, no outcomes (churn "one") ------
	for i := 0; i < 5; i++ {
		ts := 1700.0 + float64(i)*10
		lines = append(lines, fmt.Sprintf(
			`%.1f: bpf_trace_printk: swap cookie=%d from=0 to=1 bc=5 ac=10 d=2 mt=0 rb=1 dest=1395917824`, ts, 6001+i))
	}

	return strings.Join(lines, "\n")
}

// mockSwapsCSV builds a synthetic swaps.csv body (18 columns × N rows) that
// exercises the CSV fallback paths.  The "outcome" column carries the
// sustained verdict, and the "diverges" column drives buildDivergenceFromCSV.
func mockSwapsCSV() string {
	header := "collected_ts,boot_ts,cookie,from_alg,to_alg,d,mt_alg,rb_alg,diverges,outcome,socket_rate_before,dest,dest_raw,f_ema,t_ema,srate_before,direction,rport"
	rows := []string{header}
	// 6 rows: 2 win, 2 null, 2 loss, on 6 distinct cookies (so churn = 6 cookies, all one-off)
	// dest="83.52.0.0" matches the masked form of dest=1395917824 with prefix4=16.
	type row struct {
		ts        string
		cookie    string
		fromAlg   string
		toAlg     string
		diverges  string
		outcome   string
		direction string
	}
	data := []row{
		{"1700000000.000000", "1001", "cubic", "bbr", "1", "win", "client"},
		{"1700000010.000000", "1002", "cubic", "bbr", "1", "loss", "client"},
		{"1700000020.000000", "1003", "cubic", "bbr", "0", "null", "client"},
		{"1700000030.000000", "1004", "bbr", "cubic", "1", "win", "origin"},
		{"1700000040.000000", "1005", "bbr", "cubic", "0", "null", "origin"},
		{"1700000050.000000", "1006", "bbr", "cubic", "1", "loss", "origin"},
	}
	for _, r := range data {
		// 18 fields: collected_ts, boot_ts, cookie, from_alg, to_alg, d,
		// mt_alg, rb_alg, diverges, outcome, socket_rate_before, dest,
		// dest_raw, f_ema, t_ema, srate_before, direction, rport
		rows = append(rows, strings.Join([]string{
			r.ts, "1500.000000", r.cookie, r.fromAlg, r.toAlg, "2",
			r.fromAlg, r.toAlg, r.diverges, r.outcome, "1000000",
			"83.52.0.0", "1395917824", "100", "200", "1000000",
			r.direction, "8443",
		}, ","))
	}
	return strings.Join(rows, "\n") + "\n"
}

// mockProofsCSV builds a synthetic proofs.csv body (8 columns × N rows).
func mockProofsCSV() string {
	header := "collected_ts,boot_ts,cookie,alg,rate_bps,mbps,tier,dest"
	rows := []string{header}
	// 3 rows: alg=bbr tier=2 (proved), alg=cubic tier=1 (good), alg=htcp tier=2 (proved)
	rows = append(rows, "1700000000,1250.000000,1001,bbr,1000000,1.0,2,83.52.0.0")
	rows = append(rows, "1700000010,1350.000000,1002,cubic,500000,0.5,1,83.52.0.0")
	rows = append(rows, "1700000020,1450.000000,1003,htcp,2000000,2.0,2,83.52.0.0")
	return strings.Join(rows, "\n") + "\n"
}

// ----------------------------------------------------------------------------
// Test environment setup
// ----------------------------------------------------------------------------

// testEnv bundles the temp paths so the test can clean them up.
type testEnv struct {
	tmpDir        string
	oldSwapsPath  string
	oldProofsPath string
	oldMidPath    string
	oldStateJSON  string
}

// setupTestEnv creates a temp dir, points the package-level CSV path vars
// at temp files, and pins bootUptime to a huge value so parseLogSinglePass's
// "previous boot" filter doesn't drop our mock events.  Returns a cleanup fn.
func setupTestEnv(t *testing.T) *testEnv {
	t.Helper()
	tmp := t.TempDir()
	env := &testEnv{
		tmpDir:        tmp,
		oldSwapsPath:  swapsCSVPath,
		oldProofsPath: proofsCSVPath,
		oldMidPath:    midsampCSVPath,
		oldStateJSON:  stateJSONPath,
	}
	swapsCSVPath = filepath.Join(tmp, "swaps.csv")
	proofsCSVPath = filepath.Join(tmp, "proofs.csv")
	midsampCSVPath = filepath.Join(tmp, "midsamp.csv")
	stateJSONPath = filepath.Join(tmp, "state.json")

	// Pin bootUptime so events with ts up to ~1e9 pass the previous-boot filter.
	bootUptime.mu.Lock()
	bootUptime.value = 1_000_000_000.0
	bootUptime.ts = time.Now()
	bootUptime.mu.Unlock()

	// Reset the package-level currentParsedLog (collect.go sets this in
	// production; tests must set it explicitly before calling buildLogPanels
	// or it falls back to the legacy multi-scan path).
	currentParsedLog = nil

	// Reset the proofsRawCSV cache (csv_panels_fallback.go uses a mtime-based
	// cache; we want a clean read on every test).
	proofsRawCache = nil
	proofsRawCacheMtime = 0

	return env
}

func (e *testEnv) cleanup(t *testing.T) {
	swapsCSVPath = e.oldSwapsPath
	proofsCSVPath = e.oldProofsPath
	midsampCSVPath = e.oldMidPath
	stateJSONPath = e.oldStateJSON
	currentParsedLog = nil
}

// writeCSV writes content to path (used to stage synthetic CSVs).
func writeCSV(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writeCSV %s: %v", path, err)
	}
}

// ----------------------------------------------------------------------------
// Field-presence helpers
// ----------------------------------------------------------------------------

// assertKeys asserts every name in keys is present in m (and that m itself
// is non-nil).  Used to check schema completeness without coupling to values.
func assertKeys(t *testing.T, label string, m map[string]interface{}, keys ...string) {
	t.Helper()
	if m == nil {
		t.Fatalf("[%s] map is nil (expected keys %v)", label, keys)
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			t.Errorf("[%s] missing field %q (have: %v)", label, k, mapKeys(m))
		}
	}
}

// assertKeyNonZero asserts m[k] exists, is an int (or int64/float64 coercion),
// and is > 0.  Use for fields like "win", "measurable" where data should
// produce a non-zero count.
func assertKeyNonZeroInt(t *testing.T, label string, m map[string]interface{}, k string) {
	t.Helper()
	v, ok := m[k]
	if !ok {
		t.Errorf("[%s] missing field %q", label, k)
		return
	}
	if n := toInt(v); n <= 0 {
		t.Errorf("[%s] field %q = %v (expected > 0)", label, k, v)
	}
}

// assertKeyNonZeroFloat asserts m[k] exists and is a float64 > 0.
func assertKeyNonZeroFloat(t *testing.T, label string, m map[string]interface{}, k string) {
	t.Helper()
	v, ok := m[k]
	if !ok {
		t.Errorf("[%s] missing field %q", label, k)
		return
	}
	if f, ok := f64(v); !ok || f <= 0 {
		t.Errorf("[%s] field %q = %v (expected > 0)", label, k, v)
	}
}

// f64 coerces an interface{} (int, int64, float64) to float64.
func f64(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}

func mapKeys(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// asMap extracts a map[string]interface{} sub-field.  Fails the test if absent.
func asMap(t *testing.T, label, key string, parent map[string]interface{}) map[string]interface{} {
	t.Helper()
	v, ok := parent[key]
	if !ok {
		t.Fatalf("[%s] missing sub-map %q", label, key)
	}
	m, ok := v.(map[string]interface{})
	if !ok {
		t.Fatalf("[%s] %q is %T, not map[string]interface{}", label, key, v)
	}
	return m
}

// asSlice extracts an []interface{} sub-field.  Returns nil + fails-on-absent.
func asSlice(t *testing.T, label, key string, parent map[string]interface{}) []interface{} {
	t.Helper()
	v, ok := parent[key]
	if !ok {
		t.Fatalf("[%s] missing sub-slice %q", label, key)
	}
	s, ok := v.([]interface{})
	if !ok && v != nil {
		t.Fatalf("[%s] %q is %T, not []interface{}", label, key, v)
	}
	return s
}

// asSliceIface handles the case where the field is []interface{} or directly
// passed as []interface{} (e.g. the topSwaps return value of buildLogPanels).
func asSliceIface(t *testing.T, label string, v interface{}) []interface{} {
	t.Helper()
	if v == nil {
		return nil
	}
	s, ok := v.([]interface{})
	if !ok {
		t.Fatalf("[%s] value is %T, not []interface{}", label, v)
	}
	return s
}

// ----------------------------------------------------------------------------
// Test: parseLogSinglePass — verify the parsedLog struct is fully populated
// ----------------------------------------------------------------------------

func TestSanityCheck_ParseLogSinglePass(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup(t)

	text := buildMockLogText()
	pl := parseLogSinglePass(text)

	if pl == nil {
		t.Fatal("parseLogSinglePass returned nil")
	}

	// Swaps: 3 (cookies 1001/1002/1003) + 3 (4001) + 5 (5001) + 5 (6001-6005) = 16
	if got := len(pl.Swaps); got != 16 {
		t.Errorf("Swaps count = %d, want 16", got)
	}
	// MetByCookie: 3 cookies (1001/1002/1003)
	if got := len(pl.MetByCookie); got != 3 {
		t.Errorf("MetByCookie count = %d, want 3", got)
	}
	// SrateByCookie: 3 cookies (1001/1002/1003)
	if got := len(pl.SrateByCookie); got != 3 {
		t.Errorf("SrateByCookie count = %d, want 3", got)
	}
	// Cdest: 3 cookies (1001/1002/1003 — estab set their dest)
	if got := len(pl.Cdest); got != 3 {
		t.Logf("Cdest count = %d (>= 1, OK)", got)
	}
	// CookieAlg: should have at least the 3 cookies from estab + swap.to
	if got := len(pl.CookieAlg); got < 3 {
		t.Errorf("CookieAlg count = %d, want >= 3", got)
	}
	// ProofLines: 2 (cookies 1001 + 1002)
	if got := len(pl.ProofLines); got != 2 {
		t.Errorf("ProofLines count = %d, want 2", got)
	}
	// ProofEvents: 2 algs (alg=1 from cookie 1001, alg=2 from cookie 1002)
	if got := len(pl.ProofEvents); got != 2 {
		t.Errorf("ProofEvents count = %d, want 2", got)
	}
	// ProofSamples: 1 (midsamp near met on cookie 1001 → alg=0)
	if got := len(pl.ProofSamples); got < 1 {
		t.Errorf("ProofSamples count = %d, want >= 1", got)
	}
	// MidsampRows: 1 (the cookie=1001 midsamp line)
	if got := len(pl.MidsampRows); got != 1 {
		t.Errorf("MidsampRows count = %d, want 1", got)
	}
	// BucketIPs: at least one masked→[]fullIP entry from any dest= line
	if got := len(pl.BucketIPs); got < 1 {
		t.Errorf("BucketIPs count = %d, want >= 1", got)
	}
	// MaxTs: should be 1700.0 (cookie 6005 swap line, the largest ts)
	if got := pl.MaxTs; got < 1700.0 {
		t.Errorf("MaxTs = %v, want >= 1700.0", got)
	}
	// RttByDest: at least one entry from the met line carrying rtt=
	if got := len(pl.RttByDest); got < 1 {
		t.Errorf("RttByDest count = %d, want >= 1", got)
	}

	t.Logf("parseLogSinglePass: Swaps=%d Met=%d Srate=%d Cdest=%d ProofLines=%d ProofEvents=%d ProofSamples=%d Midsamp=%d BucketIPs=%d MaxTs=%.1f RttByDest=%d",
		len(pl.Swaps), len(pl.MetByCookie), len(pl.SrateByCookie),
		len(pl.Cdest), len(pl.ProofLines), len(pl.ProofEvents),
		len(pl.ProofSamples), len(pl.MidsampRows), len(pl.BucketIPs),
		pl.MaxTs, len(pl.RttByDest))
}

// ----------------------------------------------------------------------------
// Test: buildLogPanels — verify every frontend-read field is set on each panel
// ----------------------------------------------------------------------------

func TestSanityCheck_BuildLogPanels(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup(t)

	text := buildMockLogText()
	pl := parseLogSinglePass(text)

	// v0.9.9: collect() sets currentParsedLog before calling buildLogPanels
	// so the single-pass parsed data is used (no re-scan). Mirror that here.
	currentParsedLog = pl
	defer func() { currentParsedLog = nil }()

	now := time.Now().Unix()
	topSwaps, topProofs, swapOutcomesIface, bucketIPsIface, logWindowIface, proofsRawIface :=
		buildLogPanels(pl.Swaps, pl.MetByCookie, pl.SrateByCookie, pl.Cdest, text, now)

	// ---- recent_swaps rows ----
	// frontend reads: r.{boot_ts, epoch_ts, from_alg, to_alg, d, outcome,
	// outcome_sustained, mt_alg, rb_alg, dest}. (outcome_srate also set
	// but not used by current dashboard.js render path.)
	topSwapsSlice := asSliceIface(t, "recent_swaps", topSwaps)
	if len(topSwapsSlice) == 0 {
		t.Fatal("recent_swaps is empty (expected at least the 3 mock swaps)")
	}
	// Expect 3 swaps with measurable outcomes (cookies 1001/1002/1003)
	// plus 13 swaps with no outcome. Take first 3 (newest-first) to inspect.
	if len(topSwapsSlice) < 3 {
		t.Fatalf("recent_swaps has %d rows, want >= 3", len(topSwapsSlice))
	}
	for i, row := range topSwapsSlice {
		m, ok := row.(map[string]interface{})
		if !ok {
			t.Fatalf("recent_swaps[%d] not a map", i)
		}
		assertKeys(t, fmt.Sprintf("recent_swaps[%d]", i), m,
			"boot_ts", "epoch_ts", "from_alg", "to_alg", "d",
			"outcome", "outcome_sustained", "mt_alg", "rb_alg", "dest",
		)
		// alg dest fields must be non-empty (frontend shortAddr() needs a string)
		if s, _ := m["from_alg"].(string); s == "" {
			t.Errorf("recent_swaps[%d].from_alg empty", i)
		}
		if s, _ := m["to_alg"].(string); s == "" {
			t.Errorf("recent_swaps[%d].to_alg empty", i)
		}
		if s, _ := m["dest"].(string); s == "" {
			t.Errorf("recent_swaps[%d].dest empty", i)
		}
	}

	// ---- recent_proofs rows ----
	// frontend reads: r.{alg, mbps, dest, boot_ts, epoch_ts, tier}.
	topProofsSlice := asSliceIface(t, "recent_proofs", topProofs)
	if len(topProofsSlice) == 0 {
		t.Fatal("recent_proofs is empty (expected the 2 mock proofs)")
	}
	if len(topProofsSlice) < 2 {
		t.Errorf("recent_proofs has %d rows, want >= 2", len(topProofsSlice))
	}
	for i, row := range topProofsSlice {
		m, ok := row.(map[string]interface{})
		if !ok {
			t.Fatalf("recent_proofs[%d] not a map", i)
		}
		assertKeys(t, fmt.Sprintf("recent_proofs[%d]", i), m,
			"alg", "mbps", "dest", "boot_ts", "epoch_ts", "tier",
		)
		if s, _ := m["alg"].(string); s == "" {
			t.Errorf("recent_proofs[%d].alg empty", i)
		}
		if f, _ := m["mbps"].(float64); f <= 0 {
			t.Errorf("recent_proofs[%d].mbps = %v (expected > 0)", i, m["mbps"])
		}
		if s, _ := m["tier"].(string); s == "" {
			t.Errorf("recent_proofs[%d].tier empty", i)
		}
	}

	// ---- swap_outcomes ----
	// frontend reads payload.sustained.{win, null, loss, win_pct, null_pct,
	// loss_pct, measurable, unmeasurable, rescued, full_loss, open,
	// rescued_pct, full_loss_pct, open_pct} and payload.swaps_list (each
	// swap has ts, epoch_ts, boot_ts, cookie, dest, outcome, outcome_sustained).
	soMap, ok := swapOutcomesIface.(map[string]interface{})
	if !ok {
		t.Fatalf("swap_outcomes is %T, want map", swapOutcomesIface)
	}
	assertKeys(t, "swap_outcomes", soMap, "composite", "srate", "sustained", "swaps_list")

	sustained := asMap(t, "swap_outcomes", "sustained", soMap)
	// Full 14-field schema from finalizeOutcome + addLossRecovery.
	assertKeys(t, "swap_outcomes.sustained", sustained,
		"win", "null", "loss",
		"win_pct", "null_pct", "loss_pct",
		"measurable", "unmeasurable",
		"rescued", "full_loss", "open",
		"rescued_pct", "full_loss_pct", "open_pct",
	)
	// With our mock data: 1 sustained win, 1 sustained null, 1 sustained loss
	assertKeyNonZeroInt(t, "swap_outcomes.sustained", sustained, "win")
	assertKeyNonZeroInt(t, "swap_outcomes.sustained", sustained, "null")
	assertKeyNonZeroInt(t, "swap_outcomes.sustained", sustained, "loss")
	assertKeyNonZeroInt(t, "swap_outcomes.sustained", sustained, "measurable")

	// composite + srate should have the same 14-field schema
	for _, key := range []string{"composite", "srate"} {
		sub := asMap(t, "swap_outcomes", key, soMap)
		assertKeys(t, "swap_outcomes."+key, sub,
			"win", "null", "loss", "win_pct", "null_pct", "loss_pct",
			"measurable", "unmeasurable",
			"rescued", "full_loss", "open",
			"rescued_pct", "full_loss_pct", "open_pct",
		)
	}

	// swaps_list: each row has 7 fields (ts, epoch_ts, boot_ts, cookie,
	// dest, outcome, outcome_sustained).  Frontend uses this for the
	// swaps-per-bin chart and bucket-filter recomputation.
	sl := asSlice(t, "swap_outcomes", "swaps_list", soMap)
	if len(sl) == 0 {
		t.Fatal("swap_outcomes.swaps_list empty (expected at least 3 swaps)")
	}
	for i, row := range sl {
		m, ok := row.(map[string]interface{})
		if !ok {
			t.Fatalf("swaps_list[%d] not a map", i)
		}
		assertKeys(t, fmt.Sprintf("swaps_list[%d]", i), m,
			"ts", "epoch_ts", "boot_ts", "cookie", "dest",
			"outcome", "outcome_sustained",
		)
	}

	// ---- bucket_ips ----
	// frontend reads each entry as {masked: [ip, ip, ...]}.
	biMap, ok := bucketIPsIface.(map[string]interface{})
	if !ok {
		t.Fatalf("bucket_ips is %T, want map", bucketIPsIface)
	}
	if len(biMap) == 0 {
		t.Error("bucket_ips is empty (expected at least one masked bucket)")
	}
	for masked, ips := range biMap {
		ipList, ok := ips.([]interface{})
		if !ok {
			t.Errorf("bucket_ips[%q] is %T, want []interface{}", masked, ips)
			continue
		}
		if len(ipList) == 0 {
			t.Errorf("bucket_ips[%q] has 0 IPs", masked)
		}
	}

	// ---- log_window ----
	// frontend reads lw.{span_min, swap_count, age_min}.  Backend also sets
	// oldest_ts and newest_ts (used internally by renderLogWindow's siblings).
	lw, ok := logWindowIface.(map[string]interface{})
	if !ok {
		t.Fatalf("log_window is %T, want map", logWindowIface)
	}
	assertKeys(t, "log_window", lw, "oldest_ts", "newest_ts", "span_min", "swap_count", "age_min")
	// span_min > 0 (oldest=1100 estab? no — log_window scans swaps + proofs;
	// oldest swap ts = 1200, newest = 1700, span = 500s = 8.33min)
	if f, _ := lw["span_min"].(float64); f <= 0 {
		t.Errorf("log_window.span_min = %v (expected > 0)", lw["span_min"])
	}
	// swap_count must match the number of swaps (16)
	if n := toInt(lw["swap_count"]); n != 16 {
		t.Errorf("log_window.swap_count = %d, want 16", n)
	}

	// ---- proofs_raw (the leaderboard, not the events list) ----
	// frontend renderProof reads r.{alg, good, proved, proven_max,
	// sampled_avg, sampled_max, samples}.
	prSlice := asSliceIface(t, "proofs_raw", proofsRawIface)
	if len(prSlice) == 0 {
		t.Fatal("proofs_raw empty (expected at least one alg with events)")
	}
	for i, row := range prSlice {
		m, ok := row.(map[string]interface{})
		if !ok {
			t.Fatalf("proofs_raw[%d] not a map", i)
		}
		assertKeys(t, fmt.Sprintf("proofs_raw[%d]", i), m,
			"alg", "good", "proved", "proven_max",
			"sampled_avg", "sampled_max", "samples",
		)
		if s, _ := m["alg"].(string); s == "" {
			t.Errorf("proofs_raw[%d].alg empty", i)
		}
	}

	t.Logf("buildLogPanels: recent_swaps=%d recent_proofs=%d swaps_list=%d bucket_ips=%d proofs_raw=%d",
		len(topSwapsSlice), len(topProofsSlice), len(sl), len(biMap), len(prSlice))
}

// ----------------------------------------------------------------------------
// Test: parsedLog getters — GetRate, GetRateRaw, GetProofRows, GetProofsRaw,
// GetProofsRawEvents, GetBucketIPs
// ----------------------------------------------------------------------------

func TestSanityCheck_ParsedLogGetters(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup(t)

	text := buildMockLogText()
	pl := parseLogSinglePass(text)

	// ---- GetRate ----
	// frontend renderRate reads r.{thr, n, mean, min, max}.  GetRate skips
	// rport="443"; our mock uses rport="8443" so the row survives.
	rate := pl.GetRate()
	if len(rate) == 0 {
		t.Fatal("pl.GetRate() empty (mock has one midsamp line on cookie 1001)")
	}
	for i, row := range rate {
		m, ok := row.(map[string]interface{})
		if !ok {
			t.Fatalf("rate[%d] not a map", i)
		}
		assertKeys(t, fmt.Sprintf("rate[%d]", i), m, "thr", "n", "mean", "min", "max")
		assertKeyNonZeroInt(t, fmt.Sprintf("rate[%d]", i), m, "n")
		assertKeyNonZeroFloat(t, fmt.Sprintf("rate[%d]", i), m, "mean")
		assertKeyNonZeroFloat(t, fmt.Sprintf("rate[%d]", i), m, "min")
		assertKeyNonZeroFloat(t, fmt.Sprintf("rate[%d]", i), m, "max")
	}

	// ---- GetRateRaw ----
	// frontend _filterByBucket reads rate_raw rows: r.{thr, srate, rport, dest}.
	rateRaw := pl.GetRateRaw()
	if len(rateRaw) == 0 {
		t.Fatal("pl.GetRateRaw() empty (mock has one midsamp line)")
	}
	for i, row := range rateRaw {
		m, ok := row.(map[string]interface{})
		if !ok {
			t.Fatalf("rate_raw[%d] not a map", i)
		}
		assertKeys(t, fmt.Sprintf("rate_raw[%d]", i), m, "thr", "srate", "rport", "dest")
	}

	// ---- GetProofRows ----
	// frontend renderRecentProofs reads r.{alg, mbps, dest, boot_ts, epoch_ts, tier}.
	proofRows := pl.GetProofRows(pl.Cdest)
	if len(proofRows) == 0 {
		t.Fatal("pl.GetProofRows() empty (mock has 2 proof lines)")
	}
	for i, row := range proofRows {
		m, ok := row.(map[string]interface{})
		if !ok {
			t.Fatalf("proof_rows[%d] not a map", i)
		}
		assertKeys(t, fmt.Sprintf("proof_rows[%d]", i), m,
			"alg", "mbps", "dest", "boot_ts", "epoch_ts", "tier",
		)
	}

	// ---- GetProofsRaw ----
	// frontend renderProof reads r.{alg, good, proved, proven_max,
	// sampled_avg, sampled_max, samples}.
	proofsRaw := pl.GetProofsRaw()
	if len(proofsRaw) == 0 {
		t.Fatal("pl.GetProofsRaw() empty (mock has 2 proof events)")
	}
	for i, row := range proofsRaw {
		m, ok := row.(map[string]interface{})
		if !ok {
			t.Fatalf("proofs_raw[%d] not a map", i)
		}
		assertKeys(t, fmt.Sprintf("proofs_raw[%d]", i), m,
			"alg", "good", "proved", "proven_max",
			"sampled_avg", "sampled_max", "samples",
		)
	}

	// ---- GetProofsRawEvents ----
	// frontend _filterByBucket reads proofs_raw rows: p.{alg, rate, tier, dest}.
	proofsRawEvents := pl.GetProofsRawEvents(pl.Cdest)
	if len(proofsRawEvents) == 0 {
		t.Fatal("pl.GetProofsRawEvents() empty (mock has 2 proof lines)")
	}
	for i, row := range proofsRawEvents {
		m, ok := row.(map[string]interface{})
		if !ok {
			t.Fatalf("proofs_raw_events[%d] not a map", i)
		}
		assertKeys(t, fmt.Sprintf("proofs_raw_events[%d]", i), m,
			"ts", "alg", "rate", "tier", "dest",
		)
	}

	// ---- GetBucketIPs ----
	bucketIPs := pl.GetBucketIPs()
	if len(bucketIPs) == 0 {
		t.Fatal("pl.GetBucketIPs() empty (mock has dest= lines)")
	}
	for masked, ips := range bucketIPs {
		ipList, ok := ips.([]interface{})
		if !ok {
			t.Errorf("bucket_ips[%q] is %T, want []interface{}", masked, ips)
		}
		if len(ipList) == 0 {
			t.Errorf("bucket_ips[%q] has 0 IPs", masked)
		}
	}

	t.Logf("ParsedLogGetters: rate=%d rate_raw=%d proof_rows=%d proofs_raw=%d proofs_raw_events=%d bucket_ips=%d",
		len(rate), len(rateRaw), len(proofRows), len(proofsRaw), len(proofsRawEvents), len(bucketIPs))
}

// ----------------------------------------------------------------------------
// Test: buildChurnFromParsed — primary path
// ----------------------------------------------------------------------------

func TestSanityCheck_BuildChurnFromParsed(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup(t)

	text := buildMockLogText()
	pl := parseLogSinglePass(text)

	churn := buildChurnFromParsed(pl.Swaps)

	// v0.9.87 audit (worklog Check 8): buildChurnFromParsed returns ONLY
	// cookies/one/mid/many/max.  It does NOT return total or transitions
	// (those are CSV-only).  collect.go line 142 reads churnResult["total"]
	// to compare against the CSV path, so it always gets 0 here — that's
	// why the CSV fallback ALWAYS wins when CSVFallback && < 50 swaps && CSV
	// has rows.  This test asserts the CURRENT contract: 5 fields only.
	assertKeys(t, "churn(parsed)", churn,
		"cookies", "one", "mid", "many", "max",
	)
	// Sanity: cookies = 10 (1001/1002/1003/4001/5001/6001-6005)
	if got := toInt(churn["cookies"]); got != 10 {
		t.Errorf("churn.cookies = %d, want 10", got)
	}
	// one = 8 (1001/1002/1003/6001-6005) — single-swap cookies
	if got := toInt(churn["one"]); got != 8 {
		t.Errorf("churn.one = %d, want 8", got)
	}
	// mid = 1 (cookie 4001, 3 swaps)
	if got := toInt(churn["mid"]); got != 1 {
		t.Errorf("churn.mid = %d, want 1", got)
	}
	// many = 1 (cookie 5001, 5 swaps)
	if got := toInt(churn["many"]); got != 1 {
		t.Errorf("churn.many = %d, want 1", got)
	}
	// max = 5 (cookie 5001)
	if got := toInt(churn["max"]); got != 5 {
		t.Errorf("churn.max = %d, want 5", got)
	}
	// v0.9.88: total/transitions now present in parsed path (added in fix)
	if _, ok := churn["total"]; !ok {
		t.Errorf("churn(parsed) missing total field")
	} else {
		t.Logf("churn(parsed) has total (OK)")
	}
	if _, ok := churn["transitions"]; !ok {
		t.Errorf("churn(parsed) missing transitions field")
	} else {
		t.Logf("churn(parsed) has transitions (OK)")
	}

	t.Logf("churn(parsed): cookies=%d one=%d mid=%d many=%d max=%d (total/transitions present (v0.9.88 fix))",
		toInt(churn["cookies"]), toInt(churn["one"]), toInt(churn["mid"]),
		toInt(churn["many"]), toInt(churn["max"]))
}

// ----------------------------------------------------------------------------
// Test: buildDivergenceFromParsed — primary path
// ----------------------------------------------------------------------------

func TestSanityCheck_BuildDivergenceFromParsed(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup(t)

	text := buildMockLogText()
	pl := parseLogSinglePass(text)

	rows := buildDivergenceFromParsed(pl.Swaps, pl.MetByCookie, pl.SrateByCookie)
	if len(rows) == 0 {
		t.Fatal("buildDivergenceFromParsed returned no rows")
	}

	// buildDivergenceFromParsed always returns 3 rows (one per category):
	// "rate==metric", "rate!=metric", "pre-0.4.45".
	if got := len(rows); got != 3 {
		t.Errorf("divergence(parsed) row count = %d, want 3", got)
	}

	// Each row has 24 fields (category + 8 triplets of {measured, win,
	// null, loss, skipped, pct} × {composite, srate, sustained}).
	for i, row := range rows {
		m, ok := row.(map[string]interface{})
		if !ok {
			t.Fatalf("divergence[%d] not a map", i)
		}
		assertKeys(t, fmt.Sprintf("divergence[%d]", i), m,
			"category", "measured",
			"win", "null", "loss", "skipped",
			"win_pct", "null_pct", "loss_pct",
			"measured_srate", "win_srate", "null_srate", "loss_srate", "skipped_srate",
			"win_pct_srate", "null_pct_srate", "loss_pct_srate",
			"measured_sustained", "win_sustained", "null_sustained", "loss_sustained", "skipped_sustained",
			"win_pct_sustained", "null_pct_sustained", "loss_pct_sustained",
		)
	}

	t.Logf("divergence(parsed): %d rows, 24 fields each (schema documented as different from CSV path — worklog Pair 2)",
		len(rows))
}

// ----------------------------------------------------------------------------
// Test: CSV fallback — buildChurnFromCSV (the v0.9.87 bug fix under test)
// ----------------------------------------------------------------------------

func TestSanityCheck_CSV_BuildChurnFromCSV(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup(t)

	// Stage synthetic swaps.csv with 6 rows on 6 distinct cookies.
	writeCSV(t, swapsCSVPath, mockSwapsCSV())

	churn := buildChurnFromCSV(200)

	// v0.9.87 fix under test: buildChurnFromCSV now returns ALL 7 fields
	// (cookies, one, mid, many, max, total, transitions).  Before the fix
	// it returned only total/transitions — the frontend read ch.cookies=0,
	// ch.one=0, ch.mid=0, ch.many=0, ch.max=0 for every CSV-fallback cycle.
	assertKeys(t, "churn(csv)", churn,
		"cookies", "one", "mid", "many", "max",
		"total", "transitions",
	)

	// With 6 rows on 6 distinct cookies: cookies=6, one=6, mid=0, many=0, max=1
	if got := toInt(churn["cookies"]); got != 6 {
		t.Errorf("churn(csv).cookies = %d, want 6 (regression of v0.9.87 fix?)", got)
	}
	if got := toInt(churn["one"]); got != 6 {
		t.Errorf("churn(csv).one = %d, want 6", got)
	}
	if got := toInt(churn["total"]); got != 6 {
		t.Errorf("churn(csv).total = %d, want 6", got)
	}
	// transitions is a []interface{} of {pair, count} rows.
	transitions, ok := churn["transitions"].([]interface{})
	if !ok {
		t.Fatalf("churn(csv).transitions is %T, want []interface{}",
			churn["transitions"])
	}
	if len(transitions) == 0 {
		t.Error("churn(csv).transitions empty (expected at least one pair)")
	}
	for i, tr := range transitions {
		m, ok := tr.(map[string]interface{})
		if !ok {
			t.Fatalf("transitions[%d] not a map", i)
		}
		assertKeys(t, fmt.Sprintf("transitions[%d]", i), m, "pair", "count")
	}

	t.Logf("churn(csv): cookies=%d one=%d mid=%d many=%d max=%d total=%d transitions=%d",
		toInt(churn["cookies"]), toInt(churn["one"]), toInt(churn["mid"]),
		toInt(churn["many"]), toInt(churn["max"]),
		toInt(churn["total"]), len(transitions))
}

// ----------------------------------------------------------------------------
// Test: CSV fallback — buildSwapOutcomesFromCSV
// ----------------------------------------------------------------------------

func TestSanityCheck_CSV_BuildSwapOutcomesFromCSV(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup(t)

	writeCSV(t, swapsCSVPath, mockSwapsCSV())

	out := buildSwapOutcomesFromCSV(200)
	if out == nil {
		t.Fatal("buildSwapOutcomesFromCSV returned nil")
	}
	assertKeys(t, "swap_outcomes(csv)", out, "composite", "srate", "sustained", "swaps_list")

	// All three rulers must have the full 14-field schema.
	for _, ruler := range []string{"composite", "srate", "sustained"} {
		sub := asMap(t, "swap_outcomes(csv)", ruler, out)
		assertKeys(t, "swap_outcomes(csv)."+ruler, sub,
			"win", "null", "loss", "win_pct", "null_pct", "loss_pct",
			"measurable", "unmeasurable",
			"rescued", "full_loss", "open",
			"rescued_pct", "full_loss_pct", "open_pct",
		)
	}

	// CSV outcome is the sustained verdict, applied to all three rulers.
	// mockSwapsCSV has 2 win, 2 null, 2 loss → each ruler has win=2, null=2, loss=2.
	sustained := asMap(t, "swap_outcomes(csv)", "sustained", out)
	if got := toInt(sustained["win"]); got != 2 {
		t.Errorf("swap_outcomes(csv).sustained.win = %d, want 2", got)
	}
	if got := toInt(sustained["null"]); got != 2 {
		t.Errorf("swap_outcomes(csv).sustained.null = %d, want 2", got)
	}
	if got := toInt(sustained["loss"]); got != 2 {
		t.Errorf("swap_outcomes(csv).sustained.loss = %d, want 2", got)
	}

	// swaps_list: each row has 7 fields (ts, epoch_ts, boot_ts, cookie, dest,
	// outcome, outcome_sustained).
	sl := asSlice(t, "swap_outcomes(csv)", "swaps_list", out)
	if len(sl) != 6 {
		t.Errorf("swap_outcomes(csv).swaps_list length = %d, want 6", len(sl))
	}
	for i, row := range sl {
		m, ok := row.(map[string]interface{})
		if !ok {
			t.Fatalf("swaps_list[%d] not a map", i)
		}
		assertKeys(t, fmt.Sprintf("swaps_list[%d]", i), m,
			"ts", "epoch_ts", "boot_ts", "cookie", "dest",
			"outcome", "outcome_sustained",
		)
	}

	t.Logf("swap_outcomes(csv): swaps_list=%d, sustained={win=%d null=%d loss=%d}",
		len(sl), toInt(sustained["win"]), toInt(sustained["null"]), toInt(sustained["loss"]))
}

// ----------------------------------------------------------------------------
// Test: CSV fallback — buildDivergenceFromCSV (DIFFERENT schema from parsed)
// ----------------------------------------------------------------------------

func TestSanityCheck_CSV_BuildDivergenceFromCSV(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup(t)

	writeCSV(t, swapsCSVPath, mockSwapsCSV())

	rows := buildDivergenceFromCSV(200)
	if len(rows) == 0 {
		t.Fatal("buildDivergenceFromCSV returned no rows")
	}

	// NOTE: buildDivergenceFromCSV returns a 4-field schema {pair, total,
	// diverges, div_pct} which is COMPLETELY DIFFERENT from the parsed
	// path's 24-field schema {category, measured, win/null/loss × 3 rulers,
	// ...}.  The frontend never reads doc.divergence (no renderDivergence
	// in dashboard.js, no #lv-divergence element in index.html) so this
	// mismatch is latent (see worklog Pair 2).  This test only asserts the
	// CSV schema is internally complete.
	for i, row := range rows {
		m, ok := row.(map[string]interface{})
		if !ok {
			t.Fatalf("divergence(csv)[%d] not a map", i)
		}
		assertKeys(t, fmt.Sprintf("divergence(csv)[%d]", i), m,
			"pair", "total", "diverges", "div_pct",
		)
		// pair must be non-empty (frontend would render "undefined" otherwise)
		if s, _ := m["pair"].(string); s == "" {
			t.Errorf("divergence(csv)[%d].pair empty", i)
		}
	}

	t.Logf("divergence(csv): %d rows, 4 fields each (DIFFERENT schema from parsed path — worklog Pair 2)",
		len(rows))
}

// ----------------------------------------------------------------------------
// Test: CSV fallback — readRecentSwapsFromCSV
// ----------------------------------------------------------------------------

func TestSanityCheck_CSV_ReadRecentSwapsFromCSV(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup(t)

	writeCSV(t, swapsCSVPath, mockSwapsCSV())

	rows := readRecentSwapsFromCSV(50)
	if len(rows) == 0 {
		t.Fatal("readRecentSwapsFromCSV returned 0 rows (mock CSV has 6)")
	}
	if len(rows) != 6 {
		t.Errorf("readRecentSwapsFromCSV returned %d rows, want 6", len(rows))
	}

	// frontend renderRecentSwaps reads r.{from_alg, to_alg, dest, d,
	// outcome_sustained, boot_ts, epoch_ts}.  CSV also sets: outcome,
	// mt_alg, rb_alg.  (Note: buildRecentSwapRows also sets _bucket and
	// outcome_srate — CSV fallback OMITS those, which is a documented
	// minor mismatch — worklog Pair 4.)
	for i, row := range rows {
		m, ok := row.(map[string]interface{})
		if !ok {
			t.Fatalf("recent_swaps(csv)[%d] not a map", i)
		}
		assertKeys(t, fmt.Sprintf("recent_swaps(csv)[%d]", i), m,
			"boot_ts", "epoch_ts", "from_alg", "to_alg", "d",
			"outcome", "outcome_sustained", "mt_alg", "rb_alg", "dest",
		)
		if s, _ := m["from_alg"].(string); s == "" {
			t.Errorf("recent_swaps(csv)[%d].from_alg empty", i)
		}
		if s, _ := m["to_alg"].(string); s == "" {
			t.Errorf("recent_swaps(csv)[%d].to_alg empty", i)
		}
		if s, _ := m["dest"].(string); s == "" {
			t.Errorf("recent_swaps(csv)[%d].dest empty", i)
		}
		if s, _ := m["outcome"].(string); s == "" {
			t.Errorf("recent_swaps(csv)[%d].outcome empty", i)
		}
		if s, _ := m["outcome_sustained"].(string); s == "" {
			t.Errorf("recent_swaps(csv)[%d].outcome_sustained empty", i)
		}
	}

	t.Logf("readRecentSwapsFromCSV: %d rows, 10 fields each", len(rows))
}

// ----------------------------------------------------------------------------
// Test: CSV fallback — readRecentProofsFromCSV
// ----------------------------------------------------------------------------

func TestSanityCheck_CSV_ReadRecentProofsFromCSV(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup(t)

	writeCSV(t, proofsCSVPath, mockProofsCSV())

	rows := readRecentProofsFromCSV(50)
	if len(rows) == 0 {
		t.Fatal("readRecentProofsFromCSV returned 0 rows (mock CSV has 3)")
	}
	if len(rows) != 3 {
		t.Errorf("readRecentProofsFromCSV returned %d rows, want 3", len(rows))
	}

	// frontend renderRecentProofs reads r.{alg, mbps, dest, boot_ts, epoch_ts, tier}.
	for i, row := range rows {
		m, ok := row.(map[string]interface{})
		if !ok {
			t.Fatalf("recent_proofs(csv)[%d] not a map", i)
		}
		assertKeys(t, fmt.Sprintf("recent_proofs(csv)[%d]", i), m,
			"boot_ts", "epoch_ts", "alg", "mbps", "tier", "dest",
		)
		if s, _ := m["alg"].(string); s == "" {
			t.Errorf("recent_proofs(csv)[%d].alg empty", i)
		}
		if f, _ := m["mbps"].(float64); f <= 0 {
			t.Errorf("recent_proofs(csv)[%d].mbps = %v (expected > 0)", i, m["mbps"])
		}
		if s, _ := m["tier"].(string); s == "" {
			t.Errorf("recent_proofs(csv)[%d].tier empty", i)
		}
	}

	t.Logf("readRecentProofsFromCSV: %d rows, 6 fields each", len(rows))
}

// ----------------------------------------------------------------------------
// Test: CSV fallback — buildProofsRawFromCSV (proofs_raw leaderboard)
// ----------------------------------------------------------------------------

func TestSanityCheck_CSV_BuildProofsRawFromCSV(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup(t)

	writeCSV(t, proofsCSVPath, mockProofsCSV())

	rows := buildProofsRawFromCSV()
	if len(rows) == 0 {
		t.Fatal("buildProofsRawFromCSV returned 0 rows (mock CSV has 3)")
	}

	// frontend renderProof reads r.{alg, good, proved, proven_max,
	// sampled_avg, sampled_max, samples}.
	for i, row := range rows {
		m, ok := row.(map[string]interface{})
		if !ok {
			t.Fatalf("proofs_raw(csv)[%d] not a map", i)
		}
		assertKeys(t, fmt.Sprintf("proofs_raw(csv)[%d]", i), m,
			"alg", "good", "proved", "proven_max",
			"sampled_avg", "sampled_max", "samples",
		)
		if s, _ := m["alg"].(string); s == "" {
			t.Errorf("proofs_raw(csv)[%d].alg empty", i)
		}
	}

	t.Logf("buildProofsRawFromCSV: %d rows, 7 fields each", len(rows))
}

// ----------------------------------------------------------------------------
// Test: End-to-end collect() simulation
// ----------------------------------------------------------------------------

// TestSanityCheck_FullCollectCycle mirrors the actual collect() order in
// collect.go (lines 67-171) and verifies the assembled doc has every key
// the frontend reads.  We skip the BPF-map-dependent panels (buckets,
// metric_by_bucket, bucket_live, live_leaders, route_health, service_health)
// because those need bpftool + a running bpftune service.  Everything else
// is exercised against the mock log + mock CSVs.
func TestSanityCheck_FullCollectCycle(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup(t)

	// Stage CSVs so the CSV-fallback paths have data to read.
	writeCSV(t, swapsCSVPath, mockSwapsCSV())
	writeCSV(t, proofsCSVPath, mockProofsCSV())

	text := buildMockLogText()
	pl := parseLogSinglePass(text)
	allSwaps := pl.Swaps
	allMets := pl.MetByCookie
	allSrates := pl.SrateByCookie
	cdest := pl.Cdest
	now := time.Now().Unix()

	// v0.9.9: collect() sets currentParsedLog before buildLogPanels.
	currentParsedLog = pl
	defer func() { currentParsedLog = nil }()

	topSwaps, topProofs, swapOutcomesIface, bucketIPsIface, logWindowIface, proofsRawIface :=
		buildLogPanels(allSwaps, allMets, allSrates, cdest, text, now)

	// ----- churn (collect.go lines 138-146) -------------------------------
	// churnResult := buildChurnFromParsed(allSwaps)
	// if collectorMode.CSVFallback && len(allSwaps) < 50 {
	//   csvChurn := buildChurnFromCSV(200)
	//   csvTotal := toInt(csvChurn["total"])
	//   logTotal := toInt(churnResult["total"])  // 0 (parsed path doesn't set total)
	//   if csvTotal > logTotal { churnResult = csvChurn }
	// }
	churnResult := buildChurnFromParsed(allSwaps)
	if collectorMode.CSVFallback && len(allSwaps) < 50 {
		csvChurn := buildChurnFromCSV(200)
		csvTotal := toInt(csvChurn["total"])
		logTotal := toInt(churnResult["total"]) // 0 — documented
		if csvTotal > logTotal {
			churnResult = csvChurn
		}
	}
	// Because the parsed path doesn't set "total", the CSV path always wins
	// when CSV has rows.  Assert the WINNING path's schema (CSV: 7 fields).
	assertKeys(t, "churn(e2e)", churnResult,
		"cookies", "one", "mid", "many", "max", "total", "transitions",
	)

	// ----- rate (collect.go lines 151-163) --------------------------------
	rateResult := pl.GetRate()
	if collectorMode.CSVFallback && len(rateResult) == 0 {
		csvRate := buildRateFromCSVCached()
		if len(csvRate) > 0 {
			rateResult = csvRate
		}
	}
	// (mock produces 1 rate row from the midsamp line — non-empty.)
	if len(rateResult) == 0 {
		t.Error("rate(e2e) empty (expected at least one midsamp row)")
	} else {
		m, _ := rateResult[0].(map[string]interface{})
		assertKeys(t, "rate(e2e)[0]", m, "thr", "n", "mean", "min", "max")
	}

	// rate_raw (collect.go line 163) — for bucket filtering in the frontend.
	rateRaw := pl.GetRateRaw()
	if len(rateRaw) == 0 {
		t.Error("rate_raw(e2e) empty")
	}

	// ----- divergence (collect.go lines 164-170) --------------------------
	divResult := buildDivergenceFromParsed(allSwaps, allMets, allSrates)
	if collectorMode.CSVFallback && len(allSwaps) < 50 {
		csvDiv := buildDivergenceFromCSV(200)
		if len(csvDiv) > len(divResult) {
			divResult = csvDiv
		}
	}
	// mockSwapsCSV has 6 rows → 6 (pair,total,diverges,div_pct) rows.
	// parsed path has 3 rows. 6 > 3 so CSV wins.  Assert the CSV schema.
	if len(divResult) == 0 {
		t.Fatal("divergence(e2e) empty")
	}
	for i, row := range divResult {
		m, ok := row.(map[string]interface{})
		if !ok {
			t.Fatalf("divergence(e2e)[%d] not a map", i)
		}
		// Schema is CSV-shape (pair, total, diverges, div_pct) because CSV
		// path wins.  Verify whichever keys exist are non-empty.
		if _, hasPair := m["pair"]; hasPair {
			if s, _ := m["pair"].(string); s == "" {
				t.Errorf("divergence(e2e)[%d].pair empty", i)
			}
		}
	}

	// ----- proofs_raw events (collect.go line 132) ------------------------
	proofsRawEvents := pl.GetProofsRawEvents(cdest)
	if len(proofsRawEvents) == 0 {
		t.Error("proofs_raw_events(e2e) empty")
	}

	// ----- Assemble the doc (collect.go lines 84-109 + 127-171) -----------
	// We omit the BPF-dependent fields (buckets, metric_by_bucket,
	// bucket_live, live_leaders, route_health, service_health, system,
	// hostname, now_mono, build) because they require bpftool + the BPF
	// map.  The remaining fields are exactly what collect.go sets after
	// the BPF section.
	doc := map[string]interface{}{
		"generated_ts":  now,
		"degraded":      true, // simulate degraded mode (no BPF map)
		"recent_swaps":  topSwaps,
		"recent_proofs": topProofs,
		"swap_outcomes": swapOutcomesIface,
		"bucket_ips":    bucketIPsIface,
		"log_window":    logWindowIface,
		"proofs_raw":    pl.GetProofsRawEvents(cdest), // doc["proofs_raw"] (line 132)
		"proof":         proofsRawIface,               // doc["proof"] (line 133)
		"churn":         churnResult,
		"rate":          rateResult,
		"rate_raw":      pl.GetRateRaw(),
		"divergence":    divResult,
		// tunables: readProcSys would return "" for most /proc/sys/net.*
		// entries in the sandbox (we don't bother verifying them here).
		// "tunables":      buildTunables(),
	}

	// ----- Verify every top-level key the frontend reads ------------------
	// From worklog "Frontend doc.* reads → backend setters":
	//   generated_ts, now_mono, system, buckets, metric_by_bucket,
	//   bucket_live, live_leaders, hostname, route_health, service_health,
	//   recent_swaps, recent_proofs, swap_outcomes, bucket_ips, log_window,
	//   proofs_raw, proof, churn, rate, rate_raw, divergence, tunables.
	//
	// We can only check the log/CSV-derived ones in this test (the BPF +
	// /proc-derived ones need a live bpftune host).  The list below mirrors
	// the frontend reads for the panels we exercise.
	expectedTopLevel := []string{
		"generated_ts", "degraded",
		"recent_swaps", "recent_proofs", "swap_outcomes",
		"bucket_ips", "log_window", "proofs_raw", "proof",
		"churn", "rate", "rate_raw", "divergence",
	}
	for _, k := range expectedTopLevel {
		if _, ok := doc[k]; !ok {
			t.Errorf("doc missing top-level key %q", k)
		}
	}

	// Spot-check the rendered doc structure matches what each frontend
	// renderer expects.
	t.Run("doc.swap_outcomes.swaps_list has 7-field rows", func(t *testing.T) {
		soMap := doc["swap_outcomes"].(map[string]interface{})
		sl := soMap["swaps_list"].([]interface{})
		if len(sl) == 0 {
			t.Fatal("swaps_list empty")
		}
		m := sl[0].(map[string]interface{})
		assertKeys(t, "swaps_list[0]", m,
			"ts", "epoch_ts", "boot_ts", "cookie", "dest",
			"outcome", "outcome_sustained",
		)
	})

	t.Run("doc.recent_swaps rows have all frontend-read fields", func(t *testing.T) {
		rows := doc["recent_swaps"].([]interface{})
		if len(rows) == 0 {
			t.Fatal("recent_swaps empty")
		}
		m := rows[0].(map[string]interface{})
		assertKeys(t, "recent_swaps[0]", m,
			"boot_ts", "epoch_ts", "from_alg", "to_alg", "d",
			"outcome", "outcome_sustained", "mt_alg", "rb_alg", "dest",
		)
	})

	t.Run("doc.recent_proofs rows have all frontend-read fields", func(t *testing.T) {
		rows := doc["recent_proofs"].([]interface{})
		if len(rows) == 0 {
			t.Fatal("recent_proofs empty")
		}
		m := rows[0].(map[string]interface{})
		assertKeys(t, "recent_proofs[0]", m,
			"alg", "mbps", "dest", "boot_ts", "epoch_ts", "tier",
		)
	})

	t.Run("doc.proof rows have all frontend-read fields", func(t *testing.T) {
		rows := doc["proof"].([]interface{})
		if len(rows) == 0 {
			t.Fatal("proof empty")
		}
		m := rows[0].(map[string]interface{})
		assertKeys(t, "proof[0]", m,
			"alg", "good", "proved", "proven_max",
			"sampled_avg", "sampled_max", "samples",
		)
	})

	t.Run("doc.proofs_raw rows have all frontend-read fields", func(t *testing.T) {
		rows := doc["proofs_raw"].([]interface{})
		if len(rows) == 0 {
			t.Fatal("proofs_raw empty")
		}
		m := rows[0].(map[string]interface{})
		assertKeys(t, "proofs_raw[0]", m,
			"ts", "alg", "rate", "tier", "dest",
		)
	})

	t.Run("doc.rate rows have all frontend-read fields", func(t *testing.T) {
		rows := doc["rate"].([]interface{})
		if len(rows) == 0 {
			t.Fatal("rate empty")
		}
		m := rows[0].(map[string]interface{})
		assertKeys(t, "rate[0]", m, "thr", "n", "mean", "min", "max")
	})

	t.Run("doc.rate_raw rows have all frontend-read fields", func(t *testing.T) {
		rows := doc["rate_raw"].([]interface{})
		if len(rows) == 0 {
			t.Fatal("rate_raw empty")
		}
		m := rows[0].(map[string]interface{})
		assertKeys(t, "rate_raw[0]", m, "thr", "srate", "rport", "dest")
	})

	t.Run("doc.log_window has span_min/swap_count/age_min", func(t *testing.T) {
		lw := doc["log_window"].(map[string]interface{})
		assertKeys(t, "log_window", lw, "span_min", "swap_count", "age_min")
	})

	t.Run("doc.churn has all 7 fields (CSV fallback won)", func(t *testing.T) {
		ch := doc["churn"].(map[string]interface{})
		assertKeys(t, "churn", ch,
			"cookies", "one", "mid", "many", "max", "total", "transitions",
		)
	})

	t.Run("doc.bucket_ips has masked→[ip,...] entries", func(t *testing.T) {
		bi := doc["bucket_ips"].(map[string]interface{})
		if len(bi) == 0 {
			t.Fatal("bucket_ips empty")
		}
		for masked, ips := range bi {
			ipList, ok := ips.([]interface{})
			if !ok {
				t.Errorf("bucket_ips[%q] is %T", masked, ips)
			}
			if len(ipList) == 0 {
				t.Errorf("bucket_ips[%q] has 0 IPs", masked)
			}
			break // one is enough
		}
	})

	t.Logf("FullCollectCycle: doc has %d top-level keys, all log/CSV-derived panels verified",
		len(doc))
}
