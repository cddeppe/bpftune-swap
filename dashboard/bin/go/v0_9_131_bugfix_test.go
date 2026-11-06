package main

// v0_9_131_bugfix_test.go — regression tests for the four bugs found by a
// second independent audit (pre-v0.9.130 code) and verified against the
// v0.9.131 tree:
//
//  1. writeBucketSQLite's "60s throttle" was a per-CALL parity counter —
//     it advanced once per HOST, so with an even host count the
//     odd-positioned hosts were NEVER written to SQLite (silent data
//     loss for half the buckets). Fixed with a time-based gate.
//
//  2. collect.go stamped every midsamp row with Cookie:0 / Ts:now, so
//     writeMidsampCSV's "cookie:ts" dedup key was identical for all rows
//     of a cycle and only the FIRST row survived — midsamp.csv got at
//     most one sample per 30s. Fixed by passing each event's own
//     cookie/boot-ts through (midsampRow.Ts / midsampRow.Cookie).
//
//  3. The dynamic /data/swaps.json fallback served swap_outcomes — a
//     different shape than the static {range:{ts,swaps}} file — so the
//     frontend's doc[rng] was undefined on that path. Fixed by serving
//     the static file whenever it exists.
//
//  4. renderToDisk stat'ed a hardcoded /var/lib/bpftune/... path for its
//     buckets.v2.csv mtime cache, ignoring --data-root. Fixed by using
//     bucketsCSVPath.

import (
        "fmt"
        "net/http"
        "net/http/httptest"
        "os"
        "path/filepath"
        "strings"
        "sync"
        "testing"
        "time"
)

// ============================================================================
// Bug 1 — SQLite write throttle must not depend on host count
// ============================================================================

// TestV0_9_131_SQLiteEvenHostCountAllWritten reproduces the exact
// production failure shape: an EVEN number of hosts (324 on the main
// host), each written once per cycle via the collect.go loop. The old
// parity counter permanently dropped every odd-positioned host; the
// time-based gate must write the whole fleet in the first allowed pass.
func TestV0_9_131_SQLiteEvenHostCountAllWritten(t *testing.T) {
        dir := t.TempDir()
        origHist := histDir
        histDir = dir
        defer func() { histDir = origHist }()

        resetSQLiteForTest()
        sqliteDB = nil
        openTestDB(t, dir)
        lastWriteHash = make(map[string]uint64, 8)
        lastPreHash = make(map[string]uint64, 8)
        sqliteWriteMu.Lock()
        sqliteLastWriteAt = 0
        sqliteWriteMu.Unlock()

        const nHosts = 324 // even — the exact worst case
        now := int64(1700000000)

        for i := 0; i < nHosts; i++ {
                addr := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
                h := hostEntry{
                        Addr: addr,
                        Inst: 2, // collect.go skips Inst < 2; keep >= 2
                        V: map[string]interface{}{
                                "best_i": i % 16,
                                "min_rtt": float64(i),
                                // Distinct data per host so the dedup hash cannot
                                // legitimately skip any of them.
                                "metrics": []interface{}{
                                        map[string]interface{}{
                                                "metric_value": float64(1000 + i),
                                                "metric_count": 1,
                                                "rate_ema":     float64(2000 + i),
                                        },
                                },
                        },
                }
                writeBucketSQLite(h, now, 4096, 87380, 6291456)
        }

        count := sqliteRowCount(t)
        if count != nHosts {
                t.Fatalf("DATA LOSS: %d of %d hosts written (even host count = the "+
                        "old parity-counter bug). Expected all %d rows in one pass.",
                        count, nHosts, nHosts)
        }

        // The very next cycle (30s later) must be fully throttled — the
        // whole fleet, not alternating hosts.
        for i := 0; i < nHosts; i++ {
                addr := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
                h := hostEntry{Addr: addr, Inst: 2, V: map[string]interface{}{
                        "best_i": (i + 1) % 16,
                        "metrics": []interface{}{
                                map[string]interface{}{"metric_value": float64(9000 + i), "metric_count": 2},
                        },
                }}
                writeBucketSQLite(h, now+30, 4096, 87380, 6291456)
        }
        count2 := sqliteRowCount(t)
        if count2 != nHosts {
                t.Fatalf("30s pass wrote %d new rows; expected 0 (fully throttled)", count2-nHosts)
        }

        // 60s after the last pass the whole fleet is written again.
        for i := 0; i < nHosts; i++ {
                addr := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
                h := hostEntry{Addr: addr, Inst: 2, V: map[string]interface{}{
                        "best_i": (i + 2) % 16,
                        "metrics": []interface{}{
                                map[string]interface{}{"metric_value": float64(12000 + i), "metric_count": 3},
                        },
                }}
                writeBucketSQLite(h, now+90, 4096, 87380, 6291456)
        }
        count3 := sqliteRowCount(t)
        if count3 != 2*nHosts {
                t.Fatalf("after next allowed pass: expected %d rows, got %d", 2*nHosts, count3)
        }
        t.Logf("OK 324-host fleet: pass 1 → %d rows, 30s pass → throttled, 90s pass → %d rows",
                count, count3)
}

// TestV0_9_131_SQLiteThrottleGateSemantics pins the gate itself.
func TestV0_9_131_SQLiteThrottleGateSemantics(t *testing.T) {
        sqliteWriteMu.Lock()
        sqliteLastWriteAt = 0
        sqliteWriteMu.Unlock()

        const base = int64(1700000000)
        if !sqliteThrottleAllows(base) {
                t.Fatal("first call must allow (no previous pass)")
        }
        if !sqliteThrottleAllows(base) {
                t.Fatal("same-cycle caller must share the allow verdict")
        }
        if !sqliteThrottleAllows(base) {
                t.Fatal("same-cycle caller (again) must still be allowed")
        }
        if sqliteThrottleAllows(base + 30) {
                t.Fatal("30s after a pass must be throttled")
        }
        if sqliteThrottleAllows(base + 44) {
                t.Fatal("44s after a pass must be throttled")
        }
        if !sqliteThrottleAllows(base + 45) {
                t.Fatal("45s after a pass must allow (boundary)")
        }
        if sqliteThrottleAllows(base + 45 + 10) {
                t.Fatal("10s after the newest pass must be throttled")
        }
        t.Logf("OK gate semantics: same-cycle share, ≥45s gap, boundary allow")
}

// ============================================================================
// Bug 2 — midsamp.csv must keep every event of a cycle
// ============================================================================

// TestV0_9_131_MidsampOneRowPerEvent writes several midsamp events that
// share collected-ts (as one collect cycle produces) but have distinct
// cookie:ts identity — exactly what the fixed collect.go passes. All of
// them must land in midsamp.csv. The old code stamped Cookie:0/Ts:now on
// every row, collapsing them to one.
func TestV0_9_131_MidsampOneRowPerEvent(t *testing.T) {
        dir := t.TempDir()
        origMid := midsampCSVPath
        midsampCSVPath = filepath.Join(dir, "midsamp.csv")
        defer func() { midsampCSVPath = origMid }()
        dedupMu.Lock()
        saved := writtenMidsampsFlat
        writtenMidsampsFlat = map[string]bool{}
        dedupMu.Unlock()
        defer func() {
                dedupMu.Lock()
                writtenMidsampsFlat = saved
                dedupMu.Unlock()
        }()

        now := int64(1700000000)
        var evs []midsampEvent
        for i := 0; i < 7; i++ {
                evs = append(evs, midsampEvent{
                        Ts:     12345.6 + float64(i), // distinct boot ktime per event
                        Cookie: int64(1000 + i),     // distinct cookie per event
                        Rport:  "8443",
                        Alg:    -1,
                        Thr:    1000000,
                        Srate:  int64(1500000 + i),
                })
        }
        writeMidsampCSV(evs, now)

        data, err := os.ReadFile(midsampCSVPath)
        if err != nil {
                t.Fatalf("midsamp.csv not written: %v", err)
        }
        lines := strings.Split(strings.TrimSpace(string(data)), "\n")
        // 1 header + 7 rows
        if len(lines) != 8 {
                t.Fatalf("expected 1 header + 7 rows, got %d lines:\n%s", len(lines), data)
        }
        for i, want := range []string{"1000", "1001", "1002"} {
                if i >= len(lines)-1 {
                        break
                }
                if !strings.Contains(lines[1+i], want) {
                        t.Errorf("row %d missing cookie %s: %q", 1+i, want, lines[1+i])
                }
        }

        // The OLD bug shape — every row sharing one identity — must still
        // collapse to one row (dedup is correct, the identity was wrong).
        dedupMu.Lock()
        writtenMidsampsFlat = map[string]bool{}
        dedupMu.Unlock()
        bad := make([]midsampEvent, 5)
        for i := range bad {
                bad[i] = midsampEvent{Ts: float64(now), Cookie: 0, Rport: "8443", Alg: -1, Thr: 1, Srate: int64(i)}
        }
        writeMidsampCSV(bad, now)
        data2, _ := os.ReadFile(midsampCSVPath)
        rows := strings.Split(strings.TrimSpace(string(data2)), "\n")
        if len(rows) != 9 { // 8 previous + 1 (only the first fake-identity row)
                t.Errorf("shared-identity events should collapse to 1 row, got %d total rows", len(rows)-8)
        }
        t.Logf("OK midsamp: 7 distinct events → 7 rows; shared identity collapses (dedup intact)")
}

// TestV0_9_131_MidsampParserCarriesIdentity pins the singlepass side of
// the fix: midsampRow must carry the event's own ts + cookie so collect.go
// can build the dedup identity.
func TestV0_9_131_MidsampParserCarriesIdentity(t *testing.T) {
        log := "100.5: bpf_trace_printk: midsamp cookie=4242 thr=1000000 rport=8443 srate=1500000\n" +
                "101.5: bpf_trace_printk: midsamp cookie=4243 thr=1000000 rport=8443 srate=1600000\n" +
                "102.5: bpf_trace_printk: midsamp cookie=4244 thr=1000000 rport=8443 srate=1700000\n"
        pl := parseLogSinglePass(log)
        if len(pl.MidsampRows) != 3 {
                t.Fatalf("expected 3 midsamp rows, got %d", len(pl.MidsampRows))
        }
        wantTs := []float64{100.5, 101.5, 102.5}
        wantCookie := []int64{4242, 4243, 4244}
        for i, mr := range pl.MidsampRows {
                if mr.Ts != wantTs[i] || mr.Cookie != wantCookie[i] {
                        t.Errorf("row %d: got (ts=%.3f cookie=%d), want (%.3f, %d)",
                                i, mr.Ts, mr.Cookie, wantTs[i], wantCookie[i])
                }
        }
        t.Logf("OK midsampRow carries per-event ts+cookie identity")
}

// ============================================================================
// Bug 3 — /data/swaps.json fallback must serve the static shape
// ============================================================================

// TestV0_9_131_SwapsJSONFallbackServesStaticFile checks the handler-level
// behaviour: when the static swaps.json exists, the response must be its
// bytes ({ranges, "1h":{ts,swaps},...}), never the swap_outcomes shape.
func TestV0_9_131_SwapsJSONFallbackServesStaticFile(t *testing.T) {
        dir := t.TempDir()
        origHist := histDir
        histDir = dir
        defer func() { histDir = origHist }()
        os.MkdirAll(filepath.Join(dir, "data"), 0755)

        staticBody := `{"generated_ts":1700000000,"ranges":["1h","24h"],"1h":{"ts":[1700000000],"swaps":[3]}}`
        staticPath := filepath.Join(dir, "data", "swaps.json")
        if err := os.WriteFile(staticPath, []byte(staticBody), 0644); err != nil {
                t.Fatal(err)
        }
        // Backdate the file so the request path treats it as stale — the fix
        // must serve it anyway (the old dynamic fallback fired on staleness).
        old := time.Now().Add(-30 * time.Minute)
        os.Chtimes(staticPath, old, old)

        c := NewCollector()
        req := httptest.NewRequest("GET", "/data/swaps.json", nil)
        rec := httptest.NewRecorder()
        c.handleIndex(rec, req)

        body := rec.Body.String()
        if rec.Code != http.StatusOK {
                t.Fatalf("status = %d, want 200", rec.Code)
        }
        if !strings.Contains(body, `"swaps"`) || !strings.Contains(body, `"ranges"`) {
                t.Fatalf("fallback served wrong shape (want static {ranges, per-range ts/swaps}):\n%s", body)
        }
        if strings.Contains(body, "composite") || strings.Contains(body, "sustained") {
                t.Fatalf("fallback served swap_outcomes shape (the bug):\n%s", body)
        }
        t.Logf("OK /data/swaps.json fallback serves the static shape even when stale")
}

// TestV0_9_131_SwapsJSONColdStartEmptyObject pins the cold-start branch:
// no static file → {} with 200, never a 404 or a wrong-shape body.
func TestV0_9_131_SwapsJSONColdStartEmptyObject(t *testing.T) {
        dir := t.TempDir()
        origHist := histDir
        histDir = dir
        defer func() { histDir = origHist }()

        c := NewCollector()
        req := httptest.NewRequest("GET", "/data/swaps.json", nil)
        rec := httptest.NewRecorder()
        c.handleIndex(rec, req)

        if rec.Code != http.StatusOK {
                t.Fatalf("status = %d, want 200", rec.Code)
        }
        if strings.TrimSpace(rec.Body.String()) != "{}" {
                t.Fatalf("cold-start body = %q, want {}", rec.Body.String())
        }
        t.Logf("OK cold start returns {} (200)")
}

// TestV0_9_131_NoSwapOutcomesSwapsHandler pins the removal: the wrong-
// shape handler is gone and main.go no longer serves swap_outcomes at
// /data/swaps.json.
func TestV0_9_131_NoSwapOutcomesSwapsHandler(t *testing.T) {
        src, err := os.ReadFile("main.go")
        if err != nil {
                t.Skip("main.go not readable from test working dir")
        }
        s := string(src)
        if strings.Contains(s, "handleSwapsJSON") {
                t.Fatal("main.go still routes /data/swaps.json to handleSwapsJSON (wrong shape)")
        }
        h, err := os.ReadFile("http_handlers.go")
        if err == nil && strings.Contains(string(h), "func (h *historyStore) handleSwapsJSON") {
                t.Fatal("handleSwapsJSON still exists — it serves the wrong shape")
        }
        t.Logf("OK swap_outcomes no longer served at /data/swaps.json")
}

// ============================================================================
// Bug 4 — render mtime cache must track the configured CSV path
// ============================================================================

// TestV0_9_131_RenderMtimeProbeUsesConfiguredPath pins the fix at source
// level (the repo's established style for this kind of pin): render.go
// must stat bucketsCSVPath, never a hardcoded /var/lib path.
func TestV0_9_131_RenderMtimeProbeUsesConfiguredPath(t *testing.T) {
        src, err := os.ReadFile("render.go")
        if err != nil {
                t.Skip("render.go not readable from test working dir")
        }
        s := string(src)
        if strings.Contains(s, `os.Stat("/var/lib/bpftune/history/buckets.v2.csv")`) {
                t.Fatal("render.go still stats the hardcoded /var/lib path — " +
                        "--data-root runs never refresh csvAll (or track the wrong file)")
        }
        if !strings.Contains(s, "os.Stat(bucketsCSVPath)") {
                t.Fatal("render.go does not stat bucketsCSVPath (--data-root-aware var)")
        }
        t.Logf("OK render mtime probe uses bucketsCSVPath")
}

// ============================================================================
// Concurrency — the new throttle gate under -race
// ============================================================================

func TestV0_9_131_ThrottleGateConcurrent(t *testing.T) {
        sqliteWriteMu.Lock()
        sqliteLastWriteAt = 0
        sqliteWriteMu.Unlock()

        var wg sync.WaitGroup
        for g := 0; g < 16; g++ {
                wg.Add(1)
                go func(g int) {
                        defer wg.Done()
                        for i := 0; i < 100; i++ {
                                sqliteThrottleAllows(int64(1700000000 + i*30 + g))
                        }
                }(g)
        }
        wg.Wait()
        t.Logf("OK throttle gate survives concurrent hammering (16x100)")
}
