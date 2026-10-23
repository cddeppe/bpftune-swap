package main

// perf_lean_test.go — v0.9.108-lean: byte-identity tests + benchmarks.
//
// These tests prove that the v0.9.108 performance changes produce
// IDENTICAL output to the v0.9.104 implementations:
//   - readLogTailCached()   vs readLogTail() reference (tail bytes)
//   - buildDocRaw()         vs json.Marshal (document bytes)
//   - notifySSEFromRaw()    vs json.Marshal of the SSE message maps
//   - snapshotPreHash()     equivalence with the serialized-row hash
//   - rebuildBucketLiveFromRing typed series vs boxed series JSON
//   - GetProofRows/GetProofsRawEvents (parsedProofs path) vs the
//     v0.9.104 rxProof re-scan reference
//
// The benchmarks compare the new hot paths against the v0.9.104 work
// patterns on the same runner (ns/op + allocs/op) for A/B measurement.
//
// All helpers are prefixed "perf" to avoid collisions with the existing
// suites (v0_9_104_test.go, regression_test.go, sanitycheck*.go).

import (
        "bytes"
        "crypto/md5"
        "encoding/json"
        "fmt"
        "os"
        "path/filepath"
        "sort"
        "strconv"
        "strings"
        "testing"
        "time"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// perfWriteFile writes content to path and sets a deterministic mtime so
// newest-first ordering is stable across test runs.
func perfWriteFile(t *testing.T, path, content string, mtime time.Time) {
        t.Helper()
        if err := os.WriteFile(path, []byte(content), 0644); err != nil {
                t.Fatalf("write %s: %v", path, err)
        }
        if err := os.Chtimes(path, mtime, mtime); err != nil {
                t.Fatalf("chtimes %s: %v", path, err)
        }
}

// perfReferenceReadLogTail is a byte-exact copy of v0.9.104's
// readLogTail() operating on logGlobPattern (used as the oracle).
func perfReferenceReadLogTail(budget int64) string {
        files, _ := filepath.Glob(logGlobPattern)
        if len(files) == 0 {
                return ""
        }
        sort.Slice(files, func(i, j int) bool {
                fi, _ := os.Stat(files[i])
                fj, _ := os.Stat(files[j])
                return fi.ModTime().After(fj.ModTime())
        })
        var sb strings.Builder
        remaining := budget
        for _, p := range files {
                if remaining <= 0 {
                        break
                }
                fi, err := os.Stat(p)
                if err != nil {
                        continue
                }
                size := fi.Size()
                take := size
                if take > remaining {
                        take = remaining
                }
                f, err := os.Open(p)
                if err != nil {
                        continue
                }
                _, _ = f.Seek(size-take, 0)
                buf := make([]byte, take)
                _, _ = f.Read(buf)
                f.Close()
                sb.Write(buf)
                sb.WriteByte('\n')
                remaining -= take
        }
        return sb.String()
}

// perfMakeDoc builds a representative dashboard document (nested maps,
// arrays, floats, ints, nil, HTML-escapable strings).
func perfMakeDoc() map[string]interface{} {
        buckets := make([]interface{}, 0, 8)
        for i := 0; i < 8; i++ {
                buckets = append(buckets, map[string]interface{}{
                        "dest":     fmt.Sprintf("bucket-%d", i),
                        "inst":     3 + i,
                        "rtt_us":   1234.5 + float64(i),
                        "ref_mbps": 94.2,
                        "best_alg": "cubic",
                        "n_alg":    4,
                })
        }
        metricByBucket := map[string]interface{}{}
        for i := 0; i < 8; i++ {
                rows := make([]interface{}, 0, 16)
                for a := 0; a < 16; a++ {
                        rows = append(rows, map[string]interface{}{
                                "alg":         CONGS[a],
                                "metric":      float64(a) * 1.25,
                                "votes":       a,
                                "alive":       2,
                                "rate_ema":    1000 + a,
                                "swap_score":  256,
                                "penalty":     0.9375,
                                "score":       88.5,
                                "bad_streak":  0,
                                "null_streak": 1,
                                "active":      true,
                        })
                }
                metricByBucket[fmt.Sprintf("bucket-%d", i)] = rows
        }
        bucketLive := map[string]interface{}{}
        for i := 0; i < 8; i++ {
                tsArr := make([]interface{}, 0, 60)
                cols := map[string]interface{}{}
                for _, alg := range CONGS {
                        cols["re_"+alg] = []interface{}{1.5}
                        cols["ss_"+alg] = []interface{}{256}
                        cols["bs_"+alg] = []interface{}{0}
                        cols["ns_"+alg] = []interface{}{1}
                }
                for p := 0; p < 60; p++ {
                        tsArr = append(tsArr, int64(1700000000+p*30))
                }
                bucketLive[fmt.Sprintf("bucket-%d", i)] = map[string]interface{}{
                        "ts":   tsArr,
                        "cols": cols,
                }
        }
        return map[string]interface{}{
                "generated_ts": int64(1700000000),
                "degraded":     false,
                "hostname":     "test & <host>",
                "now_mono":     12345.678,
                "build": map[string]interface{}{
                        "version":      "0.4.108",
                        "dash_version": "0.9.108",
                        "explore_pct":  10,
                },
                "buckets":          buckets,
                "metric_by_bucket": metricByBucket,
                "bucket_live":      bucketLive,
                "recent_swaps":     []interface{}{},
                "recent_proofs":    []interface{}{nil},
                "log_window": map[string]interface{}{
                        "oldest_ts": int64(0),
                        "newest_ts": int64(1),
                        "span_min":  0.5,
                },
        }
}

// perfMakeLogText builds a synthetic log tail matching the BPF event formats.
// Timestamps stay small (<=250) so the previous-boot filter never drops them
// regardless of the test host's /proc/uptime.
func perfMakeLogText(nCycles int) string {
        var sb strings.Builder
        for i := 0; i < nCycles; i++ {
                ts := strconv.FormatFloat(10.0+float64(i)*0.25, 'f', 6, 64)
                cookie := strconv.Itoa(1000 + i%50)
                dest := strconv.Itoa(134744072 + i%20) // 8.8.x.x-ish
                sb.WriteString(ts + ": bpf_trace_printk: estab cookie=" + cookie +
                        " alg=0 forced=1 dest=" + dest + "\n")
                sb.WriteString(ts + ": bpf_trace_printk: met cookie=" + cookie +
                        " rport=443 alg=1 segs=10 val=5000 rtt=1500 rate=1000000 loss=0\n")
                sb.WriteString(ts + ": bpf_trace_printk: srate cookie=" + cookie +
                        " alg=1 srate=950000\n")
                sb.WriteString(ts + ": x proof cookie=" + cookie +
                        " alg=1 rate=12500000 tier=2 dest=" + dest + "\n")
                sb.WriteString(ts + ": x midsamp cookie=" + cookie +
                        " mid srate=900000 rport=8443\n")
                if i%5 == 0 {
                        sb.WriteString(ts + ": bpf_trace_printk: swap cookie=" + cookie +
                                " from=0 to=1 bc=3 ac=4 d=2 mt=0 rb=1 dest=" + dest + "\n")
                }
        }
        return sb.String()
}

// ---------------------------------------------------------------------------
// 1. readLogTailCached — byte-identical to v0.9.104 readLogTail
// ---------------------------------------------------------------------------

func TestPerfReadLogTailCachedMatchesReference(t *testing.T) {
        dir := t.TempDir()
        oldGlob := logGlobPattern
        logGlobPattern = filepath.Join(dir, "bpftune-met-live.log*")
        defer func() { logGlobPattern = oldGlob; resetTailCacheForTest() }()
        resetTailCacheForTest()

        base := time.Now().Add(-time.Hour).Truncate(time.Second)
        perfWriteFile(t, filepath.Join(dir, "bpftune-met-live.log.2"), strings.Repeat("old-line\n", 100), base)
        perfWriteFile(t, filepath.Join(dir, "bpftune-met-live.log.1"), strings.Repeat("mid-line\n", 200), base.Add(time.Minute))
        perfWriteFile(t, filepath.Join(dir, "bpftune-met-live.log"), strings.Repeat("new-line\n", 300), base.Add(2*time.Minute))

        check := func(label string, budget int64) {
                t.Helper()
                got := readLogTailCached(budget)
                want := perfReferenceReadLogTail(budget)
                if got != want {
                        t.Fatalf("%s: tail mismatch\n got len=%d %q\nwant len=%d %q",
                                label, len(got), got, len(want), want)
                }
        }

        // Cold read, several budgets (incl. one smaller than a single file).
        check("cold 8MB", 8_000_000)
        check("cold 1KB", 1_000)
        check("cold 2.5KB", 2_500)

        // Warm read with unchanged files (cache hit path).
        check("warm 1KB", 1_000)
        check("warm 8MB", 8_000_000)

        // Append-only growth (incremental path).
        f, err := os.OpenFile(filepath.Join(dir, "bpftune-met-live.log"), os.O_APPEND|os.O_WRONLY, 0644)
        if err != nil {
                t.Fatal(err)
        }
        f.WriteString(strings.Repeat("appended-line\n", 50))
        f.Close()
        os.Chtimes(filepath.Join(dir, "bpftune-met-live.log"), base.Add(3*time.Minute), base.Add(3*time.Minute))
        check("after append 1KB", 1_000)
        check("after append 8MB", 8_000_000)

        // Truncation (full re-read path).
        perfWriteFile(t, filepath.Join(dir, "bpftune-met-live.log"), "short\n", base.Add(4*time.Minute))
        check("after truncate 8MB", 8_000_000)
        check("after truncate 1KB", 1_000)

        // New rotated file appears + budget smaller than total size.
        perfWriteFile(t, filepath.Join(dir, "bpftune-met-live.log.3"), strings.Repeat("rotated\n", 400), base.Add(5*time.Minute))
        check("after rotate 8MB", 8_000_000)
        check("after rotate 3KB", 3_000)

        // No files at all.
        logGlobPattern = filepath.Join(dir, "no-such-pattern*")
        resetTailCacheForTest()
        if got := readLogTailCached(1000); got != "" {
                t.Fatalf("empty glob: got %q, want \"\"", got)
        }
}

// ---------------------------------------------------------------------------
// 2. buildDocRaw — byte-identical to json.Marshal
// ---------------------------------------------------------------------------

func TestPerfBuildDocRawByteIdentical(t *testing.T) {
        doc := perfMakeDoc()
        got, keyBytes := buildDocRaw(doc)
        want, err := json.Marshal(doc)
        if err != nil {
                t.Fatalf("reference marshal failed: %v", err)
        }
        if !bytes.Equal(got, want) {
                t.Fatalf("doc bytes mismatch\n got  (%d): %s\n want (%d): %s",
                        len(got), got, len(want), want)
        }
        // Per-key bytes must equal json.Marshal of each value (hash inputs).
        for k, v := range doc {
                ref, _ := json.Marshal(v)
                if !bytes.Equal(keyBytes[k], ref) {
                        t.Fatalf("key %q bytes mismatch: got %s want %s", k, keyBytes[k], ref)
                }
        }
        // The md5 values computed from cached bytes must equal v0.9.104's
        // computeKeyHashes (same hash inputs => same SSE delta decisions).
        for k, v := range doc {
                ref, _ := json.Marshal(v)
                wantHash := fmt.Sprintf("%x", md5.Sum(ref))
                gotHash := fmt.Sprintf("%x", md5.Sum(keyBytes[k]))
                if gotHash != wantHash {
                        t.Fatalf("key %q hash mismatch: %s vs %s", k, gotHash, wantHash)
                }
        }
}

// ---------------------------------------------------------------------------
// 3. notifySSEFromRaw — wire-format compatible with v0.9.104
// ---------------------------------------------------------------------------

func TestPerfNotifySSEFromRawMessages(t *testing.T) {
        doc := perfMakeDoc()
        _, keyBytes := buildDocRaw(doc)
        ch := make(chan []byte, 10)
        c := &Collector{
                current:    doc,
                keyHashes:  map[string]string{},
                sseClients: map[chan []byte]bool{ch: true},
        }

        // First push: full document message.
        c.notifySSEFromRaw(keyBytes)
        var msg1 map[string]interface{}
        if err := json.Unmarshal(<-ch, &msg1); err != nil {
                t.Fatalf("full message not valid JSON: %v", err)
        }
        if msg1["__t"] != "f" {
                t.Fatalf("first message should be full, got %v", msg1["__t"])
        }
        // Byte-identity against v0.9.104's json.Marshal(map{"__t":"f","v":doc}).
        ref, _ := json.Marshal(map[string]interface{}{"__t": "f", "v": doc})
        // (rebuild for byte comparison: notifySSEFromRaw already consumed ch)
        c2 := &Collector{current: doc, keyHashes: map[string]string{}, sseClients: map[chan []byte]bool{ch: true}}
        _, kb2 := buildDocRaw(doc)
        c2.notifySSEFromRaw(kb2)
        if got := <-ch; !bytes.Equal(got, ref) {
                t.Fatalf("full message bytes mismatch\n got:  %s\n want: %s", got, ref)
        }

        // Unchanged doc: second push must be silent.
        _, kb3 := buildDocRaw(doc)
        c.notifySSEFromRaw(kb3)
        select {
        case got := <-ch:
                t.Fatalf("expected no delta for unchanged doc, got %s", got)
        default:
        }

        // Change one value: delta must carry exactly the changed key.
        doc["generated_ts"] = int64(1700000001)
        _, keyBytes4 := buildDocRaw(doc)
        c.notifySSEFromRaw(keyBytes4)
        select {
        case got := <-ch:
                var m map[string]interface{}
                if err := json.Unmarshal(got, &m); err != nil {
                        t.Fatalf("delta not valid JSON: %v", err)
                }
                if m["__t"] != "d" {
                        t.Fatalf("expected delta, got %v", m["__t"])
                }
                comp, _ := m["c"].(map[string]interface{})
                if len(comp) != 1 || comp["generated_ts"] == nil {
                        t.Fatalf("delta should carry exactly generated_ts, got keys %v", comp)
                }
        default:
                t.Fatal("expected a delta message")
        }
}

// ---------------------------------------------------------------------------
// 4. snapshotPreHash — same equivalence class as the serialized-row hash
// ---------------------------------------------------------------------------

func TestPerfSnapshotPreHashEquivalence(t *testing.T) {
        mk := func(mod float64) ([]interface{}, []interface{}, []interface{}, []interface{}, []interface{}) {
                mv, re, ss, bs, ns := make([]interface{}, 16), make([]interface{}, 16),
                        make([]interface{}, 16), make([]interface{}, 16), make([]interface{}, 16)
                for i := 0; i < 16; i++ {
                        mv[i] = float64(i) + mod
                        re[i] = float64(i) * 2
                        ss[i] = 256
                        bs[i] = 0
                        ns[i] = 1
                }
                return mv, re, ss, bs, ns
        }
        a1, b1, c1, d1, e1 := mk(0)
        a2, b2, c2, d2, e2 := mk(0)
        h1 := snapshotPreHash(a1, b1, c1, d1, e1, 3, "cubic", 5, 1200.0, 94.0, 100.0)
        h2 := snapshotPreHash(a2, b2, c2, d2, e2, 3, "cubic", 5, 1200.0, 94.0, 100.0)
        if h1 != h2 {
                t.Fatal("identical snapshots must produce identical pre-hashes")
        }
        // Any changed value must change the hash.
        a3, b3, c3, d3, e3 := mk(0.5)
        if h3 := snapshotPreHash(a3, b3, c3, d3, e3, 3, "cubic", 5, 1200.0, 94.0, 100.0); h3 == h1 {
                t.Fatal("changed metric values must change the pre-hash")
        }
        // Scalar drift must change the hash.
        if h4 := snapshotPreHash(a1, b1, c1, d1, e1, 4, "bbr", 5, 1200.0, 94.0, 100.0); h4 == h1 {
                t.Fatal("changed scalars must change the pre-hash")
        }
        // nil vs 0 must differ (different JSON: null vs 0).
        a5, b5, c5, d5, e5 := mk(0)
        c5[0] = nil
        if h5 := snapshotPreHash(a5, b5, c5, d5, e5, 3, "cubic", 5, 1200.0, 94.0, 100.0); h5 == h1 {
                t.Fatal("nil vs 0 transition must change the pre-hash")
        }
}

// ---------------------------------------------------------------------------
// 5. rebuildBucketLiveFromRing — typed series marshal identically
// ---------------------------------------------------------------------------

func TestPerfRebuildBucketLiveTypedJSONIdentical(t *testing.T) {
        hist.mu.Lock()
        oldRaw := hist.raw
        hist.raw = map[string][]bucketSnapshot{}
        snap := bucketSnapshot{Ts: 1000, Instances: 3, MinRtt: 1.5, RefRate: 2.5, BestI: 1, BestAlg: "bbr"}
        for i := 0; i < 16; i++ {
                snap.Re[i] = float64(i) * 1.5
                snap.Mv[i] = float64(i) / 2
                snap.Ss[i] = int16(256 + i)
                snap.Bs[i] = int16(i % 3)
                snap.Ns[i] = int16(i % 2)
        }
        for ts := int64(700); ts <= 1120; ts += 30 {
                s := snap
                s.Ts = ts
                hist.raw["1.2.3.4"] = append(hist.raw["1.2.3.4"], s)
        }
        hist.mu.Unlock()
        defer func() {
                hist.mu.Lock()
                hist.raw = oldRaw
                hist.mu.Unlock()
        }()

        hosts := []hostEntry{{Addr: "1.2.3.4", Inst: 3}}
        bl := map[string]interface{}{}
        rebuildBucketLiveFromRing(bl, hosts, 1200)
        got, _ := json.Marshal(bl)

        // Reference: v0.9.104's []interface{} boxing for the same data.
        type refSnap struct{ ts int64; re [16]float64; ss, bs, ns [16]int16 }
        var refSnaps []refSnap
        for ts := int64(700); ts <= 1120; ts += 30 {
                r := refSnap{ts: ts, re: snap.Re, ss: snap.Ss, bs: snap.Bs, ns: snap.Ns}
                refSnaps = append(refSnaps, r)
        }
        refCols := map[string]interface{}{}
        for _, alg := range CONGS {
                refCols["re_"+alg] = []interface{}{}
                refCols["ss_"+alg] = []interface{}{}
                refCols["bs_"+alg] = []interface{}{}
                refCols["ns_"+alg] = []interface{}{}
        }
        var refTs []interface{}
        for _, s := range refSnaps {
                refTs = append(refTs, s.ts)
                for i, alg := range CONGS {
                        if i >= 16 {
                                break
                        }
                        refCols["re_"+alg] = append(refCols["re_"+alg].([]interface{}), s.re[i])
                        refCols["ss_"+alg] = append(refCols["ss_"+alg].([]interface{}), s.ss[i])
                        refCols["bs_"+alg] = append(refCols["bs_"+alg].([]interface{}), s.bs[i])
                        refCols["ns_"+alg] = append(refCols["ns_"+alg].([]interface{}), s.ns[i])
                }
        }
        refBl := map[string]interface{}{
                "1.2.3.4": map[string]interface{}{"ts": refTs, "cols": refCols},
        }
        want, _ := json.Marshal(refBl)
        if !bytes.Equal(got, want) {
                t.Fatalf("bucket_live JSON mismatch\n got:  %s\n want: %s", got, want)
        }
}

// ---------------------------------------------------------------------------
// 6. parsedProofs consumers — identical to the v0.9.104 rxProof re-scan
// ---------------------------------------------------------------------------

func TestPerfParsedProofsMatchRegexRescan(t *testing.T) {
        text := "100.500000: x proof cookie=42 alg=0 rate=12500000 tier=2 dest=134744072\n" +
                "101.500000: x proof cookie=43 alg=1 rate=10000000 tier=1\n" +
                "102.500000: bpf_trace_printk: swap cookie=42 from=0 to=2 bc=3 ac=4 d=2\n" +
                "103.500000: x proof cookie=42 alg=0 rate=5000000 tier=1 dest=134744072\n"
        pl := parseLogSinglePass(text)
        cdest := map[string]cdestEntry{}

        // New path (parsedProofs).
        gotRows := pl.GetProofRows(cdest)

        // Reference: v0.9.104 re-scanned ProofLines with rxProof.
        var refRows []interface{}
        for _, l := range pl.ProofLines {
                m := rxProof.FindStringSubmatch(l)
                if m == nil {
                        continue
                }
                ts, _ := strconv.ParseFloat(m[1], 64)
                alg, _ := strconv.Atoi(m[3])
                if alg == 0 {
                        if realAlg, ok := pl.CookieAlg[m[2]]; ok && realAlg != 0 {
                                alg = realAlg
                        }
                }
                rate, _ := strconv.ParseInt(m[4], 10, 64)
                tierLabel := "good"
                if m[5] == "2" {
                        tierLabel = "proved"
                }
                dest := ""
                v4, v6, v6b := m[6], m[7], m[8]
                if v4 != "" || v6 != "" || v6b != "" {
                        ds := destStr(v4, v6, v6b)
                        dest = labelFor(ds)
                        if dest == "" {
                                dest = ds
                        }
                }
                if dest == "" {
                        continue
                }
                refRows = append(refRows, map[string]interface{}{
                        "boot_ts": ts,
                        "alg":     algName(alg),
                        "mbps":    round1(float64(rate) / bpsToMbps),
                        "tier":    tierLabel,
                        "dest":    dest,
                })
        }
        sort.Slice(refRows, func(i, j int) bool {
                ti, _ := refRows[i].(map[string]interface{})["boot_ts"].(float64)
                tj, _ := refRows[j].(map[string]interface{})["boot_ts"].(float64)
                return ti > tj
        })
        if len(gotRows) != len(refRows) {
                t.Fatalf("row count mismatch: got %d want %d (rows=%v)", len(gotRows), len(refRows), gotRows)
        }
        for i := range gotRows {
                g := gotRows[i].(map[string]interface{})
                r := refRows[i].(map[string]interface{})
                for _, k := range []string{"boot_ts", "alg", "mbps", "tier", "dest"} {
                        if fmt.Sprintf("%v", g[k]) != fmt.Sprintf("%v", r[k]) {
                                t.Fatalf("row %d field %q mismatch: got %v want %v", i, k, g[k], r[k])
                        }
                }
        }

        // proofs_raw keeps the RAW alg (v0.9.104 asymmetry preserved):
        // the alg=0 proof for cookie 42 must NOT be rewritten to alg 2 here.
        raw := pl.GetProofsRawEvents(cdest)
        for _, e := range raw {
                m := e.(map[string]interface{})
                if m["alg"] == "bbr" {
                        t.Fatalf("GetProofsRawEvents must not apply the cookie->alg rewrite: %v", m)
                }
        }
}

// ---------------------------------------------------------------------------
// Benchmarks — new hot paths vs the v0.9.104 work patterns
// ---------------------------------------------------------------------------

// BenchmarkPerfBuildDocRaw: v0.9.108 marshal-once.
func BenchmarkPerfBuildDocRaw(b *testing.B) {
        doc := perfMakeDoc()
        b.ReportAllocs()
        b.ResetTimer()
        for i := 0; i < b.N; i++ {
                buildDocRaw(doc)
        }
}

// BenchmarkPerfDocOldPath: v0.9.104 per-cycle JSON work —
// writeCurrentJSON marshal + per-key marshal for computeKeyHashes +
// the delta message marshal (3 full passes over the document).
func BenchmarkPerfDocOldPath(b *testing.B) {
        doc := perfMakeDoc()
        b.ReportAllocs()
        b.ResetTimer()
        for i := 0; i < b.N; i++ {
                data1, _ := json.Marshal(doc) // writeCurrentJSON
                _ = data1
                hashes := make(map[string]string, len(doc))
                for k, v := range doc { // computeKeyHashes
                        data, _ := json.Marshal(v)
                        hashes[k] = fmt.Sprintf("%x", md5.Sum(data))
                }
                msg := map[string]interface{}{"__t": "d", "c": doc} // notifySSE delta
                data3, _ := json.Marshal(msg)
                _ = data3
        }
}

// BenchmarkPerfReadTailCachedWarm: v0.9.108 cache-hit path (no I/O, no alloc).
func BenchmarkPerfReadTailCachedWarm(b *testing.B) {
        dir := b.TempDir()
        oldGlob := logGlobPattern
        logGlobPattern = filepath.Join(dir, "bpftune-met-live.log*")
        defer func() { logGlobPattern = oldGlob; resetTailCacheForTest() }()
        resetTailCacheForTest()
        os.WriteFile(filepath.Join(dir, "bpftune-met-live.log"), []byte(strings.Repeat("line\n", 40000)), 0644)
        readLogTailCached(8_000_000) // warm the cache
        b.ReportAllocs()
        b.ResetTimer()
        for i := 0; i < b.N; i++ {
                readLogTailCached(8_000_000)
        }
}

// BenchmarkPerfReadTailOldPath: v0.9.104 readLogTail reference (full re-read).
func BenchmarkPerfReadTailOldPath(b *testing.B) {
        dir := b.TempDir()
        oldGlob := logGlobPattern
        logGlobPattern = filepath.Join(dir, "bpftune-met-live.log*")
        defer func() { logGlobPattern = oldGlob }()
        os.WriteFile(filepath.Join(dir, "bpftune-met-live.log"), []byte(strings.Repeat("line\n", 40000)), 0644)
        b.ReportAllocs()
        b.ResetTimer()
        for i := 0; i < b.N; i++ {
                _ = perfReferenceReadLogTail(8_000_000)
        }
}

// BenchmarkPerfParseLogSinglePass: v0.9.108 parser on a realistic tail.
func BenchmarkPerfParseLogSinglePass(b *testing.B) {
        text := perfMakeLogText(4000) // ~24K lines
        b.ReportAllocs()
        b.ResetTimer()
        for i := 0; i < b.N; i++ {
                parseLogSinglePass(text)
        }
}

// BenchmarkPerfParseLoopOldSplit: the v0.9.104 line-splitting pattern
// (strings.Split over the same text) for allocation comparison.
func BenchmarkPerfParseLoopOldSplit(b *testing.B) {
        text := perfMakeLogText(4000)
        b.ReportAllocs()
        b.ResetTimer()
        for i := 0; i < b.N; i++ {
                n := 0
                for _, line := range strings.Split(text, "\n") {
                        if len(line) > 0 {
                                n++
                        }
                }
                _ = n
        }
}

// TestPerfSanity ensures the synthetic log actually exercises the parser
// (guards against silently-dropped events invalidating the benchmarks).
func TestPerfSyntheticLogParses(t *testing.T) {
        pl := parseLogSinglePass(perfMakeLogText(50))
        if len(pl.Swaps) == 0 || len(pl.MetByCookie) == 0 || len(pl.SrateByCookie) == 0 ||
                len(pl.parsedProofs) == 0 || len(pl.MidsampRows) == 0 || len(pl.Cdest) == 0 {
                t.Fatalf("synthetic log under-exercised: swaps=%d mets=%d srates=%d proofs=%d mids=%d cdest=%d",
                        len(pl.Swaps), len(pl.MetByCookie), len(pl.SrateByCookie),
                        len(pl.parsedProofs), len(pl.MidsampRows), len(pl.Cdest))
        }
}
