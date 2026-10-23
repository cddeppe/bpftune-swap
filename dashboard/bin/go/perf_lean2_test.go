package main

// perf_lean2_test.go — v0.9.109/110-lean: byte-identity tests + benchmarks.
//
// Proves the v0.9.109+ changes produce IDENTICAL output to v0.9.104:
//   - writeCurrentJSONStream() vs json.Marshal (document bytes) and
//     md5(json.Marshal(v)) (hash bytes => identical SSE delta decisions)
//   - notifySSEFromCycle() wire format vs json.Marshal of the v0.9.104
//     message maps (full + delta + slow-key carry-forward + removed keys)
//   - fullMessageFromDisk() vs json.Marshal({"__t":"f","v":doc})
//   - gzipCached() vs gzip.NewWriter output
// Plus behavioural tests for the bucket_live filter and ring compaction.
//
// v0.9.110: the selectable-filter test now uses IP-SHAPED negative cases.
// The v0.9.109 test used "no-select-me" (non-IP) as its negative —
// labelFor() rejects non-IP strings but returns the canonical form for
// any IP-shaped addr, so the test passed while the filter was a no-op
// on real hosts (324/324 keys kept on al). The negative case must be
// IP-shaped or it cannot catch that bug class.
//
// All helpers prefixed "perf2" to avoid collisions with existing suites.

import (
        "bytes"
        "compress/gzip"
        "crypto/md5"
        "encoding/json"
        "fmt"
        "os"
        "path/filepath"
        "testing"
        "time"
)

// perf2Sandbox redirects histDir to a temp dir and restores globals.
func perf2Sandbox(t *testing.T) string {
        t.Helper()
        dir := t.TempDir()
        oldHist := histDir
        oldCycle := cycleCount
        histDir = dir
        cycleCount = 0
        t.Cleanup(func() {
                histDir = oldHist
                cycleCount = oldCycle
                resetGzipCacheForTest()
        })
        return dir
}

// ---------------------------------------------------------------------------
// 1. Streaming writer — byte-identical document + hashes
// ---------------------------------------------------------------------------

func TestPerf2StreamDocByteIdentical(t *testing.T) {
        perf2Sandbox(t)
        doc := perfMakeDoc()
        cycleCount = 0 // fullHash cycle

        cy, ok := writeCurrentJSONStream(doc, map[string]string{})
        if !ok {
                t.Fatal("writeCurrentJSONStream failed")
        }
        got, _ := currentJSONFromDisk()
        want, err := json.Marshal(doc)
        if err != nil {
                t.Fatalf("reference marshal: %v", err)
        }
        if !bytes.Equal(got, want) {
                t.Fatalf("current.json bytes mismatch\n got  (%d): %s\n want (%d): %s",
                        len(got), got, len(want), want)
        }
        // Hashes must equal v0.9.104's md5(json.Marshal(v)).
        for k, v := range doc {
                ref, _ := json.Marshal(v)
                wantHash := fmt.Sprintf("%x", md5.Sum(ref))
                if cy.newHashes[k] != wantHash {
                        t.Fatalf("key %q hash mismatch: got %s want %s", k, cy.newHashes[k], wantHash)
                }
        }
        // First push: no changed-key retention (full message path).
        if len(cy.changed) != 0 {
                t.Fatalf("first push must not retain changed bytes, got %d keys", len(cy.changed))
        }
        // Full message byte-identity.
        refMsg, _ := json.Marshal(map[string]interface{}{"__t": "f", "v": doc})
        if gotMsg := fullMessageFromDisk(); !bytes.Equal(gotMsg, refMsg) {
                t.Fatalf("full message bytes mismatch\n got:  %s\n want: %s", gotMsg, refMsg)
        }
}

// ---------------------------------------------------------------------------
// 2. Delta semantics — changed keys, removed keys, slow-key carry-forward
// ---------------------------------------------------------------------------

func TestPerf2StreamDeltaSemantics(t *testing.T) {
        perf2Sandbox(t)
        cycleCount = 0 // full-hash cycle: deterministic

        doc := perfMakeDoc()
        cy1, ok := writeCurrentJSONStream(doc, map[string]string{})
        if !ok {
                t.Fatal("write 1 failed")
        }

        // Unchanged doc: second write must report no changed keys.
        cy2, ok := writeCurrentJSONStream(doc, cy1.newHashes)
        if !ok {
                t.Fatal("write 2 failed")
        }
        if len(cy2.changed) != 0 || len(cy2.removed) != 0 {
                t.Fatalf("unchanged doc: expected empty delta, got changed=%v removed=%v",
                        cy2.changed, cy2.removed)
        }

        // Change one value: exactly that key is retained + delta wire format.
        doc["generated_ts"] = int64(1700000001)
        cy3, ok := writeCurrentJSONStream(doc, cy2.newHashes)
        if !ok {
                t.Fatal("write 3 failed")
        }
        if len(cy3.changed) != 1 || cy3.changed["generated_ts"] == nil {
                t.Fatalf("expected exactly generated_ts changed, got %v", cy3.changed)
        }

        ch := make(chan []byte, 4)
        c := &Collector{
                current:    doc,
                keyHashes:  cy2.newHashes,
                sseClients: map[chan []byte]bool{ch: true},
        }
        c.notifySSEFromCycle(cy3)
        got := <-ch
        want, _ := json.Marshal(map[string]interface{}{
                "__t": "d",
                "c":   map[string]interface{}{"generated_ts": int64(1700000001)},
        })
        if !bytes.Equal(got, want) {
                t.Fatalf("delta bytes mismatch\n got:  %s\n want: %s", got, want)
        }

        // Removed key: prevHashes carries a key the doc no longer has.
        prevWithExtra := map[string]string{}
        for k, v := range cy3.newHashes {
                prevWithExtra[k] = v
        }
        prevWithExtra["gone"] = "deadbeef"
        cy4, ok := writeCurrentJSONStream(doc, prevWithExtra)
        if !ok {
                t.Fatal("write 4 failed")
        }
        if len(cy4.removed) != 1 || cy4.removed[0] != "gone" {
                t.Fatalf("expected removed=[gone], got %v", cy4.removed)
        }
        c2 := &Collector{current: doc, keyHashes: prevWithExtra, sseClients: map[chan []byte]bool{ch: true}}
        c2.notifySSEFromCycle(cy4)
        got2 := <-ch
        var m map[string]interface{}
        if err := json.Unmarshal(got2, &m); err != nil {
                t.Fatalf("delta with removed not valid JSON: %v", err)
        }
        if rm, _ := m["r"].([]interface{}); len(rm) != 1 || rm[0] != "gone" {
                t.Fatalf("expected r=[gone], got %v", m["r"])
        }
}

func TestPerf2SlowKeyCarryForward(t *testing.T) {
        perf2Sandbox(t)
        cycleCount = 1 // non-full cycle: slow keys skipped + carried forward

        doc := perfMakeDoc()
        cy1, ok := writeCurrentJSONStream(doc, map[string]string{})
        if !ok {
                t.Fatal("write 1 failed")
        }
        // v0.9.104 semantics: computeKeyHashes skips slow keys on non-full
        // cycles; carry-forward fills from prev when present.
        if _, ok := cy1.newHashes["bucket_live"]; ok {
                t.Fatal("slow key must not be hashed on a non-full cycle")
        }
        // With a previous hash present, it must be carried forward.
        prev := map[string]string{"bucket_live": "oldhash"}
        cy2, ok := writeCurrentJSONStream(doc, prev)
        if !ok {
                t.Fatal("write 2 failed")
        }
        if cy2.newHashes["bucket_live"] != "oldhash" {
                t.Fatalf("slow key not carried forward: got %q", cy2.newHashes["bucket_live"])
        }
        if cy2.changed["bucket_live"] != nil {
                t.Fatal("slow key must not appear in the delta on a non-full cycle")
        }
}

// ---------------------------------------------------------------------------
// 3. bucket_live filter — selectable = top-8 + labeled
//    (IP-shaped negative cases — see file header)
// ---------------------------------------------------------------------------

func TestPerf2SelectableFilter(t *testing.T) {
        buckets := make([]bucketRow, 0, 8)
        metricByBucket := map[string]interface{}{}
        for i := 0; i < 8; i++ {
                id := fmt.Sprintf("10.0.0.%d", i+1)
                buckets = append(buckets, bucketRow{Dest: id})
                metricByBucket[id] = []interface{}{}
        }
        // Negative cases MUST be IP-shaped: a non-IP string is rejected by
        // labelFor() unconditionally and cannot catch the v0.9.109 bug where
        // labelFor() passed every IP-shaped addr.
        metricByBucket["172.16.9.9"] = []interface{}{} // unlabeled non-top-8
        metricByBucket["192.168.5.5"] = []interface{}{} // unlabeled non-top-8

        labels := map[string]string{
                "9.9.9.9":  "my-label", // labeled IP: key + value both selectable
                "10.1.1.1": "",          // deleted label: key still selectable (insurance)
        }
        sel := buildSelectable(buckets, labels)
        for i := 0; i < 8; i++ {
                id := fmt.Sprintf("10.0.0.%d", i+1)
                if !sel[id] {
                        t.Fatalf("top-8 bucket %s must be selectable", id)
                }
        }
        if sel["172.16.9.9"] || sel["192.168.5.5"] {
                t.Fatalf("unlabeled non-top-8 buckets must NOT be selectable: %v", sel)
        }
        if !sel["my-label"] {
                t.Fatal("custom-labeled bucket (labels value) must be selectable")
        }
        if !sel["9.9.9.9"] {
                t.Fatal("labels key must be selectable (un-resolved addr insurance)")
        }
        if !sel["10.1.1.1"] {
                t.Fatal("labels key must be selectable even when its value is empty")
        }

        filtered := selectKeys(metricByBucket, sel)
        if _, ok := filtered["172.16.9.9"]; ok {
                t.Fatal("selectKeys must drop non-selectable keys")
        }
        if _, ok := filtered["192.168.5.5"]; ok {
                t.Fatal("selectKeys must drop non-selectable keys")
        }
        if len(filtered) != 8 {
                t.Fatalf("selectKeys kept %d entries, want 8", len(filtered))
        }
}

// ---------------------------------------------------------------------------
// 4. Ring compaction — bounded cap, correct window
// ---------------------------------------------------------------------------

func TestPerf2RingCompaction(t *testing.T) {
        oldCap := ringCap
        oldRaw := hist.raw
        ringCap = 10
        hist.mu.Lock()
        hist.raw = map[string][]bucketSnapshot{}
        hist.mu.Unlock()
        defer func() {
                ringCap = oldCap
                hist.mu.Lock()
                hist.raw = oldRaw
                hist.mu.Unlock()
        }()

        for i := 0; i < 100; i++ {
                hist.addSnapshot("b1", bucketSnapshot{Ts: int64(i)})
        }
        hist.mu.RLock()
        got := hist.raw["b1"]
        hist.mu.RUnlock()
        if len(got) != ringCap {
                t.Fatalf("ring length %d, want %d", len(got), ringCap)
        }
        // Window must hold the LAST ringCap snapshots.
        for i, s := range got {
                want := int64(100 - ringCap + i)
                if s.Ts != want {
                        t.Fatalf("ring[%d].Ts = %d, want %d", i, s.Ts, want)
                }
        }
        if cap(got) > 2*ringCap {
                t.Fatalf("backing array not compacted: cap=%d > 2*ringCap=%d", cap(got), 2*ringCap)
        }
}

// ---------------------------------------------------------------------------
// 5. gzip cache — identical bytes
// ---------------------------------------------------------------------------

func TestPerf2GzipCacheIdentical(t *testing.T) {
        resetGzipCacheForTest()
        dir := t.TempDir()
        path := filepath.Join(dir, "asset.js")
        data := bytes.Repeat([]byte("chart-data-"), 5000)
        if err := os.WriteFile(path, data, 0644); err != nil {
                t.Fatal(err)
        }

        // Reference gzip.
        var ref bytes.Buffer
        zw := gzip.NewWriter(&ref)
        zw.Write(data)
        zw.Close()

        got := gzipCached(path, data)
        if got == nil || !bytes.Equal(got, ref.Bytes()) {
                t.Fatalf("gzip mismatch\n got %d bytes, want %d bytes", len(got), ref.Len())
        }
        // Second call: cache hit returns the same bytes.
        got2 := gzipCached(path, data)
        if !bytes.Equal(got, got2) {
                t.Fatal("cache hit returned different bytes")
        }
        // File change invalidates the cache (size + mtime differ).
        data2 := append(bytes.Clone(data), []byte("more")...)
        if err := os.WriteFile(path, data2, 0644); err != nil {
                t.Fatal(err)
        }
        newer := time.Now().Add(2 * time.Second)
        if err := os.Chtimes(path, newer, newer); err != nil {
                t.Fatal(err)
        }
        got3 := gzipCached(path, data2)
        var ref3 bytes.Buffer
        zw3 := gzip.NewWriter(&ref3)
        zw3.Write(data2)
        zw3.Close()
        if !bytes.Equal(got3, ref3.Bytes()) {
                t.Fatal("cache did not re-compress after file change")
        }
}

// ---------------------------------------------------------------------------
// Benchmarks — streaming writer vs the previous work patterns
// ---------------------------------------------------------------------------

// BenchmarkPerf2StreamWrite: v0.9.109 hash-as-you-go single pass
// (encode + hash + file write per key; retains only changed bytes).
func BenchmarkPerf2StreamWrite(b *testing.B) {
        dir := b.TempDir()
        oldHist := histDir
        histDir = dir
        defer func() { histDir = oldHist }()
        doc := perfMakeDoc()
        prev := map[string]string{}
        b.ReportAllocs()
        b.ResetTimer()
        for i := 0; i < b.N; i++ {
                writeCurrentJSONStream(doc, prev)
        }
}

// BenchmarkPerf2StreamWriteSteadyState: unchanged doc, hashes known —
// the common per-cycle case (no changed-key retention).
func BenchmarkPerf2StreamWriteSteadyState(b *testing.B) {
        dir := b.TempDir()
        oldHist := histDir
        histDir = dir
        defer func() { histDir = oldHist }()
        doc := perfMakeDoc()
        cy, _ := writeCurrentJSONStream(doc, map[string]string{})
        b.ReportAllocs()
        b.ResetTimer()
        for i := 0; i < b.N; i++ {
                writeCurrentJSONStream(doc, cy.newHashes)
        }
}
