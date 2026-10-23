package main

// perf_cache.go — per-cycle garbage elimination.
//
// v0.9.108-lean: incremental tail cache + marshal-once document cache.
// v0.9.109-lean2: streaming hash-as-you-go document writer — the v0.9.108
// path still materialized the full document 2x per cycle (keyBytes map +
// docBytes slice). The streaming writer encodes each key ONCE into a
// reused buffer, feeds the md5 hasher and the file in the same pass, and
// retains raw bytes ONLY for keys that actually changed (for the SSE
// delta). The full document is never assembled in the common path.
//
// Byte-identity guarantees:
//   - current.json == json.Marshal(doc)  (sorted keys, same value bytes;
//     json.Encoder.Encode == json.Marshal minus the trailing newline)
//   - key hashes == v0.9.104's md5 over json.Marshal(v)  (same input
//     bytes => identical SSE delta decisions)
//   - SSE messages == json.Marshal of the v0.9.104 message maps

import (
        "bytes"
        "compress/gzip"
        "crypto/md5"
        "encoding/json"
        "fmt"
        "os"
        "path/filepath"
        "sort"
        "strings"
        "sync"
)

// ============================================================================
// 1. Incremental log-tail cache (v0.9.108-lean)
// ============================================================================

// logGlobPattern is a var so tests can point it at a sandbox directory.
var logGlobPattern = "/var/log/bpftune-met-live.log*"

// tailFile holds one file's cached tail chunk (last min(budget, size)
// bytes) plus the stat signature it was built from.
type tailFile struct {
        size  int64
        mtime int64
        chunk []byte // tail bytes; len(chunk) == min(budget, size)
}

var (
        tailMu      sync.Mutex
        tailFiles   = map[string]*tailFile{}
        tailBudget  int64
        tailSig     string
        tailJoined  string
)

// readLogTailCached returns the last `budget` bytes across all files
// matching logGlobPattern, sorted newest-first by mtime, each chunk
// terminated by '\n' — byte-identical to v0.9.104's readLogTail().
func readLogTailCached(budget int64) string {
        tailMu.Lock()
        defer tailMu.Unlock()

        files, _ := filepath.Glob(logGlobPattern)
        if len(files) == 0 {
                return ""
        }
        sort.Slice(files, func(i, j int) bool {
                fi, _ := os.Stat(files[i])
                fj, _ := os.Stat(files[j])
                return fi.ModTime().After(fj.ModTime())
        })

        if budget != tailBudget {
                tailFiles = map[string]*tailFile{}
                tailBudget = budget
                tailSig = ""
        }

        var sig strings.Builder
        order := make([]*tailFile, 0, len(files))
        for _, p := range files {
                fi, err := os.Stat(p)
                if err != nil {
                        continue
                }
                size := fi.Size()
                mtime := fi.ModTime().UnixNano()
                fmt.Fprintf(&sig, "%s|%d|%d\n", p, size, mtime)

                fc := tailFiles[p]
                if fc == nil {
                        fc = &tailFile{}
                        tailFiles[p] = fc
                }
                switch {
                case fc.chunk != nil && size == fc.size && mtime == fc.mtime:
                        // Unchanged — reuse cached chunk.
                case fc.chunk != nil && size > fc.size && size-fc.size < budget:
                        // Grew by less than the budget: read only the new
                        // bytes and extend the cached tail.
                        if data := readFileRegion(p, fc.size, size-fc.size); data != nil {
                                fc.chunk = append(fc.chunk, data...)
                                if int64(len(fc.chunk)) > budget {
                                        fc.chunk = fc.chunk[int64(len(fc.chunk))-budget:]
                                }
                        } else {
                                fc.chunk = readTailRegion(p, size, budget)
                        }
                        fc.size, fc.mtime = size, mtime
                default:
                        fc.chunk = readTailRegion(p, size, budget)
                        fc.size, fc.mtime = size, mtime
                }
                order = append(order, fc)
        }

        s := sig.String()
        if s == tailSig && s != "" {
                return tailJoined
        }

        var sb strings.Builder
        remaining := budget
        for _, fc := range order {
                if remaining <= 0 {
                        break
                }
                take := fc.size
                if take > remaining {
                        take = remaining
                }
                if int64(len(fc.chunk)) < take {
                        take = int64(len(fc.chunk))
                }
                sb.Write(fc.chunk[int64(len(fc.chunk))-take:])
                sb.WriteByte('\n')
                remaining -= take
        }
        tailSig = s
        tailJoined = sb.String()
        return tailJoined
}

// readTailRegion reads the last min(size, budget) bytes of a file.
func readTailRegion(path string, size, budget int64) []byte {
        take := size
        if take > budget {
                take = budget
        }
        if take <= 0 {
                return []byte{}
        }
        return readFileRegion(path, size-take, take)
}

// readFileRegion reads [off, off+n) bytes of a file.  Returns nil on error.
func readFileRegion(path string, off, n int64) []byte {
        f, err := os.Open(path)
        if err != nil {
                return nil
        }
        defer f.Close()
        if _, err := f.Seek(off, 0); err != nil {
                return nil
        }
        buf := make([]byte, n)
        var got int
        for got < len(buf) {
                m, err := f.Read(buf[got:])
                if m > 0 {
                        got += m
                }
                if err != nil {
                        break
                }
        }
        return buf[:got]
}

// resetTailCacheForTest clears the tail cache (tests only).
func resetTailCacheForTest() {
        tailMu.Lock()
        defer tailMu.Unlock()
        tailFiles = map[string]*tailFile{}
        tailBudget = 0
        tailSig = ""
        tailJoined = ""
}

// ============================================================================
// 2. Streaming hash-as-you-go document writer (v0.9.109-lean2)
// ============================================================================

// docEncBuf/docEnc — reusable marshal scratch.  The collect cycle is a
// single writer; the mutex only guards against concurrent test use.
var (
        docEncMu  sync.Mutex
        docEncBuf bytes.Buffer
        docEnc    = json.NewEncoder(&docEncBuf)
)

// docCycle carries what the SSE push needs from one document write:
// the new per-key hashes, the raw JSON of CHANGED keys (retained copies)
// and the list of removed keys.
type docCycle struct {
        newHashes map[string]string
        changed   map[string][]byte
        removed   []string
}

// writeCurrentJSONStream writes current.json from doc in a single pass:
// each value is encoded once into a reused buffer, hashed (v0.9.104-
// identical md5 over the same bytes), and streamed to the file.  Raw
// bytes are retained only for keys whose hash changed since prevHashes.
//
// Returns ok=false when a value cannot be marshaled or the file cannot
// be written; the caller then falls back to the v0.9.108 reference path.
func writeCurrentJSONStream(doc map[string]interface{}, prevHashes map[string]string) (*docCycle, bool) {
        keys := make([]string, 0, len(doc))
        for k := range doc {
                keys = append(keys, k)
        }
        sort.Strings(keys)

        fullHash := (cycleCount % 4) == 0
        firstPush := len(prevHashes) == 0

        docEncMu.Lock()
        defer docEncMu.Unlock()

        path := filepath.Join(histDir, "current.json")
        tmp := path + ".tmp"
        f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
        if err != nil {
                return nil, false
        }
        abort := func() {
                f.Close()
                os.Remove(tmp)
        }
        if _, err := f.Write([]byte{'{'}); err != nil {
                abort()
                return nil, false
        }

        hashes := make(map[string]string, len(doc))
        changed := map[string][]byte{}
        for i, k := range keys {
                if i > 0 {
                        if _, err := f.Write([]byte{','}); err != nil {
                                abort()
                                return nil, false
                        }
                }
                kb, _ := json.Marshal(k)
                if _, err := f.Write(kb); err != nil {
                        abort()
                        return nil, false
                }
                if _, err := f.Write([]byte{':'}); err != nil {
                        abort()
                        return nil, false
                }
                docEncBuf.Reset()
                if err := docEnc.Encode(doc[k]); err != nil {
                        abort()
                        return nil, false
                }
                raw := docEncBuf.Bytes()
                if n := len(raw); n > 0 && raw[n-1] == '\n' {
                        raw = raw[:n-1] // json.Encoder appends '\n'; json.Marshal does not
                }
                if _, err := f.Write(raw); err != nil {
                        abort()
                        return nil, false
                }
                if !fullHash && slowChangingKeys[k] {
                        continue // hashed every 4th cycle; carried forward below
                }
                sum := md5.Sum(raw)
                h := fmt.Sprintf("%x", sum)
                hashes[k] = h
                if !firstPush {
                        if prev, ok := prevHashes[k]; !ok || prev != h {
                                cpy := make([]byte, len(raw))
                                copy(cpy, raw)
                                changed[k] = cpy
                        }
                }
        }
        if _, err := f.Write([]byte{'}'}); err != nil {
                abort()
                return nil, false
        }
        if err := f.Close(); err != nil {
                os.Remove(tmp)
                return nil, false
        }
        if err := os.Rename(tmp, path); err != nil {
                os.Remove(tmp)
                return nil, false
        }

        // v0.9.83 semantics: carry slow-key hashes forward on non-full cycles.
        if !fullHash && len(prevHashes) > 0 {
                for k := range slowChangingKeys {
                        if _, ok := hashes[k]; !ok {
                                if prev, ok := prevHashes[k]; ok {
                                        hashes[k] = prev
                                }
                        }
                }
        }

        var removed []string
        for k := range prevHashes {
                if _, exists := doc[k]; !exists {
                        removed = append(removed, k)
                }
        }
        return &docCycle{newHashes: hashes, changed: changed, removed: removed}, true
}

// fullMessageFromDisk builds the SSE full-document message
// {"__t":"f","v":<doc>} from the just-written current.json.
// Byte-identical to json.Marshal(map{"__t":"f","v":doc}).
func fullMessageFromDisk() []byte {
        data, err := os.ReadFile(filepath.Join(histDir, "current.json"))
        if err != nil {
                return []byte(`{"__t":"f","v":{}}`)
        }
        out := make([]byte, 0, len(data)+13)
        out = append(out, `{"__t":"f","v":`...)
        out = append(out, data...)
        out = append(out, '}')
        return out
}

// currentJSONFromDisk returns the current.json bytes (identical to
// json.Marshal(c.current) at the last completed cycle).
func currentJSONFromDisk() ([]byte, bool) {
        data, err := os.ReadFile(filepath.Join(histDir, "current.json"))
        if err != nil {
                return nil, false
        }
        return data, true
}

// notifySSEFromCycle pushes the SSE delta for one document cycle.
// Wire-format identical to v0.9.104's notifySSE():
//   - first push (prevHashes empty): full document message
//   - otherwise: {"__t":"d","c":{changed}}[, "r":[removed]]
//   - keyHashes updated before the empty-delta early return, as in v0.9.104
func (c *Collector) notifySSEFromCycle(cy *docCycle) {
        c.mu.RLock()
        prevHashes := c.keyHashes
        c.mu.RUnlock()

        if len(prevHashes) == 0 {
                data := fullMessageFromDisk()
                c.mu.Lock()
                for client := range c.sseClients {
                        select {
                        case client <- data:
                        default:
                        }
                }
                c.keyHashes = cy.newHashes
                c.mu.Unlock()
                return
        }

        deltaKeys := make([]string, 0, len(cy.changed))
        for k := range cy.changed {
                deltaKeys = append(deltaKeys, k)
        }
        sort.Strings(deltaKeys)

        // Assemble {"__t":"d","c":{...}} [, "r":[...]] exactly like
        // json.Marshal of the v0.9.104 message map (keys sorted __t,c,r;
        // delta object keys sorted).
        var buf []byte
        if len(deltaKeys) > 0 || len(cy.removed) > 0 {
                buf = append(buf, `{"__t":"d","c":{`...)
                for i, k := range deltaKeys {
                        if i > 0 {
                                buf = append(buf, ',')
                        }
                        kb, _ := json.Marshal(k)
                        buf = append(buf, kb...)
                        buf = append(buf, ':')
                        buf = append(buf, cy.changed[k]...)
                }
                buf = append(buf, '}')
                if len(cy.removed) > 0 {
                        buf = append(buf, `,"r":[`...)
                        for i, k := range cy.removed {
                                if i > 0 {
                                        buf = append(buf, ',')
                                }
                                kb, _ := json.Marshal(k)
                                buf = append(buf, kb...)
                        }
                        buf = append(buf, ']')
                }
                buf = append(buf, '}')
        }

        c.mu.Lock()
        c.keyHashes = cy.newHashes
        if buf != nil {
                for client := range c.sseClients {
                        select {
                        case client <- buf:
                        default:
                        }
                }
        }
        c.mu.Unlock()
}

// ============================================================================
// 3. Reference implementations (v0.9.108) — kept as fallback + test oracles
// ============================================================================

// buildDocRaw marshals every top-level value of doc exactly once and
// assembles the full document from the cached per-key bytes.
// Byte-identical to json.Marshal(doc).
func buildDocRaw(doc map[string]interface{}) (docBytes []byte, keyBytes map[string][]byte) {
        keys := make([]string, 0, len(doc))
        for k := range doc {
                keys = append(keys, k)
        }
        sort.Strings(keys)

        keyBytes = make(map[string][]byte, len(doc))
        total := 2
        for _, k := range keys {
                raw, err := json.Marshal(doc[k])
                if err != nil {
                        data, _ := json.Marshal(doc)
                        keyBytes = map[string][]byte{}
                        for _, kk := range keys {
                                keyBytes[kk] = []byte("null")
                        }
                        return data, keyBytes
                }
                keyBytes[k] = raw
                total += len(k) + len(raw) + 4
        }

        buf := make([]byte, 0, total)
        buf = append(buf, '{')
        for i, k := range keys {
                if i > 0 {
                        buf = append(buf, ',')
                }
                kb, _ := json.Marshal(k)
                buf = append(buf, kb...)
                buf = append(buf, ':')
                buf = append(buf, keyBytes[k]...)
        }
        buf = append(buf, '}')
        return buf, keyBytes
}

// writeCurrentJSONFromRaw writes the pre-marshaled document atomically.
// Fallback path for writeCurrentJSONStream failures.
func (c *Collector) writeCurrentJSONFromRaw(docBytes []byte) {
        path := filepath.Join(histDir, "current.json")
        tmp := path + ".tmp"
        if err := os.WriteFile(tmp, docBytes, 0644); err != nil {
                fmt.Fprintf(os.Stderr, "collector: write current.json failed: %v\n", err)
                return
        }
        os.Rename(tmp, path)
}

// notifySSEFromRaw — v0.9.108 reference SSE push (used as fallback and
// as the byte-identity oracle in tests).
func (c *Collector) notifySSEFromRaw(keyBytes map[string][]byte) {
        c.mu.RLock()
        current := c.current
        prevHashes := c.keyHashes
        c.mu.RUnlock()

        fullHash := (cycleCount % 4) == 0
        newHashes := make(map[string]string, len(keyBytes))
        for k, raw := range keyBytes {
                if !fullHash && slowChangingKeys[k] {
                        continue
                }
                sum := md5.Sum(raw)
                newHashes[k] = fmt.Sprintf("%x", sum)
        }
        if !fullHash && len(prevHashes) > 0 {
                for k := range slowChangingKeys {
                        if _, ok := newHashes[k]; !ok {
                                if prev, ok := prevHashes[k]; ok {
                                        newHashes[k] = prev
                                }
                        }
                }
        }

        if len(prevHashes) == 0 {
                data := assembleFullMessage(c, keyBytes)
                c.mu.Lock()
                for client := range c.sseClients {
                        select {
                        case client <- data:
                        default:
                        }
                }
                c.keyHashes = newHashes
                c.mu.Unlock()
                return
        }

        deltaKeys := make([]string, 0, len(current))
        for k := range current {
                hash, ok := newHashes[k]
                if !ok {
                        continue
                }
                prev, existed := prevHashes[k]
                if !existed || prev != hash {
                        deltaKeys = append(deltaKeys, k)
                }
        }
        var removed []string
        for k := range prevHashes {
                if _, exists := current[k]; !exists {
                        removed = append(removed, k)
                }
        }

        c.mu.Lock()
        c.keyHashes = newHashes
        c.mu.Unlock()

        if len(deltaKeys) == 0 && len(removed) == 0 {
                return
        }

        sort.Strings(deltaKeys)
        var buf []byte
        buf = append(buf, `{"__t":"d","c":{`...)
        for i, k := range deltaKeys {
                if i > 0 {
                        buf = append(buf, ',')
                }
                kb, _ := json.Marshal(k)
                buf = append(buf, kb...)
                buf = append(buf, ':')
                buf = append(buf, keyBytes[k]...)
        }
        buf = append(buf, '}')
        if len(removed) > 0 {
                buf = append(buf, `,"r":[`...)
                for i, k := range removed {
                        if i > 0 {
                                buf = append(buf, ',')
                        }
                        kb, _ := json.Marshal(k)
                        buf = append(buf, kb...)
                }
                buf = append(buf, ']')
        }
        buf = append(buf, '}')

        c.mu.Lock()
        for client := range c.sseClients {
                select {
                case client <- buf:
                default:
                }
        }
        c.mu.Unlock()
}

// assembleFullMessage builds {"__t":"f","v":<doc>} from cached bytes.
func assembleFullMessage(c *Collector, keyBytes map[string][]byte) []byte {
        c.mu.RLock()
        current := c.current
        c.mu.RUnlock()
        keys := make([]string, 0, len(current))
        for k := range current {
                keys = append(keys, k)
        }
        sort.Strings(keys)
        var buf []byte
        buf = append(buf, `{"__t":"f","v":{`...)
        first := true
        for _, k := range keys {
                raw, ok := keyBytes[k]
                if !ok {
                        continue
                }
                if !first {
                        buf = append(buf, ',')
                }
                first = false
                kb, _ := json.Marshal(k)
                buf = append(buf, kb...)
                buf = append(buf, ':')
                buf = append(buf, raw...)
        }
        buf = append(buf, '}', '}')
        return buf
}

// ============================================================================
// 4. Static-asset gzip cache (v0.9.109-lean2)
// ============================================================================

// gzipEntry — serveStatic used to re-gzip the 205KB chart.umd.min.js on
// EVERY request.  Cache the compressed bytes per (path, mtime, size).
type gzipEntry struct {
        size  int64
        mtime int64
        gz    []byte
}

var (
        gzipMu    sync.Mutex
        gzipCache = map[string]*gzipEntry{}
)

// gzipCached returns the gzip encoding of data for path (default
// compression level — byte-identical to gzip.NewWriter on the same
// input), cached across requests.  Returns nil on error (caller streams).
func gzipCached(path string, data []byte) []byte {
        var size, mtime int64
        if fi, err := os.Stat(path); err == nil {
                size = fi.Size()
                mtime = fi.ModTime().UnixNano()
        }
        gzipMu.Lock()
        defer gzipMu.Unlock()
        if e := gzipCache[path]; e != nil && e.size == size && e.mtime == mtime {
                return e.gz
        }
        var buf bytes.Buffer
        zw := gzip.NewWriter(&buf)
        if _, err := zw.Write(data); err != nil {
                return nil
        }
        if err := zw.Close(); err != nil {
                return nil
        }
        gz := buf.Bytes()
        gzipCache[path] = &gzipEntry{size: size, mtime: mtime, gz: gz}
        return gz
}

// resetGzipCacheForTest clears the gzip cache (tests only).
func resetGzipCacheForTest() {
        gzipMu.Lock()
        defer gzipMu.Unlock()
        gzipCache = map[string]*gzipEntry{}
}
