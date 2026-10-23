package main

// perf_cache.go — v0.9.108-lean: per-cycle garbage elimination.
//
// Three caches that remove the dominant allocation sources of the 30s
// collect cycle WITHOUT changing any output bytes:
//
//  1. readLogTailCached() — incremental log-tail reader.  v0.9.104's
////     readLogTail() re-read up to 8MB from disk and built a fresh string
//     EVERY cycle (even when the log had only grown by a few KB).  This
//     keeps a per-file tail cache: unchanged files are not read at all,
//     grown files are appended incrementally, and the assembled result
//     string is reused verbatim when nothing changed.  Output is
//     byte-identical to readLogTail() for the same file state.
//
//  2. buildDocRaw() — marshal each top-level key of the dashboard
//     document exactly ONCE per cycle (was 3-4x: writeCurrentJSON,
//     computeKeyHashes, notifySSE, and again per HTTP request).  The
//     cached per-key bytes are reused for hashing (same md5 values as
//     v0.9.104 — same input bytes), current.json assembly and SSE
//     messages.  Assembled output is byte-identical to json.Marshal of
//     the equivalent map (Go sorts map keys; we sort them the same way).
//
//  3. notifySSEFromRaw() / writeCurrentJSONFromRaw() — consume the
//     cached bytes instead of re-marshaling.
//
// Design note (why this beats v0.9.105's approach): v0.9.105 replaced
// json.Marshal with custom type-switch hashing and got a CPU REGRESSION
// (Go's reflect encoder is heavily optimized).  This approach keeps
// json.Marshal's fast path and simply stops calling it 3-4x per cycle.

import (
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
// 1. Incremental log-tail cache
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
//
// Caching behaviour:
//   - stat signature unchanged since last call → returns the cached
//     string with zero reads and zero allocations (common on quiet hosts)
//   - file grew → only the new bytes are read and appended to the cache
//   - file shrank / rotated / budget changed → tail re-read for that file
func readLogTailCached(budget int64) string {
        tailMu.Lock()
        defer tailMu.Unlock()

        files, _ := filepath.Glob(logGlobPattern)
        if len(files) == 0 {
                return ""
        }
        // Same ordering as readLogTail: newest-first by mtime.
        sort.Slice(files, func(i, j int) bool {
                fi, _ := os.Stat(files[i])
                fj, _ := os.Stat(files[j])
                return fi.ModTime().After(fj.ModTime())
        })

        // Budget change invalidates all cached chunk sizes.
        if budget != tailBudget {
                tailFiles = map[string]*tailFile{}
                tailBudget = budget
                tailSig = ""
        }

        // Refresh per-file chunks + build the state signature.
        var sig strings.Builder
        order := make([]*tailFile, 0, len(files))
        paths := make([]string, 0, len(files))
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
                        // Shrank, rotated, or first read: full tail read.
                        fc.chunk = readTailRegion(p, size, budget)
                        fc.size, fc.mtime = size, mtime
                }
                order = append(order, fc)
                paths = append(paths, p)
        }

        // Nothing changed → return the previous assembled string as-is.
        s := sig.String()
        if s == tailSig && s != "" {
                return tailJoined
        }

        // Assemble exactly like readLogTail: for each file newest-first,
        // take its last min(size, remaining) bytes + '\n'.
        var sb strings.Builder
        remaining := budget
        for i, fc := range order {
                if remaining <= 0 {
                        break
                }
                size := fc.size
                take := size
                if take > remaining {
                        take = remaining
                }
                if int64(len(fc.chunk)) < take {
                        take = int64(len(fc.chunk))
                }
                sb.Write(fc.chunk[int64(len(fc.chunk))-take:])
                sb.WriteByte('\n')
                remaining -= take
                _ = paths[i]
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
// 2. Marshal-once document cache
// ============================================================================

// buildDocRaw marshals every top-level value of doc exactly once and
// assembles the full document from the cached per-key bytes.
//
// Returns:
//   - docBytes: identical bytes to json.Marshal(doc) — Go's map encoder
//     sorts keys; we sort them the same way.  Per-value bytes come from
//     json.Marshal itself (same escaping, same float formatting).
//   - keyBytes: per-key raw JSON, reused for md5 hashing (identical hash
//     values to v0.9.104's computeKeyHashes) and SSE delta assembly.
//
// On any per-key marshal error the function falls back to a single
// json.Marshal(doc) so the output degrades exactly like v0.9.104.
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
                        // Fallback: identical behaviour to v0.9.104's
                        // json.Marshal(c.current) (which also fails).
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
                kb, _ := json.Marshal(k) // quoted key, same escaping as map encoder
                buf = append(buf, kb...)
                buf = append(buf, ':')
                buf = append(buf, keyBytes[k]...)
        }
        buf = append(buf, '}')
        return buf, keyBytes
}

// writeCurrentJSONFromRaw writes the pre-marshaled document atomically.
// Byte-identical to v0.9.104's writeCurrentJSON() output.
func (c *Collector) writeCurrentJSONFromRaw(docBytes []byte) {
        path := filepath.Join(histDir, "current.json")
        tmp := path + ".tmp"
        if err := os.WriteFile(tmp, docBytes, 0644); err != nil {
                fmt.Fprintf(os.Stderr, "collector: write current.json failed: %v\n", err)
                return
        }
        os.Rename(tmp, path)
}

// ============================================================================
// 3. SSE delta from cached bytes
// ============================================================================

// notifySSEFromRaw is a byte-output-compatible replacement for
// notifySSE() that hashes the pre-marshaled key bytes instead of
// re-marshaling every value.  md5 inputs are the same bytes v0.9.104
// hashed, so the stored keyHashes values and the delta decisions are
// identical.  Message assembly reproduces json.Marshal's map output
// (sorted keys, same value bytes).
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
        // v0.9.83 semantics: carry forward slow-key hashes on non-full cycles.
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
                // Full document — first push or after reset.
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

        // Delta — only changed keys.
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

        // Store new hashes for next cycle regardless of whether we send anything.
        c.mu.Lock()
        c.keyHashes = newHashes
        c.mu.Unlock()

        if len(deltaKeys) == 0 && len(removed) == 0 {
                return // nothing changed
        }

        // Assemble {"__t":"d","c":{...}} [, "r":[...]] exactly like
        // json.Marshal of the v0.9.104 message map (keys sorted: __t, c, r;
        // delta object keys sorted).
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
// Byte-identical to json.Marshal(map[string]interface{}{"__t":"f","v":doc}).
func assembleFullMessage(c *Collector, keyBytes map[string][]byte) []byte {
        c.mu.RLock()
        current := c.current
        c.mu.RUnlock()
        // Reassemble the document in sorted key order (same as buildDocRaw).
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
