package main

// cookie_dest.go — persistent cookie→dest map.
//
// v0.9.0 fix for the "proofs show dash" bug.
//
// PROBLEM
//   The cookie→dest map was rebuilt from the 2 MB log tail on every 30s
//   collect cycle.  If a proof's cookie was established MORE than 2 MB
//   of log ago (i.e. before the log tail window), the cookie was missing
//   from cdest and dest was "" in recent_proofs / recent_swaps /
//   proofs_raw — which the JS rendered as a bare middot (" · 174.7 Mb/s").
//
//   This was particularly bad for IPv6 connections because the only
//   way to recover dest6/dest6b is from the original `estab` line,
//   which fires once per connection and is the first event to rotate
//   out of the log tail.
//
// SOLUTION
//   Persist the cookie→dest map to disk so cookies from older estab
//   events survive across log rotations and binary restarts.
//
//   1. On startup: loadCookieDest() reads cookie_dest.json
//   2. On each collect cycle:
//        a. cookieDestMap(text) builds the fresh map from the log tail
//        b. mergeCookieDest(fresh, disk) — non-empty fields in fresh
//           win, disk fills in fields fresh is missing
//        c. saveCookieDestToDisk(merged) — atomic write, throttled to
//           >=60s apart and only when content changed
//        d. Use merged map as cdest
//
// FILE FORMAT
//   {"cookie_string": ["v4_string", "v6_string", "v6b_string"], ...}
//
// PATH
//   /var/lib/bpftune/history/cookie_dest.json
//   (override via --data-root; main.go sets cookieDestPath)
//
// SIZE BOUNDS
//   Each entry is ~120 bytes JSON (cookie ~10 chars + 3 dest strings
//   ~15 chars each + brackets/commas).  Cap at 200k entries → ~24 MB
//   worst case.  Eviction is FIFO when cap is reached.

import (
        "crypto/md5"
        "encoding/json"
        "fmt"
        "os"
        "path/filepath"
        "sort"
        "sync"
        "time"
)

var (
        cookieDestPath       = "/var/lib/bpftune/history/cookie_dest.json"
        cookieDestMu         sync.Mutex
        cookieDestDiskMap    map[string]cdestEntry // loaded once at startup
        cookieDestLastHash   [16]byte              // md5 of last saved map (avoids rewrites when unchanged)
        cookieDestLastSave   time.Time
        cookieDestSaveThresh = 60 * time.Second // max interval between saves (even if unchanged)
        cookieDestMaxEntries = 10_000           // v0.9.9: reduced from 200K — cookies older than 1h are useless
        // (the connection is long gone). Saves ~80% of JSON marshal time.
)

// loadCookieDestFromDisk reads the persisted cookie→dest map.
// Returns an empty map if the file doesn't exist or is corrupt
// (in which case it logs a warning but doesn't fail).
func loadCookieDestFromDisk() map[string]cdestEntry {
        data, err := os.ReadFile(cookieDestPath)
        if err != nil {
                if !os.IsNotExist(err) {
                        fmt.Fprintf(os.Stderr, "[cdest] load: read %s failed: %v\n", cookieDestPath, err)
                }
                return map[string]cdestEntry{}
        }
        // File format uses []string{v4, v6, v6b}; convert to cdestEntry.
        var raw map[string][]string
        if err := json.Unmarshal(data, &raw); err != nil {
                fmt.Fprintf(os.Stderr, "[cdest] load: parse failed (resetting): %v\n", err)
                return map[string]cdestEntry{}
        }
        out := make(map[string]cdestEntry, len(raw))
        for k, v := range raw {
                var e cdestEntry
                for i := 0; i < 3 && i < len(v); i++ {
                        e[i] = v[i]
                }
                out[k] = e
        }
        // Compute initial hash so we don't immediately rewrite on cycle 1.
        cookieDestLastHash = md5.Sum(data)
        cookieDestLastSave = time.Now()
        fmt.Fprintf(os.Stderr, "[cdest] loaded %d cookies from %s\n", len(out), cookieDestPath)
        return out
}

// saveCookieDestToDisk atomically writes the cookie→dest map to disk.
// Uses tmp + rename to avoid partial writes if the process is killed
// mid-write.  The file is opened with 0644 perms.
//
// Returns nil if the write succeeded OR if it was skipped (throttled
// or unchanged since last save).
func saveCookieDestToDisk(m map[string]cdestEntry) error {
        // Throttle: don't save more than once per cookieDestSaveThresh.
        if time.Since(cookieDestLastSave) < cookieDestSaveThresh {
                return nil
        }

        // Convert to JSON-friendly form ([]string instead of [3]string array
        // so json.Marshal produces ["1.2.3.4","",""] instead of "1.2.3.4","","").
        out := make(map[string][]string, len(m))
        for k, v := range m {
                out[k] = []string{v[0], v[1], v[2]}
        }
        data, err := json.MarshalIndent(out, "", "  ")
        if err != nil {
                return fmt.Errorf("marshal: %w", err)
        }

        // Skip if content unchanged since last save (md5 comparison).
        h := md5.Sum(data)
        if h == cookieDestLastHash {
                cookieDestLastSave = time.Now() // refresh so throttle counts the attempt
                return nil
        }

        // Ensure parent dir exists.
        dir := filepath.Dir(cookieDestPath)
        if err := os.MkdirAll(dir, 0755); err != nil {
                return fmt.Errorf("mkdir %s: %w", dir, err)
        }

        tmp := cookieDestPath + ".tmp"
        if err := os.WriteFile(tmp, data, 0644); err != nil {
                return fmt.Errorf("write %s: %w", tmp, err)
        }
        if err := os.Rename(tmp, cookieDestPath); err != nil {
                return fmt.Errorf("rename %s -> %s: %w", tmp, cookieDestPath, err)
        }

        cookieDestLastHash = h
        cookieDestLastSave = time.Now()
        return nil
}

// ensureCookieDestLoaded loads the cookie_dest map from disk if it hasn't
// been loaded yet. Called at the start of each collect cycle before
// readBPFMap() so v6ToV4Label() has data to work with.
// v0.9.41: Without this, the first readBPFMap() call has a nil
// cookieDestDiskMap and all v6 entries stay as "v6:xxxx".
func ensureCookieDestLoaded() {
        cookieDestMu.Lock()
        defer cookieDestMu.Unlock()
        if cookieDestDiskMap == nil {
                cookieDestDiskMap = loadCookieDestFromDisk()
        }
}

// persistCookieDest merges the fresh map (just built from the log tail)
// with the on-disk map (loaded at startup) and persists the result.
//
// Merge rule: fresh wins for any non-empty field.  Disk fills in fields
// that fresh is missing (this is what fixes the "old cookie" case —
// the estab line rotated out of the log tail, but the dest is still
// in the disk map from a previous cycle).
//
// Returns the merged map (caller uses it as cdest for this cycle).
func persistCookieDest(fresh map[string]cdestEntry) map[string]cdestEntry {
        cookieDestMu.Lock()
        defer cookieDestMu.Unlock()

        if cookieDestDiskMap == nil {
                // First cycle after startup: load from disk.
                cookieDestDiskMap = loadCookieDestFromDisk()
        }

        // Merge: start from disk, overlay non-empty fields from fresh.
        merged := make(map[string]cdestEntry, len(cookieDestDiskMap)+len(fresh))
        for k, v := range cookieDestDiskMap {
                merged[k] = v
        }
        for k, v := range fresh {
                cur := merged[k]
                if v[0] != "" {
                        cur[0] = v[0]
                }
                if v[1] != "" {
                        cur[1] = v[1]
                }
                if v[2] != "" {
                        cur[2] = v[2]
                }
                merged[k] = cur
        }

        // v0.9.95 (AUDIT-PROOFS-1 LEAK #5): FIFO cap. Cookies are monotonically
        // increasing per boot, but on bpftune restart (without kernel reboot)
        // OR on kernel reboot, the new boot's cookies start at 0 again. The old
        // 'sort by cookie numeric ascending and drop smallest' rule would drop
        // the NEW boot's small cookies (1-100) instead of the OLD boot's large
        // ones (40000-50000), breaking cdest lookups for all new proofs and
        // producing (unknown) dest in the panel. The fix: prefer dropping
        // entries that are NOT in the fresh set (i.e. haven't been seen in the
        // current log tail — they're disk-only and stale). Among disk-only
        // candidates, sort by cookie numeric ascending and drop smallest (still
        // correct within a single previous boot). Only if fresh itself exceeds
        // the cap do we drop the smallest fresh cookies as a last resort.
        if len(merged) > cookieDestMaxEntries {
                type ck struct {
                        k string
                        n int64
                }
                var diskOnly []ck
                for k := range merged {
                        if _, wasFresh := fresh[k]; !wasFresh {
                                var n int64
                                fmt.Sscanf(k, "%d", &n)
                                diskOnly = append(diskOnly, ck{k, n})
                        }
                }
                sort.Slice(diskOnly, func(i, j int) bool { return diskOnly[i].n < diskOnly[j].n })
                drop := len(merged) - cookieDestMaxEntries
                for i := 0; i < drop && i < len(diskOnly); i++ {
                        delete(merged, diskOnly[i].k)
                }
                // If we still need to drop more (rare: fresh set itself is over
                // cap), drop the smallest fresh cookies as a last resort.
                if drop > len(diskOnly) {
                        var freshKeys []ck
                        for k := range fresh {
                                var n int64
                                fmt.Sscanf(k, "%d", &n)
                                freshKeys = append(freshKeys, ck{k, n})
                        }
                        sort.Slice(freshKeys, func(i, j int) bool { return freshKeys[i].n < freshKeys[j].n })
                        remaining := drop - len(diskOnly)
                        for i := 0; i < remaining && i < len(freshKeys); i++ {
                                delete(merged, freshKeys[i].k)
                        }
                }
        }

        // Persist (throttled + content-hash-skipped).
        if err := saveCookieDestToDisk(merged); err != nil {
                fmt.Fprintf(os.Stderr, "[cdest] save: %v\n", err)
        }

        // Update disk map so next cycle's merge starts from the new baseline.
        cookieDestDiskMap = merged
        return merged
}
