package main

// cookie_dest.go — persistent cookie→dest map.
//
// v0.8.8: cdest was previously rebuilt from the 2 MB log tail on every
// collect cycle.  If a proof's cookie was established MORE than 2 MB
// of log ago (i.e. before the log tail window), the cookie wasn't in
// cdest and dest was empty in recent_proofs.
//
// This file persists the cookie→dest map to disk so cookies from older
// estab events survive across log rotations and binary restarts.
//
// Flow:
//   1. On startup: loadCookieDestFromDisk() — reads cookie_dest.json
//   2. On each collect cycle:
//        a. cookieDestMap(text) builds fresh map from log tail
//        b. mergeCookieDest(fresh, disk) — fresh wins for non-empty dest,
//           disk provides dest for cookies missing from fresh
//        c. saveCookieDestToDisk(merged) — atomic write
//        d. Use merged map as cdest
//
// File format: {"cookie_string": ["v4_string", "v6_string"], ...}
// Path: /var/lib/bpftune/history/cookie_dest.json (~1-5 MB for ~100k cookies)
//
// The file is rewritten on every collect cycle (30s) but only if the
// merged map changed since the last save (cheap md5 comparison).

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

var (
	cookieDestPath        = "/var/lib/bpftune/history/cookie_dest.json"
	cookieDestMu          sync.RWMutex
	cookieDestDiskMap     map[string][2]string // loaded once at startup
	cookieDestLastHash    string               // md5 of last saved map (avoids rewrites when unchanged)
	cookieDestLastSave    time.Time
	cookieDestSaveThresh  = 60 * time.Second // max interval between saves (even if unchanged)
	cookieDestMaxEntries  = 200000            // cap to bound file size (~10 MB)
)

// loadCookieDestFromDisk reads the persisted cookie→dest map.
// Returns an empty map if the file doesn't exist or is corrupt
// (in which case it logs a warning but doesn't fail).
func loadCookieDestFromDisk() map[string][2]string {
	data, err := os.ReadFile(cookieDestPath)
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "[cdest] load: read %s failed: %v\n", cookieDestPath, err)
		}
		return map[string][2]string{}
	}
	var m map[string][2]string
	if err := json.Unmarshal(data, &m); err != nil {
		fmt.Fprintf(os.Stderr, "[cdest] load: parse failed (resetting): %v\n", err)
		return map[string][2]string{}
	}
	fmt.Fprintf(os.Stderr, "[cdest] loaded %d cookies from %s\n", len(m), cookieDestPath)
	return m
}

// saveCookieDestToDisk atomically writes the cookie→dest map to disk.
// Uses tmp + rename to avoid partial writes if the process is killed
// mid-write.  The file is opened with 0644 perms.
func saveCookieDestToDisk(m map[string][2]string) error {
	if err := os.MkdirAll(filepath.Dir(cookieDestPath), 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	data, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	tmp := cookieDestPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := os.Rename(tmp, cookieDestPath); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// mergeCookieDest merges fresh (from log tail) into disk (loaded at startup
// or from previous cycle).  Returns the merged map.
//
// Merge rules:
//   - If a cookie is in BOTH: fresh wins (latest estab event overrides)
//   - If a cookie is ONLY in disk: keep disk value (preserves older cookies)
//   - If a cookie is ONLY in fresh: add to merged
//   - If fresh has empty dest for a cookie that's non-empty in disk,
//     keep the disk value (don't clobber a known dest with empty)
//
// The merged map is bounded by cookieDestMaxEntries to prevent unbounded
// growth.  When over the limit, oldest cookies (by insertion order in
// the disk map) are evicted.  In practice this never triggers — cookies
// are 32-bit ints and we cap at 200k entries (~10 MB file).
func mergeCookieDest(fresh, disk map[string][2]string) map[string][2]string {
	merged := make(map[string][2]string, len(fresh)+len(disk))

	// Start with disk entries
	for k, v := range disk {
		merged[k] = v
	}

	// Overlay fresh entries
	for k, fv := range fresh {
		if dv, ok := merged[k]; ok {
			// Cookie is in both.  Use fresh if it has any non-empty dest,
			// otherwise keep disk value.
			if fv[0] != "" || fv[1] != "" {
				merged[k] = fv
			} else {
				// Fresh is empty; keep disk value
				_ = dv
			}
		} else {
			// Cookie is new (only in fresh)
			merged[k] = fv
		}
	}

	// Bound the map size if over threshold.  Cookie values are int32,
	// so we can't easily determine "oldest" without timestamps.  As a
	// simple heuristic, just drop the entries with the smallest cookie
	// values (these are oldest connections in practice — cookie counter
	// increases over time).
	if len(merged) > cookieDestMaxEntries {
		keys := make([]string, 0, len(merged))
		for k := range merged {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		dropCount := len(merged) - cookieDestMaxEntries
		for i := 0; i < dropCount; i++ {
			delete(merged, keys[i])
		}
		fmt.Fprintf(os.Stderr, "[cdest] pruned %d old cookies (cap=%d)\n",
			dropCount, cookieDestMaxEntries)
	}

	return merged
}

// persistCookieDest is called from collect() after cookieDestMap(text).
// It merges fresh with disk, saves if changed, and returns the merged
// map for use as cdest.
//
// Safe to call from any goroutine (uses cookieDestMu).
func persistCookieDest(fresh map[string][2]string) map[string][2]string {
	cookieDestMu.Lock()
	defer cookieDestMu.Unlock()

	if cookieDestDiskMap == nil {
		// First call — load from disk (or empty if file missing)
		cookieDestDiskMap = loadCookieDestFromDisk()
	}

	merged := mergeCookieDest(fresh, cookieDestDiskMap)
	cookieDestDiskMap = merged

	// Save if changed or if it's been too long since last save
	newHash := cookieDestMapHash(merged)
	if newHash != cookieDestLastHash || time.Since(cookieDestLastSave) > cookieDestSaveThresh {
		if err := saveCookieDestToDisk(merged); err != nil {
			fmt.Fprintf(os.Stderr, "[cdest] save failed: %v\n", err)
		} else {
			cookieDestLastHash = newHash
			cookieDestLastSave = time.Now()
		}
	}

	return merged
}

// cookieDestMapHash returns a cheap content hash for change detection.
// Uses len + sum of first/last few entries' key+value bytes.  Faster
// than full md5 for large maps.
func cookieDestMapHash(m map[string][2]string) string {
	if len(m) == 0 {
		return "0:"
	}
	// Sample 16 keys (deterministic) and hash them.
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	step := len(keys) / 16
	if step == 0 {
		step = 1
	}
	var sample []byte
	for i := 0; i < len(keys); i += step {
		k := keys[i]
		v := m[k]
		sample = append(sample, k...)
		sample = append(sample, v[0]...)
		sample = append(sample, v[1]...)
	}
	return fmt.Sprintf("%d:%x", len(m), sample)
}
