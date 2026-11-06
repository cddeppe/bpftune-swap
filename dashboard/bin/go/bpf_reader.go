package main

// bpf_reader.go — runs bpftool and parses the JSON output of the
// remote_host_map BPF map.  Extracted from main.go for clarity.
//
// All addresses from the BPF map go through ResolveBucket() exactly once
// here. The resulting labeled bucket ID is then used everywhere else:
//   - current.json buckets[].dest
//   - metric_by_bucket / bucket_live map keys
//   - CSV addr column (writeBucketsCSV)
//   - ring buffer key (captureSnapshotsFromBPF)
//
// CSV readers do NOT re-apply ResolveBucket — they trust the stored label
// (see csv_reader.go). This was the root cause of "custom bucket
// disappears": applying ResolveBucket again at read time would remap a
// labeled "controld" back to itself (no harm) BUT would also remap a raw
// "2606:1a40::" (no label) to "controld" if a label was added later,
// creating duplicate entries in the ring buffer.
//
// v0.9.111 (measured on al): bpftool output buffers are now POOLED.
// cmd.Output() allocated a fresh bytes.Buffer per fork and grew it by
// doubling to the map-dump size (~8MB on a 324-bucket host) — profile
// showed 382MB cumulative garbage from 26 forks (the single largest
// allocator in steady state, >50% of all churn). runBpftoolJSON reuses
// pooled buffers and parses before returning them to the pool, so the
// steady-state fork costs zero buffer allocations. Also: the raw-syscall
// fallback is now logged (rate-limited) so the reason the syscall path
// fails on a host is visible in the journal instead of silently forking
// bpftool forever.

import (
        "bytes"
        "context"
        "encoding/json"
        "fmt"
        "os"
        "os/exec"
        "sort"
        "strconv"
        "strings"
        "sync"
        "time"
)

// hostEntry is one BPF map entry after label resolution + merge.
// Mirrors Python read_map()'s (inst, addr, v) tuple.
//
// B3-fix: MaxInst tracks the largest single inst seen across folded entries,
// separate from Inst which is the SUM. Used by the merge logic to decide
// which entry donates its metrics/best_alg/min_rtt — we want the entry
// with the most instances, not whichever appeared first.
//
// v0.9.38: V4MinRTT and V6MinRTT track per-protocol min_rtt separately.
type hostEntry struct {
        Inst     int
        MaxInst  int    // B3-fix: largest single inst across folded entries
        Addr     string // labeled + merged (e.g. "home-sco" or "2606:1a40::")
        V        map[string]interface{}
        V4MinRTT float64 // v0.9.38: separate v4 min_rtt (microseconds)
        V6MinRTT float64 // v0.9.38: separate v6 min_rtt (microseconds)
        V4Inst   int     // v0.9.38: v4-only instance count
        V6Inst   int     // v0.9.38: v6-only instance count
        // v0.9.128: map generation this bucket's data came from (0 = newest,
        // lower = newer; see readBPFMapSyscall). Older generations = maps
        // abandoned by a mid-run tuner reload — their values are frozen.
        Gen int `json:"-"`
}

// v0.9.111: pooled bpftool output buffers.  The pool entry is a
// *bytes.Buffer that keeps its capacity across forks — after warmup the
// 8MB map dump is parsed from a reused buffer with zero growth garbage.
type bpftoolBufs struct {
        out *bytes.Buffer
        err *bytes.Buffer
}

var bpftoolBufPool = sync.Pool{
        New: func() interface{} {
                return &bpftoolBufs{out: &bytes.Buffer{}, err: &bytes.Buffer{}}
        },
}

// runBpftoolJSON forks bpftool with the given args and unmarshals its
// stdout into out.  Semantics preserved from the old cmd.Output() path:
// exec failures return "bpftool: <err>[: stderr]", parse failures return
// "bpftool json: <err>".  Buffers return to the pool AFTER parsing so
// concurrent callers can never observe each other's bytes.
func runBpftoolJSON(ctx context.Context, out interface{}, args ...string) error {
        b := bpftoolBufPool.Get().(*bpftoolBufs)
        defer bpftoolBufPool.Put(b)
        b.out.Reset()
        b.err.Reset()

        cmd := exec.CommandContext(ctx, "bpftool", args...)
        cmd.Stdout = b.out
        cmd.Stderr = b.err
        if err := cmd.Run(); err != nil {
                msg := strings.TrimSpace(b.err.String())
                if msg != "" {
                        return fmt.Errorf("bpftool: %w: %s", err, msg)
                }
                return fmt.Errorf("bpftool: %w", err)
        }
        if err := json.Unmarshal(b.out.Bytes(), out); err != nil {
                return fmt.Errorf("bpftool json: %w", err)
        }
        return nil
}

// logBpfSyscallFallback — rate-limited diagnostic: WHY is the raw-syscall
// path falling back to bpftool forks on this host?  Logged at most once
// per 10 minutes so the journal shows the reason without being flooded.
var (
        bpfFallbackMu   sync.Mutex
        bpfFallbackLast time.Time
        bpfFallbackN    int
)

func logBpfSyscallFallback(err error) {
        if err == nil {
                return
        }
        bpfFallbackMu.Lock()
        defer bpfFallbackMu.Unlock()
        if time.Since(bpfFallbackLast) < 10*time.Minute {
                return
        }
        bpfFallbackLast = time.Now()
        bpfFallbackN++
        fmt.Fprintf(os.Stderr, "readBPFMap: raw syscall path failed (fallback #%d): %v — forking bpftool\n",
                bpfFallbackN, err)
}

// mapIDGenRank returns the generation index for mapID within ids: 0 = the
// NEWEST generation (highest id — BPF object ids are monotonic), regardless
// of the order ids happens to be iterated in.
//
// v0.9.130: gen tags were previously the LOOP INDEX over mapIDs, which is
// only correct while mapIDs is sorted newest-first. A resolver that returns
// the ids in any other order silently inverts the generation rules — the
// detached corpse map gets tagged as "newest" and its frozen values win
// every shared bucket, freezing the leaderboard (observed on al: Cloudflare
// showed corpse-only data while the live map kept updating). Deriving the
// rank from the id itself makes the tag correct by construction.
func mapIDGenRank(ids []int, mapID int) int {
        rank := 0
        for _, id := range ids {
                if id > mapID {
                        rank++
                }
        }
        return rank
}

// readBPFMap runs bpftool, parses the JSON, applies ResolveBucket + merges
// by final label.  Mirrors bpftune_log.py:read_map.
//
// v0.9.33: when collectorMode.CacheBPFMap is true, cache the result
// and skip the bpftool call when the map entry count hasn't changed
// (checked via a lightweight bpftool map show). This saves forking
// bpftool + parsing large JSON on every cycle when the map is stable.
//
// v0.9.127 CORRECTNESS FIX: entry count is NOT a value-change signal.
// The daemon updates rate_ema/metric_count/streaks/swap_score IN PLACE,
// so a stable bucket set meant the cached merged snapshot was served
// forever — the leaderboard froze while swaps/proofs (log-driven) stayed
// live. The count-based cache is now only used on the bpftool-fork
// FALLBACK path, and only within bpfMapCacheTTL. The raw-syscall path
// (the normal path since v0.9.86) always merges the fresh dump it
// already read.
var (
        bpfMapCache     []hostEntry
        bpfMapCacheErr  error
        bpfMapCacheSize int
        bpfMapCacheAt   time.Time
)

// bpfMapCacheTTL bounds how long the fallback (bpftool-fork) path may
// serve a cached snapshot. 60s = 2 normal cycles.
const bpfMapCacheTTL = 60 * time.Second

// ============================================================================
// v0.9.133: incremental corpse cache — flat per-cycle cost, no all-gens
// spikes (supersedes the v0.9.132 frozen-generation cache)
// ============================================================================
//
// v0.9.132 removed the per-cycle corpse tax but kept TWO all-gens dumps:
// the every-10th-cycle cache refresh, and the first call after startup
// (plus every reload). On a host with N accumulated generations ONE 30s
// cycle still dumped and parsed N x ~324 entries (~165ms CPU + ~120MB of
// allocations at N=16, real fleet geometry) — a CPU/GC spike every ~5
// minutes, and at startup the single largest allocation event of the
// process's life. Worse: readMapGens holds ALL generations' parsed entries
// live in one slice until the merge returns, so at N > ~30 the live heap
// alone (~240MB) walks through the watchdog's strict RSS arm (250MB, no
// startup grace, 2-strike kill) -> kill -> systemd restart -> identical
// spike -> the memory edition of the suicide loop v0.9.132 only gave a
// CPU-arm grace.
//
// v0.9.133 makes the cost FLAT: every dump call reads the live map plus
// AT MOST ONE corpse generation (round-robin), no matter how many
// generations exist. No call ever parses more than 2 maps.
//
// The cache stores, per corpse-carried label, the entry of the NEWEST
// corpse generation carrying it — the same value the full merge's
// generation rules pick (a newer gen replaces outright, an older gen is
// skipped). Refreshing generation rank k stores k's entries only where k
// is the newest carrier: an existing cache entry with a LOWER rank (a
// NEWER generation) keeps the label; a HIGHER rank (older) is overwritten.
// Because corpses are frozen, entries older than one sweep are still
// correct; the sweep only refreshes what the collector itself can write
// into a corpse (picker-writeback tracker fields, every 10th pass). After
// one full round-robin sweep the cache equals the Gen>0 slice of the full
// all-gens merge — proven by test, including randomized generation
// contents (v0_9_133_test.go).
//
// Differences from v0.9.132, all improvements:
//   - the every-10-cycle refresh spike is gone (one corpse map per cycle);
//   - the startup/reload full dump is gone: warmup is incremental, one
//     corpse generation per cycle (corpse-only labels appear over the
//     first N cycles — logged; the live map is complete from cycle 1);
//   - when the live map DROPS a label, the corpse fallback now appears
//     the NEXT cycle. v0.9.132 needed the next 10-cycle refresh to even
//     notice: its refresh-time Gen>0 slice never contained labels the
//     then-live map carried, so a newly-dropped label lost its corpse
//     history for up to 5 minutes.
//
// A reload (id set change) re-ranks generations, so the cache resets and
// re-warms incrementally — deliberately NOT a one-shot full rebuild: the
// reload moment is exactly when the tuner is re-initializing BPF and the
// box is busiest; the last thing to add there is an N-map dump burst.
// The legacy error path still computes a full all-gens merge when it runs
// (rare); it seeds the cache from that merge for free.

type corpseBestEnt struct {
        ent  hostEntry
        rank int // generation rank that supplied it (1 = newest corpse; 0 = live, unused here)
}

type corpseGenCache struct {
        ids     []int                    // id set the cache is built from, newest first; len = generations
        best    map[string]corpseBestEnt // corpse-carried label -> newest carrier's entry
        labels  []hostEntry              // best values, sorted by Addr (the fold input)
        cursor  int                      // round-robin position over corpse ranks 1..len(ids)-1
        warmed  int                      // sweep steps completed since the last reset
        warmDone bool                    // "warmup complete" logged once
        calls   int                      // dump calls seen (diagnostics)
}

var (
        corpseCacheMu sync.Mutex
        corpseCache   = corpseGenCache{}
)

// sameIntIDs reports whether two id slices are element-wise equal.
func sameIntIDs(a, b []int) bool {
        if len(a) != len(b) {
                return false
        }
        for i := range a {
                if a[i] != b[i] {
                        return false
                }
        }
        return true
}

// noteIDs records the current id set and reports whether it changed (a
// reload re-ranks generations, so a change resets the cache for an
// incremental re-warm). Same set -> no change.
func (c *corpseGenCache) noteIDs(ids []int) bool {
        if c.ids != nil && sameIntIDs(c.ids, ids) {
                return false
        }
        c.ids = append([]int(nil), ids...)
        c.best = map[string]corpseBestEnt{}
        c.labels = nil
        c.cursor = 0
        c.warmed = 0
        c.warmDone = false
        return true
}

// nextSweepRank picks the next corpse generation to refresh (round-robin
// over ranks 1..len(ids)-1) and advances the cursor. Returns 0 when there
// are no corpse generations. The cursor advances per ATTEMPT, so a
// permanently unreadable corpse is retried once per round instead of
// stalling the sweep (its previous slice — frozen data — stays cached).
func (c *corpseGenCache) nextSweepRank() int {
        corpses := len(c.ids) - 1
        if corpses <= 0 {
                return 0
        }
        rank := c.cursor + 1
        c.cursor = (c.cursor + 1) % corpses
        return rank
}

// storeGen folds one freshly dumped + merged corpse generation (rank >= 1)
// into the cache. k's entry wins a label only when no NEWER corpse
// generation (lower rank) already supplies it. Returns true exactly once,
// when the post-reset warmup completes (for the one-shot log line).
func (c *corpseGenCache) storeGen(rank int, merged []hostEntry) bool {
        if rank <= 0 || rank >= len(c.ids) {
                return false
        }
        for _, h := range merged {
                if cur, ok := c.best[h.Addr]; ok && cur.rank < rank {
                        continue // a newer corpse generation supplies this label
                }
                c.best[h.Addr] = corpseBestEnt{ent: h, rank: rank}
        }
        c.recomputeLabels()
        if c.warmed < len(c.ids)-1 {
                c.warmed++
                if c.warmed == len(c.ids)-1 && !c.warmDone {
                        c.warmDone = true
                        return true
                }
        }
        return false
}

// recomputeLabels rebuilds the sorted fold input from best.
func (c *corpseGenCache) recomputeLabels() {
        out := make([]hostEntry, 0, len(c.best))
        for _, b := range c.best {
                out = append(out, b.ent)
        }
        sort.Slice(out, func(i, j int) bool { return out[i].Addr < out[j].Addr })
        c.labels = out
}

// seedFromFullMerge installs the Gen>0 slice of a full all-gens merge —
// the exact end state a completed round-robin sweep converges to. Used by
// the legacy error path, which already paid for the full dump.
func (c *corpseGenCache) seedFromFullMerge(ids []int, merged []hostEntry) {
        c.ids = append([]int(nil), ids...)
        c.best = map[string]corpseBestEnt{}
        for _, h := range merged {
                if h.Gen > 0 {
                        c.best[h.Addr] = corpseBestEnt{ent: h, rank: h.Gen}
                }
        }
        if n := len(ids) - 1; n > 0 {
                c.warmed = n
        } else {
                c.warmed = 0
        }
        c.cursor = 0
        c.warmDone = true
        c.recomputeLabels()
}

// fold appends cached corpse labels that the live merge does not have —
// the same "live wins per label" rule the full merge applies to corpse
// entries. The returned slice may alias live when there is nothing to add.
func (c *corpseGenCache) fold(live []hostEntry) []hostEntry {
        if len(c.labels) == 0 {
                return live
        }
        have := make(map[string]bool, len(live))
        for _, h := range live {
                have[h.Addr] = true
        }
        out := live
        for _, h := range c.labels {
                if !have[h.Addr] {
                        out = append(out, h)
                }
        }
        return out
}

// readGenTagged dumps ONE map by its rank in mapIDs and tags every entry
// with that rank. readMapGens cannot be reused here: it ranks by the list
// passed to it, so a single-element list would tag a corpse as gen 0
// (live).
func readGenTagged(mapIDs []int, rank int) ([]map[string]interface{}, error) {
        raw, err := readRemoteHostMapByID(mapIDs[rank])
        if err != nil {
                return nil, err
        }
        for i := range raw {
                raw[i]["map_gen"] = float64(rank)
        }
        return raw, nil
}

func readBPFMap() ([]hostEntry, error) {
        // v0.9.133: resolve the id set up front; the sweep plan and the
        // reload reset both hang off it.
        mapIDs, idErr := resolveRemoteHostMapIDs()

        corpseCacheMu.Lock()
        corpseCache.calls++
        sweepRank := 0
        reload := false
        if idErr == nil {
                reload = corpseCache.noteIDs(mapIDs)
                sweepRank = corpseCache.nextSweepRank()
        }
        corpseCacheMu.Unlock()
        if reload && len(mapIDs) > 1 {
                fmt.Fprintf(os.Stderr, "corpse cache: map set changed (%d generations) — re-warming corpse data 1 gen/cycle\n", len(mapIDs))
        }

        if idErr == nil && len(mapIDs) > 0 {
                // (1) Sweep step: dump ONE corpse generation (round-robin).
                // A dump failure keeps the previous slice — corpse data is
                // frozen, so a stale slice is still correct; the id-set
                // check catches maps that actually disappear.
                if sweepRank > 0 {
                        if raw, err := readGenTagged(mapIDs, sweepRank); err == nil {
                                if merged, mErr := mergeBPFMapEntries(raw); mErr == nil {
                                        corpseCacheMu.Lock()
                                        warmDone := corpseCache.storeGen(sweepRank, merged)
                                        corpseCacheMu.Unlock()
                                        if warmDone {
                                                fmt.Fprintf(os.Stderr, "corpse cache: warmup complete (%d corpse gens, %d labels) — steady state\n",
                                                        len(mapIDs)-1, len(corpseCache.labels))
                                        }
                                }
                        }
                }
                // (2) Live dump: ONLY the newest generation.
                if raw, err := readMapGens(mapIDs[:1]); err == nil {
                        if merged, mErr := mergeBPFMapEntries(raw); mErr == nil {
                                corpseCacheMu.Lock()
                                out := corpseCache.fold(merged)
                                corpseCacheMu.Unlock()
                                // mergeBPFMapEntries cached the live-only merge for the
                                // fallback path; replace it with the folded result so a
                                // fallback snapshot still carries the corpse-only labels.
                                if collectorMode.CacheBPFMap {
                                        bpfMapCache = out
                                        bpfMapCacheErr = nil
                                        bpfMapCacheAt = time.Now()
                                }
                                return out, nil
                        }
                }
                // fall through to the legacy path on any failure
        }

        // Legacy path (v0.9.128): dump EVERY remote_host_map generation by ID,
        // newest first, tagged with its generation index. Kept as the fallback
        // for read errors, and as the whole path when id resolution failed.
        // It re-pays the full dump cost ONCE on the error path and seeds the
        // incremental cache from the result, so the next cycle is flat again.
        raw, sysErr := readBPFMapSyscall()
        if sysErr == nil && len(raw) >= 0 {
                // v0.9.127: no count-based early return here. The full dump was
                // already read by the syscall path; serving a stale cached merge
                // when the count matches froze every in-place metric update
                // (rate_ema, streaks, swap_score) out of the leaderboard.
                bpfMapCacheSize = len(raw)
                if merged, mErr := mergeBPFMapEntries(raw); mErr == nil {
                        if ids, rErr := resolveRemoteHostMapIDs(); rErr == nil {
                                corpseCacheMu.Lock()
                                corpseCache.seedFromFullMerge(ids, merged)
                                corpseCacheMu.Unlock()
                        }
                        return merged, nil
                }
                return mergeBPFMapEntries(raw)
        }
        // v0.9.111: tell the operator WHY we are forking bpftool (once/10min).
        logBpfSyscallFallback(sysErr)

        // v0.9.128: dump EVERY remote_host_map generation by ID, newest
        // first, tagged with its generation index — mirroring
        // readBPFMapSyscall. The old single `map dump name remote_host_map`
        // fork dumped every same-name map but WITHOUT ids in the output, so
        // generations were indistinguishable and the instances-priority
        // merge could let a detached generation's frozen values dominate
        // live data. (The v0.9.33 count-based cache shortcut is gone:
        // with several maps the first map's entry count said nothing about
        // the merged snapshot, and v0.9.127 had already restricted it to a
        // 60s TTL nicety.)
        mapIDs, err := resolveRemoteHostMapIDs()
        if err != nil {
                if collectorMode.CacheBPFMap {
                        bpfMapCache = nil
                        bpfMapCacheErr = err
                }
                return nil, err
        }
        // v0.9.27: add 10s timeout to prevent collector hanging on bpftool.
        ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        defer cancel()
        var rawDump []map[string]interface{}
        dumped := 0
        var dumpErr error
        for _, id := range mapIDs {
                var perMap []map[string]interface{}
                if err := runBpftoolJSON(ctx, &perMap, "--json", "map", "dump", "id", strconv.Itoa(id)); err != nil {
                        if dumpErr == nil {
                                dumpErr = err
                        }
                        continue // unreadable generation — skip, not fail
                }
                dumped++
                // v0.9.130: gen = id rank (0 = highest id = newest), NOT the
                // loop index — immune to mapIDs ordering. See mapIDGenRank.
                genRank := mapIDGenRank(mapIDs, id)
                for i := range perMap {
                        perMap[i]["map_gen"] = float64(genRank)
                }
                rawDump = append(rawDump, perMap...)
        }
        if dumped == 0 {
                if collectorMode.CacheBPFMap {
                        bpfMapCache = nil
                        bpfMapCacheErr = dumpErr
                }
                return nil, dumpErr
        }
        if collectorMode.CacheBPFMap {
                bpfMapCacheSize = len(rawDump)
        }
        return mergeBPFMapEntries(rawDump)
}

// mergeBPFMapEntries takes raw bpftool-formatted entries (either from
// bpftool JSON or from raw-syscall parsing) and merges them into
// []hostEntry. This is the common merge logic extracted from readBPFMap
// so both code paths share it.
func mergeBPFMapEntries(raw []map[string]interface{}) ([]hostEntry, error) {
        // Merge by final labeled addr: sum instances, keep the entry
        // with more instances for the other fields (matches Python).
        merged := map[string]*hostEntry{}
        var order []string
        for _, entry := range raw {
                fmtData, ok := entry["formatted"].(map[string]interface{})
                if !ok {
                        continue
                }
                // v0.9.128: generation tag (0 = newest, lower = newer). Set by
                // readBPFMapSyscall and the per-ID fork path; absent on legacy
                // single-map dumps → 0 (untagged entries all merge, which is
                // the pre-0.9.128 behaviour).
                gen := toInt(entry["map_gen"])
                val, ok := fmtData["value"].(map[string]interface{})
                if !ok {
                        continue
                }
                keyData, ok := fmtData["key"].(map[string]interface{})
                if !ok {
                        continue
                }
                in6u, ok := keyData["in6_u"].(map[string]interface{})
                if !ok {
                        continue
                }
                addrBytes, ok := in6u["u6_addr8"].([]interface{})
                if !ok || len(addrBytes) != 16 {
                        continue
                }
                b := make([]int, 16)
                for i, v := range addrBytes {
                        b[i] = toInt(v) // v0.9.25: safe type assertion (was int(v.(float64)) which panics on nil)
                }
                var addr string
                if b[10] == 0xff && b[11] == 0xff {
                        addr = fmt.Sprintf("%d.%d.%d.%d", b[12], b[13], b[14], b[15])
                } else {
                        v6 := (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]
                        if v6 != 0 {
                                addr = fmt.Sprintf("v6:%08x", v6)
                        } else {
                                addr = "0.0.0.0"
                        }
                }
                // Apply ResolveBucket + fold + canon, then merge by final key.
                final := ResolveBucket(addr)
                if final == "" {
                        final = addr
                }
                // v0.9.41: If this is a v6 entry that didn't get a label
                // (still starts with "v6:"), try to find its v4 counterpart
                // via the cookie_dest map.
                if strings.HasPrefix(final, "v6:") {
                        if v4Label := v6ToV4Label(addr); v4Label != "" {
                                final = v4Label
                        }
                }
                inst := toInt(val["instances"])
                rttUs := toFloat(val["min_rtt"])
                isV6 := strings.HasPrefix(addr, "v6:")
                if existing, ok := merged[final]; ok {
                        // v0.9.128 generation rules (frozen-leaderboard fix):
                        //  - an OLDER generation (higher gen index) arriving for
                        //    a bucket the newest generation already has is a
                        //    detached map's frozen snapshot — it must NOT be
                        //    summed or merged into the live values.
                        //  - a NEWER generation (lower gen index) arriving after
                        //    older entries replaces the bucket outright.
                        if gen > existing.Gen {
                                continue
                        }
                        if gen < existing.Gen {
                                merged[final] = newHostEntry(final, addr, val, inst, rttUs, isV6, gen)
                                continue
                        }
                        existing.Inst += inst
                        // B3-fix (v0.9.130): the representative swap below is
                        // REMOVED. v0.9.39's mergeHostValues already folds every
                        // field of every entry (sums for count/vote fields, min
                        // for min_rtt, max for streaks/scores, recomputed
                        // best_i). Replacing existing.V with the incoming val
                        // here DISCARDED all previously merged entries and then
                        // self-merged the new representative — the largest
                        // entry's instances/votes/rate_emas were counted TWICE
                        // and every entry processed before it was LOST from the
                        // leaderboard (observed on al: Cloudflare showed
                        // instances=33187 while the true sum was 23952, and the
                        // 100.96.0.0 bucket's metrics never appeared at all).
                        if inst > existing.MaxInst {
                                existing.MaxInst = inst
                        }
                        // v0.9.38: track v4 and v6 min_rtt separately.
                        if isV6 {
                                existing.V6Inst += inst
                                if rttUs > 0 && (existing.V6MinRTT == 0 || rttUs < existing.V6MinRTT) {
                                        existing.V6MinRTT = rttUs
                                }
                        } else {
                                existing.V4Inst += inst
                                if rttUs > 0 && (existing.V4MinRTT == 0 || rttUs < existing.V4MinRTT) {
                                        existing.V4MinRTT = rttUs
                                }
                        }
                        // v0.9.39: merge ALL metrics across v4+v6.
                        existing.V = mergeHostValues(existing.V, val)
                } else {
                        merged[final] = newHostEntry(final, addr, val, inst, rttUs, isV6, gen)
                        order = append(order, final)
                }
        }
        out := make([]hostEntry, 0, len(order))
        for _, addr := range order {
                out = append(out, *merged[addr])
        }
        // v0.9.33: cache the result for CacheBPFMap mode
        if collectorMode.CacheBPFMap {
                bpfMapCache = out
                bpfMapCacheErr = nil
                bpfMapCacheAt = time.Now()
                if bpfMapCacheSize == 0 {
                        bpfMapCacheSize = len(raw)
                }
        }
        return out, nil
}

// newHostEntry builds a fresh bucket entry (v0.9.128: extracted so the
// generation-replace path and the first-seen path share one constructor).
func newHostEntry(final, addr string, val map[string]interface{}, inst int, rttUs float64, isV6 bool, gen int) *hostEntry {
        he := &hostEntry{Inst: inst, MaxInst: inst, Addr: final, V: val, Gen: gen}
        if isV6 {
                he.V6Inst = inst
                if rttUs > 0 {
                        he.V6MinRTT = rttUs
                }
        } else {
                he.V4Inst = inst
                if rttUs > 0 {
                        he.V4MinRTT = rttUs
                }
        }
        return he
}

// mergeHostValues combines two BPF map values (v4 + v6) into a single
// value that reflects the combined dual-stack traffic.
//
// v0.9.39: before this, the merge only kept the "winner's" metrics.
// Now we properly sum/merge all fields:
//
//      Summed (v4 + v6): instances, selection_count,
//        metrics[i].rate_ema/metric_count/sockets_*, rate_hist bins
//      Min:  min_rtt, rtt_low_min (lower = better; 0 = no data)
//      Max:  max_rate_delivered (higher = better), rtt_low_streak,
//        metrics[i].swap_score/bad_streak/null_streak (worst case)
//      Recomputed: best_i/best_v, rate_best_i/rate_best_v
func mergeHostValues(existing, incoming map[string]interface{}) map[string]interface{} {
        if existing == nil {
                return incoming
        }
        if incoming == nil {
                return existing
        }

        // Start with a copy of existing
        merged := make(map[string]interface{}, len(existing))
        for k, v := range existing {
                merged[k] = v
        }

        // --- Prefix fields (u64) ---
        merged["instances"] = toInt(existing["instances"]) + toInt(incoming["instances"])
        merged["selection_count"] = toInt(existing["selection_count"]) + toInt(incoming["selection_count"])

        // min_rtt: min (lower is better), 0 means "no data" so prefer nonzero
        eRTT := toFloat(existing["min_rtt"])
        iRTT := toFloat(incoming["min_rtt"])
        if iRTT > 0 && (eRTT == 0 || iRTT < eRTT) {
                merged["min_rtt"] = iRTT
        }

        // max_rate_delivered: max
        eMaxRate := toFloat(existing["max_rate_delivered"])
        iMaxRate := toFloat(incoming["max_rate_delivered"])
        if iMaxRate > eMaxRate {
                merged["max_rate_delivered"] = iMaxRate
        }

        if toInt(incoming["rtt_low_streak"]) > toInt(existing["rtt_low_streak"]) {
                merged["rtt_low_streak"] = toInt(incoming["rtt_low_streak"])
        }
        eRLM := toFloat(existing["rtt_low_min"])
        iRLM := toFloat(incoming["rtt_low_min"])
        if iRLM > 0 && (eRLM == 0 || iRLM < eRLM) {
                merged["rtt_low_min"] = iRLM
        }

        // --- metrics[16] array ---
        eMetrics, _ := existing["metrics"].([]interface{})
        iMetrics, _ := incoming["metrics"].([]interface{})
        maxLen := len(eMetrics)
        if len(iMetrics) > maxLen {
                maxLen = len(iMetrics)
        }
        if maxLen > 0 {
                outMetrics := make([]interface{}, maxLen)
                for i := 0; i < maxLen; i++ {
                        var em, im map[string]interface{}
                        if i < len(eMetrics) {
                                em, _ = eMetrics[i].(map[string]interface{})
                        }
                        if i < len(iMetrics) {
                                im, _ = iMetrics[i].(map[string]interface{})
                        }
                        if em == nil && im == nil {
                                outMetrics[i] = map[string]interface{}{}
                                continue
                        }
                        if em == nil {
                                outMetrics[i] = im
                                continue
                        }
                        if im == nil {
                                outMetrics[i] = em
                                continue
                        }
                        // Merge: sum rate/count/socket fields, take max for streaks/score
                        mm := map[string]interface{}{}
                        for k, v := range em {
                                mm[k] = v
                        }
                        mm["rate_ema"] = toInt(em["rate_ema"]) + toInt(im["rate_ema"])
                        mm["metric_count"] = toInt(em["metric_count"]) + toInt(im["metric_count"])
                        mm["sockets_alive"] = toInt(em["sockets_alive"]) + toInt(im["sockets_alive"])
                        mm["sockets_good"] = toInt(em["sockets_good"]) + toInt(im["sockets_good"])
                        mm["sockets_proved"] = toInt(em["sockets_proved"]) + toInt(im["sockets_proved"])
                        if toInt(im["swap_score"]) > toInt(em["swap_score"]) {
                                mm["swap_score"] = toInt(im["swap_score"])
                        }
                        if toInt(im["bad_streak"]) > toInt(em["bad_streak"]) {
                                mm["bad_streak"] = toInt(im["bad_streak"])
                        }
                        if toInt(im["null_streak"]) > toInt(em["null_streak"]) {
                                mm["null_streak"] = toInt(im["null_streak"])
                        }
                        outMetrics[i] = mm
                }
                merged["metrics"] = outMetrics

                // Recompute best_i / best_v from merged metrics
                bestI := 0
                bestV := 0
                rateBestI := 0
                rateBestV := 0
                for i, mraw := range outMetrics {
                        m, _ := mraw.(map[string]interface{})
                        if m == nil {
                                continue
                        }
                        if toInt(m["metric_count"]) == 0 {
                                continue
                        }
                        rv := toInt(m["rate_ema"])
                        ss := toInt(m["swap_score"])
                        ssEff := ss
                        if ssEff == 0 {
                                ssEff = 256
                        }
                        bad := toInt(m["bad_streak"])
                        weighted := rv * ssEff / 256
                        if bad > 2 {
                                weighted = weighted / 4
                        }
                        if weighted > bestV {
                                bestV = weighted
                                bestI = i
                        }
                        if rv > rateBestV {
                                rateBestV = rv
                                rateBestI = i
                        }
                }
                merged["best_i"] = bestI
                merged["best_v"] = bestV
                merged["rate_best_i"] = rateBestI
                merged["rate_best_v"] = rateBestV
        }

        // --- rate_hist[32] ---
        eHist, _ := existing["rate_hist"].([]interface{})
        iHist, _ := incoming["rate_hist"].([]interface{})
        if len(eHist) > 0 || len(iHist) > 0 {
                histLen := len(eHist)
                if len(iHist) > histLen {
                        histLen = len(iHist)
                }
                outHist := make([]interface{}, histLen)
                for i := 0; i < histLen; i++ {
                        ev := 0
                        iv := 0
                        if i < len(eHist) {
                                ev = toInt(eHist[i])
                        }
                        if i < len(iHist) {
                                iv = toInt(iHist[i])
                        }
                        outHist[i] = ev + iv
                }
                merged["rate_hist"] = outHist
        }

        return merged
}

// v6ToV4Label looks up a v6 address in the cookie_dest map and returns
// the label of its v4 counterpart (if any).
//
// v0.9.41: The BPF map has separate entries for v4 and v6 connections to
// the same destination. The v4 entry might have a label (from aliases),
// but the v6 entry stays as "v6:2606xxxx" because there's no v6 alias.
// This function uses the cookie_dest map to find the v4 counterpart and
// returns its label so the v6 entry can be merged with the v4 entry.
func v6ToV4Label(v6Addr string) string {
        if cookieDestDiskMap == nil {
                return ""
        }
        hexPart := strings.TrimPrefix(v6Addr, "v6:")
        v6Num, err := strconv.ParseUint(hexPart, 16, 64)
        if err != nil {
                return ""
        }
        v6Str := strconv.FormatUint(v6Num, 10)

        // Search cookie_dest map for a cookie that has this v6 dest
        for _, entry := range cookieDestDiskMap {
                if len(entry) >= 2 && entry[1] == v6Str {
                        v4Dest := entry[0]
                        if v4Dest == "" || v4Dest == "0" {
                                continue
                        }
                        label := ResolveBucket(v4Dest)
                        if label != "" && !strings.HasPrefix(label, "v6:") {
                                return label
                        }
                        return v4Dest
                }
        }
        return ""
}
