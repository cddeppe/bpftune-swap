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
// v0.9.134: fresh corpse view at flat cost — per-cycle key discovery +
// byte-validated per-label cache (supersedes the v0.9.133 round-robin
// VALUE cache)
// ============================================================================
//
// REGRESSION THIS FIXES (observed in production within hours of v0.9.133
// shipping): the swap-target leaderboard and the actual swaps disagreed
// again — the exact v0.9.129 symptom. Root cause: v0.9.133 cached the
// PARSED values of corpse-carried labels and refreshed one corpse
// generation per cycle (round-robin), so a label carried only by corpses
// was displayed up to (N-1) x 30s stale — ~8 minutes at 16 generations.
// But corpse maps are NOT frozen: the collector's own streak writeback
// patches bad_streak/null_streak on EVERY generation every 60s, the picker
// writeback patches tracker fields, and an attached zombie program may
// still update metrics. The pick highlight is computed from the DISPLAYED
// penalty (16/(16+bad*4+null*2)) while the swap-driving tracker is
// recomputed from the CURRENT map values — a stale display picked a
// different winner than the live tracker. v0.9.128-131 never had this
// class of bug because they re-read every generation fresh every cycle.
//
// v0.9.134 restores that freshness invariant WITHOUT the v0.9.128-131
// cost. Every cycle:
//
//   1. dump the LIVE map only (as v0.9.133) — its labels are complete,
//      fresh data from cycle 1;
//   2. walk each corpse map's KEY SET (BPF_MAP_GET_NEXT_KEY only — no
//      values): cheap cursor syscalls, no parse, no allocation spike
//      (~10ms at 16 gens x 324 keys);
//   3. for every corpse-carried label (absent from the live map, newest
//      carrier), LOOK UP its key(s)' current value bytes and compare
//      them byte-for-byte with the cached copy:
//        - identical  -> reuse the cached merged entry (no parse) — and
//          because the bytes match, the cached entry IS the current map
//          state, bit for bit. No staleness is possible.
//        - changed    -> re-parse that label (and only that label).
//
// So the per-cycle parse volume is bounded by the ACTUAL CHANGE RATE of
// corpse maps (streak/tracker patches, zombie writes), not by their size:
// an inert corpse costs one 1024-byte lookup per label per cycle and zero
// parses; the freshly-reloaded window (live map has not re-seen the tail
// yet) pays the full parse ONCE and then only for what actually changes.
// The label-level merge keeps the peak parsed-entry set at ONE label
// (1-2 entries) — never the N-gens-in-one-slice peak that walked into the
// watchdog's no-grace RSS arm.
//
// Output equals the v0.9.128-131 full all-gens merge EVERY cycle (not
// just at sweep boundaries), corpse-only labels are fresh every cycle,
// and everything is present from the FIRST cycle — no warmup window.

// corpseMapFeed is the per-map access a corpse generation exposes to the
// selector: its full key set, the final-label derivation for a key, and a
// raw value lookup (the 1024-byte map value). Abstract so the selection
// core is unit-testable without BPF.
type corpseMapFeed struct {
	rank   int                                        // generation rank (1 = newest corpse)
	keys   [][]byte                                   // every key in the map
	label  func(key []byte) (final string, isV6 bool) // same normalization as mergeBPFMapEntriesCore
	lookup func(key []byte) ([]byte, bool)            // raw value bytes (copy)
}

// corpseLabelCache is the byte-validated per-label cache entry.
type corpseLabelCache struct {
	ent  hostEntry            // merged entry (Gen = rank when built)
	rank int                  // carrier rank at build time
	sigs map[string][]byte    // key (hex) -> value bytes at build time
}

// corpseViewMu guards corpseView (readBPFMap is single-threaded per
// cycle, but the mutex keeps the invariant explicit and race-detector
// clean).
var (
	corpseViewMu sync.Mutex
	corpseView   = map[string]*corpseLabelCache{} // label -> cached state

	// corpseParse is the parse seam: tests wrap it to count parses (the
	// steady-cycle parse bound is a shipped property, not a hope).
	corpseParse = parseRawHostEntry
)

// selectCorpseCarried is the pure selection + cache-validation core.
// Feeds are processed newest carrier first; a label carried by the live
// map (liveLabels) is never fetched, and a label claimed by a newer
// corpse generation is not re-fetched from older ones. A cached entry is
// reused ONLY when the carrier rank and EVERY key's current value bytes
// equal the cached copy — so a reused entry is the current map state,
// bit for bit. Returns the per-label hostEntries (Gen = carrier rank) in
// deterministic order (feeds in slice order, then first-seen label
// order). Cache entries for labels not selected this cycle are pruned,
// bounding the cache at the current corpse-carried label set.
func selectCorpseCarried(feeds []corpseMapFeed, liveLabels map[string]bool) []hostEntry {
	corpseViewMu.Lock()
	defer corpseViewMu.Unlock()

	claimed := make(map[string]bool, len(liveLabels)+16)
	for l := range liveLabels {
		claimed[l] = true
	}
	seen := make(map[string]bool, len(corpseView))
	var out []hostEntry
	for _, f := range feeds {
		// One pass over this map's keys: group by final label (the label
		// pass is real per-cycle work — it is what keeps discovery fresh).
		byLabel := make(map[string][][]byte, len(f.keys))
		var order []string
		for _, key := range f.keys {
			final, _ := f.label(key)
			if final == "" {
				continue
			}
			if claimed[final] {
				continue // live map or a newer corpse supplies this label
			}
			if _, seenLabel := byLabel[final]; !seenLabel {
				order = append(order, final)
			}
			byLabel[final] = append(byLabel[final], key)
		}
		for _, final := range order {
			claimed[final] = true // this map is the NEWEST carrier
			seen[final] = true

			// Fetch every key's current bytes (the freshness check).
			sigs := make(map[string][]byte, len(byLabel[final]))
			ok := true
			for _, k := range byLabel[final] {
				val, found := f.lookup(k)
				if !found || len(val) != sizeofRemoteHost {
					ok = false
					break
				}
				sigs[string(k)] = val
			}
			if !ok {
				delete(corpseView, final) // a key vanished mid-cycle — rebuild next time
				continue
			}

			// Byte-validated cache hit?
			if c, cached := corpseView[final]; cached && c.rank == f.rank && sigsEqual(c.sigs, sigs) {
				ent := c.ent
				ent.Gen = f.rank
				out = append(out, ent)
				continue
			}

			// Miss / changed / carrier moved: re-parse this label only.
			var raw []map[string]interface{}
			for _, k := range byLabel[final] {
				e := corpseParse(k, sigs[string(k)])
				e["map_gen"] = float64(f.rank)
				raw = append(raw, e)
			}
			merged, err := mergeBPFMapEntriesCore(raw)
			if err != nil || len(merged) == 0 {
				delete(corpseView, final)
				continue
			}
			corpseView[final] = &corpseLabelCache{ent: merged[0], rank: f.rank, sigs: sigs}
			out = append(out, merged[0])
		}
	}
	// Prune labels not selected this cycle (dropped keys, labels the live
	// map regained, maps that vanished) — bounds the cache at the current
	// corpse-carried set.
	for l := range corpseView {
		if !seen[l] {
			delete(corpseView, l)
		}
	}
	return out
}

// sigsEqual compares two key->bytes signature maps byte-for-byte.
func sigsEqual(a, b map[string][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for k, va := range a {
		vb, ok := b[k]
		if !ok || !bytes.Equal(va, vb) {
			return false
		}
	}
	return true
}

// rawKeyToFinalLabel derives the final merge label from a raw 16-byte map
// key, mirroring the byte-level logic in mergeBPFMapEntriesCore (v4
// dotted-quad or v6:XXXXXXXX, ResolveBucket canon, cookie-dest fallback
// for unresolvable v6 labels). Used BEFORE any value fetch so discovery
// costs no lookups.
func rawKeyToFinalLabel(key []byte) (string, bool) {
	if len(key) != 16 {
		return "", false
	}
	var addr string
	isV6 := false
	if key[10] == 0xff && key[11] == 0xff {
		addr = fmt.Sprintf("%d.%d.%d.%d", key[12], key[13], key[14], key[15])
	} else {
		v6 := (int(key[0]) << 24) | (int(key[1]) << 16) | (int(key[2]) << 8) | int(key[3])
		if v6 != 0 {
			addr = fmt.Sprintf("v6:%08x", v6)
			isV6 = true
		} else {
			addr = "0.0.0.0"
		}
	}
	final := ResolveBucket(addr)
	if final == "" {
		final = addr
	}
	if strings.HasPrefix(final, "v6:") {
		if v4Label := v6ToV4Label(addr); v4Label != "" {
			final = v4Label
		}
	}
	return final, isV6
}

// readCorpseCarriedRaw wires selectCorpseCarried to the real maps: for
// each corpse generation (rank 1..len(mapIDs)-1, newest first) it opens a
// VERIFIED fd (proven remote_host_map; closed per cycle — the collector
// never pins a corpse across cycles, v0.9.131), walks the key set, and
// looks up value bytes on demand. A map that fails to open/read is
// skipped for this cycle (its labels reappear when it does); the id-set
// list is refreshed by resolveRemoteHostMapIDs on its own cadence.
func readCorpseCarriedRaw(mapIDs []int, liveLabels map[string]bool) []hostEntry {
	feeds := make([]corpseMapFeed, 0, len(mapIDs)-1)
	var fds []int
	for rank := 1; rank < len(mapIDs); rank++ {
		id := mapIDs[rank]
		fd, info, err := bpfMapGetFDByIDVerified(uint32(id), "remote_host")
		if err != nil {
			continue // unreadable this cycle — skip, do not fail the cycle
		}
		if info.KeySize != 16 || info.ValueSize != sizeofRemoteHost {
			bpfCloseFD(fd)
			continue // wrong geometry — the parser's contract
		}
		f := corpseMapFeed{rank: rank}
		f.label = func(key []byte) (string, bool) { return rawKeyToFinalLabel(key) }
		f.lookup = func(key []byte) ([]byte, bool) {
			value := make([]byte, sizeofRemoteHost)
			if err := bpfMapLookupElem(fd, key, value); err != nil {
				return nil, false // key vanished mid-cycle
			}
			return value, true
		}
		// Key-set walk: BPF_MAP_GET_NEXT_KEY only (no values). curKey
		// nil = start; walk on a COPY (kernel contract, same as
		// readRemoteHostMapByID).
		var keys [][]byte
		nextKey := make([]byte, 16)
		var curKey []byte
		for {
			ok, err := bpfMapGetNextKey(fd, curKey, nextKey)
			if err != nil || !ok {
				break
			}
			k := make([]byte, 16)
			copy(k, nextKey)
			keys = append(keys, k)
			curKey = append(curKey[:0], nextKey...)
		}
		f.keys = keys
		feeds = append(feeds, f)
		fds = append(fds, fd) // closed below, AFTER selection completes
	}
	out := selectCorpseCarried(feeds, liveLabels)
	for _, fd := range fds {
		bpfCloseFD(fd)
	}
	return out
}

// lastCorpseIDSet remembers the previous generation id list for the
// one-line reload notice (diagnostics only — no correctness role: the
// byte-validated cache needs no reset on reload, the per-label rank +
// signature check handles re-ranking).
var lastCorpseIDSet []int

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

func readBPFMap() ([]hostEntry, error) {
        // v0.9.134: live dump + per-cycle corpse key discovery + targeted
        // value lookups. Everything is fresh every cycle (the v0.9.128-131
        // invariant the leaderboard<->swap agreement is built on); nothing
        // caches parsed values across cycles.
        mapIDs, idErr := resolveRemoteHostMapIDs()
        if idErr == nil && !sameIntIDs(lastCorpseIDSet, mapIDs) {
                lastCorpseIDSet = append([]int(nil), mapIDs...)
                if len(mapIDs) > 1 {
                        fmt.Fprintf(os.Stderr, "corpse view: %d remote_host_map generations — reading corpse-carried labels fresh every cycle\n", len(mapIDs))
                }
        }

        if idErr == nil && len(mapIDs) > 0 {
                // (1) Live dump: ONLY the newest generation — fresh, complete
                // for its labels from cycle 1.
                if raw, err := readMapGens(mapIDs[:1]); err == nil {
                        live, mErr := mergeBPFMapEntriesCore(raw)
                        if mErr == nil {
                                out := live
                                if len(mapIDs) > 1 {
                                        // (2) Corpse-carried labels: key-set discovery
                                        // over every corpse generation + value fetch ONLY
                                        // for labels the live map lacks (newest carrier).
                                        // Fresh every cycle — a streak/tracker patch a
                                        // corpse received seconds ago is on the
                                        // leaderboard THIS cycle.
                                        liveLabels := make(map[string]bool, len(live))
                                        for i := range live {
                                                liveLabels[live[i].Addr] = true
                                        }
                                        out = append(out, readCorpseCarriedRaw(mapIDs, liveLabels)...)
                                }
                                if collectorMode.CacheBPFMap {
                                        bpfMapCache = out
                                        bpfMapCacheErr = nil
                                        bpfMapCacheAt = time.Now()
                                        bpfMapCacheSize = len(raw)
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
        out, err := mergeBPFMapEntriesCore(raw)
        if err != nil {
                return nil, err
        }
        // v0.9.33: cache the result for CacheBPFMap mode (legacy paths).
        if collectorMode.CacheBPFMap {
                bpfMapCache = out
                bpfMapCacheErr = nil
                bpfMapCacheAt = time.Now()
        }
        return out, nil
}

// mergeBPFMapEntriesCore is the pure merge (no bpfMapCache side effect)
// used by the v0.9.134 steady path, which composes two merges per cycle
// (live + selected corpse entries) and manages the fallback cache itself.
func mergeBPFMapEntriesCore(raw []map[string]interface{}) ([]hostEntry, error) {
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
