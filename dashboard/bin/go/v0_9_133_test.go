package main

// v0_9_133_test.go — the incremental corpse cache: sweep semantics plus the
// equivalence proofs.
//
// v0.9.133 replaced the v0.9.132 cache CADENCE (every-10th-call full
// all-gens refresh + a full dump at startup/reload) with an INCREMENTAL
// round-robin sweep: every dump call reads the live map plus at most ONE
// corpse generation, no matter how many generations exist. That kills the
// last two spikes that made 1-vCPU/1GB hosts fight:
//
//   - the ~5-minute refresh spike (at 16 gens: the measured 164.7ms /
//     120MB single-cycle hit — the exact workload the watchdog CPU grace
//     was invented for);
//   - the startup/reload full dump, whose single all-gens slice held every
//     generation's parsed entries live at once — at N > ~30 that is
//     ~240MB against the watchdog's strict 250MB RSS arm (no grace,
//     2-strike): kill -> systemd restart -> identical spike -> the memory
//     edition of the suicide loop v0.9.132 only gave the CPU arm a grace.
//
// What must hold (all tested here):
//
//   1. OUTPUT EQUIVALENCE: after one full round-robin sweep (len(ids)-1
//      steps), fold(live-only merge) equals the full all-gens merge the
//      v0.9.128-131 path computed every cycle — for deterministic AND
//      randomized generation contents. NOTE the cache's `best` map is a
//      SUPERSET of the full merge's Gen>0 slice: a label the live map
//      carries is resolved to Gen 0 by the full merge (excluded from the
//      slice) but IS cached from its newest corpse carrier; fold drops it
//      because live wins. The end-to-end outputs must match, and for
//      corpse-only labels the cached entry must equal the Gen>0 slice.
//      (Label note: v4 labels canonize per /16 — genEntry(1,2,3,4) is the
//      label "1.2.0.0", per prefix4 canon.)
//   2. NEWEST CARRIER WINS: a label carried by several corpse generations
//      resolves to the NEWEST carrier — the same rule the full merge's
//      generation logic applies.
//   3. ROUND-ROBIN ORDER: the cursor covers ranks 1..K-1 without repeats,
//      advances per ATTEMPT (a failed dump must not stall the sweep), and
//      wraps.
//   4. PROGRESSIVE WARMUP: warmDone fires exactly once, after exactly
//      K-1 storeGen calls.
//   5. ID-SET CHANGE (reload): noteIDs resets the cache for an incremental
//      re-warm; the same id set is a no-op.
//   6. LIVE-DROP LATENCY: when the live map DROPS a label the corpse cache
//      carries, the corpse fallback appears the NEXT cycle (v0.9.132 needed
//      its next 10-cycle refresh to even notice — up to 5 minutes).
//   7. SWEEP REFRESH: the sweep re-reads every corpse generation once per
//      round, so picker-writeback patches to a corpse map (tracker fields,
//      every 10th pass) are picked up within one round — corpses are NOT
//      cached forever.
//   8. SEED PARITY: seedFromFullMerge (the legacy error path, which already
//      paid for a full dump) lands on the state the sweep converges to for
//      every label the full merge's Gen>0 slice carries.

import (
        "math/rand"
        "reflect"
        "sort"
        "testing"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// sweepIDs builds an id list of n generations, newest first (descending),
// like resolveRemoteHostMapIDs.
func sweepIDs(n int) []int {
        ids := make([]int, n)
        for i := range ids {
                ids[i] = 500 - i
        }
        return ids
}

// tagRank copies raw entries and tags them map_gen=rank, exactly the way
// readGenTagged / readMapGens tag a dump.
func tagRank(raw []map[string]interface{}, rank int) []map[string]interface{} {
        tagged := make([]map[string]interface{}, len(raw))
        copy(tagged, raw)
        for i := range tagged {
                tagged[i]["map_gen"] = float64(rank)
        }
        return tagged
}

// genSweepRank merges ONE generation's raw entries exactly the way the
// runtime sweep step does.
func genSweepRank(t *testing.T, raw []map[string]interface{}, rank int) []hostEntry {
        t.Helper()
        merged, err := mergeBPFMapEntries(tagRank(raw, rank))
        if err != nil {
                t.Fatalf("merge gen rank %d: %v", rank, err)
        }
        return merged
}

// fullMergeRanked is the v0.9.128-131 reference: dump ALL generations,
// tagged by rank, merged once.
func fullMergeRanked(t *testing.T, gens [][]map[string]interface{}) []hostEntry {
        t.Helper()
        var all []map[string]interface{}
        for rank, raw := range gens {
                all = append(all, tagRank(raw, rank)...)
        }
        merged, err := mergeBPFMapEntries(all)
        if err != nil {
                t.Fatalf("full merge: %v", err)
        }
        return merged
}

// runSweep drives the round-robin sweep for exactly one full round
// (len(gens)-1 steps), the way readBPFMap does: nextSweepRank picks,
// storeGen stores. gens[rank] is the raw dump of that rank.
func runSweep(t *testing.T, c *corpseGenCache, gens [][]map[string]interface{}) (warmDoneCount int) {
        t.Helper()
        steps := len(gens) - 1
        for s := 0; s < steps; s++ {
                rank := c.nextSweepRank()
                if rank <= 0 || rank >= len(gens) {
                        t.Fatalf("sweep step %d: rank %d out of corpse range [1,%d)", s, rank, len(gens))
                }
                if c.storeGen(rank, genSweepRank(t, gens[rank], rank)) {
                        warmDoneCount++
                }
        }
        return warmDoneCount
}

// assertSweepOutputEqualsFullMerge is the OUTPUT equivalence proof: the
// v0.9.133 steady path (live-only merge + fold) must equal the full
// all-gens merge, entry for entry. Also checks the corpse-only subset of
// the cache against the full merge's Gen>0 slice.
func assertSweepOutputEqualsFullMerge(t *testing.T, c *corpseGenCache, gens [][]map[string]interface{}) {
        t.Helper()
        want := fullMergeRanked(t, gens)

        liveMerged, err := mergeBPFMapEntries(tagRank(gens[0], 0))
        if err != nil {
                t.Fatalf("live merge: %v", err)
        }
        got := c.fold(liveMerged)

        if len(got) != len(want) {
                t.Fatalf("sweep-path output %d buckets, full merge %d — corpse-only labels lost or invented", len(got), len(want))
        }
        byAddr := map[string]hostEntry{}
        for _, h := range want {
                byAddr[h.Addr] = h
        }
        for _, h := range got {
                w, ok := byAddr[h.Addr]
                if !ok {
                        t.Fatalf("sweep output has %q, full merge lacks it", h.Addr)
                }
                if !reflect.DeepEqual(h, w) {
                        t.Fatalf("label %q: sweep %+v != full %+v", h.Addr, h, w)
                }
        }

        // Corpse-only labels: the cached entry must equal the full merge's
        // Gen>0 slice exactly.
        liveLabels := map[string]bool{}
        for _, h := range liveMerged {
                liveLabels[h.Addr] = true
        }
        wantSlice := map[string]hostEntry{}
        for _, h := range want {
                if h.Gen > 0 {
                        wantSlice[h.Addr] = h
                }
        }
        for addr, h := range wantSlice {
                e, ok := c.best[addr]
                if !ok {
                        t.Fatalf("corpse-only label %q missing from the cache", addr)
                }
                if !reflect.DeepEqual(e.ent, h) {
                        t.Fatalf("corpse-only label %q: cached %+v != full-merge %+v", addr, e.ent, h)
                }
                _ = liveLabels
        }
}

// ---------------------------------------------------------------------------
// 1: output equivalence (deterministic + randomized)
// ---------------------------------------------------------------------------

func TestCorpseSweepConvergenceDeterministic(t *testing.T) {
        // 4 generations: shared labels, corpse-only labels, live-only labels.
        gens := [][]map[string]interface{}{
                0: { // live
                        genEntry(9, 0, 0, 1, 0, 10, 10, 10),
                        genEntry(9, 1, 0, 2, 0, 11, 11, 11), // distinct /16 from 9.0.x
                },
                1: { // newest corpse: carries 1.2.x.y with a FRESH value
                        genEntry(1, 2, 3, 4, 1, 100, 20, 200),
                        genEntry(5, 6, 7, 8, 1, 101, 21, 201),
                },
                2: { // older corpse: stale 1.2.3.4 must LOSE to rank 1
                        genEntry(1, 2, 3, 4, 2, 500, 50, 500),
                        genEntry(6, 6, 6, 6, 2, 102, 22, 202),
                },
                3: { // oldest corpse: only a corpse-only label
                        genEntry(7, 7, 7, 7, 3, 103, 23, 203),
                },
        }
        var c corpseGenCache
        c.noteIDs(sweepIDs(len(gens)))
        if warm := runSweep(t, &c, gens); warm != 1 {
                t.Fatalf("warmDone fired %d times in the first full round, want exactly 1", warm)
        }
        assertSweepOutputEqualsFullMerge(t, &c, gens)
}

func TestCorpseSweepConvergenceRandomized(t *testing.T) {
        // Randomized generation contents: each of 20 generations carries a
        // random subset of a 64-/16-label universe with random values; labels
        // recur across generations (including the LIVE gen) so both the
        // newest-carrier rule and fold's live-wins rule are exercised at every
        // overlap depth. 25 rounds, different seeds.
        for round := 0; round < 25; round++ {
                rng := rand.New(rand.NewSource(int64(1000 + round)))
                const nGens = 20
                const universe = 64

                gens := make([][]map[string]interface{}, nGens)
                for rank := 0; rank < nGens; rank++ {
                        n := 1 + rng.Intn(universe)
                        labels := rng.Perm(universe)[:n]
                        for _, l := range labels {
                                // distinct /16 per universe label (v4 canon is /16)
                                a, b := int(10+l/16), int(20+l%16)
                                gens[rank] = append(gens[rank],
                                        genEntry(a, b, rank+1, l+1, rank, 50+l, 10+l%3, 100+l))
                        }
                }

                var cache corpseGenCache
                cache.noteIDs(sweepIDs(nGens))
                runSweep(t, &cache, gens)
                assertSweepOutputEqualsFullMerge(t, &cache, gens)
        }
}

// ---------------------------------------------------------------------------
// 2: newest carrier wins
// ---------------------------------------------------------------------------

func TestCorpseNewestCarrierWins(t *testing.T) {
        // 1.2.3.4 (label 1.2.0.0) is carried by ranks 1, 2 and 4 — the newest
        // (rank 1) must supply the cached entry, matching the full merge.
        gens := [][]map[string]interface{}{
                0: {genEntry(9, 9, 9, 9, 0, 1, 1, 1)},
                1: {genEntry(1, 2, 3, 4, 1, 111, 11, 111)},
                2: {genEntry(1, 2, 3, 4, 2, 222, 22, 222)},
                3: {genEntry(8, 8, 8, 8, 3, 3, 3, 3)},
                4: {genEntry(1, 2, 3, 4, 4, 444, 44, 444)},
        }
        var c corpseGenCache
        c.noteIDs(sweepIDs(len(gens)))
        runSweep(t, &c, gens)

        e, ok := c.best[ResolveBucket("1.2.3.4")]
        if !ok {
                t.Fatalf("1.2.3.4 (label %q) must be cached", ResolveBucket("1.2.3.4"))
        }
        if e.rank != 1 {
                t.Fatalf("1.2.3.4 supplied by rank %d, want the newest carrier rank 1", e.rank)
        }
        if got := firstCubicEMA([]hostEntry{e.ent}); got != 111 {
                t.Fatalf("newest carrier must win: rate_ema %d, want 111", got)
        }
}

// ---------------------------------------------------------------------------
// 3: round-robin cursor
// ---------------------------------------------------------------------------

func TestCorpseSweepCursorRoundRobin(t *testing.T) {
        // 5 generations -> corpse ranks 1..4, each visited once per round.
        var c corpseGenCache
        c.noteIDs(sweepIDs(5))

        seen := map[int]int{}
        for i := 0; i < 4; i++ {
                r := c.nextSweepRank()
                seen[r]++
                if seen[r] > 1 {
                        t.Fatalf("rank %d repeated within one round", r)
                }
        }
        for r := 1; r <= 4; r++ {
                if seen[r] != 1 {
                        t.Fatalf("rank %d visited %d times in round 1, want 1", r, seen[r])
                }
        }
        // Second round: same order again (cursor wrapped).
        for i := 0; i < 4; i++ {
                c.nextSweepRank()
        }
        // The cursor advances per ATTEMPT, including failed dumps (no
        // storeGen in this test at all) — that is the anti-stall contract.
        if c.cursor != 0 {
                t.Fatalf("cursor after two rounds = %d, want 0 (wrapped)", c.cursor)
        }

        // Single generation: no corpses, rank 0 forever, never stalls.
        var single corpseGenCache
        single.noteIDs(sweepIDs(1))
        for i := 0; i < 5; i++ {
                if r := single.nextSweepRank(); r != 0 {
                        t.Fatalf("single-gen sweep rank = %d, want 0", r)
                }
        }
}

// ---------------------------------------------------------------------------
// 4: progressive warmup, warmDone exactly once
// ---------------------------------------------------------------------------

func TestCorpseWarmupProgressive(t *testing.T) {
        gens := [][]map[string]interface{}{
                0: {genEntry(9, 9, 9, 9, 0, 1, 1, 1)},
                1: {genEntry(1, 1, 1, 1, 1, 10, 10, 10)},
                2: {genEntry(2, 2, 2, 2, 2, 20, 20, 20)},
                3: {genEntry(3, 3, 3, 3, 3, 30, 30, 30)},
        }
        var c corpseGenCache
        c.noteIDs(sweepIDs(len(gens)))

        // Mid-warmup: only the swept ranks are cached so far.
        c.storeGen(1, genSweepRank(t, gens[1], 1))
        if len(c.labels) != 1 {
                t.Fatalf("after 1 sweep step, cache has %d labels, want 1", len(c.labels))
        }
        if _, ok := c.best[ResolveBucket("1.1.1.1")]; !ok {
                t.Fatalf("rank-1 label %q missing mid-warmup", ResolveBucket("1.1.1.1"))
        }

        // Complete the round: warmDone fires on the LAST step, not before.
        if c.storeGen(2, genSweepRank(t, gens[2], 2)) {
                t.Fatal("warmDone fired early (step 2 of 3)")
        }
        if !c.storeGen(3, genSweepRank(t, gens[3], 3)) {
                t.Fatal("warmDone must fire on the final warmup step")
        }
        // A second full round must NOT fire it again.
        for r := 1; r <= 3; r++ {
                if c.storeGen(r, genSweepRank(t, gens[r], r)) {
                        t.Fatal("warmDone fired a second time — must be once per reset")
                }
        }
}

// ---------------------------------------------------------------------------
// 5: id-set change (reload) re-warms
// ---------------------------------------------------------------------------

func TestCorpseIDSetChangeRewarms(t *testing.T) {
        gens := [][]map[string]interface{}{
                0: {genEntry(9, 9, 9, 9, 0, 1, 1, 1)},
                1: {genEntry(1, 1, 1, 1, 1, 10, 10, 10)},
                2: {genEntry(2, 2, 2, 2, 2, 20, 20, 20)},
        }
        var c corpseGenCache
        ids := sweepIDs(len(gens))
        if !c.noteIDs(ids) {
                t.Fatal("first noteIDs must report a change (cold cache)")
        }
        runSweep(t, &c, gens)
        if len(c.best) != 2 {
                t.Fatalf("warm cache has %d labels, want 2", len(c.best))
        }

        // Same set again: no change, cache stays warm.
        if c.noteIDs(ids) {
                t.Fatal("same id set must NOT report a change")
        }
        if len(c.best) != 2 {
                t.Fatal("cache must survive an unchanged id set")
        }

        // Reload: id set changed -> reset, incremental re-warm.
        newIDs := sweepIDs(len(gens) + 1)
        if !c.noteIDs(newIDs) {
                t.Fatal("changed id set must report a change")
        }
        if len(c.best) != 0 || len(c.labels) != 0 || c.cursor != 0 || c.warmed != 0 || c.warmDone {
                t.Fatalf("reload must reset the cache for incremental re-warm: %+v", c)
        }

        // Reordered set is a DIFFERENT set (ranks are positions).
        if sameIntIDs([]int{3, 2, 1}, []int{1, 2, 3}) {
                t.Fatal("reordered ids must compare as different (ranks are positions)")
        }
}

// ---------------------------------------------------------------------------
// 6: live-drop latency — corpse fallback appears the NEXT cycle
// ---------------------------------------------------------------------------

func TestCorpseLiveDropReappearsNextCycle(t *testing.T) {
        gens := [][]map[string]interface{}{
                0: {genEntry(1, 2, 3, 4, 0, 82, 100, 100)}, // live carries 1.2.0.0
                1: {genEntry(1, 2, 3, 4, 1, 726, 20, 5000)},
        }
        var c corpseGenCache
        c.noteIDs(sweepIDs(len(gens)))
        runSweep(t, &c, gens)

        // Live map still carries the label: live wins, corpse not folded in.
        live, err := mergeBPFMapEntries(tagRank(gens[0], 0))
        if err != nil {
                t.Fatal(err)
        }
        out := c.fold(live)
        if len(out) != 1 || out[0].Gen != 0 {
                t.Fatalf("live must win while it carries the label: %+v", out)
        }

        // Live map DROPS the label: the corpse fallback must appear on the
        // very next fold — no refresh window (v0.9.132 needed up to 5 min).
        liveDropped, err := mergeBPFMapEntries(nil)
        if err != nil {
                t.Fatal(err)
        }
        out = c.fold(liveDropped)
        want := ResolveBucket("1.2.3.4")
        if len(out) != 1 || out[0].Gen != 1 || out[0].Addr != want {
                t.Fatalf("dropped label must fall back to the corpse entry next cycle: want addr %q gen 1, got %+v", want, out)
        }
}

// ---------------------------------------------------------------------------
// 7: the sweep refreshes patched corpse data within one round
// ---------------------------------------------------------------------------

func TestCorpseSweepRefreshesPatchedCorpse(t *testing.T) {
        gens := [][]map[string]interface{}{
                0: {genEntry(9, 9, 9, 9, 0, 1, 1, 1)},
                1: {genEntry(1, 1, 1, 1, 1, 10, 10, 10)},
                2: {genEntry(2, 2, 2, 2, 2, 20, 20, 20)},
        }
        var c corpseGenCache
        c.noteIDs(sweepIDs(len(gens)))
        runSweep(t, &c, gens)

        // The picker writeback patches tracker fields into EVERY map
        // generation every 10th pass — model that as a changed rank-2 value.
        patched := []map[string]interface{}{genEntry(2, 2, 2, 2, 2, 99, 20, 20)}

        // Sweep reaches rank 2 on the second step of the next round.
        c.nextSweepRank() // rank 1
        if r := c.nextSweepRank(); r != 2 {
                t.Fatalf("expected sweep to reach rank 2, got %d", r)
        }
        c.storeGen(2, genSweepRank(t, patched, 2))

        e, ok := c.best[ResolveBucket("2.2.2.2")]
        if !ok {
                t.Fatalf("2.2.2.2 (label %q) must be cached", ResolveBucket("2.2.2.2"))
        }
        if got := firstCubicEMA([]hostEntry{e.ent}); got != 99 {
                t.Fatalf("patched corpse value must be picked up within one sweep round: rate_ema %d, want 99", got)
        }
}

// ---------------------------------------------------------------------------
// 8: seedFromFullMerge parity with sweep convergence
// ---------------------------------------------------------------------------

func TestCorpseSeedFromFullMerge(t *testing.T) {
        // Live (9.9.0.0) does NOT overlap the corpse labels here — the seeded
        // cache (Gen>0 slice) and the swept cache must then agree on every
        // corpse label.
        gens := [][]map[string]interface{}{
                0: {genEntry(9, 9, 9, 9, 0, 1, 1, 1)},
                1: {genEntry(1, 2, 3, 4, 1, 100, 20, 200), genEntry(5, 6, 7, 8, 1, 101, 21, 201)},
                2: {genEntry(1, 2, 3, 4, 2, 500, 50, 500), genEntry(6, 6, 6, 6, 2, 102, 22, 202)},
                3: {genEntry(7, 7, 7, 7, 3, 103, 23, 203)},
        }
        ids := sweepIDs(len(gens))

        // Sweep convergence.
        var swept corpseGenCache
        swept.noteIDs(ids)
        runSweep(t, &swept, gens)

        // Seed from the full merge.
        var seeded corpseGenCache
        seeded.noteIDs(ids)
        seeded.seedFromFullMerge(ids, fullMergeRanked(t, gens))

        if len(seeded.best) != len(swept.best) {
                t.Fatalf("seeded cache has %d labels, swept has %d", len(seeded.best), len(swept.best))
        }
        for addr, w := range swept.best {
                g, ok := seeded.best[addr]
                if !ok {
                        t.Fatalf("label %q missing from seeded cache", addr)
                }
                if g.rank != w.rank {
                        t.Fatalf("label %q: seeded rank %d != swept rank %d", addr, g.rank, w.rank)
                }
                if !reflect.DeepEqual(g.ent, w.ent) {
                        t.Fatalf("label %q: seeded %+v != swept %+v", addr, g.ent, w.ent)
                }
        }
        if !seeded.warmDone || seeded.warmed != len(ids)-1 {
                t.Fatalf("seed must mark warmup complete: warmDone=%v warmed=%d", seeded.warmDone, seeded.warmed)
        }
        // storeGen must not fire warmDone again after a seed.
        if seeded.storeGen(1, genSweepRank(t, gens[1], 1)) {
                t.Fatal("warmDone fired after seedFromFullMerge — must not")
        }

        // The seeded cache must reproduce the same steady output as the full
        // merge (same property the swept cache is held to).
        assertSeededOutput := func() {
                want := fullMergeRanked(t, gens)
                liveMerged, err := mergeBPFMapEntries(tagRank(gens[0], 0))
                if err != nil {
                        t.Fatal(err)
                }
                got := seeded.fold(liveMerged)
                if len(got) != len(want) {
                        t.Fatalf("seeded steady output %d buckets, full merge %d", len(got), len(want))
                }
                sort.Slice(got, func(i, j int) bool { return got[i].Addr < got[j].Addr })
                sort.Slice(want, func(i, j int) bool { return want[i].Addr < want[j].Addr })
                for i := range got {
                        if !reflect.DeepEqual(got[i], want[i]) {
                                t.Fatalf("bucket %q: seeded %+v != full %+v", got[i].Addr, got[i], want[i])
                        }
                }
        }
        assertSeededOutput()
}

// ---------------------------------------------------------------------------
// rank bounds + fold aliasing sanity
// ---------------------------------------------------------------------------

func TestCorpseStoreGenRankBounds(t *testing.T) {
        var c corpseGenCache
        c.noteIDs(sweepIDs(3)) // ranks 0 (live), 1, 2

        if c.storeGen(0, []hostEntry{{Addr: "0.0.0.0"}}) {
                t.Fatal("rank 0 (live) must be rejected")
        }
        if c.storeGen(3, []hostEntry{{Addr: "0.0.0.0"}}) {
                t.Fatal("rank >= len(ids) must be rejected")
        }
        if len(c.best) != 0 {
                t.Fatalf("out-of-range store must be a no-op, cache has %d labels", len(c.best))
        }
}

func TestCorpseFoldAliasesLiveWhenEmpty(t *testing.T) {
        var c corpseGenCache
        live := []hostEntry{{Addr: "1.2.3.4"}}
        out := c.fold(live)
        if len(out) != 1 || &out[0] != &live[0] {
                t.Fatal("empty cache fold must alias live (no copy)")
        }
}
