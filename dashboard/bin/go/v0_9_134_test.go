package main

// v0_9_134_test.go — the fresh-corpse-view property suite.
//
// v0.9.134 replaced the v0.9.133 round-robin VALUE cache (one corpse
// generation re-read per cycle; the rest served from memory for up to a
// full round, (N-1) x 30s ~ 8 minutes at 16 generations) with per-cycle
// freshness: key-set discovery over every corpse map + a per-label cache
// validated by EXACT BYTE COMPARISON of every key's current value — a
// cache hit means the cached entry IS the current map state, bit for bit.
//
// WHY (production regression, observed within hours of v0.9.133
// shipping): the swap-target leaderboard and the actual swaps disagreed
// again — the v0.9.129 symptom. Corpse maps are NOT frozen: the streak
// writeback patches bad_streak/null_streak on EVERY generation every 60s
// and the picker writeback patches tracker fields. The pick highlight is
// computed from the DISPLAYED penalty (16/(16+bad*4+null*2)) while the
// swap-driving tracker is recomputed from CURRENT map values — a display
// up to one round stale picked a different winner than the live tracker.
//
// What must hold NOW (all tested here):
//
//   1. FRESHNESS: a value patched into a corpse map (streak writeback,
//      picker writeback, zombie program) is on the leaderboard the VERY
//      NEXT cycle. This is the test v0.9.133 lacked.
//   2. NO WARMUP WINDOW: from a cold start, every corpse-carried label is
//      in the FIRST cycle's output.
//   3. EVERY-CYCLE EQUIVALENCE: live merge + selected corpse entries
//      equal the full all-gens merge on EVERY cycle (deterministic +
//      randomized), including cycles AFTER cache hits.
//   4. CACHE-HIT PARITY: a cycle that reuses a cached entry produces
//      output identical (reflect.DeepEqual) to a fresh parse.
//   5. PARSE BOUND: an unchanged corpse map costs ZERO parses on the next
//      cycle (the cost claim behind flatness).
//   6. NEWEST CARRIER WINS + LOOKUP BOUND: a label carried by several
//      corpse generations resolves to the newest carrier; older
//      carriers' keys and live-carried labels are never looked up.
//   7. LIVE WINS PER LABEL: a label the live map carries never fetches a
//      corpse value, and the live values are what the output holds.
//   8. KEY-SET GROWTH + PRUNING: a corpse map gaining a key (zombie
//      activity) is discovered the next cycle; a vanishing label is
//      pruned from the cache.
//   9. LABEL PARITY: rawKeyToFinalLabel derives the same final label the
//      merge derives for the same key bytes.

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"reflect"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// v4key builds the IPv4-mapped 16-byte map key for a.b.c.d.
func v4key(a, b, c, d byte) []byte {
	k := make([]byte, 16)
	k[10], k[11] = 0xff, 0xff
	k[12], k[13], k[14], k[15] = a, b, c, d
	return k
}

// rawVal builds a raw 1024-byte remote_host value: cubic slot 0 carrying
// rateEMA/count, prefix instances, and optional bad/null streaks — the
// fields the tests assert on.
func rawVal(rateEMA, count, instances int) []byte {
	return rawValStreaks(rateEMA, count, instances, 0, 0)
}

func rawValStreaks(rateEMA, count, instances, bad, nullStreak int) []byte {
	v := make([]byte, sizeofRemoteHost)
	binary.LittleEndian.PutUint64(v[offInstances:], uint64(instances))
	base := offMetricsArray // metric slot 0
	binary.LittleEndian.PutUint64(v[base+offMetricCount:], uint64(count))
	binary.LittleEndian.PutUint16(v[base+offMetricRateEMA:], uint16(rateEMA))
	binary.LittleEndian.PutUint16(v[base+offMetricSwapScore:], uint16(256))
	v[base+offMetricBadStreak] = byte(bad)
	v[base+offMetricNullStreak] = byte(nullStreak)
	return v
}

// fakeCorpseMap is an in-memory corpse generation: raw keys plus a raw
// value store the test can MUTATE between cycles (the streak / picker
// writebacks, a zombie program — the real corpse mutators).
type fakeCorpseMap struct {
	rank  int
	keys  [][]byte
	vals  map[string][]byte
	looks *int // lookup counter (nil = don't count)
}

func newFakeCorpseMap(rank int) *fakeCorpseMap {
	return &fakeCorpseMap{rank: rank, vals: map[string][]byte{}}
}

func (m *fakeCorpseMap) put(key []byte, val []byte) {
	ks := string(key)
	if _, ok := m.vals[ks]; !ok {
		m.keys = append(m.keys, append([]byte(nil), key...))
	}
	m.vals[ks] = val
}

func (m *fakeCorpseMap) del(key []byte) {
	ks := string(key)
	delete(m.vals, ks)
	idx := -1
	for i, k := range m.keys {
		if string(k) == ks {
			idx = i
			break
		}
	}
	if idx >= 0 {
		m.keys = append(m.keys[:idx], m.keys[idx+1:]...)
	}
}

func (m *fakeCorpseMap) feed() corpseMapFeed {
	return corpseMapFeed{
		rank:  m.rank,
		keys:  m.keys,
		label: func(key []byte) (string, bool) { return rawKeyToFinalLabel(key) },
		lookup: func(key []byte) ([]byte, bool) {
			if m.looks != nil {
				*m.looks++
			}
			v, ok := m.vals[string(key)]
			if !ok {
				return nil, false
			}
			out := make([]byte, len(v))
			copy(out, v)
			return out, true
		},
	}
}

// resetCorpseView clears the per-label cache between tests.
func resetCorpseView() {
	corpseViewMu.Lock()
	corpseView = map[string]*corpseLabelCache{}
	corpseViewMu.Unlock()
}

// v134Cycle is the readBPFMap steady path against fakes: live merge +
// live-label set + selectCorpseCarried over the corpse feeds.
func v134Cycle(t *testing.T, liveKeys [][]byte, liveVals map[string][]byte, corpses []*fakeCorpseMap) []hostEntry {
	t.Helper()
	var liveRaw []map[string]interface{}
	for _, k := range liveKeys {
		e := parseRawHostEntry(k, liveVals[string(k)])
		e["map_gen"] = 0
		liveRaw = append(liveRaw, e)
	}
	live, err := mergeBPFMapEntriesCore(liveRaw)
	if err != nil {
		t.Fatalf("live merge: %v", err)
	}
	liveLabels := make(map[string]bool, len(live))
	for i := range live {
		liveLabels[live[i].Addr] = true
	}
	feeds := make([]corpseMapFeed, 0, len(corpses))
	for _, m := range corpses {
		feeds = append(feeds, m.feed())
	}
	out := append([]hostEntry(nil), live...)
	out = append(out, selectCorpseCarried(feeds, liveLabels)...)
	return out
}

// fullMergeRaw is the v0.9.128-131 reference over the SAME raw fixtures:
// every generation's entries, parsed identically, tagged by rank, merged
// once.
func fullMergeRaw(t *testing.T, gens []map[string][]byte, genKeys [][][]byte) []hostEntry {
	t.Helper()
	var all []map[string]interface{}
	for rank, vals := range gens {
		for _, k := range genKeys[rank] {
			e := parseRawHostEntry(k, vals[string(k)])
			e["map_gen"] = float64(rank)
			all = append(all, e)
		}
	}
	merged, err := mergeBPFMapEntries(all)
	if err != nil {
		t.Fatalf("full merge: %v", err)
	}
	return merged
}

func penaltyOf(h *hostEntry) float64 {
	metrics, _ := h.V["metrics"].([]interface{})
	if len(metrics) == 0 {
		return -1
	}
	m, _ := metrics[0].(map[string]interface{})
	bs := toInt(m["bad_streak"])
	ns := toInt(m["null_streak"])
	return 16.0 / (16.0 + float64(bs)*4.0 + float64(ns)*2.0)
}

// ---------------------------------------------------------------------------
// 1: FRESHNESS — the v0.9.133 regression, in the exact shape it bit: a
// streak patched into a corpse map must move the displayed penalty the
// very next cycle.
// ---------------------------------------------------------------------------

func TestCorpseFreshnessNextCycle(t *testing.T) {
	resetCorpseView()
	// Live map carries 9.9.9.9; corpse rank 1 carries 5.6.7.8 with
	// cubic bad_streak=0 (penalty 1.000). The streak writeback then
	// patches bad_streak=3 — the next cycle must show penalty
	// 16/(16+3*4) = 0.571.
	liveKeys := [][]byte{v4key(9, 9, 9, 9)}
	liveVals := map[string][]byte{string(v4key(9, 9, 9, 9)): rawVal(40, 50, 60)}
	corpse := newFakeCorpseMap(1)
	ck := v4key(5, 6, 7, 8)
	corpse.put(ck, rawValStreaks(100, 20, 30, 0, 0))

	c1 := v134Cycle(t, liveKeys, liveVals, []*fakeCorpseMap{corpse})
	e1 := findByAddr(c1, ResolveBucket("5.6.7.8"))
	if e1 == nil {
		t.Fatal("corpse-carried 5.6.7.8 missing from cycle 1")
	}
	if p := penaltyOf(e1); p < 0.999 || p > 1.001 {
		t.Fatalf("cycle 1 penalty = %f, want 1.000 (bad_streak 0)", p)
	}

	// The streak writeback patches the corpse map (bad_streak 0 -> 3).
	corpse.put(ck, rawValStreaks(100, 20, 30, 3, 0))

	// v0.9.133 served the cached slice here — up to (N-1) cycles stale.
	c2 := v134Cycle(t, liveKeys, liveVals, []*fakeCorpseMap{corpse})
	e2 := findByAddr(c2, ResolveBucket("5.6.7.8"))
	if e2 == nil {
		t.Fatal("corpse-carried 5.6.7.8 missing from cycle 2")
	}
	if p := penaltyOf(e2); p > 0.58 || p < 0.56 {
		t.Fatalf("cycle 2 penalty = %f, want ~0.571 (bad_streak 3 visible NEXT cycle — the v0.9.133 regression)", p)
	}
}

// ---------------------------------------------------------------------------
// 2: NO WARMUP WINDOW — every corpse-carried label is present in the
// FIRST cycle's output, from completely cold state.
// ---------------------------------------------------------------------------

func TestCorpseCompleteFromFirstCycle(t *testing.T) {
	resetCorpseView()
	liveKeys := [][]byte{v4key(9, 9, 9, 9)}
	liveVals := map[string][]byte{string(v4key(9, 9, 9, 9)): rawVal(40, 50, 60)}
	corpses := []*fakeCorpseMap{newFakeCorpseMap(1), newFakeCorpseMap(2), newFakeCorpseMap(3)}
	want := map[string]bool{}
	for gi, g := range [][4]byte{{5, 6, 7, 8}, {6, 7, 8, 9}, {7, 8, 9, 10}} {
		corpses[gi].put(v4key(g[0], g[1], g[2], g[3]), rawVal(10*gi+5, 20, 30))
		want[ResolveBucket(fmt.Sprintf("%d.%d.%d.%d", g[0], g[1], g[2], g[3]))] = true
	}

	c1 := v134Cycle(t, liveKeys, liveVals, corpses)
	if findByAddr(c1, ResolveBucket("9.9.9.9")) == nil {
		t.Fatal("live label missing")
	}
	for addr := range want {
		if findByAddr(c1, addr) == nil {
			t.Fatalf("corpse-carried label %q missing from the FIRST cycle — v0.9.133 needed N cycles to warm up", addr)
		}
	}
}

// ---------------------------------------------------------------------------
// 3 + 4: EVERY-CYCLE EQUIVALENCE (incl. after cache hits) + CACHE-HIT
// PARITY.
// ---------------------------------------------------------------------------

func v134AssertEquivalence(t *testing.T, liveKeys [][]byte, liveVals map[string][]byte, corpses []*fakeCorpseMap) {
	t.Helper()
	// Reference: full all-gens merge over the same raw fixtures.
	gens := []map[string][]byte{liveVals}
	genKeys := [][][]byte{liveKeys}
	for _, c := range corpses {
		vals := map[string][]byte{}
		for _, k := range c.keys {
			vals[string(k)] = c.vals[string(k)]
		}
		gens = append(gens, vals)
		genKeys = append(genKeys, c.keys)
	}
	want := fullMergeRaw(t, gens, genKeys)
	got := v134Cycle(t, liveKeys, liveVals, corpses)

	if len(got) != len(want) {
		t.Fatalf("steady output %d buckets, full merge %d — labels lost or invented", len(got), len(want))
	}
	byAddr := map[string]hostEntry{}
	for _, h := range want {
		byAddr[h.Addr] = h
	}
	for _, h := range got {
		w, ok := byAddr[h.Addr]
		if !ok {
			t.Fatalf("steady output has %q, full merge lacks it", h.Addr)
		}
		if !reflect.DeepEqual(h, w) {
			t.Fatalf("label %q: steady %+v != full %+v", h.Addr, h, w)
		}
	}
}

func TestCorpseEquivalenceEveryCycleDeterministic(t *testing.T) {
	resetCorpseView()
	liveKeys := [][]byte{v4key(1, 2, 3, 4), v4key(9, 9, 9, 9)}
	liveVals := map[string][]byte{
		string(v4key(1, 2, 3, 4)): rawVal(82, 187, 100),
		string(v4key(9, 9, 9, 9)): rawVal(40, 50, 60),
	}
	g1 := newFakeCorpseMap(1)
	g1.put(v4key(1, 2, 3, 4), rawVal(726, 20, 5000)) // fat corpse copy of a LIVE label
	g1.put(v4key(5, 6, 7, 8), rawVal(11, 12, 13))     // corpse-only
	g2 := newFakeCorpseMap(2)
	g2.put(v4key(5, 6, 7, 8), rawVal(999, 99, 99))  // older carrier of 5.6.7.8 — must LOSE
	g2.put(v4key(6, 7, 8, 9), rawVal(21, 22, 23))   // corpse-only, oldest gen

	// The equivalence must hold on EVERY cycle — cycle 1 (cold parses),
	// cycle 2 (cache hits), cycle 3 (still hits).
	for cycle := 1; cycle <= 3; cycle++ {
		v134AssertEquivalence(t, liveKeys, liveVals, []*fakeCorpseMap{g1, g2})
	}
}

func TestCorpseEquivalenceEveryCycleRandomized(t *testing.T) {
	rng := rand.New(rand.NewSource(134))
	for round := 0; round < 25; round++ {
		resetCorpseView()
		nGens := 2 + rng.Intn(4) // 2..5 generations
		liveKeys := [][]byte{}
		liveVals := map[string][]byte{}
		corpses := make([]*fakeCorpseMap, 0, nGens-1)
		for rank := 0; rank < nGens; rank++ {
			n := 1 + rng.Intn(6)
			if rank == 0 {
				for i := 0; i < n; i++ {
					k := v4key(byte(1+rng.Intn(6)), byte(rng.Intn(4)), byte(rng.Intn(255)), byte(rng.Intn(255)))
					liveKeys = append(liveKeys, k)
					liveVals[string(k)] = rawVal(rng.Intn(1000), rng.Intn(50), rng.Intn(100))
				}
				continue
			}
			m := newFakeCorpseMap(rank)
			for i := 0; i < n; i++ {
				// first two octets pick the /16 bucket: heavy overlap with
				// the live map and other corpses — collisions intended
				k := v4key(byte(1+rng.Intn(6)), byte(rng.Intn(4)), byte(rng.Intn(255)), byte(rng.Intn(255)))
				m.put(k, rawVal(rng.Intn(1000), rng.Intn(50), rng.Intn(100)))
			}
			corpses = append(corpses, m)
		}
		// Two cycles per round: cold + cache-hit.
		v134AssertEquivalence(t, liveKeys, liveVals, corpses)
		v134AssertEquivalence(t, liveKeys, liveVals, corpses)
	}
}

func TestCorpseCacheHitParity(t *testing.T) {
	resetCorpseView()
	liveKeys := [][]byte{v4key(9, 9, 9, 9)}
	liveVals := map[string][]byte{string(v4key(9, 9, 9, 9)): rawVal(40, 50, 60)}
	corpse := newFakeCorpseMap(1)
	corpse.put(v4key(5, 6, 7, 8), rawVal(11, 12, 13))

	c1 := v134Cycle(t, liveKeys, liveVals, []*fakeCorpseMap{corpse})
	c2 := v134Cycle(t, liveKeys, liveVals, []*fakeCorpseMap{corpse}) // cache hit
	e1 := findByAddr(c1, ResolveBucket("5.6.7.8"))
	e2 := findByAddr(c2, ResolveBucket("5.6.7.8"))
	if e1 == nil || e2 == nil {
		t.Fatal("5.6.7.8 missing")
	}
	if !reflect.DeepEqual(*e1, *e2) {
		t.Fatalf("cache-hit entry differs from fresh parse: %+v != %+v", *e2, *e1)
	}
}

// ---------------------------------------------------------------------------
// 5: PARSE BOUND — an unchanged corpse map costs ZERO parses next cycle.
// ---------------------------------------------------------------------------

func TestCorpseUnchangedParsesZero(t *testing.T) {
	resetCorpseView()
	liveKeys := [][]byte{v4key(9, 9, 9, 9)}
	liveVals := map[string][]byte{string(v4key(9, 9, 9, 9)): rawVal(40, 50, 60)}
	corpse := newFakeCorpseMap(1)
	corpse.put(v4key(5, 6, 7, 8), rawVal(11, 12, 13))
	corpse.put(v4key(6, 7, 8, 9), rawVal(21, 22, 23))

	v134Cycle(t, liveKeys, liveVals, []*fakeCorpseMap{corpse}) // cold: parses

	var mu sync.Mutex
	parses := 0
	corpseViewMu.Lock()
	orig := corpseParse
	corpseParse = func(key, value []byte) map[string]interface{} {
		mu.Lock()
		parses++
		mu.Unlock()
		return orig(key, value)
	}
	corpseViewMu.Unlock()
	defer func() {
		corpseViewMu.Lock()
		corpseParse = orig
		corpseViewMu.Unlock()
	}()

	v134Cycle(t, liveKeys, liveVals, []*fakeCorpseMap{corpse}) // steady: cache hits
	if parses != 0 {
		t.Fatalf("unchanged corpse map caused %d parses — steady cycle must parse nothing (flatness)", parses)
	}

	// One label changes (streak writeback): exactly its keys re-parse.
	corpse.put(v4key(5, 6, 7, 8), rawValStreaks(11, 12, 13, 2, 0))
	v134Cycle(t, liveKeys, liveVals, []*fakeCorpseMap{corpse})
	if parses != 1 {
		t.Fatalf("one changed label caused %d parses, want exactly 1", parses)
	}
}

// ---------------------------------------------------------------------------
// 6: NEWEST CARRIER WINS + LOOKUP BOUND (the cost claim).
// ---------------------------------------------------------------------------

func TestCorpseNewestCarrierWinsAndLookupBound(t *testing.T) {
	resetCorpseView()
	liveKeys := [][]byte{v4key(9, 9, 9, 9)}
	liveVals := map[string][]byte{string(v4key(9, 9, 9, 9)): rawVal(40, 50, 60)}
	newer := newFakeCorpseMap(1)
	older := newFakeCorpseMap(3)
	label := v4key(5, 6, 7, 8)
	newer.put(label, rawVal(111, 20, 30)) // newest carrier
	older.put(label, rawVal(999, 99, 99)) // must never be looked up
	older.put(v4key(6, 7, 8, 9), rawVal(55, 10, 20))
	newer.looks, older.looks = new(int), new(int)

	out := v134Cycle(t, liveKeys, liveVals, []*fakeCorpseMap{newer, older})
	e := findByAddr(out, ResolveBucket("5.6.7.8"))
	if e == nil || firstCubicEMA([]hostEntry{*e}) != 111 {
		t.Fatalf("newest carrier must win, got %+v", e)
	}
	if *newer.looks != 1 {
		t.Fatalf("newer map lookups = %d, want 1", *newer.looks)
	}
	if *older.looks != 1 {
		t.Fatalf("older map lookups = %d, want 1 (only its OWN label; the older 5.6.7.8 key must never be looked up)", *older.looks)
	}
}

// ---------------------------------------------------------------------------
// 7: LIVE WINS PER LABEL — a live-carried label never looks up a corpse.
// ---------------------------------------------------------------------------

func TestCorpseLiveWinsNeverFetches(t *testing.T) {
	resetCorpseView()
	liveKeys := [][]byte{v4key(1, 2, 3, 4)}
	liveVals := map[string][]byte{string(v4key(1, 2, 3, 4)): rawVal(82, 187, 100)}
	corpse := newFakeCorpseMap(1)
	corpse.put(v4key(1, 2, 3, 4), rawVal(726, 20, 5000)) // fat corpse of a LIVE label
	corpse.put(v4key(5, 6, 7, 8), rawVal(11, 12, 13))
	corpse.looks = new(int)

	out := v134Cycle(t, liveKeys, liveVals, []*fakeCorpseMap{corpse})
	if len(out) != 2 {
		t.Fatalf("expected 2 buckets, got %d", len(out))
	}
	e := findByAddr(out, ResolveBucket("1.2.3.4"))
	if e == nil || e.Gen != 0 || firstCubicEMA([]hostEntry{*e}) != 82 {
		t.Fatalf("live 1.2.3.4 must win with its own values (Gen=0, ema=82), got %+v", e)
	}
	if findByAddr(out, ResolveBucket("5.6.7.8")) == nil {
		t.Fatal("corpse-only 5.6.7.8 must survive")
	}
	if *corpse.looks != 1 {
		t.Fatalf("corpse lookups = %d, want 1 (only the corpse-only label; live-carried labels never look up)", *corpse.looks)
	}
}

// ---------------------------------------------------------------------------
// 8: KEY-SET GROWTH + CACHE PRUNING.
// ---------------------------------------------------------------------------

func TestCorpseKeySetGrowthAndPruning(t *testing.T) {
	resetCorpseView()
	liveKeys := [][]byte{v4key(9, 9, 9, 9)}
	liveVals := map[string][]byte{string(v4key(9, 9, 9, 9)): rawVal(40, 50, 60)}
	corpse := newFakeCorpseMap(1)
	k1 := v4key(5, 6, 7, 8)
	corpse.put(k1, rawVal(11, 12, 13))

	c1 := v134Cycle(t, liveKeys, liveVals, []*fakeCorpseMap{corpse})
	if findByAddr(c1, ResolveBucket("5.6.7.8")) == nil {
		t.Fatal("precondition: 5.6.7.8 present")
	}
	// A zombie program adds a brand-new key to the corpse map.
	corpse.put(v4key(8, 8, 8, 8), rawVal(77, 10, 10))
	c2 := v134Cycle(t, liveKeys, liveVals, []*fakeCorpseMap{corpse})
	if findByAddr(c2, ResolveBucket("8.8.8.8")) == nil {
		t.Fatal("zombie-added key must be discovered the NEXT cycle (key-set walk every cycle)")
	}
	// The label's key vanishes (map cleanup): pruned from output AND cache.
	corpse.del(k1)
	c3 := v134Cycle(t, liveKeys, liveVals, []*fakeCorpseMap{corpse})
	if findByAddr(c3, ResolveBucket("5.6.7.8")) != nil {
		t.Fatal("vanished label must leave the output")
	}
	corpseViewMu.Lock()
	n := len(corpseView)
	corpseViewMu.Unlock()
	if n != 1 {
		t.Fatalf("cache holds %d labels after pruning, want 1", n)
	}
}

// ---------------------------------------------------------------------------
// 9: LABEL PARITY — discovery's label derivation matches the merge's.
// ---------------------------------------------------------------------------

func TestRawKeyToFinalLabelParity(t *testing.T) {
	cases := [][]byte{
		v4key(1, 2, 3, 4),
		v4key(9, 9, 9, 9),
		v4key(104, 16, 132, 229),
		v4key(8, 8, 8, 8),
	}
	for _, key := range cases {
		keyMap := parseRawKey(key)
		addrBytes := keyMap["in6_u"].(map[string]interface{})["u6_addr8"].([]interface{})
		b := make([]int, 16)
		for i, v := range addrBytes {
			b[i] = toInt(v)
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
		final := ResolveBucket(addr)
		if final == "" {
			final = addr
		}
		got, _ := rawKeyToFinalLabel(key)
		if got != final {
			t.Fatalf("key %v: discovery label %q != merge label %q — the paths drifted", key, got, final)
		}
	}
}

// ---------------------------------------------------------------------------
// steady-state vs full merge + live-regained (ported intent of the
// v0.9.132 cache tests, which tested the deleted round-robin cache).
// ---------------------------------------------------------------------------

func TestCorpseSteadyStateMatchesFullMerge(t *testing.T) {
	resetCorpseView()
	liveKeys := [][]byte{v4key(1, 2, 3, 4), v4key(9, 9, 9, 9)}
	liveVals := map[string][]byte{
		string(v4key(1, 2, 3, 4)): rawVal(82, 187, 100),
		string(v4key(9, 9, 9, 9)): rawVal(40, 50, 60),
	}
	g1 := newFakeCorpseMap(1)
	g1.put(v4key(1, 2, 3, 4), rawVal(726, 20, 5000))
	g1.put(v4key(5, 6, 7, 8), rawVal(726, 20, 5000))
	v134AssertEquivalence(t, liveKeys, liveVals, []*fakeCorpseMap{g1})
}

func TestCorpseLiveRegainsLabelSkipsCorpse(t *testing.T) {
	resetCorpseView()
	liveKeys := [][]byte{v4key(5, 6, 7, 8)}
	liveVals := map[string][]byte{string(v4key(5, 6, 7, 8)): rawVal(11, 22, 33)}
	corpse := newFakeCorpseMap(1)
	corpse.put(v4key(5, 6, 7, 8), rawVal(999, 20, 5000))
	corpse.looks = new(int)

	out := v134Cycle(t, liveKeys, liveVals, []*fakeCorpseMap{corpse})
	if len(out) != 1 || out[0].Gen != 0 || firstCubicEMA(out) != 11 {
		t.Fatalf("live-regained label must win: got %d buckets, Gen=%d ema=%d", len(out), out[0].Gen, firstCubicEMA(out))
	}
	if *corpse.looks != 0 {
		t.Fatalf("live-regained label must never look up the corpse (got %d lookups)", *corpse.looks)
	}
}
