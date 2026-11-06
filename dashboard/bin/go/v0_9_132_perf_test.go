package main

// v0_9_132_perf_test.go — regression tests for the v0.9.132 performance
// fixes (all collector-side; the tuner is untouched):
//
//   1. frozen-generation cache: steady-state readBPFMap output must equal
//      the full all-gens merge (corpse tax removed without changing data);
//   2. cache cadence: refresh on first call, on id-set change, and every
//      corpseCacheRefreshEvery calls — and nothing in between;
//   3. live-regains-label: when the live map re-gains a cached corpse
//      label, the live entry wins (fold skips the corpse);
//   4. picker scan plan: newest-only on steady passes, all gens on every
//      10th pass starting with the first;
//   5. watchdog: grace suppresses the CPU kill, 3 strikes kill post-grace,
//      RSS keeps the strict 2-strike rule with no grace.
//
// The merge-equivalence tests deliberately reuse the v0_9_128 helpers
// (genEntry / findByAddr / firstCubicEMA) so the scenarios stay in the
// same vocabulary as the generation-rule tests they must not regress.

import (
	"reflect"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// 1 + 2 + 3: frozen-generation cache
// ---------------------------------------------------------------------------

// fullMerge is what v0.9.128-131 computed EVERY cycle: dump all gens,
// merge once. The v0.9.132 steady path must reproduce this output from a
// live-only dump plus the cached corpse contribution.
func fullMerge(live, corpse []map[string]interface{}) []hostEntry {
	raw := append(append([]map[string]interface{}{}, live...), corpse...)
	out, err := mergeBPFMapEntries(raw)
	if err != nil {
		panic(err)
	}
	return out
}

func TestCorpseCacheSteadyStateMatchesFullMerge(t *testing.T) {
	// Live map: 1.2.3.4 (also present as a fat corpse) + 9.9.9.9.
	// Corpses: frozen 1.2.3.4 (must LOSE to live) + corpse-only 5.6.7.8.
	live := []map[string]interface{}{
		genEntry(1, 2, 3, 4, 0, 82, 187, 100),
		genEntry(9, 9, 9, 9, 0, 40, 50, 60),
	}
	corpse := []map[string]interface{}{
		genEntry(1, 2, 3, 4, 1, 726, 20, 5000),
		genEntry(5, 6, 7, 8, 1, 726, 20, 5000),
	}

	want := fullMerge(live, corpse)

	// Refresh pass (as readBPFMap does): full merge, cache the Gen>0 slice.
	var cache corpseGenCache
	cache.rebuild([]int{282, 223}, want, 1)

	// Steady pass: merge ONLY the live dump, fold the cache.
	liveOnly, err := mergeBPFMapEntries(append([]map[string]interface{}{}, live...))
	if err != nil {
		t.Fatalf("live-only merge: %v", err)
	}
	got := cache.fold(liveOnly)

	if len(got) != len(want) {
		t.Fatalf("steady output has %d buckets, full merge has %d — corpse-only labels lost", len(got), len(want))
	}
	byAddrWant := map[string]hostEntry{}
	for _, h := range want {
		byAddrWant[h.Addr] = h
	}
	for _, h := range got {
		w, ok := byAddrWant[h.Addr]
		if !ok {
			t.Fatalf("steady output has label %q the full merge lacks", h.Addr)
		}
		if h.Inst != w.Inst || h.Gen != w.Gen || h.MaxInst != w.MaxInst {
			t.Fatalf("label %q: steady {inst=%d gen=%d max=%d} != full {inst=%d gen=%d max=%d}",
				h.Addr, h.Inst, h.Gen, h.MaxInst, w.Inst, w.Gen, w.MaxInst)
		}
		// The metrics payload must be the same winner's values: compare the
		// cubic rate_ema the way the v0.9.128 tests do.
		if gotEMA, wantEMA := firstCubicEMA([]hostEntry{h}), firstCubicEMA([]hostEntry{w}); gotEMA != wantEMA {
			t.Fatalf("label %q: cubic rate_ema steady=%d full=%d", h.Addr, gotEMA, wantEMA)
		}
	}

	// The fat corpse must NOT have won 1.2.3.4 in either path.
	if e := findByAddr(got, ResolveBucket("1.2.3.4")); e == nil || firstCubicEMA([]hostEntry{*e}) != 82 {
		t.Fatalf("live 1.2.3.4 must win with rate_ema 82 in the steady path too")
	}
	// The corpse-only label must survive the steady path.
	if e := findByAddr(got, ResolveBucket("5.6.7.8")); e == nil || e.Gen != 1 {
		t.Fatalf("corpse-only 5.6.7.8 must survive the steady path with Gen=1")
	}
}

func TestCorpseCacheLiveRegainsLabelSkipsCorpse(t *testing.T) {
	// Corpse-only label 5.6.7.8 is cached; the live map later re-gains it.
	corpse := []map[string]interface{}{genEntry(5, 6, 7, 8, 1, 726, 20, 5000)}
	want := fullMerge(nil, corpse)
	var cache corpseGenCache
	cache.rebuild([]int{282, 223}, want, 1)

	liveNow := []map[string]interface{}{genEntry(5, 6, 7, 8, 0, 11, 22, 33)}
	liveMerged, err := mergeBPFMapEntries(liveNow)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	got := cache.fold(liveMerged)

	if len(got) != 1 {
		t.Fatalf("expected 1 bucket, got %d", len(got))
	}
	if got[0].Gen != 0 || firstCubicEMA(got) != 11 {
		t.Fatalf("live-regained label must win: got Gen=%d ema=%d, want Gen=0 ema=11", got[0].Gen, firstCubicEMA(got))
	}
}

func TestCorpseCacheCadence(t *testing.T) {
	ids := []int{282, 223}
	var c corpseGenCache

	// First call on an unbuilt cache: refresh.
	if !corpseRefreshDue(&c, 1, ids) {
		t.Fatal("unbuilt cache must refresh")
	}
	c.rebuild(ids, nil, 1)

	// Same ids, within the window: no refresh.
	for call := 2; call < 1+corpseCacheRefreshEvery; call++ {
		if corpseRefreshDue(&c, call, ids) {
			t.Fatalf("call %d within the window must not refresh", call)
		}
	}
	// Cadence expiry: refresh.
	if !corpseRefreshDue(&c, 1+corpseCacheRefreshEvery, ids) {
		t.Fatal("cadence expiry must refresh")
	}
	c.rebuild(ids, nil, 1+corpseCacheRefreshEvery)

	// Id set changed (a reload happened): refresh immediately.
	if !corpseRefreshDue(&c, 2+corpseCacheRefreshEvery, []int{301, 282, 223}) {
		t.Fatal("id-set change must refresh")
	}
	// A single-gen host (no corpses at all) never refreshes off-cadence.
	var single corpseGenCache
	single.rebuild([]int{42}, nil, 1)
	for call := 2; call <= corpseCacheRefreshEvery; call++ {
		if corpseRefreshDue(&single, call, []int{42}) {
			t.Fatalf("single-gen host: call %d must not refresh", call)
		}
	}
}

func TestSameIntIDs(t *testing.T) {
	cases := []struct {
		a, b []int
		want bool
	}{
		{[]int{1, 2}, []int{1, 2}, true},
		{[]int{1, 2}, []int{2, 1}, false},
		{[]int{1, 2}, []int{1, 2, 3}, false},
		{nil, nil, true},
		{[]int{5}, nil, false},
	}
	for _, c := range cases {
		if got := sameIntIDs(c.a, c.b); got != c.want {
			t.Fatalf("sameIntIDs(%v, %v) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// 4: picker scan plan
// ---------------------------------------------------------------------------

func TestPickerScanIDs(t *testing.T) {
	all := []int{282, 223, 190}

	// First pass after startup: full scan.
	if got := pickerScanIDs(1, all); !reflect.DeepEqual(got, all) {
		t.Fatalf("pass 1 must full-scan, got %v", got)
	}
	// Steady passes: newest only.
	for call := 2; call <= 10; call++ {
		if got := pickerScanIDs(call, all); !reflect.DeepEqual(got, []int{282}) {
			t.Fatalf("pass %d must scan newest only, got %v", call, got)
		}
	}
	// Every 10th pass: full scan again.
	if got := pickerScanIDs(11, all); !reflect.DeepEqual(got, all) {
		t.Fatalf("pass 11 must full-scan, got %v", got)
	}
	if got := pickerScanIDs(21, all); !reflect.DeepEqual(got, all) {
		t.Fatalf("pass 21 must full-scan, got %v", got)
	}
	// Degenerate: no ids at all.
	if got := pickerScanIDs(1, nil); len(got) != 0 {
		t.Fatalf("empty id set must stay empty, got %v", got)
	}
	// Single generation: steady and full scans are the same thing.
	if got := pickerScanIDs(2, []int{7}); !reflect.DeepEqual(got, []int{7}) {
		t.Fatalf("single-gen steady scan = the one map, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// 5: watchdog decision
// ---------------------------------------------------------------------------

func TestWatchdogDecision(t *testing.T) {
	grace := watchdogGracePeriod

	// RSS: strict 2-strike, NO grace (memory bounds failing is always real).
	if kill, _ := watchdogDecision(30*time.Second, 2, 0); !kill {
		t.Fatal("2 RSS strikes during grace must still kill")
	}
	if kill, _ := watchdogDecision(30*time.Second, 1, 0); kill {
		t.Fatal("1 RSS strike must not kill")
	}

	// CPU during grace: suppressed even with the (impossible-in-loop) max
	// counter — the loop never counts during grace, and the decision must
	// not kill on CPU before grace ends.
	if kill, _ := watchdogDecision(grace-time.Second, 0, 99); kill {
		t.Fatal("CPU breaches during grace must never kill")
	}

	// CPU after grace: 3 strikes kill, 2 do not (v0.9.102's 2-strike rule
	// was the suicide-loop trigger).
	if kill, _ := watchdogDecision(grace, 0, 2); kill {
		t.Fatal("2 CPU strikes post-grace must not kill (was the suicide loop)")
	}
	if kill, reason := watchdogDecision(grace, 0, 3); !kill || reason != "cpu" {
		t.Fatalf("3 CPU strikes post-grace must kill with reason cpu, got kill=%v reason=%q", kill, reason)
	}

	// RSS wins priority reporting order.
	if _, reason := watchdogDecision(grace, 2, 3); reason != "rss" {
		t.Fatal("RSS kill must take priority")
	}
}
