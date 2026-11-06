package main

// v0_9_132_perf_test.go — regression tests for the v0.9.132 performance
// fixes (all collector-side; the tuner is untouched):
//
//   1. frozen-generation cache: steady-state readBPFMap output must equal
//      the full all-gens merge (corpse tax removed without changing data);
//   2. live-regains-label: when the live map re-gains a cached corpse
//      label, the live entry wins (fold skips the corpse);
//   3. picker scan plan: newest-only on steady passes, all gens on every
//      10th pass starting with the first;
//   4. watchdog: grace suppresses the CPU kill, 3 strikes kill post-grace,
//      RSS keeps the strict 2-strike rule with no grace.
//
// v0.9.133 superseded the v0.9.132 cache CADENCE (every-10th-call full
// refresh -> per-call round-robin sweep of one corpse generation) — the
// cadence test moved to v0_9_133_test.go with the new semantics. The
// fold-equivalence tests below still hold: the fold itself is unchanged,
// and seedFromFullMerge produces the same starting state the old rebuild
// did (the Gen>0 slice of a full merge).
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
// 1 + 2: frozen-generation cache
// ---------------------------------------------------------------------------

// fullMerge is what v0.9.128-131 computed EVERY cycle: dump all gens,
// merge once. The v0.9.132+ steady path must reproduce this output from a
// live-only dump plus the cached corpse contribution.
// (v0.9.134) TestCorpseCacheSteadyStateMatchesFullMerge and
// TestCorpseCacheLiveRegainsLabelSkipsCorpse tested the v0.9.132/133
// round-robin VALUE cache, deleted in v0.9.134 after the production
// freshness regression (stale corpse display vs fresh swap trackers).
// Their intent is ported to v0_9_134_test.go:
// TestCorpseSteadyStateMatchesFullMerge and TestCorpseLiveRegainsLabelSkipsCorpse.

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
