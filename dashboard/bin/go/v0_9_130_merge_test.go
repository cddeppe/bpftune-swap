package main

// v0_9_130_merge_test.go — regression tests for the two frozen-leaderboard
// root causes fixed in v0.9.130:
//
//  1. B3 representative self-merge: when a larger-inst entry arrived for a
//     label that already had merged entries, existing.V was REPLACED by the
//     new val and then mergeHostValues(existing.V, val) merged the new
//     representative WITH ITSELF — its instances/votes/rate_emas counted
//     twice, and every entry merged before it was silently discarded.
//     (Observed on al: Cloudflare instances=33187 vs true sum 23952; the
//     100.96.0.0 bucket's metrics never reached the leaderboard at all.)
//
//  2. Positional gen tags: map_gen was the loop index over mapIDs, correct
//     only while mapIDs is sorted newest-first. mapIDGenRank now derives
//     the tag from the id itself (highest id = gen 0), immune to ordering.

import (
        "fmt"
        "testing"
)

func mkMergeEntry(inst int, gen int, cubicVotes, cubicEMA, illVotes int) map[string]interface{} {
        metrics := make([]interface{}, 16)
        for i := range metrics {
                metrics[i] = map[string]interface{}{
                        "state_flags": float64(0), "greedy_count": float64(0),
                        "metric_count": float64(0), "metric_value": float64(0),
                        "sockets_alive": float64(0), "sockets_good": float64(0),
                        "sockets_proved": float64(0), "rate_ema": float64(0),
                        "swap_score": float64(256), "bad_streak": float64(0),
                        "null_streak": float64(0),
                }
        }
        metrics[0].(map[string]interface{})["metric_count"] = float64(cubicVotes)
        metrics[0].(map[string]interface{})["rate_ema"] = float64(cubicEMA)
        metrics[9].(map[string]interface{})["metric_count"] = float64(illVotes)
        return map[string]interface{}{
                "formatted": map[string]interface{}{
                        "key": map[string]interface{}{
                                "in6_u": map[string]interface{}{
                                        "u6_addr8": []interface{}{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 100, 96, 0, 0},
                                },
                        },
                        "value": map[string]interface{}{
                                "instances": float64(inst), "min_rtt": float64(5000),
                                "metrics":   metrics,
                        },
                },
                "map_gen": float64(gen),
        }
}

func cfMetric(merged []hostEntry, algIdx int, field string) (int, *hostEntry) {
        for i := range merged {
                if merged[i].Addr == "Cloudflare" || merged[i].Addr == "100.96.0.0" {
                        h := &merged[i]
                        if mi, ok := h.V["metrics"].([]interface{}); ok {
                                if m, ok := mi[algIdx].(map[string]interface{}); ok {
                                        return toInt(m[field]), h
                                }
                        }
                }
        }
        return -1, nil
}

// TestMergeNoDoubleCountNoDataLoss: five same-generation Cloudflare entries
// (the al repro: 100.96 first, then the largest 162.159, then three more).
// Pre-v0.9.130 this produced instances=33187, cubic=1190 (162.159 doubled,
// 100.96 lost). Must now be the exact sums.
func TestMergeNoDoubleCountNoDataLoss(t *testing.T) {
        raw := []map[string]interface{}{
                mkMergeEntry(6280, 0, 220, 66, 1409),  // 100.96.0.0 (live)
                mkMergeEntry(15515, 0, 380, 62, 900),  // 162.159.0.0 (live, largest)
                mkMergeEntry(140, 0, 90, 45, 45),      // 172.64.0.0
                mkMergeEntry(60, 0, 40, 30, 10),       // 172.66.0.0
                mkMergeEntry(1957, 0, 300, 58, 255),   // 2606:4700::
        }
        merged, err := mergeBPFMapEntries(raw)
        if err != nil {
                t.Fatalf("merge: %v", err)
        }
        wantInst := 6280 + 15515 + 140 + 60 + 1957 // 23952
        wantCubic := 220 + 380 + 90 + 40 + 300     // 1030
        wantIll := 1409 + 900 + 45 + 10 + 255      // 2619
        wantCubicEMA := 66 + 62 + 45 + 30 + 58     // 261

        inst, h := cfMetric(merged, 0, "metric_count")
        if h == nil {
                t.Fatal("Cloudflare entry not found in merge output")
        }
        if got := toInt(h.V["instances"]); got != wantInst {
                t.Errorf("V.instances = %d, want %d (double-count/data-loss regression)", got, wantInst)
        }
        if h.Inst != wantInst {
                t.Errorf("h.Inst = %d, want %d", h.Inst, wantInst)
        }
        if inst != wantCubic {
                t.Errorf("cubic votes = %d, want %d", inst, wantCubic)
        }
        if ema, h2 := cfMetric(merged, 0, "rate_ema"); h2 != nil && ema != wantCubicEMA {
                t.Errorf("cubic rate_ema = %d, want %d", ema, wantCubicEMA)
        }
        if ill, _ := cfMetric(merged, 9, "metric_count"); ill != wantIll {
                t.Errorf("illinois votes = %d, want %d", ill, wantIll)
        }
}

// TestMergeLargestFirstNoDoubleCount: same entries, largest first — the
// other ordering that used to double the representative.
func TestMergeLargestFirstNoDoubleCount(t *testing.T) {
        raw := []map[string]interface{}{
                mkMergeEntry(15515, 0, 380, 62, 900),
                mkMergeEntry(6280, 0, 220, 66, 1409),
                mkMergeEntry(1957, 0, 300, 58, 255),
        }
        merged, err := mergeBPFMapEntries(raw)
        if err != nil {
                t.Fatalf("merge: %v", err)
        }
        if inst, h := cfMetric(merged, 0, "metric_count"); h == nil || inst != 900 {
                t.Errorf("cubic votes = %d, want 900", inst)
        }
        if _, h := cfMetric(merged, 0, "metric_count"); h != nil && toInt(h.V["instances"]) != 15515+6280+1957 {
                t.Errorf("V.instances = %d, want %d", toInt(h.V["instances"]), 15515+6280+1957)
        }
}

// TestMapIDGenRank: the tag must be derived from the id, not position.
func TestMapIDGenRank(t *testing.T) {
        cases := []struct {
                ids    []int
                mapID  int
                wantGen int
        }{
                {[]int{282, 223}, 282, 0}, // newest-first list: unchanged behaviour
                {[]int{282, 223}, 223, 1},
                {[]int{223, 282}, 282, 0}, // oldest-first list: tag must STILL be right
                {[]int{223, 282}, 223, 1},
                {[]int{284, 282, 225, 223}, 282, 1}, // scratch maps in the list
                {[]int{284, 282, 225, 223}, 223, 3},
                {[]int{223, 225, 282, 284}, 282, 1},
        }
        for _, c := range cases {
                if got := mapIDGenRank(c.ids, c.mapID); got != c.wantGen {
                        t.Errorf("mapIDGenRank(%v, %d) = %d, want %d", c.ids, c.mapID, got, c.wantGen)
                }
        }
}

// TestGenTagsOrderIndependent: identical merged output regardless of the
// order the two generations arrive in — the frozen-leaderboard guard.
func TestGenTagsOrderIndependent(t *testing.T) {
        live := mkMergeEntry(6280, 0, 220, 66, 1409)
        corpse := mkMergeEntry(40, 1, 10, 363, 5)
        liveReversed := mkMergeEntry(6280, 0, 220, 66, 1409)
        corpseReversed := mkMergeEntry(40, 1, 10, 363, 5)

        mergedA, err := mergeBPFMapEntries([]map[string]interface{}{live, corpse})
        if err != nil {
                t.Fatalf("merge A: %v", err)
        }
        mergedB, err := mergeBPFMapEntries([]map[string]interface{}{corpseReversed, liveReversed})
        if err != nil {
                t.Fatalf("merge B: %v", err)
        }
        for _, m := range [][]hostEntry{mergedA, mergedB} {
                inst, h := cfMetric(m, 0, "metric_count")
                if h == nil {
                        t.Fatal("Cloudflare entry missing")
                }
                if toInt(h.V["instances"]) != 6280 || inst != 220 {
                        t.Errorf("live generation must win regardless of arrival order: got inst=%d cubic=%d, want 6280/220",
                                toInt(h.V["instances"]), inst)
                }
                if h.Gen != 0 {
                        t.Errorf("merged entry Gen = %d, want 0 (live)", h.Gen)
                }
        }
        _ = fmt.Sprint // keep fmt if unused elsewhere
}
