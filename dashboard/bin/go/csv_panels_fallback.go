package main

// csv_panels_fallback.go — when the log tail is sparse (just rotated, or
// after a restart), fall back to reading historical data from CSVs so
// the dashboard panels always show data.
//
// v0.9.6: extends the recent_swaps/recent_proofs fallback pattern to
// swap_outcomes, proofs_raw (leaderboard), divergence, and churn.
// These panels previously showed empty after a restart until enough new
// log data accumulated — now they pull from swaps.csv and proofs.csv.
//
// All functions return data in the SAME shape as their log-derived
// counterparts so the frontend renders them identically.

import (
        "bufio"
        "os"
        "sort"
        "strconv"
        "strings"
)

// readSwapsCSVRows reads the last N rows from swaps.csv and returns
// them as parsed structures. Shared by all CSV fallback functions.
// Returns nil if the file doesn't exist or is unreadable.
func readSwapsCSVRows(n int) []csvSwapRow {
        f, err := os.Open(swapsCSVPath)
        if err != nil {
                return nil
        }
        defer f.Close()

        var lines []string
        scanner := bufio.NewScanner(f)
        scanner.Buffer(make([]byte, 0, 65536), 8*1024*1024) // 8MB max line
        for scanner.Scan() {
                lines = append(lines, scanner.Text())
        }
        if len(lines) < 2 {
                return nil
        }
        // Skip header
        lines = lines[1:]
        // Take last N
        if len(lines) > n {
                lines = lines[len(lines)-n:]
        }

        out := make([]csvSwapRow, 0, len(lines))
        for _, line := range lines {
                fields := strings.Split(line, ",")
                if len(fields) < 18 {
                        continue
                }
                ts, _ := strconv.ParseFloat(fields[1], 64)
                cookie, _ := strconv.ParseInt(fields[2], 10, 64)
                fromAlg := fields[3]
                toAlg := fields[4]
                d, _ := strconv.Atoi(fields[5])
                mtAlg := fields[6]
                rbAlg := fields[7]
                diverges := fields[8] == "1"
                outcome := fields[9]
                dest := fields[11]
                srateBefore := fields[15]
                direction := fields[16]
                rport := fields[17]

                out = append(out, csvSwapRow{
                        Ts:          ts,
                        Cookie:      cookie,
                        FromAlg:     fromAlg,
                        ToAlg:       toAlg,
                        D:           d,
                        MtAlg:       mtAlg,
                        RbAlg:       rbAlg,
                        Diverges:    diverges,
                        Outcome:     outcome,
                        Dest:        dest,
                        SrateBefore: srateBefore,
                        Direction:   direction,
                        Rport:       rport,
                })
        }
        return out
}

// csvSwapRow is a parsed row from swaps.csv used by the fallback panels.
// (Distinct from the swapCSVRow type in render_swaps.go which has different fields.)
type csvSwapRow struct {
        Ts          float64
        Cookie      int64
        FromAlg     string
        ToAlg       string
        D           int
        MtAlg       string
        RbAlg       string
        Diverges    bool
        Outcome     string
        Dest        string
        SrateBefore string
        Direction   string
        Rport       string
}

// buildSwapOutcomesFromCSV reads the last N swaps from swaps.csv and
// computes outcome counts. The CSV's "outcome" column is the sustained
// outcome (enriched during CSV write), so we use it for all three
// outcome types (composite/srate/sustained) — the frontend shows them
// in separate tabs but the data is the same when derived from CSV.
//
// This mirrors buildSwapOutcomes in log_parsing.go.
func buildSwapOutcomesFromCSV(n int) map[string]interface{} {
        rows := readSwapsCSVRows(n)
        if len(rows) == 0 {
                return emptySwapOutcomes()
        }

        cCounts := newOutcomeCounts()
        sCounts := newOutcomeCounts()
        sustCounts := newOutcomeCounts()

        var swapsList []swapOutRow

        for _, r := range rows {
                // CSV outcome is the sustained outcome — use for all three.
                incrOutcome(cCounts, r.Outcome)
                incrOutcome(sCounts, r.Outcome)
                incrOutcome(sustCounts, r.Outcome)

                destLabel := labelFor(r.Dest)
                if destLabel == "" {
                        destLabel = r.Dest
                }
                swapsList = append(swapsList, swapOutRow{
                        Ts:               r.Ts,
                        Cookie:           r.Cookie,
                        Outcome:          r.Outcome,
                        OutcomeSrate:     r.Outcome,
                        OutcomeSustained: r.Outcome,
                        Dest:             destLabel,
                })
        }

        out := map[string]interface{}{
                "composite": finalizeOutcome(cCounts),
                "srate":     finalizeOutcome(sCounts),
                "sustained": finalizeOutcome(sustCounts),
        }
        addLossRecovery(out, swapsList)
        out["swaps_list"] = buildSwapsListForOutcomes(swapsList)
        return out
}

// buildProofsRawFromCSV reads all proofs from proofs.csv and aggregates
// good/proved counts per alg. This mirrors buildProofsRaw in log_parsing.go.
func buildProofsRawFromCSV() []interface{} {
        f, err := os.Open(proofsCSVPath)
        if err != nil {
                return []interface{}{}
        }
        defer f.Close()

        type algStats struct {
                good       int
                proved     int
                provenMax  int64
                sampleSum  int64
                sampleN    int
                sampleMax  int64
        }
        stats := map[int]*algStats{}

        scanner := bufio.NewScanner(f)
        scanner.Buffer(make([]byte, 0, 65536), 1024*1024)
        isHeader := true
        for scanner.Scan() {
                line := scanner.Text()
                if isHeader {
                        isHeader = false
                        continue
                }
                fields := strings.Split(line, ",")
                if len(fields) < 8 {
                        continue
                }
                algStr := fields[3]
                rateStr := fields[4]
                tier := fields[6]
                alg, err := strconv.Atoi(algStr)
                if err != nil {
                        // Try CONGS name lookup
                        alg = algIndexFromName(algStr)
                        if alg < 0 {
                                continue
                        }
                }
                rate, _ := strconv.ParseInt(rateStr, 10, 64)
                s, ok := stats[alg]
                if !ok {
                        s = &algStats{}
                        stats[alg] = s
                }
                if tier == "2" {
                        s.proved++
                        if rate > s.provenMax {
                                s.provenMax = rate
                        }
                } else {
                        s.good++
                }
                // Every proof is also a "sample" — track for sampled_avg/max
                s.sampleSum += rate
                s.sampleN++
                if rate > s.sampleMax {
                        s.sampleMax = rate
                }
        }

        var algs []int
        for a := range stats {
                algs = append(algs, a)
        }
        sort.Ints(algs)

        out := make([]interface{}, 0, len(algs))
        for _, a := range algs {
                s := stats[a]
                var provenMax, sampledAvg, sampledMax interface{}
                if s.provenMax > 0 {
                        provenMax = round1(float64(s.provenMax) / bpsToMbps)
                }
                if s.sampleN > 0 {
                        sampledAvg = round1(float64(s.sampleSum) / float64(s.sampleN))  // v0.9.25: already Mbps
                        sampledMax = round1(float64(s.sampleMax))  // v0.9.25: already Mbps
                }
                var samplesN interface{}
                if s.sampleN > 0 {
                        samplesN = s.sampleN
                }
                out = append(out, map[string]interface{}{
                        "alg":         algName(a),
                        "good":        s.good,
                        "proved":      s.proved,
                        "proven_max":  provenMax,
                        "sampled_avg": sampledAvg,
                        "sampled_max": sampledMax,
                        "samples":     samplesN,
                })
        }
        // Sort descending by proven_max
        sort.Slice(out, func(i, j int) bool {
                vi, _ := out[i].(map[string]interface{})["proven_max"].(float64)
                vj, _ := out[j].(map[string]interface{})["proven_max"].(float64)
                return vi > vj
        })
        return out
}

// buildDivergenceFromCSV reads the last N swaps from swaps.csv and
// computes mt_alg vs rb_alg divergence. Mirrors buildDivergenceFromParsed.
func buildDivergenceFromCSV(n int) []interface{} {
        rows := readSwapsCSVRows(n)
        if len(rows) == 0 {
                return []interface{}{}
        }

        type group struct {
                total    int
                diverges int
        }
        groups := map[string]*group{}

        for _, r := range rows {
                key := r.MtAlg + " → " + r.RbAlg
                g, ok := groups[key]
                if !ok {
                        g = &group{}
                        groups[key] = g
                }
                g.total++
                if r.Diverges {
                        g.diverges++
                }
        }

        var keys []string
        for k := range groups {
                keys = append(keys, k)
        }
        sort.Strings(keys)

        out := make([]interface{}, 0, len(keys))
        for _, k := range keys {
                g := groups[k]
                var pct float64
                if g.total > 0 {
                        pct = round1(float64(g.diverges) * 100.0 / float64(g.total))
                }
                out = append(out, map[string]interface{}{
                        "pair":      k,
                        "total":     g.total,
                        "diverges":  g.diverges,
                        "div_pct":   pct,
                })
        }
        return out
}

// buildChurnFromCSV reads the last N swaps from swaps.csv and computes
// from_alg → to_alg transition counts. Mirrors buildChurnFromParsed.
func buildChurnFromCSV(n int) map[string]interface{} {
        rows := readSwapsCSVRows(n)
        if len(rows) == 0 {
                return map[string]interface{}{
                        "total":     0,
                        "transitions": []interface{}{},
                }
        }

        transitions := map[string]int{}
        for _, r := range rows {
                key := r.FromAlg + " → " + r.ToAlg
                transitions[key]++
        }

        var keys []string
        for k := range transitions {
                keys = append(keys, k)
        }
        sort.Strings(keys)

        list := make([]interface{}, 0, len(keys))
        for _, k := range keys {
                list = append(list, map[string]interface{}{
                        "pair":  k,
                        "count": transitions[k],
                })
        }

        return map[string]interface{}{
                "total":       len(rows),
                "transitions": list,
        }
}

// algIndexFromName converts an algorithm name (e.g. "bbr") to its index
// in CONGS. Returns -1 if not found.
func algIndexFromName(name string) int {
        for i, c := range CONGS {
                if c == name {
                        return i
                }
        }
        return -1
}

// mergeProofsRaw merges log-derived and CSV-derived proof leaderboard data.
// For each algorithm, it sums the counts (good, proved, samples) and takes
// the max of proven_max and sampled_max. This gives a combined view that
// includes both the live log tail and the historical CSV data.
func mergeProofsRaw(logData, csvData []interface{}) []interface{} {
        type algStats struct {
                alg        string
                good       int
                proved     int
                provenMax  interface{}
                sampleSum  int64
                sampleN    int
                sampleMax  int64
        }
        merged := map[string]*algStats{}

        for _, source := range [][]interface{}{logData, csvData} {
                for _, item := range source {
                        row, ok := item.(map[string]interface{})
                        if !ok {
                                continue
                        }
                        alg, _ := row["alg"].(string)
                        if alg == "" {
                                continue
                        }
                        s, ok := merged[alg]
                        if !ok {
                                s = &algStats{alg: alg}
                                merged[alg] = s
                        }
                        s.good += toInt(row["good"])
                        s.proved += toInt(row["proved"])
                        if pm, ok := row["proven_max"].(float64); ok {
                                if pm > toFloat(s.provenMax) {
                                        s.provenMax = pm
                                }
                        }
                        if sa, ok := row["sampled_avg"].(float64); ok {
                                n := toInt(row["samples"])
                                if n > 0 {
                                        s.sampleSum += int64(sa * float64(n))
                                        s.sampleN += n
                                }
                        }
                        if sm, ok := row["sampled_max"].(float64); ok {
                                if int64(sm) > s.sampleMax {
                                        s.sampleMax = int64(sm)
                                }
                        }
                }
        }

        var algs []string
        for a := range merged {
                algs = append(algs, a)
        }
        sort.Strings(algs)

        out := make([]interface{}, 0, len(algs))
        for _, a := range algs {
                s := merged[a]
                var provenMax, sampledAvg, sampledMax interface{}
                if s.provenMax != nil {
                        provenMax = s.provenMax
                }
                if s.sampleN > 0 {
                        sampledAvg = round1(float64(s.sampleSum) / float64(s.sampleN))  // v0.9.25: already Mbps
                        sampledMax = round1(float64(s.sampleMax))  // v0.9.25: already Mbps
                }
                var samplesN interface{}
                if s.sampleN > 0 {
                        samplesN = s.sampleN
                }
                out = append(out, map[string]interface{}{
                        "alg":         s.alg,
                        "good":        s.good,
                        "proved":      s.proved,
                        "proven_max":  provenMax,
                        "sampled_avg": sampledAvg,
                        "sampled_max": sampledMax,
                        "samples":     samplesN,
                })
        }
        sort.Slice(out, func(i, j int) bool {
                vi, _ := out[i].(map[string]interface{})["proven_max"].(float64)
                vj, _ := out[j].(map[string]interface{})["proven_max"].(float64)
                return vi > vj
        })
        return out
}

// v0.9.9: lazy-load proofs.csv — cache the parsed result and only re-read
// when the file's mtime changes. Most cycles the file hasn't been written
// to yet (writes happen at the end of collect()).
var (
        proofsRawCache     []interface{}
        proofsRawCacheMtime int64
)

func buildProofsRawFromCSVCached() []interface{} {
        fi, err := os.Stat(proofsCSVPath)
        if err != nil {
                return []interface{}{}
        }
        mtime := fi.ModTime().Unix()
        if proofsRawCache != nil && mtime == proofsRawCacheMtime {
                return proofsRawCache
        }
        proofsRawCache = buildProofsRawFromCSV()
        proofsRawCacheMtime = mtime
        return proofsRawCache
}
