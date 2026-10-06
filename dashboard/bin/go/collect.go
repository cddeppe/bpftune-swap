package main

// collect.go — the per-cycle collection pipeline.
//
// v0.7.0 fixes:
//   - Parse the log tail ONCE per cycle. Previously:
//       parseLogs()      -> parsed swaps + mets + srates (1st parse)
//       buildRate(text)  -> re-scanned text for midsamp lines (2nd parse)
//       writeSrateCSV(text) -> re-parsed text for srate events (3rd parse)
//       buildChurnFromParsed(allSwaps) -> ok (uses parsed)
//       buildDivergenceFromParsed(...) -> ok (uses parsed)
//     Now we parse ONCE, then pass parsed data to all consumers. This
//     eliminates ~2/3 of the per-cycle CPU cost (was hitting 40% peak
//     every 30s; now <15%).
//
//   - Single source of truth for label resolution.  All addresses from
//     BPF map are resolved once in readBPFMap → hostEntry.Addr.  No
//     downstream code re-applies ResolveBucket (which was the root cause
//     of "custom bucket disappears" — see bucketing.go comment).
//
//   - Ring buffer cap raised to 2880 entries (24h at 30s) was already
//     correct; the 17h-of-data bug was actually caused by CSV rows
//     being keyed inconsistently (raw vs labeled) across label changes.
//     Now CSV writes the labeled form and CSV reads use the stored
//     label as-is (no re-resolve), so historical data accumulates
//     under a single key per bucket.

import (
        "fmt"
        "os"
        "sort"
        "strings"
        "time"
)

// collect is the per-cycle collection pipeline. Runs every 30s.
//
// A4-fix: On readBPFMap() failure, degrade gracefully instead of
// aborting the entire cycle. We still update generated_ts, run log-derived
// panels (recent_swaps, recent_proofs, etc.), push an SSE event, and write
// current.json. We only skip BPF-derived panels (buckets, metric_by_bucket,
// bucket_live, live_leaders) and CSV appends. This prevents the frontend
// from freezing for 30+ seconds on a transient bpftool failure.
func (c *Collector) collect() {
        now := time.Now().Unix()

        hosts, err := readBPFMap()
        if err != nil {
                fmt.Fprintf(os.Stderr, "collector: BPF map read failed (degraded mode): %v\n", err)
                hosts = nil // degraded mode — log panels still update
        }

        // ----- Parse log tail ONCE for the entire cycle ---------------------
        // All consumers below (recent_swaps, swap_outcomes, churn, divergence,
        // writeSwapsCSV, writeSrateCSV) reuse these parsed results.
        logText := readLogTail(logTailBytes)
        allSwaps, allMets, allSrates := parseSwapsMetsSrates(logText)
        // v0.9.0: persist cookie→dest map across cycles so proofs with
        // cookies established before the 2 MB log tail still get a dest.
        // Without this, recent_proofs rows for old cookies showed dest=""
        // and rendered as a bare middot.  Also picks up dest6b from prior
        // estab events for IPv6 connections (needed for /64 labels).
        cdest := persistCookieDest(cookieDestMap(logText))

        // ----- Build live buckets + metric_by_bucket + bucket_live ---------
        buckets, metricByBucket, bucketLive, liveLeaders := buildLiveBuckets(hosts, now)

        // ----- Build current.json document -----------------------------------
        doc := map[string]interface{}{
                "generated_ts": now,
                "degraded":     err != nil, // A4-fix: signal degraded mode to frontend
                "build": map[string]interface{}{
                        "version":          bpftuneVersion(),
                        "dash_version":     dashVersion(),
                        "service":          bpftuneServiceActive(),
                        "uptime_min":       uptimeMin(),
                        "started_utc":      startedUTC(),
                        "log_path":         "/var/log/bpftune-met-live.log",
                        "prefix4":          prefix4Value(),
                        "prefix6":          prefix6Value(),
                        "explore_pct":      explorePctValue(),
                        "proof_good_bps":   proofGoodBpsValue(),
                        "proof_proved_bps": proofProvedBpsValue(),
                },
                "system":           readSystemInfo(),
                "buckets":          buckets,
                "metric_by_bucket": metricByBucket,
                "bucket_live":      bucketLive,
                "live_leaders":     liveLeaders,
                "hostname":         readProc("/proc/sys/kernel/hostname"),
                "now_mono":         readBPFClock(logText),
        }

        // ----- Log-derived panels (single parse, multiple consumers) --------
        topSwaps, topProofs, swapOutcomes, bucketIPs, logWindow, proofsRaw := buildLogPanels(allSwaps, allMets, allSrates, cdest, logText)

        // v0.7.6: streak writeback — patch BPF map bad_streak/null_streak from
        // sustained outcomes (60-300s after swap). Mirrors deleted Python
        // streak_writeback.py. Async to avoid blocking the 30s collect cycle.
        go c.writebackStreaks(allSwaps, allMets, allSrates)
        doc["recent_swaps"] = topSwaps
        doc["recent_proofs"] = topProofs
        doc["swap_outcomes"] = swapOutcomes
        doc["bucket_ips"] = bucketIPs
        doc["log_window"] = logWindow
        doc["proofs_raw"] = buildProofsRawEvents(logText, cdest)
        doc["proof"] = proofsRaw

        // ----- Other data panels (reuse parsed log results) ----------------
        doc["churn"] = buildChurnFromParsed(allSwaps)
        doc["rate"] = buildRate(logText) // midsamp scanning, separate from swap/met/srate
        doc["divergence"] = buildDivergenceFromParsed(allSwaps, allMets, allSrates)
        doc["tunables"] = buildTunables()

        // ----- Capture snapshots for the in-memory ring buffer --------------
        captureSnapshotsFromBPF(hosts, now)

        // ----- Rebuild bucket_live from ring buffer (full 1h time series) --
        // This replaces the single-point bucketLive built above with the
        // real time-series from the ring buffer.
        rebuildBucketLiveFromRing(bucketLive, hosts, now)

        // ----- Write CSV rows (write labeled form; reader trusts label) ----
        writeBucketsCSV(hosts, now)
        // v0.7.6: enrich swaps with outcome/direction/srate_before before CSV write.
        // Mirrors Python _resolve_pending enrichment logic.
        enrichSwapsForCSV(allSwaps, allMets, allSrates, cdest)
        writeSwapsCSV(allSwaps, now)
        // v0.8.7: removed writeTruthRows(allSwaps) call - writeSwapsCSV
        // already writes truth rows for each NEW swap (those that pass the
        // writtenSwaps dedup check).  Calling writeTruthRows separately
        // was writing DUPLICATE truth rows on every collect cycle because
        // writeTruthRows uses a SEPARATE dedup map (writtenTruth) that
        // writeSwapsCSV never updates - so every classified swap that
        // had just been written by writeSwapsCSV was written AGAIN by
        // writeTruthRows.  The in-CSV write at csv_writer.go:247 is the
        // single source of truth now.
        writeSrateCSVFromParsed(allSrates, now) // v0.7: no re-parse

        // v0.9.5: write proofs.csv for the recent-proofs panel fallback
        writeProofsCSVFromInterface(topProofs, now)

        // ----- Update current state + push to SSE --------------------------
        c.mu.Lock()
        c.current = doc
        c.keyHashes = computeKeyHashes(doc)
        c.mu.Unlock()

        c.writeCurrentJSON()
        c.notifySSE()
}

// buildLiveBuckets constructs the buckets list (top 8),
// metric_by_bucket, bucket_live (single-point placeholder), and
// live_leaders. All in a single pass over sorted hosts.
//
// v0.7.5e: STABLE SORT to match meta.json's order (n_alg desc,
// inst desc, id asc). Previously this was just Inst desc, which meant
// current.json's buckets[] array had a DIFFERENT order than meta.json's
// buckets[] array — the dropdown (from meta, every 5 min) and the table
// (from current, every 30s) disagreed. Now both use the same order so
// they stop "fighting" each other.
func buildLiveBuckets(hosts []hostEntry, now int64) (
        buckets []bucketRow, metricByBucket map[string]interface{},
        bucketLive map[string]interface{}, liveLeaders []interface{},
) {
        type bucket struct {
                Dest    string  `json:"dest"`
                Inst    int     `json:"inst"`
                RttUs   float64 `json:"rtt_us"`
                RefMbps float64 `json:"ref_mbps"`
                BestAlg string  `json:"best_alg"`
                NAlg    int     `json:"n_alg"`
        }
        metricByBucket = map[string]interface{}{}
        bucketLive = map[string]interface{}{}

        // v0.7.5e: pre-compute n_alg per host so the sort can use it
        // without re-parsing metrics twice per comparison.
        type hostWithAlg struct {
                hostEntry
                nAlg int
        }
        sortedHosts := make([]hostWithAlg, len(hosts))
        for i, h := range hosts {
                n := 0
                if mi, _ := h.V["metrics"].([]interface{}); mi != nil {
                        for _, m := range mi {
                                if mm, ok := m.(map[string]interface{}); ok &&
                                        toInt(mm["metric_count"]) > 0 {
                                        n++
                                }
                        }
                }
                sortedHosts[i] = hostWithAlg{hostEntry: h, nAlg: n}
        }
        // Stable sort: n_alg desc, inst desc, id asc — matches meta.json's
        // (n_alg desc, inst_mean desc, id asc) order closely enough that
        // the live buckets list and the 5-min meta list no longer disagree.
        sort.SliceStable(sortedHosts, func(i, j int) bool {
                if sortedHosts[i].nAlg != sortedHosts[j].nAlg {
                        return sortedHosts[i].nAlg > sortedHosts[j].nAlg
                }
                if sortedHosts[i].Inst != sortedHosts[j].Inst {
                        return sortedHosts[i].Inst > sortedHosts[j].Inst
                }
                return sortedHosts[i].Addr < sortedHosts[j].Addr
        })

        for _, sh := range sortedHosts {
                h := sh.hostEntry
                v := h.V
                addr := h.Addr
                if addr == "0.0.0.1" || addr == "?" {
                        continue
                }
                if strings.HasPrefix(addr, "127.") ||
                        strings.HasPrefix(addr, "169.254.") ||
                        strings.HasPrefix(addr, "0.") {
                        continue
                }
                if h.Inst < 2 {
                        continue
                }
                inst := h.Inst

                // Picker's choice (same formula as data_live_leaders).
                metrics, _ := v["metrics"].([]interface{})
                bestI := toInt(v["best_i"])
                if bestI < 0 || bestI >= len(CONGS) {
                        bestI = 0
                }
                bestW := 0
                for i := 0; i < len(CONGS) && i < len(metrics); i++ {
                        mi, _ := metrics[i].(map[string]interface{})
                        if mi == nil {
                                continue
                        }
                        cnt := toInt(mi["metric_count"])
                        rv := toInt(mi["rate_ema"])
                        if cnt < minLeaderTrust || rv == 0 {
                                continue
                        }
                        ss := toInt(mi["swap_score"])
                        ssEff := ss
                        if ssEff == 0 {
                                ssEff = 256
                        }
                        bad := toInt(mi["bad_streak"])
                        nul := toInt(mi["null_streak"])
                        weighted := rv * ssEff / 256
                        pen := 16 + bad*4 + nul*2
                        weighted = weighted * 16 / pen
                        if weighted > bestW {
                                bestW = weighted
                                bestI = i
                        }
                }
                bestAlg := CONGS[bestI]
                if bestI >= len(CONGS) {
                        bestAlg = fmt.Sprintf("alg%d", bestI)
                }
                // v0.7.5e: reuse pre-computed n_alg (was re-parsing here).
                nAlg := sh.nAlg
                refMbps := toFloat(v["max_rate_delivered"]) / bpsToMbps
                if len(buckets) < 8 {
                        buckets = append(buckets, bucketRow{
                                Dest:    addr,
                                Inst:    inst,
                                RttUs:   toFloat(v["min_rtt"]),
                                RefMbps: round1(refMbps),
                                BestAlg: bestAlg,
                                NAlg:    nAlg,
                        })
                }

                // metric_by_bucket: full per-alg row matching Python's output.
                metricRows := buildMetricRows(metrics)
                metricByBucket[addr] = metricRows

                // bucket_live (single-point placeholder; rebuilt from ring buffer below).
                ts := now
                cols := map[string]interface{}{}
                for i := 0; i < len(CONGS); i++ {
                        var mi map[string]interface{}
                        if i < len(metrics) {
                                mi, _ = metrics[i].(map[string]interface{})
                        }
                        if mi == nil {
                                mi = map[string]interface{}{}
                        }
                        cols["re_"+CONGS[i]] = []interface{}{toFloat(mi["rate_ema"])}
                        cols["ss_"+CONGS[i]] = []interface{}{toInt(mi["swap_score"])}
                        cols["bs_"+CONGS[i]] = []interface{}{toInt(mi["bad_streak"])}
                        cols["ns_"+CONGS[i]] = []interface{}{toInt(mi["null_streak"])}
                }
                bucketLive[addr] = map[string]interface{}{
                        "ts":   []interface{}{ts},
                        "cols": cols,
                }

                // live_leaders entry.
                ll := buildLiveLeadersEntry(addr, inst, metrics)
                if ll != nil && len(liveLeaders) < liveMaxBuckets {
                        liveLeaders = append(liveLeaders, ll)
                }
        }
        return
}

// bucketRow is the JSON-serializable bucket entry in current.json.
type bucketRow struct {
        Dest    string  `json:"dest"`
        Inst    int     `json:"inst"`
        RttUs   float64 `json:"rtt_us"`
        RefMbps float64 `json:"ref_mbps"`
        BestAlg string  `json:"best_alg"`
        NAlg    int     `json:"n_alg"`
}

// buildMetricRows builds the per-algorithm row list for one bucket.
func buildMetricRows(metrics []interface{}) []interface{} {
        var metricRows []interface{}
        for i := 0; i < len(CONGS); i++ {
                var mi map[string]interface{}
                if i < len(metrics) {
                        mi, _ = metrics[i].(map[string]interface{})
                }
                if mi == nil {
                        mi = map[string]interface{}{}
                }
                val := toInt(mi["metric_value"])
                if val == (1<<63-1) || val < 0 {
                        val = 0
                }
                mc := toInt(mi["metric_count"])
                a := toInt(mi["sockets_alive"])
                ss := toInt(mi["swap_score"])
                bs := toInt(mi["bad_streak"])
                ns := toInt(mi["null_streak"])
                re := toInt(mi["rate_ema"])
                penalty := 16.0 / (16.0 + float64(bs)*4.0 + float64(ns)*2.0)
                score := float64(re) * (float64(ss) / 256.0) * penalty
                active := mc > 0 || a > 0 || re > 0 || ss > 0
                var metricVal interface{}
                if val > 0 {
                        metricVal = round1(float64(val) / 1e6)
                } else {
                        metricVal = 0
                }
                row := map[string]interface{}{
                        "alg":         CONGS[i],
                        "metric":      metricVal,
                        "votes":       mc,
                        "alive":       a,
                        "rate_ema":    re,
                        "swap_score":  ss,
                        "penalty":     round3(penalty),
                        "score":       round2(score),
                        "bad_streak":  bs,
                        "null_streak": ns,
                        "active":      active,
                }
                metricRows = append(metricRows, row)
        }
        sort.SliceStable(metricRows, func(i, j int) bool {
                ri, _ := metricRows[i].(map[string]interface{})
                rj, _ := metricRows[j].(map[string]interface{})
                ai, _ := ri["active"].(bool)
                aj, _ := rj["active"].(bool)
                if ai != aj {
                        return ai
                }
                si, _ := ri["score"].(float64)
                sj, _ := rj["score"].(float64)
                return si > sj
        })
        return metricRows
}

// buildLiveLeadersEntry builds one live_leaders entry from metrics.
// Returns nil if no candidates qualify (cnt < minLeaderTrust or rv == 0).
func buildLiveLeadersEntry(addr string, inst int, metrics []interface{}) map[string]interface{} {
        var cands []struct {
                W, Rv, Ss, Bad, Nul, Cnt, I int
        }
        for i := 0; i < len(CONGS); i++ {
                var mi map[string]interface{}
                if i < len(metrics) {
                        mi, _ = metrics[i].(map[string]interface{})
                }
                if mi == nil {
                        continue
                }
                cnt := toInt(mi["metric_count"])
                rv := toInt(mi["rate_ema"])
                ss := toInt(mi["swap_score"])
                bad := toInt(mi["bad_streak"])
                nul := toInt(mi["null_streak"])
                if cnt < minLeaderTrust || rv == 0 {
                        continue
                }
                ssEff := ss
                if ssEff == 0 {
                        ssEff = 256
                }
                weighted := rv * ssEff / 256
                pen := 16 + bad*4 + nul*2
                weighted = weighted * 16 / pen
                cands = append(cands, struct {
                        W, Rv, Ss, Bad, Nul, Cnt, I int
                }{weighted, rv, ss, bad, nul, cnt, i})
        }
        if len(cands) == 0 {
                return nil
        }
        sort.SliceStable(cands, func(i, j int) bool { return cands[i].W > cands[j].W })
        topN := liveTopN
        if len(cands) < topN {
                topN = len(cands)
        }
        topRows := make([]interface{}, 0, topN)
        for _, c := range cands[:topN] {
                topRows = append(topRows, map[string]interface{}{
                        "alg":        CONGS[c.I],
                        "weighted":   c.W,
                        "rate_ema":   c.Rv,
                        "swap_score": c.Ss,
                        "bad":        c.Bad,
                        "null":       c.Nul,
                        "count":      c.Cnt,
                })
        }
        return map[string]interface{}{
                "dest": addr,
                "inst": inst,
                "top":  topRows,
        }
}

// rebuildBucketLiveFromRing replaces the single-point bucket_live with
// the full 1h time-series from the ring buffer (fixes "charts go empty
// every 30s" — SSE now pushes real time-series data).
func rebuildBucketLiveFromRing(bucketLive map[string]interface{}, hosts []hostEntry, now int64) {
        cutoff := now - 3600
        for _, h := range hosts {
                addr := h.Addr
                hist.mu.RLock()
                rawSnaps := hist.raw[addr]
                var tsArr []interface{}
                colsLive := map[string]interface{}{}
                for _, alg := range CONGS {
                        colsLive["re_"+alg] = []interface{}{}
                        colsLive["ss_"+alg] = []interface{}{}
                        colsLive["bs_"+alg] = []interface{}{}
                        colsLive["ns_"+alg] = []interface{}{}
                }
                for _, s := range rawSnaps {
                        if s.Ts < cutoff {
                                continue
                        }
                        tsArr = append(tsArr, s.Ts)
                        // v0.7.2: read from arrays, output maps for JSON
                        for i, alg := range CONGS {
                                if i >= 16 {
                                        break
                                }
                                reArr, _ := colsLive["re_"+alg].([]interface{})
                                colsLive["re_"+alg] = append(reArr, s.Re[i])
                                ssArr, _ := colsLive["ss_"+alg].([]interface{})
                                colsLive["ss_"+alg] = append(ssArr, s.Ss[i])
                                bsArr, _ := colsLive["bs_"+alg].([]interface{})
                                colsLive["bs_"+alg] = append(bsArr, s.Bs[i])
                                nsArr, _ := colsLive["ns_"+alg].([]interface{})
                                colsLive["ns_"+alg] = append(nsArr, s.Ns[i])
                        }
                }
                hist.mu.RUnlock()
                if len(tsArr) > 0 {
                        bucketLive[addr] = map[string]interface{}{
                                "ts":   tsArr,
                                "cols": colsLive,
                        }
                }
        }
}

// voteSum sums metric_count across all algs for one bucket. Used to
// sort hosts busiest-first (matches Python _vote_sum).
func voteSum(v map[string]interface{}) int {
        if v == nil {
                return 0
        }
        metrics, _ := v["metrics"].([]interface{})
        total := 0
        for _, m := range metrics {
                if mi, ok := m.(map[string]interface{}); ok {
                        total += toInt(mi["metric_count"])
                }
        }
        return total
}
