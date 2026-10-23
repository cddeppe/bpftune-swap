package main

// collect.go — the per-cycle collection pipeline.
//
// v0.7.0 fixes:
//   - Parse the log tail ONCE per cycle.
//   - Single source of truth for label resolution.
//   - Consistent CSV row keys across label changes.
//
// v0.9.108-lean: readLogTailCached + marshal-once + typed ring series.
// v0.9.109-lean2: bucket_live + metric_by_bucket restricted to selectable
// buckets (the set the frontend dropdown can contain).
// v0.9.110-lean3: FIXED the selectable filter (labelFor() clause was a
// no-op on real hosts — see buildSelectable below; measured 324/324 keys
// kept on al, 6.9MB current.json → 308KB after the fix).
// v0.9.111-lean4: the ring buffer now also honours the selectable set
// (was: every BPF-map host — 324 on al). See history.go.

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
// aborting the entire cycle (log panels still update).
func (c *Collector) collect() {
        cycleCount++  // v0.9.25: increment cycle counter (was never incremented — throttle was dead)
        now := time.Now().Unix()

        // v0.9.41: ensure cookie_dest map is loaded BEFORE readBPFMap()
        // so v6ToV4Label() can cross-reference v6 entries to v4 labels.
        ensureCookieDestLoaded()

        hosts, err := readBPFMap()
        if err != nil {
                fmt.Fprintf(os.Stderr, "collector: BPF map read failed (degraded mode): %v\n", err)
                hosts = nil // degraded mode — log panels still update
        }

        // ----- Parse log tail ONCE for the entire cycle ---------------------
        // v0.9.108: incremental tail cache — unchanged files are not
        // re-read and the assembled string is reused when nothing changed.
        logText := readLogTailCached(collectorMode.LogTailBytes)
        pl := parseLogSinglePass(logText)
        allSwaps := pl.Swaps
        allMets := pl.MetByCookie
        allSrates := pl.SrateByCookie
        cdest := persistCookieDest(pl.Cdest)

        // ----- Build live buckets + metric_by_bucket + bucket_live ---------
        buckets, metricByBucket, bucketLive, liveLeaders := buildLiveBuckets(hosts, now)

        // v0.9.36: build route health ONCE (uses the FULL metricByBucket —
        // route health is per-host and must not be filtered).
        routeHealth := buildRouteHealth(hosts, metricByBucket)

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
                "now_mono":         nowMono(pl.MaxTs),
                "route_health":     routeHealth,
                "service_health":   getServiceHealth(),
        }

        // ----- Log-derived panels (single parse, multiple consumers) --------
        currentParsedLog = pl
        defer func() { currentParsedLog = nil }()

        topSwaps, topProofs, swapOutcomes, bucketIPs, logWindow, proofsRaw := buildLogPanels(allSwaps, allMets, allSrates, cdest, logText, now)

        // v0.7.6: streak writeback — async to avoid blocking the 30s cycle.
        if cycleCount % 2 == 0 {
                go c.writebackStreaks(allSwaps, allMets, allSrates)
        }
        doc["recent_swaps"] = topSwaps
        doc["recent_proofs"] = topProofs
        doc["swap_outcomes"] = swapOutcomes
        doc["bucket_ips"] = bucketIPs
        doc["log_window"] = logWindow
        doc["proofs_raw"] = pl.GetProofsRawEvents(cdest)
        doc["proof"] = proofsRaw

        // ----- Other data panels (reuse parsed log results) ----------------
        churnResult := buildChurnFromParsed(allSwaps)
        if collectorMode.CSVFallback && len(allSwaps) < 50 {
                csvChurn := buildChurnFromCSV(200)
                csvTotal := toInt(csvChurn["total"])
                logTotal := toInt(churnResult["total"])
                if csvTotal > logTotal {
                        churnResult = csvChurn
                }
        }
        doc["churn"] = churnResult
        rateResult := pl.GetRate()
        if collectorMode.CSVFallback && len(rateResult) == 0 {
                csvRate := buildRateFromCSVCached()
                if len(csvRate) > 0 {
                        rateResult = csvRate
                }
        }
        doc["rate"] = rateResult
        doc["rate_raw"] = pl.GetRateRaw()
        doc["tunables"] = buildTunables()

        // ----- Ring capture + bucket_live ---------------------------------
        // v0.9.111: compute the selectable set BEFORE the ring capture so
        // the ring only holds entries the charts can display (top-8 +
        // labeled). Previously the ring held every BPF-map host (324 on
        // al) and saveToDisk marshaled all of it every 10 cycles (13MB
        // marshal + 13MB file every 5 min; profile #2 allocator).
        selectable := buildSelectable(buckets, loadLabels())
        ringSelectable = selectable
        captureSnapshotsFromBPF(hosts, now)

        // ----- Rebuild bucket_live from ring buffer (full 1h time series) --
        selHosts := make([]hostEntry, 0, len(hosts))
        for _, h := range hosts {
                if selectable[h.Addr] {
                        selHosts = append(selHosts, h)
                }
        }
        rebuildBucketLiveFromRing(bucketLive, selHosts, now)
        doc["metric_by_bucket"] = selectKeys(metricByBucket, selectable)
        doc["bucket_live"] = selectKeys(bucketLive, selectable)

        // ----- Write CSV + SQLite rows ------------------------------------
        // v0.9.9: throttle buckets.csv writes to every 2nd cycle.
        // v0.9.10: dual-write to SQLite (30s res) + CSV (60s res).
        csvN := collectorMode.CSVWriteEveryN
        if csvN <= 0 { csvN = 1 }
        doCSV := (cycleCount % csvN) == 0

        if doCSV {
                if sqliteDB != nil {
                        rmemMin, rmemDef, rmemMax := readTcpRmem()
                        for _, h := range hosts {
                                if h.Inst < 2 {
                                        continue
                                }
                                writeBucketSQLite(h, now, rmemMin, rmemDef, rmemMax)
                        }
                }
                if cycleCount%2 == 0 {
                        writeBucketsCSV(hosts, now)
                }
        }
        enrichSwapsForCSV(allSwaps, allMets, allSrates, cdest)
        if doCSV {
                writeSwapsCSV(allSwaps, now)
                writeSrateCSVFromParsed(allSrates, now)
                if len(pl.MidsampRows) > 0 {
                        midsampEvents := make([]midsampEvent, 0, len(pl.MidsampRows))
                        for _, mr := range pl.MidsampRows {
                                midsampEvents = append(midsampEvents, midsampEvent{
                                        Ts:     float64(now),
                                        Thr:    mr.Thr,
                                        Srate:  mr.Srate,
                                        Rport:  mr.Rport,
                                        Alg:    -1,
                                        Cookie: 0,
                                })
                        }
                        writeMidsampCSV(midsampEvents, now)
                }

                // v0.9.5: write proofs.csv for the recent-proofs panel fallback
                // v0.9.91: write ONLY the log-derived proofs to proofs.csv.
                var logProofs []interface{}
                if pl != nil {
                        logProofs = pl.GetProofRows(cdest)
                }
                writeProofsCSVFromInterface(logProofs, now)
        }

        // v0.9.7: one-time backfill from log tail on first collect cycle.
        backfillDone.Do(func() {
                backfillProofsFromLog(logText, cdest)
                backfillMidsampFromLog(logText)
        })

        // ----- Update current state + push to SSE --------------------------
        // v0.9.109: streaming hash-as-you-go writer (fallback: v0.9.108 path).
        c.mu.RLock()
        prevHashes := c.keyHashes
        c.mu.RUnlock()

        if cy, ok := writeCurrentJSONStream(doc, prevHashes); ok {
                c.mu.Lock()
                c.current = doc
                c.mu.Unlock()
                c.notifySSEFromCycle(cy)
        } else {
                docBytes, keyBytes := buildDocRaw(doc)
                c.mu.Lock()
                c.current = doc
                c.mu.Unlock()
                c.writeCurrentJSONFromRaw(docBytes)
                c.notifySSEFromRaw(keyBytes)
        }
}

// buildSelectable returns exactly the set of bucket keys the frontend
// dropdown can contain:
//   - the top-8 table buckets (meta.json bucket ids, doc.buckets "(live)")
//   - custom-labeled buckets (labels map VALUES)
//   - labels map KEYS (raw IPs — insurance for addrs not yet label-resolved)
//
// v0.9.110: the v0.9.109 `labelFor(addr) != ""` clause is REMOVED —
// labelFor() returns the canonical form for any IP-shaped addr, which
// made the filter a no-op on real hosts (324/324 keys kept on al).
func buildSelectable(buckets []bucketRow, labels map[string]string) map[string]bool {
        selectable := make(map[string]bool, 16)
        for _, b := range buckets {
                if b.Dest != "" {
                        selectable[b.Dest] = true
                }
        }
        for ip, lbl := range labels {
                if ip != "" {
                        selectable[ip] = true
                }
                if lbl != "" {
                        selectable[lbl] = true
                }
        }
        return selectable
}

// selectKeys returns a copy of m containing only the keys in keep.
func selectKeys(m map[string]interface{}, keep map[string]bool) map[string]interface{} {
        out := make(map[string]interface{}, len(keep))
        for k, v := range m {
                if keep[k] {
                        out[k] = v
                }
        }
        return out
}

// buildLiveBuckets constructs the buckets list (top 8),
// metric_by_bucket, bucket_live (single-point placeholder), and
// live_leaders. All in a single pass over sorted hosts.
//
// v0.7.5e: STABLE SORT to match meta.json's order (n_alg desc,
// inst desc, id asc).
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
        // Stable sort: n_alg desc, inst desc, id asc.
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

                // bucket_live (single-point placeholder; rebuilt from ring below).
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
// the full 1h time-series from the ring buffer.
// v0.9.108: typed series arrays instead of []interface{} boxing.
// v0.9.109/110: callers pass only the selectable hosts.
func rebuildBucketLiveFromRing(bucketLive map[string]interface{}, hosts []hostEntry, now int64) {
        cutoff := now - 3600
        for _, h := range hosts {
                addr := h.Addr
                hist.mu.RLock()
                rawSnaps := hist.raw[addr]
                var tsArr []int64
                var reArrs [16][]float64
                var ssArrs, bsArrs, nsArrs [16][]int16
                for _, s := range rawSnaps {
                        if s.Ts < cutoff {
                                continue
                        }
                        tsArr = append(tsArr, s.Ts)
                        for i := 0; i < 16; i++ {
                                reArrs[i] = append(reArrs[i], s.Re[i])
                                ssArrs[i] = append(ssArrs[i], s.Ss[i])
                                bsArrs[i] = append(bsArrs[i], s.Bs[i])
                                nsArrs[i] = append(nsArrs[i], s.Ns[i])
                        }
                }
                hist.mu.RUnlock()
                if len(tsArr) > 0 {
                        colsLive := make(map[string]interface{}, 64)
                        for i, alg := range CONGS {
                                colsLive["re_"+alg] = reArrs[i]
                                colsLive["ss_"+alg] = ssArrs[i]
                                colsLive["bs_"+alg] = bsArrs[i]
                                colsLive["ns_"+alg] = nsArrs[i]
                        }
                        bucketLive[addr] = map[string]interface{}{
                                "ts":   tsArr,
                                "cols": colsLive,
                        }
                }
        }
}
