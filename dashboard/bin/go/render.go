package main

// render.go — pre-builds bucket_*.json, meta.json, swaps.json, fleet.json
// as static files on disk.  Runs every 5 min (like the Python renderer
// cron) plus immediately when labels.json changes.
//
// v0.7.0 fixes:
//   - meta.json: use buckets[].dest directly (already labeled by
//     readBPFMap).  Was previously re-applying labelFor which produced
//     inconsistent IDs ("v6:26061a40" instead of "controld") when the
//     label resolution chain produced different output between calls
//     (race condition with mtime-cached labels.json).
//   - Stable sort: tie-break by id (alphabetical) so the "top bucket
//     jumps between home-sco/controld" bug goes away.  When two
//     buckets have the same n_alg, the same inst_mean, the sort is
//     now deterministic.
//   - Static file invalidation: when labels.json mtime changes (user
//     added/removed a label), all /data/*.json files are deleted so
//     the next renderToDisk cycle regenerates them with fresh labels.
//     This fixes "custom bucket disappears" — a stale static meta.json
//     (10 min cache window) was being served instead of the freshly-
//     labeled dynamic response.
//   - sanitizedBucketID: replace ALL non-alphanumeric chars (including
//     dashes) with underscore, so "v6:26061a40" → "v6_26061a40" and
//     "home-sco" → "home_sco" and "controld" → "controld".  This makes
//     the static filename deterministic — was previously producing
//     different filenames for the same bucket depending on which code
//     path sanitized it.

import (
        "bufio"
        "encoding/json"
        "fmt"
        "os"
        "path/filepath"
        "sort"
        "strconv"
        "strings"
        "time"
)

// ============================================================================
// renderToDisk — entry point.  Called every 5 min + on labels change.
// ============================================================================

func (c *Collector) renderToDisk() {
        // v0.7.0: invalidate static files when labels.json changed.
        if StaticFilesAreDirty() {
                invalidateStaticFiles()
                ClearStaticFilesDirty()
        }

        c.mu.RLock()
        buckets := c.current["buckets"]
        swapOutcomes := c.current["swap_outcomes"]
        c.mu.RUnlock()

        bucketMaps := bucketsAsMaps(buckets)
        if len(bucketMaps) == 0 {
                return
        }

        // v0.7.4: renderToDisk is always fast — read only CSV tail (~8MB, 24h).
        // renderSlowToDisk reads the full CSV (for 7d+30d+all, daily at 4am).
        hist.csvAll = readCSVTail(86400)     // last 24h only — 8MB not 60MB
        defer func() { hist.csvAll = nil }() // free after rendering

        // Write meta.json
        hist.renderMetaToDisk(bucketMaps)

        // Write swaps.json
        if _, ok := swapOutcomes.(map[string]interface{}); ok {
                renderSwapsFromCSV(time.Now().Unix())
        }

        // Write fleet.json
        hist.renderFleetToDisk(bucketMaps)

        // v0.7.4: fast=true — only 1h+24h, preserve slow ranges from existing file
        hist.renderBucketsToDisk(bucketMaps, swapOutcomes, true)
}

// renderSlowToDisk generates the 7d + all series (runs once a day).
// v0.7.3: these ranges barely change in 5 min, so no need to regenerate
// them every 5 min.  Runs on startup + once a day.
//
// v0.9.5: MERGE not REPLACE. Previously this function read the full CSV
// and overwrote bucket_*.json with ALL ranges (1h+24h+7d+30d+all).  If
// the CSV was trimmed (e.g. by csv_rotate or manual cleanup), the 30d/all
// ranges would lose data because the trimmed CSV doesn't have enough
// history.  Now we PRESERVE existing 30d/all series and only update
// 1h+24h+7d from the CSV.
func (c *Collector) renderSlowToDisk() {
        // v0.7.9: rotate CSVs daily to prevent endless growth
        rotateAllCSVs()

        c.mu.RLock()
        buckets := c.current["buckets"]
        swapOutcomes := c.current["swap_outcomes"]
        c.mu.RUnlock()

        bucketMaps := bucketsAsMaps(buckets)
        if len(bucketMaps) == 0 {
                return
        }

        // v0.7.5p: stream CSV directly into binned series (low memory).
        // Memory: ~3-5MB instead of ~680MB for a 223MB CSV.
        bucketIDs := make([]string, 0, len(bucketMaps))
        for _, b := range bucketMaps {
                id, _ := b["dest"].(string)
                if id != "" {
                        bucketIDs = append(bucketIDs, id)
                }
        }

        hist.mu.Lock()
        hist.streamedSeries = streamCSVToSeries(bucketIDs)
        hist.mu.Unlock()

        defer func() {
                hist.mu.Lock()
                hist.streamedSeries = nil
                hist.mu.Unlock()
        }()

        // v0.9.5: MERGE not REPLACE.  Read the existing bucket_*.json
        // file first, preserve its 30d/all series, then update only
        // 1h+24h+7d from the (possibly trimmed) CSV.
        hist.renderBucketsToDiskPreserving(bucketMaps, swapOutcomes, false)

        os.Stderr.WriteString("renderSlowToDisk: regenerated 7d (preserved 30d+all) for " +
                toString(len(bucketMaps)) + " buckets (streamed)\n")
}

// invalidateStaticFiles deletes all /data/*.json so the next renderToDisk
// cycle regenerates them with fresh labels.  Called when labels.json
// mtime changes.
func invalidateStaticFiles() {
        dataDir := filepath.Join(histDir, "data")
        entries, err := os.ReadDir(dataDir)
        if err != nil {
                return
        }
        for _, e := range entries {
                if e.IsDir() {
                        continue
                }
                if !strings.HasSuffix(e.Name(), ".json") {
                        continue
                }
                _ = os.Remove(filepath.Join(dataDir, e.Name()))
        }
        os.Stderr.WriteString("invalidateStaticFiles: cleared /data/*.json (labels.json changed)\n")
}

// ============================================================================
// renderMetaToDisk — writes meta.json
//
// v0.7.0: uses buckets[].dest directly (already labeled).  Does NOT
// re-apply labelFor.  Sort is now stable with id as final tie-breaker.
// ============================================================================

func (h *historyStore) renderMetaToDisk(buckets []map[string]interface{}) {
        h.mu.RLock()
        defer h.mu.RUnlock()

        type entry struct {
                id, label string
                instMean  float64
                lastTs    int64
                nAlg      int
        }
        var entries []entry
        for _, b := range buckets {
                // v0.7.0: id is already labeled (from readBPFMap → hostEntry.Addr).
                // Do NOT re-apply labelFor here — that was the meta.json bug.
                id, _ := b["dest"].(string)
                if id == "" {
                        // Some code paths may have set "id" instead of "dest".
                        // Handle both for safety, but don't re-resolve.
                        id, _ = b["id"].(string)
                }
                if id == "" {
                        continue
                }
                inst := toInt(b["inst"])
                var instSum int
                var instCount int
                var lastTs int64
                if raw, ok := h.raw[id]; ok {
                        for _, s := range raw {
                                instSum += s.Instances
                                instCount++
                                if s.Ts > lastTs {
                                        lastTs = s.Ts
                                }
                        }
                }
                var im float64
                if instCount > 0 {
                        im = float64(instSum) / float64(instCount)
                } else {
                        im = float64(inst)
                }
                nAlg := toInt(b["n_alg"])
                entries = append(entries, entry{id, id, im, lastTs, nAlg})
        }
        // v0.7.0: STABLE SORT — sort by (n_alg desc, inst_mean desc, id asc).
        // The id tie-breaker is the fix for "top bucket jumps between home-sco
        // and controld" — previously two buckets with the same n_alg + inst_mean
        // could swap positions between renders, causing the default_bucket
        // field to flip-flop in meta.json.
        sort.Slice(entries, func(i, j int) bool {
                if entries[i].nAlg != entries[j].nAlg {
                        return entries[i].nAlg > entries[j].nAlg
                }
                if entries[i].instMean != entries[j].instMean {
                        return entries[i].instMean > entries[j].instMean
                }
                return entries[i].id < entries[j].id
        })

        bucketEntries := make([]interface{}, 0, len(entries))
        for _, e := range entries {
                bucketEntries = append(bucketEntries, map[string]interface{}{
                        "id":             e.id,
                        "label":          e.id,
                        "points":         len(h.raw[e.id]),
                        "instances_mean": e.instMean,
                        "last_ts":        e.lastTs,
                })
        }
        defaultBucket := "all"
        if len(entries) > 0 {
                defaultBucket = entries[0].id
        }
        doc := map[string]interface{}{
                "generated_ts":   time.Now().Unix(),
                "ranges":         []string{"1h", "24h", "7d", "30d", "all"},
                "algs":           sortedAlgs(),
                "buckets":        bucketEntries,
                "default_bucket": defaultBucket,
                "has_tcp_rmem":   false,
        }
        writeJSONToDisk("meta.json", doc)
}

// ============================================================================
// renderSwapsToDisk — writes swaps.json (per-range binned)
// ============================================================================

func (h *historyStore) renderSwapsToDisk(so map[string]interface{}) {
        sl, _ := so["swaps_list"].([]interface{})
        if len(sl) == 0 {
                writeJSONToDisk("swaps.json", map[string]interface{}{})
                return
        }
        uptime := readProcUptime()
        nowEpoch := float64(time.Now().Unix())
        doc := map[string]interface{}{}
        for rngName, rngCfg := range ranges {
                span, _ := rngCfg[0].(int)
                width, _ := rngCfg[1].(int)
                if width == 0 {
                        width = 60
                }
                var cutoff float64
                if span > 0 {
                        cutoff = nowEpoch - float64(span)
                }
                binCounts := map[int64]int{}
                for _, s := range sl {
                        sm, ok := s.(map[string]interface{})
                        if !ok {
                                continue
                        }
                        ts, ok := sm["ts"].(float64)
                        if !ok {
                                continue
                        }
                        epochTs := nowEpoch - uptime + ts
                        if span > 0 && epochTs < cutoff {
                                continue
                        }
                        binIdx := int64(epochTs / float64(width))
                        binCounts[binIdx]++
                }
                var binIdxs []int64
                for bi := range binCounts {
                        binIdxs = append(binIdxs, bi)
                }
                sort.Slice(binIdxs, func(i, j int) bool { return binIdxs[i] < binIdxs[j] })
                swapsArr := make([]interface{}, len(binIdxs))
                tsArr := make([]interface{}, len(binIdxs))
                for i, bi := range binIdxs {
                        swapsArr[i] = binCounts[bi]
                        tsArr[i] = bi*int64(width) + int64(width)/2
                }
                doc[rngName] = map[string]interface{}{
                        "ts":    tsArr,
                        "swaps": swapsArr,
                }
        }
        writeJSONToDisk("swaps.json", doc)
}

// ============================================================================
// renderFleetToDisk — writes fleet.json (top 25 by 24h coverage)
// ============================================================================

func (h *historyStore) renderFleetToDisk(buckets []map[string]interface{}) {
        type pair struct {
                bid string
                cov float64
        }
        var pairs []pair

        // v0.7.5f: fleet diagnostics — log CSV state once per render.
        csvAllNil := h.csvAll == nil
        csvAllLen := 0
        if !csvAllNil {
                csvAllLen = len(h.csvAll)
        }
        os.Stderr.WriteString("fleet-diag: csvAll=" + boolStr(csvAllNil) +
                " csvAllBuckets=" + itoa(csvAllLen) +
                " liveBuckets=" + itoa(len(buckets)) + "\n")
        for _, b := range buckets {
                id, _ := b["dest"].(string)
                if id == "" {
                        continue
                }
                // v0.7.3: use pre-loaded CSV map (from renderToDisk) instead of
                // reading the full CSV per-bucket.  Falls back to per-bucket read.
                var snaps []bucketSnapshot
                if h.csvAll != nil {
                        snaps = readBucketCSVFromMap(h.csvAll, id, 86400)
                } else {
                        snaps = readBucketCSV(id, 86400)
                }
                if len(snaps) == 0 {
                        os.Stderr.WriteString("fleet-diag: bucket=" + id + " snaps=0 (skipped)\n")
                        continue
                }
                var have, seen int
                for _, s := range snaps {
                        seen++
                        if s.RefRate > 0 {
                                have++
                        }
                }
                if seen == 0 {
                        continue
                }
                pairs = append(pairs, pair{id, round1(float64(have) * 100.0 / float64(seen))})
        }
        // Stable sort: cov desc, id asc (deterministic).
        sort.Slice(pairs, func(i, j int) bool {
                if pairs[i].cov != pairs[j].cov {
                        return pairs[i].cov > pairs[j].cov
                }
                return pairs[i].bid < pairs[j].bid
        })
        if len(pairs) > 25 {
                pairs = pairs[:25]
        }
        labels := make([]string, len(pairs))
        cov := make([]float64, len(pairs))
        for i, p := range pairs {
                labels[i] = p.bid
                cov[i] = p.cov
        }
        writeJSONToDisk("fleet.json", map[string]interface{}{
                "buckets":      labels,
                "coverage_24h": cov,
        })
}

// ============================================================================
// renderBucketsToDisk — writes bucket_<id>.json for each bucket
// ============================================================================

func (h *historyStore) renderBucketsToDisk(buckets []map[string]interface{}, swapOutcomes interface{}, fast bool) {
        for _, b := range buckets {
                id, _ := b["dest"].(string)
                if id == "" {
                        continue
                }
                safe := sanitizeBucketID(id)
                h.renderBucketToDisk(id, safe, swapOutcomes, fast)
        }
}

// v0.7.3: fast=true means only update 1h+24h (preserve 7d+all from existing file).
// fast=false means regenerate ALL ranges (used by daily 4am renderSlowToDisk).
func (h *historyStore) renderBucketToDisk(bucketID, safe string, swapOutcomes interface{}, fast bool) {
        h.mu.RLock()
        defer h.mu.RUnlock()

        doc := map[string]interface{}{"id": bucketID, "series": map[string]interface{}{}}

        // v0.7.4: in fast mode, PRESERVE slow ranges (7d, 30d, all) from existing file.
        // Only 1h+24h are regenerated; slow ranges come from the daily 4am render.
        if fast {
                path := filepath.Join(histDir, "data", "bucket_"+safe+".json")
                if data, err := os.ReadFile(path); err == nil {
                        var existing map[string]interface{}
                        if err := json.Unmarshal(data, &existing); err == nil {
                                if series, ok := existing["series"].(map[string]interface{}); ok {
                                        for _, rng := range []string{"7d", "30d", "all"} {
                                                if s, ok := series[rng]; ok {
                                                        doc["series"].(map[string]interface{})[rng] = s
                                                }
                                        }
                                }
                                if last, ok := existing["last"]; ok {
                                        doc["last"] = last
                                }
                        }
                }
        }

        for rngName, rngCfg := range ranges {
                span, _ := rngCfg[0].(int)
                width, _ := rngCfg[1].(int)
                if width == 0 {
                        width = 60
                }

                // v0.7.4: in fast mode, only generate fast ranges (1h, 24h).
                // Slow ranges (7d, 30d, all) are preserved from existing file.
                if fast && !isFastRange(rngName) {
                        continue
                }

                // v0.7.5p: for slow ranges, use pre-built streamed series if available
                var series map[string]interface{}
                if h.streamedSeries != nil && !isFastRange(rngName) {
                        if bucketSeries, ok := h.streamedSeries[bucketID]; ok {
                                if rngSeries, ok := bucketSeries[rngName]; ok {
                                        series = rngSeries
                                }
                        }
                }

                var snaps []bucketSnapshot
                if series == nil {
                        switch rngName {
                        case "1h":
                                snaps = h.raw[bucketID]
                                if span > 0 {
                                        cutoff := time.Now().Unix() - int64(span)
                                        var filtered []bucketSnapshot
                                        for _, s := range snaps {
                                                if s.Ts >= cutoff {
                                                        filtered = append(filtered, s)
                                                }
                                        }
                                        snaps = filtered
                                }
                        case "24h", "7d", "30d", "all":
                                if h.csvAll != nil {
                                        snaps = readBucketCSVFromMap(h.csvAll, bucketID, int64(span))
                                } else {
                                        snaps = readBucketCSV(bucketID, int64(span))
                                }
                        }
                        series = buildSeriesFromSnaps(snaps, width)
                }
                bs := map[int64]bool{}
                for _, sn := range snaps {
                        bs[sn.Ts/int64(width)] = true
                }
                var bis []int64
                for bi := range bs {
                        bis = append(bis, bi)
                }
                sort.Slice(bis, func(i, j int) bool { return bis[i] < bis[j] })
                sa := make([]interface{}, len(bis))
                bc := map[int64]int{}
                if f, e := os.Open(swapsCSVPath); e == nil {
                        sc := bufio.NewScanner(f)
                        sc.Buffer(make([]byte, 1<<20), 8<<20) // D2-fix: 8MB cap
                        sc.Scan()
                        for sc.Scan() {
                                c := strings.Split(sc.Text(), ",")
                                if len(c) < 13 {
                                        continue
                                }
                                if c[11] != bucketID { // B1-fix: trust stored label
                                        continue
                                }
                                st, _ := strconv.ParseInt(c[0], 10, 64)
                                bc[st/int64(width)]++
                        }
                        // D2-fix: log scanner errors instead of silently truncating.
                        if err := sc.Err(); err != nil {
                                fmt.Fprintf(os.Stderr, "render.go: swaps.csv scan error: %v\n", err)
                        }
                        f.Close()
                }
                for i, bi := range bis {
                        sa[i] = bc[bi]
                }
                series["swaps"] = sa
                doc["series"].(map[string]interface{})[rngName] = series
        }

        if raw := h.raw[bucketID]; len(raw) > 0 {
                last := raw[len(raw)-1]
                // v0.7.2: build map from arrays for JSON output
                reMap := map[string]interface{}{}
                for i, alg := range CONGS {
                        if i >= 16 {
                                break
                        }
                        if last.Re[i] != 0 {
                                reMap[alg] = last.Re[i]
                        }
                }
                doc["last"] = map[string]interface{}{
                        "collected_ts": last.Ts,
                        "best_alg":     last.BestAlg,
                        "best_i":       last.BestI,
                        "instances":    last.Instances,
                        "ref_rate":     last.RefRate,
                        "min_rtt":      last.MinRtt,
                        "rate_best_i":  last.RateBestI,
                        "rate_best_v":  last.RateBestV,
                        "tcp_rmem_max": last.TcpRmemMax,
                        "re":           reMap,
                }
        }

        writeJSONToDisk("bucket_"+safe+".json", doc)
}

// v0.9.5: renderBucketsToDiskPreserving — like renderBucketsToDisk but
// PRESERVES existing 30d+all series from the existing bucket_*.json file.
// Only regenerates 1h+24h+7d.  This prevents data loss when the CSV has
// been trimmed (e.g. by csv_rotate or manual cleanup) — the 30d/all
// charts keep their existing historical data instead of being overwritten
// with a shorter series from the trimmed CSV.
func (h *historyStore) renderBucketsToDiskPreserving(buckets []map[string]interface{}, swapOutcomes interface{}, fast bool) {
        for _, b := range buckets {
                id, _ := b["dest"].(string)
                if id == "" {
                        continue
                }
                safe := sanitizeBucketID(id)
                h.renderBucketToDiskPreserving(id, safe, swapOutcomes)
        }
}

// renderBucketToDiskPreserving — renders 1h+24h+7d from CSV/ring buffer,
// but PRESERVES 30d+all from the existing bucket_*.json file.
func (h *historyStore) renderBucketToDiskPreserving(bucketID, safe string, swapOutcomes interface{}) {
        h.mu.RLock()
        defer h.mu.RUnlock()

        doc := map[string]interface{}{"id": bucketID, "series": map[string]interface{}{}}

        // PRESERVE 30d + all from existing file
        path := filepath.Join(histDir, "data", "bucket_"+safe+".json")
        if data, err := os.ReadFile(path); err == nil {
                var existing map[string]interface{}
                if err := json.Unmarshal(data, &existing); err == nil {
                        if series, ok := existing["series"].(map[string]interface{}); ok {
                                for _, rng := range []string{"30d", "all"} {
                                        if s, ok := series[rng]; ok {
                                                doc["series"].(map[string]interface{})[rng] = s
                                        }
                                }
                        }
                        if last, ok := existing["last"]; ok {
                                doc["last"] = last
                        }
                }
        }

        // Regenerate 1h, 24h, 7d
        for rngName, rngCfg := range ranges {
                span, _ := rngCfg[0].(int)
                width, _ := rngCfg[1].(int)
                if width == 0 {
                        width = 60
                }

                // Only generate 1h, 24h, 7d — skip 30d, all (preserved above)
                if rngName == "30d" || rngName == "all" {
                        continue
                }

                // v0.7.5p: for slow ranges (7d), use pre-built streamed series
                var series map[string]interface{}
                if h.streamedSeries != nil && !isFastRange(rngName) {
                        if bucketSeries, ok := h.streamedSeries[bucketID]; ok {
                                if rngSeries, ok := bucketSeries[rngName]; ok {
                                        series = rngSeries
                                }
                        }
                }

                var snaps []bucketSnapshot
                if series == nil {
                        switch rngName {
                        case "1h":
                                snaps = h.raw[bucketID]
                                if span > 0 {
                                        cutoff := time.Now().Unix() - int64(span)
                                        var filtered []bucketSnapshot
                                        for _, s := range snaps {
                                                if s.Ts >= cutoff {
                                                        filtered = append(filtered, s)
                                                }
                                        }
                                        snaps = filtered
                                }
                        case "24h", "7d":
                                if h.csvAll != nil {
                                        snaps = readBucketCSVFromMap(h.csvAll, bucketID, int64(span))
                                } else {
                                        snaps = readBucketCSV(bucketID, int64(span))
                                }
                        }
                        series = buildSeriesFromSnaps(snaps, width)
                }
                bs := map[int64]bool{}
                for _, sn := range snaps {
                        bs[sn.Ts/int64(width)] = true
                }
                var bis []int64
                for bi := range bs {
                        bis = append(bis, bi)
                }
                sort.Slice(bis, func(i, j int) bool { return bis[i] < bis[j] })
                sa := make([]interface{}, len(bis))
                bc := map[int64]int{}
                if f, e := os.Open(swapsCSVPath); e == nil {
                        sc := bufio.NewScanner(f)
                        sc.Buffer(make([]byte, 1<<20), 8<<20) // D2-fix: 8MB cap
                        sc.Scan()
                        for sc.Scan() {
                                c := strings.Split(sc.Text(), ",")
                                if len(c) < 13 {
                                        continue
                                }
                                if c[11] != bucketID { // B1-fix: trust stored label
                                        continue
                                }
                                st, _ := strconv.ParseInt(c[0], 10, 64)
                                bc[st/int64(width)]++
                        }
                        // D2-fix: log scanner errors instead of silently truncating.
                        if err := sc.Err(); err != nil {
                                fmt.Fprintf(os.Stderr, "render.go: swaps.csv scan error: %v\n", err)
                        }
                        f.Close()
                }
                for i, bi := range bis {
                        sa[i] = bc[bi]
                }
                series["swaps"] = sa
                doc["series"].(map[string]interface{})[rngName] = series
        }

        if raw := h.raw[bucketID]; len(raw) > 0 {
                last := raw[len(raw)-1]
                reMap := map[string]interface{}{}
                for i, alg := range CONGS {
                        if i >= 16 {
                                break
                        }
                        if last.Re[i] != 0 {
                                reMap[alg] = last.Re[i]
                        }
                }
                doc["last"] = map[string]interface{}{
                        "collected_ts": last.Ts,
                        "best_alg":     last.BestAlg,
                        "best_i":       last.BestI,
                        "instances":    last.Instances,
                        "ref_rate":     last.RefRate,
                        "min_rtt":      last.MinRtt,
                        "rate_best_i":  last.RateBestI,
                        "rate_best_v":  last.RateBestV,
                        "tcp_rmem_max": last.TcpRmemMax,
                        "re":           reMap,
                }
        }

        writeJSONToDisk("bucket_"+safe+".json", doc)
}

// ============================================================================
// Helpers
// ============================================================================

// sanitizeBucketID converts a bucket ID to a filesystem-safe filename
// component.  ALL non-alphanumeric chars (including dashes and colons)
// become underscores.  This makes the static filename deterministic
// regardless of which code path produced the bucket ID.
//
// Examples:
//
//      "home-sco"        → "home_sco"
//      "v6:26061a40"     → "v6_26061a40"
//      "2606:1a40::"     → "2606_1a40__"   (was inconsistent before)
//      "controld"        → "controld"
//      "1.2.3.4"         → "1_2_3_4"
func sanitizeBucketID(id string) string {
        var b strings.Builder
        for _, c := range id {
                if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' {
                        b.WriteRune(c)
                } else {
                        b.WriteByte('_')
                }
        }
        return b.String()
}

// buildSeriesFromSnaps bins snapshots into `width`-second bins and
// produces the time-series arrays for one range.
func buildSeriesFromSnaps(snaps []bucketSnapshot, width int) map[string]interface{} {
        type bin struct {
                ts    int64
                snaps []bucketSnapshot
        }
        binMap := map[int64]*bin{}
        for _, s := range snaps {
                bi := s.Ts / int64(width)
                if b, ok := binMap[bi]; ok {
                        b.snaps = append(b.snaps, s)
                } else {
                        binMap[bi] = &bin{ts: bi*int64(width) + int64(width)/2, snaps: []bucketSnapshot{s}}
                }
        }
        var binIdxs []int64
        for bi := range binMap {
                binIdxs = append(binIdxs, bi)
        }
        sort.Slice(binIdxs, func(i, j int) bool { return binIdxs[i] < binIdxs[j] })

        series := map[string]interface{}{"ts": []int64{}}
        for _, alg := range CONGS {
                series["re_"+alg] = []interface{}{}
                series["ss_"+alg] = []interface{}{}
                series["bs_"+alg] = []interface{}{}
                series["ns_"+alg] = []interface{}{}
                series["mv_"+alg] = []interface{}{}
                series["score_"+alg] = []interface{}{}
        }
        tsArr := make([]int64, 0, len(binIdxs))
        arrs := map[string][]interface{}{}
        for _, alg := range CONGS {
                arrs["re_"+alg] = []interface{}{}
                arrs["ss_"+alg] = []interface{}{}
                arrs["bs_"+alg] = []interface{}{}
                arrs["ns_"+alg] = []interface{}{}
                arrs["mv_"+alg] = []interface{}{}
                arrs["score_"+alg] = []interface{}{}
        }
        for _, bi := range binIdxs {
                b := binMap[bi]
                tsArr = append(tsArr, b.ts)
                avg := aggregateSnapshots(b.snaps)
                // v0.7.2: read from arrays, output maps for JSON
                for i, alg := range CONGS {
                        if i >= 16 {
                                break
                        }
                        arrs["re_"+alg] = append(arrs["re_"+alg], avg.Re[i])
                        arrs["ss_"+alg] = append(arrs["ss_"+alg], avg.Ss[i])
                        arrs["bs_"+alg] = append(arrs["bs_"+alg], avg.Bs[i])
                        arrs["ns_"+alg] = append(arrs["ns_"+alg], avg.Ns[i])
                        arrs["mv_"+alg] = append(arrs["mv_"+alg], avg.Mv[i])
                        _p := 16.0 / (16.0 + float64(avg.Bs[i])*4.0 + float64(avg.Ns[i])*2.0)
                        _sc := float64(avg.Re[i]) * (float64(avg.Ss[i]) / 256.0) * _p
                        arrs["score_"+alg] = append(arrs["score_"+alg], round2(_sc))
                }
        }
        series["ts"] = tsArr
        series["_tsLen"] = len(tsArr)
        for k, v := range arrs {
                series[k] = v
        }
        return series
}

// writeJSONToDisk writes a JSON file to /var/lib/bpftune/history/data/<name>
// atomically (write to .tmp, then rename).
func writeJSONToDisk(name string, doc interface{}) {
        data, _ := json.Marshal(doc)
        path := filepath.Join(histDir, "data", name)
        _ = os.MkdirAll(filepath.Join(histDir, "data"), 0755)
        tmp := path + ".tmp"
        _ = os.WriteFile(tmp, data, 0644)
        _ = os.Rename(tmp, path)
}

// countSwapsPerBin counts swap events per time bin for a specific bucket.
func countSwapsPerBin(swapOutcomes interface{}, bucketID string, width int, span int) []interface{} {
        so, ok := swapOutcomes.(map[string]interface{})
        if !ok {
                return []interface{}{}
        }
        sl, _ := so["swaps_list"].([]interface{})
        if !ok {
                _ = sl
                return []interface{}{}
        }
        now := time.Now().Unix()
        uptime := readProcUptime()
        nowEpoch := float64(now)
        var cutoff int64
        if span > 0 {
                cutoff = now - int64(span)
        }
        binCounts := map[int64]int{}
        for _, s := range sl {
                sm, ok := s.(map[string]interface{})
                if !ok {
                        continue
                }
                dest, _ := sm["dest"].(string)
                if dest != bucketID {
                        continue
                }
                ts, ok := sm["ts"].(float64)
                if !ok {
                        continue
                }
                epochTs := nowEpoch - uptime + ts
                tsInt := int64(epochTs)
                if span > 0 && tsInt < cutoff {
                        continue
                }
                binIdx := tsInt / int64(width)
                binCounts[binIdx]++
        }
        var binIdxs []int64
        for bi := range binCounts {
                binIdxs = append(binIdxs, bi)
        }
        sort.Slice(binIdxs, func(i, j int) bool { return binIdxs[i] < binIdxs[j] })
        result := make([]interface{}, len(binIdxs))
        for i, bi := range binIdxs {
                result[i] = binCounts[bi]
        }
        return result
}

// ============================================================================
// sortedAlgs returns CONGS in alphabetical order (matches Python renderer).
// ============================================================================

func sortedAlgs() []string {
        out := make([]string, len(CONGS))
        copy(out, CONGS)
        sort.Strings(out)
        return out
}

// ============================================================================
// bucketsAsMaps converts the buckets list (from collect()) to
// []map[string]interface{} for the HTTP/render handlers.
// ============================================================================

func bucketsAsMaps(buckets interface{}) []map[string]interface{} {
        if buckets == nil {
                return nil
        }
        data, err := jsonMarshal(buckets)
        if err != nil {
                return nil
        }
        var out []map[string]interface{}
        if err := jsonUnmarshal(data, &out); err != nil {
                return nil
        }
        return out
}

// ============================================================================
// File helpers (avoid importing encoding/json + os everywhere)
// ============================================================================

func historyPath(name string) string {
        return filepath.Join(histDir, name)
}

func readFile(path string) ([]byte, error) {
        return os.ReadFile(path)
}

func writeFileAtomic(path string, build func() []byte) {
        tmp := path + ".tmp"
        _ = os.WriteFile(tmp, build(), 0644)
        _ = os.Rename(tmp, path)
}

func jsonMarshal(v interface{}) ([]byte, error) {
        return json.Marshal(v)
}

func jsonUnmarshal(data []byte, v interface{}) error {
        return json.Unmarshal(data, v)
}

// toString forces import of strconv for loadCSVTailIntoRingBuffer's panic message
var _ = strconv.Itoa

// v0.7.5f: helpers for fleet diagnostics logging.
func boolStr(b bool) string {
        if b {
                return "nil"
        }
        return "set"
}

func itoa(n int) string {
        return strconv.Itoa(n)
}
