package main

// csv_reader.go — reads buckets.v2.csv for historical chart data.
//
// v0.7.3: NO persistent CSV cache.  The CSV is read fresh each time
// renderToDisk runs (every 5 min) and the result is freed after.
// This cuts memory by ~80MB (the old csvFullCache held 45K snapshots
// permanently + the 47MB CSV string during reads).
//
// For dynamic fallback (when static file is stale), readBucketCSV
// reads per-bucket from the CSV file.  This is slower (~50-100ms)
// but only happens when the 10-min static file cache expires, which
// is rare (renderToDisk regenerates every 5 min).

import (
        "bufio"
        "os"
        "sort"
        "strconv"
        "strings"
        "sync"
        "time"
)

// ============================================================================
// readCSVTail — reads only the last N bytes of the CSV (for 24h in fast mode)
// v0.7.4: reads ~8MB instead of 60MB.  7.5x less memory + CPU.
// ============================================================================

func readCSVTail(span int64) map[string][]bucketSnapshot {
        // v0.9.10: prefer SQLite when available — indexed queries are 10-100x
        // faster than scanning a 10MB+ CSV file.
        if sqliteDB != nil {
                if result := readBucketsAllFromSQLite(span); len(result) > 0 {
                        return result
                }
                // Fall through to CSV if SQLite returned nothing (e.g. before
                // migration completes or after a fresh DB with no data yet)
        }
        f, err := os.Open(bucketsCSVPath)
        if err != nil {
                return nil
        }
        defer f.Close()

        // Read header (first line)
        headerBytes, err := readHeader(f)
        if err != nil {
                return nil
        }
        header := strings.Split(strings.TrimSpace(headerBytes), ",")
        colIdx := map[string]int{}
        for i, col := range header {
                colIdx[col] = i
        }

        // Seek to tail — read last 8MB (covers ~24h of data for 104 buckets)
        fi, err := f.Stat()
        if err != nil {
                return nil
        }
        readSize := int64(20 * 1024 * 1024) // 8MB
        if readSize > fi.Size() {
                readSize = fi.Size()
        }
        _, err = f.Seek(fi.Size()-readSize, 0)
        if err != nil {
                return nil
        }
        data := make([]byte, readSize)
        _, err = f.Read(data)
        if err != nil {
                return nil
        }

        lines := strings.Split(string(data), "\n")
        // Skip first line (might be partial)
        if len(lines) > 1 {
                lines = lines[1:]
        }

        cutoff := time.Now().Unix() - span
        result := map[string][]bucketSnapshot{}
        for _, line := range lines {
                line = strings.TrimSpace(line)
                if line == "" {
                        continue
                }
                cols := strings.Split(line, ",")
                if len(cols) < 9 {
                        continue
                }
                addr := cols[1] // B1-fix: trust stored label, no ResolveBucket
                ts, err := strconv.ParseInt(cols[0], 10, 64)
                if err != nil || ts < cutoff {
                        continue
                }
                snap := bucketSnapshot{Ts: ts}
                snap.Instances, _ = strconv.Atoi(cols[2])
                snap.MinRtt, _ = strconv.ParseFloat(cols[3], 64)
                snap.RefRate, _ = strconv.ParseFloat(cols[4], 64)
                snap.BestI, _ = strconv.Atoi(cols[5])
                if snap.BestI >= 0 && snap.BestI < len(CONGS) {
                        snap.BestAlg = CONGS[snap.BestI]
                }
                for i, alg := range CONGS {
                        if i >= 16 {
                                break
                        }
                        if idx, ok := colIdx["mv_"+alg]; ok && idx < len(cols) && cols[idx] != "" {
                                snap.Mv[i], _ = strconv.ParseFloat(cols[idx], 64)
                        }
                        if idx, ok := colIdx["re_"+alg]; ok && idx < len(cols) && cols[idx] != "" {
                                snap.Re[i], _ = strconv.ParseFloat(cols[idx], 64)
                        }
                        if idx, ok := colIdx["ss_"+alg]; ok && idx < len(cols) && cols[idx] != "" {
                                v, _ := strconv.Atoi(cols[idx])
                                snap.Ss[i] = v
                        }
                        if idx, ok := colIdx["bs_"+alg]; ok && idx < len(cols) && cols[idx] != "" {
                                v, _ := strconv.Atoi(cols[idx])
                                snap.Bs[i] = v
                        }
                        if idx, ok := colIdx["ns_"+alg]; ok && idx < len(cols) && cols[idx] != "" {
                                v, _ := strconv.Atoi(cols[idx])
                                snap.Ns[i] = v
                        }
                }
                result[addr] = append(result[addr], snap)
        }
        return result
}

func readHeader(f *os.File) (string, error) {
        _, err := f.Seek(0, 0)
        if err != nil {
                return "", err
        }
        buf := make([]byte, 4096)
        n, err := f.Read(buf)
        if err != nil {
                return "", err
        }
        idx := strings.IndexByte(string(buf[:n]), '\n')
        if idx < 0 {
                return string(buf[:n]), nil
        }
        return string(buf[:idx]), nil
}

// ============================================================================
// readCSVAll — reads the entire CSV into a per-bucket map (NO CACHE)
// Called by renderToDisk every 5 min.  Result is freed after use.
// ============================================================================

var (
        csvReadCache   = map[string]cachedCSVRead{}
        csvReadCacheMu sync.Mutex
)

func readCSVAll() map[string][]bucketSnapshot {
        data, err := os.ReadFile(bucketsCSVPath)
        if err != nil {
                return nil
        }
        lines := strings.Split(string(data), "\n")
        if len(lines) < 2 {
                return nil
        }
        header := strings.Split(lines[0], ",")
        colIdx := map[string]int{}
        for i, col := range header {
                colIdx[col] = i
        }
        result := map[string][]bucketSnapshot{}
        for i := 1; i < len(lines); i++ {
                line := strings.TrimSpace(lines[i])
                if line == "" {
                        continue
                }
                cols := strings.Split(line, ",")
                if len(cols) < 9 {
                        continue
                }
                addr := cols[1] // B1-fix: trust stored label, no ResolveBucket
                ts, err := strconv.ParseInt(cols[0], 10, 64)
                if err != nil {
                        continue
                }
                snap := bucketSnapshot{Ts: ts}
                snap.Instances, _ = strconv.Atoi(cols[2])
                snap.MinRtt, _ = strconv.ParseFloat(cols[3], 64)
                snap.RefRate, _ = strconv.ParseFloat(cols[4], 64)
                snap.BestI, _ = strconv.Atoi(cols[5])
                if snap.BestI >= 0 && snap.BestI < len(CONGS) {
                        snap.BestAlg = CONGS[snap.BestI]
                }
                for i, alg := range CONGS {
                        if i >= 16 {
                                break
                        }
                        if idx, ok := colIdx["mv_"+alg]; ok && idx < len(cols) && cols[idx] != "" {
                                snap.Mv[i], _ = strconv.ParseFloat(cols[idx], 64)
                        }
                        if idx, ok := colIdx["re_"+alg]; ok && idx < len(cols) && cols[idx] != "" {
                                snap.Re[i], _ = strconv.ParseFloat(cols[idx], 64)
                        }
                        if idx, ok := colIdx["ss_"+alg]; ok && idx < len(cols) && cols[idx] != "" {
                                v, _ := strconv.Atoi(cols[idx])
                                snap.Ss[i] = v
                        }
                        if idx, ok := colIdx["bs_"+alg]; ok && idx < len(cols) && cols[idx] != "" {
                                v, _ := strconv.Atoi(cols[idx])
                                snap.Bs[i] = v
                        }
                        if idx, ok := colIdx["ns_"+alg]; ok && idx < len(cols) && cols[idx] != "" {
                                v, _ := strconv.Atoi(cols[idx])
                                snap.Ns[i] = v
                        }
                }
                result[addr] = append(result[addr], snap)
        }
        return result
}

// readBucketCSVFast returns snapshots for one bucket from a pre-loaded map.
// Used by renderToDisk (which calls readCSVAll once, then iterates).
func readBucketCSVFromMap(all map[string][]bucketSnapshot, bucketID string, span int64) []bucketSnapshot {
        snaps := all[bucketID]
        if span > 0 {
                cutoff := time.Now().Unix() - span
                var filtered []bucketSnapshot
                for _, s := range snaps {
                        if s.Ts >= cutoff {
                                filtered = append(filtered, s)
                        }
                }
                return filtered
        }
        return snaps
}

// readBucketCSV reads per-bucket from the CSV file directly (slow, ~50-100ms).
// Used by handleBucketJSON dynamic fallback (rare — only when static file stale).
func readBucketCSV(bucketID string, span int64) []bucketSnapshot {
        // v0.9.10: prefer SQLite when available
        if sqliteDB != nil {
                if result := readBucketsFromSQLite(bucketID, span); len(result) > 0 {
                        return result
                }
        }
        csvReadCacheMu.Lock()
        cacheKey := bucketID + ":" + strconv.FormatInt(span, 10)
        if cached, ok := csvReadCache[cacheKey]; ok && time.Since(cached.readAt) < 5*time.Minute {
                csvReadCacheMu.Unlock()
                return cached.data
        }
        csvReadCacheMu.Unlock()

        data, err := os.ReadFile(bucketsCSVPath)
        if err != nil {
                return nil
        }
        lines := strings.Split(string(data), "\n")
        if len(lines) < 2 {
                return nil
        }
        header := strings.Split(lines[0], ",")
        colIdx := map[string]int{}
        for i, col := range header {
                colIdx[col] = i
        }
        var cutoff int64
        if span > 0 {
                cutoff = time.Now().Unix() - span
        }
        var snaps []bucketSnapshot
        for i := 1; i < len(lines); i++ {
                line := strings.TrimSpace(lines[i])
                if line == "" {
                        continue
                }
                cols := strings.Split(line, ",")
                if len(cols) < 9 {
                        continue
                }
                addr := cols[1] // B1-fix: trust stored label, no ResolveBucket
                if addr != bucketID {
                        continue
                }
                ts, err := strconv.ParseInt(cols[0], 10, 64)
                if err != nil || (span > 0 && ts < cutoff) {
                        continue
                }
                snap := bucketSnapshot{Ts: ts}
                snap.Instances, _ = strconv.Atoi(cols[2])
                snap.MinRtt, _ = strconv.ParseFloat(cols[3], 64)
                snap.RefRate, _ = strconv.ParseFloat(cols[4], 64)
                snap.BestI, _ = strconv.Atoi(cols[5])
                if snap.BestI >= 0 && snap.BestI < len(CONGS) {
                        snap.BestAlg = CONGS[snap.BestI]
                }
                for i, alg := range CONGS {
                        if i >= 16 {
                                break
                        }
                        if idx, ok := colIdx["mv_"+alg]; ok && idx < len(cols) && cols[idx] != "" {
                                snap.Mv[i], _ = strconv.ParseFloat(cols[idx], 64)
                        }
                        if idx, ok := colIdx["re_"+alg]; ok && idx < len(cols) && cols[idx] != "" {
                                snap.Re[i], _ = strconv.ParseFloat(cols[idx], 64)
                        }
                        if idx, ok := colIdx["ss_"+alg]; ok && idx < len(cols) && cols[idx] != "" {
                                v, _ := strconv.Atoi(cols[idx])
                                snap.Ss[i] = v
                        }
                        if idx, ok := colIdx["bs_"+alg]; ok && idx < len(cols) && cols[idx] != "" {
                                v, _ := strconv.Atoi(cols[idx])
                                snap.Bs[i] = v
                        }
                        if idx, ok := colIdx["ns_"+alg]; ok && idx < len(cols) && cols[idx] != "" {
                                v, _ := strconv.Atoi(cols[idx])
                                snap.Ns[i] = v
                        }
                }
                snaps = append(snaps, snap)
        }
        csvReadCacheMu.Lock()
        csvReadCache[cacheKey] = cachedCSVRead{data: snaps, readAt: time.Now()}
        if len(csvReadCache) > 50 {
                for k := range csvReadCache {
                        delete(csvReadCache, k)
                        break
                }
        }
        csvReadCacheMu.Unlock()
        return snaps
}

// readBucketCSVFast is kept for backward compat (fleet handler).
// Calls readBucketCSV with a 5-min cache.
func readBucketCSVFast(bucketID string, span int64) []bucketSnapshot {
        return readBucketCSV(bucketID, span)
}

type cachedCSVRead struct {
        data   []bucketSnapshot
        readAt time.Time
}

// ============================================================================
// loadCSVTailIntoRingBuffer — read the last 1h of CSV into the ring buffer
// v0.7.3: only loads 1h (was 24h) since ring buffer is only 1h.
// ============================================================================

func loadCSVTailIntoRingBuffer() {
        defer func() {
                if r := recover(); r != nil {
                        os.Stderr.WriteString("loadCSVTailIntoRingBuffer PANICKED: " + toString(r) + "\n")
                }
        }()
        all := readCSVTail(3600)
        if all == nil {
                os.Stderr.WriteString("loadCSVTailIntoRingBuffer: readCSVAll returned nil\n")
                return
        }
        // v0.7.3: only load last 1h (ringCap * 30s = 1h)
        cutoff := time.Now().Unix() - int64(ringCap*30)
        count := 0
        for bucketID, snaps := range all {
                for _, s := range snaps {
                        if s.Ts < cutoff {
                                continue
                        }
                        hist.mu.Lock()
                        hist.raw[bucketID] = append(hist.raw[bucketID], s)
                        if len(hist.raw[bucketID]) > ringCap {
                                hist.raw[bucketID] = hist.raw[bucketID][len(hist.raw[bucketID])-ringCap:]
                        }
                        hist.mu.Unlock()
                        count++
                }
        }
        os.Stderr.WriteString("loadCSVTailIntoRingBuffer: loaded " + strconv.Itoa(count) +
                " entries for " + strconv.Itoa(len(all)) + " buckets\n")
}

// ============================================================================
// v0.7.5p: Streaming CSV reader — replaces readCSVAll for slow renders.
// Reads buckets.v2.csv line by line and accumulates running sums per bin
// (instead of loading all rows into memory as bucketSnapshot structs).
//
// Memory: O(buckets × ranges × bins) = ~3-5MB for 8 buckets × 3 ranges × ~120 bins
// (vs readCSVAll which uses O(total_rows × struct_size) = ~680MB for a 223MB CSV)
//
// Only processes "slow" ranges (7d, 30d, all). The 1h range comes from the
// ring buffer, and the 24h range comes from readCSVTail(86400) = 8MB.
//
// Returns: map[bucketID]map[rngName]series (same format as buildSeriesFromSnaps)
// ============================================================================

// binAcc accumulates running sums for one time bin across multiple snapshots.
type binAcc struct {
        ts    int64 // bin center timestamp
        count int   // number of snapshots accumulated
        sumRe [16]float64
        sumSs [16]int
        sumBs [16]int
        sumNs [16]int
        sumMv [16]float64
}

func streamCSVToSeries(bucketIDs []string) map[string]map[string]map[string]interface{} {
        // Determine which ranges to stream (only slow ranges — skip 1h and 24h)
        type rngCfg struct {
                span  int64 // 0 = unlimited
                width int64
        }
        slowRanges := map[string]rngCfg{}
        for rngName, rc := range ranges {
                if isFastRange(rngName) {
                        continue
                }
                span, _ := rc[0].(int)
                width, _ := rc[1].(int)
                if width == 0 {
                        width = 60
                }
                var span64 int64
                if span > 0 {
                        span64 = int64(span)
                }
                slowRanges[rngName] = rngCfg{span64, int64(width)}
        }

        if len(slowRanges) == 0 || len(bucketIDs) == 0 {
                return nil
        }

        // Build bucket set for fast lookup
        bucketSet := map[string]bool{}
        for _, id := range bucketIDs {
                bucketSet[id] = true
        }

        // Per-bucket, per-range, per-bin accumulators
        // bins[bucketID][rngName][binIdx] = *binAcc
        bins := map[string]map[string]map[int64]*binAcc{}
        for _, bid := range bucketIDs {
                bins[bid] = map[string]map[int64]*binAcc{}
                for rngName := range slowRanges {
                        bins[bid][rngName] = map[int64]*binAcc{}
                }
        }

        now := time.Now().Unix()

        f, err := os.Open(bucketsCSVPath)
        if err != nil {
                os.Stderr.WriteString("streamCSVToSeries: failed to open CSV: " + err.Error() + "\n")
                return nil
        }
        defer f.Close()

        scanner := bufio.NewScanner(f)
        scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

        // Read header to get column indices
        if !scanner.Scan() {
                return nil
        }
        header := strings.Split(strings.TrimSpace(scanner.Text()), ",")
        colIdx := map[string]int{}
        for i, col := range header {
                colIdx[col] = i
        }

        // Scan data lines — accumulate running sums per bin
        rowCount := 0
        for scanner.Scan() {
                line := strings.TrimSpace(scanner.Text())
                if line == "" {
                        continue
                }
                cols := strings.Split(line, ",")
                if len(cols) < 9 {
                        continue
                }

                ts, err := strconv.ParseInt(cols[0], 10, 64)
                if err != nil {
                        continue
                }

                addr := cols[1] // B1-fix: trust stored label, no ResolveBucket
                if !bucketSet[addr] {
                        continue
                }

                // Parse per-alg fields
                var re [16]float64
                var ss [16]int
                var bs [16]int
                var ns [16]int
                var mv [16]float64
                for i, alg := range CONGS {
                        if i >= 16 {
                                break
                        }
                        if idx, ok := colIdx["re_"+alg]; ok && idx < len(cols) && cols[idx] != "" {
                                {
                                        v, _ := strconv.ParseFloat(cols[idx], 64)
                                        if v > 10000000 {
                                                v = 0
                                        }
                                        re[i] = v
                                }
                        }
                        if idx, ok := colIdx["ss_"+alg]; ok && idx < len(cols) && cols[idx] != "" {
                                {
                                        v, _ := strconv.Atoi(cols[idx])
                                        if v > 1000 {
                                                v = 0
                                        }
                                        ss[i] = v
                                }
                        }
                        if idx, ok := colIdx["bs_"+alg]; ok && idx < len(cols) && cols[idx] != "" {
                                {
                                        v, _ := strconv.Atoi(cols[idx])
                                        if v > 1000 {
                                                v = 0
                                        }
                                        bs[i] = v
                                }
                        }
                        if idx, ok := colIdx["ns_"+alg]; ok && idx < len(cols) && cols[idx] != "" {
                                {
                                        v, _ := strconv.Atoi(cols[idx])
                                        if v > 1000 {
                                                v = 0
                                        }
                                        ns[i] = v
                                }
                        }
                        if idx, ok := colIdx["mv_"+alg]; ok && idx < len(cols) && cols[idx] != "" {
                                mv[i], _ = strconv.ParseFloat(cols[idx], 64)
                        }
                }

                // Add to bins for each slow range
                bucketBins, ok := bins[addr]
                if !ok {
                        continue
                }
                for rngName, cfg := range slowRanges {
                        if cfg.span > 0 && ts < now-cfg.span {
                                continue // outside the range window
                        }
                        binIdx := ts / cfg.width
                        rngBins := bucketBins[rngName]
                        b, exists := rngBins[binIdx]
                        if !exists {
                                b = &binAcc{ts: binIdx*cfg.width + cfg.width/2}
                                rngBins[binIdx] = b
                        }
                        b.count++
                        for i := 0; i < 16; i++ {
                                b.sumRe[i] += re[i]
                                b.sumSs[i] += ss[i]
                                b.sumBs[i] += bs[i]
                                b.sumNs[i] += ns[i]
                                b.sumMv[i] += mv[i]
                        }
                }
                rowCount++
        }

        // Finalize: compute averages from sums, produce series arrays
        result := map[string]map[string]map[string]interface{}{}
        for bid, rngBins := range bins {
                result[bid] = map[string]map[string]interface{}{}
                for rngName, binMap := range rngBins {
                        result[bid][rngName] = finalizeSeriesFromBins(binMap)
                }
        }

        os.Stderr.WriteString("streamCSVToSeries: processed " + strconv.Itoa(rowCount) +
                " rows for " + strconv.Itoa(len(bucketIDs)) + " buckets\n")

        return result
}

// finalizeSeriesFromBins converts a map of bin accumulators into the series
// format expected by the dashboard (same format as buildSeriesFromSnaps).
func finalizeSeriesFromBins(binMap map[int64]*binAcc) map[string]interface{} {
        // Sort bin indices
        var binIdxs []int64
        for bi := range binMap {
                binIdxs = append(binIdxs, bi)
        }
        sort.Slice(binIdxs, func(i, j int) bool { return binIdxs[i] < binIdxs[j] })

        series := map[string]interface{}{}
        tsArr := make([]int64, 0, len(binIdxs))
        arrs := map[string][]interface{}{}
        for _, alg := range CONGS {
                arrs["re_"+alg] = []interface{}{}
                arrs["ss_"+alg] = []interface{}{}
                arrs["bs_"+alg] = []interface{}{}
                arrs["ns_"+alg] = []interface{}{}
                arrs["mv_"+alg] = []interface{}{}
        }

        for _, bi := range binIdxs {
                b := binMap[bi]
                tsArr = append(tsArr, b.ts)
                n := b.count
                if n == 0 {
                        n = 1
                }
                for i, alg := range CONGS {
                        if i >= 16 {
                                break
                        }
                        arrs["re_"+alg] = append(arrs["re_"+alg], b.sumRe[i]/float64(n))
                        arrs["ss_"+alg] = append(arrs["ss_"+alg], b.sumSs[i]/n)
                        arrs["bs_"+alg] = append(arrs["bs_"+alg], b.sumBs[i]/n)
                        arrs["ns_"+alg] = append(arrs["ns_"+alg], b.sumNs[i]/n)
                        arrs["mv_"+alg] = append(arrs["mv_"+alg], b.sumMv[i]/float64(n))
                }
        }

        series["ts"] = tsArr
        for k, v := range arrs {
                series[k] = v
        }
        return series
}

// v0.7.5p: validateMetric clamps unreasonable values to 0.
// Prevents column-mismatch bugs (old Python rows have different column order).
func validateRe(v float64) float64 {
        if v > 10000000 {
                return 0
        }
        return v
}
func validateSs(v int) int {
        if v > 1000 {
                return 0
        }
        return v
}
func validateBs(v int) int {
        if v > 1000 {
                return 0
        }
        return v
}
func validateNs(v int) int {
        if v > 1000 {
                return 0
        }
        return v
}
