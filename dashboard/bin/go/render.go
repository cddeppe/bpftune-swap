package main

// render.go — static file rendering (replaces Python renderer + SQLite)
//
// v0.7.0 refactor: extracted from main.go. Writes JSON files to histDir:
//   - bucket_{ID}.json  (series: {ts: [...], re_/ss_/bs_/ns_: {...}})
//   - meta.json         (config + bucket list with labels)
//   - swaps.json        (all swap rows for the swaps table)
//   - fleet.json        (top buckets for the fleet view)
//
// Replaces the Python renderer and SQLite. All outputs are byte-compatible
// with the Python-era files (see README for the history JSON spec).
//
// v0.7.1: renderMetaToDisk / renderFleetToDisk — labels come from
//         readAliases() + cached labelPrefix, not from the per-cycle
//         labels.json file.  The file is only written (fresh) by
//         handleLabels POST.
// v0.7.2: renderMetaToDisk adds ringsize to bucket entries.
// v0.7.3: renderSwapsFromCSV — swap scatter uses "bucket" field (matches
//         Python). "bucket_ref" is the masked-ref-peak, not the first byte
//         of the IP.
// v0.7.4: 7d range — writeJSONToDisk writes bucket_7d.json with 24h
//         data (same as Python).  Python's range loop only writes 24h
//         JSONs (range not passed to writeJSONToDisk) — fixed.
// v0.7.5: 5-file split — bucket_1h.json/24h.json (every 5 min, fast),
//         bucket_7d.json/all.json (daily, slow), meta.json+swaps.json+
//         fleet.json (every 5 min, fast).
// v0.7.6: renderSwapsFromCSV uses bucketJSONPath(s) — no hardcoded range
//         list.  renderSwapsFromCSV/bucketJSONPath/sliceOfMap use toFloat.
// v0.9.90: renderToDisk's 24h read (readCSVTail) now runs ONCE per cycle
//         and is shared across all bucket renders (was: 8x per cycle on
//         al — 25MB of CSV scanned per cycle).
// v0.9.119: scanSwapCSVLines — swaps.csv is scanned ONCE per cycle.
//         Previously renderBucketToDisk re-opened and re-scanned the
//         entire swaps.csv once per BUCKET (8 scans/cycle) and
//         renderSwapsFromCSV scanned it a 9th time.  That 5-minute I/O
//         burst pegged iowait on memory-tight hosts (100% CPU graphs
//         with 69% io).  Consumers parse each line with their own
//         unchanged code — all rendered output is byte-identical.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Static file write rate-limit (v0.7.5: 10min was too slow for 5min data
// updates — 10min writes meant data was stale 50% of the time).
var (
	lastStaticWriteTime time.Time
	staticFilesDirtyMu  sync.Mutex
	staticFilesDirty    bool // set true on label change (handleLabels POST)
)

// writeJSONToDisk writes a value as pretty-printed JSON (matching Python).
func writeJSONToDisk(name string, v interface{}) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "render: marshal %s: %v\n", name, err)
		return
	}
	// Write atomically: .tmp then rename
	path := filepath.Join(histDir, name)
	if err := os.WriteFile(path+".tmp", data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "render: write %s: %v\n", name, err)
		return
	}
	os.Rename(path+".tmp", path)
}

// bucketJSONPath returns the path to a bucket's series JSON file.
// v0.7.5: range-specific (bucket_1h.json, bucket_24h.json, etc).
func bucketJSONPath(bucketID string, rng string) string {
	safe := strings.Replace(bucketID, ":", "_", -1)
	return filepath.Join(histDir, fmt.Sprintf("bucket_%s_%s.json", safe, rng))
}

// bucketDest returns the bucket's dest field (the labeled or masked addr).
func bucketDest(bm map[string]interface{}) string {
	if s, ok := bm["dest"].(string); ok {
		return s
	}
	return ""
}

// renderMetaToDisk writes meta.json (config + buckets + labels).
// Labels come from readAliases() + cached labelPrefix — NOT from the
// per-cycle labels.json (v0.7.1 fix; handleLabels POST writes fresh).
// v0.7.2: each bucket includes ringsize (len(h.raw[bucketID]), 1h count).
func renderMetaToDisk(bucketMaps []map[string]interface{}) {
	// --- labels: readAliases + cached labelPrefix (NOT the file) ---
	aliases := readAliases()
	labelPrefix := getCachedLabelPrefix()

	// v0.7.2: ringsize per bucket
	hist.mu.RLock()
	ringSize := map[string]int{}
	for _, bm := range bucketMaps {
		id := bucketDest(bm)
		ringSize[id] = len(hist.raw[id])
	}
	hist.mu.RUnlock()

	// --- labels: write fresh labels.json (preserve aliases file semantics) ---
	// The write path is handleLabels POST; we do NOT rewrite here.
	// --- meta buckets ---
	buckets := make([]map[string]interface{}, 0, len(bucketMaps))
	for _, bm := range bucketMaps {
		id := bucketDest(bm)
		label := labelPrefix[id]
		if label == "" {
			label = labelPrefix[id]
		}
		inst := toInt(bm["inst"])
		// v0.9.104: renames map instances -> inst so meta.json
		// uses "inst" throughout (same as bucket_{id}.json).
		nAlg := toInt(bm["n_alg"])
		bestAlg, _ := bm["best_alg"].(string)
		entry := map[string]interface{}{
			"id": id, "label": label, "inst": inst,
			"best_alg": bestAlg, "n_alg": nAlg,
			// v0.7.2: ring buffer entry count for this bucket
			"points": ringSize[id],
		}
		buckets = append(buckets, entry)
	}
	meta := map[string]interface{}{
		"generated_ts": time.Now().Unix(),
		"ranges":      []string{"1h", "24h", "7d", "all"},
		"algs":        CONGS,
		"buckets":     buckets,
		"default_bucket": firstOrDefault(buckets, "id"),
		"default_range":  "24h",
		"aliases":        aliases,
	}
	writeJSONToDisk("meta.json", meta)
}

// renderFleetToDisk writes fleet.json (top buckets + coverage).
// Coverage = count of unique 5-min bins in the last 24h per bucket.
// v0.7.1: labels from readAliases + cached labelPrefix (not the file).
// v0.9.90: reads the shared 24h table when the caller already loaded it
// (hist.csvAll set by renderToDisk) — was a second full 24h scan per cycle.
func renderFleetToDisk(bucketMaps []map[string]interface{}) {
	aliases := readAliases()
	labelPrefix := getCachedLabelPrefix()

	// Read 24h of data for coverage calc
	// v0.9.90: shared read — renderToDisk already loaded hist.csvAll for
	// the bucket renders in this same cycle; reuse it instead of scanning
	// the 24h table again.  (readCSVTail / readBucketsAllFromSQLite is
	// the single most expensive call in the render path.)
	hist.mu.RLock()
	csvgrep := hist.csvAll
	hist.mu.RUnlock()
	if csvgrep == nil {
		csvgrep = readCSVTail(86400)
	}

	type bktCov struct {
		id      string
		inst    int
		nAlg    int
		bestAlg string
		label   string
		bins    map[int64]bool
	}

	byID := map[string]*bktCov{}
	for _, bm := range bucketMaps {
		id := bucketDest(bm)
		label := labelPrefix[id]
		if label == "" {
			label = labelPrefix[id]
		}
		byID[id] = &bktCov{
			id:      id,
			inst:    toInt(bm["inst"]),
			nAlg:    toInt(bm["n_alg"]),
			bestAlg: strOrEmpty(bm["best_alg"]),
			label:   label,
			bins:    map[int64]bool{},
		}
	}

	// Count unique 5-min bins in the last 24h per bucket
	cutoff := time.Now().Unix() - 86400
	for bucketID, snaps := range csvgrep {
		b := byID[bucketID]
		if b == nil {
			continue
		}
		for _, snap := range snaps {
			if snap.Ts < cutoff {
				continue
			}
			bin := snap.Ts / 300
			b.bins[bin] = true
		}
	}

	// v0.7.4: 7d coverage = same as 24h (Python parity).
	// Python counted 24h unique bins for BOTH coverage_24h and
	// coverage_7d. We match that.
	type fleetBkt struct {
		id      string `json:"id"`
		label   string `json:"label"`
		inst    int    `json:"inst"`
		nAlg    int    `json:"n_alg"`
		bestAlg string `json:"best_alg"`
		cov24   float64 `json:"coverage_24h"`
		cov7d   float64 `json:"coverage_7d"`
	}

	fleet := make([]fleetBkt, 0, len(byID))
	for _, b := range byID {
		cov := len(b.bins) / 288.0 // 288 bins in 24h at 5min
		fleet = append(fleet, fleetBkt{
			id: b.id, label: b.label, inst: b.inst,
			nAlg: b.nAlg, bestAlg: b.bestAlg,
			cov24: cov, cov7d: cov,
		})
	}
	sort.Slice(fleet, func(i, j int) bool {
		return fleet[i].cov24 > fleet[j].cov24
	})

	fleetOut := map[string]interface{}{
		"generated_ts": time.Now().Unix(),
		"buckets":      fleet,
	}
	writeJSONToDisk("fleet.json", fleetOut)
}

// renderBucketToDisk writes bucket_{ID}.json for one bucket.
// bucketMaps is passed in from renderToDisk; we use only the matching entry.
// v0.7.4: 7d writes bucket_7d.json with 24h data (same as Python — Python
// also writes 24h JSONs for all ranges).
// v0.7.5: called from renderToDisk (1h+24h, fast) and renderSlowToDisk
// (7d+all, slow).
// v0.9.90: swapRows shared — the entire swaps.csv scan runs ONCE per
// cycle in renderToDisk; this function filters the shared rows (was:
// re-opened + re-scanned the whole swaps.csv per bucket — 8x/cycle).
func renderBucketToDisk(bm map[string]interface{}, swapRows []map[string]interface{}) {
	bucketID := bucketDest(bm)
	if bucketID == "" {
		return
	}

	// Per-range: pick data + filename
	// v0.7.5: each range gets its own file (1h/24h fast, 7d/all slow)
	type rngSpec struct {
		rng    string
		span   int64
		maxAge time.Duration
	}
	ranges := []rngSpec{
		{"1h", 3600, 0},       // 1h data, no age limit
		{"24h", 86400, 0},     // 24h data
		{"7d", 7 * 86400, 0},  // 7d data
		{"all", 90 * 86400, 0}, // all-time
	}

	// v0.7.5: we don't re-render if the file is fresh enough
	// (handled by renderToDisk's 5min throttle)

	for _, rs := range ranges {
		var snapshots []bucketSnapshot
		switch {
		case rs.rng == "1h":
			snapshots = readBucketsFromSQLite(bucketID, rs.span)
		case rs.rng == "24h" || rs.rng == "7d" || rs.rng == "all":
			// v0.7.5: all ranges use readBucketCSV (CSV is the source of truth
			// for 7d/all since the ring only holds 1h).
			snapshots = readBucketCSVFromMap(hist.csvAll, bucketID)
			if len(snapshots) == 0 {
				snapshots = readBucketCSV(bucketID, rs.span)
			}
		}
		if len(snapshots) == 0 {
			continue
		}

		// Bucket metadata
		inst := toInt(bm["inst"])
		bestAlg, _ := bm["best_alg"].(string)
		nAlg := toInt(bm["n_alg"])
		minRtt := toFloat(bm["rtt_us"])
		refMbps := toFloat(bm["ref_mbps"])

		// Build swap rows (x=ts, y=rate) for scatter overlay
		// v0.9.90: iterate the shared per-cycle scan; the per-row parsing
		// and bucket filter are byte-identical to the old per-bucket scan.
		for _, line := range swapRows {
			fields := parseCSVLine(line)
			if len(fields) < 7 {
				continue
			}
			ts, _ := strconv.ParseFloat(fields[0], 64)
			cookie, _ := strconv.ParseUint(fields[1], 10, 64)
			from, _ := strconv.Atoi(fields[2])
			to, _ := strconv.Atoi(fields[3])
			d, _ := strconv.Atoi(fields[4])
			rate, _ := strconv.ParseFloat(fields[5], 64)
			dur, _ := strconv.ParseFloat(fields[6], 64)
			row := map[string]interface{}{
				"ts":     ts,
				"cookie": fmt.Sprintf("%d", cookie),
				"from":   from,
				"to":     to,
				"d":      d,
				"rate":   rate,
				"dur":    dur,
				"dest":   "", "dest6": "", "dest6b": "",
			}
			if len(fields) > 7 {
				row["dest"] = fields[7]
			}
			if len(fields) > 8 {
				row["dest6"] = fields[8]
			}
			if len(fields) > 9 {
				row["dest6b"] = fields[9]
			}
			// Only include swaps that belong to this bucket
			if maskedIP(swapDestToIP(row)) != bucketID {
				continue
			}
			swapScatter = append(swapScatter, row)
		}

		// Build output JSON (matches Python write_bucket_json)
		out := buildBucketJSON(bucketID, inst, bestAlg, nAlg, minRtt, refMbps, snapshots, swapScatter, rs.rng)

		// Write file (atomic: .tmp then rename)
		path := bucketJSONPath(bucketID, rs.rng)
		if err := os.WriteFile(path+".tmp", out, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "render: write bucket %s: %v\n", bucketID, err)
			continue
		}
		os.Rename(path+".tmp", path)
	}
}

// buildBucketJSON builds the bucket_{ID}.json output for one range.
// Output shape (matches Python):
//   {
//     "generated_ts": ..., "id": ..., "range": ..., "label": ...,
//     "algs": [...],
//     "meta": {"inst":..., "best_alg":..., "n_alg":..., "min_rtt":...,
//              "ref_mbps":..., "ref_n":...},
//     "series": {"ts":[...], "re_":{...}, "ss_":{...}, "bs_":{...}, "ns_":{...}, "mv_":{...}},
//     "swaps": [...], "proven": [...],
//     "swap_outcomes": {...}, "churn": {...}
//   }
func buildBucketJSON(
	bucketID string,
	inst int,
	bestAlg string,
	nAlg int,
	minRtt float64,
	refMbps float64,
	snapshots []bucketSnapshot,
	swapScatter []map[string]interface{},
	rng string,
) []byte {
	// labelPrefix (cached; not the file)
	labelPrefix := getCachedLabelPrefix()
	label := labelPrefix[bucketID]
	if label == "" {
		label = labelPrefix[bucketID]
	}

	// --- meta ---
	refN := 0
	for _, snap := range snapshots {
		if snap.RefRate > 0 {
			refN++
		}
	}
	meta := map[string]interface{}{
		"inst":         inst,
		"best_alg":     bestAlg,
		"n_alg":        nAlg,
		"min_rtt":      minRtt,
		"ref_mbps":     refMbps,
		"ref_n":        refN,
		"tcp_rmem_min": 0,
		"tcp_rmem_def": 0,
		"tcp_rmem_max": 0,
	}
	// v0.7.3: last snapshot's rmem fields override meta if present
	if n := len(snapshots); n > 0 {
		last := snapshots[n-1]
		// tcp_rmem_* are not in bucketSnapshot — they come from
		// writeBucketJSON's caller via writeBucketsCSV.  For the JSON
		// file we use 0 (Python parity).
		_ = last
	}

	// --- series ---
	tsArr := make([]float64, len(snapshots))
	reSeries := map[string][]interface{}{}
	ssSeries := map[string][]interface{}{}
	bsSeries := map[string][]interface{}{}
	nsSeries := map[string][]interface{}{}
	mvSeries := map[string][]interface{}{}
	for _, alg := range CONGS {
		reSeries[alg] = make([]interface{}, len(snapshots))
		ssSeries[alg] = make([]interface{}, len(snapshots))
		bsSeries[alg] = make([]interface{}, len(snapshots))
		nsSeries[alg] = make([]interface{}, len(snapshots))
		mvSeries[alg] = make([]interface{}, len(snapshots))
	}
	for i, snap := range snapshots {
		tsArr[i] = float64(snap.Ts)
		// snap.Re / Ss / Bs / Ns / Mv are []interface{} of 16 values
		re := float64SliceFromAny(snap.Re)
		ss := float64SliceFromAny(snap.Ss)
		bs := float64SliceFromAny(snap.Bs)
		ns := float64SliceFromAny(snap.Ns)
		mv := float64SliceFromAny(snap.Mv)
		for j, alg := range CONGS {
			reSeries[alg][i] = re[j]
			ssSeries[alg][i] = ss[j]
			bsSeries[alg][i] = bs[j]
			nsSeries[alg][i] = ns[j]
			mvSeries[alg][i] = mv[j]
		}
	}
	series := map[string]interface{}{
		"ts": tsArr,
		"re_": reSeries,
		"ss_": ssSeries,
		"bs_": bsSeries,
		"ns_": nsSeries,
		"mv_": mvSeries,
	}

	// --- swaps scatter (filter to this bucket) ---
	swaps := make([]map[string]interface{}, 0)
	for _, row := range swapScatter {
		// bucketIsMasked=true if bucketID is the masked (not labeled) form
		maskedHost := maskedIP(swapDestToIP(row))
		if maskedHost != bucketID {
			continue
		}
		// bucket_is_masked: true when bucketID is the raw masked addr
		bucketIsMasked := true
		if labelPrefix[bucketID] != "" {
			bucketIsMasked = false
		}
		// v0.7.3: bucket_ref = masked-ref-peak (bucket 24h ref rate)
		row["bucket"] = bucketID
		row["bucket_is_masked"] = bucketIsMasked
		row["mbps"] = toFloat(row["rate"]) / 1e6
		row["dur_ago_min"] = toFloat(row["dur"]) / 60.0
		row["bucket_ref"] = refMbps
		row["bucket_ref_mbps"] = refMbps
		row["bucket_ref_available"] = refMbps > 0
		swaps = append(swaps, row)
	}

	// --- proven scatter (swaps where rate > bucket ref) ---
	proven := make([]map[string]interface{}, 0)
	for _, row := range swaps {
		if toFloat(row["rate"]) > refMbps*1e6 && refMbps > 0 {
			prov := make(map[string]interface{}, len(row))
			for k, v := range row {
				prov[k] = v
			}
			prov["proven"] = true
			proven = append(proven, prov)
		}
	}

	// --- swap_outcomes (win/null/loss) ---
	// v0.7.4: composite = rate > 1.25*ref (win), < 0.75*ref (loss), else null
	win, null, loss := 0, 0, 0
	for _, row := range swaps {
		rate := toFloat(row["rate"])
		ref := refMbps * 1e6
		if ref > 0 {
			switch {
			case rate > ref*1.25:
				win++
			case rate < ref*0.75:
				loss++
			default:
				null++
			}
		}
	}
	swapOutcomes := map[string]interface{}{
		"win":  win,
		"null": null,
		"loss": loss,
	}

	// --- churn ---
	churn := map[string]interface{}{
		"cookies": 0, "one": 0, "mid": 0, "many": 0, "max": 0,
		"transitions": []interface{}{},
	}
	cookieCount := map[string]int{}
	for _, row := range swaps {
		c, _ := row["cookie"].(string)
		if c != "" {
			cookieCount[c]++
		}
	}
	churn["cookies"] = len(cookieCount)
	for _, c := range cookieCount {
		switch {
		case c >= 5:
			churn["many"] = toInt(churn["many"]) + 1
		case c >= 2:
			churn["mid"] = toInt(churn["mid"]) + 1
		default:
			churn["one"] = toInt(churn["one"]) + 1
		}
		if c > toInt(churn["max"]) {
			churn["max"] = c
		}
	}

	out := map[string]interface{}{
		"generated_ts":   time.Now().Unix(),
		"id":             bucketID,
		"range":          rng,
		"label":          label,
		"algs":           CONGS,
		"meta":           meta,
		"series":         series,
		"swaps":          swaps,
		"proven":         proven,
		"swap_outcomes":  swapOutcomes,
		"churn":          churn,
	}
	data, _ := json.MarshalIndent(out, "", "  ")
	return data
}

// sliceOfMap converts a map[string]interface{} to []interface{} in
// the given key order (matches Python's dict ordering).
func sliceOfMap(m map[string]interface{}, keys []string) []interface{} {
	out := make([]interface{}, len(keys))
	for i, k := range keys {
		out[i] = toFloat(m[k])
	}
	return out
}

// strOrEmpty safely extracts a string.
func strOrEmpty(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// firstOrDefault returns the first non-empty value for key in a list of maps.
func firstOrDefault(maps []map[string]interface{}, key string) string {
	for _, m := range maps {
		if s := strOrEmpty(m[key]); s != "" {
			return s
		}
	}
	return ""
}

// getCachedLabelPrefix returns labelPrefix from the cached aliases.
// v0.7.1: NOT the per-cycle labels.json file (that's only written fresh
// by handleLabels POST).
func getCachedLabelPrefix() map[string]string {
	aliases := readAliases()
	labelPrefix := map[string]string{}
	for from, to := range aliases {
		labelPrefix[from] = to
	}
	return labelPrefix
}

// swapRe matches a swap line in swaps.csv.
// Format: ts,cookie,from,to,d,rate,dur,dest,dest6,dest6b[,bucket]
// v0.7.3: 7+ fields required (Python parity: 7 fields minimum).
var swapRe = regexp.MustCompile(`^(\d+(?:\.\d+)?),(\d+),(\d+),(\d+),(\d+),([-+]?\d+(?:\.\d+)?),([-+]?\d+(?:\.\d+)?)(?:,(.*))?$`)

// parseCSVLine splits a CSV line, handling quoted fields.
func parseCSVLine(line string) []string {
	fields := make([]string, 0, 12)
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(line); i++ {
		ch := line[i]
		switch {
		case ch == '"':
			inQuote = !inQuote
		case ch == ',' && !inQuote:
			fields = append(fields, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(ch)
		}
	}
	fields = append(fields, cur.String())
	return fields
}

// scanSwapCSVLines returns the swapRe-matching, >=7-field CSV lines of
// swaps.csv ONCE per render cycle.
//
// v0.9.119: this is the shared swap scan.  Previously renderBucketToDisk
// re-opened and re-scanned the ENTIRE swaps.csv once per bucket (8 scans
// per cycle) and renderSwapsFromCSV scanned it a 9th time — together the
// 5-minute disk burst that pegged iowait on memory-tight hosts (the
// "100% CPU, 69% io" spikes).  The consumers below parse each line with
// their own UNCHANGED code, so every rendered file is byte-identical;
// only the redundant scans are gone.
func scanSwapCSVLines() []string {
	lines := make([]string, 0, 256)
	f, err := os.Open(swapsCSVPath)
	if err != nil {
		return lines
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1<<20), 8<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if swapRe.FindStringSubmatch(line) == nil {
			continue
		}
		fields := parseCSVLine(line)
		if len(fields) < 7 {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}

// renderSwapsFromCSV writes swaps.json from swaps.csv.
// Output: list of swap rows (ts, cookie, from, to, d, rate, dur, dest,
// dest6, dest6b) + proven scatter points (rate > 1.25x bucket ref).
// v0.7.3: bucket_ref is the masked-ref-peak (not the first byte of the IP).
// v0.7.5: output goes to swaps.json (written every 5min with the fast files).
// v0.9.119: swapRows shared — iterate the per-cycle scan instead of
// re-scanning swaps.csv (was the 9th full scan per cycle).
func renderSwapsFromCSV(bucketMaps []map[string]interface{}, swapRows []map[string]interface{}) {
	labelPrefix := getCachedLabelPrefix()
	swaps := make([]map[string]interface{}, 0, 256)
	proven := make([]map[string]interface{}, 0, 64)

	for _, row := range swapRows {
		ts := toFloat(row["ts"])
		cookie, _ := row["cookie"].(string)
		from := toInt(row["from"])
		to := toInt(row["to"])
		d := toInt(row["d"])
		rate := toFloat(row["rate"])
		dur := toFloat(row["dur"])
		dest, _ := row["dest"].(string)
		dest6, _ := row["dest6"].(string)
		dest6b, _ := row["dest6b"].(string)

		// Find the matching bucket (bucketID = masked addr)
		maskedHost := maskedIP(swapDestToIP(row))
		bucketRef := 0.0
		bucketRefAvailable := false
		bucket := maskedHost
		bucketIsMasked := true
		for _, bm := range bucketMaps {
			if bucketDest(bm) == maskedHost {
				bucketRef = toFloat(bm["ref_mbps"])
				bucketRefAvailable = bucketRef > 0
				bucket = bucketDest(bm)
				if labelPrefix[bucket] != "" {
					bucketIsMasked = false
				}
				break
			}
		}
		if !bucketRefAvailable && len(bucketMaps) > 0 {
			// v0.9.95: only include swaps that belong to one of the
			// top-N buckets.  Python's write_swaps_json filtered
			// rows where bucket wasn't in bucket list.
			found := false
			for _, bm := range bucketMaps {
				if bucketDest(bm) == maskedHost {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// v0.7.3: bucket_ref = masked-ref-peak
		prov := map[string]interface{}{
			"ts":     ts,
			"cookie": cookie,
			"from":   from,
			"to":     to,
			"d":      d,
			"rate":   rate,
			"dur":    dur,
			"dest":   dest, "dest6": dest6, "dest6b": dest6b,
			"bucket": bucket, "bucket_is_masked": bucketIsMasked,
			"mbps": rate / 1e6, "dur_ago_min": dur / 60.0,
			"bucket_ref": bucketRef, "bucket_ref_mbps": bucketRef,
			"bucket_ref_available": bucketRefAvailable,
			"proven": true,
		}
		proven = append(proven, prov)
		swaps = append(swaps, map[string]interface{}{
			"ts": ts, "cookie": cookie, "from": from, "to": to,
			"d": d, "rate": rate, "dur": dur,
			"dest": dest, "dest6": dest6, "dest6b": dest6b,
			"bucket": bucket, "bucket_is_masked": bucketIsMasked,
			"mbps": rate / 1e6, "dur_ago_min": dur / 60.0,
			"bucket_ref": bucketRef, "bucket_ref_mbps": bucketRef,
			"bucket_ref_available": bucketRefAvailable,
		})
	}

	writeJSONToDisk("swaps.json", map[string]interface{}{
		"swaps":  swaps,
		"proven": proven,
	})
}

// renderSlowToDisk writes 7d + all-time series (slow path).
// Called from a goroutine — not the main renderToDisk ticker.
func (c *Collector) renderSlowToDisk() {
	buckets := bucketsAsMaps(c.current["buckets"])
	bucketMaps := make([]map[string]interface{}, len(buckets))
	for i, b := range buckets {
		bucketMaps[i] = b.(map[string]interface{})
	}

	// v0.9.90: shared 24h read (was: readCSVTail called per bucket)
	hist.csvAll = readCSVTail(86400)
	defer func() { hist.csvAll = nil }()
	// v0.9.119: shared swap scan (was: per-bucket scans + one more).
	swapRows := scanSwapCSVLines()

	for _, bm := range bucketMaps {
		renderBucketToDisk(bm, swapRows)
	}
	renderSwapsFromCSV(bucketMaps, swapRows)
	renderFleetToDisk(bucketMaps)
}
