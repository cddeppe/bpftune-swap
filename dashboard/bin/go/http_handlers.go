package main

// http_handlers.go — HTTP handlers for /data/bucket_<id>.json,
// /data/meta.json, /data/swaps.json, /data/fleet.json.
//
// v0.7.0 fixes:
//   - handleMetaJSON: use buckets[].dest directly (already labeled by
//     readBPFMap).  Was previously calling labelFor on already-labeled
//     IDs (matching the renderMetaToDisk bug).
//   - Stable sort with id tie-breaker (same fix as renderMetaToDisk).
//   - handleBucketJSON: sanitize bucket ID consistently with render.go
//     so dynamic + static responses produce the same filenames.

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ============================================================================
// HTTP handler: /data/bucket_<id>.json
// ============================================================================

func (h *historyStore) handleBucketJSON(w http.ResponseWriter, r *http.Request, bucketID string) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	doc := map[string]interface{}{
		"id":     bucketID,
		"series": map[string]interface{}{},
	}

	for rngName, rngCfg := range ranges {
		span, _ := rngCfg[0].(int)
		width, _ := rngCfg[1].(int)
		if width == 0 {
			width = 60
		}

		var snaps []bucketSnapshot
		switch rngName {
		case "1h":
			// v0.7.3: 1h from ring buffer (instant, live SSE data)
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
			// v0.7.3: 24h/7d/all from CSV (dynamic fallback when static file stale)
			snaps = readBucketCSV(bucketID, int64(span))
		}

		series := buildSeriesFromSnaps(snaps, width)
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
				fmt.Fprintf(os.Stderr, "handleBucketJSON: swaps.csv scan error: %v\n", err)
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

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	jsonEncoder(w).Encode(doc)
}

// ============================================================================
// HTTP handler: /data/meta.json
// ============================================================================

func (h *historyStore) handleMetaJSON(w http.ResponseWriter, r *http.Request, buckets []map[string]interface{}) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	type entry struct {
		id            string
		label         string
		instancesMean float64
		lastTs        int64
		nAlg          int
	}
	var entries []entry
	for _, b := range buckets {
		// v0.7.0: id is already labeled (from readBPFMap). Do NOT re-resolve.
		id, _ := b["dest"].(string)
		if id == "" {
			continue
		}
		inst := toInt(b["inst"])
		nAlg := toInt(b["n_alg"])
		label := id
		var instSum int
		var instCount int
		var lastTs int64
		if raw, ok := h.raw[id]; ok && len(raw) > 0 {
			for _, s := range raw {
				instSum += s.Instances
				instCount++
				if s.Ts > lastTs {
					lastTs = s.Ts
				}
			}
		}
		var instMean float64
		if instCount > 0 {
			instMean = float64(instSum) / float64(instCount)
		} else {
			instMean = float64(inst)
		}
		entries = append(entries, entry{id, label, instMean, lastTs, nAlg})
	}
	// v0.7.0: STABLE SORT — n_alg desc, inst_mean desc, id asc.
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].nAlg != entries[j].nAlg {
			return entries[i].nAlg > entries[j].nAlg
		}
		if entries[i].instancesMean != entries[j].instancesMean {
			return entries[i].instancesMean > entries[j].instancesMean
		}
		return entries[i].id < entries[j].id
	})

	bucketEntries := make([]interface{}, 0, len(entries))
	for _, e := range entries {
		bucketEntries = append(bucketEntries, map[string]interface{}{
			"id":             e.id,
			"label":          e.label,
			"points":         len(h.raw[e.id]),
			"instances_mean": e.instancesMean,
			"last_ts":        e.lastTs,
		})
	}
	defaultBucket := "all"
	if len(entries) > 0 {
		defaultBucket = entries[0].id
	}

	rngList := []string{"1h", "24h", "7d", "30d", "all"}
	doc := map[string]interface{}{
		"generated_ts":   time.Now().Unix(),
		"ranges":         rngList,
		"algs":           sortedAlgs(),
		"buckets":        bucketEntries,
		"default_bucket": defaultBucket,
		"has_tcp_rmem":   false,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	jsonEncoder(w).Encode(doc)
}

// ============================================================================
// HTTP handler: /data/swaps.json
// ============================================================================

func (h *historyStore) handleSwapsJSON(w http.ResponseWriter, r *http.Request, swapOutcomes map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	jsonEncoder(w).Encode(swapOutcomes)
}

// ============================================================================
// HTTP handler: /data/fleet.json
// ============================================================================

func (h *historyStore) handleFleetJSON(w http.ResponseWriter, r *http.Request, buckets []map[string]interface{}) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	type pair struct {
		bid string
		cov float64
	}
	var pairs []pair
	for _, b := range buckets {
		id, _ := b["dest"].(string)
		if id == "" {
			continue
		}
		snaps := readBucketCSVFast(id, 86400)
		if len(snaps) == 0 {
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
	// Stable sort: cov desc, id asc.
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
	doc := map[string]interface{}{
		"buckets":      labels,
		"coverage_24h": cov,
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	jsonEncoder(w).Encode(doc)
}

// jsonEncoder returns a JSON encoder writing to w.
func jsonEncoder(w http.ResponseWriter) *jsonEncoderImpl {
	return jsonNewEncoder(w)
}
