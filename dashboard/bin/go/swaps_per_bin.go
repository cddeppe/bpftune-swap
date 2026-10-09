package main

// swaps_per_bin.go — dynamic endpoint that bins swaps from swaps.csv for
// any range, with optional bucket filter. Always fresh (no 5-min stale
// static file). Fixes the swaps-per-bin chart for 24h/7d/30d/all ranges.

import (
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"
)

const swapsPerBinCacheTTL = 30 * time.Second

type swapsPerBinCacheKey struct {
	rng, bucket string
}

type swapsPerBinCacheEntry struct {
	result   map[string]interface{}
	genTime  time.Time
	csvMtime int64
}

var (
	swapsPerBinCache   = map[swapsPerBinCacheKey]*swapsPerBinCacheEntry{}
	swapsPerBinCacheMu sync.Mutex
)

func swapsPerBinMaxBytes(rng string) int64 {
	switch rng {
	case "1h", "24h":
		return 8_000_000
	case "7d":
		return 16_000_000
	case "30d", "all":
		return 64_000_000
	default:
		return 16_000_000
	}
}

// handleSwapsPerBinJSON — GET /data/swaps_per_bin.json?range=<rng>&bucket=<id>
func (h *historyStore) handleSwapsPerBinJSON(w http.ResponseWriter, r *http.Request) {
	rng := r.URL.Query().Get("range")
	if rng == "" {
		rng = "24h"
	}
	bucketID := r.URL.Query().Get("bucket")
	if bucketID == "" {
		bucketID = "all"
	}

	rngCfg, ok := ranges[rng]
	if !ok {
		rng = "24h"
		rngCfg = ranges["24h"]
	}
	span, _ := rngCfg[0].(int)
	width, _ := rngCfg[1].(int)
	if width == 0 {
		width = 60
	}

	csvMtime := int64(0)
	if fi, err := os.Stat(swapsCSVPath); err == nil {
		csvMtime = fi.ModTime().Unix()
	}

	cacheKey := swapsPerBinCacheKey{rng, bucketID}
	swapsPerBinCacheMu.Lock()
	entry := swapsPerBinCache[cacheKey]
	if entry != nil && entry.csvMtime == csvMtime &&
		time.Since(entry.genTime) < swapsPerBinCacheTTL {
		result := entry.result
		swapsPerBinCacheMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache")
		json.NewEncoder(w).Encode(result)
		return
	}
	swapsPerBinCacheMu.Unlock()

	rows := readSwapsCSVTail(swapsPerBinMaxBytes(rng))

	nowEpoch := time.Now().Unix()
	var cutoff int64
	if span > 0 {
		cutoff = nowEpoch - int64(span)
	}

	binCounts := map[int64]int{}
	for _, sw := range rows {
		dest := sw.Dest
		if lbl := labelFor(dest); lbl != "" {
			dest = lbl
		}
		if bucketID != "all" && dest != bucketID {
			continue
		}
		if span > 0 && sw.CollectedTs < cutoff {
			continue
		}
		binIdx := sw.CollectedTs / int64(width)
		binCounts[binIdx]++
	}

	var binIdxs []int64
	for bi := range binCounts {
		binIdxs = append(binIdxs, bi)
	}
	sort.Slice(binIdxs, func(i, j int) bool { return binIdxs[i] < binIdxs[j] })

	tsArr := make([]interface{}, len(binIdxs))
	swapsArr := make([]interface{}, len(binIdxs))
	for i, bi := range binIdxs {
		tsArr[i] = bi*int64(width) + int64(width)/2
		swapsArr[i] = binCounts[bi]
	}

	result := map[string]interface{}{
		"ts":           tsArr,
		"swaps":        swapsArr,
		"interval":     width,
		"rSec":         span,
		"range":        rng,
		"bucket":       bucketID,
		"generated_ts": nowEpoch,
		"n_swaps":      len(rows),
	}

	swapsPerBinCacheMu.Lock()
	swapsPerBinCache[cacheKey] = &swapsPerBinCacheEntry{
		result: result, genTime: time.Now(), csvMtime: csvMtime,
	}
	if len(swapsPerBinCache) > 64 {
		for k := range swapsPerBinCache {
			delete(swapsPerBinCache, k)
			break
		}
	}
	swapsPerBinCacheMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	json.NewEncoder(w).Encode(result)
}
