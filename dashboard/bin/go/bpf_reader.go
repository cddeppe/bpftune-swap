package main

// bpf_reader.go — runs bpftool and parses the JSON output of the
// remote_host_map BPF map.  Extracted from main.go for clarity.
//
// All addresses from the BPF map go through ResolveBucket() exactly once
// here. The resulting labeled bucket ID is then used everywhere else:
//   - current.json buckets[].dest
//   - metric_by_bucket / bucket_live map keys
//   - CSV addr column (writeBucketsCSV)
//   - ring buffer key (captureSnapshotsFromBPF)
//
// CSV readers do NOT re-apply ResolveBucket — they trust the stored label
// (see csv_reader.go). This was the root cause of "custom bucket
// disappears": applying ResolveBucket again at read time would remap a
// labeled "controld" back to itself (no harm) BUT would also remap a raw
// "2606:1a40::" (no label) to "controld" if a label was added later,
// creating duplicate entries in the ring buffer.

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// hostEntry is one BPF map entry after label resolution + merge.
// Mirrors Python read_map()'s (inst, addr, v) tuple.
//
// B3-fix: MaxInst tracks the largest single inst seen across folded entries,
// separate from Inst which is the SUM. Used by the merge logic to decide
// which entry donates its metrics/best_alg/min_rtt — we want the entry
// with the most instances, not whichever appeared first.
//
// v0.9.38: V4MinRTT and V6MinRTT track per-protocol min_rtt separately.
// Before this, the merge only kept one min_rtt (from the entry with more
// instances, usually v4). This meant v6 RTT was always 0, and the route
// monitor could never switch to v6 because it had no v6 data.
type hostEntry struct {
	Inst     int
	MaxInst  int    // B3-fix: largest single inst across folded entries
	Addr     string // labeled + merged (e.g. "home-sco" or "2606:1a40::")
	V        map[string]interface{}
	V4MinRTT float64 // v0.9.38: separate v4 min_rtt (microseconds)
	V6MinRTT float64 // v0.9.38: separate v6 min_rtt (microseconds)
	V4Inst   int     // v0.9.38: v4-only instance count
	V6Inst   int     // v0.9.38: v6-only instance count
}

// readBPFMap runs bpftool, parses the JSON, applies ResolveBucket + merges
// by final label.  Mirrors bpftune_log.py:read_map.
//
// v0.9.33: when collectorMode.CacheBPFMap is true, cache the result
// and skip the bpftool call when the map entry count hasn't changed
// (checked via a lightweight bpftool map show). This saves forking
// bpftool + parsing large JSON on every cycle when the map is stable.
var (
	bpfMapCache     []hostEntry
	bpfMapCacheErr  error
	bpfMapCacheSize int
)

func readBPFMap() ([]hostEntry, error) {
	// v0.9.86: try raw BPF syscalls first (no fork), fall back to bpftool.
	// The syscall path uses BPF_MAP_GET_NEXT_KEY + BPF_MAP_LOOKUP_ELEM to
	// iterate the map and parse raw bytes. Identical output to bpftool dump.
	if raw, err := readBPFMapSyscall(); err == nil && len(raw) >= 0 {
		// Check cache: if entry count matches, return cache.
		if collectorMode.CacheBPFMap && bpfMapCache != nil && len(raw) == bpfMapCacheSize {
			return bpfMapCache, bpfMapCacheErr
		}
		bpfMapCacheSize = len(raw)
		return mergeBPFMapEntries(raw)
	}

	// Fallback: bpftool fork path (used when syscalls fail — e.g.,
	// kernel < 4.4 without BPF_MAP_GET_FD_BY_ID, or map FD is stale).
	// v0.9.33: check if the map size changed since last call.
	if collectorMode.CacheBPFMap && bpfMapCache != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "bpftool", "--json", "map", "show", "name", "remote_host_map")
		output, err := cmd.Output()
		if err == nil {
			var mapInfo []map[string]interface{}
			if json.Unmarshal(output, &mapInfo) == nil && len(mapInfo) > 0 {
				sz := toInt(mapInfo[0]["entries"])
				if sz == bpfMapCacheSize {
					return bpfMapCache, bpfMapCacheErr
				}
				bpfMapCacheSize = sz
			}
		}
	}

	// v0.9.27: add 10s timeout to prevent collector hanging on bpftool
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bpftool", "--json", "map", "dump", "name", "remote_host_map")
	output, err := cmd.Output()
	if err != nil {
		if collectorMode.CacheBPFMap {
			bpfMapCache = nil
			bpfMapCacheErr = err
		}
		return nil, fmt.Errorf("bpftool: %w", err)
	}
	var raw []map[string]interface{}
	if err := json.Unmarshal(output, &raw); err != nil {
		if collectorMode.CacheBPFMap {
			bpfMapCache = nil
			bpfMapCacheErr = err
		}
		return nil, fmt.Errorf("bpftool json: %w", err)
	}
	if collectorMode.CacheBPFMap {
		bpfMapCacheSize = len(raw)
	}
	return mergeBPFMapEntries(raw)
}

// mergeBPFMapEntries takes raw bpftool-formatted entries (either from
// bpftool JSON or from raw-syscall parsing) and merges them into
// []hostEntry. This is the common merge logic extracted from readBPFMap
// so both code paths share it.
func mergeBPFMapEntries(raw []map[string]interface{}) ([]hostEntry, error) {
	// Merge by final labeled addr: sum instances, keep the entry
	// with more instances for the other fields (matches Python).
	merged := map[string]*hostEntry{}
	var order []string
	for _, entry := range raw {
		fmtData, ok := entry["formatted"].(map[string]interface{})
		if !ok {
			continue
		}
		val, ok := fmtData["value"].(map[string]interface{})
		if !ok {
			continue
		}
		keyData, ok := fmtData["key"].(map[string]interface{})
		if !ok {
			continue
		}
		in6u, ok := keyData["in6_u"].(map[string]interface{})
		if !ok {
			continue
		}
		addrBytes, ok := in6u["u6_addr8"].([]interface{})
		if !ok || len(addrBytes) != 16 {
			continue
		}
		b := make([]int, 16)
		for i, v := range addrBytes {
			b[i] = toInt(v) // v0.9.25: safe type assertion (was int(v.(float64)) which panics on nil)
		}
		var addr string
		if b[10] == 0xff && b[11] == 0xff {
			addr = fmt.Sprintf("%d.%d.%d.%d", b[12], b[13], b[14], b[15])
		} else {
			v6 := (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]
			if v6 != 0 {
				addr = fmt.Sprintf("v6:%08x", v6)
			} else {
				addr = "0.0.0.0"
			}
		}
		// Apply ResolveBucket + fold + canon, then merge by final key.
		final := ResolveBucket(addr)
		if final == "" {
			final = addr
		}
		// v0.9.41: If this is a v6 entry that didn't get a label
		// (still starts with "v6:"), try to find its v4 counterpart
		// via the cookie_dest map. The cookie_dest map tracks
		// (cookie → v4_dest, v6_dest) from estab log lines. If a
		// cookie has both v4 and v6 dests, they're the same
		// destination — so the v6 entry should get the v4's label.
		if strings.HasPrefix(final, "v6:") {
			if v4Label := v6ToV4Label(addr); v4Label != "" {
				final = v4Label
			}
		}
		inst := toInt(val["instances"])
		rttUs := toFloat(val["min_rtt"])
		isV6 := strings.HasPrefix(addr, "v6:")
		if existing, ok := merged[final]; ok {
			existing.Inst += inst
			// B3-fix: keep the entry with the largest single inst as the
			// representative for non-instance fields (best_alg, min_rtt,
			// max_rate_delivered, metrics[]).
			if inst > existing.MaxInst {
				existing.MaxInst = inst
				existing.V = val
			}
			// v0.9.38: track v4 and v6 min_rtt separately so the route
			// monitor has real v6 data even when v4 has more connections.
			if isV6 {
				existing.V6Inst += inst
				if rttUs > 0 && (existing.V6MinRTT == 0 || rttUs < existing.V6MinRTT) {
					existing.V6MinRTT = rttUs
				}
			} else {
				existing.V4Inst += inst
				if rttUs > 0 && (existing.V4MinRTT == 0 || rttUs < existing.V4MinRTT) {
					existing.V4MinRTT = rttUs
				}
			}
			// v0.9.39: merge ALL metrics across v4+v6 so the dashboard
			// shows combined dual-stack throughput, not just v4.
			existing.V = mergeHostValues(existing.V, val)
		} else {
			he := &hostEntry{Inst: inst, MaxInst: inst, Addr: final, V: val}
			if isV6 {
				he.V6Inst = inst
				if rttUs > 0 {
					he.V6MinRTT = rttUs
				}
			} else {
				he.V4Inst = inst
				if rttUs > 0 {
					he.V4MinRTT = rttUs
				}
			}
			merged[final] = he
			order = append(order, final)
		}
	}
	out := make([]hostEntry, 0, len(order))
	for _, addr := range order {
		out = append(out, *merged[addr])
	}
	// v0.9.33: cache the result for CacheBPFMap mode
	if collectorMode.CacheBPFMap {
		bpfMapCache = out
		bpfMapCacheErr = nil
		if bpfMapCacheSize == 0 {
			bpfMapCacheSize = len(raw)
		}
	}
	return out, nil
}

// mergeHostValues combines two BPF map values (v4 + v6) into a single
// value that reflects the combined dual-stack traffic.
//
// v0.9.39: Before this, the merge only kept the "winner's" metrics (the
// entry with more instances, usually v4). This meant v6 throughput,
// rate_ema, socket counts, and per-algorithm metrics were silently
// discarded. Now we properly sum/merge all fields:
//
//	Summed (v4 + v6):
//	  - instances, selection_count
//	  - metrics[i].rate_ema, metric_count, sockets_alive/good/proved
//	  - rate_hist bins
//
//	Min (best of both):
//	  - min_rtt (lower = better)
//
//	Max (best of both):
//	  - max_rate_delivered (higher = better)
//	  - metrics[i].swap_score, bad_streak, null_streak (worst case)
//
//	Recomputed after merge:
//	  - best_i / best_v (from merged metrics)
//	  - rate_best_i / rate_best_v (from merged rate_ema)
func mergeHostValues(existing, incoming map[string]interface{}) map[string]interface{} {
	if existing == nil {
		return incoming
	}
	if incoming == nil {
		return existing
	}

	// Start with a copy of existing
	merged := make(map[string]interface{}, len(existing))
	for k, v := range existing {
		merged[k] = v
	}

	// --- Prefix fields (u64) ---
	// instances: sum
	merged["instances"] = toInt(existing["instances"]) + toInt(incoming["instances"])

	// selection_count: sum
	merged["selection_count"] = toInt(existing["selection_count"]) + toInt(incoming["selection_count"])

	// min_rtt: min (lower = better), but 0 means "no data" so prefer nonzero
	eRTT := toFloat(existing["min_rtt"])
	iRTT := toFloat(incoming["min_rtt"])
	if iRTT > 0 && (eRTT == 0 || iRTT < eRTT) {
		merged["min_rtt"] = iRTT
	}

	// max_rate_delivered: max (higher = better)
	eMaxRate := toFloat(existing["max_rate_delivered"])
	iMaxRate := toFloat(incoming["max_rate_delivered"])
	if iMaxRate > eMaxRate {
		merged["max_rate_delivered"] = iMaxRate
	}

	// rtt_low_streak: max (worst case)
	if toInt(incoming["rtt_low_streak"]) > toInt(existing["rtt_low_streak"]) {
		merged["rtt_low_streak"] = toInt(incoming["rtt_low_streak"])
	}
	// rtt_low_min: min (lower = better)
	eRLM := toFloat(existing["rtt_low_min"])
	iRLM := toFloat(incoming["rtt_low_min"])
	if iRLM > 0 && (eRLM == 0 || iRLM < eRLM) {
		merged["rtt_low_min"] = iRLM
	}

	// --- metrics[16] array ---
	eMetrics, _ := existing["metrics"].([]interface{})
	iMetrics, _ := incoming["metrics"].([]interface{})
	maxLen := len(eMetrics)
	if len(iMetrics) > maxLen {
		maxLen = len(iMetrics)
	}
	if maxLen > 0 {
		outMetrics := make([]interface{}, maxLen)
		for i := 0; i < maxLen; i++ {
			var em, im map[string]interface{}
			if i < len(eMetrics) {
				em, _ = eMetrics[i].(map[string]interface{})
			}
			if i < len(iMetrics) {
				im, _ = iMetrics[i].(map[string]interface{})
			}
			if em == nil && im == nil {
				outMetrics[i] = map[string]interface{}{}
				continue
			}
			if em == nil {
				outMetrics[i] = im
				continue
			}
			if im == nil {
				outMetrics[i] = em
				continue
			}
			// Merge: sum rate/count/socket fields, take max for streaks/score
			mm := map[string]interface{}{}
			for k, v := range em {
				mm[k] = v
			}
			mm["rate_ema"] = toInt(em["rate_ema"]) + toInt(im["rate_ema"])
			mm["metric_count"] = toInt(em["metric_count"]) + toInt(im["metric_count"])
			mm["sockets_alive"] = toInt(em["sockets_alive"]) + toInt(im["sockets_alive"])
			mm["sockets_good"] = toInt(em["sockets_good"]) + toInt(im["sockets_good"])
			mm["sockets_proved"] = toInt(em["sockets_proved"]) + toInt(im["sockets_proved"])
			if toInt(im["swap_score"]) > toInt(em["swap_score"]) {
				mm["swap_score"] = toInt(im["swap_score"])
			}
			if toInt(im["bad_streak"]) > toInt(em["bad_streak"]) {
				mm["bad_streak"] = toInt(im["bad_streak"])
			}
			if toInt(im["null_streak"]) > toInt(em["null_streak"]) {
				mm["null_streak"] = toInt(im["null_streak"])
			}
			// state_flags, greedy_count, metric_value: take from existing (winner)
			outMetrics[i] = mm
		}
		merged["metrics"] = outMetrics

		// Recompute best_i / best_v from merged metrics
		bestI := 0
		bestV := 0
		rateBestI := 0
		rateBestV := 0
		for i, mraw := range outMetrics {
			m, _ := mraw.(map[string]interface{})
			if m == nil {
				continue
			}
			if toInt(m["metric_count"]) == 0 {
				continue
			}
			// best_v: weighted score (same formula as BPF kernel)
			rv := toInt(m["rate_ema"])
			ss := toInt(m["swap_score"])
			ssEff := ss
			if ssEff == 0 {
				ssEff = 256
			}
			bad := toInt(m["bad_streak"])
			weighted := rv * ssEff / 256
			if bad > 2 {
				weighted = weighted / 4
			}
			if weighted > bestV {
				bestV = weighted
				bestI = i
			}
			// rate_best: just highest rate_ema
			if rv > rateBestV {
				rateBestV = rv
				rateBestI = i
			}
		}
		merged["best_i"] = bestI
		merged["best_v"] = bestV
		merged["rate_best_i"] = rateBestI
		merged["rate_best_v"] = rateBestV
	}

	// --- rate_hist[32] ---
	eHist, _ := existing["rate_hist"].([]interface{})
	iHist, _ := incoming["rate_hist"].([]interface{})
	if len(eHist) > 0 || len(iHist) > 0 {
		histLen := len(eHist)
		if len(iHist) > histLen {
			histLen = len(iHist)
		}
		outHist := make([]interface{}, histLen)
		for i := 0; i < histLen; i++ {
			ev := 0
			iv := 0
			if i < len(eHist) {
				ev = toInt(eHist[i])
			}
			if i < len(iHist) {
				iv = toInt(iHist[i])
			}
			outHist[i] = ev + iv
		}
		merged["rate_hist"] = outHist
	}

	return merged
}

// v6ToV4Label looks up a v6 address in the cookie_dest map and returns
// the label of its v4 counterpart (if any).
//
// v0.9.41: The BPF map has separate entries for v4 and v6 connections to
// the same destination (e.g. YouTube). The v4 entry might have a label
// (from aliases) like "142.250.0.0", but the v6 entry stays as "v6:2606xxxx"
// because there's no v6 alias. This function uses the cookie_dest map to
// find the v4 counterpart and returns its label so the v6 entry can be
// merged with the v4 entry.
//
// The cookie_dest map (built from estab log lines) records:
//
//	cookie → ["v4_dest", "v6_dest", "v6b_dest"]
//
// If a cookie has both v4 and v6 dests, they're the same destination.
// We look for any cookie where the v6 dest matches the input v6 address,
// then resolve the v4 dest to its label.
func v6ToV4Label(v6Addr string) string {
	if cookieDestDiskMap == nil {
		return ""
	}
	// The v6 addr from the BPF map is "v6:XXXXXXXX" (8 hex chars = first 4 bytes of v6)
	// The cookie_dest map stores v6 as "dest6=<number>" from the estab log line,
	// which is also the first 4 bytes as a decimal number.
	// Convert the hex to the same format used in cdest.
	hexPart := strings.TrimPrefix(v6Addr, "v6:")
	v6Num, err := strconv.ParseUint(hexPart, 16, 64)
	if err != nil {
		return ""
	}
	v6Str := strconv.FormatUint(v6Num, 10)

	// Search cookie_dest map for a cookie that has this v6 dest
	for _, entry := range cookieDestDiskMap {
		if len(entry) >= 2 && entry[1] == v6Str {
			// Found a cookie with this v6 dest. Get the v4 dest.
			v4Dest := entry[0]
			if v4Dest == "" || v4Dest == "0" {
				continue
			}
			// Resolve the v4 dest to its label
			label := ResolveBucket(v4Dest)
			if label != "" && !strings.HasPrefix(label, "v6:") {
				return label
			}
			// If no label, return the raw v4 address (still better than "v6:xxxx")
			return v4Dest
		}
	}
	return ""
}
