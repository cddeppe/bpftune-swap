package main

// bpf_map_dump.go — reads the BPF remote_host_map via raw syscalls
// (BPF_MAP_GET_NEXT_KEY + BPF_MAP_LOOKUP_ELEM) and parses the 1024-byte
// value struct into the same map[string]interface{} structure that the
// bpftool JSON parser produces.
//
// v0.9.86: eliminates the `bpftool --json map dump` fork in readBPFMap
// (called every 30s when the entry count changes) and the
// `bpftool --json map show name remote_host_map` fork (called every 30s
// to check entry count). Both replaced with in-process syscalls.
//
// Struct layout (must match streak_writeback.go constants):
//
//   0-111:    14 × u64 prefix fields (min_rtt, max_rate_delivered, etc.)
//   112-247:  rate_hist (32 × u32 bins + u64 sum = 136 bytes)
//   248-1015: metrics[16] (16 × 48 bytes = 768 bytes)
//   1016-1023: seq (u64)
//   Total: 1024 bytes

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// readBPFMapSyscall reads the entire remote_host_map via raw BPF syscalls.
// Returns []map[string]interface{} with the same structure as bpftool's
// JSON output (each entry has "formatted" → "key" + "value" → field maps).
// Falls back to the caller (bpftool fork) if any syscall fails.
func readBPFMapSyscall() ([]map[string]interface{}, error) {
	// Get the map ID (cached for 5 min by resolveRemoteHostMapID).
	mapID, err := resolveRemoteHostMapID()
	if err != nil || mapID < 0 {
		return nil, fmt.Errorf("resolveRemoteHostMapID: %w", err)
	}

	// Get the map FD (cached until stale).
	fd, err := getMapFD(mapID)
	if err != nil {
		return nil, fmt.Errorf("getMapFD: %w", err)
	}

	// Iterate keys with BPF_MAP_GET_NEXT_KEY.
	// The remote_host_map uses 16-byte keys (in6_addr).
	keySize := 16
	valueSize := sizeofRemoteHost // 1024 bytes

	var entries []map[string]interface{}
	curKey := make([]byte, keySize)
	nextKey := make([]byte, keySize)
	hasKey := false

	for {
		ok, err := bpfMapGetNextKey(fd, curKey, nextKey)
		if err != nil {
			return nil, fmt.Errorf("bpfMapGetNextKey: %w", err)
		}
		if !ok {
			break // no more keys
		}
		// Read the value for this key.
		value := make([]byte, valueSize)
		if err := bpfMapLookupElem(fd, nextKey, value); err != nil {
			// Key was deleted between GET_NEXT_KEY and LOOKUP_ELEM — skip.
			curKey = nextKey
			hasKey = true
			continue
		}

		// Parse the raw bytes into the same structure bpftool produces.
		entry := parseRawHostEntry(nextKey, value)
		entries = append(entries, entry)

		curKey = nextKey
		hasKey = true
	}

	if !hasKey && len(entries) == 0 {
		// Map is empty — that's valid, return empty slice.
		return []map[string]interface{}{}, nil
	}

	return entries, nil
}

// parseRawHostEntry converts a raw 16-byte key + 1024-byte value into the
// same "formatted" structure that bpftool --json produces. This allows
// the existing readBPFMap merge logic to work unchanged.
func parseRawHostEntry(key, value []byte) map[string]interface{} {
	// Parse key (in6_addr, 16 bytes) into the same structure as bpftool.
	keyMap := parseRawKey(key)

	// Parse value (1024 bytes) into field maps.
	valMap := parseRawValue(value)

	return map[string]interface{}{
		"formatted": map[string]interface{}{
			"key":   keyMap,
			"value": valMap,
		},
	}
}

// parseRawKey converts a 16-byte in6_addr key into bpftool's key structure.
func parseRawKey(key []byte) map[string]interface{} {
	// bpftool outputs: { "in6_u": { "u6_addr8": [b0, b1, ..., b15] } }
	addrBytes := make([]interface{}, len(key))
	for i, b := range key {
		addrBytes[i] = b
	}
	return map[string]interface{}{
		"in6_u": map[string]interface{}{
			"u6_addr8": addrBytes,
		},
	}
}

// parseRawValue converts a 1024-byte remote_host struct into bpftool's
// value field map. Uses the same offsets as streak_writeback.go.
func parseRawValue(buf []byte) map[string]interface{} {
	val := map[string]interface{}{}

	// Parse 14 prefix u64 fields at known offsets.
	// Each is 8 bytes, little-endian.
	for i, name := range prefixFields {
		off := i * 8
		if off+8 > len(buf) {
			break
		}
		v := binary.LittleEndian.Uint64(buf[off : off+8])
		// bpftool outputs these as JSON numbers (float64 in Go's json.Unmarshal).
		// Convert to float64 for compatibility with existing code that does
		// toFloat(val["min_rtt"]) etc.
		val[name] = float64(v)
	}

	// Parse rate_hist: 32 × u32 bins + u64 sum.
	// bpftool outputs these as "rate_hist" → { "bins": [...], "sum": N }.
	// We put them in the same nested structure.
	if offRateHist+sizeofRateHist <= len(buf) {
		bins := make([]interface{}, rateHistBins)
		for i := 0; i < rateHistBins; i++ {
			off := offRateHist + i*4
			bins[i] = float64(binary.LittleEndian.Uint32(buf[off : off+4]))
		}
		sumOff := offRateHist + rateHistBins*4
		sum := float64(binary.LittleEndian.Uint64(buf[sumOff : sumOff+8]))
		val["rate_hist"] = map[string]interface{}{
			"bins": bins,
			"sum":  sum,
		}
	}

	// Parse metrics[16]: each 48 bytes with u64 + u64 + u64 + u64 + 5×u16 + u8 + u8 + pad.
	metrics := make([]interface{}, numTCPConnMetrics)
	for i := 0; i < numTCPConnMetrics; i++ {
		base := offMetricsArray + i*sizeofTCPConnMetric
		if base+sizeofTCPConnMetric > len(buf) {
			break
		}
		m := map[string]interface{}{}
		// 4 × u64 fields (state_flags, greedy_count, metric_count, metric_value)
		for j, name := range metricFieldsU64 {
			off := base + j*8
			m[name] = float64(binary.LittleEndian.Uint64(buf[off : off+8]))
		}
		// 5 × u16 fields (sockets_alive, sockets_good, sockets_proved, rate_ema, swap_score)
		for j, name := range metricFieldsU16 {
			off := base + 32 + j*2
			m[name] = float64(binary.LittleEndian.Uint16(buf[off : off+2]))
		}
		// bad_streak (u8 @ 42), null_streak (u8 @ 43)
		m["bad_streak"] = float64(buf[base+offMetricBadStreak])
		m["null_streak"] = float64(buf[base+offMetricNullStreak])
		metrics[i] = m
	}
	val["metrics"] = metrics

	// Also set "instances" and "min_rtt" at top level for code that reads
	// val["instances"] / val["min_rtt"] directly (these are already in
	// prefixFields, but bpftool also includes them at the value root —
	// actually they ARE the prefix fields, so they're already set above).

	// Set V4MinRTT / V6MinRTT — these aren't in the raw struct, they're
	// computed by readBPFMap's merge logic. Leave them out — the caller
	// handles them.

	return val
}

// getMapEntryCountSyscall counts BPF map entries via BPF_MAP_GET_NEXT_KEY
// iteration. Used to check if the cache is stale without forking bpftool.
func getMapEntryCountSyscall(mapID int) (int, error) {
	fd, err := getMapFD(mapID)
	if err != nil {
		return -1, err
	}
	count := 0
	curKey := make([]byte, 16) // remote_host_map key size
	nextKey := make([]byte, 16)
	for {
		ok, err := bpfMapGetNextKey(fd, curKey, nextKey)
		if err != nil {
			return -1, err
		}
		if !ok {
			break
		}
		count++
		curKey = nextKey
	}
	return count, nil
}

// _ = strings.TrimSpace // keep import if needed later
var _ = strings.TrimSpace
