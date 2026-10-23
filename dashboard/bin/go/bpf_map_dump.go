package main

// bpf_map_dump.go — reads the BPF remote_host_map via raw syscalls
// (BPF_MAP_GET_NEXT_KEY + BPF_MAP_LOOKUP_ELEM) and parses the 1024-byte
// value struct into the same map[string]interface{} structure that the
// bpftool JSON parser produces.
//
// v0.9.86: eliminates the `bpftool --json map dump` + `map show` forks.
//
// v0.9.112 (round 5) — fixes for the field failure on al
// ("bpfMapGetNextKey: BPF_MAP_GET_NEXT_KEY: invalid argument"):
//   1. iteration now STARTS with key=NULL (the kernel contract). The old
//      code passed a 16-byte zero-filled key on the first call — map
//      types whose get_next_key rejects unknown keys answer EINVAL.
//   2. curKey no longer ALIASES nextKey (`curKey = nextKey` made both
//      slices the same memory from iteration 2 on) — now a copy.
//   3. key/value sizes are validated against BPF_OBJ_GET_INFO_BY_FD
//      (the real map geometry) instead of being assumed 16/1024.
//   4. every failure now names the map (name/id/type/sizes) so any
//      residual fallback is self-diagnosing in the journal.
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

	// v0.9.112: ask the kernel for the map's real geometry instead of
	// assuming it. Used for buffer sizing, validation and diagnostics.
	info, infoErr := bpfMapGetInfoByFD(fd)
	keySize := 16
	valueSize := sizeofRemoteHost // 1024 bytes
	if infoErr == nil {
		if info.KeySize != uint32(keySize) || info.ValueSize != uint32(valueSize) {
			return nil, fmt.Errorf("map %q (id=%d type=%d): key_size=%d value_size=%d, parser expects %d/%d",
				info.Name, info.ID, info.Type, info.KeySize, info.ValueSize, keySize, valueSize)
		}
	}

	// v0.9.112: iterate with key=NULL first (kernel contract), then walk
	// forward with a COPY of the previous nextKey (no aliasing).
	var entries []map[string]interface{}
	nextKey := make([]byte, keySize)
	var curKey []byte // nil = start of iteration

	for {
		ok, err := bpfMapGetNextKey(fd, curKey, nextKey)
		if err != nil {
			return nil, mapIterError(info, infoErr, err)
		}
		if !ok {
			break // no more keys
		}
		// Read the value for this key.
		value := make([]byte, valueSize)
		if err := bpfMapLookupElem(fd, nextKey, value); err != nil {
			// Key was deleted between GET_NEXT_KEY and LOOKUP_ELEM — skip.
			curKey = append(curKey[:0], nextKey...)
			continue
		}

		// Parse the raw bytes into the same structure bpftool produces.
		entry := parseRawHostEntry(nextKey, value)
		entries = append(entries, entry)

		curKey = append(curKey[:0], nextKey...) // v0.9.112: COPY (was aliasing)
	}

	if entries == nil {
		// Map is empty — that's valid, return empty slice (v0.9.86 contract).
		return []map[string]interface{}{}, nil
	}
	return entries, nil
}

// mapIterError enriches iteration failures with the map's identity so the
// rate-limited fallback log line in bpf_reader.go is self-diagnosing.
func mapIterError(info bpfMapInfo, infoErr, err error) error {
	if infoErr != nil {
		return fmt.Errorf("bpfMapGetNextKey: %w (map info unavailable: %v)", err, infoErr)
	}
	return fmt.Errorf("bpfMapGetNextKey: %w (map %q id=%d type=%d key_size=%d value_size=%d)",
		err, info.Name, info.ID, info.Type, info.KeySize, info.ValueSize)
}

// parseRawHostEntry converts a raw 16-byte key + 1024-byte value into the
// same "formatted" structure that bpftool --json produces.
func parseRawHostEntry(key, value []byte) map[string]interface{} {
	keyMap := parseRawKey(key)
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

	// Parse 14 prefix u64 fields at known offsets (little-endian).
	// bpftool outputs these as JSON numbers (float64 after unmarshal).
	for i, name := range prefixFields {
		off := i * 8
		if off+8 > len(buf) {
			break
		}
		v := binary.LittleEndian.Uint64(buf[off : off+8])
		val[name] = float64(v)
	}

	// Parse rate_hist: 32 × u32 bins + u64 sum.
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

	// Parse metrics[16]: each 48 bytes.
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

	return val
}

// getMapEntryCountSyscall counts BPF map entries via BPF_MAP_GET_NEXT_KEY
// iteration. Used to check if the cache is stale without forking bpftool.
// v0.9.112: same iteration contract as readBPFMapSyscall (nil start, no aliasing).
func getMapEntryCountSyscall(mapID int) (int, error) {
	fd, err := getMapFD(mapID)
	if err != nil {
		return -1, err
	}
	count := 0
	nextKey := make([]byte, 16) // remote_host_map key size
	var curKey []byte          // nil = start of iteration
	for {
		ok, err := bpfMapGetNextKey(fd, curKey, nextKey)
		if err != nil {
			return -1, err
		}
		if !ok {
			break
		}
		count++
		curKey = append(curKey[:0], nextKey...)
	}
	return count, nil
}

// _ = strings.TrimSpace // keep import if needed later
var _ = strings.TrimSpace
