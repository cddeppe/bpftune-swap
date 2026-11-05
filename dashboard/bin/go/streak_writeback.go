package main

// streak_writeback.go — sustained → kernel streak correction.
//
// Mirrors the deleted dashboard/bin/streak_writeback.py (232 lines).
// Patches bad_streak and null_streak in the remote_host_map BPF map
// based on the sustained outcome (60-300s after the swap) of the last
// 8 swaps per (host, alg) pair.
//
// CRITICAL: only patches 2 bytes per metric slot (offsets 42 and 43).
// swap_score (offset 40), rate_ema (offset 38), sockets_* (32-41),
// prefix fields (0-111), rate_hist (112-247) are preserved bit-for-bit
// from the lookup.  See "0.4.86" comment in the original Python: the
// kernel (0.4.84+) owns swap_score, and the old writeback that
// recalculated it from rate_ema caused unfair low scores for low-rate
// algs.  We now ONLY patch bad_streak/null_streak.
//
// Hooked from collect() in collect.go, called once per 30s cycle.

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// BPF remote_host_map value layout (must match kernel struct exactly).
// Mirrors Python streak_writeback.py constants.
// v0.4.104: route_min_rtt field removed — BPF can't write beyond offset 1024.
// Route RTT is now logged via bpf_printk and parsed from the trace log.
const (
	rateHistBins        = 32
	numTCPConnMetrics   = 16
	offMetricBadStreak  = 42
	offMetricNullStreak = 43
	sizeofTCPConnMetric = 48
	offRateHist         = 112
	sizeofRateHist      = 4*rateHistBins + 8
	offMetricsArray     = offRateHist + sizeofRateHist
	sizeofSeqField      = 8 // 0.4.89: __u64 seq at end of struct (C1 race fix)
	sizeofRemoteHost    = offMetricsArray + (numTCPConnMetrics * sizeofTCPConnMetric) + sizeofSeqField
	writebackWindow     = 8
)

// Auto-detected prefix lengths (mutable — re-detected each cycle).
// Defaults match Python: /16 for v4, /32 for v6 (BPF log records only
// 32 bits of v6 dest, so /32 is the maximum meaningful mask).
var (
	maskBitsV4  = 16
	maskBitsV6  = 32
	writebackMu sync.Mutex
)

// v0.7.9: only log mask detection + v6 warning when they CHANGE,
// not every 30s cycle. Prevents journal spam.
var (
	lastMaskV4 = -1
	lastMaskV6 = -1
	v6Warned   = false
	// v0.9.36: cache for resolveRemoteHostMapID + detectMask.
	// mapIDCache: caches the BPF map ID for 5 min (changes only on tuner reload).
	// maskCache: caches the mask detection for 30 min (changes only on tunable edit).
	maskCacheMu   sync.Mutex
	mapIDCacheAt  time.Time
	mapIDCacheTTL = 5 * time.Minute
	maskCacheAt   time.Time
	maskCacheTTL  = 30 * time.Minute
	cachedMapID   = -1
)

// v0.9.126 fix: the daemon pins tuner_config_map at
// /sys/fs/bpf/bpftune/tcp_conn/explore (src/tcp_conn_tuner.c EXPLORE_PIN_DIR,
// since 0.4.64). Older dashboard code probed /sys/fs/bpftune/... — never this
// daemon's pin location — kept as a legacy fallback for forks only.
// (Constants live in config_handler.go: tunerConfigPinMain/Legacy.)

// prefixFields is the ordered list of u64 fields at the start of the
// remote_host value (offsets 0..111).  Used to re-serialize the JSON
// value back to bytes.  Mirrors Python _PREFIX_FIELDS.
// v0.4.104: route_min_rtt is at the END of the struct (after seq),
// so this list is UNCHANGED from 0.4.103.
var prefixFields = []string{
	"min_rtt", "max_rate_delivered", "instances", "selection_count",
	"best_i", "best_v", "second_i", "second_v",
	"rate_best_i", "rate_best_v", "rate_second_i", "rate_second_v",
	"rtt_low_streak", "rtt_low_min",
}

// metricFieldsU64 / metricFieldsU16 are the ordered fields in each
// 48-byte tcp_conn_metric slot.  Mirrors Python _METRIC_FIELDS_*.
var (
	metricFieldsU64 = []string{"state_flags", "greedy_count", "metric_count", "metric_value"}
	metricFieldsU16 = []string{"sockets_alive", "sockets_good", "sockets_proved", "rate_ema", "swap_score"}
)

// ============================================================================
// BPF map access helpers
// ============================================================================

// resolveRemoteHostMapID finds the remote_host_map by name via
// `bpftool map show`.  Returns the numeric id, or -1 if not found.
// Mirrors Python _resolve_remote_host_map_id.
// v0.9.36: cached for 5 min — the map ID only changes when the BPF
// program is reloaded (tuner restart). Was forking bpftool every 2 min.
func resolveRemoteHostMapID() (int, error) {
	maskCacheMu.Lock()
	if cachedMapID > 0 && time.Since(mapIDCacheAt) < mapIDCacheTTL {
		id := cachedMapID
		maskCacheMu.Unlock()
		return id, nil
	}
	maskCacheMu.Unlock()

	out, err := exec.Command("bpftool", "--json", "map", "show").Output()
	if err != nil {
		return -1, fmt.Errorf("bpftool map show: %w", err)
	}
	var maps []map[string]interface{}
	if err := json.Unmarshal(out, &maps); err != nil {
		return -1, fmt.Errorf("bpftool map show json: %w", err)
	}
	for _, m := range maps {
		name, _ := m["name"].(string)
		if strings.Contains(name, "remote_host") {
			id := int(toInt(m["id"]))
			maskCacheMu.Lock()
			cachedMapID = id
			mapIDCacheAt = time.Now()
			maskCacheMu.Unlock()
			return id, nil
		}
	}
	return -1, fmt.Errorf("remote_host_map not found")
}

// detectMask auto-detects the v4/v6 prefix length by inspecting existing
// map keys.  Finds the smallest mask (8/16/24/32 for v4, 32/48/64/128 for
// v6) where the trailing bytes are all zero across all entries.
// Mirrors Python _detect_mask.
// v0.9.36: cached for 30 min — the mask only changes when prefix4/prefix6
// tunables change. Was doing a full `bpftool map dump` every 2 min.
func detectMask(mapID int) {
	// v0.9.126 fix: PRIMARY source = the daemon's actual prefix4/prefix6,
	// read live from the pinned tuner_config_map (slots 1 and 2, live
	// since 0.4.79). The key-scan inference below cannot distinguish a
	// prefix-masked bucket key from an ALIAS TARGET stored verbatim by
	// the daemon (bucket_key_alias_or_prefix: *key = *a), so on hosts
	// with operator-folded aliases (e.g. 104.16.9.9 as a Cloudflare fold
	// target) it inferred /32 — and every streak correction then missed
	// its bucket key. Reading the map is 2 syscalls; no caching needed.
	if v4, ok4 := readTunerConfigSlot(1); ok4 && v4 >= 1 && v4 <= 32 {
		if v6, ok6 := readTunerConfigSlot(2); ok6 && v6 >= 1 && v6 <= 128 {
			if int(v4) != maskBitsV4 {
				maskBitsV4 = int(v4)
				if int(v4) != lastMaskV4 {
					lastMaskV4 = int(v4)
					fmt.Fprintf(os.Stderr, "[writeback] /%d v4 mask (from tuner_config_map slot 1)\n", v4)
				}
			}
			if int(v6) != maskBitsV6 {
				maskBitsV6 = int(v6)
				if int(v6) != lastMaskV6 {
					lastMaskV6 = int(v6)
					fmt.Fprintf(os.Stderr, "[writeback] /%d v6 mask (from tuner_config_map slot 2)\n", v6)
				}
			}
			return
		}
	}

	// Fallback (pin unavailable — older tuner, bpffs not mounted):
	// cached key-scan inference. v0.9.126 fix: alias-target keys are
	// excluded from the scan (see excludeAliasTargetKeys).
	maskCacheMu.Lock()
	if mapID == cachedMapID && time.Since(maskCacheAt) < maskCacheTTL {
		maskCacheMu.Unlock()
		return // cache hit — mask unchanged
	}
	maskCacheMu.Unlock()

	detectMaskUncached(mapID)

	maskCacheMu.Lock()
	cachedMapID = mapID
	maskCacheAt = time.Now()
	maskCacheMu.Unlock()
}

// readTunerConfigSlot reads tuner_config_map[slot] (BPF_MAP_TYPE_ARRAY,
// __u32 key, __u32 value) from the daemon's pinned map. Returns (value, true)
// on success. Tries the real pin path first, then the legacy dashboard path.
func readTunerConfigSlot(slot uint32) (uint32, bool) {
	for _, pin := range []string{tunerConfigPinMain, tunerConfigPinLegacy} {
		fd, err := bpfOpenPinnedMap(pin)
		if err != nil {
			continue
		}
		key := make([]byte, 4)
		binary.LittleEndian.PutUint32(key, slot)
		val := make([]byte, 4)
		err = bpfMapLookupElem(fd, key, val)
		unix.Close(fd)
		if err == nil {
			return binary.LittleEndian.Uint32(val), true
		}
	}
	return 0, false
}

// excludeAliasTargetKeys drops keys that are alias TARGETS. The daemon
// stores alias targets verbatim in remote_host_map, so they are unaligned
// by construction and poison the trailing-zero inference (v0.9.126 fix).
// v4 keys are 4-byte slices, v6 keys are 16-byte slices (see detectMaskSyscall).
// The alias map is passed in (not loaded here) so the exclusion is unit-testable
// and loaded once per detection pass.
func excludeAliasTargetKeys(keys [][]byte, v6 bool, aliases map[string]string) [][]byte {
	if len(aliases) == 0 || len(keys) == 0 {
		return keys
	}
	targets := make(map[string]bool, len(aliases))
	for _, to := range aliases {
		targets[to] = true
	}
	out := make([][]byte, 0, len(keys))
	for _, k := range keys {
		var ip net.IP
		if v6 {
			if len(k) != 16 {
				out = append(out, k)
				continue
			}
			ip = net.IP(append([]byte(nil), k...))
		} else {
			if len(k) != 4 {
				out = append(out, k)
				continue
			}
			ip = net.IPv4(k[0], k[1], k[2], k[3])
		}
		if !targets[ip.String()] {
			out = append(out, k)
		}
	}
	return out
}

// detectMaskUncached does the actual mask detection.
// v0.9.86: uses BPF_MAP_GET_NEXT_KEY to iterate keys via raw syscall
// (no bpftool fork). Falls back to bpftool dump if the syscall path fails.
func detectMaskUncached(mapID int) {
	// v0.9.86: try raw syscall path first.
	if v4Keys, v6Keys, ok := detectMaskSyscall(mapID); ok {
		// v0.9.126 fix: alias targets are stored verbatim by the
		// daemon and must not feed the mask inference.
		aliases := loadAliasCanonicalMap()
		applyMaskDetection(excludeAliasTargetKeys(v4Keys, false, aliases),
			excludeAliasTargetKeys(v6Keys, true, aliases))
		return
	}

	// Fallback: bpftool dump
	out, err := exec.Command("bpftool", "--json", "map", "dump", "id", strconv.Itoa(mapID)).Output()
	if err != nil {
		return
	}
	var data []map[string]interface{}
	if err := json.Unmarshal(out, &data); err != nil {
		return
	}
	var v4, v6 [][]byte
	for _, entry := range data {
		formatted, _ := entry["formatted"].(map[string]interface{})
		if formatted == nil {
			formatted = entry
		}
		keyData, _ := formatted["key"].(map[string]interface{})
		if keyData == nil {
			continue
		}
		in6u, _ := keyData["in6_u"].(map[string]interface{})
		if in6u == nil {
			continue
		}
		addrBytes, _ := in6u["u6_addr8"].([]interface{})
		if len(addrBytes) != 16 {
			continue
		}
		b := make([]byte, 16)
		for i, v := range addrBytes {
			b[i] = byte(toInt(v))
		}
		if b[10] == 0xff && b[11] == 0xff {
			v4 = append(v4, append([]byte(nil), b[12:16]...))
		} else {
			v6 = append(v6, b)
		}
	}
	applyMaskDetection(excludeAliasTargetKeys(v4, false, loadAliasCanonicalMap()),
		excludeAliasTargetKeys(v6, true, loadAliasCanonicalMap()))
}

// detectMaskSyscall iterates BPF map keys via raw syscall and separates
// them into v4 (4-byte) and v6 (16-byte) slices. Returns (v4Keys, v6Keys, ok).
func detectMaskSyscall(mapID int) (v4, v6 [][]byte, ok bool) {
	fd, err := getMapFD(mapID)
	if err != nil {
		return nil, nil, false
	}
	curKey := make([]byte, 16)
	nextKey := make([]byte, 16)
	for {
		hasMore, err := bpfMapGetNextKey(fd, curKey, nextKey)
		if err != nil || !hasMore {
			break
		}
		key := make([]byte, 16)
		copy(key, nextKey)
		if key[10] == 0xff && key[11] == 0xff {
			v4 = append(v4, append([]byte(nil), key[12:16]...))
		} else {
			v6 = append(v6, key)
		}
		curKey = nextKey
	}
	return v4, v6, true
}

// applyMaskDetection runs the mask detection algorithm on the extracted keys.
func applyMaskDetection(v4, v6 [][]byte) {
	if len(v4) > 0 {
		for _, bits := range []int{8, 16, 24, 32} {
			idx := bits / 8
			allZero := true
			for _, e := range v4 {
				for _, x := range e[idx:] {
					if x != 0 {
						allZero = false
						break
					}
				}
				if !allZero {
					break
				}
			}
			if allZero {
				if bits != maskBitsV4 {
					maskBitsV4 = bits
					if bits != lastMaskV4 {
						lastMaskV4 = bits
						fmt.Fprintf(os.Stderr, "[writeback] /%d v4 mask (%d entries)\n", bits, len(v4))
					}
				}
				break
			}
		}
	}
	if len(v6) > 0 {
		for _, bits := range []int{32, 48, 64, 128} {
			nbytes := bits / 8
			allZero := true
			for _, e := range v6 {
				for _, x := range e[nbytes:] {
					if x != 0 {
						allZero = false
						break
					}
				}
				if !allZero {
					break
				}
			}
			if allZero {
				if bits != maskBitsV6 {
					maskBitsV6 = bits
					if bits != lastMaskV6 {
						lastMaskV6 = bits
						fmt.Fprintf(os.Stderr, "[writeback] /%d v6 mask (%d entries)\n", bits, len(v6))
					}
				}
				break
			}
		}
		if maskBitsV6 > 32 {
			fmt.Fprintf(os.Stderr, "[writeback] WARNING: v6 mask /%d > /32 — BPF log only records 32 bits of dest6\n", maskBitsV6)
		}
	}
}

// maskedIP applies the current mask to an IP string.  Returns "" if not
// a valid IP.  Mirrors Python _masked_ip.
func maskedIP(s string) string {
	ip := net.ParseIP(s)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		if maskBitsV4 < 32 {
			mask := net.CIDRMask(maskBitsV4, 32)
			return ip.Mask(mask).String()
		}
		return v4.String()
	}
	if maskBitsV6 < 128 {
		mask := net.CIDRMask(maskBitsV6, 128)
		return ip.Mask(mask).String()
	}
	return ip.String()
}

// ============================================================================
// Alias canonicalization for writeback keys (bucket fix, on top of v0.9.116)
// ============================================================================

// aliasCanonicalHolder caches {from_ip → to_ip} parsed from
// /etc/bpftune/aliases (mtime-cached, same 30s stat discipline as the
// other holders in bucketing.go).
//
// NOTE: mtimeCache.get() calls markLabelsChanged() after each load. For
// the aliases file this is benign: markLabelsChanged() only sets
// staticFilesDirty when /var/lib/bpftune/aliases.labels.json's mtime has
// actually changed, which is exactly when invalidation is wanted anyway.
var aliasCanonicalHolder mtimeCache

// loadAliasCanonicalMap parses /etc/bpftune/aliases lines of the form
//
//	FROM_IP = TO_IP [label]
//
// into {normalized FROM → normalized TO}. Keys are exact IPs — this
// mirrors the running daemon's dest_alias_map (BPF_MAP_TYPE_HASH, exact
// in6_addr keys, loaded from the same file at daemon start). Lines with
// unparseable addresses are skipped. If the file is missing or empty,
// returns an empty map (writeback then behaves exactly like v0.9.116).
func loadAliasCanonicalMap() map[string]string {
	return aliasCanonicalHolder.get(aliasesFile, func(data []byte) map[string]string {
		out := map[string]string{}
		for _, raw := range strings.Split(string(data), "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			from := strings.TrimSpace(parts[0])
			fields := strings.Fields(strings.TrimSpace(parts[1]))
			if len(fields) == 0 {
				continue
			}
			to := fields[0]
			fi := net.ParseIP(from)
			if fi == nil {
				continue
			}
			ti := net.ParseIP(to)
			if ti == nil {
				continue
			}
			out[fi.String()] = ti.String()
		}
		return out
	})
}

// canonicalWritebackHost maps a raw destination IP to the SAME canonical
// bucket key the running C daemon derives at key time:
//
//  1. exact alias lookup on the raw IP      → hit: use the alias target
//  2. else mask (v4 /maskBitsV4, v6 /maskBitsV6)
//  3. alias lookup on the MASKED key       → hit: use the alias target
//  4. else the masked key
//
// Returns (host, foldKind) where foldKind is "raw" (step 1), "masked"
// (step 3) or "" (no fold). The returned host string is KEY-READY: it
// must be passed to keyArgsForExact, NOT to keyArgsFor (which would
// re-mask an alias target and break /32 canonical keys).
//
// Before the bucket fix, writeback only did step 2 — so streak
// corrections for operator-folded destinations (e.g. Cloudflare edges
// folded via /etc/bpftune/aliases) were patched into a masked key that
// the daemon never grouped under, and the corrections were lost.
func canonicalWritebackHost(rawDest string) (string, string) {
	ip := net.ParseIP(rawDest)
	if ip == nil {
		return "", ""
	}
	aliases := loadAliasCanonicalMap()
	if len(aliases) > 0 {
		if to, ok := aliases[ip.String()]; ok && to != "" {
			if ti := net.ParseIP(to); ti != nil {
				return ti.String(), "raw"
			}
		}
	}
	masked := maskedIP(rawDest)
	if masked == "" {
		return "", ""
	}
	if len(aliases) > 0 {
		if to, ok := aliases[masked]; ok && to != "" {
			if ti := net.ParseIP(to); ti != nil {
				return ti.String(), "masked"
			}
		}
	}
	return masked, ""
}

// keyArgsFor builds the 16-byte BPF key as a slice of hex strings.
// For v4: 10 zero bytes + 2 0xff bytes + 4 v4 bytes.
// For v6: 16 v6 bytes (no v4-mapped prefix).
// Returns nil if the IP is invalid.  Mirrors Python _key_args_for.
func keyArgsFor(ipStr string) []string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}
	var raw []byte
	if v4 := ip.To4(); v4 != nil {
		if maskBitsV4 < 32 {
			mask := net.CIDRMask(maskBitsV4, 32)
			v4 = v4.Mask(mask)
		}
		raw = make([]byte, 16)
		// raw[0:10] = 10 zero bytes (already zero from make)
		raw[10] = 0xff
		raw[11] = 0xff
		copy(raw[12:16], v4)
	} else {
		v6 := ip.To16()
		if maskBitsV6 < 128 {
			mask := net.CIDRMask(maskBitsV6, 128)
			v6 = v6.Mask(mask)
		}
		raw = v6
	}
	args := make([]string, 16)
	for i, b := range raw {
		args[i] = fmt.Sprintf("%02x", b)
	}
	return args
}

// keyArgsForExact builds the 16-byte BPF key from an ALREADY-CANONICAL
// host string WITHOUT applying the prefix mask. Used by the writeback
// after canonicalWritebackHost: the mask path returns an already-masked
// address (re-masking would be a no-op but is still wrong for /32 v4
// masks), and an alias target is used verbatim as the bucket key by the
// daemon, so it must never be re-masked here.
// For v4: 10 zero bytes + 2 0xff bytes + 4 v4 bytes.
// For v6: 16 v6 bytes (no v4-mapped prefix).
// Returns nil if the IP is invalid.
func keyArgsForExact(ipStr string) []string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}
	var raw []byte
	if v4 := ip.To4(); v4 != nil {
		raw = make([]byte, 16)
		raw[10] = 0xff
		raw[11] = 0xff
		copy(raw[12:16], v4)
	} else {
		raw = ip.To16()
	}
	args := make([]string, 16)
	for i, b := range raw {
		args[i] = fmt.Sprintf("%02x", b)
	}
	return args
}

// valueJSONToBytes serializes the JSON value back to the exact 1016-byte
// BPF layout.  Mirrors Python _value_json_to_bytes.  Returns nil if the
// value is malformed (size mismatch).
func valueJSONToBytes(v map[string]interface{}) []byte {
	buf := make([]byte, 0, sizeofRemoteHost)
	// 14 × u64 prefix fields (112 bytes total, offsets 0..111)
	for _, f := range prefixFields {
		buf = binary.LittleEndian.AppendUint64(buf, uint64(toInt(v[f])))
	}
	// rate_hist: 32 × u32 bins + 1 × u64 total (136 bytes, offsets 112..247)
	rate, _ := v["rate"].(map[string]interface{})
	bins, _ := rate["bins"].([]interface{})
	for i := 0; i < rateHistBins; i++ {
		var b uint32
		if i < len(bins) {
			b = uint32(toInt(bins[i]))
		}
		buf = binary.LittleEndian.AppendUint32(buf, b)
	}
	buf = binary.LittleEndian.AppendUint64(buf, uint64(toInt(rate["total"])))
	// 16 × 48-byte tcp_conn_metric slots (768 bytes, offsets 248..1015)
	metrics, _ := v["metrics"].([]interface{})
	for i := 0; i < numTCPConnMetrics; i++ {
		var m map[string]interface{}
		if i < len(metrics) {
			m, _ = metrics[i].(map[string]interface{})
		}
		if m == nil {
			m = map[string]interface{}{}
		}
		// 4 × u64 (32 bytes, offsets 0..31 within metric)
		for _, f := range metricFieldsU64 {
			buf = binary.LittleEndian.AppendUint64(buf, uint64(toInt(m[f])))
		}
		// 5 × u16 (10 bytes, offsets 32..41 within metric)
		for _, f := range metricFieldsU16 {
			buf = binary.LittleEndian.AppendUint16(buf, uint16(toInt(m[f])))
		}
		// bad_streak (u8 @ offset 42) + null_streak (u8 @ offset 43) + 4 bytes padding
		buf = append(buf, byte(toInt(m["bad_streak"])&0xff))
		buf = append(buf, byte(toInt(m["null_streak"])&0xff))
		buf = append(buf, 0, 0, 0, 0)
	}
	// 0.4.89: seq field (__u64) at end of struct -- preserve from lookup.
	// The writeback only patches bad_streak/null_streak; seq is carried
	// through unchanged, same as all other fields we don't touch.
	buf = binary.LittleEndian.AppendUint64(buf, uint64(toInt(v["seq"])))

	if len(buf) != sizeofRemoteHost {
		return nil
	}
	return buf
}

// mapLookupBytes looks up a single BPF map entry and returns the raw
// value bytes (typically 1016 bytes for remote_host_map).
// Uses the raw "value" array from bpftool --json (list of hex strings
// like "0x7c") — more reliable than re-serializing from formatted.value.
//
// CRITICAL: bpftool --json map lookup returns a SINGLE object (not a list),
// or null if the key isn't found. The old code unmarshaled as a list,
// which caused EVERY lookup to fail silently → 0 hosts patched.
//
// v0.9.86: tries the raw syscall path first (BPF_MAP_LOOKUP_ELEM), falls
// back to bpftool fork if the syscall fails (e.g., map FD can't be obtained
// or kernel doesn't support BPF_MAP_GET_FD_BY_ID).
func mapLookupBytes(mapID int, keyArgs []string) ([]byte, error) {
	// v0.9.86: try raw syscall first — ~0.01ms vs ~15ms for bpftool fork.
	if buf, err := mapLookupBytesSyscall(mapID, keyArgs); err == nil {
		return buf, nil
	}
	// Fall back to bpftool fork if syscall failed.
	args := []string{"--json", "map", "lookup", "id", strconv.Itoa(mapID), "key", "hex"}
	args = append(args, keyArgs...)
	out, err := exec.Command("bpftool", args...).Output()
	if err != nil {
		return nil, err
	}
	// bpftool --json map lookup returns a single object, not a list.
	var result map[string]interface{}
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, err
	}
	if result == nil {
		return nil, fmt.Errorf("no value (key not found)")
	}
	// Primary path: use raw value bytes (list of hex strings like "0x7c").
	// This avoids valueJSONToBytes re-serialization entirely — the bytes
	// are already in the correct BPF layout.
	rawValue, ok := result["value"].([]interface{})
	if ok && len(rawValue) > 0 {
		buf := make([]byte, len(rawValue))
		for i, v := range rawValue {
			s, _ := v.(string)
			b, err := strconv.ParseUint(s, 0, 8) // base 0 = auto-detect 0x prefix
			if err != nil {
				return nil, fmt.Errorf("value byte %d parse %q: %w", i, s, err)
			}
			buf[i] = byte(b)
		}
		return buf, nil
	}
	// Fallback: re-serialize from formatted.value (older bpftool versions)
	formatted, _ := result["formatted"].(map[string]interface{})
	if formatted == nil {
		formatted = result
	}
	val, _ := formatted["value"].(map[string]interface{})
	if val == nil {
		return nil, fmt.Errorf("no value field")
	}
	return valueJSONToBytes(val), nil
}

// v0.9.86: cached BPF map FD (file descriptor). The FD is valid until the
// map is destroyed (bpftune reload). If the FD becomes stale, the syscall
// will return EBADF and we fall back to bpftool.
var cachedMapFD int = -1

// mapLookupBytesSyscall uses BPF_MAP_LOOKUP_ELEM syscall to read a map
// entry without forking bpftool. Returns the raw value bytes.
func mapLookupBytesSyscall(mapID int, keyArgs []string) ([]byte, error) {
	// Get or refresh the map FD from the map ID.
	fd, err := getMapFD(mapID)
	if err != nil {
		return nil, err
	}

	// Convert keyArgs (hex strings like "0a", "0b") to bytes.
	key, err := hexArgsToBytes(keyArgs)
	if err != nil {
		return nil, err
	}

	// Allocate value buffer to the exact size the kernel expects.
	value := make([]byte, sizeofRemoteHost)

	// Read the map entry via raw syscall.
	if err := bpfMapLookupElem(fd, key, value); err != nil {
		// If the FD is stale (EBADF), invalidate the caches so the next
		// call re-resolves the FD and the map ID. v0.9.126 fix:
		// bpfMapLookupElem wraps the errno with %w, so the old
		// `err == unix.EBADF` was ALWAYS FALSE — after a tuner
		// restart the cached FD stayed EBADF forever and every
		// writeback forked bpftool per host per cycle. errors.Is
		// unwraps correctly.
		if errors.Is(err, unix.EBADF) {
			invalidateMapCaches()
		}
		return nil, err
	}
	return value, nil
}

// invalidateMapCaches drops the cached map FD and the cached map ID after
// an EBADF: the map was destroyed (tuner reload/restart) and both caches
// may point at the dead object. The next writeback cycle re-resolves the
// ID via `bpftool map show`. (v0.9.126 fix — the map-ID cache previously
// kept pointing at the dead map for up to 5 minutes.)
func invalidateMapCaches() {
	cachedMapFD = -1
	maskCacheMu.Lock()
	cachedMapID = -1
	mapIDCacheAt = time.Time{}
	maskCacheMu.Unlock()
}

// getMapFD resolves a BPF map ID to a file descriptor, with caching.
func getMapFD(mapID int) (int, error) {
	if cachedMapFD > 0 {
		return cachedMapFD, nil
	}
	fd, _, err := bpfMapGetFDByIDVerified(uint32(mapID), "remote_host_map")
	if err != nil {
		return -1, err
	}
	cachedMapFD = fd
	return fd, nil
}

// hexArgsToBytes converts bpftool's hex key args (like "0a", "0b", "00")
// to a raw byte slice for BPF syscalls.
func hexArgsToBytes(keyArgs []string) ([]byte, error) {
	buf := make([]byte, len(keyArgs))
	for i, s := range keyArgs {
		b, err := strconv.ParseUint(s, 0, 8)
		if err != nil {
			return nil, fmt.Errorf("key byte %d parse %q: %w", i, s, err)
		}
		buf[i] = byte(b)
	}
	return buf, nil
}

// mapUpdateBytes writes the (possibly modified) buffer back to the BPF map.
// Mirrors Python _map_update_bytes.
// v0.9.86: tries the raw syscall path first (BPF_MAP_UPDATE_ELEM), falls
// back to bpftool fork if the syscall fails.
func mapUpdateBytes(mapID int, keyArgs []string, buf []byte) bool {
	// v0.9.86: try raw syscall first.
	if mapUpdateBytesSyscall(mapID, keyArgs, buf) {
		return true
	}
	// Fall back to bpftool fork.
	args := []string{"map", "update", "id", strconv.Itoa(mapID), "key", "hex"}
	args = append(args, keyArgs...)
	args = append(args, "value", "hex")
	for _, b := range buf {
		args = append(args, fmt.Sprintf("%02x", b))
	}
	cmd := exec.Command("bpftool", args...)
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "[writeback] WARN map update failed: %v\n", err)
		return false
	}
	return true
}

// mapUpdateBytesSyscall uses BPF_MAP_UPDATE_ELEM syscall to write a map
// entry without forking bpftool. Returns true on success.
func mapUpdateBytesSyscall(mapID int, keyArgs []string, buf []byte) bool {
	fd, err := getMapFD(mapID)
	if err != nil {
		return false
	}
	key, err := hexArgsToBytes(keyArgs)
	if err != nil {
		return false
	}
	if err := bpfMapUpdateElem(fd, key, buf, 0); err != nil {
		// v0.9.126 fix: errors.Is — see mapLookupBytesSyscall.
		if errors.Is(err, unix.EBADF) {
			invalidateMapCaches()
		}
		return false
	}
	return true
}

// ============================================================================
// Streak computation
// ============================================================================

// streaksFromHistory walks the last 8 sustained outcomes (oldest→newest)
// and computes bad_streak and null_streak per the kernel's rule:
//
//	win  → reset both to 0
//	loss → bad++, null=0
//	null → null++ (does NOT reset bad — see Python comment)
//
// Both capped at 255 (uint8 overflow is implicit).
// Mirrors Python _streaks_from_history.
func streaksFromHistory(outcomes []string) (bad, null uint8) {
	for _, o := range outcomes {
		switch o {
		case "win":
			bad, null = 0, 0
		case "loss":
			bad++
			null = 0
		default: // "null" or any other value
			null++
		}
	}
	return
}

// patchStreaks writes bad_streak (offset 42) and null_streak (offset 43)
// into the metric slot for algIdx.  ONLY touches these 2 bytes —
// swap_score, rate_ema, sockets_*, prefix fields, rate_hist are
// preserved from the lookup.  Mirrors Python _patch_streaks.
func patchStreaks(buf []byte, algIdx int, bad, null uint8) {
	// D3 fix: bounds-check algIdx to prevent out-of-bounds write panic.
	// A malformed log line with to=99 would crash the entire collector.
	if algIdx < 0 || algIdx >= numTCPConnMetrics {
		return
	}
	base := offMetricsArray + (algIdx * sizeofTCPConnMetric)
	if base+offMetricNullStreak+1 > len(buf) {
		return
	}
	buf[base+offMetricBadStreak] = bad
	buf[base+offMetricNullStreak] = null
	// Explicitly DO NOT touch swap_score (offset 40) or rate_ema (38).
	// Kernel (0.4.84+) owns swap_score — see Python 0.4.86 comment.
}

// ============================================================================
// Entry point — called from collect()
// ============================================================================

// swapDestToIP converts a swapRow's dest fields to a usable IP string.
// The kernel logs v4 dest as a u32 decimal (e.g. "1378604897" = 82.37.36.1)
// and v6 dest as a u32 (first 4 bytes only).  Returns "" if no usable dest.
// WITHOUT THIS, net.ParseIP("1378604897") returns nil and ALL swaps get
// skipped at the maskedIP() call.
func swapDestToIP(sw swapRow) string {
	// Try v4 first (decimal u32 from kernel log)
	if sw.Dest != "" && sw.Dest != "0" {
		if n, err := strconv.ParseUint(sw.Dest, 10, 32); err == nil && n != 0 {
			ip := net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
			return ip.String()
		}
		// Maybe it's already dotted-quad (from cdest map fallback)
		if ip := net.ParseIP(sw.Dest); ip != nil {
			return ip.String()
		}
	}
	// Try v6 (decimal u32 = first 4 bytes of v6 addr)
	if sw.Dest6 != "" && sw.Dest6 != "0" {
		if n, err := strconv.ParseUint(sw.Dest6, 10, 32); err == nil && n != 0 {
			b := make([]byte, 16)
			b[0] = byte(n >> 24)
			b[1] = byte(n >> 16)
			b[2] = byte(n >> 8)
			b[3] = byte(n)
			return net.IP(b).String()
		}
	}
	return ""
}

// wbRow is the per-swap row used by the writeback.  Pre-computes the
// masked host and both outcomes to avoid re-computing inside the
// (host, alg) grouping loop.
type wbRow struct {
	ts        float64
	toAlg     int
	host      string // masked remote_host
	outcome   string // immediate (fallback)
	sustained string // sustained (preferred)
}

// writebackStreaks is the per-cycle entry point.  Called from collect()
// every 30s.  Takes the parsed swaps + met + srate data and patches
// bad_streak/null_streak in remote_host_map based on the sustained
// outcomes of the last 8 swaps per (host, alg) pair.
//
// Returns (hostsPatched, slotsPatched) for logging.
// Mirrors Python writeback_streaks(swaps).
func (c *Collector) writebackStreaks(swaps []swapRow, met map[int64][]metEntry, srate map[int64][]srateEntry) (int, int) {
	// TryLock: if a previous writeback is still running (rare — should
	// complete in <1s), skip this cycle rather than queuing up.
	if !writebackMu.TryLock() {
		fmt.Fprintf(os.Stderr, "[writeback] skipped (previous cycle still running)\n")
		return 0, 0
	}
	defer writebackMu.Unlock()

	mapID, err := resolveRemoteHostMapID()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[writeback] no remote_host_map: %v\n", err)
		return 0, 0
	}
	detectMask(mapID)

	// Pre-compute canonical host + both outcomes for each swap.
	// Filter to swaps that have at least one outcome (immediate OR sustained).
	// Mirrors Python: new_swaps = [s for s in swaps if s.get('outcome_sustained') or s.get('outcome')]
	var rows []wbRow
	skippedNoDest := 0
	foldsRaw, foldsMasked := 0, 0
	for _, sw := range swaps {
		rawDest := swapDestToIP(sw)
		if rawDest == "" {
			skippedNoDest++
			continue
		}
		h, foldKind := canonicalWritebackHost(rawDest)
		if h == "" {
			continue
		}
		switch foldKind {
		case "raw":
			foldsRaw++
		case "masked":
			foldsMasked++
		}
		o := outcomeComposite(met, sw.Cookie, sw.Ts)
		o3 := outcomeSustained(srate, sw.Cookie, sw.Ts)
		if o == "" && o3 == "" {
			continue
		}
		rows = append(rows, wbRow{
			ts:        sw.Ts,
			toAlg:     sw.To,
			host:      h,
			outcome:   o,
			sustained: o3,
		})
	}
	if skippedNoDest > 0 {
		fmt.Fprintf(os.Stderr, "[writeback] %d swaps skipped (no remote_host)\n", skippedNoDest)
	}
	if foldsRaw > 0 || foldsMasked > 0 {
		fmt.Fprintf(os.Stderr, "[writeback] alias fold: %d raw + %d masked hits this cycle\n", foldsRaw, foldsMasked)
	}
	if len(rows) == 0 {
		return 0, 0
	}

	// Group by host (masked remote_host).
	byHost := map[string][]wbRow{}
	for _, r := range rows {
		byHost[r.host] = append(byHost[r.host], r)
	}

	totalHosts, totalSlots := 0, 0
	for host, hostRows := range byHost {
		// host is key-ready (already aliased and/or masked) — see
		// canonicalWritebackHost. Use the exact builder so alias
		// targets are not re-masked.
		keyArgs := keyArgsForExact(host)
		if keyArgs == nil {
			continue
		}

		// Lookup current value (1 BPF map lookup per host).
		buf, err := mapLookupBytes(mapID, keyArgs)
		if err != nil {
			continue
		}
		if buf == nil || len(buf) != sizeofRemoteHost {
			fmt.Fprintf(os.Stderr, "[writeback] WARN: %s buf %d!=%d; skip\n", host, len(buf), sizeofRemoteHost)
			continue
		}

		// Find unique algs in this host's swaps.
		algSet := map[int]bool{}
		for _, r := range hostRows {
			algSet[r.toAlg] = true
		}

		patches := 0
		for algIdx := range algSet {
			// Take last writebackWindow swaps with sustained outcome for (host, alg).
			// Mirrors Python:
			//   recent = sorted([s for s in swaps
			//                    if masked_ip(s.remote_host)==host
			//                    and s.to_alg==alg_idx
			//                    and s.outcome_sustained], by ts)[-8:]
			var recent []wbRow
			for _, r := range hostRows {
				if r.toAlg != algIdx {
					continue
				}
				if r.sustained == "" {
					continue
				}
				recent = append(recent, r)
			}
			if len(recent) == 0 {
				continue
			}

			// Sort by ts ascending (oldest first).
			sort.Slice(recent, func(i, j int) bool { return recent[i].ts < recent[j].ts })

			// Take last writebackWindow (most recent 8).
			if len(recent) > writebackWindow {
				recent = recent[len(recent)-writebackWindow:]
			}

			// Compute streaks from the outcomes.
			outcomes := make([]string, len(recent))
			for i, r := range recent {
				outcomes[i] = r.sustained
			}
			bad, null := streaksFromHistory(outcomes)

			// Patch the 2 bytes for this alg slot.
			patchStreaks(buf, algIdx, bad, null)
			patches++
		}

		if patches == 0 {
			continue
		}

		// C1-fix: re-lookup the buffer immediately before writeback and
		// compare the seq field. The kernel increments seq on every update
		// to the remote_host entry. If seq changed between the original
		// lookup (T0) and now (T1), the kernel has updated metric_count /
		// rate_ema / swap_score / etc. in the meantime, and writing back
		// our stale buf would clobber those updates.
		freshBuf, err := mapLookupBytes(mapID, keyArgs)
		if err != nil || len(freshBuf) != sizeofRemoteHost {
			fmt.Fprintf(os.Stderr, "[writeback] WARN: %s re-lookup failed; skip\n", host)
			continue
		}
		origSeq := binary.LittleEndian.Uint64(buf[sizeofRemoteHost-sizeofSeqField:])
		freshSeq := binary.LittleEndian.Uint64(freshBuf[sizeofRemoteHost-sizeofSeqField:])
		if skip, why := writebackSeqCheck(origSeq, freshSeq); skip {
			fmt.Fprintf(os.Stderr, "[writeback] %s %s; skip\n", host, why)
			continue
		}
		// Copy our 2-byte streak patches into the fresh buffer so we don't
		// lose any other kernel-side updates that happened between T0 and T1.
		for algIdx := range algSet {
			base := offMetricsArray + (algIdx * sizeofTCPConnMetric)
			if base+offMetricNullStreak+1 > len(freshBuf) || base+offMetricNullStreak+1 > len(buf) {
				continue
			}
			freshBuf[base+offMetricBadStreak] = buf[base+offMetricBadStreak]
			freshBuf[base+offMetricNullStreak] = buf[base+offMetricNullStreak]
		}
		buf = freshBuf

		// Write back the modified buffer (1 BPF map update per host).
		if mapUpdateBytes(mapID, keyArgs, buf) {
			totalHosts++
			totalSlots += patches
			fmt.Fprintf(os.Stderr, "[writeback] %s: patched %d alg slots\n", host, patches)
		}
	}

	if totalHosts > 0 {
		fmt.Fprintf(os.Stderr, "[writeback] done: %d hosts, %d algorithm slots corrected (processed %d swaps)\n",
			totalHosts, totalSlots, len(rows))
	}
	return totalHosts, totalSlots
}

// writebackSeqCheck decides whether the C1 re-lookup must abort the
// writeback for this host. v0.9.126 fix: adds the odd-seq torn-read guard —
// the kernel seq-wraps every multi-field update (__sync_fetch_and_add(&seq,1)
// before AND after), so an odd freshSeq means the re-lookup landed mid-update
// and freshBuf is torn. The daemon's own userspace readers skip on odd seq
// (tcp_conn_tuner.c, "BPF mid-update"); the writeback must too, or we graft
// the 2 patch bytes onto a torn buffer and persist it. Returns (skip, reason).
func writebackSeqCheck(origSeq, freshSeq uint64) (bool, string) {
	if origSeq != freshSeq {
		return true, fmt.Sprintf("seq changed (%d → %d); kernel updated mid-cycle", origSeq, freshSeq)
	}
	if freshSeq&1 == 1 {
		return true, fmt.Sprintf("seq %d odd (kernel mid-update; torn read)", freshSeq)
	}
	return false, ""
}
