package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

var (
	proofGoodBpsPath   = "/var/lib/bpftune/proof_good_bps"
	proofProvedBpsPath = "/var/lib/bpftune/proof_proved_bps"
)

// tuner_config_map pin paths. v0.9.126 fix: the daemon pins at
// /sys/fs/bpf/bpftune/tcp_conn/explore (src/tcp_conn_tuner.c EXPLORE_PIN_DIR,
// since 0.4.64). The dashboard previously used /sys/fs/bpftune/... — never
// this daemon's pin location — so EVERY live map update silently failed.
// The legacy path is kept as a fallback probe for forks/older tuners.
const (
	tunerConfigPinMain   = "/sys/fs/bpf/bpftune/tcp_conn/explore"
	tunerConfigPinLegacy = "/sys/fs/bpftune/tcp_conn/explore"
)

// updateTunerConfigSlotLive writes tuner_config_map[slot] = value via
// `bpftool map update pinned` (slot 0 = explore_pct, 4 = proof_good_bps,
// 5 = proof_proved_bps; the map has 6 entries since tuner 0.4.91).
// Tries the real pin path first, then the legacy one. Returns nil on
// success at either path.
func updateTunerConfigSlotLive(slot uint32, value uint32) error {
	hexWord := fmt.Sprintf("%02x %02x %02x %02x",
	byte(value), byte(value>>8), byte(value>>16), byte(value>>24))
	keyWord := fmt.Sprintf("%02x %02x %02x %02x",
	byte(slot), byte(slot>>8), byte(slot>>16), byte(slot>>24))
	var lastErr error
	for _, pin := range []string{tunerConfigPinMain, tunerConfigPinLegacy} {
	if _, err := os.Stat(pin); err != nil {
		continue
	}
	cmd := exec.Command("bpftool", "map", "update", "pinned", pin,
		"key", "hex", keyWord, "value", "hex", hexWord)
	if err := cmd.Run(); err == nil {
		return nil
	} else {
		lastErr = err
	}
	}
	if lastErr == nil {
	lastErr = fmt.Errorf("tuner_config_map pin not found (tried %s and %s)",
		tunerConfigPinMain, tunerConfigPinLegacy)
	}
	return lastErr
}

// ============================================================================
// /api/config handler — read/write prefix4, prefix6, explore_pct
// Values persist to /var/lib/bpftune/{prefix4,prefix6,explore_pct}
// BPF map updated via bpftool for live effect on next ESTABLISHED.
// ============================================================================

func (c *Collector) handleConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method == "GET" {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"prefix4":          prefix4Value(),
			"prefix6":          prefix6Value(),
			"explore_pct":      explorePctValue(),
			"proof_good_bps":   proofGoodBpsValue(),
			"proof_proved_bps": proofProvedBpsValue(),
		})
		return
	}

	if r.Method == "POST" {
		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
			return
		}

		changed := []string{}

		if v, ok := req["prefix4"]; ok {
			n := toInt(v)
			if n >= 1 && n <= 32 {
				os.WriteFile(prefix4Path, []byte(fmt.Sprintf("%d", n)), 0644)
				changed = append(changed, "prefix4")
			}
		}

		if v, ok := req["prefix6"]; ok {
			n := toInt(v)
			if n >= 1 && n <= 128 {
				os.WriteFile(prefix6Path, []byte(fmt.Sprintf("%d", n)), 0644)
				changed = append(changed, "prefix6")
			}
		}

		if v, ok := req["explore_pct"]; ok {
			n := toInt(v)
			if n >= 0 && n <= 100 {
				os.WriteFile(explorePctPath, []byte(fmt.Sprintf("%d", n)), 0644)
				// v0.9.22: update BPF map LIVE (key=0, no daemon restart).
				// The old code restarted bpftune, disrupting all sockets.
				// Now the BPF program reads tuner_config_map[0] on every
				// ESTABLISHED callback, so the change takes effect immediately
				// on the next connection.
				// v0.9.25: check for errors instead of silently ignoring
				// v0.9.126 fix: correct pin path (see updateTunerConfigSlotLive).
				if err := updateTunerConfigSlotLive(0, uint32(n)); err == nil {
					changed = append(changed, "explore_pct")
				} else {
					changed = append(changed, "explore_pct (file only, BPF map update failed)")
				}
			}
		}

		// v0.9.126 fix: proof_good_bps and proof_proved_bps are now
		// ALSO written live to tuner_config_map slots 4 and 5. The old
		// comment claimed the map had max_entries=1 — that predates
		// tuner 0.4.91, which expanded it to 6 entries (slot 0 =
		// exp_pct, 1 = prefix4, 2 = prefix6, 3 = bpf_debug, 4 =
		// proof_good_bps, 5 = proof_proved_bps) and added live BPF
		// readers (get_proof_good_bps/get_proof_proved_bps). The
		// daemon never reads the /var/lib/bpftune/proof_* files, so
		// until now changing proof thresholds in the UI silently did
		// nothing to tuner decisions. Files are still written for
		// persistence and re-sync after daemon restarts.
		if v, ok := req["proof_good_bps"]; ok {
			n := toInt(v)
			if n > 0 {
				os.WriteFile(proofGoodBpsPath, []byte(fmt.Sprintf("%d", n)), 0644)
				if err := updateTunerConfigSlotLive(4, uint32(n)); err == nil {
					changed = append(changed, "proof_good_bps")
				} else {
					changed = append(changed, "proof_good_bps (file only, BPF map update failed)")
				}
			}
		}
		if v, ok := req["proof_proved_bps"]; ok {
			n := toInt(v)
			if n > 0 {
				os.WriteFile(proofProvedBpsPath, []byte(fmt.Sprintf("%d", n)), 0644)
				if err := updateTunerConfigSlotLive(5, uint32(n)); err == nil {
					changed = append(changed, "proof_proved_bps")
				} else {
					changed = append(changed, "proof_proved_bps (file only, BPF map update failed)")
				}
			}
		}
		// Invalidate mtime caches
		prefix4Holder.mu.Lock()
		prefix4Holder.mtime = time.Time{}
		prefix4Holder.mu.Unlock()
		prefix6Holder.mu.Lock()
		prefix6Holder.mtime = time.Time{}
		prefix6Holder.mu.Unlock()
		explorePctHolder.mu.Lock()
		explorePctHolder.mtime = time.Time{}
		explorePctHolder.mu.Unlock()

		// v0.9.22: do NOT restart bpftune — it disrupts all TCP sockets.
		// explore_pct is now updated live via bpftool (see above).
		// prefix4/prefix6 take effect on next bpftune restart (reboot/maintenance).

		// Invalidate static files
		staticFilesDirtyMu.Lock()
		staticFilesDirty = true
		staticFilesDirtyMu.Unlock()

		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":               true,
			"changed":          changed,
			"prefix4":          prefix4Value(),
			"prefix6":          prefix6Value(),
			"explore_pct":      explorePctValue(),
			"proof_good_bps":   proofGoodBpsValue(),
			"proof_proved_bps": proofProvedBpsValue(),
		})
		return
	}

	http.NotFound(w, r)
}

func proofGoodBpsValue() int {
	data, err := os.ReadFile(proofGoodBpsPath)
	if err != nil {
		return 3750000
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	if n <= 0 {
		return 3750000
	}
	return n
}

func proofProvedBpsValue() int {
	data, err := os.ReadFile(proofProvedBpsPath)
	if err != nil {
		return 12500000
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	if n <= 0 {
		return 12500000
	}
	return n
}
