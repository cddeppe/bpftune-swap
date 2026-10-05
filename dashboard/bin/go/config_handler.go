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
				changed = append(changed, "explore_pct")
			}
		}

		if v, ok := req["proof_good_bps"]; ok {
			n := toInt(v)
			if n > 0 {
				os.WriteFile(proofGoodBpsPath, []byte(fmt.Sprintf("%d", n)), 0644)
				exec.Command("bpftool", "map", "update", "pinned",
					"/sys/fs/bpf/bpftune/tcp_conn/explore",
					"key", "hex", "04 00 00 00",
					"value", "hex", fmt.Sprintf("%02x %02x %02x %02x",
						byte(n), byte(n>>8), byte(n>>16), byte(n>>24))).Run()
				changed = append(changed, "proof_good_bps")
			}
		}
		if v, ok := req["proof_proved_bps"]; ok {
			n := toInt(v)
			if n > 0 {
				os.WriteFile(proofProvedBpsPath, []byte(fmt.Sprintf("%d", n)), 0644)
				exec.Command("bpftool", "map", "update", "pinned",
					"/sys/fs/bpf/bpftune/tcp_conn/explore",
					"key", "hex", "05 00 00 00",
					"value", "hex", fmt.Sprintf("%02x %02x %02x %02x",
						byte(n), byte(n>>8), byte(n>>16), byte(n>>24))).Run()
				changed = append(changed, "proof_proved_bps")
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

		// Restart bpftune to pick up new config values (reads file on startup)
		if len(changed) > 0 {
			exec.Command("systemctl", "restart", "bpftune").Run()
		}

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
