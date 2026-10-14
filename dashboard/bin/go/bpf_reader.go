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
        "encoding/json"
        "context"
        "fmt"
        "strings"
        "time"
        "os/exec"
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
        Inst      int
        MaxInst   int    // B3-fix: largest single inst across folded entries
        Addr      string // labeled + merged (e.g. "home-sco" or "2606:1a40::")
        V         map[string]interface{}
        V4MinRTT  float64 // v0.9.38: separate v4 min_rtt (microseconds)
        V6MinRTT  float64 // v0.9.38: separate v6 min_rtt (microseconds)
        V4Inst    int     // v0.9.38: v4-only instance count
        V6Inst    int     // v0.9.38: v6-only instance count
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
        // v0.9.33: check if the map size changed since last call.
        // If CacheBPFMap is enabled and the size is the same, return cache.
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
                        b[i] = toInt(v)  // v0.9.25: safe type assertion (was int(v.(float64)) which panics on nil)
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
                } else {
                        he := &hostEntry{Inst: inst, MaxInst: inst, Addr: final, V: val}
                        if isV6 {
                                he.V6Inst = inst
                                if rttUs > 0 { he.V6MinRTT = rttUs }
                        } else {
                                he.V4Inst = inst
                                if rttUs > 0 { he.V4MinRTT = rttUs }
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
