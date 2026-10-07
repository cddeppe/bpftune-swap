package main

// history.go — multi-level in-memory ring buffer for historical
// time-series data.  Replaces the Python renderer + SQLite + CSV.
//
// Architecture:
//   - Every 30s collect cycle: capture a bucketSnapshot per bucket
//   - Multi-level ring buffer:
//       raw:     last 24h at 30s intervals (2880 entries) → serves 1h + 24h
//       bin5m:   last 24h at 5min intervals (288 entries)  → 24h fallback
//       bin1h:   last 7d at 1h intervals (168 entries)     → serves 7d
//       bin6h:   last 30d at 6h intervals (120 entries)     → serves "all"
//   - HTTP handlers + render-to-disk functions live in render.go and
//     http_handlers.go (extracted from this file in v0.7.0).
//
// On restart, loadCSVTailIntoRingBuffer() reads the last 24h of CSV
// into the raw ring buffer so 1h/24h charts work immediately.

import (
        "sync"
        "time"
)

// ============================================================================
// Snapshot types
// ============================================================================

// v0.7.2: arrays instead of maps — saves ~1.5GB memory on 104-bucket hosts.
// Each map has ~150 bytes overhead; 1.5M maps × 150B = 225MB just for empty
// map headers.  Arrays are inline in the struct — zero overhead.
type bucketSnapshot struct {
        Ts         int64       `json:"ts"` // wall-clock collected_ts
        BestAlg    string      `json:"best_alg"`
        BestI      int         `json:"best_i"`
        Instances  int         `json:"instances"`
        RefRate    float64     `json:"ref_rate"`
        MinRtt     float64     `json:"min_rtt"`
        RateBestI  int         `json:"rate_best_i"`
        RateBestV  float64     `json:"rate_best_v"`
        TcpRmemMax int         `json:"tcp_rmem_max"`
        Re         [16]float64 `json:"re"` // rate_ema per alg index
        Ss         [16]int     `json:"ss"` // swap_score per alg index
        Bs         [16]int     `json:"bs"` // bad_streak per alg index
        Ns         [16]int     `json:"ns"` // null_streak per alg index
        Mv         [16]float64 `json:"mv"` // metric_value per alg index
}

// historyStore is the ring buffer.  v0.7.3: single level (raw only).
// 24h/7d/all charts are served from static files (renderToDisk reads CSV).
type historyStore struct {
        mu         sync.RWMutex
        raw        map[string][]bucketSnapshot // bucketID → last ringCap snapshots (1h)
        cycleCount int
        // v0.7.3: csvAll is loaded once per renderToDisk cycle, then freed.
        // This avoids holding the 47MB CSV in memory permanently.
        csvAll map[string][]bucketSnapshot
        // v0.7.5p: streamed series for slow ranges (7d/30d/all).
        // Set by renderSlowToDisk via streamCSVToSeries(), then freed.
        // renderBucketToDisk uses this instead of readBucketCSVFromMap.
        streamedSeries map[string]map[string]map[string]interface{}
}

// ringCap is the ring buffer size.  Default 120 = 1h at 30s intervals.
// Configurable via --ring-cap flag.
var ringCap = 120

var hist = &historyStore{
        raw: map[string][]bucketSnapshot{},
}

// ============================================================================
// addSnapshot — called every 30s collect cycle
// ============================================================================

func (h *historyStore) addSnapshot(bucketID string, snap bucketSnapshot) {
        h.mu.Lock()
        defer h.mu.Unlock()

        // v0.7.3: ring buffer cap = 120 (1h at 30s).  24h/7d/all charts read
        // from CSV via static files (rendered every 5 min by renderToDisk).
        // This cuts memory from ~220MB to ~9MB for the ring buffer.
        h.raw[bucketID] = append(h.raw[bucketID], snap)
        if len(h.raw[bucketID]) > ringCap {
                h.raw[bucketID] = h.raw[bucketID][len(h.raw[bucketID])-ringCap:]
        }

        h.cycleCount++

        // v0.7.3: save to disk every 10 cycles (5 min) for crash recovery.
        // No more bin5m/bin1h/bin6h — those were for 24h/7d/all which now
        // come from CSV.
}

// aggregateSnapshots averages a list of snapshots into a single bin.
func aggregateSnapshots(snaps []bucketSnapshot) bucketSnapshot {
        if len(snaps) == 0 {
                return bucketSnapshot{}
        }
        if len(snaps) == 1 {
                return snaps[0]
        }
        // v0.7.2: arrays are zero-valued by default — no init needed
        out := bucketSnapshot{
                BestAlg:    snaps[len(snaps)-1].BestAlg,
                BestI:      snaps[len(snaps)-1].BestI,
                TcpRmemMax: snaps[len(snaps)-1].TcpRmemMax,
        }
        var sumTs int64
        var sumInst, sumRBI int
        var sumRR, sumMinRtt, sumRBV float64
        for _, s := range snaps {
                sumTs += s.Ts
                sumInst += s.Instances
                sumRBI += s.RateBestI
                sumRR += s.RefRate
                sumMinRtt += s.MinRtt
                sumRBV += s.RateBestV
                // v0.7.2: array index instead of map key
                for i := 0; i < 16; i++ {
                        out.Re[i] += s.Re[i]
                        out.Ss[i] += s.Ss[i]
                        out.Bs[i] += s.Bs[i]
                        out.Ns[i] += s.Ns[i]
                        out.Mv[i] += s.Mv[i]
                }
        }
        n := len(snaps)
        out.Ts = sumTs / int64(n)
        out.Instances = sumInst / n
        out.RateBestI = sumRBI / n
        out.RefRate = sumRR / float64(n)
        out.MinRtt = sumMinRtt / float64(n)
        out.RateBestV = sumRBV / float64(n)
        // v0.7.2: divide arrays by n
        for i := 0; i < 16; i++ {
                out.Re[i] /= float64(n)
                out.Ss[i] /= n
                out.Bs[i] /= n
                out.Ns[i] /= n
                out.Mv[i] /= float64(n)
        }
        return out
}

// ============================================================================
// RANGES — mirrors Python renderer RANGES dict
// ============================================================================

// v0.7.4: five ranges. 1h+24h are "fast" (every 5 min). 7d+30d+all are
// "slow" (daily at 4am).  "all" = full history, never pruned.
var ranges = map[string][2]interface{}{
        "1h":  {3600, 60},          // 1h, 60s bins
        "24h": {86400, 300},        // 24h, 5min bins
        "7d":  {7 * 86400, 3600},   // 7d, 1h bins
        "30d": {30 * 86400, 3600},  // 30d, 1h bins
        "all": {90 * 86400, 86400}, // 90 days, 24h bins (lightweight overview)
}

// isFastRange returns true for ranges that update every 5 min (1h, 24h).
// Slow ranges (7d, 30d, all) only update at 4am daily.
func isFastRange(rng string) bool {
        return rng == "1h" || rng == "24h"
}

// ============================================================================
// captureSnapshotsFromBPF builds bucketSnapshot entries from the BPF
// map data and adds them to the history store.  Called once per collect
// cycle.  Save to disk every 10 cycles (5 min).
// ============================================================================

func captureSnapshotsFromBPF(hosts []hostEntry, now int64) {
        for _, h := range hosts {
                if h.Inst < 2 {
                        continue
                }
                // v0.7.2: arrays are zero-valued by default — no init needed
                snap := bucketSnapshot{
                        Ts:        now,
                        BestAlg:   "",
                        Instances: h.Inst,
                }
                v := h.V
                metrics, _ := v["metrics"].([]interface{})
                bestI := toInt(v["best_i"])
                if bestI >= 0 && bestI < len(CONGS) {
                        snap.BestAlg = CONGS[bestI]
                }
                snap.BestI = bestI
                snap.RefRate = toFloat(v["max_rate_delivered"]) / bpsToMbps
                snap.MinRtt = toFloat(v["min_rtt"])
                for i, m := range metrics {
                        if i >= len(CONGS) || i >= 16 {
                                break
                        }
                        mi, ok := m.(map[string]interface{})
                        if !ok {
                                continue
                        }
                        // v0.7.2: array index instead of map key
                        snap.Re[i] = toFloat(mi["rate_ema"])
                        snap.Ss[i] = toInt(mi["swap_score"])
                        snap.Bs[i] = toInt(mi["bad_streak"])
                        snap.Ns[i] = toInt(mi["null_streak"])
                        snap.Mv[i] = toFloat(mi["metric_value"])
                }
                hist.addSnapshot(h.Addr, snap)
        }

        // v0.9.9: prune dead buckets — remove ring buffer entries for hosts
        // that haven't been seen in the BPF map for 5 cycles (~2.5 min).
        // This prevents the ring buffer from accumulating entries for
        // hundreds of dead hosts over weeks of operation.
        if hist.cycleCount%5 == 0 {
                hist.pruneDeadBuckets(hosts)
        }

        if hist.cycleCount%10 == 0 {
                hist.saveToDisk()
        }
}

// pruneDeadBuckets removes ring buffer entries for bucket IDs that are
// not in the current hosts list and haven't had a snapshot in the last
// 5 cycles. This frees memory and speeds up ring buffer iteration.
func (h *historyStore) pruneDeadBuckets(hosts []hostEntry) {
        alive := make(map[string]bool, len(hosts))
        for _, h := range hosts {
                alive[h.Addr] = true
        }
        h.mu.Lock()
        defer h.mu.Unlock()
        for bucketID, snaps := range h.raw {
                if alive[bucketID] {
                        continue
                }
                // Keep if last snapshot is recent (< 5 min)
                if len(snaps) > 0 {
                        last := snaps[len(snaps)-1].Ts
                        if time.Now().Unix()-last < 300 {
                                continue
                        }
                }
                delete(h.raw, bucketID)
        }
}

// ============================================================================
// Disk persistence — save/load ring buffer to survive restarts
// ============================================================================

func (h *historyStore) saveToDisk() {
        h.mu.RLock()
        defer h.mu.RUnlock()

        path := historyPath("collector-go-history.json")
        writeFileAtomic(path, func() []byte {
                type persistData struct {
                        Raw map[string][]bucketSnapshot `json:"raw"`
                }
                data := persistData{Raw: h.raw}
                out, _ := jsonMarshal(data)
                return out
        })
}

func (h *historyStore) loadFromDisk() {
        h.mu.Lock()
        defer h.mu.Unlock()

        path := historyPath("collector-go-history.json")
        data, err := readFile(path)
        if err != nil {
                return
        }
        type persistData struct {
                Raw map[string][]bucketSnapshot `json:"raw"`
        }
        var pd persistData
        if err := jsonUnmarshal(data, &pd); err != nil {
                return
        }
        if pd.Raw != nil {
                h.raw = pd.Raw
        }
}
