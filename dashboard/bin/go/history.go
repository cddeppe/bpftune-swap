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
//
// v0.9.111 (measured on al): the ring now holds ONLY selectable buckets
// (top-8 table buckets + labeled — the set the charts can display).
// Previously it held entries for ALL BPF-map hosts (324 on al) and:
//   - saveToDisk() marshaled the whole ring every 10 cycles: a 13MB
//     JSON marshal + 13MB file write every 5 min (profile: 26.8MB of
//     cumulative churn, the #2 allocator)
//   - ~20MB of ring backing arrays sat live for buckets that no chart,
//     panel or endpoint can read (dashboard.js only ever requests
//     selectable buckets — see buildSelectable in collect.go)
// Non-selectable entries (including CSV history loaded at startup) are
// dropped on the next capture cycle.

import (
        "sync"
        "time"
)

// ============================================================================
// Snapshot types
// ============================================================================

// v0.7.2: arrays instead of maps — saves ~1.5GB memory on 104-bucket hosts.
// v0.9.96: Ss/Bs/Ns are int16 (swap_score 0-1024, streaks 0-255).
// IMPORTANT: aggregation MUST be done in int (not int16) — see aggregateSnapshots.
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
        Ss         [16]int16   `json:"ss"` // v0.9.96: was [16]int
        Bs         [16]int16   `json:"bs"` // v0.9.96: was [16]int
        Ns         [16]int16   `json:"ns"` // v0.9.96: was [16]int
        Mv         [16]float64 `json:"mv"` // metric_value per alg index
}

// historyStore is the ring buffer.  v0.7.3: single level (raw only).
// 24h/7d/all charts are served from static files (renderToDisk reads CSV).
type historyStore struct {
        mu         sync.RWMutex
        raw        map[string][]bucketSnapshot // bucketID → last ringCap snapshots (1h)
        cycleCount int
        // v0.7.3: csvAll is loaded once per renderToDisk cycle, then freed.
        csvAll map[string][]bucketSnapshot
        // v0.7.5p: streamed series for slow ranges (7d/30d/all).
        streamedSeries map[string]map[string]map[string]interface{}
}

// ringCap is the ring buffer size.  Default 120 = 1h at 30s intervals.
// Configurable via --ring-cap flag.
var ringCap = 120

// ringSelectable — v0.9.111: when non-nil, captureSnapshotsFromBPF keeps
// ring entries ONLY for these bucket keys and drops everything else.
// Set by collect() each cycle (buildSelectable); nil = keep all (tests).
// Accessed only from the collect goroutine.
var ringSelectable map[string]bool

var hist = &historyStore{
        raw: map[string][]bucketSnapshot{},
}

// ============================================================================
// addSnapshot — called every 30s collect cycle
// ============================================================================

func (h *historyStore) addSnapshot(bucketID string, snap bucketSnapshot) {
        h.mu.Lock()
        defer h.mu.Unlock()

        // v0.7.3: ring buffer cap = 120 (1h at 30s).
        h.raw[bucketID] = append(h.raw[bucketID], snap)
        if len(h.raw[bucketID]) > ringCap {
                s := h.raw[bucketID][len(h.raw[bucketID])-ringCap:]
                // v0.9.109: compact when the backing array has drifted far
                // ahead of the visible window (bounds retained dead copies).
                if cap(s) > 2*ringCap {
                        ns := make([]bucketSnapshot, ringCap)
                        copy(ns, s)
                        s = ns
                }
                h.raw[bucketID] = s
        }
}

// aggregateSnapshots averages a list of snapshots into a single bin.
func aggregateSnapshots(snaps []bucketSnapshot) bucketSnapshot {
        if len(snaps) == 0 {
                return bucketSnapshot{}
        }
        if len(snaps) == 1 {
                return snaps[0]
        }
        out := bucketSnapshot{
                BestAlg:    snaps[len(snaps)-1].BestAlg,
                BestI:      snaps[len(snaps)-1].BestI,
                TcpRmemMax: snaps[len(snaps)-1].TcpRmemMax,
        }
        var sumTs int64
        var sumInst, sumRBI int
        var sumRR, sumMinRtt, sumRBV float64
        // v0.9.96: sum in int to avoid int16 overflow.
        var sumSs, sumBs, sumNs [16]int
        for _, s := range snaps {
                sumTs += s.Ts
                sumInst += s.Instances
                sumRBI += s.RateBestI
                sumRR += s.RefRate
                sumMinRtt += s.MinRtt
                sumRBV += s.RateBestV
                for i := 0; i < 16; i++ {
                        out.Re[i] += s.Re[i]
                        sumSs[i] += int(s.Ss[i])
                        sumBs[i] += int(s.Bs[i])
                        sumNs[i] += int(s.Ns[i])
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
        for i := 0; i < 16; i++ {
                out.Re[i] /= float64(n)
                out.Ss[i] = int16(sumSs[i] / n)
                out.Bs[i] = int16(sumBs[i] / n)
                out.Ns[i] = int16(sumNs[i] / n)
                out.Mv[i] /= float64(n)
        }
        return out
}

// ============================================================================
// RANGES — mirrors Python renderer RANGES dict
// ============================================================================

var ranges = map[string][2]interface{}{
        "1h":  {3600, 60},          // 1h, 60s bins
        "24h": {86400, 300},        // 24h, 5min bins
        "7d":  {7 * 86400, 3600},   // 7d, 1h bins
        "30d": {30 * 86400, 3600},  // 30d, 1h bins
        "all": {90 * 86400, 86400}, // 90 days, 24h bins
}

// isFastRange returns true for ranges that update every 5 min (1h, 24h).
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
                // v0.9.111: only selectable buckets enter the ring (see
                // ringSelectable). Non-selectable hosts' series are read
                // by no chart/panel/endpoint.
                if ringSelectable != nil && !ringSelectable[h.Addr] {
                        continue
                }
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
                        snap.Re[i] = toFloat(mi["rate_ema"])
                        snap.Ss[i] = int16(toInt(mi["swap_score"]))
                        snap.Bs[i] = int16(toInt(mi["bad_streak"]))
                        snap.Ns[i] = int16(toInt(mi["null_streak"]))
                        snap.Mv[i] = toFloat(mi["metric_value"])
                }
                hist.addSnapshot(h.Addr, snap)
        }

        // v0.9.111: converge — drop ring entries outside the selectable
        // set (clears CSV history loaded at startup and stale labels).
        if ringSelectable != nil {
                hist.mu.Lock()
                for k := range hist.raw {
                        if !ringSelectable[k] {
                                delete(hist.raw, k)
                        }
                }
                hist.mu.Unlock()
        }

        // v0.9.9: prune dead buckets (not seen in the BPF map for 5 cycles).
        hist.cycleCount++  // v0.9.25: increment once per cycle (was per-snapshot)
        if hist.cycleCount%5 == 0 {
                hist.pruneDeadBuckets(hosts)
        }

        if hist.cycleCount%10 == 0 {
                hist.saveToDisk()
        }
}

// pruneDeadBuckets removes ring buffer entries for bucket IDs that are
// not in the current hosts list and haven't had a snapshot in the last
// 5 cycles.
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
