package main

// route_health.go — builds per-bucket route health data for the dashboard.
//
// For each bucket, extracts:
//   - rtt_ms: minimum RTT in milliseconds
//   - loss_pct: estimated loss percentage from bad_streak + null_streak
//   - rate_mbps: best rate_ema across algorithms
//   - protocol: "ipv4", "ipv6", or "dual"
//   - health: "good", "degraded", or "bad"
//
// The dashboard renders this as a compact health bar under the Swap Target
// Pick chart, following the same bucket/range selectors.

import (
        "fmt"
        "strings"
)

// routeHealthEntry is the per-bucket health data.
type routeHealthEntry struct {
        RTTMs    float64 `json:"rtt_ms"`
        LossPct  float64 `json:"loss_pct"`
        RateMbps float64 `json:"rate_mbps"`
        Protocol string  `json:"protocol"`  // "ipv4", "ipv6", "dual"
        Health   string  `json:"health"`     // "good", "degraded", "bad"
        BestAlg  string  `json:"best_alg"`
        Inst     int     `json:"inst"`
}

// buildRouteHealth creates a map of bucketID → routeHealthEntry from the
// live BPF map data. Called once per collect cycle.
func buildRouteHealth(hosts []hostEntry, metricByBucket map[string]interface{}) map[string]interface{} {
        out := map[string]interface{}{}

        for _, h := range hosts {
                if h.Inst < 2 {
                        continue
                }
                addr := h.Addr
                if addr == "" || addr == "0.0.0.1" || addr == "?" {
                        continue
                }
                if strings.HasPrefix(addr, "127.") ||
                        strings.HasPrefix(addr, "169.254.") ||
                        strings.HasPrefix(addr, "0.") {
                        continue
                }

                v := h.V
                rttUs := toFloat(v["min_rtt"])
                rttMs := rttUs / 1000.0

                // Determine protocol from address format
                protocol := "ipv4"
                if strings.HasPrefix(addr, "v6:") || strings.Contains(addr, ":") {
                        protocol = "ipv6"
                }

                // Aggregate loss from metric_by_bucket
                mbRows, _ := metricByBucket[addr].([]interface{})
                maxBadStreak := 0
                maxNullStreak := 0
                bestRateEma := 0
                for _, row := range mbRows {
                        mi, _ := row.(map[string]interface{})
                        if mi == nil {
                                continue
                        }
                        bs := toInt(mi["bad_streak"])
                        ns := toInt(mi["null_streak"])
                        if bs > maxBadStreak {
                                maxBadStreak = bs
                        }
                        if ns > maxNullStreak {
                                maxNullStreak = ns
                        }
                        re := toInt(mi["rate_ema"])
                        if re > bestRateEma {
                                bestRateEma = re
                        }
                }

                // Estimate loss percentage from streaks.
                // bad_streak + null_streak = consecutive bad/null outcomes.
                // Map to a rough percentage: 0 streaks = 0%, 5+ = 20%+
                lossPct := float64(maxBadStreak*4+maxNullStreak*2) / 10.0
                if lossPct > 100 {
                        lossPct = 100
                }

                // Rate in Mbps
                rateMbps := float64(bestRateEma) / bpsToMbps

                // Health classification
                health := "good"
                if lossPct >= 10 || rttMs >= 200 {
                        health = "degraded"
                }
                if lossPct >= 30 || rttMs >= 500 {
                        health = "bad"
                }

                // Best alg
                bestAlg := ""
                if bi := toInt(v["best_i"]); bi >= 0 && bi < len(CONGS) {
                        bestAlg = CONGS[bi]
                }

                out[addr] = routeHealthEntry{
                        RTTMs:    round1(rttMs),
                        LossPct:  round1(lossPct),
                        RateMbps: round1(rateMbps),
                        Protocol: protocol,
                        Health:   health,
                        BestAlg:  bestAlg,
                        Inst:     h.Inst,
                }
        }

        // Check for dual-stack: if a bucket has both an IPv4 and IPv6 form,
        // mark both as "dual" protocol.
        for addr := range out {
                // Look for the other protocol version of the same labeled bucket
                for addr2, entry2 := range out {
                        if addr == addr2 {
                                continue
                        }
                        e1, _ := out[addr].(routeHealthEntry)
                        e2, _ := entry2.(routeHealthEntry)
                        if e1.Protocol != e2.Protocol {
                                // Check if they resolve to the same label
                                l1 := labelFor(addr)
                                l2 := labelFor(addr2)
                                if l1 != "" && l1 == l2 {
                                        e1.Protocol = "dual"
                                        out[addr] = e1
                                        e2.Protocol = "dual"
                                        out[addr2] = e2
                                }
                        }
                }
        }

        if len(out) == 0 {
                return nil
        }
        return out
}

// routeHealthForBucket returns the health entry for a specific bucket,
// or nil if not available. Used by the HTTP handler.
func routeHealthForBucket(all map[string]interface{}, bucketID string) interface{} {
        if all == nil {
                return nil
        }
        // Try exact match
        if entry, ok := all[bucketID]; ok {
                return entry
        }
        // Try label match
        for addr, entry := range all {
                if labelFor(addr) == bucketID {
                        return entry
                }
        }
        // Try finding the other protocol version
        for addr, entry := range all {
                lbl := labelFor(addr)
                if lbl != "" && lbl == bucketID {
                        return entry
                }
        }
        _ = fmt.Sprintf("")  // suppress unused import
        return nil
}
