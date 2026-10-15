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
        RTTMs    float64 `json:"rtt_ms"`        // combined min RTT (backward compat)
        LossPct  float64 `json:"loss_pct"`
        RateMbps float64 `json:"rate_mbps"`
        Protocol string  `json:"protocol"`  // "ipv4", "ipv6", "dual"
        Health   string  `json:"health"`     // "good", "degraded", "bad"
        BestAlg  string  `json:"best_alg"`
        Inst     int     `json:"inst"`

        // v0.9.78: per-direction RTT split for the Origin Health panel.
        // IncomingRTTMs is the min RTT measured on connections where the
        // remote peer initiated (rport > 32768). OutgoingRTTMs is the min
        // RTT for connections this host initiated (rport ≤ 32768).
        // 0 = no data for that direction (the panel renders "no data").
        IncomingRTTMs float64 `json:"incoming_rtt_ms"`
        OutgoingRTTMs float64 `json:"outgoing_rtt_ms"`
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
                if addr == "" || addr == "0.0.0.0" || addr == "?" {
                        continue
                }
                if strings.HasPrefix(addr, "127.") ||
                        strings.HasPrefix(addr, "169.254.") ||
                        strings.HasPrefix(addr, "0.") {
                        continue
                }

                v := h.V
                // v0.4.104: use RTT from the parsed log (rxRtt) instead of
                // min_rtt from the BPF map. The BPF map's min_rtt is the
                // scoring reference (guarded by outlier/heal logic), not
                // suitable for route health display. The rtt log line gives
                // the raw RTT from actual connections.
                rttMs := 0.0
                // v0.9.78: per-direction RTT split. addr here is the raw
                // BPF bucket address (e.g. "130.61.0.0" or "v6:26061a40").
                // The IncomingRttByDest / OutgoingRttByDest maps are keyed
                // by the resolved dest label, so we resolve addr to a label
                // first, then look up the per-direction RTT.
                var inRTTMs, outRTTMs float64
                if currentParsedLog != nil {
                        if currentParsedLog.RttByDest != nil {
                                if rttUs, ok := currentParsedLog.RttByDest[addr]; ok && rttUs > 0 {
                                        rttMs = rttUs / 1000.0
                                }
                        }
                        // v0.9.78: also look up per-direction RTT. The maps
                        // are keyed by the dest label (after labelFor / aliases
                        // resolution), not the raw bucket addr — so we have
                        // to resolve the label first.
                        addrLabel := labelFor(addr)
                        if addrLabel == "" {
                                addrLabel = addr
                        }
                        if currentParsedLog.IncomingRttByDest != nil {
                                if v, ok := currentParsedLog.IncomingRttByDest[addrLabel]; ok && v > 0 {
                                        inRTTMs = v / 1000.0
                                }
                        }
                        if currentParsedLog.OutgoingRttByDest != nil {
                                if v, ok := currentParsedLog.OutgoingRttByDest[addrLabel]; ok && v > 0 {
                                        outRTTMs = v / 1000.0
                                }
                        }
                }
                // Fallback to BPF map min_rtt if no log RTT available
                if rttMs == 0 {
                        rttMs = toFloat(v["min_rtt"]) / 1000.0
                }

                // Determine protocol from which min_rtt we're using
                protocol := "ipv4"
                if h.V4MinRTT == 0 && h.V6MinRTT > 0 {
                        protocol = "ipv6"
                }
                if h.V4MinRTT > 0 && h.V6MinRTT > 0 {
                        protocol = "dual"
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
                        // v0.9.78: per-direction RTT for Origin Health panel.
                        IncomingRTTMs: round1(inRTTMs),
                        OutgoingRTTMs: round1(outRTTMs),
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
