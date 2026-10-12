package main

// route_monitor.go — per-destination protocol preference switching.
//
// v0.9.35: NO PINGS. Uses only BPF-derived data from the collector's
// snapshot (min_rtt, loss_pct from the BPF map). No process forking,
// no ICMP, no DNS lookups, no CPU spikes.
//
// Route switching only happens when BOTH protocols have real BPF data
// (RTT > 0) and one is degraded while the other is good.
//
// Dual-stack discovery uses the aliases file only — no DNS.

import (
        "fmt"
        "net"
        "os"
        "os/exec"
        "sort"
        "strings"
        "sync"
        "time"
)

type RouteMonitor struct {
        mu sync.Mutex
        destinations map[string]*destRouteState
}

type destRouteState struct {
        mu sync.Mutex
        Label          string
        IPv4Addr       string
        IPv6Addr       string
        HasIPv4        bool
        HasIPv6        bool
        PreferredProto string

        v4BadStreak   int
        v6BadStreak   int
        v4GoodStreak  int
        v6GoodStreak  int

        V4RTT  float64
        V4Loss float64
        V6RTT  float64
        V6Loss float64
        UsingBPF bool

        LastSwitchTs     int64
        LastSwitchReason string
}

var routeMonitor = &RouteMonitor{
        destinations: map[string]*destRouteState{},
}

var (
        lastHostsSnapshot    []hostEntry
        lastBpfHealthSnapshot map[string]interface{}
)

var routeMonitorEnabled = false

func runRouteMonitor() {
        if !routeMonitorEnabled {
                return
        }
        ticker := time.NewTicker(180 * time.Second)
        defer ticker.Stop()
        for range ticker.C {
                routeMonitor.cycle()
        }
}

func (rm *RouteMonitor) cycle() {
        rm.mu.Lock()
        hosts := lastHostsSnapshot
        bpfHealth := lastBpfHealthSnapshot
        rm.mu.Unlock()

        if hosts == nil {
                return
        }

        rm.discoverDestinations(hosts, bpfHealth)

        type destEval struct {
                label string
                state *destRouteState
        }
        toEval := make([]destEval, 0, len(rm.destinations))
        rm.mu.Lock()
        for label, state := range rm.destinations {
                toEval = append(toEval, destEval{label, state})
        }
        rm.mu.Unlock()

        for _, de := range toEval {
                rm.evaluateDestination(de.label, de.state, bpfHealth)
        }
}

// discoverDestinations finds dual-stack destinations from BPF map + aliases.
// NO DNS lookups — only uses the aliases file and BPF map entries.
func (rm *RouteMonitor) discoverDestinations(hosts []hostEntry, bpfHealth map[string]interface{}) {
        aliasLabels := loadAliasesLabelsMap()
        type protoAddrs struct{ v4, v6 string }
        labelAddrs := map[string]*protoAddrs{}
        for ip, lbl := range aliasLabels {
                pa, ok := labelAddrs[lbl]
                if !ok { pa = &protoAddrs{}; labelAddrs[lbl] = pa }
                if strings.Contains(ip, ":") { pa.v6 = ip } else { pa.v4 = ip }
        }

        byLabel := map[string][]hostEntry{}
        for _, h := range hosts {
                if h.Inst < 2 { continue }
                addr := h.Addr
                if addr == "" || addr == "0.0.0.1" || addr == "?" { continue }
                if strings.HasPrefix(addr, "127.") || strings.HasPrefix(addr, "169.254.") || strings.HasPrefix(addr, "0.") { continue }
                lbl := labelFor(addr)
                if lbl == "" { lbl = addr }
                byLabel[lbl] = append(byLabel[lbl], h)
        }

        allLabels := map[string]bool{}
        for lbl := range byLabel { allLabels[lbl] = true }
        for lbl := range labelAddrs { allLabels[lbl] = true }

        for label := range allLabels {
                hasV4, hasV6 := false, false
                var v4Addr, v6Addr string

                if entries, ok := byLabel[label]; ok {
                        for _, h := range entries {
                                if strings.Contains(h.Addr, ":") || strings.HasPrefix(h.Addr, "v6:") {
                                        hasV6 = true; v6Addr = h.Addr
                                } else {
                                        hasV4 = true; v4Addr = h.Addr
                                }
                        }
                }
                if pa, ok := labelAddrs[label]; ok {
                        if !hasV4 && pa.v4 != "" { hasV4 = true; v4Addr = pa.v4 }
                        if !hasV6 && pa.v6 != "" { hasV6 = true; v6Addr = pa.v6 }
                }

                if !hasV4 && !hasV6 { continue }

                rm.mu.Lock()
                state, ok := rm.destinations[label]
                if !ok {
                        state = &destRouteState{Label: label}
                        rm.destinations[label] = state
                }
                rm.mu.Unlock()

                state.mu.Lock()
                state.HasIPv4 = hasV4
                state.HasIPv6 = hasV6
                if hasV4 { state.IPv4Addr = v4Addr }
                if hasV6 { state.IPv6Addr = v6Addr }
                state.mu.Unlock()
        }
}

// evaluateDestination uses ONLY BPF data — no pings.
func (rm *RouteMonitor) evaluateDestination(label string, state *destRouteState, bpfHealth map[string]interface{}) {
        state.mu.Lock()
        hasV4 := state.HasIPv4
        hasV6 := state.HasIPv6
        state.mu.Unlock()

        if !hasV4 || !hasV6 {
                return // single-stack, can't switch
        }

        // Read BPF metrics only
        var v4RTT, v4Loss, v6RTT, v6Loss float64
        usingBPF := false
        if bpfHealth != nil {
                for addr, raw := range bpfHealth {
                        entry, ok := raw.(routeHealthEntry)
                        if !ok { continue }
                        lbl := labelFor(addr)
                        if lbl != label { continue }
                        if entry.Protocol != "ipv6" && entry.Protocol != "dual" {
                                v4RTT = entry.RTTMs
                                v4Loss = entry.LossPct
                                usingBPF = true
                        }
                        if entry.Protocol == "ipv6" || entry.Protocol == "dual" {
                                v6RTT = entry.RTTMs
                                v6Loss = entry.LossPct
                                usingBPF = true
                        }
                }
        }

        // Only evaluate if we have real BPF data for BOTH protocols
        v4DataValid := v4RTT > 0
        v6DataValid := v6RTT > 0
        if !v4DataValid || !v6DataValid {
                // Can't compare — skip this destination
                state.mu.Lock()
                state.V4RTT = v4RTT; state.V4Loss = v4Loss
                state.V6RTT = v6RTT; state.V6Loss = v6Loss
                state.UsingBPF = usingBPF
                state.v4BadStreak = 0; state.v4GoodStreak = 0
                state.v6BadStreak = 0; state.v6GoodStreak = 0
                state.mu.Unlock()
                return
        }

        const badLossThreshold = 5.0
        const badRTTThreshold = 100.0
        const goodLossThreshold = 1.0
        const goodRTTThreshold = 50.0
        const switchThreshold = 3

        state.mu.Lock()
        defer state.mu.Unlock()

        state.UsingBPF = true
        state.V4RTT = v4RTT; state.V4Loss = v4Loss
        state.V6RTT = v6RTT; state.V6Loss = v6Loss

        // Update streaks
        if v4Loss >= badLossThreshold || v4RTT >= badRTTThreshold {
                state.v4BadStreak++; state.v4GoodStreak = 0
        } else if v4Loss <= goodLossThreshold && v4RTT <= goodRTTThreshold {
                state.v4GoodStreak++; state.v4BadStreak = 0
        }
        if v6Loss >= badLossThreshold || v6RTT >= badRTTThreshold {
                state.v6BadStreak++; state.v6GoodStreak = 0
        } else if v6Loss <= goodLossThreshold && v6RTT <= goodRTTThreshold {
                state.v6GoodStreak++; state.v6BadStreak = 0
        }

        // Switch logic
        if (state.PreferredProto == "" || state.PreferredProto == "ipv4") &&
                state.v4BadStreak >= switchThreshold && state.v6GoodStreak >= switchThreshold {
                rm.switchTo(state, "ipv6",
                        fmt.Sprintf("IPv4 degraded (loss=%.1f%% rtt=%.1fms), IPv6 good (loss=%.1f%% rtt=%.1fms)",
                                v4Loss, v4RTT, v6Loss, v6RTT))
                return
        }
        if (state.PreferredProto == "" || state.PreferredProto == "ipv6") &&
                state.v6BadStreak >= switchThreshold && state.v4GoodStreak >= switchThreshold {
                rm.switchTo(state, "ipv4",
                        fmt.Sprintf("IPv6 degraded (loss=%.1f%% rtt=%.1fms), IPv4 good (loss=%.1f%% rtt=%.1fms)",
                                v6Loss, v6RTT, v4Loss, v4RTT))
                return
        }
}

func (rm *RouteMonitor) switchTo(state *destRouteState, proto string, reason string) {
        if proto == "ipv4" && state.IPv4Addr != "" {
                ipStr := normalizeRoutePrefix(state.IPv4Addr)
                if ipStr != "" {
                        exec.Command("ip", "route", "replace", ipStr, "metric", "100").Run()
                        if state.IPv6Addr != "" {
                                v6Str := convertV6ForRoute(state.IPv6Addr)
                                if v6Str != "" { exec.Command("ip", "-6", "route", "del", v6Str, "metric", "100").Run() }
                        }
                }
        } else if proto == "ipv6" && state.IPv6Addr != "" {
                v6Str := convertV6ForRoute(state.IPv6Addr)
                if v6Str != "" {
                        exec.Command("ip", "-6", "route", "replace", v6Str, "metric", "100").Run()
                        if state.IPv4Addr != "" {
                                ipStr := normalizeRoutePrefix(state.IPv4Addr)
                                if ipStr != "" { exec.Command("ip", "route", "del", ipStr, "metric", "100").Run() }
                        }
                }
        }
        state.PreferredProto = proto
        state.LastSwitchTs = time.Now().Unix()
        state.LastSwitchReason = reason
        fmt.Fprintf(os.Stderr, "[route-monitor] %s: switched to %s — %s\n", state.Label, proto, reason)
}

func normalizeRoutePrefix(addr string) string {
        addr = strings.TrimPrefix(addr, "v4:")
        addr = strings.Split(addr, "/")[0]
        parts := strings.Split(addr, ".")
        if len(parts) != 4 { return "" }
        if parts[2] == "0" && parts[3] == "0" {
                return parts[0] + "." + parts[1] + ".0.0/16"
        }
        return addr + "/32"
}

func convertV6ForRoute(addr string) string {
        addr = strings.TrimPrefix(addr, "v6:")
        if strings.HasPrefix(addr, "v6:") {
                hex := strings.TrimPrefix(addr, "v6:")
                if len(hex) >= 8 {
                        return hex[:4] + ":" + hex[4:8] + "::/32"
                }
        }
        if ip := net.ParseIP(addr); ip != nil && ip.To4() == nil {
                return addr + "/128"
        }
        return ""
}

func (rm *RouteMonitor) getState() []interface{} {
        rm.mu.Lock()
        states := make([]*destRouteState, 0, len(rm.destinations))
        for _, state := range rm.destinations {
                states = append(states, state)
        }
        rm.mu.Unlock()

        out := make([]interface{}, 0, len(states))
        for _, state := range states {
                state.mu.Lock()
                entry := map[string]interface{}{
                        "label": state.Label,
                        "has_ipv4": state.HasIPv4,
                        "has_ipv6": state.HasIPv6,
                        "preferred": state.PreferredProto,
                        "v4_rtt_ms": round1(state.V4RTT),
                        "v4_loss_pct": round1(state.V4Loss),
                        "v6_rtt_ms": round1(state.V6RTT),
                        "v6_loss_pct": round1(state.V6Loss),
                        "using_bpf": state.UsingBPF,
                        "last_switch_ts": state.LastSwitchTs,
                        "last_switch_reason": state.LastSwitchReason,
                }
                state.mu.Unlock()
                out = append(out, entry)
        }

        sort.Slice(out, func(i, j int) bool {
                ci, _ := out[i].(map[string]interface{})["label"].(string)
                cj, _ := out[j].(map[string]interface{})["label"].(string)
                return ci < cj
        })
        return out
}
