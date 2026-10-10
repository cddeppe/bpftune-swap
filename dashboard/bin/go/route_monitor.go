package main

// route_monitor.go — per-destination protocol preference switching.
//
// Monitors RTT and loss for each destination bucket. When a destination
// has both IPv4 and IPv6 paths (dual-stack), compares them and adds
// per-destination route rules to prefer the better protocol.
//
// For receive-only destinations (e.g. YouTube, where VPS is the client),
// uses ping-based RTT/loss instead of BPF metrics (which are filtered
// out by the direction gate).
//
// SAFETY:
//   - Never touches the default route (only adds per-destination routes)
//   - Never affects SSH traffic (port 22 not routed by destination)
//   - Always keeps both protocols reachable (just changes metric)
//   - Hysteresis: requires 3 consecutive "bad" readings before switching
//   - Switches back after 3 consecutive "good" readings on the other path
//
// This runs as a goroutine, called every 60s from collect.go.

import (
        "context"
        "fmt"
        "net"
        "os"
        "os/exec"
        "sort"
        "strconv"
        "strings"
        "sync"
        "time"
)

// RouteMonitor tracks per-destination protocol preference.
type RouteMonitor struct {
        mu sync.Mutex

        // Per-destination state: maps a labeled destination to its preference
        destinations map[string]*destRouteState
}

type destRouteState struct {
        Label          string
        IPv4Addr       string  // e.g. "82.43.215.97" or "82.43.0.0"
        IPv6Addr       string  // e.g. "2603:c020::" or "v6:2603c020"
        HasIPv4        bool
        HasIPv6        bool

        // Current preference: "ipv4", "ipv6", or "" (no preference set)
        PreferredProto string

        // Hysteresis counters
        v4BadStreak   int
        v6BadStreak   int
        v4GoodStreak  int
        v6GoodStreak  int

        // Last ping results (for receive-only destinations)
        V4PingRTT float64  // ms, 0 = not tested
        V6PingRTT float64
        V4PingLoss float64  // percent
        V6PingLoss float64

        // Last BPF-based metrics (for send destinations)
        V4BpfRTT  float64  // ms
        V6BpfRTT  float64
        V4BpfLoss float64  // percent
        V6BpfLoss float64

        // Whether we're using BPF data or ping data
        UsingBPF bool

        // Last switch time + reason (for dashboard display)
        LastSwitchTs   int64
        LastSwitchReason string
}

var routeMonitor = &RouteMonitor{
        destinations: map[string]*destRouteState{},
}

// routeMonitorEnabled is set by --route-monitor flag
var routeMonitorEnabled = false

// runRouteMonitor is the main loop, called as a goroutine.
func runRouteMonitor() {
        if !routeMonitorEnabled {
                return
        }
        ticker := time.NewTicker(60 * time.Second)
        defer ticker.Stop()
        for range ticker.C {
                routeMonitor.cycle()
        }
}

// cycle runs one monitoring pass.
func (rm *RouteMonitor) cycle() {
        rm.mu.Lock()
        defer rm.mu.Unlock()

        // Get current BPF map data
        hosts, err := readBPFMap()
        if err != nil {
                fmt.Fprintf(os.Stderr, "[route-monitor] BPF map read failed: %v\n", err)
                // Continue — we can still ping known destinations
        }

        // Build per-destination health map from BPF data
        bpfHealth := buildRouteHealth(hosts, nil)

        // For each known destination, evaluate and potentially switch
        for label, state := range rm.destinations {
                rm.evaluateDestination(label, state, bpfHealth)
        }

        // Discover new destinations from BPF map (for dual-stack detection)
        rm.discoverDestinations(hosts, bpfHealth)
}

// discoverDestinations finds dual-stack destinations from the BPF map.
// Also resolves DNS for labeled destinations to discover IPv6 addresses
// that may not appear in the BPF map (if xray only connected via IPv4).
func (rm *RouteMonitor) discoverDestinations(hosts []hostEntry, bpfHealth map[string]interface{}) {
        // Group by label
        byLabel := map[string][]hostEntry{}
        for _, h := range hosts {
                if h.Inst < 2 {
                        continue
                }
                addr := h.Addr
                if addr == "" || addr == "0.0.0.1" || addr == "?" {
                        continue
                }
                if strings.HasPrefix(addr, "127.") || strings.HasPrefix(addr, "169.254.") || strings.HasPrefix(addr, "0.") {
                        continue
                }
                lbl := labelFor(addr)
                if lbl == "" {
                        lbl = addr  // no label, use raw addr
                }
                byLabel[lbl] = append(byLabel[lbl], h)
        }

        // For each label, check if we have both IPv4 and IPv6
        for label, entries := range byLabel {
                if len(entries) < 1 {
                        continue
                }
                hasV4 := false
                hasV6 := false
                var v4Addr, v6Addr string
                for _, h := range entries {
                        if strings.Contains(h.Addr, ":") || strings.HasPrefix(h.Addr, "v6:") {
                                hasV6 = true
                                v6Addr = h.Addr
                        } else {
                                hasV4 = true
                                v4Addr = h.Addr
                        }
                }

                // If we only have IPv4 in the BPF map, try DNS resolution
                // to discover if the destination also has IPv6.
                if hasV4 && !hasV6 {
                        // Try to resolve the raw IPv4 address back to a hostname,
                        // then look up AAAA records. This works for labeled
                        // destinations in /etc/bpftune/aliases.
                        if v4Addr != "" && !strings.HasPrefix(v4Addr, "v6:") {
                                // Try reverse DNS + forward AAAA lookup
                                v6Resolved := resolveIPv6ForAddr(v4Addr)
                                if v6Resolved != "" {
                                        hasV6 = true
                                        v6Addr = v6Resolved
                                }
                        }
                }

                if !hasV4 && !hasV6 {
                        continue
                }

                // Create or update state
                state, ok := rm.destinations[label]
                if !ok {
                        state = &destRouteState{Label: label}
                        rm.destinations[label] = state
                }
                state.HasIPv4 = hasV4
                state.HasIPv6 = hasV6
                if hasV4 {
                        state.IPv4Addr = v4Addr
                }
                if hasV6 {
                        state.IPv6Addr = v6Addr
                }
        }
}

// evaluateDestination checks one destination and switches if needed.
func (rm *RouteMonitor) evaluateDestination(label string, state *destRouteState, bpfHealth map[string]interface{}) {
        if !state.HasIPv4 && !state.HasIPv6 {
                return
        }

        // Try to get BPF-based metrics for this destination
        state.UsingBPF = false
        if bpfHealth != nil {
                // Look for IPv4 entry
                if state.HasIPv4 {
                        for addr, raw := range bpfHealth {
                                if entry, ok := raw.(routeHealthEntry); ok {
                                        lbl := labelFor(addr)
                                        if lbl == label && entry.Protocol != "ipv6" {
                                                state.V4BpfRTT = entry.RTTMs
                                                state.V4BpfLoss = entry.LossPct
                                                state.UsingBPF = true
                                        }
                                }
                        }
                }
                // Look for IPv6 entry
                if state.HasIPv6 {
                        for addr, raw := range bpfHealth {
                                if entry, ok := raw.(routeHealthEntry); ok {
                                        lbl := labelFor(addr)
                                        if lbl == label && (entry.Protocol == "ipv6" || entry.Protocol == "dual") {
                                                state.V6BpfRTT = entry.RTTMs
                                                state.V6BpfLoss = entry.LossPct
                                                state.UsingBPF = true
                                        }
                                }
                        }
                }
        }

        // If BPF data is zero (receive-only destination OR no metrics yet),
        // fall back to pings for both protocols.
        if !state.UsingBPF || (state.V4BpfRTT == 0 && state.V6BpfRTT == 0) {
                // Always ping when BPF metrics are zero
                state.UsingBPF = false
                if state.HasIPv4 && state.IPv4Addr != "" {
                        rtt, loss := pingDest(state.IPv4Addr, 5)
                        state.V4PingRTT = rtt
                        state.V4PingLoss = loss
                }
                if state.HasIPv6 && state.IPv6Addr != "" {
                        rtt, loss := pingDest(state.IPv6Addr, 5)
                        state.V6PingRTT = rtt
                        state.V6PingLoss = loss
                }
        }

        // Use whichever data we have (BPF or ping)
        v4RTT := state.V4BpfRTT
        v4Loss := state.V4BpfLoss
        v6RTT := state.V6BpfRTT
        v6Loss := state.V6BpfLoss
        if !state.UsingBPF {
                v4RTT = state.V4PingRTT
                v4Loss = state.V4PingLoss
                v6RTT = state.V6PingRTT
                v6Loss = state.V6PingLoss
        }

        // Update streaks (hysteresis: 3 consecutive readings needed)
        const badLossThreshold = 5.0   // 5% loss = bad
        const badRTTThreshold = 100.0   // 100ms = degraded
        const goodLossThreshold = 1.0   // <1% loss = good
        const goodRTTThreshold = 50.0    // <50ms = good

        if state.HasIPv4 {
                if v4Loss >= badLossThreshold || v4RTT >= badRTTThreshold {
                        state.v4BadStreak++
                        state.v4GoodStreak = 0
                } else if v4Loss <= goodLossThreshold && v4RTT <= goodRTTThreshold {
                        state.v4GoodStreak++
                        state.v4BadStreak = 0
                }
        }
        if state.HasIPv6 {
                if v6Loss >= badLossThreshold || v6RTT >= badRTTThreshold {
                        state.v6BadStreak++
                        state.v6GoodStreak = 0
                } else if v6Loss <= goodLossThreshold && v6RTT <= goodRTTThreshold {
                        state.v6GoodStreak++
                        state.v6BadStreak = 0
                }
        }

        // Decision logic: only switch if both protocols are available
        if !state.HasIPv4 || !state.HasIPv6 {
                return  // single-stack, nothing to switch
        }

        const switchThreshold = 3  // need 3 consecutive bad readings

        // If currently on IPv4 (or no preference) and IPv4 is bad but IPv6 is good
        if (state.PreferredProto == "" || state.PreferredProto == "ipv4") &&
                state.v4BadStreak >= switchThreshold && state.v6GoodStreak >= switchThreshold {
                rm.switchTo(state, "ipv6",
                        fmt.Sprintf("IPv4 degraded (loss=%.1f%% rtt=%.1fms), IPv6 good (loss=%.1f%% rtt=%.1fms)",
                                v4Loss, v4RTT, v6Loss, v6RTT))
                return
        }

        // If currently on IPv6 (or no preference) and IPv6 is bad but IPv4 is good
        if (state.PreferredProto == "" || state.PreferredProto == "ipv6") &&
                state.v6BadStreak >= switchThreshold && state.v4GoodStreak >= switchThreshold {
                rm.switchTo(state, "ipv4",
                        fmt.Sprintf("IPv6 degraded (loss=%.1f%% rtt=%.1fms), IPv4 good (loss=%.1f%% rtt=%.1fms)",
                                v6Loss, v6RTT, v4Loss, v4RTT))
                return
        }
}

// switchTo changes the route preference for a destination.
func (rm *RouteMonitor) switchTo(state *destRouteState, proto string, reason string) {
        // Safety: extract the actual IP address to route
        // For IPv4 destinations like "82.43.0.0", we route the /16 or /32
        // For IPv6 destinations like "v6:2603c020", we convert to proper IPv6

        if proto == "ipv4" && state.IPv4Addr != "" {
                // Parse the IPv4 address and determine prefix length
                ipStr := strings.TrimPrefix(state.IPv4Addr, "v4:")
                ipStr = strings.Split(ipStr, "/")[0]
                if ip := net.ParseIP(ipStr); ip != nil && ip.To4() != nil {
                        // Use /32 for specific hosts, /16 for bucket addresses
                        // If it ends in .0, it's a bucket — use the /16
                        parts := strings.Split(ipStr, ".")
                        if len(parts) == 4 && parts[2] == "0" && parts[3] == "0" {
                                ipStr = parts[0] + "." + parts[1] + ".0.0/16"
                        } else {
                                ipStr = ipStr + "/32"
                        }
                        // Lower metric = higher priority
                        exec.Command("ip", "route", "replace", ipStr, "metric", "100").Run()
                        // If we previously preferred IPv6, remove that route override
                        if state.IPv6Addr != "" {
                                exec.Command("ip", "-6", "route", "del",
                                        convertV6ForRoute(state.IPv6Addr), "metric", "100").Run()
                        }
                }
        } else if proto == "ipv6" && state.IPv6Addr != "" {
                v6Str := convertV6ForRoute(state.IPv6Addr)
                if v6Str != "" {
                        exec.Command("ip", "-6", "route", "replace", v6Str, "metric", "100").Run()
                        // If we previously preferred IPv4, remove that route override
                        if state.IPv4Addr != "" {
                                ipStr := strings.TrimPrefix(state.IPv4Addr, "v4:")
                                ipStr = strings.Split(ipStr, "/")[0]
                                if ip := net.ParseIP(ipStr); ip != nil && ip.To4() != nil {
                                        parts := strings.Split(ipStr, ".")
                                        if len(parts) == 4 && parts[2] == "0" && parts[3] == "0" {
                                                ipStr = parts[0] + "." + parts[1] + ".0.0/16"
                                        } else {
                                                ipStr = ipStr + "/32"
                                        }
                                        exec.Command("ip", "route", "del", ipStr, "metric", "100").Run()
                                }
                        }
                }
        }

        state.PreferredProto = proto
        state.LastSwitchTs = time.Now().Unix()
        state.LastSwitchReason = reason
        fmt.Fprintf(os.Stderr, "[route-monitor] %s: switched to %s — %s\n",
                state.Label, proto, reason)
}

// convertV6ForRoute converts a v6:hex address to a routable IPv6 prefix.
func convertV6ForRoute(addr string) string {
        if strings.HasPrefix(addr, "v6:") {
                hex := strings.TrimPrefix(addr, "v6:")
                if len(hex) >= 8 {
                        // Convert first 32 bits to IPv6 notation: xxxx:xxxx::
                        h1 := hex[:4]
                        h2 := hex[4:8]
                        return h1 + ":" + h2 + "::/32"
                }
        }
        // If it's already a full IPv6 address, use it with /128
        if ip := net.ParseIP(addr); ip != nil && ip.To4() == nil {
                return addr + "/128"
        }
        return ""
}

// pingDest pings a destination and returns RTT (ms) and loss (percent).
func pingDest(addr string, count int) (float64, float64) {
        // Strip v6: prefix for ping6
        target := strings.TrimPrefix(addr, "v6:")
        if strings.HasPrefix(addr, "v6:") || strings.Contains(addr, ":") {
                return ping6(target, count)
        }
        return ping4(target, count)
}

func ping4(target string, count int) (float64, float64) {
        ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        defer cancel()
        out, err := exec.CommandContext(ctx, "ping", "-c", strconv.Itoa(count),
                "-W", "1", "-q", target).Output()
        if err != nil {
                return 0, 100
        }
        return parsePingOutput(string(out))
}

func ping6(target string, count int) (float64, float64) {
        ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        defer cancel()
        out, err := exec.CommandContext(ctx, "ping6", "-c", strconv.Itoa(count),
                "-W", "1", "-q", target).Output()
        if err != nil {
                return 0, 100
        }
        return parsePingOutput(string(out))
}

// parsePingOutput extracts RTT and loss from ping -q output.
// Example output: "rtt min/avg/max/mdev = 8.123/12.456/20.789/3.012 ms"
//                 "5 packets transmitted, 5 received, 0% packet loss"
func parsePingOutput(output string) (float64, float64) {
        var rtt, loss float64

        lines := strings.Split(output, "\n")
        for _, line := range lines {
                // Parse loss: "5 packets transmitted, 5 received, 0% packet loss"
                if strings.Contains(line, "packet loss") {
                        parts := strings.Split(line, ",")
                        for _, p := range parts {
                                p = strings.TrimSpace(p)
                                if strings.HasSuffix(p, "% packet loss") {
                                        lossStr := strings.TrimSuffix(p, "% packet loss")
                                        loss, _ = strconv.ParseFloat(lossStr, 64)
                                }
                        }
                }
                // Parse RTT: "rtt min/avg/max/mdev = 8.123/12.456/20.789/3.012 ms"
                // or "round-trip min/avg/max/mdev = ..."
                if strings.Contains(line, "min/avg/max") {
                        idx := strings.Index(line, "=")
                        if idx >= 0 {
                                vals := strings.TrimSpace(line[idx+1:])
                                vals = strings.TrimSuffix(vals, " ms")
                                parts := strings.Split(vals, "/")
                                if len(parts) >= 2 {
                                        rtt, _ = strconv.ParseFloat(parts[1], 64)  // avg
                                }
                        }
                }
        }
        return rtt, loss
}

// getRouteMonitorState returns the current route monitor state for the dashboard.
func (rm *RouteMonitor) getState() []interface{} {
        rm.mu.Lock()
        defer rm.mu.Unlock()

        out := make([]interface{}, 0, len(rm.destinations))
        for _, state := range rm.destinations {
                v4RTT := state.V4BpfRTT
                v4Loss := state.V4BpfLoss
                v6RTT := state.V6BpfRTT
                v6Loss := state.V6BpfLoss
                if !state.UsingBPF {
                        v4RTT = state.V4PingRTT
                        v4Loss = state.V4PingLoss
                        v6RTT = state.V6PingRTT
                        v6Loss = state.V6PingLoss
                }

                entry := map[string]interface{}{
                        "label":          state.Label,
                        "has_ipv4":       state.HasIPv4,
                        "has_ipv6":       state.HasIPv6,
                        "preferred":      state.PreferredProto,
                        "v4_rtt_ms":      round1(v4RTT),
                        "v4_loss_pct":    round1(v4Loss),
                        "v6_rtt_ms":      round1(v6RTT),
                        "v6_loss_pct":    round1(v6Loss),
                        "using_bpf":      state.UsingBPF,
                        "last_switch_ts": state.LastSwitchTs,
                        "last_switch_reason": state.LastSwitchReason,
                }
                out = append(out, entry)
        }

        // Sort by label for consistent display
        sort.Slice(out, func(i, j int) bool {
                ci, _ := out[i].(map[string]interface{})["label"].(string)
                cj, _ := out[j].(map[string]interface{})["label"].(string)
                return ci < cj
        })

        return out
}

// resolveIPv6ForAddr tries to find an IPv6 address for a destination
// that only has IPv4 in the BPF map. Uses reverse DNS to find the
// hostname, then forward DNS for AAAA records.
func resolveIPv6ForAddr(v4Addr string) string {
        // Strip any prefix
        v4 := strings.TrimPrefix(v4Addr, "v4:")
        v4 = strings.Split(v4, "/")[0]

        // Parse the IPv4 address
        ip := net.ParseIP(v4)
        if ip == nil || ip.To4() == nil {
                return ""
        }

        // Try reverse DNS to get the hostname
        ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
        defer cancel()
        names, err := net.DefaultResolver.LookupAddr(ctx, ip.String())
        if err != nil || len(names) == 0 {
                return ""
        }

        // For each hostname, try to resolve AAAA records
        for _, name := range names {
                name = strings.TrimSuffix(name, ".")
                ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
                defer cancel2()
                ips, err := net.DefaultResolver.LookupIPAddr(ctx2, name)
                if err != nil {
                        continue
                }
                for _, ipa := range ips {
                        if ipa.IP.To4() == nil && !ipa.IP.IsUnspecified() {
                                // Found an IPv6 address
                                return ipa.IP.String()
                        }
                }
        }

        return ""
}
