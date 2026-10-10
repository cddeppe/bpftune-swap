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
        mu sync.Mutex  // v0.9.34: per-state lock for concurrent access
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

// v0.9.34: snapshots from the last collect() cycle — the route monitor
// reuses these instead of calling readBPFMap() itself (which would
// fork a second bpftool process and compete with the collector).
var (
        lastHostsSnapshot    []hostEntry
        lastBpfHealthSnapshot map[string]interface{}
)

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
// v0.9.34: does NOT call readBPFMap() — reuses the hosts data from
// the last collect() cycle via lastHostsSnapshot. This avoids running
// a second bpftool process that competes with the collector.
func (rm *RouteMonitor) cycle() {
        // Step 1: Get BPF map data from the last collect cycle (no fork!)
        rm.mu.Lock()
        hosts := lastHostsSnapshot
        bpfHealth := lastBpfHealthSnapshot
        rm.mu.Unlock()

        if hosts == nil {
                // No data yet — skip this cycle
                return
        }

        // Step 2: Discover destinations (short lock — just map updates)
        rm.mu.Lock()
        rm.discoverDestinations(hosts, bpfHealth)

        // Step 3: Build a snapshot of destinations to evaluate (copy under lock)
        type destEval struct {
                label string
                state *destRouteState
        }
        toEval := make([]destEval, 0, len(rm.destinations))
        for label, state := range rm.destinations {
                toEval = append(toEval, destEval{label, state})
        }
        rm.mu.Unlock()

        // Step 4: Run pings/DNS OUTSIDE the lock (this is the slow part).
        // v0.9.34: run all destinations concurrently to avoid blocking.
        var wg sync.WaitGroup
        for _, de := range toEval {
                wg.Add(1)
                go func(de destEval) {
                        defer wg.Done()
                        rm.evaluateDestination(de.label, de.state, bpfHealth)
                }(de)
        }
        wg.Wait()
}

// discoverDestinations finds dual-stack destinations from the BPF map,
// aliases file, AND DNS resolution for external destinations (YouTube, etc.).
func (rm *RouteMonitor) discoverDestinations(hosts []hostEntry, bpfHealth map[string]interface{}) {
        // Step 1: Build label → IPv4/IPv6 address map from aliases file.
        aliasLabels := loadAliasesLabelsMap()  // {to_ip: label}
        type protoAddrs struct {
                v4 string
                v6 string
        }
        labelAddrs := map[string]*protoAddrs{}
        for ip, lbl := range aliasLabels {
                pa, ok := labelAddrs[lbl]
                if !ok {
                        pa = &protoAddrs{}
                        labelAddrs[lbl] = pa
                }
                if strings.Contains(ip, ":") {
                        pa.v6 = ip
                } else {
                        pa.v4 = ip
                }
        }

        // Step 2: Group BPF map entries by label
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
                        lbl = addr
                }
                byLabel[lbl] = append(byLabel[lbl], h)
        }

        // Step 3: Merge BPF + aliases data
        allLabels := map[string]bool{}
        for lbl := range byLabel {
                allLabels[lbl] = true
        }
        for lbl := range labelAddrs {
                allLabels[lbl] = true
        }

        for label := range allLabels {
                hasV4 := false
                hasV6 := false
                var v4Addr, v6Addr string

                // From BPF map
                if entries, ok := byLabel[label]; ok {
                        for _, h := range entries {
                                if strings.Contains(h.Addr, ":") || strings.HasPrefix(h.Addr, "v6:") {
                                        hasV6 = true
                                        v6Addr = h.Addr
                                } else {
                                        hasV4 = true
                                        v4Addr = h.Addr
                                }
                        }
                }

                // From aliases file (fills in the missing protocol)
                if pa, ok := labelAddrs[label]; ok {
                        if !hasV4 && pa.v4 != "" {
                                hasV4 = true
                                v4Addr = pa.v4
                        }
                        if !hasV6 && pa.v6 != "" {
                                hasV6 = true
                                v6Addr = pa.v6
                        }
                }

                // v0.9.34: For external IPv4-only destinations (YouTube, etc.),
                // try to discover IPv6 via DNS. These appear as /16 bucket
                // addresses like "142.250.0.0" with no label and no aliases.
                if hasV4 && !hasV6 && v4Addr != "" {
                        v6Resolved := resolveIPv6ForBucket(v4Addr, label)
                        if v6Resolved != "" {
                                hasV6 = true
                                v6Addr = v6Resolved
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
                        fmt.Fprintf(os.Stderr, "[route-monitor] discovered %s: v4=%v(%s) v6=%v(%s)\n",
                                label, hasV4, v4Addr, hasV6, v6Addr)
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
// v0.9.34: does NOT hold state.mu during pings — only locks briefly
// to read/write fields. This prevents getState() from blocking.
func (rm *RouteMonitor) evaluateDestination(label string, state *destRouteState, bpfHealth map[string]interface{}) {
        // Step 1: Read state under lock (fast — no I/O)
        state.mu.Lock()
        hasV4 := state.HasIPv4
        hasV6 := state.HasIPv6
        v4Addr := state.IPv4Addr
        v6Addr := state.IPv6Addr
        _ = state.PreferredProto  // read but not used yet (for future switch-back logic)
        state.mu.Unlock()

        if !hasV4 && !hasV6 {
                return
        }

        // Step 2: Look up BPF metrics (no lock — bpfHealth is read-only)
        usingBPF := false
        var v4BpfRTT, v4BpfLoss, v6BpfRTT, v6BpfLoss float64
        if bpfHealth != nil {
                if hasV4 {
                        for addr, raw := range bpfHealth {
                                if entry, ok := raw.(routeHealthEntry); ok {
                                        lbl := labelFor(addr)
                                        if lbl == label && entry.Protocol != "ipv6" {
                                                v4BpfRTT = entry.RTTMs
                                                v4BpfLoss = entry.LossPct
                                                usingBPF = true
                                        }
                                }
                        }
                }
                if hasV6 {
                        for addr, raw := range bpfHealth {
                                if entry, ok := raw.(routeHealthEntry); ok {
                                        lbl := labelFor(addr)
                                        if lbl == label && (entry.Protocol == "ipv6" || entry.Protocol == "dual") {
                                                v6BpfRTT = entry.RTTMs
                                                v6BpfLoss = entry.LossPct
                                                usingBPF = true
                                        }
                                }
                        }
                }
        }

        // Step 3: Run pings OUTSIDE any lock (this is the slow part — 3s each)
        var v4PingRTT, v4PingLoss, v6PingRTT, v6PingLoss float64
        needPings := !usingBPF || (v4BpfRTT == 0 && v6BpfRTT == 0)
        if needPings {
                usingBPF = false
                if hasV4 && v4Addr != "" {
                        v4PingRTT, v4PingLoss = pingDest(v4Addr, 3)
                }
                if hasV6 && v6Addr != "" {
                        v6PingRTT, v6PingLoss = pingDest(v6Addr, 3)
                }
        }

        // Use whichever data we have
        v4RTT := v4BpfRTT
        v4Loss := v4BpfLoss
        v6RTT := v6BpfRTT
        v6Loss := v6BpfLoss
        if !usingBPF {
                v4RTT = v4PingRTT
                v4Loss = v4PingLoss
                v6RTT = v6PingRTT
                v6Loss = v6PingLoss
        }

        // Step 4: Update streaks + write results under lock (fast — no I/O)
        state.mu.Lock()
        defer state.mu.Unlock()

        state.UsingBPF = usingBPF
        state.V4BpfRTT = v4BpfRTT
        state.V4BpfLoss = v4BpfLoss
        state.V6BpfRTT = v6BpfRTT
        state.V6BpfLoss = v6BpfLoss
        state.V4PingRTT = v4PingRTT
        state.V4PingLoss = v4PingLoss
        state.V6PingRTT = v6PingRTT
        state.V6PingLoss = v6PingLoss

        // Update streaks (hysteresis: 3 consecutive readings needed)
        // v0.9.34: treat "100% loss + 0ms RTT" as "ping failed" (no data),
        // NOT as "path is degraded". Only count as bad if we have a real
        // RTT measurement with actual loss.
        const badLossThreshold = 5.0   // 5% loss = bad
        const badRTTThreshold = 100.0   // 100ms = degraded
        const goodLossThreshold = 1.0   // <1% loss = good
        const goodRTTThreshold = 50.0    // <50ms = good

        // v0.9.34: isDataValid returns false for "ping failed" (100% loss, 0ms RTT)
        v4DataValid := v4RTT > 0 || v4Loss < 100
        v6DataValid := v6RTT > 0 || v6Loss < 100

        if state.HasIPv4 && v4DataValid {
                if v4Loss >= badLossThreshold || v4RTT >= badRTTThreshold {
                        state.v4BadStreak++
                        state.v4GoodStreak = 0
                } else if v4Loss <= goodLossThreshold && v4RTT <= goodRTTThreshold {
                        state.v4GoodStreak++
                        state.v4BadStreak = 0
                }
        } else if state.HasIPv4 {
                // Ping failed — reset streaks (don't count as good or bad)
                state.v4BadStreak = 0
                state.v4GoodStreak = 0
        }
        if state.HasIPv6 && v6DataValid {
                if v6Loss >= badLossThreshold || v6RTT >= badRTTThreshold {
                        state.v6BadStreak++
                        state.v6GoodStreak = 0
                } else if v6Loss <= goodLossThreshold && v6RTT <= goodRTTThreshold {
                        state.v6GoodStreak++
                        state.v6BadStreak = 0
                }
        } else if state.HasIPv6 {
                state.v6BadStreak = 0
                state.v6GoodStreak = 0
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
// Uses per-state locks so it doesn't block on concurrent pings.
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
                        "label":              state.Label,
                        "has_ipv4":           state.HasIPv4,
                        "has_ipv6":           state.HasIPv6,
                        "preferred":          state.PreferredProto,
                        "v4_rtt_ms":          round1(v4RTT),
                        "v4_loss_pct":        round1(v4Loss),
                        "v6_rtt_ms":          round1(v6RTT),
                        "v6_loss_pct":        round1(v6Loss),
                        "using_bpf":          state.UsingBPF,
                        "last_switch_ts":     state.LastSwitchTs,
                        "last_switch_reason": state.LastSwitchReason,
                }
                state.mu.Unlock()
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

// resolveIPv6ForBucket tries to discover an IPv6 address for a /16 bucket
// address (e.g. "142.250.0.0"). Bucket addresses aren't real IPs, so
// reverse DNS fails on them. Instead, we try the first usable IP in the
// range (e.g. "142.250.0.1") and resolve that.
// Also checks known CDN prefixes by /16 range.
func resolveIPv6ForBucket(v4Bucket string, label string) string {
        // If this is a labeled destination from aliases, skip — aliases handles it
        if label != v4Bucket {
                return ""
        }

        parts := strings.Split(v4Bucket, ".")
        if len(parts) != 4 {
                return ""
        }

        // Try reverse DNS on .0.1, .1.1, .0.2
        testIPs := []string{
                parts[0] + "." + parts[1] + ".0.1",
                parts[0] + "." + parts[1] + ".1.1",
                parts[0] + "." + parts[1] + ".0.2",
        }
        for _, testIP := range testIPs {
                v6 := resolveIPv6ForAddr(testIP)
                if v6 != "" {
                        return v6
                }
        }

        // Known CDN prefixes by /16
        cdnprefix := parts[0] + "." + parts[1]
        knownCDNs := map[string]string{
                "142.250": "youtube.com",
                "142.251": "youtube.com",
                "172.217": "google.com",
                "173.194": "google.com",
                "192.178": "google.com",
                "172.64":  "cloudflare.com",
                "104.16":  "cloudflare.com",
                "104.17":  "cloudflare.com",
                "151.101": "fastly.com",
                "199.232": "fastly.com",
                "13.107":  "microsoft.com",
                "20.190":  "microsoft.com",
                "20.250":  "microsoft.com",
        }
        if hostname, ok := knownCDNs[cdnprefix]; ok {
                ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
                defer cancel()
                ips, err := net.DefaultResolver.LookupIPAddr(ctx, hostname)
                if err == nil {
                        for _, ipa := range ips {
                                if ipa.IP.To4() == nil && !ipa.IP.IsUnspecified() {
                                        return ipa.IP.String()
                                }
                        }
                }
        }
        return ""
}
