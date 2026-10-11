package main

// route_monitor.go — per-destination protocol preference switching.
//
// v0.9.34: fully optimized — no process forking, cached DNS,
// only evaluates active destinations.
//
// Optimizations:
//   - Uses Go raw ICMP sockets instead of forking ping/ping6 processes
//   - DNS results cached per-destination (only resolved once)
//   - Only evaluates destinations with active BPF traffic
//   - 180s interval (route switching doesn't need to be instant)
//   - Single ICMP echo per destination (not 2-3 pings)

import (
        "context"
        "encoding/binary"
        "fmt"
        "net"
        "os"
        "os/exec"
        "sort"
        "strings"
        "sync"
        "time"
)

// RouteMonitor tracks per-destination protocol preference.
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

        // Hysteresis
        v4BadStreak   int
        v6BadStreak   int
        v4GoodStreak  int
        v6GoodStreak  int

        // Cached metrics
        V4RTT  float64
        V4Loss float64
        V6RTT  float64
        V6Loss float64
        UsingBPF bool

        // DNS cache (only resolve once)
        dnsResolved bool

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

        // Only discover/evaluate destinations that have active BPF traffic
        rm.discoverDestinations(hosts, bpfHealth)

        // Build snapshot of destinations to evaluate
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

        // Run evaluations concurrently
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

func (rm *RouteMonitor) discoverDestinations(hosts []hostEntry, bpfHealth map[string]interface{}) {
        // Build label → IPv4/IPv6 from aliases
        aliasLabels := loadAliasesLabelsMap()
        type protoAddrs struct{ v4, v6 string }
        labelAddrs := map[string]*protoAddrs{}
        for ip, lbl := range aliasLabels {
                pa, ok := labelAddrs[lbl]
                if !ok { pa = &protoAddrs{}; labelAddrs[lbl] = pa }
                if strings.Contains(ip, ":") { pa.v6 = ip } else { pa.v4 = ip }
        }

        // Group BPF entries by label (only active traffic)
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

        // Merge
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

                // DNS discovery (only once per destination)
                if hasV4 && !hasV6 && v4Addr != "" {
                        state, exists := rm.destinations[label]
                        if !exists || !state.dnsResolved {
                                v6Resolved := resolveIPv6ForBucket(v4Addr, label)
                                if v6Resolved != "" {
                                        hasV6 = true; v6Addr = v6Resolved
                                }
                                if state != nil { state.dnsResolved = true }
                        }
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

func (rm *RouteMonitor) evaluateDestination(label string, state *destRouteState, bpfHealth map[string]interface{}) {
        state.mu.Lock()
        hasV4 := state.HasIPv4
        hasV6 := state.HasIPv6
        v4Addr := state.IPv4Addr
        v6Addr := state.IPv6Addr
        state.mu.Unlock()

        if !hasV4 && !hasV6 { return }

        // Get BPF metrics (no lock — read-only)
        usingBPF := false
        var v4BpfRTT, v4BpfLoss, v6BpfRTT, v6BpfLoss float64
        if bpfHealth != nil {
                if hasV4 {
                        for addr, raw := range bpfHealth {
                                if entry, ok := raw.(routeHealthEntry); ok {
                                        if labelFor(addr) == label && entry.Protocol != "ipv6" {
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
                                        if labelFor(addr) == label && (entry.Protocol == "ipv6" || entry.Protocol == "dual") {
                                                v6BpfRTT = entry.RTTMs
                                                v6BpfLoss = entry.LossPct
                                                usingBPF = true
                                        }
                                }
                        }
                }
        }

        // Only ping dual-stack destinations missing BPF data
        var v4PingRTT, v4PingLoss, v6PingRTT, v6PingLoss float64
        needV4Ping := hasV4 && hasV6 && v4BpfRTT == 0 && v4Addr != ""
        needV6Ping := hasV4 && hasV6 && v6BpfRTT == 0 && v6Addr != ""
        if needV4Ping || needV6Ping {
                usingBPF = false
                if needV4Ping {
                        v4PingRTT, v4PingLoss = icmpPing(v4Addr)
                }
                if needV6Ping {
                        v6PingRTT, v6PingLoss = icmpPing(v6Addr)
                }
        }

        v4RTT := v4BpfRTT; v4Loss := v4BpfLoss
        v6RTT := v6BpfRTT; v6Loss := v6BpfLoss
        if !usingBPF {
                v4RTT = v4PingRTT; v4Loss = v4PingLoss
                v6RTT = v6PingRTT; v6Loss = v6PingLoss
        }

        // Update streaks
        const badLossThreshold = 5.0
        const badRTTThreshold = 100.0
        const goodLossThreshold = 1.0
        const goodRTTThreshold = 50.0

        v4DataValid := v4RTT > 0
        v6DataValid := v6RTT > 0

        state.mu.Lock()
        defer state.mu.Unlock()

        state.UsingBPF = usingBPF
        state.V4RTT = v4RTT; state.V4Loss = v4Loss
        state.V6RTT = v6RTT; state.V6Loss = v6Loss

        if hasV4 && v4DataValid {
                if v4Loss >= badLossThreshold || v4RTT >= badRTTThreshold {
                        state.v4BadStreak++; state.v4GoodStreak = 0
                } else if v4Loss <= goodLossThreshold && v4RTT <= goodRTTThreshold {
                        state.v4GoodStreak++; state.v4BadStreak = 0
                }
        } else if hasV4 {
                state.v4BadStreak = 0; state.v4GoodStreak = 0
        }
        if hasV6 && v6DataValid {
                if v6Loss >= badLossThreshold || v6RTT >= badRTTThreshold {
                        state.v6BadStreak++; state.v6GoodStreak = 0
                } else if v6Loss <= goodLossThreshold && v6RTT <= goodRTTThreshold {
                        state.v6GoodStreak++; state.v6BadStreak = 0
                }
        } else if hasV6 {
                state.v6BadStreak = 0; state.v6GoodStreak = 0
        }

        if !hasV4 || !hasV6 { return }

        const switchThreshold = 3
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

// normalizeRoutePrefix converts an address to a routable prefix
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

// icmpPing sends a single ICMP echo using Go's net package — no process fork.
// Returns RTT in ms and loss percentage (0 or 100).
func icmpPing(addr string) (float64, float64) {
        target := normalizePingTarget(addr)
        if target == "" { return 0, 100 }

        if strings.Contains(target, ":") {
                return icmpPing6(target)
        }
        return icmpPing4(target)
}

func icmpPing4(target string) (float64, float64) {
        ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
        defer cancel()
        conn, err := (&net.Dialer{}).DialContext(ctx, "ip4:icmp", target)
        if err != nil { return 0, 100 }
        defer conn.Close()

        // Set 2s read deadline
        conn.SetDeadline(time.Now().Add(2 * time.Second))

        // Build ICMP echo request
        msg := make([]byte, 16)
        binary.BigEndian.PutUint16(msg[0:], 8)  // type: echo
        binary.BigEndian.PutUint16(msg[4:], 1)  // id
        binary.BigEndian.PutUint16(msg[6:], 1)  // seq
        // Checksum
        cs := icmpChecksum(msg)
        binary.BigEndian.PutUint16(msg[2:], cs)

        start := time.Now()
        _, err = conn.Write(msg)
        if err != nil { return 0, 100 }

        buf := make([]byte, 1500)
        _, err = conn.Read(buf)
        if err != nil { return 0, 100 }

        rtt := float64(time.Since(start).Microseconds()) / 1000.0
        return rtt, 0
}

func icmpPing6(target string) (float64, float64) {
        ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
        defer cancel()
        conn, err := (&net.Dialer{}).DialContext(ctx, "ip6:ipv6-icmp", target)
        if err != nil { return 0, 100 }
        defer conn.Close()

        conn.SetDeadline(time.Now().Add(2 * time.Second))

        msg := make([]byte, 16)
        binary.BigEndian.PutUint16(msg[0:], 128) // type: echo request (IPv6)
        binary.BigEndian.PutUint16(msg[4:], 1)
        binary.BigEndian.PutUint16(msg[6:], 1)
        cs := icmpChecksum(msg)
        binary.BigEndian.PutUint16(msg[2:], cs)

        start := time.Now()
        _, err = conn.Write(msg)
        if err != nil { return 0, 100 }

        buf := make([]byte, 1500)
        _, err = conn.Read(buf)
        if err != nil { return 0, 100 }

        rtt := float64(time.Since(start).Microseconds()) / 1000.0
        return rtt, 0
}

func icmpChecksum(data []byte) uint16 {
        var sum uint32
        for i := 0; i < len(data)-1; i += 2 {
                sum += uint32(binary.BigEndian.Uint16(data[i:]))
        }
        if len(data)%2 == 1 {
                sum += uint32(data[len(data)-1]) << 8
        }
        for sum>>16 > 0 {
                sum = (sum & 0xFFFF) + (sum >> 16)
        }
        return ^uint16(sum)
}

// normalizePingTarget converts bucket addresses to pingable IPs
func normalizePingTarget(addr string) string {
        addr = strings.TrimPrefix(addr, "v6:")
        addr = strings.Split(addr, "/")[0]

        if strings.Contains(addr, ":") {
                if strings.Contains(addr, "::") {
                        if strings.HasSuffix(addr, "::") { return addr + "1" }
                        return addr
                }
                parts := strings.Split(addr, ":")
                if len(parts) >= 2 {
                        g1, g2 := parts[0], parts[1]
                        for len(g1) < 4 { g1 = "0" + g1 }
                        for len(g2) < 4 { g2 = "0" + g2 }
                        return g1 + ":" + g2 + "::1"
                }
                return ""
        }

        parts := strings.Split(addr, ".")
        if len(parts) != 4 { return "" }

        knownPingable := map[string]string{
                "142.250": "8.8.8.8", "142.251": "8.8.8.8",
                "172.217": "8.8.8.8", "173.194": "8.8.8.8", "192.178": "8.8.8.8",
                "172.64": "1.1.1.1", "104.16": "1.1.1.1", "104.17": "1.1.1.1",
                "151.101": "151.101.1.1", "199.232": "199.232.1.1",
                "185.199": "185.199.108.1",
        }
        prefix := parts[0] + "." + parts[1]
        if known, ok := knownPingable[prefix]; ok { return known }

        if parts[2] == "0" && parts[3] == "0" {
                return parts[0] + "." + parts[1] + ".0.1"
        }
        if parts[3] == "0" {
                return parts[0] + "." + parts[1] + "." + parts[2] + ".1"
        }
        return addr
}

func resolveIPv6ForBucket(v4Bucket string, label string) string {
        if label != v4Bucket { return "" }
        parts := strings.Split(v4Bucket, ".")
        if len(parts) != 4 { return "" }
        testIPs := []string{
                parts[0] + "." + parts[1] + ".0.1",
                parts[0] + "." + parts[1] + ".1.1",
        }
        for _, testIP := range testIPs {
                v6 := resolveIPv6ForAddr(testIP)
                if v6 != "" { return v6 }
        }
        knownCDNs := map[string]string{
                "142.250": "youtube.com", "142.251": "youtube.com",
                "172.217": "google.com", "173.194": "google.com", "192.178": "google.com",
                "172.64": "cloudflare.com", "104.16": "cloudflare.com", "104.17": "cloudflare.com",
                "151.101": "fastly.com", "199.232": "fastly.com",
                "13.107": "microsoft.com", "20.190": "microsoft.com", "20.250": "microsoft.com",
        }
        if hostname, ok := knownCDNs[parts[0]+"."+parts[1]]; ok {
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

func resolveIPv6ForAddr(v4Addr string) string {
        v4 := strings.TrimPrefix(v4Addr, "v4:")
        v4 = strings.Split(v4, "/")[0]
        ip := net.ParseIP(v4)
        if ip == nil || ip.To4() == nil { return "" }
        ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
        defer cancel()
        names, err := net.DefaultResolver.LookupAddr(ctx, ip.String())
        if err != nil || len(names) == 0 { return "" }
        for _, name := range names {
                name = strings.TrimSuffix(name, ".")
                ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
                defer cancel2()
                ips, err := net.DefaultResolver.LookupIPAddr(ctx2, name)
                if err != nil { continue }
                for _, ipa := range ips {
                        if ipa.IP.To4() == nil && !ipa.IP.IsUnspecified() {
                                return ipa.IP.String()
                        }
                }
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
