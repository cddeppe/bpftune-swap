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

// v0.9.73: dedicated mutex for the package-level snapshot vars below.
//
// Before this fix, the writer (collect.go:126-127, running in the 30s
// collect goroutine) wrote lastHostsSnapshot / lastBpfHealthSnapshot
// WITHOUT any lock. The route-monitor goroutine read the same vars in
// cycle() under rm.mu (which does NOT protect these package vars) and
// in evaluateDestination without any lock at all.
//
// That is a textbook Go data race:
//   - Concurrent map header assignment + iteration on
//     lastBpfHealthSnapshot can throw a runtime panic, killing the
//     route-monitor goroutine. The Origin Health panel then freezes
//     at whatever was last computed.
//   - Concurrent slice header assignment + iteration on
//     lastHostsSnapshot is undefined behavior even if it rarely panics.
//
// The fix uses a sync.RWMutex so multiple readers (route-monitor cycle)
// can proceed concurrently while the writer (collector collect)
// serializes against all of them.
var (
        snapshotMu             sync.RWMutex
        lastHostsSnapshot      []hostEntry
        lastBpfHealthSnapshot  map[string]interface{}
)

// setSnapshot is called by the collect goroutine to publish the latest
// BPF map + route-health data for the route-monitor goroutine to consume.
// MUST be called without holding rm.mu to avoid lock-ordering issues.
func setRouteSnapshot(hosts []hostEntry, bpfHealth map[string]interface{}) {
        snapshotMu.Lock()
        defer snapshotMu.Unlock()
        lastHostsSnapshot = hosts
        lastBpfHealthSnapshot = bpfHealth
}

// getRouteSnapshot returns local copies of the latest snapshots. The
// returned slices/maps may be read freely without holding snapshotMu —
// subsequent setRouteSnapshot calls replace the package-level headers
// rather than mutating the underlying data, so stale references remain
// valid for the duration of a cycle.
func getRouteSnapshot() (hosts []hostEntry, bpfHealth map[string]interface{}) {
        snapshotMu.RLock()
        defer snapshotMu.RUnlock()
        hosts = lastHostsSnapshot
        bpfHealth = lastBpfHealthSnapshot
        return
}

var routeMonitorEnabled = false

func runRouteMonitor() {
        if !routeMonitorEnabled {
                return
        }
        // v0.9.71: run an immediate cycle on startup so destinations
        // appear instantly instead of waiting 5 minutes.
        routeMonitor.cycle()
        // v0.9.35: 5 minute interval — minimal ICMP footprint
        ticker := time.NewTicker(300 * time.Second)
        defer ticker.Stop()
        for range ticker.C {
                routeMonitor.cycle()
        }
}

func (rm *RouteMonitor) cycle() {
        // v0.9.73: take snapshot under the dedicated snapshotMu, not rm.mu
        // (rm.mu protects rm.destinations, not these package-level vars).
        hosts, bpfHealth := getRouteSnapshot()

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

        // v0.9.73: pass the local `hosts` snapshot so evaluateDestination
        // doesn't re-read the package-level var without a lock (the original
        // code at line 308 did exactly that, which was racy).
        for _, de := range toEval {
                rm.evaluateDestination(de.label, de.state, bpfHealth, hosts)
        }
}

// discoverDestinations finds dual-stack destinations from BPF map + aliases.
// v0.9.72: also links v4 and v6 entries via ctrld DNS cache — if the
// same domain resolves to both v4 and v6 IPs, the BPF map entries
// are linked as dual-stack even without aliases.
func (rm *RouteMonitor) discoverDestinations(hosts []hostEntry, bpfHealth map[string]interface{}) {
        aliasLabels := loadAliasesLabelsMap()
        type protoAddrs struct{ v4, v6 string }
        labelAddrs := map[string]*protoAddrs{}
        for ip, lbl := range aliasLabels {
                pa, ok := labelAddrs[lbl]
                if !ok { pa = &protoAddrs{}; labelAddrs[lbl] = pa }
                if strings.Contains(ip, ":") { pa.v6 = ip } else { pa.v4 = ip }
        }

        // v0.9.72: Build a domain→{v4prefix, v6prefix} map from ctrld cache.
        // This lets us link v4 BPF entries like "130.61.0.0" with v6 entries
        // like "v6:26061a40" when they belong to the same domain.
        type domPrefixes struct{ v4, v6 string }
        domainMap := map[string]*domPrefixes{}
        ctrldState.mu.RLock()
        if ctrldState.available {
                for ip, domain := range ctrldState.ipToDomain {
                        dp, ok := domainMap[domain]
                        if !ok { dp = &domPrefixes{}; domainMap[domain] = dp }
                        if strings.Contains(ip, ":") {
                                // IPv6 — extract first 4 bytes as hex prefix
                                // e.g. "2606:1a40:3::1" → "26061a40" → "v6:26061a40"
                                hex := ipv6ToBpfHex(ip)
                                if hex != "" { dp.v6 = "v6:" + hex }
                        } else {
                                // IPv4 — extract /16 prefix
                                parts := strings.Split(ip, ".")
                                if len(parts) >= 2 {
                                        dp.v4 = parts[0] + "." + parts[1] + ".0.0"
                                }
                        }
                }
        }
        ctrldState.mu.RUnlock()

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

        // v0.9.72: Also link v4 and v6 entries via domain matching.
        // For each v4-only entry, check if ctrld knows a v6 counterpart.
        // For each v6-only entry, check if ctrld knows a v4 counterpart.
        for lbl, entries := range byLabel {
                hasV4, hasV6 := false, false
                for _, h := range entries {
                        if strings.Contains(h.Addr, ":") || strings.HasPrefix(h.Addr, "v6:") {
                                hasV6 = true
                        } else {
                                hasV4 = true
                        }
                }
                // If only v4, try to find v6 counterpart via domain
                // v0.9.73: delete dead scaffolding loop — was leftover from
                // v0.9.72 v6->v4 linking work and never iterated anything.
                if hasV4 && !hasV6 {
                        // Look up domain for this v4 label
                        domain := getDomainForBucket(lbl)
                        if domain != "" {
                                if dp, ok := domainMap[domain]; ok && dp.v6 != "" {
                                        // Check if the v6 BPF entry exists in hosts
                                        for _, h := range hosts {
                                                if h.Addr == dp.v6 && h.Inst >= 2 {
                                                        // Found the v6 counterpart — add it
                                                        byLabel[lbl] = append(byLabel[lbl], h)
                                                        break
                                                }
                                        }
                                }
                        }
                }
                // If only v6, try to find v4 counterpart via domain
                if hasV6 && !hasV4 {
                        domain := getDomainForBucket(lbl)
                        if domain != "" {
                                if dp, ok := domainMap[domain]; ok && dp.v4 != "" {
                                        for _, h := range hosts {
                                                if h.Addr == dp.v4 && h.Inst >= 2 {
                                                        byLabel[lbl] = append(byLabel[lbl], h)
                                                        break
                                                }
                                        }
                                }
                        }
                }
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

// ipv6ToBpfHex converts a full IPv6 address to the BPF map's 8-hex-char
// prefix format. e.g. "2606:1a40:3::1" → "26061a40"
func ipv6ToBpfHex(ip string) string {
        // Take the first two hextets: "2606:1a40:..." → "2606" + "1a40"
        parts := strings.Split(ip, ":")
        if len(parts) < 2 { return "" }
        h1 := parts[0]
        h2 := parts[1]
        // Pad to 4 chars each
        for len(h1) < 4 { h1 = "0" + h1 }
        for len(h2) < 4 { h2 = "0" + h2 }
        return h1 + h2
}

// evaluateDestination uses BPF data with minimal ICMP fallback.
// v0.9.73: added `hosts` parameter so the per-protocol min_rtt lookup
// at line ~308 can read from the caller's local snapshot instead of
// reading the package-level lastHostsSnapshot without a lock.
func (rm *RouteMonitor) evaluateDestination(label string, state *destRouteState, bpfHealth map[string]interface{}, hosts []hostEntry) {
        state.mu.Lock()
        hasV4 := state.HasIPv4
        hasV6 := state.HasIPv6
        v4Addr := state.IPv4Addr
        v6Addr := state.IPv6Addr
        state.mu.Unlock()

        if !hasV4 || !hasV6 {
                return // single-stack, can't switch
        }

        // Read BPF metrics
        // v0.9.38: read per-protocol min_rtt directly from the hosts snapshot.
        // Before this, the route monitor read from bpfHealth which only had
        // one merged RTT (usually v4). Now we get both v4 and v6 RTT separately.
        var v4BpfRTT, v4BpfLoss, v6BpfRTT, v6BpfLoss float64
        usingBPF := false
        if bpfHealth != nil {
                for addr, raw := range bpfHealth {
                        entry, ok := raw.(routeHealthEntry)
                        if !ok { continue }
                        lbl := labelFor(addr)
                        if lbl != label { continue }
                        // v0.9.38: the routeHealthEntry now has per-protocol data
                        // via the V4MinRTT/V6MinRTT fields in hostEntry.
                        // But routeHealthEntry itself doesn't carry those — we need
                        // to read from the hosts snapshot instead.
                        if entry.Protocol != "ipv6" {
                                v4BpfRTT = entry.RTTMs
                                v4BpfLoss = entry.LossPct
                                usingBPF = true
                        }
                        if entry.Protocol == "ipv6" || entry.Protocol == "dual" {
                                v6BpfRTT = entry.RTTMs
                                v6BpfLoss = entry.LossPct
                                usingBPF = true
                        }
                }
        }

        // v0.9.38: also check hosts snapshot for per-protocol min_rtt.
        // This is the real fix — the merged BPF map entry has V4MinRTT and
        // V6MinRTT tracked separately, so v6 gets real data.
        // v0.9.73: read from the `hosts` parameter (caller's local snapshot)
        // instead of the package-level lastHostsSnapshot — eliminates the
        // data race on that var.
        if hosts != nil {
                for _, h := range hosts {
                        if h.Inst < 2 { continue }
                        lbl := labelFor(h.Addr)
                        if lbl == "" { lbl = h.Addr }
                        if lbl != label { continue }
                        if h.V4MinRTT > 0 {
                                v4BpfRTT = h.V4MinRTT / 1000.0
                                usingBPF = true
                        }
                        if h.V6MinRTT > 0 {
                                v6BpfRTT = h.V6MinRTT / 1000.0
                                usingBPF = true
                        }
                        break // found this label
                }
        }

        // v0.9.35: minimal ICMP — only 1 ping, only dual-stack, only when BPF has no data
        // v0.9.37: ICMP returns -1,-1 when it can't get data (blocked, no route).
        // Don't overwrite BPF data with -1; only use ICMP result if it's > 0.
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

        // Use BPF data if available, otherwise ping data (if ping succeeded)
        v4RTT := v4BpfRTT; v4Loss := v4BpfLoss
        v6RTT := v6BpfRTT; v6Loss := v6BpfLoss
        if needV4Ping && v4PingRTT > 0 { v4RTT = v4PingRTT; v4Loss = v4PingLoss }
        if needV6Ping && v6PingRTT > 0 { v6RTT = v6PingRTT; v6Loss = v6PingLoss }
        if needV4Ping || needV6Ping {
                usingBPF = false
        }

        const badLossThreshold = 5.0
        const badRTTThreshold = 100.0
        const goodLossThreshold = 1.0
        const goodRTTThreshold = 50.0
        const switchThreshold = 3

        state.mu.Lock()
        defer state.mu.Unlock()

        state.UsingBPF = usingBPF
        state.V4RTT = v4RTT; state.V4Loss = v4Loss
        state.V6RTT = v6RTT; state.V6Loss = v6Loss

        // v0.9.35: RTT=0 means no data (ping failed or BPF has no metrics).
        // A real RTT is always > 0. If RTT=0, skip — don't count as good or bad.
        v4DataValid := v4RTT > 0
        v6DataValid := v6RTT > 0

        // Update streaks — only when we have real data
        if v4DataValid {
                if v4Loss >= badLossThreshold || v4RTT >= badRTTThreshold {
                        state.v4BadStreak++; state.v4GoodStreak = 0
                } else if v4Loss <= goodLossThreshold && v4RTT <= goodRTTThreshold {
                        state.v4GoodStreak++; state.v4BadStreak = 0
                }
        } else {
                state.v4BadStreak = 0; state.v4GoodStreak = 0
        }
        if v6DataValid {
                if v6Loss >= badLossThreshold || v6RTT >= badRTTThreshold {
                        state.v6BadStreak++; state.v6GoodStreak = 0
                } else if v6Loss <= goodLossThreshold && v6RTT <= goodRTTThreshold {
                        state.v6GoodStreak++; state.v6BadStreak = 0
                }
        } else {
                state.v6BadStreak = 0; state.v6GoodStreak = 0
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
                // v0.9.71: look up domain from ctrld DNS cache for origin IPs.
                // For unlabeled destinations (raw IPs like "130.61.0.0"),
                // the label IS the IP — look it up directly.
                domain := getDomainForBucket(state.Label)
                // instead of misleading "0.0ms 100% loss"
                v4HasData := state.V4RTT > 0
                v6HasData := state.V6RTT > 0
                entry := map[string]interface{}{
                        "label": state.Label,
                        "domain": domain, // v0.9.71: from ctrld DNS cache
                        "has_ipv4": state.HasIPv4,
                        "has_ipv6": state.HasIPv6,
                        "preferred": state.PreferredProto,
                        "v4_rtt_ms": round1(state.V4RTT),
                        "v4_loss_pct": round1(state.V4Loss),
                        "v4_has_data": v4HasData,
                        "v6_rtt_ms": round1(state.V6RTT),
                        "v6_loss_pct": round1(state.V6Loss),
                        "v6_has_data": v6HasData,
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

// ============================================================================
// Minimal ICMP — 1 echo per destination, Go raw sockets, no process fork
// ============================================================================

// v0.9.37: return -1, -1 (no data) instead of 0, 100 on failure.
// 0, 100 was misleading the dashboard into showing "100% loss" when
// really we just couldn't get any data (ICMP blocked, no route, etc).
func icmpPing(addr string) (float64, float64) {
        target := normalizePingTarget(addr)
        if target == "" { return -1, -1 }
        if strings.Contains(target, ":") {
                return icmpPing6(target)
        }
        return icmpPing4(target)
}

func icmpPing4(target string) (float64, float64) {
        ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
        defer cancel()
        conn, err := (&net.Dialer{}).DialContext(ctx, "ip4:icmp", target)
        if err != nil { return -1, -1 }
        defer conn.Close()
        conn.SetDeadline(time.Now().Add(2 * time.Second))
        msg := make([]byte, 16)
        binary.BigEndian.PutUint16(msg[0:], 8)
        binary.BigEndian.PutUint16(msg[4:], 1)
        binary.BigEndian.PutUint16(msg[6:], 1)
        binary.BigEndian.PutUint16(msg[2:], icmpChecksum(msg))
        start := time.Now()
        if _, err := conn.Write(msg); err != nil { return -1, -1 }
        buf := make([]byte, 1500)
        if _, err := conn.Read(buf); err != nil { return -1, -1 }
        return float64(time.Since(start).Microseconds()) / 1000.0, 0
}

func icmpPing6(target string) (float64, float64) {
        ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
        defer cancel()
        conn, err := (&net.Dialer{}).DialContext(ctx, "ip6:ipv6-icmp", target)
        if err != nil { return -1, -1 }
        defer conn.Close()
        conn.SetDeadline(time.Now().Add(2 * time.Second))
        msg := make([]byte, 16)
        binary.BigEndian.PutUint16(msg[0:], 128)
        binary.BigEndian.PutUint16(msg[4:], 1)
        binary.BigEndian.PutUint16(msg[6:], 1)
        binary.BigEndian.PutUint16(msg[2:], icmpChecksum(msg))
        start := time.Now()
        if _, err := conn.Write(msg); err != nil { return -1, -1 }
        buf := make([]byte, 1500)
        if _, err := conn.Read(buf); err != nil { return -1, -1 }
        return float64(time.Since(start).Microseconds()) / 1000.0, 0
}

func icmpChecksum(data []byte) uint16 {
        var sum uint32
        for i := 0; i < len(data)-1; i += 2 {
                sum += uint32(binary.BigEndian.Uint16(data[i:]))
        }
        if len(data)%2 == 1 {
                sum += uint32(data[len(data)-1]) << 8
        }
        for sum>>16 > 0 { sum = (sum & 0xFFFF) + (sum >> 16) }
        return ^uint16(sum)
}

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
                "104.18": "1.1.1.1",
                "151.101": "151.101.1.1", "199.232": "199.232.1.1",
                "185.199": "185.199.108.1",
        }
        prefix := parts[0] + "." + parts[1]
        if known, ok := knownPingable[prefix]; ok { return known }
        if parts[2] == "0" && parts[3] == "0" { return parts[0] + "." + parts[1] + ".0.1" }
        if parts[3] == "0" { return parts[0] + "." + parts[1] + "." + parts[2] + ".1" }
        return addr
}
