package main

// rate_ema_writeback.go — Backfill rate_ema in remote_host_map from proof events.
//
// PROBLEM
// =======
// For short-lived sockets (e.g. cloudflared tunnel connections to Cloudflare),
// the BPF tuner's periodic srate sampler never fires — the socket closes before
// the sampler ticks. As a result, rate_ema in remote_host_map stays at 0 for
// those (dest, alg) entries.
//
// The BPF picker (tcp_conn_tuner.bpf.c lines 1380-1414) reads rate_ema
// directly from the map to choose swap targets:
//   if (remote_host->metrics[rt].rate_ema > 0) { ... compare algs ... }
// With rate_ema = 0, the picker cannot differentiate algorithms — every alg
// scores 0 via the formula `rate_ema * swap_score / 256 * penalty`.
//
// Meanwhile, proof events DO fire for these sockets (at close time, capturing
// the final delivered rate). The proof rate is a real measurement — Cloudflare
// proofs show 45-266 Mb/s — but that data never reaches the BPF map.
//
// FIX
// ===
// This file adds writebackRateEmaFromProofs, called every 60s (every 2nd
// collect cycle) alongside writebackStreaks. For each (dest, alg) pair that
// has a recent proof event AND rate_ema == 0 in the BPF map, we write the
// proof rate as rate_ema.
//
// SAFETY
// ======
//  1. Only writes when rate_ema is currently 0. If the BPF srate path has
//     populated it, we leave it alone — no overwrite of BPF-managed values.
//  2. Uses the same writebackMu mutex as writebackStreaks — they never run
//     concurrently. If streak writeback is in progress, this skips the cycle.
//  3. Uses the same read-modify-write pattern as streak_writeback.go (proven
//     in production since v0.7.6). Reads the whole remote_host struct,
//     patches the rate_ema field, writes it back.
//  4. The rate_ema field is __u16 (max 65535) in 100KB/s units. Proof rates
//     are capped to 65535 before writing — no overflow.
//  5. The picker reads rate_ema atomically (aligned __u16 read), so there's
//     no torn-read risk from our write.
//
// UNIT CONVERSION
// ===============
// parsedProof.rate is in bytes per second (Bps).
// RATE_EMA_BYTES_PER_UNIT = 100000 (100 KB).
// So: rate_ema = rate_Bps / 100000, capped at 65535.
// Example: 100.9 Mb/s = 12,612,500 Bps → rate_ema = 126.

import (
        "encoding/binary"
        "fmt"
        "net"
        "os"
        "sort"
        "strconv"
)

// Offset of rate_ema within struct tcp_conn_metric.
// Layout: state_flags(8) + greedy_count(8) + metric_count(8) + metric_value(8)
//         + sockets_alive(2) + sockets_good(2) + sockets_proved(2) = 38
// Then:  rate_ema(2) at offset 38, swap_score(2) at 40,
//        bad_streak(1) at 42, null_streak(1) at 43.
// Matches offMetricBadStreak=42, offMetricNullStreak=43 in streak_writeback.go.
const offMetricRateEma = 38

// RATE_EMA_BYTES_PER_UNIT must match the BPF constant (100000 = 100 KB).
// rate_ema is stored as rate_Bps / 100000, capped to __u16 (65535).
const rateEmaBytesPerUnit = int64(100000)
const rateEmaMax = 65535

// destStringsToIP converts raw decimal-u32 dest fields (v4/v6/v6b) to a
// net.ParseIP-parseable string, mirroring swapDestToIP from streak_writeback.go.
// Do NOT use destStr() — that returns display labels like "v6:%08x" for
// v6-only dests which maskedIP() rejects.
func destStringsToIP(v4, v6, v6b string) string {
        // v4 path: decimal u32 → dotted-quad
        if v4 != "" && v4 != "0" {
                if n, err := strconv.ParseUint(v4, 10, 32); err == nil && n != 0 {
                        return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n)).String()
                }
                if ip := net.ParseIP(v4); ip != nil {
                        return ip.String()
                }
        }
        // v6 path: decimal u32 → first 4 bytes of 16-byte IPv6
        if v6 != "" && v6 != "0" {
                if n, err := strconv.ParseUint(v6, 10, 32); err == nil && n != 0 {
                        b := make([]byte, 16)
                        b[0] = byte(n >> 24)
                        b[1] = byte(n >> 16)
                        b[2] = byte(n >> 8)
                        b[3] = byte(n)
                        if v6b != "" && v6b != "0" {
                                if n6b, err := strconv.ParseUint(v6b, 10, 32); err == nil && n6b != 0 {
                                        b[4] = byte(n6b >> 24)
                                        b[5] = byte(n6b >> 16)
                                        b[6] = byte(n6b >> 8)
                                        b[7] = byte(n6b)
                                }
                        }
                        return net.IP(b).String()
                }
        }
        return ""
}

// writebackRateEmaFromProofs is the per-cycle entry point. Called from
// collect() every 60s (every 2nd cycle, same cadence as writebackStreaks).
// Takes the parsed proof events and writes rate_ema into remote_host_map
// for any (dest, alg) entry that currently has rate_ema == 0.
//
// Returns (hostsPatched, slotsPatched) for logging.
func (c *Collector) writebackRateEmaFromProofs(proofs []parsedProof, cdest map[string]cdestEntry) (int, int) {
        // TryLock: if streak writeback is still running, skip this cycle.
        if !writebackMu.TryLock() {
                fmt.Fprintf(os.Stderr, "[rate_ema_wb] skipped (writeback mutex busy)\n")
                return 0, 0
        }
        defer writebackMu.Unlock()

        mapID, err := resolveRemoteHostMapID()
        if err != nil {
                fmt.Fprintf(os.Stderr, "[rate_ema_wb] no remote_host_map: %v\n", err)
                return 0, 0
        }
        detectMask(mapID)

        // Group proofs by (masked_host, alg). For each group, keep the MAX rate
        // (the best observed delivery — most representative of what the alg can do).
        type proofKey struct {
                host string
                alg  int
        }
        bestRateByPair := map[proofKey]int64{}
        skippedNoDest := 0
        for _, pp := range proofs {
                // Resolve raw dest IP directly from v4/v6/v6b decimal-u32 fields,
                // mirroring swapDestToIP. Do NOT use destStr() — that returns display
                // labels like "v6:%08x" for v6-only dests which maskedIP() rejects.
                var rawDest string
                if pp.v4 != "" || pp.v6 != "" || pp.v6b != "" {
                        rawDest = destStringsToIP(pp.v4, pp.v6, pp.v6b)
                } else if d, ok := cdest[pp.cookie]; ok {
                        rawDest = destStringsToIP(d[0], d[1], d[2])
                }
                if rawDest == "" {
                        skippedNoDest++
                        continue
                }
                host := maskedIP(rawDest)
                if host == "" {
                        continue
                }
                k := proofKey{host: host, alg: pp.alg}
                if pp.rate > bestRateByPair[k] {
                        bestRateByPair[k] = pp.rate
                }
        }
        if skippedNoDest > 0 {
                fmt.Fprintf(os.Stderr, "[rate_ema_wb] %d proofs skipped (no dest)\n", skippedNoDest)
        }
        if len(bestRateByPair) == 0 {
                return 0, 0
        }

        // Group by host so we do one BPF map lookup per host (not per proof).
        hostsByPair := map[string]map[int]int64{} // host -> {alg: bestRate}
        for k, rate := range bestRateByPair {
                if hostsByPair[k.host] == nil {
                        hostsByPair[k.host] = map[int]int64{}
                }
                hostsByPair[k.host][k.alg] = rate
        }

        totalHosts, totalSlots := 0, 0
        for host, algRates := range hostsByPair {
                keyArgs := keyArgsFor(host)
                if keyArgs == nil {
                        continue
                }

                // Lookup current BPF map value (one syscall per host).
                buf, err := mapLookupBytes(mapID, keyArgs)
                if err != nil {
                        continue
                }
                if buf == nil || len(buf) != sizeofRemoteHost {
                        fmt.Fprintf(os.Stderr, "[rate_ema_wb] WARN: %s buf %d!=%d; skip\n", host, len(buf), sizeofRemoteHost)
                        continue
                }

                // Check each alg in this host's proof set.
                // Only write rate_ema for algs where it's currently 0.
                patches := 0
                for alg, rate := range algRates {
                        if alg < 0 || alg >= numTCPConnMetrics {
                                continue
                        }
                        off := offMetricsArray + alg*sizeofTCPConnMetric + offMetricRateEma
                        if off+2 > len(buf) {
                                continue
                        }
                        curEma := binary.LittleEndian.Uint16(buf[off : off+2])
                        if curEma != 0 {
                                // BPF srate path has populated this — leave it alone.
                                continue
                        }

                        // Convert proof rate (Bps) to rate_ema units (100KB/s), cap at 65535.
                        newEma := rate / rateEmaBytesPerUnit
                        if newEma > rateEmaMax {
                                newEma = rateEmaMax
                        }
                        if newEma <= 0 {
                                continue
                        }

                        binary.LittleEndian.PutUint16(buf[off:off+2], uint16(newEma))
                        patches++
                }

                if patches == 0 {
                        continue
                }

                // Write the modified buffer back to the BPF map.
                if mapUpdateBytes(mapID, keyArgs, buf) {
                        totalHosts++
                        totalSlots += patches
                        // Log which algs got patched (for debugging).
                        algList := make([]int, 0, patches)
                        for alg := range algRates {
                                algList = append(algList, alg)
                        }
                        sort.Ints(algList)
                        fmt.Fprintf(os.Stderr, "[rate_ema_wb] %s: patched %d alg slot(s) from proofs\n", host, patches)
                }
        }

        if totalSlots > 0 {
                fmt.Fprintf(os.Stderr, "[rate_ema_wb] wrote rate_ema for %d alg slot(s) across %d host(s)\n", totalSlots, totalHosts)
        }
        return totalHosts, totalSlots
}
