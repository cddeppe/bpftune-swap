package main

// csv_fallback.go — when the log tail is sparse (just rotated, or low
// traffic), fall back to reading recent swaps from swaps.csv so the
// dashboard panels always show data.
//
// The recent_swaps panel reads from the live log tail (last 16MB).
// When the log was just rotated, that's nearly empty — but swaps.csv
// has ALL historical swaps, going back days. This file reads the last
// N swaps from swaps.csv and formats them like log-derived swaps so
// the dashboard renders them identically.

import (
        "bufio"
        "os"
        "strconv"
        "strings"
)

// readRecentSwapsFromCSV reads the last N rows from swaps.csv and
// returns them in the same format as buildRecentSwapRows (newest-first).
// Returns empty slice if the file doesn't exist or is unreadable.
//
// swaps.csv columns (18):
//   collected_ts, boot_ts, cookie, from_alg, to_alg, d, mt_alg, rb_alg,
//   diverges, outcome, socket_rate_before, dest, dest_raw, f_ema, t_ema,
//   srate_before, direction, rport
func readRecentSwapsFromCSV(n int) []interface{} {
        f, err := os.Open(swapsCSVPath)
        if err != nil {
                return []interface{}{}
        }
        defer f.Close()

        // Read all lines (swaps.csv is typically 1-30MB, not huge)
        var lines []string
        scanner := bufio.NewScanner(f)
        scanner.Buffer(make([]byte, 0, 65536), 1024*1024)
        for scanner.Scan() {
                lines = append(lines, scanner.Text())
        }
        if len(lines) < 2 {
                return []interface{}{}
        }

        // Skip header (first line)
        lines = lines[1:]

        // Take last N
        if len(lines) > n {
                lines = lines[len(lines)-n:]
        }

        out := make([]interface{}, 0, len(lines))
        // Reverse so newest-first (CSV is oldest-first)
        for i := len(lines) - 1; i >= 0; i-- {
                fields := strings.Split(lines[i], ",")
                if len(fields) < 18 {
                        continue
                }
                collectedTs, _ := strconv.ParseInt(fields[0], 10, 64)
                // v0.9.21: sanity check — if collected_ts < 1e9 (before 2001),
                // it's BPF ktime from the old backfill bug, not wall-clock epoch.
                // Set to 0 so ageLabel skips it (returns empty, same as before).
                if collectedTs > 0 && collectedTs < 1000000000 {
                        collectedTs = 0
                }
                bootTs, _ := strconv.ParseFloat(fields[1], 64)
                fromAlg := fields[3]
                toAlg := fields[4]
                d, _ := strconv.Atoi(fields[5])
                mtAlg := fields[6]
                rbAlg := fields[7]
                outcome := fields[9]
                dest := fields[11]
                // Apply label resolution
                destLabel := labelFor(dest)
                if destLabel == "" {
                        destLabel = dest
                }
                row := map[string]interface{}{
                        "boot_ts":           bootTs,
                        "epoch_ts":          collectedTs,
                        "from_alg":          fromAlg,
                        "to_alg":            toAlg,
                        "d":                 d,
                        "outcome":           outcome,
                        "outcome_sustained": outcome, // CSV already has the sustained outcome
                        "mt_alg":            mtAlg,
                        "rb_alg":            rbAlg,
                        "dest":              destLabel,
                }
                out = append(out, row)
        }
        return out
}

// readRecentProofsFromCSV reads the last N rows from proofs.csv and
// returns them in the same format as buildRecentProofRows (newest-first).
// Returns empty slice if the file doesn't exist or is unreadable.
//
// proofs.csv columns (8):
//   collected_ts, boot_ts, cookie, alg, rate_bps, mbps, tier, dest
func readRecentProofsFromCSV(n int) []interface{} {
        f, err := os.Open(proofsCSVPath)
        if err != nil {
                return []interface{}{}
        }
        defer f.Close()

        var lines []string
        scanner := bufio.NewScanner(f)
        scanner.Buffer(make([]byte, 0, 65536), 1024*1024)
        for scanner.Scan() {
                lines = append(lines, scanner.Text())
        }
        if len(lines) < 2 {
                return []interface{}{}
        }

        // Skip header
        lines = lines[1:]

        // Take last N
        if len(lines) > n {
                lines = lines[len(lines)-n:]
        }

        out := make([]interface{}, 0, len(lines))
        // Reverse so newest-first
        for i := len(lines) - 1; i >= 0; i-- {
                fields := strings.Split(lines[i], ",")
                if len(fields) < 8 {
                        continue
                }
                collectedTs, _ := strconv.ParseInt(fields[0], 10, 64)
                if collectedTs > 0 && collectedTs < 1000000000 {
                        collectedTs = 0
                }
                ts, _ := strconv.ParseFloat(fields[1], 64)
                alg := fields[3]
                mbps, _ := strconv.ParseFloat(fields[5], 64)
                tier := fields[6]
                tierLabel := "good"
                if tier == "2" {
                        tierLabel = "proved"
                }
                dest := fields[7]
                destLabel := labelFor(dest)
                if destLabel == "" {
                        destLabel = dest
                }
                out = append(out, map[string]interface{}{
                        "boot_ts":  ts,
                        // v0.9.31 (Bug 9): use collectedTs (wall-clock) not boot_ts formula.
                        // The boot_ts formula produces future timestamps for cross-boot data.
                        "epoch_ts": collectedTs,
                        "alg":      alg,
                        "mbps":     mbps,
                        "tier":     tierLabel,
                        "dest":    destLabel,
                })
        }
        return out
}
