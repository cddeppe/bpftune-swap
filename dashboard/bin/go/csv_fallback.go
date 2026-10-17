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
        "fmt"
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
        // v0.9.95 (AUDIT-SWAPS-1 + AUDIT-PROOFS-1): dedup at read time by
        // boot_ts+cookie. After a dashboard restart, writtenSwaps is empty so
        // the same swap event gets re-written to CSV with a new collected_ts
        // (T2) alongside the original (T1). Without this dedup, both rows
        // would appear in the panel as duplicates. With it, the FIRST seen
        // (which is the NEWEST because the loop below iterates newest-first)
        // wins and the duplicate is dropped. Keyed by boot_ts:cookie — both
        // fields uniquely identify the underlying swap event (cookie is
        // kernel-assigned, boot_ts is BPF ktime at the event).
        seen := make(map[string]bool)
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
                cookieStr := fields[2]
                dedupKey := fmt.Sprintf("%.3f:%s", bootTs, cookieStr)
                if seen[dedupKey] {
                        continue
                }
                seen[dedupKey] = true
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
			"outcome_srate":     "", // v0.9.88: add for frontend compat
			"_bucket":           destLabel, // v0.9.88: add for swap_outcomes filter
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
        // v0.9.95 (AUDIT-PROOFS-1): dedup at read time by boot_ts+alg. After
        // a dashboard restart, writtenProofs is empty so the same proof event
        // gets re-written to CSV with a new collected_ts (T2) alongside the
        // original (T1). Without this dedup, both rows would appear in the
        // panel as duplicates. With it, the FIRST seen (which is the NEWEST
        // because the loop below iterates newest-first) wins and the duplicate
        // is dropped. Keyed by boot_ts:alg — both fields uniquely identify
        // the underlying proof event (alg is the algorithm, boot_ts is BPF
        // ktime at the event).
        seen := make(map[string]bool)
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
                dedupKey := fmt.Sprintf("%.3f:%s", ts, alg)
                if seen[dedupKey] {
                        continue
                }
                seen[dedupKey] = true
                mbps, _ := strconv.ParseFloat(fields[5], 64)
                tier := fields[6]
                tierLabel := "good"
                if tier == "2" {
                        tierLabel = "proved"
                }
                dest := fields[7]
                // v0.9.94: skip rows with empty dest. These are legacy rows
                // written by older dashboard versions (pre-v0.9.91) that used
                // the merged topProofs list — they include CSV fallback proofs
                // with no dest= field. v0.9.93 prevents NEW empty-dest rows
                // from being written, but the existing ones in proofs.csv
                // would still show as (unknown) in the panel without this
                // filter. Skipping them here means the panel never shows
                // (unknown) — even if the CSV still has legacy empty-dest
                // rows, they're silently filtered out at read time.
                if dest == "" {
                        continue
                }
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
