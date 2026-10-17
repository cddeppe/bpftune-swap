package main

// csv_writer.go — appends to the existing buckets.v2.csv, swaps.csv,
// srate.csv files.  Matches the column format of the Python collector
// so the historical data continues seamlessly.
//
// v0.7.0 change: the addr column is written as the LABELED form (already
// resolved by readBPFMap → hostEntry.Addr).  The CSV reader trusts this
// and does NOT re-apply ResolveBucket on read.  This was the root cause
// of "custom bucket disappears": applying ResolveBucket again at read
// time would remap a labeled "controld" back to itself (no harm) BUT
// would also remap a raw "2606:1a40::" (no label) to "controld" if a
// label was added later — splitting the bucket into two ring-buffer
// entries (one keyed by the old label, one keyed by the new label).
// Now historical rows stay under the same key as new rows.
//
// Trade-off: if a label is added LATER, old rows written before the
// label existed stay under the old (unlabeled) key.  The user can fix
// this by running the dashboard for 24h after adding a label — the
// old rows will age out of the 24h window.  Alternatively, a one-time
// migration script could be written to re-resolve historical rows,
// but that's out of scope here.
//
// buckets.v2.csv columns (94 total):
//   collected_ts, addr, instances, min_rtt, ref_rate, best_i, best_alg,
//   rate_best_i, rate_best_v,
//   mv_<alg>, re_<alg>  (16 algs × 2 = 32 columns)
//   tcp_rmem_min, tcp_rmem_def, tcp_rmem_max
//   ss_<alg>  (16 algs)
//   bs_<alg>  (16 algs)
//   ns_<alg>  (16 algs)
//
// swaps.csv columns (18):
//   collected_ts, boot_ts, cookie, from_alg, to_alg, d, mt_alg, rb_alg,
//   diverges, outcome, socket_rate_before, dest, dest_raw, f_ema, t_ema,
//   srate_before, direction, rport
//
// srate.csv columns (5):
//   collected_ts, boot_ts, cookie, alg, srate

import (
        "fmt"
        "os"
        "strconv"
        "strings"
        "sync"
        "time"
)

// CSV file paths.  These are vars (not consts) so the --data-root flag
// can override them at startup for sandboxed testing.
var (
        bucketsCSVPath = "/var/lib/bpftune/history/buckets.v2.csv"
        swapsCSVPath   = "/var/lib/bpftune/history/swaps.csv"
        srateCSVPath   = "/var/lib/bpftune/history/srate.csv"
        proofsCSVPath  = "/var/lib/bpftune/history/proofs.csv"  // v0.9.5: for proof panel fallback
        midsampCSVPath = "/var/lib/bpftune/history/midsamp.csv" // v0.9.7: for rate progression fallback
)

// Dedup sets — track which swaps/srates/proofs have already been written to CSV.
// Keyed by a composite "cookie:ts" string which uniquely identifies an event.
//
// v0.9.96: ALL dedup maps are now flat (single map, no outer-keyed-by-cookie
// nested map). The old `map[int64]map[float64]bool{}` form grew an OUTER entry
// per unique cookie and the outer map was NEVER pruned (only the inner map's
// size was capped). On a 1-week-running host with ~10k unique cookies/day,
// the outer map leaked ~70k entries × ~80 B = ~5.6 MB across all four maps,
// plus the inner maps' headers (~150 B each × 70k = ~10 MB) — totals ~90 MB
// of dead-state growth over a week.
//
// `writtenProofsFlat` is keyed by ts only (proof events are uniquely
// identified by boot_ts) — the old code derived cookieFake = int64(ts) from
// ts anyway, so the outer dimension was completely redundant.
var (
        writtenSwapsFlat    = map[string]bool{}   // v0.9.96: flat swaps.csv dedup, key "cookie:ts"
        writtenSratesFlat   = map[string]bool{}   // v0.9.96: flat srate.csv dedup, key "cookie:ts"
        writtenTruthFlat    = map[string]bool{}   // v0.9.96: flat swapscore_truth dedup, key "cookie:ts"
        writtenProofsFlat   = map[float64]bool{}  // v0.9.96: flat proofs.csv dedup, key ts (boot_ts uniquely identifies a proof)
        dedupMu             sync.Mutex
)

// COL-001 fix: writeCSVHeaderIfEmpty checks if CSV file is empty
// and writes the header row if so. Prevents first data row from
// being treated as header by csv.DictReader (loses all per-alg cols).
func writeCSVHeaderIfEmpty(path, header string) {
        info, err := os.Stat(path)
        if err != nil {
                if !os.IsNotExist(err) {
                        return
                }
                os.WriteFile(path, []byte(header+"\n"), 0644)
                return
        }
        if info.Size() == 0 {
                os.WriteFile(path, []byte(header+"\n"), 0644)
        }
}

func bucketsCSVHeader() string {
        parts := []string{"collected_ts", "addr", "instances", "min_rtt", "ref_rate", "best_i", "best_alg", "rate_best_i", "rate_best_v"}
        for _, alg := range CONGS {
                parts = append(parts, "mv_"+alg, "re_"+alg)
        }
        parts = append(parts, "tcp_rmem_min", "tcp_rmem_def", "tcp_rmem_max")
        for _, alg := range CONGS {
                parts = append(parts, "ss_"+alg)
        }
        for _, alg := range CONGS {
                parts = append(parts, "bs_"+alg)
        }
        for _, alg := range CONGS {
                parts = append(parts, "ns_"+alg)
        }
        return strings.Join(parts, ",")
}

func swapsCSVHeader() string {
        return strings.Join([]string{"collected_ts", "boot_ts", "cookie", "from_alg", "to_alg", "d", "mt_alg", "rb_alg", "diverges", "outcome", "socket_rate_before", "dest", "dest_raw", "f_ema", "t_ema", "srate_before", "direction", "rport"}, ",")
}

// v0.9.5: proofs.csv — one row per NEW proof event (deduplicated).
// Used as fallback for the recent proofs panel when the log tail is sparse.
// Columns: collected_ts, boot_ts, cookie, alg, rate_bps, mbps, tier, dest
func proofsCSVHeader() string {
        return strings.Join([]string{"collected_ts", "boot_ts", "cookie", "alg", "rate_bps", "mbps", "tier", "dest"}, ",")
}

func srateCSVHeader() string {
        return strings.Join([]string{"collected_ts", "boot_ts", "cookie", "alg", "srate"}, ",")
}

// ============================================================================
// writeBucketsCSV — one row per bucket per 30s cycle
// ============================================================================

func writeBucketsCSV(hosts []hostEntry, now int64) {
        // COL-001 fix: ensure header exists
        writeCSVHeaderIfEmpty(bucketsCSVPath, bucketsCSVHeader())
        f, err := os.OpenFile(bucketsCSVPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
        if err != nil {
                return
        }
        defer f.Close()

        rmemMin, rmemDef, rmemMax := readTcpRmem()

        for _, h := range hosts {
                if h.Inst < 2 {
                        continue
                }
                row := buildBucketCSVRow(h, now, rmemMin, rmemDef, rmemMax)
                f.WriteString(row + "\n")
        }
}

func buildBucketCSVRow(h hostEntry, now int64, rmemMin, rmemDef, rmemMax int) string {
        v := h.V
        metrics, _ := v["metrics"].([]interface{})

        mv := make([]string, 16)
        re := make([]string, 16)
        ss := make([]string, 16)
        bs := make([]string, 16)
        ns := make([]string, 16)
        for i := 0; i < 16; i++ {
                var mi map[string]interface{}
                if i < len(metrics) {
                        mi, _ = metrics[i].(map[string]interface{})
                }
                if mi == nil {
                        mv[i] = ""
                        re[i] = ""
                        ss[i] = ""
                        bs[i] = ""
                        ns[i] = ""
                } else {
                        mv[i] = strconv.FormatFloat(toFloat(mi["metric_value"]), 'f', -1, 64)
                        re[i] = strconv.FormatFloat(toFloat(mi["rate_ema"]), 'f', -1, 64)
                        mc := toInt(mi["metric_count"])
                        if mc > 0 || toInt(mi["sockets_alive"]) > 0 || toFloat(mi["rate_ema"]) > 0 {
                                ss[i] = strconv.Itoa(toInt(mi["swap_score"]))
                                bs[i] = strconv.Itoa(toInt(mi["bad_streak"]))
                                ns[i] = strconv.Itoa(toInt(mi["null_streak"]))
                        } else {
                                ss[i] = ""
                                bs[i] = ""
                                ns[i] = ""
                        }
                }
        }

        bestI := toInt(v["best_i"])
        bestAlg := ""
        if bestI >= 0 && bestI < len(CONGS) {
                bestAlg = CONGS[bestI]
        }

        rateBestI := bestI
        rateBestV := 0.0
        if bestI >= 0 && bestI < len(metrics) {
                mi, _ := metrics[bestI].(map[string]interface{})
                if mi != nil {
                        rateBestV = toFloat(mi["rate_ema"])
                }
        }
        parts := []string{
                strconv.FormatInt(now, 10), // collected_ts
                h.Addr,                     // addr (LABELED — do not re-resolve on read)
                strconv.Itoa(h.Inst),       // instances
                strconv.FormatFloat(toFloat(v["min_rtt"]), 'f', -1, 64),
                strconv.FormatFloat(toFloat(v["max_rate_delivered"])/bpsToMbps, 'f', -1, 64),
                strconv.Itoa(bestI),
                bestAlg,
                strconv.Itoa(rateBestI), // rate_best_i
                strconv.FormatFloat(rateBestV, 'f', -1, 64), // rate_best_v
        }
        for i := 0; i < 16; i++ {
                parts = append(parts, mv[i], re[i])
        }
        parts = append(parts,
                strconv.Itoa(rmemMin),
                strconv.Itoa(rmemDef),
                strconv.Itoa(rmemMax),
        )
        parts = append(parts, ss...)
        parts = append(parts, bs...)
        parts = append(parts, ns...)

        return strings.Join(parts, ",")
}

// ============================================================================
// writeSwapsCSV — one row per NEW swap event (deduplicated)
// ============================================================================

func writeSwapsCSV(swaps []swapRow, now int64) {
        dedupMu.Lock()
        defer dedupMu.Unlock()

        // COL-001 fix: ensure header exists
        writeCSVHeaderIfEmpty(swapsCSVPath, swapsCSVHeader())
        f, err := os.OpenFile(swapsCSVPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
        if err != nil {
                return
        }
        defer f.Close()

        for _, sw := range swaps {
                // v0.9.96: flat map keyed by "cookie:ts" — was nested
                // map[int64]map[float64]bool keyed by (cookie, ts). The outer
                // map was never pruned, leaking ~1 entry per unique cookie
                // (~70k over a week on busy hosts).
                key := fmt.Sprintf("%d:%.6f", sw.Cookie, sw.Ts)
                if writtenSwapsFlat[key] {
                        continue
                }
                writtenSwapsFlat[key] = true

                // Prune entries whose ts part is older than 1 hour, once we
                // exceed 5000 entries (5× the per-cookie cap of the old form —
                // 5000 covers ~50 active cookies × 100 events each).
                if len(writtenSwapsFlat) > 5000 {
                        for k := range writtenSwapsFlat {
                                if idx := strings.Index(k, ":"); idx >= 0 {
                                        if kts, err := strconv.ParseFloat(k[idx+1:], 64); err == nil && kts < sw.Ts-3600 {
                                                delete(writtenSwapsFlat, k)
                                        }
                                }
                        }
                }

                row := buildSwapCSVRow(sw, now)
                f.WriteString(row + "\n")
                // v0.7.6: write truth file entry for resolved swaps.
                // v0.9.0: pass sw.DestResolved (full dest including v6/v6b) instead
                // of destIP(sw.Dest) — fixes IPv6 swaps being silently dropped
                // from the ML training file.
                if sw.Outcome == "win" || sw.Outcome == "loss" || sw.Outcome == "null" {
                        writeTruthRow(sw.DestResolved, algName(sw.To), sw.Outcome)
                }
        }
}

func buildSwapCSVRow(sw swapRow, now int64) string {
        mtAlg := ""
        if sw.Mt != "" {
                if i, err := strconv.Atoi(sw.Mt); err == nil {
                        mtAlg = CONGS[i&15]
                }
        }
        rbAlg := ""
        if sw.Rb != "" {
                if i, err := strconv.Atoi(sw.Rb); err == nil {
                        rbAlg = CONGS[i&15]
                }
        }
        fromAlg := algName(sw.From)
        toAlg := algName(sw.To)
        d, _ := strconv.Atoi(sw.D)
        diverges := "0"
        if mtAlg != "" && rbAlg != "" && mtAlg != rbAlg {
                diverges = "1"
        }
        dest := sw.DestResolved // v0.9.0: use the fully-resolved dest (handles v6)
        if dest == "" {
                dest = destIP(sw.Dest) // fall back to v4-only if enrichment didn't run
        }
        destRaw := sw.Dest

        parts := []string{
                strconv.FormatInt(now, 10),
                strconv.FormatFloat(sw.Ts, 'f', 6, 64),
                strconv.FormatInt(sw.Cookie, 10),
                fromAlg,
                toAlg,
                strconv.Itoa(d),
                mtAlg,
                rbAlg,
                diverges,
                sw.Outcome,     // outcome (enriched: win/loss/null/no_post/"")
                sw.SrateBefore, // socket_rate_before (enriched: pre-swap srate)
                dest,
                destRaw,
                "",             // f_ema (TODO: from BPF map)
                "",             // t_ema (TODO: from BPF map)
                sw.SrateBefore, // srate_before (same as socket_rate_before)
                sw.Direction,   // direction (enriched: origin/client/"")
                sw.Rport,       // rport (enriched: from met event)
        }
        return strings.Join(parts, ",")
}

// ============================================================================
// writeSrateCSVFromParsed — one row per NEW srate event (deduplicated)
//
// v0.7.0: takes pre-parsed srate entries instead of re-parsing the log
// text.  Eliminates the 3rd log-parse per cycle (was 30% of CPU).
// ============================================================================

func writeSrateCSVFromParsed(srateByCookie map[int64][]srateEntry, now int64) {
        dedupMu.Lock()
        defer dedupMu.Unlock()

        if len(srateByCookie) == 0 {
                return
        }

        // COL-001 fix: ensure header exists
        writeCSVHeaderIfEmpty(srateCSVPath, srateCSVHeader())
        f, err := os.OpenFile(srateCSVPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
        if err != nil {
                return
        }
        defer f.Close()

        for cookie, events := range srateByCookie {
                for _, e := range events {
                        // v0.9.96: flat map keyed by "cookie:ts" (was nested
                        // map[int64]map[float64]bool — outer never pruned).
                        key := fmt.Sprintf("%d:%.6f", cookie, e.Ts)
                        if writtenSratesFlat[key] {
                                continue
                        }
                        writtenSratesFlat[key] = true

                        if len(writtenSratesFlat) > 5000 {
                                for k := range writtenSratesFlat {
                                        if idx := strings.Index(k, ":"); idx >= 0 {
                                                if kts, err := strconv.ParseFloat(k[idx+1:], 64); err == nil && kts < e.Ts-3600 {
                                                        delete(writtenSratesFlat, k)
                                                }
                                        }
                                }
                        }

                        alg := algName(e.Alg)
                        parts := []string{
                                strconv.FormatInt(now, 10),
                                strconv.FormatFloat(e.Ts, 'f', 6, 64),
                                strconv.FormatInt(cookie, 10),
                                alg,
                                strconv.FormatInt(e.Srate, 10),
                        }
                        f.WriteString(strings.Join(parts, ",") + "\n")
                }
        }
}

// ============================================================================
// readTcpRmem — reads /proc/sys/net/ipv4/tcp_rmem
// ============================================================================

func readTcpRmem() (min, def, max int) {
        data, err := os.ReadFile("/proc/sys/net/ipv4/tcp_rmem")
        if err != nil {
                return 4096, 87380, 6291456
        }
        parts := strings.Fields(string(data))
        if len(parts) < 3 {
                return 4096, 87380, 6291456
        }
        min, _ = strconv.Atoi(parts[0])
        def, _ = strconv.Atoi(parts[1])
        max, _ = strconv.Atoi(parts[2])
        return
}

// writeProofsCSVFromInterface takes the []interface{} from buildRecentProofRows
// and writes each to proofs.csv.  Called from collect.go.
func writeProofsCSVFromInterface(proofs []interface{}, now int64) {
        if len(proofs) == 0 {
                return
        }
        dedupMu.Lock()
        defer dedupMu.Unlock()

        writeCSVHeaderIfEmpty(proofsCSVPath, proofsCSVHeader())
        f, err := os.OpenFile(proofsCSVPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
        if err != nil {
                return
        }
        defer f.Close()

        for _, p := range proofs {
                row, ok := p.(map[string]interface{})
                if !ok {
                        continue
                }
                ts, _ := row["boot_ts"].(float64)
                alg, _ := row["alg"].(string)
                mbps, _ := row["mbps"].(float64)
                tier, _ := row["tier"].(string)
                dest, _ := row["dest"].(string)
                // v0.9.93: skip rows with empty dest. This happens when:
                //   - The proof line had no dest=/dest6=/dest6b= fields
                //     (old BPF binary pre-v0.4.98 — proofs from rotated
                //     log files like bpftune-met-live.log.1 still have
                //     this old format)
                //   - The cdest[cookie] lookup also failed (cookie from
                //     previous bpftune run isn't in current cdest map)
                // Writing these to proofs.csv creates the (unknown) dest
                // feedback loop: CSV fallback rows with empty dest get
                // read back next cycle and shown in the panel as (unknown).
                // Skip them entirely — better to have fewer proofs in the
                // panel than to pollute the CSV with (unknown) rows.
                if dest == "" {
                        continue
                }
                // Convert tier label back to numeric for CSV
                tierNum := "1"
                if tier == "proved" {
                        tierNum = "2"
                }
                // Compute rate_bps from mbps
                rateBps := int64(mbps * bpsToMbps)
                // v0.9.96: flat map keyed by ts (proof events are uniquely
                // identified by boot_ts). Was: nested map keyed by
                // (int64(ts), ts) — redundant because cookieFake = int64(ts)
                // is derived from ts. The outer map was never pruned, growing
                // ~1 entry per proof event (~86k/day = ~13 MB/day = ~90 MB/wk).
                if writtenProofsFlat[ts] {
                        continue
                }
                writtenProofsFlat[ts] = true

                // Prune entries older than 1 hour once we exceed 1000.
                // (Proofs are ~1/sec at most, so 1000 = ~17 min headroom.)
                if len(writtenProofsFlat) > 1000 {
                        for k := range writtenProofsFlat {
                                if k < ts-3600 {
                                        delete(writtenProofsFlat, k)
                                }
                        }
                }

                // cookieFake for the CSV column is still int64(ts) — preserves
                // the on-disk column format exactly (no CSV byte changes).
                cookieFake := int64(ts)
                csvRow := []string{
                        strconv.FormatInt(now, 10),
                        strconv.FormatFloat(ts, 'f', 6, 64),
                        strconv.FormatInt(cookieFake, 10),
                        alg,
                        strconv.FormatInt(rateBps, 10),
                        strconv.FormatFloat(mbps, 'f', 1, 64),
                        tierNum,
                        dest,
                }
                f.WriteString(strings.Join(csvRow, ",") + "\n")
        }
}

// ============================================================================
// writeProofsCSV — one row per NEW proof event (deduplicated)
//
// v0.9.5: proofs.csv is the fallback for the recent proofs panel.
// When the live log tail doesn't have enough proof events (e.g. after
// log rotation, or when estab events dominate the tail), the panel
// reads the last N proofs from proofs.csv instead.
//
// Proof events are parsed from the log text by buildRecentProofRows
// and buildProofsRawEvents. We pass the parsed results here to write
// them to CSV.
// ============================================================================

type proofCSVRow struct {
        Ts      float64
        Cookie  string
        Alg     string
        RateBps int64
        Mbps    float64
        Tier    string
        Dest    string
}

// ============================================================================
// suppress unused warning
// ============================================================================

var _ = fmt.Sprintf
var _ = time.Now
