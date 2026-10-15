package main

// Full log-parsing + swap-outcome derivation.
// Mirrors bpftune_log.py (_swaps_mets_srates, _proof_events,
// _cookie_dest_map, _dest_str, _bucket_of) + bpftune_data.py
// (data_recent_swaps, data_recent_proofs, data_swap_outcomes,
// _outcome_composite, _outcome_srate, _outcome_sustained,
// _finalize_outcome, _add_loss_recovery).
//
// The Go collector re-parses the log tail (last 2MB across all
// bpftune-met-*.log files) every collect() cycle.  This matches the
// Python CLI's data_* approach (no cross-cycle state needed for
// outcome derivation — the tail is wide enough to contain both a
// swap and its post-swap srate samples 60-300s later).

import (
        "fmt"
        "os"
        "path/filepath"
        "regexp"
        "sort"
        "strconv"
        "strings"
        "time"
)

// ============================================================================
// Regex patterns — exact mirrors of bpftune_log.py
// ============================================================================

var (
        rxSwap = regexp.MustCompile(
                `(\d+\.\d+): bpf_trace_printk: swap cookie=(\d+) ` +
                        `from=(\d+) to=(\d+) bc=(\d+) ac=(\d+) d=(\d+)` +
                        `(?: mt=(\d+) rb=(\d+))?` +
                        `(?: dest=(\d+))?` +
                        `(?: dest6=(\d+))?` +
                        `(?: dest6b=(\d+))?`)

        rxMet = regexp.MustCompile(
                `(\d+\.\d+): bpf_trace_printk: met cookie=(\d+) ` +
                        `rport=(\d+) alg=(\d+) segs=(\d+) val=(\d+)` +
                        `(?: rtt=(\d+))?` +
                        `(?: rate=(\d+))?` +
                        `(?: loss=(\d+))?` +
                        `(?: smrtt=(\d+))?` +
                        `(?: bmrtt=(\d+))?` +
                        `(?: avgrtt=(\d+))?`)

        rxSrate = regexp.MustCompile(
                `(\d+\.\d+): bpf_trace_printk: srate cookie=(\d+) ` +
                        `alg=(\d+) srate=(\d+)`)

        rxEstab = regexp.MustCompile(
                `(\d+\.\d+): bpf_trace_printk: estab cookie=(\d+) ` +
                        `alg=(\d+) forced=\d+ dest=(\d+)(?: dest6=(\d+))?(?: dest6b=(\d+))?`)

        rxProof = regexp.MustCompile(
                `(\d+\.\d+): .*proof cookie=(\d+) alg=(\d+) rate=(\d+) tier=(\d+)` +
                        `(?: dest=(\d+))?(?: dest6=(\d+))?(?: dest6b=(\d+))?`)

        rxMidsamp = regexp.MustCompile(
                `(\d+\.\d+): .*midsamp cookie=(\d+) .*srate=(\d+)`)

        rxDestInt = regexp.MustCompile(`dest=(\d+)`)
        rxDest6   = regexp.MustCompile(`dest6=(\d+)`)
        rxDest6B  = regexp.MustCompile(`dest6b=(\d+)`)
)

// ============================================================================
// Parsed event types
// ============================================================================

type metEntry struct {
        Ts    float64
        Val   int64
        Rport string
        Alg   int
}

type srateEntry struct {
        Ts    float64
        Srate int64
        Alg   int
}

// cdest is the cookie→dest map.  Each entry is [v4, v6, v6b] where
// v6 is the first 32 bits of an IPv6 dest and v6b is the next 32 bits
// (so together they form a /64).  Any field may be "" when not present
// in the source log line.
//
// v0.9.0: previously [2]string (v4, v6) — this dropped dest6b, which
// meant IPv6 connections were bucketed only by their top 32 bits and
// /64 labels in aliases.labels.json could never match.
type cdestEntry [3]string

// swapRow is the raw extracted swap tuple (matches Python's
// _swaps_mets_srates row layout).
type swapRow struct {
        Ts     float64
        Cookie int64
        From   int
        To     int
        Bc     int
        Ac     int
        D      string
        Mt     string
        Rb     string
        Dest   string // raw numeric string, may be ""
        Dest6  string
        Dest6b string
        // Enriched fields (filled in by enrichSwapsForCSV before writeSwapsCSV)
        Outcome      string // "win"/"loss"/"null"/"no_post"/""
        SrateBefore  string // pre-swap srate value as string
        Direction    string // "origin"/"client"/""
        Rport        string // remote port from met event
        DestResolved string // v0.9.0: fully-resolved display string (v4 dotted, v6:hex, or full /64 IPv6 form)
}

// ============================================================================
// Main entry — parseLogs
// ============================================================================

// buildLogPanels is the entry point for log-derived dashboard panels.
// Takes pre-parsed swaps/mets/srates (parsed ONCE per cycle in collect.go)
// so we don't re-parse the log 4 times per cycle (was hitting 40% CPU peak).
//
// Returns: topSwaps (top 18), topProofs (top 18), swapOutcomes, bucketIPs,
// logWindow, proofsRaw.
func buildLogPanels(swaps []swapRow,
        metByCookie map[int64][]metEntry,
        srateByCookie map[int64][]srateEntry,
        cdest map[string]cdestEntry, text string, now int64) (topSwaps, topProofs []interface{},
        swapOutcomes, bucketIPs, logWindow, proofsRaw interface{}) {

        // v0.9.17: don't return early when text is empty — fall through
        // to the CSV fallback paths below. The old code returned empty
        // for everything, which meant the dashboard showed no data
        // after log rotation, reboot, or log clearing.
        if text == "" {
                // Still return empty for bucket_ips and proofsRaw (no log
                // data to scan), but fall through for swaps/proofs which
                // have CSV fallbacks below.
                // Actually, just set text to empty and let the code below
                // handle it — the CSV fallback triggers on len < 18.
        }

        // v0.9.9: use single-pass parsed data if available via the
        // package-level parsedLog pointer. Set by collect() before calling
        // buildLogPanels. Falls back to the old multi-scan path if nil
        // (e.g. in tests).
        pl := currentParsedLog

        // ----- recent_swaps (newest-first, last 18) --------------------------
        // v0.9.59: RESTORE CSV fallback — was removed in v0.9.58 which left
        // the panel empty when the log was sparse. The "1h ago" bug was never
        // caused by CSV fallback — it was caused by v0.9.56's epoch_ts = nowEpoch
        // (read time), which was fixed in v0.9.57. The CSV fallback uses
        // collected_ts (wall-clock, within 30s of actual swap time) which is correct.
        allSwaps := buildRecentSwapRows(swaps, metByCookie, srateByCookie, cdest)
        topSwapsSlice := lastN(allSwaps, 18)
        if len(topSwapsSlice) < 18 {
                csvSwaps := readRecentSwapsFromCSV(50)
                if len(csvSwaps) > 0 {
                        var recentCsvSwaps []interface{}
                        cutoff := now - 24*3600
                        for _, s := range csvSwaps {
                                if m, ok := s.(map[string]interface{}); ok {
                                        if ts, ok := m["epoch_ts"].(int64); ok && ts >= cutoff {
                                                recentCsvSwaps = append(recentCsvSwaps, s)
                                        }
                                }
                        }
                        if len(recentCsvSwaps) > 0 {
                                topSwapsSlice = mergeSwapsNewestFirst(topSwapsSlice, recentCsvSwaps, 18)
                        }
                }
        }
        topSwaps = topSwapsSlice

        // ----- recent_proofs (newest-first, last 18) --------------------------
        // v0.9.63: always use pl (single-pass parser). Old else-branch deleted.
        var allProofs []interface{}
        if pl != nil {
                allProofs = pl.GetProofRows(cdest)
        }
        topProofsSlice := lastN(allProofs, 18)
        // v0.9.13: MERGE live + CSV instead of replacing.
        if len(topProofsSlice) < 18 {
                csvProofs := readRecentProofsFromCSV(18)
                if len(csvProofs) > 0 {
                        topProofsSlice = mergeProofsNewestFirst(topProofsSlice, csvProofs, 18)
                }
        }
        topProofs = topProofsSlice

        // ----- swap_outcomes (composite + srate + sustained) ----------------
        // v0.9.6: fall back to swaps.csv when the log tail has few swaps,
        // so the outcomes panel always shows data after a restart.
        logOutcomesMap := buildSwapOutcomes(swaps, metByCookie, srateByCookie)
        if len(swaps) < 50 {
                csvOutcomes := buildSwapOutcomesFromCSV(200)
                csvMeasurable := 0
                if comp, ok := csvOutcomes["composite"].(map[string]interface{}); ok {
                        csvMeasurable = toInt(comp["measurable"])
                }
                logMeasurable := 0
                if comp, ok := logOutcomesMap["composite"].(map[string]interface{}); ok {
                        logMeasurable = toInt(comp["measurable"])
                }
                if csvMeasurable > logMeasurable {
                        swapOutcomes = csvOutcomes
                } else {
                        swapOutcomes = logOutcomesMap
                }
        } else {
                swapOutcomes = logOutcomesMap
        }

        // ----- bucket_ips (all dest= occurrences, /16 or /32 grouped) ------
        // v0.9.63: always use pl (single-pass parser). Old else-branch deleted.
        if pl != nil {
                bucketIPs = pl.GetBucketIPs()
        }

        // ----- log_window (oldest/newest swap ts, span, age) ----------------
        logWindow = buildLogWindow(swaps, topProofs)

        // ----- proofs_raw (proof leaderboard: good/proved/sampled per alg) --
        // v0.9.7: ALWAYS merge CSV data into the leaderboard. The log tail
        // only covers a few hours; proofs.csv accumulates over days. We
        // merge both sources so the leaderboard shows full history.
        var logProofsRaw []interface{}
        if pl != nil {
                logProofsRaw = pl.GetProofsRaw()
        }
        csvProofsRaw := buildProofsRawFromCSVCached()
        if len(csvProofsRaw) > 0 {
                proofsRaw = mergeProofsRaw(logProofsRaw, csvProofsRaw)
        } else {
                proofsRaw = logProofsRaw
        }

        return topSwaps, topProofs, swapOutcomes, bucketIPs, logWindow, proofsRaw
}

// currentParsedLog is set by collect() before calling buildLogPanels.
// It allows buildLogPanels to use the single-pass parsed data instead
// of re-scanning the log text. Nil in tests.
var currentParsedLog *parsedLog

// ============================================================================
// ============================================================================
// buildRecentSwapRows — derive outcome per swap, return dashboard rows
// ============================================================================

func buildRecentSwapRows(swaps []swapRow,
        metByCookie map[int64][]metEntry,
        srateByCookie map[int64][]srateEntry,
        cdest map[string]cdestEntry) []interface{} {

        // v0.9.65: use epochOf() helper instead of inline formula
        rows := make([]interface{}, 0, len(swaps))
        for _, sw := range swaps {
                o := outcomeComposite(metByCookie, sw.Cookie, sw.Ts)
                o2 := outcomeSrate(srateByCookie, sw.Cookie, sw.Ts)
                o3 := outcomeSustained(srateByCookie, sw.Cookie, sw.Ts)

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

                // dest resolution: prefer swap row's own dest fields, fall
                // back to cookie→dest map from estab events.  v0.9.0: cdest
                // now carries v6b too, so /64 IPv6 labels resolve correctly.
                v4, v6, v6b := sw.Dest, sw.Dest6, sw.Dest6b
                if v4 == "" && v6 == "" && v6b == "" {
                        if d, ok := cdest[strconv.FormatInt(sw.Cookie, 10)]; ok {
                                v4, v6, v6b = d[0], d[1], d[2]
                        }
                }
                destStr := destStr(v4, v6, v6b)
                bucketOf := bucketOf(v4, v6, v6b)
                destLabel := labelFor(destStr)
                if destLabel == "" {
                        destLabel = destStr
                }

                d, _ := strconv.Atoi(sw.D)
                fromAlg := algName(sw.From)
                toAlg := algName(sw.To)

                row := map[string]interface{}{
                        "boot_ts":           sw.Ts,
                        "epoch_ts":          epochOf(sw.Ts),
                        "from_alg":          fromAlg,
                        "to_alg":            toAlg,
                        "d":                 d,
                        "outcome":           o,
                        "outcome_srate":     o2,
                        "outcome_sustained": o3,
                        "mt_alg":            mtAlg,
                        "rb_alg":            rbAlg,
                        "dest":              destLabel,
                        "_bucket":           bucketOf,
                }
                rows = append(rows, row)
        }
        // v0.9.16: sort by boot_ts descending (newest-first).
        // Was: reverse(rows) — but readLogTail reads files newest-first
        // by mtime, and within each file lines are chronological.
        // So the combined text is [newer_file (oldest→newest)] +
        // [older_file (oldest→newest)] — NOT globally chronological.
        // reverse() gave [older_newest, older_oldest, newer_newest,
        // newer_oldest] = wrong order. Sort fixes it properly.
        sort.Slice(rows, func(i, j int) bool {
                ti, _ := rows[i].(map[string]interface{})["boot_ts"].(float64)
                tj, _ := rows[j].(map[string]interface{})["boot_ts"].(float64)
                return ti > tj
        })
        return rows
}

// ============================================================================
// Outcome derivation — three rulers (composite, srate, sustained)
// ============================================================================

// outcomeComposite: post/pre ratio of `val` from met events.
//
//      post = first met sample in [T+3, T+300]
//      pre  = last met sample before T
//      r = post/pre; r<=0.9 → win (lower is better — opposite of srate),
//      r>=1.1 → loss, else null
func outcomeComposite(met map[int64][]metEntry, cookie int64, ts float64) string {
        tl := met[cookie]
        var pre, post int64 = -1, -1
        for _, e := range tl {
                if e.Ts < ts+0.001 {
                        pre = e.Val
                } else if ts+3.0 <= e.Ts && e.Ts <= ts+300.0 {
                        post = e.Val
                        break
                }
        }
        if pre <= 0 || post <= 0 {
                return ""
        }
        r := float64(post) / float64(pre)
        switch {
        case r <= 0.9:
                return "win"
        case r >= 1.1:
                return "loss"
        }
        return "null"
}

// outcomeSrate: post/pre ratio of `srate` from srate events.
//
//      pre = last srate before T
//      post = first srate after T
//      r>=1.1 → win, r<=0.9 → loss, else null
func outcomeSrate(srate map[int64][]srateEntry, cookie int64, ts float64) string {
        tl := srate[cookie]
        var pre, post int64 = -1, -1
        for _, e := range tl {
                if e.Ts < ts {
                        pre = e.Srate
                } else if e.Ts > ts {
                        post = e.Srate
                        break
                }
        }
        if pre <= 0 || post <= 0 {
                return ""
        }
        r := float64(post) / float64(pre)
        switch {
        case r >= 1.1:
                return "win"
        case r <= 0.9:
                return "loss"
        }
        return "null"
}

// outcomeSustained: median srate in [T+60, T+300] vs pre-swap srate.
//
//      r>=1.1 → win, r<=0.9 → loss, else null
func outcomeSustained(srate map[int64][]srateEntry, cookie int64, ts float64) string {
        tl := srate[cookie]
        var pre int64 = -1
        var post []int64
        for _, e := range tl {
                if e.Ts < ts {
                        pre = e.Srate
                } else if sustainedLoS <= (e.Ts-ts) && (e.Ts-ts) <= sustainedHiS {
                        post = append(post, e.Srate)
                }
        }
        if pre <= 0 || len(post) == 0 {
                return ""
        }
        pm := medianInt64(post)
        if pm <= 0 {
                return ""
        }
        r := float64(pm) / float64(pre)
        switch {
        case r >= 1.1:
                return "win"
        case r <= 0.9:
                return "loss"
        }
        return "null"
}

// ============================================================================
// swap_outcomes aggregate (composite + srate + sustained + loss recovery)
// ============================================================================

// swapOutRow is the intermediate per-swap row used inside outcome
// derivation + loss-recovery classification.
type swapOutRow struct {
        Ts               float64
        Cookie           int64
        Outcome          string
        OutcomeSrate     string
        OutcomeSustained string
        Dest             string
}

func buildSwapOutcomes(swaps []swapRow,
        met map[int64][]metEntry, srate map[int64][]srateEntry) map[string]interface{} {

        cCounts := newOutcomeCounts()
        sCounts := newOutcomeCounts()
        sustCounts := newOutcomeCounts()

        var swapsList []swapOutRow

        for _, sw := range swaps {
                o := outcomeComposite(met, sw.Cookie, sw.Ts)
                o2 := outcomeSrate(srate, sw.Cookie, sw.Ts)
                o3 := outcomeSustained(srate, sw.Cookie, sw.Ts)
                incrOutcome(cCounts, o)
                incrOutcome(sCounts, o2)
                incrOutcome(sustCounts, o3)
                swapsList = append(swapsList, swapOutRow{
                        Ts: sw.Ts, Cookie: sw.Cookie,
                        Outcome: o, OutcomeSrate: o2, OutcomeSustained: o3,
                        Dest: labelFor(destStr(sw.Dest, sw.Dest6, sw.Dest6b)),
                })
        }

        out := map[string]interface{}{
                "composite": finalizeOutcome(cCounts),
                "srate":     finalizeOutcome(sCounts),
                "sustained": finalizeOutcome(sustCounts),
        }
        addLossRecovery(out, swapsList)
        // swaps_list (for the renderer's writeback path).
        out["swaps_list"] = buildSwapsListForOutcomes(swapsList)
        return out
}

type outcomeCounts struct {
        Win, Null, Loss, Skip int
}

func newOutcomeCounts() *outcomeCounts { return &outcomeCounts{} }

func incrOutcome(c *outcomeCounts, o string) {
        switch o {
        case "win":
                c.Win++
        case "loss":
                c.Loss++
        case "null":
                c.Null++
        default:
                c.Skip++
        }
}

func finalizeOutcome(c *outcomeCounts) map[string]interface{} {
        total := c.Win + c.Null + c.Loss
        pct := func(x int) float64 {
                if total == 0 {
                        return 0
                }
                return round1(float64(x) * 100.0 / float64(total))
        }
        return map[string]interface{}{
                "measurable":   total,
                "unmeasurable": c.Skip,
                "win":          c.Win,
                "win_pct":      pct(c.Win),
                "null":         c.Null,
                "null_pct":     pct(c.Null),
                "loss":         c.Loss,
                "loss_pct":     pct(c.Loss),
        }
}

// addLossRecovery mutates out to add rescued/full_loss/open + _pct fields.
// Mirrors bpftune_data.py:_add_loss_recovery.
func addLossRecovery(out map[string]interface{}, swaps []swapOutRow) {
        if len(swaps) == 0 {
                for _, key := range []string{"composite", "srate", "sustained"} {
                        if sub, ok := out[key].(map[string]interface{}); ok {
                                sub["rescued"] = 0
                                sub["full_loss"] = 0
                                sub["open"] = 0
                                sub["rescued_pct"] = 0.0
                                sub["full_loss_pct"] = 0.0
                                sub["open_pct"] = 0.0
                        }
                }
                return
        }
        // Sort by ts ascending.
        sort.Slice(swaps, func(i, j int) bool { return swaps[i].Ts < swaps[j].Ts })
        lastTs := swaps[len(swaps)-1].Ts
        fieldMap := map[string]string{
                "composite": "Outcome", "srate": "OutcomeSrate", "sustained": "OutcomeSustained",
        }
        for key, field := range fieldMap {
                sub, ok := out[key].(map[string]interface{})
                if !ok {
                        continue
                }
                totalLoss, _ := sub["loss"].(int)
                if totalLoss <= 0 {
                        sub["rescued"] = 0
                        sub["full_loss"] = 0
                        sub["open"] = 0
                        sub["rescued_pct"] = 0.0
                        sub["full_loss_pct"] = 0.0
                        sub["open_pct"] = 0.0
                        continue
                }
                // Build judged (only swaps with a verdict in this field).
                type judgedRow struct {
                        Ts      float64
                        Cookie  int64
                        Verdict string
                }
                var judged []judgedRow
                for _, s := range swaps {
                        v := fieldValue(s, field)
                        if v == "win" || v == "null" || v == "loss" {
                                judged = append(judged, judgedRow{s.Ts, s.Cookie, v})
                        }
                }
                type lossRow struct {
                        Ts     float64
                        Cookie int64
                }
                var losses []lossRow
                for _, j := range judged {
                        if j.Verdict == "loss" {
                                losses = append(losses, lossRow{j.Ts, j.Cookie})
                        }
                }
                rescued, full, open := 0, 0, 0
                for _, loss := range losses {
                        found := false
                        for _, j := range judged {
                                if j.Ts == loss.Ts && j.Cookie == loss.Cookie {
                                        continue
                                }
                                if j.Ts <= loss.Ts {
                                        continue
                                }
                                if j.Ts-loss.Ts > float64(tRescueWindowS) {
                                        break
                                }
                                if j.Cookie == loss.Cookie && j.Verdict == "win" {
                                        found = true
                                        break
                                }
                        }
                        if found {
                                rescued++
                        } else if (lastTs - loss.Ts) > float64(tRescueWindowS) {
                                full++
                        } else {
                                open++
                        }
                }
                sub["rescued"] = rescued
                sub["full_loss"] = full
                sub["open"] = open
                sub["rescued_pct"] = round1(float64(rescued) * 100.0 / float64(totalLoss))
                sub["full_loss_pct"] = round1(float64(full) * 100.0 / float64(totalLoss))
                sub["open_pct"] = round1(float64(open) * 100.0 / float64(totalLoss))
        }
}

func fieldValue(s swapOutRow, field string) string {
        switch field {
        case "Outcome":
                return s.Outcome
        case "OutcomeSrate":
                return s.OutcomeSrate
        case "OutcomeSustained":
                return s.OutcomeSustained
        }
        return ""
}

func buildSwapsListForOutcomes(swaps []swapOutRow) []interface{} {
        // v0.9.65: use epochOf() helper
        out := make([]interface{}, 0, len(swaps))
        for _, s := range swaps {
                // BUG 14 fix: use nil for unmeasured outcomes (dashboard expects null, not "")
                var oc, ou_ interface{}
                if s.Outcome != "" {
                        oc = s.Outcome
                }
                if s.OutcomeSustained != "" {
                        ou_ = s.OutcomeSustained
                }
                out = append(out, map[string]interface{}{
                        "ts":                s.Ts,
                        "epoch_ts":          epochOf(s.Ts),
                        "boot_ts":           s.Ts,
                        "cookie":            s.Cookie,
                        "dest":              s.Dest,
                        "outcome":           oc,
                        "outcome_sustained": ou_,
                })
        }
        return out
}
// Merge rule: existing entries are NOT overwritten by empty dest fields
// (so a swap event without dest6b doesn't blow away a prior estab's value).
// This is the same BUG 5 fix that was already in place for the [2]string
// variant, extended to all three fields.
func cookieDestMap(text string) map[string]cdestEntry {
        out := map[string]cdestEntry{}
        for _, line := range strings.Split(text, "\n") {
                if m := rxSwap.FindStringSubmatch(line); m != nil {
                        // swap row: groups 2=cookie, 10=dest, 11=dest6, 12=dest6b
                        cookie := m[2]
                        if m[10] != "" || m[11] != "" || m[12] != "" {
                                cur := out[cookie]
                                if m[10] != "" {
                                        cur[0] = m[10]
                                }
                                if m[11] != "" {
                                        cur[1] = m[11]
                                }
                                if m[12] != "" {
                                        cur[2] = m[12]
                                }
                                out[cookie] = cur
                        }
                        continue
                }
                if m := rxEstab.FindStringSubmatch(line); m != nil {
                        // estab row: groups 2=cookie, 4=dest, 5=dest6, 6=dest6b
                        cookie := m[2]
                        cur := out[cookie]
                        if m[4] != "" {
                                cur[0] = m[4]
                        }
                        if m[5] != "" {
                                cur[1] = m[5]
                        }
                        if m[6] != "" {
                                cur[2] = m[6]
                        }
                        out[cookie] = cur
                }
        }
        return out
}
// ============================================================================
// buildLogWindow — oldest/newest swap ts + span/age info
// ============================================================================

func buildLogWindow(swaps []swapRow, proofs []interface{}) map[string]interface{} {
        if len(swaps) == 0 && len(proofs) == 0 {
                return emptyLogWindow()
        }
        var oldest, newest float64
        haveFirst := false
        for _, s := range swaps {
                if !haveFirst {
                        oldest = s.Ts
                        newest = s.Ts
                        haveFirst = true
                        continue
                }
                if s.Ts < oldest {
                        oldest = s.Ts
                }
                if s.Ts > newest {
                        newest = s.Ts
                }
        }
        for _, p := range proofs {
                if row, ok := p.(map[string]interface{}); ok {
                        if ts, ok := row["boot_ts"].(float64); ok {
                                if !haveFirst {
                                        oldest = ts
                                        newest = ts
                                        haveFirst = true
                                        continue
                                }
                                if ts < oldest {
                                        oldest = ts
                                }
                                if ts > newest {
                                        newest = ts
                                }
                        }
                }
        }
        if !haveFirst {
                return emptyLogWindow()
        }
        // v0.9.65: use epochOf() helper
        oldestWall := epochOf(oldest)
        var newestWall int64
        if newest > readProcUptime() {
                newestWall = readLogFileMtime()
        } else {
                newestWall = epochOf(newest)
        }
        ageMin := round1((float64(time.Now().Unix()) - float64(newestWall)) / 60.0)
        return map[string]interface{}{
                "oldest_ts":  oldestWall,
                "newest_ts":  newestWall,
                "span_min":   round1((newest - oldest) / 60.0),
                "swap_count": len(swaps),
                "age_min":    ageMin,
        }
}
type proofEvent struct {
        good, proved int
        provenMax    int64
}
type proofSample struct {
        sum     int64
        n       int
        sampMax int64
}
// ============================================================================
// Dest decoding (numeric → IP string)
// ============================================================================

// destStr returns the display string for a destination.  Prefers v6
// when present.  Mirrors bpftune_log.py:_dest_str.
//
// v0.9.0: third arg v6b (dest6b) added.  When both v6 and v6b are
// present, the full /64 IPv6 form "xxxx:xxxx:yyyy:yyyy::" is returned
// (so labels in aliases.labels.json defined on a /64 can match).
// When only v6 is present, the previous "v6:XXXXXXXX" form is returned
// (which foldV6 then converts to the /32 standard form).
func destStr(v4, v6, v6b string) string {
        if v6 != "" {
                if n6, err := strconv.ParseInt(v6, 10, 64); err == nil && n6 != 0 {
                        // v6b present?  Build full /64 form.
                        if v6b != "" {
                                if n6b, err := strconv.ParseInt(v6b, 10, 64); err == nil && n6b != 0 {
                                        hi := uint64(n6) & 0xFFFFFFFF
                                        lo := uint64(n6b) & 0xFFFFFFFF
                                        return fmt.Sprintf("%04x:%04x:%04x:%04x::",
                                                (hi>>16)&0xFFFF, hi&0xFFFF,
                                                (lo>>16)&0xFFFF, lo&0xFFFF)
                                }
                        }
                        // Only first 32 bits — keep the v6:hex form (matches Python
                        // _dest_str).  foldV6 will convert this to "xxxx:xxxx::".
                        return fmt.Sprintf("v6:%08x", uint64(n6)&0xFFFFFFFF)
                }
        }
        return destIP(v4)
}

// bucketOf returns the /prefix4 (v4) or /prefix6 (v6) bucket key.
// v0.4.2: respects current prefix4/prefix6 from /var/lib/bpftune/.
// Mirrors bpftune_log.py:_bucket_of (but Python hardcodes /16; we make
// it prefix-aware per user spec).
func bucketOf(v4, v6, v6b string) string {
        // Build the address string in standard or v6:hex form.
        addr := destStr(v4, v6, v6b)
        if addr == "" {
                return ""
        }
        // Filter 0.0.0.0/127.x.x.x (only applies to v4).
        if v6 == "" && v4 != "" {
                n, err := strconv.ParseInt(v4, 10, 64)
                if err == nil {
                        first := (n >> 24) & 0xFF
                        if first == 0 || first == 127 {
                                return ""
                        }
                }
        }
        return canonBucketWithPrefix(addr, prefix4Value(), prefix6Value())
}

// destIP converts a numeric dest (as decimal string) to dotted-quad.
// Returns "" for 0/127.x.x.x/None.  Mirrors bpftune_log.py:_dest_ip.
func destIP(s string) string {
        if s == "" || s == "1" {
                return ""
        }
        n, err := strconv.ParseInt(s, 10, 64)
        if err != nil {
                return ""
        }
        first := (n >> 24) & 0xFF
        if first == 0 || first == 127 {
                return ""
        }
        return fmt.Sprintf("%d.%d.%d.%d",
                (n>>24)&0xFF, (n>>16)&0xFF, (n>>8)&0xFF, n&0xFF)
}

// ============================================================================
// Log file readers
// ============================================================================

// readLogTail reads the last `budget` bytes across all bpftune-met-*.log
// files, sorted newest-first.  Mirrors bpftune_log.py:tail_recent.
func readLogTail(budget int64) string {
        // v0.9.31 (Bug 6): match rotated logs too (was *.log, missed .log.1 etc.)
        pattern := "/var/log/bpftune-met-live.log*"
        files, _ := filepath.Glob(pattern)
        if len(files) == 0 {
                return ""
        }
        // Sort newest-first by mtime.
        sort.Slice(files, func(i, j int) bool {
                fi, _ := os.Stat(files[i])
                fj, _ := os.Stat(files[j])
                return fi.ModTime().After(fj.ModTime())
        })
        // v0.9.9: use a strings.Builder with pooled buffer to reduce GC pressure.
        // Was: var chunks []string + strings.Join — allocated a new []string
        // slice and concatenated all chunks into one big string per cycle.
        var sb strings.Builder
        remaining := budget
        for _, p := range files {
                if remaining <= 0 {
                        break
                }
                fi, err := os.Stat(p)
                if err != nil {
                        continue
                }
                size := fi.Size()
                take := size
                if take > remaining {
                        take = remaining
                }
                f, err := os.Open(p)
                if err != nil {
                        continue
                }
                _, _ = f.Seek(size-take, 0)
                buf := make([]byte, take)
                _, _ = f.Read(buf)
                f.Close()
                sb.Write(buf)
                sb.WriteByte('\n')
                remaining -= take
        }
        return sb.String()
}

// bootEpoch returns the wall-clock epoch time of the system boot.
// Used by all timestamp conversions: epoch_of_event = bootEpoch() + bpf_ktime.
// v0.9.65: single helper replaces 3 copies of the formula across log_parsing.go + singlepass.go.
func bootEpoch() float64 {
        return float64(time.Now().Unix()) - readProcUptime()
}

// epochOf converts a BPF ktime timestamp (seconds since boot) to wall-clock epoch.
// All swap/proof timestamps go through this single function.
func epochOf(bpfKtime float64) int64 {
        return int64(bootEpoch() + bpfKtime)
}

// readProcUptime returns /proc/uptime seconds (or 0 on error).
func readProcUptime() float64 {
        data, err := os.ReadFile("/proc/uptime")
        if err != nil {
                return 0
        }
        fields := strings.Fields(string(data))
        if len(fields) == 0 {
                return 0
        }
        u, _ := strconv.ParseFloat(fields[0], 64)
        return u
}

func readLogFileMtime() int64 {
        fi, err := os.Stat("/var/log/bpftune-met-live.log")
        if err != nil {
                return time.Now().Unix()
        }
        return fi.ModTime().Unix()
}

// nowMono returns the BPF clock, falling back to /proc/uptime when the
// log tail is empty (e.g., just after rotation). This ensures the
// frontend always has a valid now_mono for converting BPF ktime → epoch
// timestamps in swaps_list, even when the log is temporarily empty.
func nowMono(maxTs float64) float64 {
        if maxTs > 0 {
                return maxTs
        }
        return readProcUptime()
}

// ============================================================================
// Helpers
// ============================================================================

func algName(i int) string {
        if i >= 0 && i < len(CONGS) {
                return CONGS[i]
        }
        return fmt.Sprintf("alg%d", i)
}

func medianInt64(xs []int64) int64 {
        if len(xs) == 0 {
                return 0
        }
        s := make([]int64, len(xs))
        copy(s, xs)
        sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
        n := len(s)
        if n%2 == 1 {
                return s[n/2]
        }
        return (s[n/2-1] + s[n/2]) / 2
}

func round1(f float64) float64 {
        return float64(int(f*10+0.5)) / 10.0
}

func round2(f float64) float64 {
        return float64(int(f*100+0.5)) / 100.0
}

func round3(f float64) float64 {
        return float64(int(f*1000+0.5)) / 1000.0
}

// lastN returns the last n elements (newest-first since swaps are
// oldest-first when iterated).  Actually for newest-first input it
// returns the first n elements.
func lastN(rows []interface{}, n int) []interface{} {
        if len(rows) <= n {
                return rows
        }
        return rows[:n]
}

func reverse(rows []interface{}) []interface{} {
        out := make([]interface{}, len(rows))
        for i, r := range rows {
                out[len(rows)-1-i] = r
        }
        return out
}

func contains(s []string, v string) bool {
        for _, x := range s {
                if x == v {
                        return true
                }
        }
        return false
}

func emptySwapOutcomes() map[string]interface{} {
        // v0.9.11 fix: swaps_list goes at the TOP level (matching
        // buildSwapOutcomes), not inside each ruler sub-map. The old
        // code put swaps_list inside composite/srate/sustained, but
        // the frontend reads swap_outcomes.swaps_list — so the
        // swaps-per-bin chart showed no data when the log was empty.
        empty := map[string]interface{}{
                "measurable": 0, "unmeasurable": 0,
                "win": 0, "win_pct": 0.0,
                "null": 0, "null_pct": 0.0,
                "loss": 0, "loss_pct": 0.0,
                "rescued": 0, "full_loss": 0, "open": 0,
                "rescued_pct": 0.0, "full_loss_pct": 0.0, "open_pct": 0.0,
        }
        return map[string]interface{}{
                "composite":  copyMap(empty),
                "srate":      copyMap(empty),
                "sustained":  copyMap(empty),
                "swaps_list": []interface{}{},
        }
}

func copyMap(m map[string]interface{}) map[string]interface{} {
        out := map[string]interface{}{}
        for k, v := range m {
                out[k] = v
        }
        return out
}

func emptyLogWindow() map[string]interface{} {
        return map[string]interface{}{
                "oldest_ts":  int64(0),
                "newest_ts":  int64(0),
                "span_min":   0.0,
                "swap_count": 0,
                "age_min":    0.0,
        }
}

// (v0.9.0) saveCookieDestMap stub removed.  Real persistence lives in
// cookie_dest.go (persistCookieDest + loadCookieDest).  The previous stub
// wrote to collector-go-state.json but was never called from anywhere,
// creating the misleading impression that the cookie→dest map survived
// restarts.  It did not.

// ============================================================================
// v0.9.13: merge helpers — combine live + CSV data, newest-first, deduped
// ============================================================================

// mergeSwapsNewestFirst merges two newest-first swap lists, deduplicates
// by boot_ts+cookie, and returns the top N newest entries.
func mergeSwapsNewestFirst(live, csv []interface{}, n int) []interface{} {
        seen := make(map[string]bool)
        var merged []interface{}
        // v0.9.61: sort by epoch_ts (wall-clock) instead of boot_ts (BPF ktime).
        // boot_ts is not comparable across boots — CSV swaps from a previous boot
        // have higher ktime values than current-boot live swaps, pushing live swaps
        // to the bottom of the list. epoch_ts is wall-clock and always comparable.
        getEpochTs := func(m map[string]interface{}) int64 {
                if ts, ok := m["epoch_ts"].(int64); ok && ts > 0 {
                        return ts
                }
                return 0
        }
        add := func(row interface{}) {
                if m, ok := row.(map[string]interface{}); ok {
                        ts := getEpochTs(m)
                        cookie, _ := m["dest"].(string)
                        key := fmt.Sprintf("%d:%s", ts, cookie)
                        if !seen[key] {
                                seen[key] = true
                                merged = append(merged, row)
                        }
                }
        }
        for _, r := range live {
                add(r)
        }
        for _, r := range csv {
                add(r)
        }
        // Sort by epoch_ts descending (newest first)
        sort.Slice(merged, func(i, j int) bool {
                ti := getEpochTs(merged[i].(map[string]interface{}))
                tj := getEpochTs(merged[j].(map[string]interface{}))
                return ti > tj
        })
        if len(merged) > n {
                merged = merged[:n]
        }
        return merged
}

// mergeProofsNewestFirst merges two newest-first proof lists, deduplicates
// by boot_ts+alg, and returns the top N newest entries.
func mergeProofsNewestFirst(live, csv []interface{}, n int) []interface{} {
        seen := make(map[string]bool)
        var merged []interface{}
        add := func(row interface{}) {
                if m, ok := row.(map[string]interface{}); ok {
                        ts, _ := m["boot_ts"].(float64)
                        alg, _ := m["alg"].(string)
                        key := fmt.Sprintf("%.3f:%s", ts, alg)
                        if !seen[key] {
                                seen[key] = true
                                merged = append(merged, row)
                        }
                }
        }
        for _, r := range live {
                add(r)
        }
        for _, r := range csv {
                add(r)
        }
        sort.Slice(merged, func(i, j int) bool {
                ti, _ := merged[i].(map[string]interface{})["boot_ts"].(float64)
                tj, _ := merged[j].(map[string]interface{})["boot_ts"].(float64)
                return ti > tj
        })
        if len(merged) > n {
                merged = merged[:n]
        }
        return merged
}
