package main

// singlepass.go — single-pass log parser.
//
// PROBLEM
//   The log tail (2-16MB, ~237K lines) was scanned 9 separate times per
//   collect cycle, each doing strings.Split(text, "\n") = 237K string
//   allocations. 9 scans = 2.1M allocations per cycle.
//
//   The scans were:
//     1. parseSwapsMetsSrates(text)  — swaps, mets, srates
//     2. cookieDestMap(text)         — estab + swap dest fields
//     3. buildRecentProofRows(text)  — proof lines
//     4. proofEvents(text)           — proof + met lines (scans TWICE)
//     5. buildProofsRawEvents(text)  — proof lines again
//     6. buildRate(text)             — midsamp lines
//     7. buildBucketIPs(text)        — dest= occurrences
//     8. readBPFClock(text)          — max timestamp
//
// SOLUTION
//   One pass through the text, classifying each line by its prefix and
//   extracting all data into a single parsedLog struct. Then the
//   consumers use the struct instead of re-scanning the text.
//
//   The struct is passed by pointer (zero-copy) to all consumers.
//   Each consumer extracts only the fields it needs from the struct's
//   pre-parsed data.
//
// v0.9.108-lean changes (pure performance, identical parse results):
//   - line iteration via strings.IndexByte instead of strings.Split
//     (saves the ~100K-entry []string slice per cycle)
//   - cheap literal pre-filters before each regex. The literals below
//     are REQUIRED substrings of the respective patterns (see
//     log_parsing.go), so a line that lacks the literal can never match
//     the regex — skipping the regex is sound and changes no result.
//   - midsamp lines are parsed ONCE (the deferred pass re-ran rxMidsamp
//     on every midsamp line that the main loop had already matched)
//   - proof fields are captured during the main pass (parsedProofs) so
//     GetProofRows / GetProofsRawEvents don't re-run rxProof over every
//     proof line each cycle. alg is stored RAW (m[3]) and the v0.9.31
//     cookie→alg rewrite is applied at consumer time exactly as before.
//   - GetProofRows: readProcUptime()/time.Now() hoisted out of the loop
//     (was an os.ReadFile per row).

import (
        "net"
        "sort"
        "sync"
        "time"
        "strconv"
        "strings"
)

// parsedLog holds the result of a single pass over the log tail.
// All fields are populated in one loop over the lines of text.
type parsedLog struct {
        Swaps      []swapRow
        MetByCookie map[int64][]metEntry
        SrateByCookie map[int64][]srateEntry
        Cdest      map[string]cdestEntry
        CookieAlg  map[string]int    // v0.9.31: cookie→alg for cubic-proof fix
        ProofLines []string   // raw lines matching "proof cookie="
        ProofEvents map[int]proofEvent
        ProofSamples map[int]proofSample
        MidsampRows []midsampRow
        BucketIPs   map[string][]string // masked → []fullIP
        MaxTs       float64              // max bpf_trace_printk timestamp
        RttByDest   map[string]float64   // v0.4.104: dest→min RTT (microseconds)
        // v0.9.108: proof fields captured during the main pass so the
        // consumers below don't re-run rxProof per proof line.
        parsedProofs []parsedProof

        // Pre-computed views (built once from the raw data above)
        proofRowsCache     []interface{}
        proofsRawCache     []interface{}
        proofsRawEventsCache []interface{}
        bucketIPsCache      map[string]interface{}
        rateCache           []interface{}
}

// parsedProof holds the captured fields of one "proof cookie=" line.
// alg is the RAW alg= value (m[3]); the v0.9.31 cookie→alg rewrite is
// applied by consumers at read time, exactly like v0.9.104.
type parsedProof struct {
        ts     float64
        cookie string
        alg    int
        rate   int64
        tier   string
        v4, v6, v6b string
}

// parsedMidsamp holds the captured fields of one midsamp line for the
// deferred proofSamples pass (replaces re-running rxMidsamp on the raw line).
type parsedMidsamp struct {
        ts     float64
        cookie int64
        r      int64
}

// midsampRow is a parsed midsamp line, used by buildRate.
type midsampRow struct {
        Thr   int
        Srate int64
        Rport string
        Dest  string  // v0.9.32: resolved dest for bucket filtering
}

// parseLogSinglePass does ONE pass over text and extracts everything.
// This replaces the 9 separate strings.Split(text, "\n") scans.
// bootUptime caches /proc/uptime with a 30s TTL.
// v0.9.25: was sync.Once (cached forever) — after 5 min, ALL new events
// were filtered as "previous boot" because the cached uptime was stale.
var bootUptime struct {
        mu    sync.Mutex
        value float64
        ts    time.Time
}

// getBootUptime returns /proc/uptime (seconds since boot).
// Used to filter out events from previous boots.
func getBootUptime() float64 {
        bootUptime.mu.Lock()
        defer bootUptime.mu.Unlock()
        if time.Since(bootUptime.ts) < 30*time.Second {
                return bootUptime.value
        }
        bootUptime.value = readProcUptime()
        bootUptime.ts = time.Now()
        return bootUptime.value
}

// Event-literal pre-filters.  Each literal is a REQUIRED substring of
// the corresponding regex pattern (log_parsing.go), so filtering on it
// can never discard a line that would have matched.
const (
        litMet    = "bpf_trace_printk: met cookie="
        litSrate  = "bpf_trace_printk: srate cookie="
        litSwap   = "bpf_trace_printk: swap cookie="
        litEstab  = "bpf_trace_printk: estab cookie="
        litMidsamp = "midsamp cookie="
)

func parseLogSinglePass(text string) *parsedLog {
        pl := &parsedLog{
                MetByCookie:  map[int64][]metEntry{},
                SrateByCookie: map[int64][]srateEntry{},
                Cdest:        map[string]cdestEntry{},
                CookieAlg:    map[string]int{},
                ProofEvents:  map[int]proofEvent{},
                ProofSamples: map[int]proofSample{},
                BucketIPs:    map[string][]string{},
                RttByDest:    map[string]float64{}, // v0.4.104
        }

        p4 := prefix4Value()
        p6 := prefix6Value()

        // Collect midsamp events for deferred processing — the original
        // proofEvents() does TWO passes: first to build metByCookie,
        // then to process midsamp using the complete metByCookie.
        // We collect midsamp events here and process them after the main
        // loop, so all met entries are guaranteed to be in MetByCookie.
        var midsampLines []parsedMidsamp

        // v0.9.108: iterate lines without strings.Split — no 100K-entry
        // []string per cycle.  Semantics are identical to
        // strings.Split(text, "\n") + skipping empty lines.
        rest := text
        for len(rest) > 0 {
                var line string
                if idx := strings.IndexByte(rest, '\n'); idx >= 0 {
                        line = rest[:idx]
                        rest = rest[idx+1:]
                } else {
                        line = rest
                        rest = ""
                }
                if len(line) == 0 {
                        continue
                }

                // --- readBPFClock: extract max timestamp from any trace_pipe line ---
                // This is the cheapest check — do it first for every line.
                // v0.9.19: filter out events from previous boots.
                // BPF ktime resets to 0 on kernel boot. If ktime > /proc/uptime,
                // the event is from a PREVIOUS boot (stale log file). Skip it.
                if idx := strings.Index(line, ": bpf_trace_printk:"); idx >= 0 {
                        start := idx
                        for start > 0 {
                                c := line[start-1]
                                if (c >= '0' && c <= '9') || c == '.' {
                                        start--
                                } else {
                                        break
                                }
                        }
                        if start < idx {
                                if ts, err := strconv.ParseFloat(line[start:idx], 64); err == nil {
                                        uptime := getBootUptime()
                                        if uptime > 0 && ts > uptime+300 {
                                                // Event is from a previous boot (ktime > uptime + 5min margin)
                                                continue
                                        }
                                        if ts > pl.MaxTs {
                                                pl.MaxTs = ts
                                        }
                                }
                        }
                }

                // --- Classify by event type using fast prefix checks ---
                // Order: most common events first (met, srate) → swap → estab → proof → midsamp
                // v0.9.108: each regex is behind its required literal so
                // non-matching lines skip the regex engine entirely.

                if strings.Contains(line, litMet) {
                if m := rxMet.FindStringSubmatch(line); m != nil {
                        ts, _ := strconv.ParseFloat(m[1], 64)
                        cookie, _ := strconv.ParseInt(m[2], 10, 64)
                        rport := m[3]
                        alg, _ := strconv.Atoi(m[4])
                        val, _ := strconv.ParseInt(m[6], 10, 64)
                        pl.MetByCookie[cookie] = append(pl.MetByCookie[cookie],
                                metEntry{Ts: ts, Val: val, Rport: rport, Alg: alg})
                        // v0.9.31: track current alg per cookie for cubic-proof fix
                        if alg != 0 {
                                pl.CookieAlg[m[2]] = alg
                        }
                        // v0.4.105: extract RTT from met lines for route health
                        // (no BPF changes needed — met lines already have rtt=)
                        if len(m) > 7 && m[7] != "" {
                                rttUs, _ := strconv.ParseFloat(m[7], 64)
                                if rttUs > 0 {
                                        cookieStr := m[2]
                                        if d, ok := pl.Cdest[cookieStr]; ok {
                                                ds := destStr(d[0], d[1], d[2])
                                                destLabel := labelFor(ds)
                                                if destLabel == "" {
                                                        destLabel = ds
                                                }
                                                if existing, ok := pl.RttByDest[destLabel]; !ok || rttUs < existing {
                                                        pl.RttByDest[destLabel] = rttUs
                                                }
                                        }
                                }
                        }
                        continue
                }
                }

                if strings.Contains(line, litSrate) {
                if m := rxSrate.FindStringSubmatch(line); m != nil {
                        ts, _ := strconv.ParseFloat(m[1], 64)
                        cookie, _ := strconv.ParseInt(m[2], 10, 64)
                        alg, _ := strconv.Atoi(m[3])
                        sr, _ := strconv.ParseInt(m[4], 10, 64)
                        pl.SrateByCookie[cookie] = append(pl.SrateByCookie[cookie],
                                srateEntry{Ts: ts, Srate: sr, Alg: alg})
                        // v0.9.31: srate carries the current alg post-swap
                        if alg != 0 {
                                pl.CookieAlg[m[2]] = alg
                        }
                        continue
                }
                }

                if strings.Contains(line, litSwap) {
                if m := rxSwap.FindStringSubmatch(line); m != nil {
                        ts, _ := strconv.ParseFloat(m[1], 64)
                        cookie, _ := strconv.ParseInt(m[2], 10, 64)
                        fa, _ := strconv.Atoi(m[3])
                        ta, _ := strconv.Atoi(m[4])
                        bc, _ := strconv.Atoi(m[5])
                        ac, _ := strconv.Atoi(m[6])
                        row := swapRow{
                                Ts: ts, Cookie: cookie, From: fa, To: ta, Bc: bc, Ac: ac,
                                D: m[7], Mt: m[8], Rb: m[9],
                                Dest: m[10], Dest6: m[11], Dest6b: m[12],
                        }
                        pl.Swaps = append(pl.Swaps, row)

                        // cookieDestMap: extract dest fields from swap events
                        if m[10] != "" || m[11] != "" || m[12] != "" {
                                cur := pl.Cdest[m[2]]
                                if m[10] != "" {
                                        cur[0] = m[10]
                                }
                                if m[11] != "" {
                                        cur[1] = m[11]
                                }
                                if m[12] != "" {
                                        cur[2] = m[12]
                                }
                                pl.Cdest[m[2]] = cur
                        }

                        // buildBucketIPs: dest= occurrences
                        pl.extractBucketIPs(line, p4, p6)
                        // v0.9.31: swap.to is authoritative — set_cong was called
                        pl.CookieAlg[m[2]] = ta
                        continue
                }
                }

                if strings.Contains(line, litEstab) {
                if m := rxEstab.FindStringSubmatch(line); m != nil {
                        // cookieDestMap: extract dest fields from estab events
                        cookie := m[2]
                        cur := pl.Cdest[cookie]
                        if m[4] != "" {
                                cur[0] = m[4]
                        }
                        if m[5] != "" {
                                cur[1] = m[5]
                        }
                        if m[6] != "" {
                                cur[2] = m[6]
                        }
                        pl.Cdest[cookie] = cur
                        // v0.9.31: estab.alg is the kernel CC at conn start
                        if estabAlg, err := strconv.Atoi(m[3]); err == nil && estabAlg != 0 {
                                if _, exists := pl.CookieAlg[cookie]; !exists {
                                        pl.CookieAlg[cookie] = estabAlg
                                }
                        }

                        // buildBucketIPs: estab lines also carry dest=
                        pl.extractBucketIPs(line, p4, p6)
                        continue
                }
                }

                if strings.Contains(line, "proof cookie=") {
                        if m := rxProof.FindStringSubmatch(line); m != nil {
                                pl.ProofLines = append(pl.ProofLines, line)

                                // proofEvents: aggregate good/proved/provenMax per alg
                                ts, _ := strconv.ParseFloat(m[1], 64)
                                a, _ := strconv.Atoi(m[3])
                                // v0.9.31: rewrite alg=0 from cookie→alg map
                                if a == 0 {
                                        if realAlg, ok := pl.CookieAlg[m[2]]; ok && realAlg != 0 {
                                                a = realAlg
                                        }
                                }
                                rate, _ := strconv.ParseInt(m[4], 10, 64)
                                tier := m[5]
                                e := pl.ProofEvents[a]
                                if tier == "2" {
                                        e.proved++
                                } else {
                                        e.good++
                                }
                                if rate > e.provenMax {
                                        e.provenMax = rate
                                }
                                pl.ProofEvents[a] = e

                                // v0.9.108: capture fields for the consumers below
                                // (alg stored RAW — consumers apply the cookie→alg
                                // rewrite at read time, as in v0.9.104).
                                pl.parsedProofs = append(pl.parsedProofs, parsedProof{
                                        ts:     ts,
                                        cookie: m[2],
                                        alg:    toIntOrZero(m[3]),
                                        rate:   rate,
                                        tier:   tier,
                                        v4:     m[6],
                                        v6:     m[7],
                                        v6b:    m[8],
                                })

                                // buildBucketIPs: proof lines also carry dest=
                                pl.extractBucketIPs(line, p4, p6)
                        }
                        continue
                }

                if strings.Contains(line, litMidsamp) {
                if m := rxMidsamp.FindStringSubmatch(line); m != nil {
                        // Defer midsamp processing — needs complete metByCookie.
                        // v0.9.108: capture the fields once instead of storing
                        // the raw line and re-running rxMidsamp in the deferred pass.
                        mts, _ := strconv.ParseFloat(m[1], 64)
                        mcookie, _ := strconv.ParseInt(m[2], 10, 64)
                        mrVal, _ := strconv.ParseInt(m[3], 10, 64)
                        midsampLines = append(midsampLines, parsedMidsamp{mts, mcookie, mrVal})

                        // buildRate: extract thr/rport/srate for the rate panel
                        // (this doesn't need metByCookie, so do it inline)
                        mt := rxMidsampThr.FindStringSubmatch(line)
                        mr := rxMidsampRport.FindStringSubmatch(line)
                        ms := rxMidsampSrate.FindStringSubmatch(line)
                        if mt != nil && mr != nil && ms != nil {
                                thr, _ := atoiSafe(mt[1])
                                srate, _ := parseInt64Safe(ms[1])
                                // v0.9.32: resolve dest from cookie→dest map
                                cookieStr := m[2]
                                dest := ""
                                if d, ok := pl.Cdest[cookieStr]; ok {
                                        ds := destStr(d[0], d[1], d[2])
                                        dest = labelFor(ds)
                                        if dest == "" {
                                                dest = ds
                                        }
                                }
                                pl.MidsampRows = append(pl.MidsampRows, midsampRow{
                                        Thr:   thr,
                                        Srate: srate,
                                        Rport: mr[1],
                                        Dest:  dest,
                                })
                        }

                        // buildBucketIPs: midsamp lines may carry dest=
                        pl.extractBucketIPs(line, p4, p6)
                        continue
                }
                }

                // buildBucketIPs: any remaining line with dest=
                pl.extractBucketIPs(line, p4, p6)
        }

        // Deferred midsamp processing — now that MetByCookie is complete,
        // process midsamp events for proofSamples (mirrors the second pass
        // of the original proofEvents function).
        const metWindowS = 60.0
        for _, mp := range midsampLines {
                ts := mp.ts
                cookie := mp.cookie
                r := mp.r
                if r <= 0 {
                        continue
                }
                cand := pl.MetByCookie[cookie]
                var bestA int = -1
                var bestD float64 = -1
                for _, e := range cand {
                        d := e.Ts - ts
                        if d < 0 {
                                d = -d
                        }
                        if d > metWindowS {
                                continue
                        }
                        if bestA < 0 || d < bestD {
                                bestA = e.Alg
                                bestD = d
                        }
                }
                if bestA >= 0 {
                        s := pl.ProofSamples[bestA]
                        s.sum += r
                        s.n++
                        if r > s.sampMax {
                                s.sampMax = r
                        }
                        pl.ProofSamples[bestA] = s
                }
        }

        return pl
}

// toIntOrZero parses a decimal string to int, 0 on error.
func toIntOrZero(s string) int {
        n, _ := strconv.Atoi(s)
        return n
}

// extractBucketIPs extracts dest= / dest6= / dest6b= from a line and
// adds them to pl.BucketIPs. This is the same logic as buildBucketIPs
// but operates on a single line instead of the full text.
// v0.9.84: fast-path with strings.Contains check before regex. Most log
// lines (midsamp, met, srate, proof without dest=) don't contain "dest="
// at all — the regex was being invoked on every line for nothing.
func (pl *parsedLog) extractBucketIPs(line string, p4, p6 int) {
        // v0.9.84: cheap byte-check before expensive regex. Skips ~80% of lines.
        if !strings.Contains(line, "dest=") {
                return
        }
        if m := rxDestInt.FindStringSubmatch(line); m != nil && len(m) > 1 {
                n, err := strconv.ParseUint(m[1], 10, 64)
                if err == nil && n != 0 {
                        b := make([]byte, 4)
                        b[0] = byte(n >> 24)
                        b[1] = byte(n >> 16)
                        b[2] = byte(n >> 8)
                        b[3] = byte(n)
                        full := net.IP(b).String()
                        mask := net.CIDRMask(p4, 32)
                        masked := net.IP(b).Mask(mask).String()
                        if !contains(pl.BucketIPs[masked], full) {
                                pl.BucketIPs[masked] = append(pl.BucketIPs[masked], full)
                        }
                }
        }
        if m := rxDest6.FindStringSubmatch(line); m != nil && len(m) > 1 {
                n6, err := strconv.ParseUint(m[1], 10, 64)
                if err == nil && n6 != 0 {
                        ip := make([]byte, 16)
                        ip[0] = byte(n6 >> 24)
                        ip[1] = byte(n6 >> 16)
                        ip[2] = byte(n6 >> 8)
                        ip[3] = byte(n6)
                        fullIP := make([]byte, 16)
                        copy(fullIP, ip)
                        if m2 := rxDest6B.FindStringSubmatch(line); m2 != nil && len(m2) > 1 {
                                n6b, err := strconv.ParseUint(m2[1], 10, 64)
                                if err == nil && n6b != 0 {
                                        fullIP[4] = byte(n6b >> 24)
                                        fullIP[5] = byte(n6b >> 16)
                                        fullIP[6] = byte(n6b >> 8)
                                        fullIP[7] = byte(n6b)
                                }
                        }
                        fullV6 := net.IP(fullIP).String()
                        mask := net.CIDRMask(p6, 128)
                        masked := net.IP(ip).Mask(mask).String()
                        if !contains(pl.BucketIPs[masked], fullV6) {
                                pl.BucketIPs[masked] = append(pl.BucketIPs[masked], fullV6)
                        }
                }
        }
}

// GetBucketIPs returns the pre-computed bucket_ips map (JSON-serializable).
// Built once from pl.BucketIPs and cached.
func (pl *parsedLog) GetBucketIPs() map[string]interface{} {
        if pl.bucketIPsCache != nil {
                return pl.bucketIPsCache
        }
        out := map[string]interface{}{}
        for k, v := range pl.BucketIPs {
                iface := make([]interface{}, len(v))
                for i, s := range v {
                        iface[i] = s
                }
                out[k] = iface
        }
        pl.bucketIPsCache = out
        return pl.bucketIPsCache
}

// GetProofRows returns the pre-computed recent_proofs rows (last 18, newest-first).
// Built once from pl.parsedProofs and cached.
// v0.9.108: operates on the captured proof fields (no rxProof re-scan) and
// hoists readProcUptime()/time.Now() out of the row loop. Row content is
// identical to v0.9.104 (including the parse-order alg semantics).
func (pl *parsedLog) GetProofRows(cdest map[string]cdestEntry) []interface{} {
        if pl.proofRowsCache != nil {
                return pl.proofRowsCache
        }
        pps := pl.parsedProofs
        if len(pps) > 18 {
                pps = pps[len(pps)-18:]
        }
        uptime := readProcUptime()
        nowEpoch := float64(time.Now().Unix())
        out := make([]interface{}, 0, len(pps))
        for _, pp := range pps {
                ts := pp.ts
                cookie := pp.cookie
                alg := pp.alg
                // v0.9.31: rewrite alg=0 from cookie→alg map (cubic-proof fix)
                if alg == 0 {
                        if realAlg, ok := pl.CookieAlg[cookie]; ok && realAlg != 0 {
                                alg = realAlg
                        }
                }
                rate := pp.rate
                tier := pp.tier
                tierLabel := "good"
                if tier == "2" {
                        tierLabel = "proved"
                }
                dest := ""
                v4, v6, v6b := pp.v4, pp.v6, pp.v6b
                if v4 != "" || v6 != "" || v6b != "" {
                        ds := destStr(v4, v6, v6b)
                        dest = labelFor(ds)
                        if dest == "" {
                                dest = ds
                        }
                } else if d, ok := cdest[cookie]; ok {
                        ds := destStr(d[0], d[1], d[2])
                        dest = labelFor(ds)
                        if dest == "" {
                                dest = ds
                        }
                }
                // v0.9.95 (AUDIT-PROOFS-1 LEAK #1): skip rows with empty dest.
                // The live path was the last remaining leak — v0.9.93/v0.9.94
                // only filtered the CSV round-trip. Without this, passive
                // connections (no estab -> no cdest entry) and pre-v0.4.98 BPF
                // binaries (no dest= in proof line) still leak (unknown) into
                // the panel. The row is unusable anyway (frontend renders
                // "(unknown)"); better to show fewer rows than pollute the panel.
                if dest == "" {
                        continue
                }
                // v0.9.31 (Bug 1): add epoch_ts for age label (was missing)
                out = append(out, map[string]interface{}{
                        "boot_ts":  ts,
                        "epoch_ts": int64(nowEpoch - uptime + ts),
                        "alg":      algName(alg),
                        "mbps":     round1(float64(rate) / bpsToMbps),
                        "tier":     tierLabel,
                        "dest":     dest,
                })
        }
        // v0.9.16: sort by boot_ts descending (newest-first).
        // Was: reverse(out) — same bug as buildRecentSwapRows.
        sort.Slice(out, func(i, j int) bool {
                ti, _ := out[i].(map[string]interface{})["boot_ts"].(float64)
                tj, _ := out[j].(map[string]interface{})["boot_ts"].(float64)
                return ti > tj
        })
        pl.proofRowsCache = out
        return pl.proofRowsCache
}

// GetProofsRaw returns the pre-computed proof leaderboard (good/proved/sampled per alg).
// Built once from pl.ProofEvents and pl.ProofSamples and cached.
func (pl *parsedLog) GetProofsRaw() []interface{} {
        if pl.proofsRawCache != nil {
                return pl.proofsRawCache
        }
        algSet := map[int]bool{}
        for a := range pl.ProofEvents {
                algSet[a] = true
        }
        for a := range pl.ProofSamples {
                algSet[a] = true
        }
        var algs []int
        for a := range algSet {
                algs = append(algs, a)
        }
        sort.Ints(algs)
        out := make([]interface{}, 0, len(algs))
        for _, a := range algs {
                e := pl.ProofEvents[a]
                s := pl.ProofSamples[a]
                var provenMax, sampledAvg, sampledMax interface{}
                if e.provenMax > 0 {
                        provenMax = round1(float64(e.provenMax) / bpsToMbps)
                }
                if s.n > 0 {
                        sampledAvg = round1(float64(s.sum) / float64(s.n) / bpsToMbps)
                        sampledMax = round1(float64(s.sampMax) / bpsToMbps)
                }
                var samplesN interface{}
                if s.n > 0 {
                        samplesN = s.n
                }
                out = append(out, map[string]interface{}{
                        "alg":         algName(a),
                        "good":        e.good,
                        "proved":      e.proved,
                        "proven_max":  provenMax,
                        "sampled_avg": sampledAvg,
                        "sampled_max": sampledMax,
                        "samples":     samplesN,
                })
        }
        sort.Slice(out, func(i, j int) bool {
                vi, _ := out[i].(map[string]interface{})["proven_max"].(float64)
                vj, _ := out[j].(map[string]interface{})["proven_max"].(float64)
                return vi > vj
        })
        pl.proofsRawCache = out
        return pl.proofsRawCache
}

// GetProofsRawEvents returns the pre-computed proofs_raw events list.
// Built once from pl.parsedProofs and cached.
// v0.9.108: no rxProof re-scan. NOTE: unlike GetProofRows, this view does
// NOT apply the v0.9.31 cookie→alg rewrite — preserved from v0.9.104.
func (pl *parsedLog) GetProofsRawEvents(cdest map[string]cdestEntry) []interface{} {
        if pl.proofsRawEventsCache != nil {
                return pl.proofsRawEventsCache
        }
        out := make([]interface{}, 0, len(pl.parsedProofs))
        for _, pp := range pl.parsedProofs {
                ts := pp.ts
                alg := pp.alg
                rate := pp.rate
                tier := pp.tier
                tierLabel := "good"
                if tier == "2" {
                        tierLabel = "proved"
                }
                dest := ""
                v4, v6, v6b := pp.v4, pp.v6, pp.v6b
                if v4 != "" || v6 != "" || v6b != "" {
                        ds := destStr(v4, v6, v6b)
                        dest = labelFor(ds)
                        if dest == "" {
                                dest = ds
                        }
                } else if d, ok := cdest[pp.cookie]; ok {
                        ds := destStr(d[0], d[1], d[2])
                        dest = labelFor(ds)
                        if dest == "" {
                                dest = ds
                        }
                }
                // v0.9.95 (AUDIT-PROOFS-1 LEAK #4): defence-in-depth — same
                // filter as GetProofRows above. proofs_raw is consumed by the
                // frontend's _filterByBucket which already drops empty-dest
                // rows, but we shouldn't ship them at all.
                if dest == "" {
                        continue
                }
                out = append(out, map[string]interface{}{
                        "ts":   ts,
                        "alg":  algName(alg),
                        "rate": round1(float64(rate) / bpsToMbps),
                        "tier": tierLabel,
                        "dest": dest,
                })
        }
        pl.proofsRawEventsCache = out
        return pl.proofsRawEventsCache
}

// GetRateRaw returns raw midsamp rows with dest field, for bucket filtering.
// Each row has: thr, srate, rport, dest
func (pl *parsedLog) GetRateRaw() []interface{} {
        out := make([]interface{}, 0, len(pl.MidsampRows))
        for _, mr := range pl.MidsampRows {
                out = append(out, map[string]interface{}{
                        "thr":   mr.Thr,
                        "srate": mr.Srate,
                        "rport": mr.Rport,
                        "dest":  mr.Dest,  // v0.9.32: now populated from cookie→dest map
                })
        }
        return out
}

// GetRate returns the pre-computed rate progression panel.
// Built once from pl.MidsampRows and cached.
func (pl *parsedLog) GetRate() []interface{} {
        if pl.rateCache != nil {
                return pl.rateCache
        }
        outMap := map[int][]int64{}
        for _, mr := range pl.MidsampRows {
                if mr.Rport == "443" {
                        continue // skip origin traffic
                }
                outMap[mr.Thr] = append(outMap[mr.Thr], mr.Srate)
        }
        var thrs []int
        for t := range outMap {
                thrs = append(thrs, t)
        }
        sort.Ints(thrs)
        const maxBps = int64(1250000000)
        rows := make([]interface{}, 0, len(thrs))
        for _, thr := range thrs {
                vs := outMap[thr]
                filtered := vs[:0]
                for _, v := range vs {
                        if v <= maxBps {
                                filtered = append(filtered, v)
                        }
                }
                if len(filtered) == 0 {
                        filtered = vs
                }
                var sum int64
                var minV, maxV int64
                minV = filtered[0]
                maxV = filtered[0]
                for _, v := range filtered {
                        sum += v
                        if v < minV {
                                minV = v
                        }
                        if v > maxV {
                                maxV = v
                        }
                }
                n := len(filtered)
                rows = append(rows, map[string]interface{}{
                        "thr":  thr,
                        "n":    n,
                        "mean": round1(float64(sum) / float64(n) / bpsToMbps),
                        "min":  round1(float64(minV) / bpsToMbps),
                        "max":  round1(float64(maxV) / bpsToMbps),
                })
        }
        pl.rateCache = rows
        return pl.rateCache
}
