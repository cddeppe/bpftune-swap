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

import (
        "net"
        "sort"
	"sync"
        "strconv"
        "strings"
)

// parsedLog holds the result of a single pass over the log tail.
// All fields are populated in one loop over strings.Split(text, "\n").
type parsedLog struct {
        Swaps      []swapRow
        MetByCookie map[int64][]metEntry
        SrateByCookie map[int64][]srateEntry
        Cdest      map[string]cdestEntry
        ProofLines []string   // raw lines matching "proof cookie="
        ProofEvents map[int]proofEvent
        ProofSamples map[int]proofSample
        MidsampRows []midsampRow
        BucketIPs   map[string][]string // masked → []fullIP
        MaxTs       float64              // max bpf_trace_printk timestamp

        // Pre-computed views (built once from the raw data above)
        proofRowsCache     []interface{}
        proofsRawCache     []interface{}
        proofsRawEventsCache []interface{}
        bucketIPsCache      map[string]interface{}
        rateCache           []interface{}
}

// midsampRow is a parsed midsamp line, used by buildRate.
type midsampRow struct {
        Thr   int
        Srate int64
        Rport string
}

// parseLogSinglePass does ONE pass over text and extracts everything.
// This replaces the 9 separate strings.Split(text, "\n") scans.
// bootUptimeCache caches /proc/uptime to avoid re-reading on every parse.
var bootUptimeCache struct {
	sync.Once
	value float64
}

// getBootUptime returns /proc/uptime (seconds since boot).
// Used to filter out events from previous boots.
func getBootUptime() float64 {
	bootUptimeCache.Do(func() {
		bootUptimeCache.value = readProcUptime()
	})
	return bootUptimeCache.value
}

func parseLogSinglePass(text string) *parsedLog {
        pl := &parsedLog{
                MetByCookie:  map[int64][]metEntry{},
                SrateByCookie: map[int64][]srateEntry{},
                Cdest:        map[string]cdestEntry{},
                ProofEvents:  map[int]proofEvent{},
                ProofSamples: map[int]proofSample{},
                BucketIPs:    map[string][]string{},
        }

        p4 := prefix4Value()
        p6 := prefix6Value()

        // Collect midsamp lines for deferred processing — the original
        // proofEvents() does TWO passes: first to build metByCookie,
        // then to process midsamp using the complete metByCookie.
        // We collect midsamp lines here and process them after the main
        // loop, so all met entries are guaranteed to be in MetByCookie.
        var midsampLines []string

        for _, line := range strings.Split(text, "\n") {
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

                if m := rxMet.FindStringSubmatch(line); m != nil {
                        ts, _ := strconv.ParseFloat(m[1], 64)
                        cookie, _ := strconv.ParseInt(m[2], 10, 64)
                        rport := m[3]
                        alg, _ := strconv.Atoi(m[4])
                        val, _ := strconv.ParseInt(m[6], 10, 64)
                        pl.MetByCookie[cookie] = append(pl.MetByCookie[cookie],
                                metEntry{Ts: ts, Val: val, Rport: rport, Alg: alg})
                        continue
                }

                if m := rxSrate.FindStringSubmatch(line); m != nil {
                        ts, _ := strconv.ParseFloat(m[1], 64)
                        cookie, _ := strconv.ParseInt(m[2], 10, 64)
                        alg, _ := strconv.Atoi(m[3])
                        sr, _ := strconv.ParseInt(m[4], 10, 64)
                        pl.SrateByCookie[cookie] = append(pl.SrateByCookie[cookie],
                                srateEntry{Ts: ts, Srate: sr, Alg: alg})
                        continue
                }

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
                        continue
                }

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

                        // buildBucketIPs: estab lines also carry dest=
                        pl.extractBucketIPs(line, p4, p6)
                        continue
                }

                if strings.Contains(line, "proof cookie=") {
                        if m := rxProof.FindStringSubmatch(line); m != nil {
                                pl.ProofLines = append(pl.ProofLines, line)

                                // proofEvents: aggregate good/proved/provenMax per alg
                                a, _ := strconv.Atoi(m[3])
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

                                // buildBucketIPs: proof lines also carry dest=
                                pl.extractBucketIPs(line, p4, p6)
                        }
                        continue
                }

                if m := rxMidsamp.FindStringSubmatch(line); m != nil {
                        // Defer midsamp processing — needs complete metByCookie.
                        // The original proofEvents() does TWO passes: first to
                        // build metByCookie from all met lines, then to process
                        // midsamp. We collect midsamp lines here and process
                        // them after the main loop.
                        midsampLines = append(midsampLines, line)

                        // buildRate: extract thr/rport/srate for the rate panel
                        // (this doesn't need metByCookie, so do it inline)
                        mt := rxMidsampThr.FindStringSubmatch(line)
                        mr := rxMidsampRport.FindStringSubmatch(line)
                        ms := rxMidsampSrate.FindStringSubmatch(line)
                        if mt != nil && mr != nil && ms != nil {
                                thr, _ := atoiSafe(mt[1])
                                srate, _ := parseInt64Safe(ms[1])
                                pl.MidsampRows = append(pl.MidsampRows, midsampRow{
                                        Thr:   thr,
                                        Srate: srate,
                                        Rport: mr[1],
                                })
                        }

                        // buildBucketIPs: midsamp lines may carry dest=
                        pl.extractBucketIPs(line, p4, p6)
                        continue
                }

                // buildBucketIPs: any remaining line with dest=
                pl.extractBucketIPs(line, p4, p6)
        }

        // Deferred midsamp processing — now that MetByCookie is complete,
        // process midsamp lines for proofSamples (mirrors the second pass
        // of the original proofEvents function).
        const metWindowS = 60.0
        for _, line := range midsampLines {
                m := rxMidsamp.FindStringSubmatch(line)
                if m == nil {
                        continue
                }
                ts, _ := strconv.ParseFloat(m[1], 64)
                cookie, _ := strconv.ParseInt(m[2], 10, 64)
                r, _ := strconv.ParseInt(m[3], 10, 64)
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

// extractBucketIPs extracts dest= / dest6= / dest6b= from a line and
// adds them to pl.BucketIPs. This is the same logic as buildBucketIPs
// but operates on a single line instead of the full text.
func (pl *parsedLog) extractBucketIPs(line string, p4, p6 int) {
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
        return out
}

// GetProofRows returns the pre-computed recent_proofs rows (last 18, newest-first).
// Built once from pl.ProofLines and cached.
func (pl *parsedLog) GetProofRows(cdest map[string]cdestEntry) []interface{} {
        if pl.proofRowsCache != nil {
                return pl.proofRowsCache
        }
        lines := pl.ProofLines
        if len(lines) > 18 {
                lines = lines[len(lines)-18:]
        }
        out := make([]interface{}, 0, len(lines))
        for _, l := range lines {
                m := rxProof.FindStringSubmatch(l)
                if m == nil {
                        continue
                }
                ts, _ := strconv.ParseFloat(m[1], 64)
                cookie := m[2]
                alg, _ := strconv.Atoi(m[3])
                rate, _ := strconv.ParseInt(m[4], 10, 64)
                tier := m[5]
                tierLabel := "good"
                if tier == "2" {
                        tierLabel = "proved"
                }
                dest := ""
                v4, v6, v6b := m[6], m[7], m[8]
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
                out = append(out, map[string]interface{}{
                        "boot_ts": ts,
                        "alg":     algName(alg),
                        "mbps":    round1(float64(rate) / bpsToMbps),
                        "tier":    tierLabel,
                        "dest":    dest,
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
// Built once from pl.ProofLines and cached.
func (pl *parsedLog) GetProofsRawEvents(cdest map[string]cdestEntry) []interface{} {
        if pl.proofsRawEventsCache != nil {
                return pl.proofsRawEventsCache
        }
        out := make([]interface{}, 0, len(pl.ProofLines))
        for _, l := range pl.ProofLines {
                m := rxProof.FindStringSubmatch(l)
                if m == nil {
                        continue
                }
                ts, _ := strconv.ParseFloat(m[1], 64)
                cookie := m[2]
                alg, _ := strconv.Atoi(m[3])
                rate, _ := strconv.ParseInt(m[4], 10, 64)
                tier := m[5]
                tierLabel := "good"
                if tier == "2" {
                        tierLabel = "proved"
                }
                dest := ""
                v4, v6, v6b := m[6], m[7], m[8]
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
