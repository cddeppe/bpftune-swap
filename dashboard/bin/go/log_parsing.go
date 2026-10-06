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
	"net"
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
			`rport=(\d+) alg=(\d+) segs=(\d+) val=(\d+)`)

	rxSrate = regexp.MustCompile(
		`(\d+\.\d+): bpf_trace_printk: srate cookie=(\d+) ` +
			`alg=(\d+) srate=(\d+)`)

	rxEstab = regexp.MustCompile(
		`(\d+\.\d+): bpf_trace_printk: estab cookie=(\d+) ` +
			`alg=(\d+) forced=\d+ dest=(\d+)(?: dest6=(\d+))?(?: dest6b=(\d+))?`)

	rxProof = regexp.MustCompile(
		`(\d+\.\d+): .*proof cookie=(\d+) alg=(\d+) rate=(\d+) tier=(\d+)`)

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
	cdest map[string]cdestEntry, text string) (topSwaps, topProofs []interface{},
	swapOutcomes, bucketIPs, logWindow, proofsRaw interface{}) {

	if text == "" {
		return []interface{}{}, []interface{}{},
			emptySwapOutcomes(), map[string]interface{}{},
			emptyLogWindow(), []interface{}{}
	}

	// ----- recent_swaps (newest-first, last 18) --------------------------
	allSwaps := buildRecentSwapRows(swaps, metByCookie, srateByCookie, cdest)
	topSwaps = lastN(allSwaps, 18)

	// ----- recent_proofs (newest-first, last 18) --------------------------
	allProofs := buildRecentProofRows(text, cdest)
	topProofs = lastN(allProofs, 18)

	// ----- swap_outcomes (composite + srate + sustained) ----------------
	swapOutcomes = buildSwapOutcomes(swaps, metByCookie, srateByCookie)

	// ----- bucket_ips (all dest= occurrences, /16 or /32 grouped) ------
	bucketIPs = buildBucketIPs(text)

	// ----- log_window (oldest/newest swap ts, span, age) ----------------
	logWindow = buildLogWindow(swaps)

	// ----- proofs_raw (proof leaderboard: good/proved/sampled per alg) --
	proofsRaw = buildProofsRaw(text)

	return topSwaps, topProofs, swapOutcomes, bucketIPs, logWindow, proofsRaw
}

// ============================================================================
// parseSwapsMetsSrates — extract swap / met / srate events from text
// ============================================================================

func parseSwapsMetsSrates(text string) (swaps []swapRow,
	metByCookie map[int64][]metEntry, srateByCookie map[int64][]srateEntry) {

	metByCookie = map[int64][]metEntry{}
	srateByCookie = map[int64][]srateEntry{}

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
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
			swaps = append(swaps, row)
			continue
		}
		if m := rxMet.FindStringSubmatch(line); m != nil {
			ts, _ := strconv.ParseFloat(m[1], 64)
			cookie, _ := strconv.ParseInt(m[2], 10, 64)
			rport := m[3]
			alg, _ := strconv.Atoi(m[4])
			val, _ := strconv.ParseInt(m[6], 10, 64)
			metByCookie[cookie] = append(metByCookie[cookie],
				metEntry{Ts: ts, Val: val, Rport: rport, Alg: alg})
			continue
		}
		if m := rxSrate.FindStringSubmatch(line); m != nil {
			ts, _ := strconv.ParseFloat(m[1], 64)
			cookie, _ := strconv.ParseInt(m[2], 10, 64)
			alg, _ := strconv.Atoi(m[3])
			sr, _ := strconv.ParseInt(m[4], 10, 64)
			srateByCookie[cookie] = append(srateByCookie[cookie],
				srateEntry{Ts: ts, Srate: sr, Alg: alg})
		}
	}
	return swaps, metByCookie, srateByCookie
}

// ============================================================================
// buildRecentSwapRows — derive outcome per swap, return dashboard rows
// ============================================================================

func buildRecentSwapRows(swaps []swapRow,
	metByCookie map[int64][]metEntry,
	srateByCookie map[int64][]srateEntry,
	cdest map[string]cdestEntry) []interface{} {

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
	// Newest-first (matches data_recent_swaps 0.4.90 contract).
	return reverse(rows)
}

// ============================================================================
// Outcome derivation — three rulers (composite, srate, sustained)
// ============================================================================

// outcomeComposite: post/pre ratio of `val` from met events.
//
//	post = first met sample in [T+3, T+300]
//	pre  = last met sample before T
//	r = post/pre; r<=0.9 → win (lower is better — opposite of srate),
//	r>=1.1 → loss, else null
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
//	pre = last srate before T
//	post = first srate after T
//	r>=1.1 → win, r<=0.9 → loss, else null
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
//	r>=1.1 → win, r<=0.9 → loss, else null
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
			"cookie":            s.Cookie,
			"dest":              s.Dest,
			"outcome":           oc,
			"outcome_sustained": ou_,
		})
	}
	return out
}

// ============================================================================
// buildRecentProofRows — parse proof events, attach dest via cookie map
// ============================================================================

func buildRecentProofRows(text string, cdest map[string]cdestEntry) []interface{} {
	var lines []string
	for _, l := range strings.Split(text, "\n") {
		if strings.Contains(l, "proof cookie=") {
			lines = append(lines, l)
		}
	}
	// Take last 18 (oldest → newest), then reverse so newest-first.
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
		if d, ok := cdest[cookie]; ok {
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
	return reverse(out)
}

// ============================================================================
// cookieDestMap — cookie → (v4, v6) from estab + swap events
// ============================================================================

// cookieDestMap builds the cookie→dest map from estab + swap events.
// v0.9.0: stores cdestEntry [3]string{v4, v6, v6b} — dest6b is now
// captured from both rxSwap (group 12) and rxEstab (group 6, newly added).
//
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
func buildBucketIPs(text string) map[string]interface{} {
	buckets := map[string][]string{}
	p4 := prefix4Value()
	p6 := prefix6Value()
	for _, line := range strings.Split(text, "\n") {
		if m := rxDestInt.FindStringSubmatch(line); m != nil && len(m) > 1 {
			n, err := strconv.ParseUint(m[1], 10, 64)
			if err != nil || n == 0 {
				continue
			}
			// Build 4-byte v4 IP.
			b := make([]byte, 4)
			b[0] = byte(n >> 24)
			b[1] = byte(n >> 16)
			b[2] = byte(n >> 8)
			b[3] = byte(n)
			full := net.IP(b).String()
			// Mask with prefix4.
			mask := net.CIDRMask(p4, 32)
			masked := net.IP(b).Mask(mask).String()
			if !contains(buckets[masked], full) {
				buckets[masked] = append(buckets[masked], full)
			}
		}
		if m := rxDest6.FindStringSubmatch(line); m != nil && len(m) > 1 {
			n6, err := strconv.ParseUint(m[1], 10, 64)
			if err != nil || n6 == 0 {
				continue
			}
			// Build 16-byte v6 IP (top 32 bits = n6, rest = 0).
			ip := make([]byte, 16)
			ip[0] = byte(n6 >> 24)
			ip[1] = byte(n6 >> 16)
			ip[2] = byte(n6 >> 8)
			ip[3] = byte(n6)
			// Build full form (may include dest6b for /64 form).
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
			// Mask with prefix6.
			mask := net.CIDRMask(p6, 128)
			masked := net.IP(ip).Mask(mask).String()
			if !contains(buckets[masked], fullV6) {
				buckets[masked] = append(buckets[masked], fullV6)
			}
		}
	}
	out := map[string]interface{}{}
	for k, v := range buckets {
		// Cast []string → []interface{} for JSON marshalling.
		iface := make([]interface{}, len(v))
		for i, s := range v {
			iface[i] = s
		}
		out[k] = iface
	}
	return out
}

// ============================================================================
// buildLogWindow — oldest/newest swap ts + span/age info
// ============================================================================

func buildLogWindow(swaps []swapRow) map[string]interface{} {
	if len(swaps) == 0 {
		return emptyLogWindow()
	}
	oldest := swaps[0].Ts
	newest := swaps[0].Ts
	for _, s := range swaps[1:] {
		if s.Ts < oldest {
			oldest = s.Ts
		}
		if s.Ts > newest {
			newest = s.Ts
		}
	}
	uptime := readProcUptime()
	now := float64(time.Now().Unix())
	oldestWall := int64(now - uptime + oldest)
	var newestWall int64
	if newest > uptime {
		newestWall = readLogFileMtime()
	} else {
		newestWall = int64(now - uptime + newest)
	}
	ageMin := round1((now - float64(newestWall)) / 60.0)
	return map[string]interface{}{
		"oldest_ts":  oldestWall,
		"newest_ts":  newestWall,
		"span_min":   round1((newest - oldest) / 60.0),
		"swap_count": len(swaps),
		"age_min":    ageMin,
	}
}

// ============================================================================
// buildProofsRaw — proof leaderboard (good/proved/sampled per alg)
// ============================================================================

func buildProofsRaw(text string) []interface{} {
	events, samples := proofEvents(text)
	algSet := map[int]bool{}
	for a := range events {
		algSet[a] = true
	}
	for a := range samples {
		algSet[a] = true
	}
	var algs []int
	for a := range algSet {
		algs = append(algs, a)
	}
	sort.Ints(algs)
	out := make([]interface{}, 0, len(algs))
	for _, a := range algs {
		e := events[a]
		s := samples[a]
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
	// Sort descending by proven_max (treat nil as 0).
	sort.Slice(out, func(i, j int) bool {
		vi, _ := out[i].(map[string]interface{})["proven_max"].(float64)
		vj, _ := out[j].(map[string]interface{})["proven_max"].(float64)
		return vi > vj
	})
	return out
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

// buildProofsRawEvents builds the proofs_raw list (one entry per proof
// event, with cookie→dest resolution).  v0.9.0: takes cdest as a
// parameter instead of re-parsing the log on every cycle — the prior
// implementation called cookieDestMap(text) a SECOND time per cycle,
// duplicating the work already done in collect.go.  For a 2 MB log tail
// with ~10k lines, that was ~5ms of wasted regex per cycle.
func buildProofsRawEvents(text string, cdest map[string]cdestEntry) []interface{} {
	var out []interface{}
	for _, line := range strings.Split(text, "\n") {
		if !strings.Contains(line, "proof cookie=") {
			continue
		}
		m := rxProof.FindStringSubmatch(line)
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
		if d, ok := cdest[cookie]; ok {
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
	return out
}

func proofEvents(text string) (map[int]proofEvent, map[int]proofSample) {
	events := map[int]proofEvent{}
	samples := map[int]proofSample{}
	metByCookie := map[int64][]struct {
		Ts  float64
		Alg int
	}{}

	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "proof cookie=") {
			m := rxProof.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			a, _ := strconv.Atoi(m[3])
			rate, _ := strconv.ParseInt(m[4], 10, 64)
			tier := m[5]
			e := events[a]
			if tier == "2" {
				e.proved++
			} else {
				e.good++
			}
			if rate > e.provenMax {
				e.provenMax = rate
			}
			events[a] = e
			continue
		}
		if m := rxMet.FindStringSubmatch(line); m != nil {
			ts, _ := strconv.ParseFloat(m[1], 64)
			c, _ := strconv.ParseInt(m[2], 10, 64)
			alg, _ := strconv.Atoi(m[4])
			metByCookie[c] = append(metByCookie[c],
				struct {
					Ts  float64
					Alg int
				}{ts, alg})
		}
	}
	const metWindowS = 60.0
	for _, line := range strings.Split(text, "\n") {
		m := rxMidsamp.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ts, _ := strconv.ParseFloat(m[1], 64)
		c, _ := strconv.ParseInt(m[2], 10, 64)
		r, _ := strconv.ParseInt(m[3], 10, 64)
		if r <= 0 {
			continue
		}
		cand := metByCookie[c]
		var bestA int = -1
		var bestD float64 = -1
		for _, e := range cand {
			d := e.Ts - ts
			if d < 0 {
				d = -d
			}
			if bestD < 0 || d < bestD {
				bestD = d
				bestA = e.Alg
			}
		}
		if bestA < 0 || bestD < 0 || bestD > metWindowS {
			continue
		}
		s := samples[bestA]
		s.sum += r
		s.n++
		if r > s.sampMax {
			s.sampMax = r
		}
		samples[bestA] = s
	}
	return events, samples
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
	pattern := "/var/log/bpftune-met-*.log"
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
	var chunks []string
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
		chunks = append(chunks, string(buf))
		remaining -= take
	}
	return strings.Join(chunks, "\n")
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
	empty := map[string]interface{}{
		"measurable": 0, "unmeasurable": 0,
		"win": 0, "win_pct": 0.0,
		"null": 0, "null_pct": 0.0,
		"loss": 0, "loss_pct": 0.0,
		"rescued": 0, "full_loss": 0, "open": 0,
		"rescued_pct": 0.0, "full_loss_pct": 0.0, "open_pct": 0.0,
		"swaps_list": []interface{}{},
	}
	return map[string]interface{}{
		"composite": copyMap(empty),
		"srate":     copyMap(empty),
		"sustained": copyMap(empty),
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
