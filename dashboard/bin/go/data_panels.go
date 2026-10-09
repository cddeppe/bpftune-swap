package main

// Missing data panels: churn, rate, divergence, tunables.
// Mirrors bpftune_data.py:
//   data_churn (line 806), data_rate (line 536),
//   data_divergence (line 740), data_tunables (line 138).

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// ============================================================================
// data_churn — swap count per cookie, classified as one/mid/many
// ============================================================================

func buildChurn(text string) map[string]interface{} {
	swaps, _, _ := parseSwapsMetsSrates(text)
	counts := map[int64]int{}
	for _, sw := range swaps {
		counts[sw.Cookie]++
	}
	if len(counts) == 0 {
		return map[string]interface{}{
			"cookies": 0, "one": 0, "mid": 0, "many": 0, "max": 0,
		}
	}
	one, mid, many := 0, 0, 0
	maxCount := 0
	for _, v := range counts {
		switch {
		case v >= 5:
			many++
		case v >= 2:
			mid++
		default:
			one++
		}
		if v > maxCount {
			maxCount = v
		}
	}
	return map[string]interface{}{
		"cookies": len(counts),
		"one":     one,
		"mid":     mid,
		"many":    many,
		"max":     maxCount,
	}
}

// ============================================================================
// data_rate — midsamp aggregation per threshold
// ============================================================================

var (
	rxMidsampThr   = regexp.MustCompile(`thr=(\d+)`)
	rxMidsampRport = regexp.MustCompile(`rport=(\d+)`)
	rxMidsampSrate = regexp.MustCompile(`srate=(\d+)`)
)

func buildRate(text string) []interface{} {
	outMap := map[int][]int64{}
	for _, line := range strings.Split(text, "\n") {
		if !strings.Contains(line, "midsamp") {
			continue
		}
		mt := rxMidsampThr.FindStringSubmatch(line)
		mr := rxMidsampRport.FindStringSubmatch(line)
		ms := rxMidsampSrate.FindStringSubmatch(line)
		if mt == nil || mr == nil || ms == nil {
			continue
		}
		if mr[1] == "443" {
			continue // skip origin traffic
		}
		thr, _ := atoiSafe(mt[1])
		srate, _ := parseInt64Safe(ms[1])
		outMap[thr] = append(outMap[thr], srate)
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
		// Filter out values > maxBps (garbage)
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
	return rows
}

// ============================================================================
// data_divergence — mt_alg vs rb_alg divergence classification
// ============================================================================

func buildDivergence(text string) []interface{} {
	swaps, met, srate := parseSwapsMetsSrates(text)
	type group struct {
		total              int
		win, null, loss    int
		winS, nullS, lossS int
		winU, nullU, lossU int
	}
	keys := []string{"rate==metric", "rate!=metric", "pre-0.4.45"}
	groups := map[string]*group{}
	for _, k := range keys {
		groups[k] = &group{}
	}
	for _, sw := range swaps {
		var key string
		mtI, rbI := sw.Mt, sw.Rb
		if mtI == "" || rbI == "" {
			key = "pre-0.4.45"
		} else if mtI == rbI {
			key = "rate==metric"
		} else {
			key = "rate!=metric"
		}
		g := groups[key]
		g.total++
		o := outcomeComposite(met, sw.Cookie, sw.Ts)
		if o != "" {
			switch o {
			case "win":
				g.win++
			case "null":
				g.null++
			case "loss":
				g.loss++
			}
		}
		o2 := outcomeSrate(srate, sw.Cookie, sw.Ts)
		if o2 != "" {
			switch o2 {
			case "win":
				g.winS++
			case "null":
				g.nullS++
			case "loss":
				g.lossS++
			}
		}
		o3 := outcomeSustained(srate, sw.Cookie, sw.Ts)
		if o3 != "" {
			switch o3 {
			case "win":
				g.winU++
			case "null":
				g.nullU++
			case "loss":
				g.lossU++
			}
		}
	}
	rows := make([]interface{}, 0, len(keys))
	for _, k := range keys {
		g := groups[k]
		cmeas := g.win + g.null + g.loss
		smeas := g.winS + g.nullS + g.lossS
		umeas := g.winU + g.nullU + g.lossU
		cp := func(x int) float64 {
			if cmeas == 0 {
				return 0
			}
			return round1(float64(x) * 100.0 / float64(cmeas))
		}
		sp := func(x int) float64 {
			if smeas == 0 {
				return 0
			}
			return round1(float64(x) * 100.0 / float64(smeas))
		}
		up := func(x int) float64 {
			if umeas == 0 {
				return 0
			}
			return round1(float64(x) * 100.0 / float64(umeas))
		}
		rows = append(rows, map[string]interface{}{
			"category":           k,
			"measured":           cmeas,
			"win_pct":            cp(g.win),
			"null_pct":           cp(g.null),
			"loss_pct":           cp(g.loss),
			"win":                g.win,
			"null":               g.null,
			"loss":               g.loss,
			"skipped":            g.total - cmeas,
			"measured_srate":     smeas,
			"win_pct_srate":      sp(g.winS),
			"null_pct_srate":     sp(g.nullS),
			"loss_pct_srate":     sp(g.lossS),
			"win_srate":          g.winS,
			"null_srate":         g.nullS,
			"loss_srate":         g.lossS,
			"skipped_srate":      g.total - smeas,
			"measured_sustained": umeas,
			"win_pct_sustained":  up(g.winU),
			"null_pct_sustained": up(g.nullU),
			"loss_pct_sustained": up(g.lossU),
			"win_sustained":      g.winU,
			"null_sustained":     g.nullU,
			"loss_sustained":     g.lossU,
			"skipped_sustained":  g.total - umeas,
		})
	}
	return rows
}

// ============================================================================
// data_tunables — read /proc/sys/net.* values, grouped by category
// ============================================================================

var knownTunables = []string{
	"net.core.netdev_budget",
	"net.core.netdev_budget_usecs",
	"net.core.rmem_default",
	"net.ipv4.tcp_rmem",
	"net.ipv4.tcp_wmem",
}

var interestingTunables = []string{
	"net.core.netdev_budget",
	"net.core.netdev_budget_usecs",
	"net.core.rmem_default",
	"net.core.rmem_max",
	"net.core.wmem_default",
	"net.core.wmem_max",
	"net.ipv4.tcp_rmem",
	"net.ipv4.tcp_wmem",
	"net.ipv4.tcp_congestion_control",
	"net.ipv4.tcp_mtu_probing",
	"net.ipv4.tcp_slow_start_after_idle",
	"net.ipv4.tcp_no_metrics_save",
	"net.ipv4.tcp_window_scaling",
	"net.ipv4.tcp_timestamps",
	"net.ipv4.tcp_sack",
}

func buildTunables() []interface{} {
	// Merge interesting + known into a sorted unique set
	nameSet := map[string]bool{}
	for _, n := range interestingTunables {
		nameSet[n] = true
	}
	for _, n := range knownTunables {
		nameSet[n] = true
	}
	var names []string
	for n := range nameSet {
		names = append(names, n)
	}
	sort.Strings(names)

	type item struct {
		key   string
		value string
	}
	var items []item
	for _, n := range names {
		if strings.Contains(n, "allowed_congestion_control") {
			continue
		}
		v := readProcSys(n)
		if v == "" {
			continue
		}
		short := n[4:] // strip "net."
		items = append(items, item{short, v})
	}

	// Group by first two segments
	type group struct {
		name  string
		items []map[string]interface{}
	}
	groups := map[string]*group{}
	var order []string
	for _, it := range items {
		parts := strings.SplitN(it.key, ".", 3)
		var gKey string
		if len(parts) < 2 {
			gKey = it.key
		} else {
			subParts := strings.SplitN(parts[1], "_", 2)
			gKey = parts[0] + "." + subParts[0]
		}
		g, ok := groups[gKey]
		if !ok {
			g = &group{name: gKey}
			groups[gKey] = g
			order = append(order, gKey)
		}
		g.items = append(g.items, map[string]interface{}{
			"key":   it.key,
			"value": it.value,
		})
	}
	rows := make([]interface{}, 0, len(order))
	for _, gk := range order {
		rows = append(rows, map[string]interface{}{
			"group": gk,
			"items": groups[gk].items,
		})
	}
	return rows
}

func readProcSys(name string) string {
	path := filepath.Join("/proc/sys", strings.ReplaceAll(name, ".", "/"))
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// ============================================================================
// Helpers
// ============================================================================

func atoiSafe(s string) (int, error) {
	var n int
	var negative bool
	for i, c := range s {
		if i == 0 && c == '-' {
			negative = true
			continue
		}
		if c < '0' || c > '9' {
			return 0, errBadHex
		}
		n = n*10 + int(c-'0')
	}
	if negative {
		n = -n
	}
	return n, nil
}

func parseInt64Safe(s string) (int64, error) {
	var n int64
	var negative bool
	for i, c := range s {
		if i == 0 && c == '-' {
			negative = true
			continue
		}
		if c < '0' || c > '9' {
			return 0, errBadHex
		}
		n = n*10 + int64(c-'0')
	}
	if negative {
		n = -n
	}
	return n, nil
}

// v0.5.12: buildChurnFromParsed accepts pre-parsed swaps (no re-parse)
func buildChurnFromParsed(swaps []swapRow) map[string]interface{} {
	counts := map[int64]int{}
	for _, sw := range swaps {
		counts[sw.Cookie]++
	}
	if len(counts) == 0 {
		return map[string]interface{}{"cookies": 0, "one": 0, "mid": 0, "many": 0, "max": 0}
	}
	one, mid, many := 0, 0, 0
	maxCount := 0
	for _, v := range counts {
		switch {
		case v >= 5:
			many++
		case v >= 2:
			mid++
		default:
			one++
		}
		if v > maxCount {
			maxCount = v
		}
	}
	return map[string]interface{}{"cookies": len(counts), "one": one, "mid": mid, "many": many, "max": maxCount}
}

// v0.5.12: buildDivergenceFromParsed accepts pre-parsed results (no re-parse)
func buildDivergenceFromParsed(swaps []swapRow, met map[int64][]metEntry, srate map[int64][]srateEntry) []interface{} {
	type group struct {
		total              int
		win, null, loss    int
		winS, nullS, lossS int
		winU, nullU, lossU int
	}
	keys := []string{"rate==metric", "rate!=metric", "pre-0.4.45"}
	groups := map[string]*group{}
	for _, k := range keys {
		groups[k] = &group{}
	}
	for _, sw := range swaps {
		var key string
		if sw.Mt == "" || sw.Rb == "" {
			key = "pre-0.4.45"
		} else if sw.Mt == sw.Rb {
			key = "rate==metric"
		} else {
			key = "rate!=metric"
		}
		g := groups[key]
		g.total++
		switch outcomeComposite(met, sw.Cookie, sw.Ts) {
		case "win":
			g.win++
		case "null":
			g.null++
		case "loss":
			g.loss++
		}
		switch outcomeSrate(srate, sw.Cookie, sw.Ts) {
		case "win":
			g.winS++
		case "null":
			g.nullS++
		case "loss":
			g.lossS++
		}
		switch outcomeSustained(srate, sw.Cookie, sw.Ts) {
		case "win":
			g.winU++
		case "null":
			g.nullU++
		case "loss":
			g.lossU++
		}
	}
	rows := make([]interface{}, 0, len(keys))
	for _, k := range keys {
		g := groups[k]
		cmeas := g.win + g.null + g.loss
		smeas := g.winS + g.nullS + g.lossS
		umeas := g.winU + g.nullU + g.lossU
		cp := func(x int) float64 {
			if cmeas == 0 {
				return 0
			}
			return round1(float64(x) * 100.0 / float64(cmeas))
		}
		sp := func(x int) float64 {
			if smeas == 0 {
				return 0
			}
			return round1(float64(x) * 100.0 / float64(smeas))
		}
		up := func(x int) float64 {
			if umeas == 0 {
				return 0
			}
			return round1(float64(x) * 100.0 / float64(umeas))
		}
		rows = append(rows, map[string]interface{}{
			"category": k, "measured": cmeas,
			"win_pct": cp(g.win), "null_pct": cp(g.null), "loss_pct": cp(g.loss),
			"win": g.win, "null": g.null, "loss": g.loss, "skipped": g.total - cmeas,
			"measured_srate": smeas, "win_pct_srate": sp(g.winS), "null_pct_srate": sp(g.nullS), "loss_pct_srate": sp(g.lossS),
			"win_srate": g.winS, "null_srate": g.nullS, "loss_srate": g.lossS, "skipped_srate": g.total - smeas,
			"measured_sustained": umeas, "win_pct_sustained": up(g.winU), "null_pct_sustained": up(g.nullU), "loss_pct_sustained": up(g.lossU),
			"win_sustained": g.winU, "null_sustained": g.nullU, "loss_sustained": g.lossU, "skipped_sustained": g.total - umeas,
		})
	}
	return rows
}
