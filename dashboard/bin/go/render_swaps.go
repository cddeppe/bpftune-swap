package main

// render_swaps.go — historical swap outcome trends from swaps.csv + srate.csv.
// Mirrors Python bpftune-render.py:emit_swaps + _attach_sustained_outcomes + wilson.
//
// Replaces the old renderSwapsToDisk which only used the current cycle's
// swap_outcomes (a single data point). Now reads historical CSV data and
// builds time-binned win/loss trends with Wilson confidence intervals.
//
// Output structure (per timerange):
//   {
//     "ts": [...],              // bin centers
//     "swaps": [...],           // total swaps per bin
//     "d0_rate": [...],         // composite win rate (non-diverging)
//     "d0_lo": [...], "d0_hi": [...],  // Wilson confidence interval
//     "d0_n": [...],            // sample count
//     "d0_rate_sustained": [...],      // sustained win rate
//     "d0_lo_sustained": [...], "d0_hi_sustained": [...],
//     "d0_n_sustained": [...],
//     "d1_rate": [...], ...     // same for diverging (d=1)
//   }

import (
	"encoding/csv"
	"math"
	"os"
	"sort"
	"strconv"
)

// swapCSVRow is a parsed row from swaps.csv.
type swapCSVRow struct {
	CollectedTs      int64 // wall-clock epoch (column 0 of swaps.csv)
	BootTs           float64
	Cookie           int64
	FromAlg          string
	ToAlg            string
	Diverges         bool
	Outcome          string // composite outcome: "win"/"loss"/"null"/"no_post"/""
	Dest             string
	SrateBefore      string // pre-swap srate (as string)
	Direction        string
	Rport            string
	OutcomeSustained string // recomputed by attachSustainedOutcomes
}

// srateCSVRow is a parsed row from srate.csv.
type srateCSVRow struct {
	BootTs float64
	Cookie int64
	Alg    int
	Srate  int64
}

// wilson computes the Wilson score interval for a binomial proportion.
// wins = number of successes, total = number of trials.
// Returns (lower, upper) bounds. z=1.96 for 95% confidence.
// Mirrors Python bpftune-render.py:wilson.
func wilson(wins, total int) (float64, float64) {
	if total == 0 {
		return 0.0, 1.0
	}
	z := 1.96
	p := float64(wins) / float64(total)
	n := float64(total)
	denom := 1 + z*z/n
	center := (p + z*z/(2*n)) / denom
	spread := z * math.Sqrt(p*(1-p)/n+z*z/(4*n*n)) / denom
	lo := center - spread
	hi := center + spread
	if lo < 0 {
		lo = 0
	}
	if hi > 1 {
		hi = 1
	}
	return lo, hi
}

// readSwapsCSVTail reads the last maxBytes of swaps.csv and parses rows.
// Mirrors Python load_csv with bounded memory.
func readSwapsCSVTail(maxBytes int64) []swapCSVRow {
	f, err := os.Open(swapsCSVPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	info, _ := f.Stat()
	if info.Size() > maxBytes {
		f.Seek(info.Size()-maxBytes, 0)
		// Skip partial first line
		buf := make([]byte, 1)
		for {
			_, err := f.Read(buf)
			if err != nil || buf[0] == '\n' {
				break
			}
		}
	}

	reader := csv.NewReader(f)
	reader.FieldsPerRecord = -1 // allow variable fields
	_, _ = reader.Read()        // skip header

	var rows []swapCSVRow
	for {
		rec, err := reader.Read()
		if err != nil {
			break
		}
		if len(rec) < 18 {
			continue
		}
		ct, _ := strconv.ParseInt(rec[0], 10, 64) // collected_ts (wall-clock epoch)
		bt, _ := strconv.ParseFloat(rec[1], 64)
		cookie, _ := strconv.ParseInt(rec[2], 10, 64)
		diverges := rec[8] == "1"
		row := swapCSVRow{
			CollectedTs: ct,
			BootTs:      bt,
			Cookie:      cookie,
			FromAlg:     rec[3],
			ToAlg:       rec[4],
			Diverges:    diverges,
			Outcome:     rec[9],
			Dest:        rec[11],
			SrateBefore: rec[15],
			Direction:   rec[16],
			Rport:       rec[17],
		}
		rows = append(rows, row)
	}
	return rows
}

// readSrateCSVTail reads the last maxBytes of srate.csv and parses rows.
func readSrateCSVTail(maxBytes int64) []srateCSVRow {
	f, err := os.Open(srateCSVPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	info, _ := f.Stat()
	if info.Size() > maxBytes {
		f.Seek(info.Size()-maxBytes, 0)
		buf := make([]byte, 1)
		for {
			_, err := f.Read(buf)
			if err != nil || buf[0] == '\n' {
				break
			}
		}
	}

	reader := csv.NewReader(f)
	reader.FieldsPerRecord = -1
	_, _ = reader.Read()

	var rows []srateCSVRow
	for {
		rec, err := reader.Read()
		if err != nil {
			break
		}
		if len(rec) < 5 {
			continue
		}
		bt, _ := strconv.ParseFloat(rec[1], 64)
		cookie, _ := strconv.ParseInt(rec[2], 10, 64)
		alg, _ := strconv.Atoi(rec[3])
		sr, _ := strconv.ParseInt(rec[4], 10, 64)
		rows = append(rows, srateCSVRow{
			BootTs: bt,
			Cookie: cookie,
			Alg:    alg,
			Srate:  sr,
		})
	}
	return rows
}

// attachSustainedOutcomes recomputes sustained outcomes from srate.csv data.
// Mirrors Python _attach_sustained_outcomes.
// For each swap: uses srate_before as pre, finds srates in [T+60, T+300],
// computes median, then ratio → win/loss/null.
func attachSustainedOutcomes(swaps []swapCSVRow, srates []srateCSVRow) {
	// Build cookie → sorted srate list
	byCookie := map[int64][]srateCSVRow{}
	for _, s := range srates {
		byCookie[s.Cookie] = append(byCookie[s.Cookie], s)
	}
	for c := range byCookie {
		sort.Slice(byCookie[c], func(i, j int) bool {
			return byCookie[c][i].BootTs < byCookie[c][j].BootTs
		})
	}

	for i := range swaps {
		sw := &swaps[i]
		sw.OutcomeSustained = ""

		sb, err := strconv.ParseFloat(sw.SrateBefore, 64)
		if err != nil || sb <= 0 {
			continue
		}

		lst := byCookie[sw.Cookie]
		if len(lst) == 0 {
			continue
		}

		// Find srates in [T+60, T+300]
		var post []float64
		for _, s := range lst {
			delta := s.BootTs - sw.BootTs
			if delta >= 60.0 && delta <= 300.0 {
				post = append(post, float64(s.Srate))
			}
		}
		if len(post) == 0 {
			continue
		}

		// Median
		sort.Float64s(post)
		var pm float64
		n := len(post)
		if n%2 == 1 {
			pm = post[n/2]
		} else {
			pm = (post[n/2-1] + post[n/2]) / 2.0
		}
		if pm <= 0 {
			continue
		}

		ratio := pm / sb
		switch {
		case ratio >= 1.1:
			sw.OutcomeSustained = "win"
		case ratio <= 0.9:
			sw.OutcomeSustained = "loss"
		default:
			sw.OutcomeSustained = "null"
		}
	}
}

// renderSwapsFromCSV reads swaps.csv + srate.csv, recomputes sustained
// outcomes, and writes swaps.json with time-binned win/loss trends.
// Replaces the old renderSwapsToDisk that only used current cycle data.
// Mirrors Python emit_swaps.
func renderSwapsFromCSV(nowEpoch int64) {
	// Read last 16MB of swaps.csv (covers ~7d of swaps at ~1/min)
	swaps := readSwapsCSVTail(16_000_000)
	if len(swaps) == 0 {
		writeJSONToDisk("swaps.json", map[string]interface{}{})
		return
	}

	// Read last 8MB of srate.csv (covers ~7d of srate events)
	srates := readSrateCSVTail(8_000_000)

	// Recompute sustained outcomes
	attachSustainedOutcomes(swaps, srates)

	doc := map[string]interface{}{}
	for rngName, rngCfg := range ranges {
		span, _ := rngCfg[0].(int)
		width, _ := rngCfg[1].(int)
		if width == 0 {
			width = 60
		}

		// Bin accumulator: binIdx → direction → {cw, cl, uu, ul}
		type binAcc struct {
			cw, cl, uu, ul int
		}
		bins := map[int64]map[int]*binAcc{}
		for _, sw := range swaps {
			// Convert boot_ts to epoch
			epochTs := float64(sw.CollectedTs)
			if span > 0 {
				cutoff := float64(nowEpoch) - float64(span)
				if epochTs < cutoff {
					continue
				}
			}
			binIdx := int64(epochTs / float64(width))
			d := 0
			if sw.Diverges {
				d = 1
			}
			if bins[binIdx] == nil {
				bins[binIdx] = map[int]*binAcc{}
			}
			if bins[binIdx][d] == nil {
				bins[binIdx][d] = &binAcc{}
			}
			acc := bins[binIdx][d]
			o := sw.Outcome
			if o == "win" {
				acc.cw++
			} else if o == "loss" {
				acc.cl++
			}
			o2 := sw.OutcomeSustained
			if o2 == "win" {
				acc.uu++
			} else if o2 == "loss" {
				acc.ul++
			}
		}

		// Sort bin indices
		var binIdxs []int64
		for bi := range bins {
			binIdxs = append(binIdxs, bi)
		}
		sort.Slice(binIdxs, func(i, j int) bool { return binIdxs[i] < binIdxs[j] })

		// Build output arrays
		node := map[string]interface{}{}
		tsArr := make([]interface{}, len(binIdxs))
		swapsArr := make([]interface{}, len(binIdxs))
		d0Rate := make([]interface{}, len(binIdxs))
		d0Lo := make([]interface{}, len(binIdxs))
		d0Hi := make([]interface{}, len(binIdxs))
		d0N := make([]interface{}, len(binIdxs))
		d0RateSust := make([]interface{}, len(binIdxs))
		d0LoSust := make([]interface{}, len(binIdxs))
		d0HiSust := make([]interface{}, len(binIdxs))
		d0NSust := make([]interface{}, len(binIdxs))
		d1Rate := make([]interface{}, len(binIdxs))
		d1Lo := make([]interface{}, len(binIdxs))
		d1Hi := make([]interface{}, len(binIdxs))
		d1N := make([]interface{}, len(binIdxs))
		d1RateSust := make([]interface{}, len(binIdxs))
		d1LoSust := make([]interface{}, len(binIdxs))
		d1HiSust := make([]interface{}, len(binIdxs))
		d1NSust := make([]interface{}, len(binIdxs))

		for i, bi := range binIdxs {
			tsArr[i] = bi*int64(width) + int64(width)/2
			bin := bins[bi]
			total := 0
			for d := 0; d <= 1; d++ {
				acc := bin[d]
				if acc == nil {
					acc = &binAcc{}
				}
				cw, cl := acc.cw, acc.cl
				cn := cw + cl
				total += cn
				lo, hi := wilson(cw, cn)
				var rate interface{}
				if cn > 0 {
					rate = float64(cw) / float64(cn)
				}
				uw, ul := acc.uu, acc.ul
				un := uw + ul
				lo2, hi2 := wilson(uw, un)
				var rateSust interface{}
				if un > 0 {
					rateSust = float64(uw) / float64(un)
				}
				if d == 0 {
					d0Rate[i] = rate
					d0Lo[i] = lo
					d0Hi[i] = hi
					d0N[i] = cn
					d0RateSust[i] = rateSust
					d0LoSust[i] = lo2
					d0HiSust[i] = hi2
					d0NSust[i] = un
				} else {
					d1Rate[i] = rate
					d1Lo[i] = lo
					d1Hi[i] = hi
					d1N[i] = cn
					d1RateSust[i] = rateSust
					d1LoSust[i] = lo2
					d1HiSust[i] = hi2
					d1NSust[i] = un
				}
			}
			swapsArr[i] = total
		}

		node["ts"] = tsArr
		node["swaps"] = swapsArr
		node["d0_rate"] = d0Rate
		node["d0_lo"] = d0Lo
		node["d0_hi"] = d0Hi
		node["d0_n"] = d0N
		node["d0_rate_sustained"] = d0RateSust
		node["d0_lo_sustained"] = d0LoSust
		node["d0_hi_sustained"] = d0HiSust
		node["d0_n_sustained"] = d0NSust
		node["d1_rate"] = d1Rate
		node["d1_lo"] = d1Lo
		node["d1_hi"] = d1Hi
		node["d1_n"] = d1N
		node["d1_rate_sustained"] = d1RateSust
		node["d1_lo_sustained"] = d1LoSust
		node["d1_hi_sustained"] = d1HiSust
		node["d1_n_sustained"] = d1NSust

		doc[rngName] = node
	}
	writeJSONToDisk("swaps.json", doc)
}
