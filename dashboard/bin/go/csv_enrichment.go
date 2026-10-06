package main

// csv_enrichment.go — fills in Outcome/SrateBefore/Direction/Rport on
// swapRow before CSV write.  Mirrors Python _resolve_pending enrichment.
//
// Called from collect.go after parseSwapsMetsSrates, before writeSwapsCSV.
// Modifies swaps in-place.
//
// Outcome logic (mirrors Python _resolve_pending):
//   - If outcomeSustained returns win/loss/null → use that
//   - If empty, fallback to outcomeComposite (immediate outcome)
//   - If still empty and swap is >300s old → "no_post"
//   - If still empty and <300s old → "" (will be filled on a later cycle)
//
// Direction logic:
//   - Find first met event 3-300s after swap → use its rport
//   - rport=="443" → "origin", else "client"
//
// SrateBefore:
//   - Last srate event before the swap's timestamp

import (
	"strconv"
)

// enrichSwapsForCSV fills in enriched fields on each swapRow.
// Called from collect.go before writeSwapsCSV.
//
// v0.9.0: now also fills in DestResolved (the fully-resolved display
// string for the dest, including v6b for /64 IPv6).  This is used by
// writeTruthRow so IPv6 swaps get a non-empty bucket key in the truth
// file (previously they were dropped because destIP(sw.Dest) was ""
// for IPv6 connections where sw.Dest is "0").
func enrichSwapsForCSV(swaps []swapRow, met map[int64][]metEntry, srate map[int64][]srateEntry, cdest map[string]cdestEntry) {
	if len(swaps) == 0 {
		return
	}

	// Compute newest timestamp across all swaps and srate events
	// (used to determine if a swap's 300s outcome window has expired)
	newestTs := 0.0
	for _, sw := range swaps {
		if sw.Ts > newestTs {
			newestTs = sw.Ts
		}
	}
	for _, entries := range srate {
		for _, e := range entries {
			if e.Ts > newestTs {
				newestTs = e.Ts
			}
		}
	}

	for i := range swaps {
		sw := &swaps[i]

		// 1. Outcome: sustained first, then composite fallback, then no_post
		o3 := outcomeSustained(srate, sw.Cookie, sw.Ts)
		if o3 == "" {
			// Fallback to composite (immediate outcome)
			o3 = outcomeComposite(met, sw.Cookie, sw.Ts)
		}
		if o3 == "" && newestTs-sw.Ts > 300 {
			o3 = "no_post"
		}
		sw.Outcome = o3

		// 2. SrateBefore: last srate event before the swap
		for _, e := range srate[sw.Cookie] {
			if e.Ts < sw.Ts {
				sw.SrateBefore = strconv.FormatInt(e.Srate, 10)
			}
		}

		// 3. Direction + Rport: first met event 3-300s after swap
		for _, e := range met[sw.Cookie] {
			delta := e.Ts - sw.Ts
			if delta >= 3.0 && delta <= 300.0 {
				sw.Rport = e.Rport
				if e.Rport == "443" {
					sw.Direction = "origin"
				} else {
					sw.Direction = "client"
				}
				break
			}
		}

		// 4. DestResolved: prefer swap row's own dest fields, fall back
		// to cdest (which carries dest6b from prior estab events).
		v4, v6, v6b := sw.Dest, sw.Dest6, sw.Dest6b
		if v4 == "" && v6 == "" && v6b == "" {
			if d, ok := cdest[strconv.FormatInt(sw.Cookie, 10)]; ok {
				v4, v6, v6b = d[0], d[1], d[2]
			}
		}
		sw.DestResolved = destStr(v4, v6, v6b)
	}
}
