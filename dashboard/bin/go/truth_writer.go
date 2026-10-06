package main

// truth_writer.go — appends resolved swap outcomes to swapscore_truth.jsonl
// for the bpftune tuner.  Mirrors Python _truth_write.
//
// Format: one JSON object per line:
//   {"bucket":"82.43.0.0","tgt":"cubic","cls":"win"}
//
// bucket = /16 prefix for v4 (first two octets + .0.0), "v6:XXXXXXXX" for v6
//          v0.9.0: now also accepts full /64 IPv6 form "xxxx:xxxx:yyyy:yyyy::"
//                  and folds it to /32 (or whatever prefix6 is configured).
// tgt    = to_alg NAME (e.g. "cubic", "bbr", "htcp") — v0.8.6 fix D2: was
//          previously the alg index as a string, which made the truth file
//          unusable for the ML training pipeline (indices are not stable
//          across BPF map reloads / kernel versions).
// cls    = "win"/"loss"/"null" (only written for resolved outcomes,
//          NOT for "no_post" or empty — matches Python behavior)
//
// v0.9.0: writeTruthRow now takes the fully-resolved dest string
// (sw.DestResolved) instead of just the v4 dest field.  This means:
//   - IPv6 swaps (where sw.Dest == "0") now actually get truth rows
//     written — previously destIP("0") returned "" and writeTruthRow
//     bailed out, so the ML training file was 100% IPv4-only.
//   - The bucket key for IPv6 swaps is the masked /prefix6 form
//     (e.g. "2606:1a40::"), matching what the BPF map uses.
//
// Called from writeSwapsCSV after the dedup check passes (so each swap
// only gets one truth entry, not one per cycle).

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

var truthFilePath = "/var/lib/bpftune/history/swapscore_truth.jsonl"

// writeTruthRow appends a truth entry for a resolved swap.
// Only writes if outcome is win/loss/null (not "no_post" or empty).
// Mirrors Python _truth_write.
//
// v0.9.0: destStr is now the fully-resolved dest string (sw.DestResolved)
// rather than just the v4 dest field.  This may be:
//   - "1.2.3.4" (v4 dotted)
//   - "v6:26061a40" (v6 32-bit hex form, from swap row that lacks dest6b)
//   - "2606:1a40:abcd:ef01::" (full /64 IPv6 form, from cdest merge)
//   - "" (no dest info at all — bail)
func writeTruthRow(destStrArg, toAlg, outcome string) {
	if outcome != "win" && outcome != "loss" && outcome != "null" {
		return
	}
	if destStrArg == "" || toAlg == "" {
		return
	}

	// Compute the bucket key.
	//   v4:    /16 prefix (first two octets + .0.0)
	//   v6:    v6:hex form (the cdest form) OR standard IPv6 form,
	//          masked to /prefix6 (default /32) so the bucket key
	//          matches what the BPF map uses.
	var bucket string
	if strings.HasPrefix(destStrArg, "v6:") {
		// "v6:26061a40" form — already 32 bits, keep as-is so truth
		// file matches the form the tuner reads from cdest.
		bucket = destStrArg
	} else if strings.Contains(destStrArg, ":") {
		// Standard IPv6 form (e.g. "2606:1a40:abcd:ef01::").
		// Mask to /prefix6 (default /32) so the bucket key matches
		// the BPF map's masked form.
		masked := canonBucketWithPrefix(destStrArg, prefix4Value(), prefix6Value())
		if masked == "" {
			return
		}
		bucket = masked
	} else {
		// v4 dotted form — fold to /16.
		parts := strings.Split(destStrArg, ".")
		if len(parts) >= 2 {
			bucket = parts[0] + "." + parts[1] + ".0.0"
		} else {
			return
		}
	}

	rec := map[string]string{
		"bucket": bucket,
		"tgt":    toAlg,
		"cls":    outcome,
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return
	}

	f, err := os.OpenFile(truthFilePath,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[truth] ERROR OpenFile: %v (path=%s)\n", err, truthFilePath)
		return
	}
	defer f.Close()
	f.Write(data)
	f.Write([]byte("\n"))
	fmt.Fprintf(os.Stderr, "[truth] OK wrote %d bytes to %s (bucket=%s)\n", len(data)+1, truthFilePath, bucket)
}

// writeTruthRows writes truth file entries for all swaps with classified
// outcomes (win/loss/null). v0.8.3 introduced this as a separate function
// with its own dedup map, but v0.8.7 removed the call from collect.go
// because writeSwapsCSV already writes truth rows inline (with its own
// dedup) — calling writeTruthRows separately caused duplicate writes.
//
// v0.9.0: this function is kept for backward compat with any external
// scripts that import it, but is NOT called from the collector.  It now
// uses sw.DestResolved instead of destIP(sw.Dest) for IPv6 support.
func writeTruthRows(swaps []swapRow) {
	dedupMu.Lock()
	defer dedupMu.Unlock()
	classified := 0
	written := 0
	for _, sw := range swaps {
		if sw.Outcome != "win" && sw.Outcome != "loss" && sw.Outcome != "null" {
			continue
		}
		if writtenTruth[sw.Cookie] == nil {
			writtenTruth[sw.Cookie] = map[float64]bool{}
		}
		classified++
		if !writtenTruth[sw.Cookie][sw.Ts] {
			writeTruthRow(sw.DestResolved, algName(sw.To), sw.Outcome)
			writtenTruth[sw.Cookie][sw.Ts] = true
			written++
			fmt.Fprintf(os.Stderr, "[truth] wrote: dest=%s tgt=%s cls=%s\n", sw.DestResolved, algName(sw.To), sw.Outcome)
		}
	}
	fmt.Fprintf(os.Stderr, "[truth] writeTruthRows: %d swaps, %d classified, %d written\n", len(swaps), classified, written)
}
