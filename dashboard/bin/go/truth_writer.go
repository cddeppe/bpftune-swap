package main

// truth_writer.go — appends resolved swap outcomes to swapscore_truth.jsonl
// for the bpftune tuner.  Mirrors Python _truth_write.
//
// Format: one JSON object per line:
//   {"bucket":"82.43.0.0","tgt":"cubic","cls":"win"}
//
// bucket = /16 prefix for v4 (first two octets + .0.0), "v6:XXXXXXXX" for v6
// tgt    = to_alg NAME (e.g. "cubic", "bbr", "htcp") — v0.8.6 fix D2: was
//          previously the alg index as a string, which made the truth file
//          unusable for the ML training pipeline (indices are not stable
//          across BPF map reloads / kernel versions).
// cls    = "win"/"loss"/"null" (only written for resolved outcomes,
//          NOT for "no_post" or empty — matches Python behavior)
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
func writeTruthRow(destIPStr, toAlg, outcome string) {
	if outcome != "win" && outcome != "loss" && outcome != "null" {
		return
	}
	if destIPStr == "" || toAlg == "" {
		return
	}

	// Compute bucket: /16 for v4, v6:hex for v6
	bucket := destIPStr
	if !strings.HasPrefix(destIPStr, "v6:") {
		parts := strings.Split(destIPStr, ".")
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
	fmt.Fprintf(os.Stderr, "[truth] OK wrote %d bytes to %s\n", len(data)+1, truthFilePath)
}


// writeTruthRows writes truth file entries for all swaps with classified
// outcomes (win/loss/null). Called from collect() after writeSwapsCSV.
// Uses a separate writtenTruth dedup map. v0.8.3.
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
			writeTruthRow(destIP(sw.Dest), algName(sw.To), sw.Outcome)
			writtenTruth[sw.Cookie][sw.Ts] = true
			written++
			fmt.Fprintf(os.Stderr, "[truth] wrote: dest=%s tgt=%s cls=%s\n", destIP(sw.Dest), algName(sw.To), sw.Outcome)
		}
	}
	fmt.Fprintf(os.Stderr, "[truth] writeTruthRows: %d swaps, %d classified, %d written\n", len(swaps), classified, written)
}
