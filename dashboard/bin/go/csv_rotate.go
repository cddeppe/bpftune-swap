package main

// csv_rotate.go — prevents history CSVs from growing endlessly.
// Called daily from renderSlowToDisk (4am). When a CSV exceeds its
// size threshold, trims to keep only rows from the last 90 days.
//
// Without this, buckets.v2.csv grows ~4.6MB/day (8 buckets × 2880
// cycles/day × ~200 bytes/row). Over a year = 1.7GB. The 90-day
// retention keeps it under ~420MB, and the "all" chart range (90 days,
// 24h bins) only needs the last 90 days anyway.

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// rotateCSVIfLarge checks if a CSV file exceeds maxSizeMB. If so,
// it streams the file, keeping only rows where collected_ts (column 0)
// is within the last maxDays. Writes to a temp file, then atomically
// replaces the original.
func rotateCSVIfLarge(path string, maxDays int, maxSizeMB int64) {
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	maxSize := maxSizeMB * 1024 * 1024
	if info.Size() < maxSize {
		return // under threshold, no rotation needed
	}

	cutoff := time.Now().Unix() - int64(maxDays)*86400

	in, err := os.Open(path)
	if err != nil {
		return
	}
	defer in.Close()

	tmpPath := path + ".rotating"
	out, err := os.Create(tmpPath)
	if err != nil {
		return
	}

	writer := bufio.NewWriter(out)
	scanner := bufio.NewScanner(in)
	// D1-fix: bump max line size from 1MB to 8MB. The old 1MB cap would
	// silently error on any line exceeding it, and since sc.Err() was
	// never checked, the rotation would complete with a truncated tmp
	// file and atomically replace the production CSV — permanent data loss.
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	kept := 0
	skipped := 0
	isHeader := true

	for scanner.Scan() {
		line := scanner.Text()
		if isHeader {
			writer.WriteString(line + "\n")
			isHeader = false
			continue
		}
		commaIdx := strings.IndexByte(line, ',')
		if commaIdx < 0 {
			continue
		}
		ts, err := strconv.ParseInt(line[:commaIdx], 10, 64)
		if err != nil {
			continue
		}
		if ts >= cutoff {
			writer.WriteString(line + "\n")
			kept++
		} else {
			skipped++
		}
	}

	// D1-fix: check scanner error BEFORE renaming. If the scanner errored
	// (e.g., a line exceeded the 8MB buffer, or a read I/O error), abort
	// the rotation — do NOT replace the production file with a truncated
	// tmp file. The old code never checked this, causing permanent data
	// loss on any over-long line.
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "csv_rotate: ABORT %s: scanner error: %v (production file untouched)\n", path, err)
		writer.Flush()
		out.Close()
		in.Close()
		os.Remove(tmpPath)
		return
	}

	writer.Flush()
	out.Close()
	in.Close()

	if err := os.Rename(tmpPath, path); err != nil {
		os.Stderr.WriteString("csv_rotate: rename failed for " + path + ": " + err.Error() + "\n")
		os.Remove(tmpPath)
		return
	}

	os.Stderr.WriteString("csv_rotate: " + path + " trimmed " +
		strconv.Itoa(skipped) + " old rows, kept " + strconv.Itoa(kept) +
		" (" + strconv.Itoa(maxDays) + "d retention)\n")
}

// rotateAllCSVs is called daily from renderSlowToDisk.
// Prevents endless growth of history CSVs.
func rotateAllCSVs() {
	rotateCSVIfLarge(bucketsCSVPath, 90, 200) // 200MB threshold
	rotateCSVIfLarge(swapsCSVPath, 90, 50)    // 50MB threshold
	rotateCSVIfLarge(srateCSVPath, 90, 50)    // 50MB threshold
}
