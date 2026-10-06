package main

// csv_rotate.go — prevents history CSVs from growing endlessly.
// Called daily from renderSlowToDisk (4am).
//
// v0.9.6: TIERED RETENTION for buckets.v2.csv:
//   - 0-7 days:   full resolution (every 30s row kept as-is)
//   - 7-30 days:  downsampled to 5min bins (keep last row per bucket per 5min)
//   - 30-90 days: downsampled to 1h bins (keep last row per bucket per 1h)
//   - >90 days:   dropped
//
// This cuts buckets.v2.csv from ~420MB to ~45MB while keeping enough
// resolution for all chart ranges:
//   - 1h chart:  reads from ring buffer (live, unaffected)
//   - 24h chart: reads last 24h from CSV (all within 7d, full resolution)
//   - 7d chart:  reads last 7d from CSV (full resolution, binned to 1h by reader)
//   - 30d chart: reads last 30d from CSV (7d full + 23d at 5min, binned to 1h)
//   - all chart: reads last 90d from CSV (7d full + 23d at 5min + 60d at 1h, binned to 24h)
//
// swaps.csv, srate.csv, proofs.csv: kept at full resolution for 90 days
// (they’re much smaller — swaps ~50MB, srate ~50MB, proofs ~10MB at 90d).

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// tieredRetentionConfig defines the retention tiers for a CSV file.
// Each tier specifies an age boundary and a bin size (in seconds).
// Rows older than the last tier’s boundary are dropped.
type tieredRetentionConfig struct {
	tiers []retentionTier
}

type retentionTier struct {
	maxAgeDays int // rows older than this are in the next tier (or dropped if last)
	binSeconds int64 // 0 = keep full resolution (no downsampling)
}

// bucketsTieredConfig: 7d full, 30d at 5min, 90d at 1h
var bucketsTieredConfig = tieredRetentionConfig{
	tiers: []retentionTier{
		{maxAgeDays: 7, binSeconds: 0},     // 0-7d: full resolution
		{maxAgeDays: 30, binSeconds: 300},  // 7-30d: 5min bins
		{maxAgeDays: 90, binSeconds: 3600}, // 30-90d: 1h bins
	},
}

// rotateCSVIfLarge checks if a CSV file exceeds maxSizeMB. If so,
// it trims to keep only rows from the last maxDays. Writes to a temp
// file, then atomically replaces the original.
//
// This is the SIMPLE (non-tiered) rotation used for swaps.csv, srate.csv,
// proofs.csv. buckets.v2.csv uses rotateCSVTiered instead.
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
	// D1-fix: 8MB max line size
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

	// D1-fix: check scanner error BEFORE renaming
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

// rotateCSVTiered performs tiered rotation on a CSV file.
// Each row is assigned to a tier based on its age (collected_ts).
// Within each tier, rows are grouped by (bucket_addr, time_bin) and
// only the LAST row in each group is kept. This dramatically reduces
// file size while preserving enough data for charts.
//
// CSV format: collected_ts (col 0), addr (col 1), ... (rest of row)
// The addr column is used as the grouping key so each bucket gets its
// own downsampled representation.
func rotateCSVTiered(path string, cfg tieredRetentionConfig, maxSizeMB int64) {
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	maxSize := maxSizeMB * 1024 * 1024
	if info.Size() < maxSize {
		return // under threshold, no rotation needed
	}

	now := time.Now().Unix()

	// Read all rows, classifying each into a tier.
	// tierBuckets[tierIdx][binKey] = line  (keep last line per bin)
	type binKey struct {
		addr string
		bin  int64
	}
	tierBuckets := make([]map[binKey]string, len(cfg.tiers))
	for i := range tierBuckets {
		tierBuckets[i] = make(map[binKey]string)
	}
	var header string

	in, err := os.Open(path)
	if err != nil {
		return
	}
	defer in.Close()

	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024) // 8MB max line

	totalRows := 0
	isHeader := true
	for scanner.Scan() {
		line := scanner.Text()
		if isHeader {
			header = line
			isHeader = false
			continue
		}
		totalRows++

		// Parse collected_ts (col 0) and addr (col 1)
		fields := strings.SplitN(line, ",", 3)
		if len(fields) < 2 {
			continue
		}
		ts, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil {
			continue
		}
		addr := fields[1]

		age := now - ts
		if age < 0 {
			age = 0 // clock skew guard
		}

		// Find which tier this row belongs to
		tierIdx := -1
		ageDays := age / 86400
		for i, t := range cfg.tiers {
			if ageDays < int64(t.maxAgeDays) {
				tierIdx = i
				break
			}
		}
		if tierIdx < 0 {
			continue // older than last tier — drop
		}

		tier := cfg.tiers[tierIdx]
		if tier.binSeconds == 0 {
			// Full resolution — keep every row. Use a unique key.
			// We use the timestamp itself as part of the key.
			tierBuckets[tierIdx][binKey{addr: addr, bin: ts}] = line
		} else {
			// Downsample — keep last row per (addr, time_bin)
			bin := ts / tier.binSeconds
			tierBuckets[tierIdx][binKey{addr: addr, bin: bin}] = line
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "csv_rotate: ABORT %s: scanner error: %v (production file untouched)\n", path, err)
		return
	}

	// Collect all kept rows, sorted by timestamp
	type keptRow struct {
		ts   int64
		line string
	}
	var allKept []keptRow
	for tierIdx, buckets := range tierBuckets {
		for _, line := range buckets {
			// Re-parse ts for sorting (we stored the full line)
			commaIdx := strings.IndexByte(line, ',')
			if commaIdx < 0 {
				continue
			}
			ts, _ := strconv.ParseInt(line[:commaIdx], 10, 64)
			allKept = append(allKept, keptRow{ts: ts, line: line})
		}
		_ = tierIdx
	}
	sort.Slice(allKept, func(i, j int) bool {
		return allKept[i].ts < allKept[j].ts
	})

	// Write to temp file
	tmpPath := path + ".rotating"
	out, err := os.Create(tmpPath)
	if err != nil {
		return
	}
	writer := bufio.NewWriter(out)

	if header != "" {
		writer.WriteString(header + "\n")
	}
	kept := 0
	for _, r := range allKept {
		writer.WriteString(r.line + "\n")
		kept++
	}
	writer.Flush()
	out.Close()

	skipped := totalRows - kept
	if err := os.Rename(tmpPath, path); err != nil {
		os.Stderr.WriteString("csv_rotate: rename failed for " + path + ": " + err.Error() + "\n")
		os.Remove(tmpPath)
		return
	}

	fmt.Fprintf(os.Stderr, "csv_rotate: %s tiered rotation: %d → %d rows (dropped %d), tiers: 7d full / 30d 5min / 90d 1h\n",
		path, totalRows, kept, skipped)
}

// rotateAllCSVs is called daily from renderSlowToDisk.
// Prevents endless growth of history CSVs.
func rotateAllCSVs() {
	// buckets.v2.csv: tiered (7d full / 30d 5min / 90d 1h), 200MB threshold
	rotateCSVTiered(bucketsCSVPath, bucketsTieredConfig, 200)
	// swaps.csv: simple 90d retention, 50MB threshold
	rotateCSVIfLarge(swapsCSVPath, 90, 50)
	// srate.csv: simple 90d retention, 50MB threshold
	rotateCSVIfLarge(srateCSVPath, 90, 50)
	// proofs.csv: simple 90d retention, 20MB threshold
	rotateCSVIfLarge(proofsCSVPath, 90, 20)
}
