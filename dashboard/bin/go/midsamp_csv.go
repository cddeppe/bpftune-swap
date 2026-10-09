package main

// midsamp_csv.go — v0.9.7: midsamp.csv writer, reader, and backfill.
//
// The rate progression panel (buildRate) previously only read from the
// live log tail. After log rotation or restart, all midsamp data was
// lost. This file adds:
//   - writeMidsampCSV: writes midsamp events to midsamp.csv each cycle
//   - buildRateFromCSV: reads midsamp.csv and aggregates by threshold
//   - backfillMidsampFromLog: parses the log tail and writes all midsamp
//     events to midsamp.csv on first run (one-time backfill)
//   - backfillProofsFromLog: same for proofs.csv (parses log tail and
//     writes all proof events that aren't already in the CSV)

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// midsampCSVPath is set in csv_writer.go's var block (added by v0.9.7).
// writtenMidsamps is the dedup set for midsamp.csv.
var writtenMidsamps = map[int64]map[float64]bool{}

// midsampCSVHeader returns the CSV header for midsamp.csv.
// Columns: collected_ts, boot_ts, cookie, rport, alg, thr, srate
func midsampCSVHeader() string {
	return strings.Join([]string{"collected_ts", "boot_ts", "cookie", "rport", "alg", "thr", "srate"}, ",")
}

// midsampEvent is a parsed midsamp event from the log.
type midsampEvent struct {
	Ts    float64
	Cookie int64
	Rport  string
	Alg    int
	Thr    int
	Srate  int64
}

// parseMidsampEvents extracts all midsamp events from log text.
// Used by both writeMidsampCSV (normal cycle) and backfillMidsampFromLog.
func parseMidsampEvents(text string) []midsampEvent {
	rxTs := regexp.MustCompile(`^[\s.]*([\d.]+):.*midsamp`)
	rxCookie := regexp.MustCompile(`cookie=(\d+)`)
	rxRport := regexp.MustCompile(`rport=(\d+)`)
	rxAlg := regexp.MustCompile(`alg=(\d+)`)
	rxThr := regexp.MustCompile(`thr=(\d+)`)
	rxSrate := regexp.MustCompile(`srate=(\d+)`)

	var out []midsampEvent
	for _, line := range strings.Split(text, "\n") {
		if !strings.Contains(line, "midsamp") {
			continue
		}
		mTs := rxTs.FindStringSubmatch(line)
		if mTs == nil {
			continue
		}
		ts, err := strconv.ParseFloat(mTs[1], 64)
		if err != nil {
			continue
		}
		mCookie := rxCookie.FindStringSubmatch(line)
		mRport := rxRport.FindStringSubmatch(line)
		mAlg := rxAlg.FindStringSubmatch(line)
		mThr := rxThr.FindStringSubmatch(line)
		mSrate := rxSrate.FindStringSubmatch(line)
		if mCookie == nil || mRport == nil || mAlg == nil || mThr == nil || mSrate == nil {
			continue
		}
		cookie, _ := strconv.ParseInt(mCookie[1], 10, 64)
		alg, _ := strconv.Atoi(mAlg[1])
		thr, _ := strconv.Atoi(mThr[1])
		srate, _ := strconv.ParseInt(mSrate[1], 10, 64)
		out = append(out, midsampEvent{
			Ts:    ts,
			Cookie: cookie,
			Rport:  mRport[1],
			Alg:    alg,
			Thr:    thr,
			Srate:  srate,
		})
	}
	return out
}

// writeMidsampCSV writes midsamp events to midsamp.csv (deduplicated).
// Called from collect.go each cycle.
func writeMidsampCSV(events []midsampEvent, now int64) {
	if len(events) == 0 {
		return
	}
	dedupMu.Lock()
	defer dedupMu.Unlock()

	writeCSVHeaderIfEmpty(midsampCSVPath, midsampCSVHeader())
	f, err := os.OpenFile(midsampCSVPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	for _, e := range events {
		if writtenMidsamps[e.Cookie] == nil {
			writtenMidsamps[e.Cookie] = map[float64]bool{}
		}
		if writtenMidsamps[e.Cookie][e.Ts] {
			continue
		}
		writtenMidsamps[e.Cookie][e.Ts] = true

		if len(writtenMidsamps[e.Cookie]) > 1000 {
			for k := range writtenMidsamps[e.Cookie] {
				if k < e.Ts-3600 {
					delete(writtenMidsamps[e.Cookie], k)
				}
			}
		}

		row := []string{
			strconv.FormatInt(now, 10),
			strconv.FormatFloat(e.Ts, 'f', 6, 64),
			strconv.FormatInt(e.Cookie, 10),
			e.Rport,
			strconv.Itoa(e.Alg),
			strconv.Itoa(e.Thr),
			strconv.FormatInt(e.Srate, 10),
		}
		f.WriteString(strings.Join(row, ",") + "\n")
	}
}

// buildRateFromCSV reads midsamp.csv and aggregates by threshold.
// Mirrors buildRate in data_panels.go but reads from CSV instead of log.
// Skips rport=443 (origin traffic) to match buildRate's behavior.
func buildRateFromCSV() []interface{} {
	f, err := os.Open(midsampCSVPath)
	if err != nil {
		return []interface{}{}
	}
	defer f.Close()

	outMap := map[int][]int64{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 65536), 8*1024*1024)
	isHeader := true
	for scanner.Scan() {
		line := scanner.Text()
		if isHeader {
			isHeader = false
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) < 7 {
			continue
		}
		rport := fields[3]
		if rport == "443" {
			continue // skip origin traffic
		}
		thr, err := strconv.Atoi(fields[5])
		if err != nil {
			continue
		}
		srate, err := strconv.ParseInt(fields[6], 10, 64)
		if err != nil {
			continue
		}
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

// backfillMidsampFromLog parses the log tail and writes all midsamp events
// to midsamp.csv that aren't already there. Called once on startup.
func backfillMidsampFromLog(text string) {
	events := parseMidsampEvents(text)
	if len(events) == 0 {
		return
	}
	// v0.9.25: use wall-clock epoch time, NOT boot_ts (BPF ktime).
	now := time.Now().Unix()
	writeMidsampCSV(events, now)
	fmt.Fprintf(os.Stderr, "[backfill] midsamp.csv: wrote %d events from log tail\n", len(events))
}

// backfillProofsFromLog parses the log tail and writes all proof events
// to proofs.csv that aren't already there. Called once on startup.
func backfillProofsFromLog(text string, cdest map[string]cdestEntry) {
	allProofs := buildRecentProofRows(text, cdest)
	if len(allProofs) == 0 {
		return
	}
	// v0.9.21: use wall-clock epoch time, NOT boot_ts (BPF ktime).
	// The old code set now = boot_ts (e.g., 734) which was written
	// as collected_ts in the CSV. This caused the frontend's epoch_ts
	// age calculation to show "20734d" instead of the correct age.
	now := time.Now().Unix()
	writeProofsCSVFromInterface(allProofs, now)
	fmt.Fprintf(os.Stderr, "[backfill] proofs.csv: wrote %d proofs from log tail\n", len(allProofs))
}

// backfillDone prevents repeated backfill on every collect cycle.
var backfillDone sync.Once

// v0.9.9: lazy-load midsamp.csv — cache the parsed result and only re-read
// when the file's mtime changes. Most cycles the file hasn't been written
// to yet (writes happen at the end of collect()).
var (
        rateCSVCache     []interface{}
        rateCSVCacheMtime int64
)

func buildRateFromCSVCached() []interface{} {
        fi, err := os.Stat(midsampCSVPath)
        if err != nil {
                return []interface{}{}
        }
        mtime := fi.ModTime().Unix()
        if rateCSVCache != nil && mtime == rateCSVCacheMtime {
                return rateCSVCache
        }
        rateCSVCache = buildRateFromCSV()
        rateCSVCacheMtime = mtime
        return rateCSVCache
}
