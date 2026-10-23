package main

import "time"

type CollectorMode struct {
	Name            string
	CollectInterval time.Duration
	LogTailBytes    int64
	CSVFallback     bool
	ProofMergeCSV   bool
	BackfillOnStart bool
	CookieDestSave  int
	SinglePassLog   bool
	// v0.9.33: throttle CSV writes to every Nth cycle.
	// 1 = every cycle (30s), 2 = every 2nd cycle (60s), etc.
	CSVWriteEveryN int
	// v0.9.33: skip renderToDisk when no new swaps since last render.
	SkipRenderWhenIdle bool
	// v0.9.33: cache readBPFMap output when entry count unchanged.
	CacheBPFMap bool
}

var collectorMode = CollectorMode{
	Name: "normal", CollectInterval: 30 * time.Second, LogTailBytes: 8_000_000,
	CSVFallback: true, ProofMergeCSV: true, BackfillOnStart: true,
	CookieDestSave: 5, SinglePassLog: true,
	CSVWriteEveryN: 1, SkipRenderWhenIdle: false, CacheBPFMap: true,
}

var cycleCount int

func parseCollectorMode(mode string) CollectorMode {
	switch mode {
	case "lean":
		return CollectorMode{"lean", 60 * time.Second, 4_000_000, false, false, false, 10, true, 1, false, false}
	case "debug":
		return CollectorMode{"debug", 30 * time.Second, 16_000_000, true, true, true, 1, false, 1, false, false}
	case "normal-light":
		// v0.9.83: reduced log tail from 8MB to 2MB.
		// The 8MB tail was overkill — the user's log had only ~180KB
		// of events (1513 lines × ~120 bytes). 2MB still covers
		// ~17K lines = 100+ collect cycles of events, which is way
		// more than the 30s cycle needs. Saves ~75% of log I/O +
		// parsing per cycle.
		// v0.9.33: normal mode with reduced CPU/memory.
		// Keeps CSV fallback + 30s interval (dashboard stays fresh).
		// Throttles CSV writes to every 2nd cycle (60s).
		// Skips renderToDisk when no new swaps.
		// Caches BPF map reads when entry count unchanged.
		return CollectorMode{
			"normal-light", 30 * time.Second, 4_000_000,
			true, true, true, 5, true,
			2, true, true,
		}
	default:
		// v0.9.36: normal mode now uses 8MB log tail (was 16MB) and
		// enables BPF map caching. The 16MB tail was causing high
		// iowait on 1GB RAM hosts. 8MB still covers ~5min of events
		// which is enough for the 1h chart + proof enrichment.
		return CollectorMode{
			"normal", 30 * time.Second, 8_000_000,
			true, true, true, 5, true,
			1, false, true,
		}
	}
}
