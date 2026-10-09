package main

import "time"

type CollectorMode struct {
        Name             string
        CollectInterval  time.Duration
        LogTailBytes     int64
        CSVFallback      bool
        ProofMergeCSV    bool
        BackfillOnStart  bool
        CookieDestSave   int
        SinglePassLog    bool
        // v0.9.33: throttle CSV writes to every Nth cycle.
        // 1 = every cycle (30s), 2 = every 2nd cycle (60s), etc.
        CSVWriteEveryN int
        // v0.9.33: skip renderToDisk when no new swaps since last render.
        SkipRenderWhenIdle bool
        // v0.9.33: cache readBPFMap output when entry count unchanged.
        CacheBPFMap bool
}

var collectorMode = CollectorMode{
        Name: "normal", CollectInterval: 30 * time.Second, LogTailBytes: 16_000_000,
        CSVFallback: true, ProofMergeCSV: true, BackfillOnStart: true,
        CookieDestSave: 5, SinglePassLog: true,
        CSVWriteEveryN: 1, SkipRenderWhenIdle: false, CacheBPFMap: false,
}

var cycleCount int

func parseCollectorMode(mode string) CollectorMode {
        switch mode {
        case "lean":
                return CollectorMode{"lean", 60 * time.Second, 4_000_000, false, false, false, 10, true, 1, false, false}
        case "debug":
                return CollectorMode{"debug", 30 * time.Second, 16_000_000, true, true, true, 1, false, 1, false, false}
        case "normal-light":
                // v0.9.33: normal mode with reduced CPU/memory.
                // Keeps CSV fallback + 30s interval (dashboard stays fresh).
                // Reduces log tail to 8MB (50% less parsing).
                // Throttles CSV writes to every 2nd cycle (60s).
                // Skips renderToDisk when no new swaps.
                // Caches BPF map reads when entry count unchanged.
                return CollectorMode{
                        "normal-light", 30 * time.Second, 8_000_000,
                        true, true, true, 5, true,
                        2, true, true,
                }
        default:
                return CollectorMode{
                        "normal", 30 * time.Second, 16_000_000,
                        true, true, true, 5, true,
                        1, false, false,
                }
        }
}

func shouldSaveCookieDest() bool {
        cycleCount++
        return cycleCount%collectorMode.CookieDestSave == 0
}
