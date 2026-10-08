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
}

var collectorMode = CollectorMode{
        Name: "normal", CollectInterval: 30 * time.Second, LogTailBytes: 16_000_000,
        CSVFallback: true, ProofMergeCSV: true, BackfillOnStart: true,
        CookieDestSave: 5, SinglePassLog: true,
}

var cycleCount int

func parseCollectorMode(mode string) CollectorMode {
        switch mode {
        case "lean":
                return CollectorMode{"lean", 60 * time.Second, 4_000_000, false, false, false, 10, true}
        case "debug":
                return CollectorMode{"debug", 30 * time.Second, 16_000_000, true, true, true, 1, false}
        default:
                return CollectorMode{"normal", 30 * time.Second, 16_000_000, true, true, true, 5, true}
        }
}

func shouldSaveCookieDest() bool {
        cycleCount++
        return cycleCount%collectorMode.CookieDestSave == 0
}
