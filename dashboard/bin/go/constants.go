package main

// Congestion control algorithm names (index = alg number from BPF).
// Mirrors bpftune_log.py:CONGS.
var CONGS = []string{
        "cubic", "bbr", "htcp", "dctcp", "scalable", "vegas",
        "veno", "westwood", "reno", "illinois", "yeah", "lp",
        "bic", "highspeed", "hybla", "nv",
}

// Shared constants.  Mirrors bpftune_log.py constants block.
const (
        bpsToMbps       = 1_000_000.0 / 8.0
        sustainedLoS    = 60.0
        sustainedHiS    = 300.0
        metCacheTTL     = 600.0
        tRescueWindowS  = 3600
        logTailBytes    = 16_000_000  // v0.9.3: 2MB→16MB. Estab events are
                                       // verbose and fill the 2MB tail with
                                       // ~14k estab lines, pushing out proof/
                                       // swap events. 16MB gives ~5x more room
                                       // so proofs stay in the tail.  Cookie→dest
                                       // persistence (cookie_dest.json) means
                                       // we don't need the estab events to stay
                                       // in the tail — they're persisted separately.
        liveTopN        = 6
        liveMaxBuckets  = 8
        minLeaderTrust  = 10
        recentSwapsCap  = 50
        recentProofsCap = 50
)

// File paths.  Vars (not consts) so --data-root can override at startup.
var stateJSONPath = "/var/lib/bpftune/history/collector-go-state.json"
