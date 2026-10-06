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
	logTailBytes    = 2_000_000
	liveTopN        = 6
	liveMaxBuckets  = 8
	minLeaderTrust  = 10
	recentSwapsCap  = 50
	recentProofsCap = 50
)

// File paths.  Vars (not consts) so --data-root can override at startup.
var stateJSONPath = "/var/lib/bpftune/history/collector-go-state.json"
