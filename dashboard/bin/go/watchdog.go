package main

// watchdog.go — v0.9.102: Self-kill safety switch.
// If RSS exceeds 250MB or CPU exceeds 80% for 2 consecutive 30s checks,
// the collector kills itself. systemd restarts with RestartSec=5.
//
// v0.9.132: the CPU arm got a startup grace period and a 3rd strike.
// The first minutes of a collector's life run the heaviest work it ever
// does — synchronous first collect() + renderToDisk(), and at +5 min
// renderSlowToDisk()'s full-CSV pass. On 1-vCPU hosts that burst alone
// exceeded 80% for 2 consecutive checks, so v0.9.102's 2-strike rule
// turned a transient startup burst into kill→restart→burst→kill with
// Restart=always: a suicide loop that pinned the CPU at 100% sawtooth
// and re-read every CSV from disk every ~2 minutes (huge I/O). Now:
//   - CPU breaches during the first watchdogGracePeriod are logged but
//     NOT counted;
//   - after grace, CPU needs 3 consecutive breaches (90s sustained
//     >80%) — a real runaway, not a render pass.
// The RSS arm keeps the strict no-grace 2-strike rule: RSS >250MB means
// the v0.9.131 memory bounds failed, and dying fast is correct.

import (
        "fmt"
        "os"
        "runtime"
        "runtime/debug"
        "strconv"
        "strings"
        "time"
)

const (
        watchdogInterval        = 30 * time.Second
        watchdogRSSLimit        = 250
        watchdogCPULimit        = 80
        watchdogMaxBreaches     = 2 // RSS strikes (unchanged since v0.9.102)
        watchdogCPUMaxBreaches  = 3 // v0.9.132: was 2 — see file header
        watchdogHeapLimit       = 200
        watchdogGOGC            = 30
        watchdogGracePeriod     = 8 * time.Minute // v0.9.132: startup grace (CPU arm only)
)

// watchdogDecision is the pure kill decision (unit-tested in
// v0_9_132_perf_test.go). memBreaches / cpuBreaches are the CURRENT
// consecutive-breach counters as the loop computes them (breaches
// accumulated during grace are not counted — the loop handles that).
func watchdogDecision(procAge time.Duration, memBreaches, cpuBreaches int) (kill bool, reason string) {
        if memBreaches >= watchdogMaxBreaches {
                return true, "rss"
        }
        if procAge >= watchdogGracePeriod && cpuBreaches >= watchdogCPUMaxBreaches {
                return true, "cpu"
        }
        return false, ""
}

func startWatchdog() {
        debug.SetGCPercent(watchdogGOGC)
        debug.SetMemoryLimit(int64(watchdogHeapLimit) * 1024 * 1024)
        fmt.Fprintf(os.Stderr, "watchdog: started (RSS limit %dMB, CPU limit %d%%, heap limit %dMiB, GOGC %d; grace %v on CPU arm, %d CPU strikes)\n",
                watchdogRSSLimit, watchdogCPULimit, watchdogHeapLimit, watchdogGOGC, watchdogGracePeriod, watchdogCPUMaxBreaches)

        startedAt := time.Now()
        go func() {
                var memBreaches, cpuBreaches int
                var prevUTime, prevSTime int64
                prevTime := time.Now()
                ticker := time.NewTicker(watchdogInterval)
                defer ticker.Stop()

                for t := range ticker.C {
                        rssMB := readRSSMB()
                        if rssMB > watchdogRSSLimit {
                                memBreaches++
                                fmt.Fprintf(os.Stderr, "watchdog: RSS %dMB > %dMB (breach %d/%d)\n",
                                        rssMB, watchdogRSSLimit, memBreaches, watchdogMaxBreaches)
                        } else {
                                memBreaches = 0
                        }

                        cpuPct := readCPUPercent(&prevUTime, &prevSTime, &prevTime, t)
                        procAge := time.Since(startedAt)
                        inGrace := procAge < watchdogGracePeriod
                        if cpuPct > float64(watchdogCPULimit) {
                                if inGrace {
                                        // v0.9.132: log but don't count — startup (first collect +
                                        // renderToDisk + the +5min renderSlowToDisk full-CSV pass)
                                        // is legitimately the heaviest stretch of our life.
                                        fmt.Fprintf(os.Stderr, "watchdog: CPU %.1f%% > %d%% during startup grace (%v of %v elapsed) — not counting\n",
                                                cpuPct, watchdogCPULimit, procAge.Round(time.Second), watchdogGracePeriod)
                                } else {
                                        cpuBreaches++
                                        fmt.Fprintf(os.Stderr, "watchdog: CPU %.1f%% > %d%% (breach %d/%d)\n",
                                                cpuPct, watchdogCPULimit, cpuBreaches, watchdogCPUMaxBreaches)
                                }
                        } else {
                                cpuBreaches = 0
                        }

                        if kill, reason := watchdogDecision(procAge, memBreaches, cpuBreaches); kill {
                                if reason == "rss" {
                                        fmt.Fprintf(os.Stderr, "watchdog: KILLING SELF — RSS %dMB for %d consecutive checks\n", rssMB, memBreaches)
                                } else {
                                        fmt.Fprintf(os.Stderr, "watchdog: KILLING SELF — CPU %.1f%% for %d consecutive checks\n", cpuPct, cpuBreaches)
                                }
                                os.Exit(2)
                        }
                }
        }()
}

func readRSSMB() int {
        data, err := os.ReadFile("/proc/self/status")
        if err != nil {
                var ms runtime.MemStats
                runtime.ReadMemStats(&ms)
                return int(ms.Sys / 1024 / 1024)
        }
        for _, line := range strings.Split(string(data), "\n") {
                if strings.HasPrefix(line, "VmRSS:") {
                        fields := strings.Fields(line)
                        if len(fields) >= 2 {
                                kb, _ := strconv.Atoi(fields[1])
                                return kb / 1024
                        }
                }
        }
        var ms runtime.MemStats
        runtime.ReadMemStats(&ms)
        return int(ms.Sys / 1024 / 1024)
}

func readCPUPercent(prevUTime, prevSTime *int64, prevTime *time.Time, now time.Time) float64 {
        data, err := os.ReadFile("/proc/self/stat")
        if err != nil {
                return 0
        }
        fields := strings.Fields(string(data))
        if len(fields) < 17 {
                return 0
        }
        utime, _ := strconv.ParseInt(fields[13], 10, 64)
        stime, _ := strconv.ParseInt(fields[14], 10, 64)

        cpuTicksUsed := (utime - *prevUTime) + (stime - *prevSTime)
        elapsed := now.Sub(*prevTime).Seconds()
        *prevUTime = utime
        *prevSTime = stime
        *prevTime = now

        if elapsed <= 0 {
                return 0
        }

        cpuSeconds := float64(cpuTicksUsed) / 100.0
        return (cpuSeconds / elapsed) * 100.0
}
