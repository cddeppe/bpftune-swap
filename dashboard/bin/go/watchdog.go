package main

// watchdog.go — v0.9.102: Self-kill safety switch.
// If RSS exceeds 250MB or CPU exceeds 80% for 2 consecutive 30s checks,
// the collector kills itself. systemd restarts with RestartSec=5.

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
	watchdogInterval    = 30 * time.Second
	watchdogRSSLimit    = 250
	watchdogCPULimit    = 80
	watchdogMaxBreaches = 2
	watchdogHeapLimit   = 200
	watchdogGOGC        = 30
)

func startWatchdog() {
	debug.SetGCPercent(watchdogGOGC)
	debug.SetMemoryLimit(int64(watchdogHeapLimit) * 1024 * 1024)
	fmt.Fprintf(os.Stderr, "watchdog: started (RSS limit %dMB, CPU limit %d%%, heap limit %dMiB, GOGC %d)\n",
		watchdogRSSLimit, watchdogCPULimit, watchdogHeapLimit, watchdogGOGC)

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
			if cpuPct > float64(watchdogCPULimit) {
				cpuBreaches++
				fmt.Fprintf(os.Stderr, "watchdog: CPU %.1f%% > %d%% (breach %d/%d)\n",
					cpuPct, watchdogCPULimit, cpuBreaches, watchdogMaxBreaches)
			} else {
				cpuBreaches = 0
			}

			if memBreaches >= watchdogMaxBreaches {
				fmt.Fprintf(os.Stderr, "watchdog: KILLING SELF — RSS %dMB for %d consecutive checks\n", rssMB, memBreaches)
				os.Exit(2)
			}
			if cpuBreaches >= watchdogMaxBreaches {
				fmt.Fprintf(os.Stderr, "watchdog: KILLING SELF — CPU %.1f%% for %d consecutive checks\n", cpuPct, cpuBreaches)
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
