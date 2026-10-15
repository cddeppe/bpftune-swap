package main

// health_check.go — v0.9.45: Auto-fix system-level settings that the
// bpftune tuner needs to function correctly. Runs once on collector
// startup so the user never has to manually configure these.
//
// v0.9.46: Added trace capture service monitoring — the #1 cause of
// "no swaps in dashboard" is the bpftune-met-trace service dying.
// When it's dead, the log file goes stale and the collector shows
// no recent swaps even though the tuner is actively swapping.
//
// What this does:
//   1. Increases /sys/kernel/debug/tracing/buffer_size_kb to 256MB
//      (default is ~1.4MB which overflows and loses swap events)
//   2. Syncs saved explore_pct from /var/lib/bpftune/explore_pct to
//      the BPF tuner_config_map (in case bpftune restarted and reset
//      the map to default 5%)
//   3. Ensures the bpftune-met-trace service is running (creates the
//      service file if missing, starts it if dead)
//   4. Verifies BPF programs are loaded
//   5. Logs warnings if anything is wrong

import (
        "fmt"
        "os"
        "os/exec"
        "strconv"
        "strings"
        "time"
)

// ensureSystemHealth runs on collector startup and fixes system-level
// settings that the bpftune tuner needs. All idempotent — safe to run
// every startup, no harm if already correct.
func ensureSystemHealth() {
        fmt.Fprintf(os.Stderr, "collector: running system health checks...\n")

        // 1. Increase trace_pipe ring buffer to 256MB (stops event loss)
        // Default is ~1408 KB (1.4MB) which overflows on busy hosts,
        // causing "CPU:0 [LOST N EVENTS]" and dropping swap events.
        ensureTraceBufferSize()

        // 2. Sync saved explore_pct to BPF map
        // When bpftune restarts, it reads /var/lib/bpftune/explore_pct and
        // writes it to the BPF map. But if the BPF program was reloaded
        // (kernel update, manual bpftool reload), the map resets to default
        // (5%). This re-applies the saved value.
        syncExplorePctToBPF()

        // 3. Ensure the trace capture service is running
        // v0.9.46: This is the #1 cause of "no swaps in dashboard".
        // The bpftune-met-trace service reads trace_pipe and writes to
        // /var/log/bpftune-met-live.log. When it dies, the log goes stale.
        ensureTraceCaptureService()

        // 4. Verify BPF programs are loaded
        checkBPFPrograms()

        fmt.Fprintf(os.Stderr, "collector: system health checks complete\n")
}

// ensureTraceBufferSize increases the trace_pipe ring buffer.
// The BPF tuner writes swap/proof/met events to the trace_pipe.
// With the default ~1.4MB buffer, high-traffic hosts lose events
// (seen as "CPU:0 [LOST 31486 EVENTS]" in trace output).
// We set it to 256MB which is enough for even the busiest hosts.
func ensureTraceBufferSize() {
        const targetSize = 256 * 1024 // 256MB in KB
        const bufferSizePath = "/sys/kernel/debug/tracing/buffer_size_kb"

        // Read current size
        current, err := os.ReadFile(bufferSizePath)
        if err != nil {
                // Not mounted or no permission — non-fatal
                fmt.Fprintf(os.Stderr, "  trace buffer: could not read %s: %v (non-fatal)\n", bufferSizePath, err)
                return
        }
        currentSize, _ := strconv.Atoi(strings.TrimSpace(string(current)))

        if currentSize >= targetSize {
                fmt.Fprintf(os.Stderr, "  trace buffer: already %dKB (OK)\n", currentSize)
                return
        }

        // Write new size
        err = os.WriteFile(bufferSizePath, []byte(fmt.Sprintf("%d", targetSize)), 0644)
        if err != nil {
                fmt.Fprintf(os.Stderr, "  trace buffer: could not increase to %dKB: %v (non-fatal)\n", targetSize, err)
                return
        }

        fmt.Fprintf(os.Stderr, "  trace buffer: increased %dKB → %dKB (stops event loss)\n", currentSize, targetSize)
}

// syncExplorePctToBPF reads the saved explore_pct from
// /var/lib/bpftune/explore_pct and writes it to the BPF tuner_config_map.
// This ensures the tuner uses the user's saved setting even after
// bpftune restarts or the BPF map is reset.
func syncExplorePctToBPF() {
        saved := explorePctValue()
        if saved < 0 || saved > 100 {
                saved = 5 // default
        }

        // Try to read current BPF map value
        // The pinned map is at /sys/fs/bpftune/tcp_conn/explore
        // (pinned by the tuner on startup)
        pinPath := "/sys/fs/bpftune/tcp_conn/explore"

        // Use bpftool to read current value
        out, err := exec.Command("bpftool", "map", "lookup", "pinned", pinPath,
                "key", "hex", "00 00 00 00").Output()
        if err != nil {
                // Map not pinned or bpftool not available — non-fatal
                // The tuner itself reads EXPLORE_STATE on startup, so this is
                // just a safety net.
                fmt.Fprintf(os.Stderr, "  explore_pct: could not read BPF map (non-fatal): %v\n", err)
                return
        }

        // Parse current value from bpftool output
        // Output looks like: "00 00 00 00\nvalue: 0x05 0x00 0x00 0x00"
        currentPct := -1
        lines := strings.Split(string(out), "\n")
        for _, line := range lines {
                if strings.Contains(line, "value:") {
                        // Extract hex bytes after "value:"
                        parts := strings.SplitN(line, "value:", 2)
                        if len(parts) == 2 {
                                hexStr := strings.TrimSpace(parts[1])
                                hexParts := strings.Fields(hexStr)
                                if len(hexParts) > 0 {
                                        // First byte is the value (little-endian, single byte for 0-100)
                                        hexVal := hexParts[0]
                                        hexVal = strings.TrimPrefix(hexVal, "0x")
                                        if v, err := strconv.ParseUint(hexVal, 16, 32); err == nil {
                                                currentPct = int(v)
                                        }
                                }
                        }
                        break
                }
        }

        if currentPct == saved {
                fmt.Fprintf(os.Stderr, "  explore_pct: BPF map already %d%% (OK)\n", saved)
                return
        }

        // Write saved value to BPF map
        hexVal := fmt.Sprintf("%02x %02x %02x %02x",
                byte(saved), byte(saved>>8), byte(saved>>16), byte(saved>>24))
        err = exec.Command("bpftool", "map", "update", "pinned", pinPath,
                "key", "hex", "00 00 00 00",
                "value", "hex", hexVal).Run()
        if err != nil {
                fmt.Fprintf(os.Stderr, "  explore_pct: WARNING could not sync %d%% to BPF map: %v\n", saved, err)
                return
        }

        if currentPct >= 0 {
                fmt.Fprintf(os.Stderr, "  explore_pct: synced BPF map %d%% → %d%% (from saved config)\n", currentPct, saved)
        } else {
                fmt.Fprintf(os.Stderr, "  explore_pct: synced BPF map → %d%% (from saved config)\n", saved)
        }
}

// checkBPFPrograms verifies that the bpftune BPF programs are loaded.
// Logs a warning if not — the collector will still run (degraded mode)
// but the dashboard won't show live data.
func checkBPFPrograms() {
        out, err := exec.Command("bpftool", "prog", "show").Output()
        if err != nil {
                fmt.Fprintf(os.Stderr, "  BPF programs: could not check (bpftool failed): %v\n", err)
                return
        }
        count := strings.Count(string(out), "bpftune")
        if count == 0 {
                fmt.Fprintf(os.Stderr, "  BPF programs: WARNING — no bpftune programs loaded! Tuner not running.\n")
                return
        }
        fmt.Fprintf(os.Stderr, "  BPF programs: %d bpftune programs loaded (OK)\n", count)
}

// ensureTraceCaptureService ensures the bpftune-met-trace service is
// running. This service reads from /sys/kernel/debug/tracing/trace_pipe
// and writes to /var/log/bpftune-met-live.log. When it dies, the log
// goes stale and the dashboard shows no recent swaps even though the
// tuner is actively swapping.
//
// v0.9.46: This is the #1 cause of "dashboard shows no swaps".
// The service can die from OOM, kernel updates, or manual stop.
// The collector now auto-restarts it.
//
// v0.9.54: Also clears stale log entries from previous boots.
// When bpftune restarts, the log file still has events from the previous
// boot. These old events have BPF timestamps from the old boot, causing
// the dashboard to show wrong ages (e.g. "1 hour ago" when swaps are
// actually happening now). The collector now clears the log on startup
// and when it detects events from a previous boot.
func ensureTraceCaptureService() {
        const serviceName = "bpftune-met-trace"
        const serviceFilePath = "/etc/systemd/system/bpftune-met-trace.service"
        const logPath = "/var/log/bpftune-met-live.log"

        // v0.9.59: REMOVED log clearing. The single-pass parser already
        // filters events from previous boots (line 139 in singlepass.go:
        // if uptime > 0 && ts > uptime+300 { continue }). Clearing the log
        // on startup was too aggressive — it wiped all accumulated events
        // and left the dashboard empty until enough new events accumulated.
        // Check if the service is running
        out, err := exec.Command("systemctl", "is-active", serviceName).Output()
        status := strings.TrimSpace(string(out))
        if err == nil && status == "active" {
                // Service is running — verify the log file is fresh
                if fi, err := os.Stat(logPath); err == nil {
                        age := time.Since(fi.ModTime())
                        if age > 5*time.Minute {
                                fmt.Fprintf(os.Stderr, "  trace service: running but log file is %v old — restarting\n", age.Round(time.Minute))
                                exec.Command("systemctl", "restart", serviceName).Run()
                        } else {
                                fmt.Fprintf(os.Stderr, "  trace service: active (log file %v old) (OK)\n", age.Round(time.Second))
                        }
                } else {
                        fmt.Fprintf(os.Stderr, "  trace service: active (log file not found yet) (OK)\n")
                }
                return
        }

        // Service is not running — start it
        fmt.Fprintf(os.Stderr, "  trace service: %s (status=%s), starting...\n", serviceName, status)

        // Reload systemd to pick up the service file if it was just created
        exec.Command("systemctl", "daemon-reload").Run()

        // Enable and start
        exec.Command("systemctl", "enable", serviceName).Run()
        err = exec.Command("systemctl", "start", serviceName).Run()
        if err != nil {
                fmt.Fprintf(os.Stderr, "  trace service: WARNING could not start: %v\n", err)
                return
        }

        // Verify it started
        time.Sleep(1 * time.Second)
        out, _ = exec.Command("systemctl", "is-active", serviceName).Output()
        status = strings.TrimSpace(string(out))
        if status == "active" {
                fmt.Fprintf(os.Stderr, "  trace service: started (was %s) (OK)\n", status)
        } else {
                fmt.Fprintf(os.Stderr, "  trace service: WARNING still %s after start attempt\n", status)
        }
}

// createTraceServiceFile writes the systemd service file for the trace
// capture service. This service reads trace_pipe and writes to the log
// file that the collector reads.
func createTraceServiceFile(path string) {
        const serviceContent = `[Unit]
Description=bpftune trace_pipe capture to /var/log/bpftune-met-live.log
After=sys-kernel-debug.mount sys-kernel-tracing.mount bpftune.service
ConditionPathExists=/sys/kernel/debug/tracing/trace_pipe

[Service]
Type=simple
ExecStart=/bin/sh -c 'while true; do cat /sys/kernel/debug/tracing/trace_pipe >> /var/log/bpftune-met-live.log 2>&1; sleep 0.1; done'
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
`
        err := os.WriteFile(path, []byte(serviceContent), 0644)
        if err != nil {
                fmt.Fprintf(os.Stderr, "  trace service: could not create %s: %v\n", path, err)
                return
        }
        fmt.Fprintf(os.Stderr, "  trace service: created %s\n", path)

        // Also ensure the log file exists
        f, err := os.OpenFile("/var/log/bpftune-met-live.log", os.O_CREATE|os.O_APPEND, 0644)
        if err == nil {
                f.Close()
        }
}

// getServiceHealth collects the current health status of all system
// components the tuner depends on. Called on every collect cycle and
// included in current.json as "service_health".
//
// v0.9.46: The dashboard renders this as a visual health panel so users
// can immediately see if something is wrong.
func getServiceHealth() map[string]interface{} {
        health := map[string]interface{}{}

        // 1. BPF programs loaded?
        bpfCount := 0
        if out, err := exec.Command("bpftool", "prog", "show").Output(); err == nil {
                bpfCount = strings.Count(string(out), "bpftune")
        }
        health["bpf_programs"] = bpfCount
        health["bpf_programs_ok"] = bpfCount > 0

        // 2. bpftune service active?
        bpftuneActive := "unknown"
        if out, err := exec.Command("systemctl", "is-active", "bpftune").Output(); err == nil {
                bpftuneActive = strings.TrimSpace(string(out))
        }
        health["bpftune_service"] = bpftuneActive
        health["bpftune_service_ok"] = bpftuneActive == "active"

        // 3. Trace capture service active?
        traceActive := "unknown"
        if out, err := exec.Command("systemctl", "is-active", "bpftune-met-trace").Output(); err == nil {
                traceActive = strings.TrimSpace(string(out))
        }
        health["trace_service"] = traceActive
        health["trace_service_ok"] = traceActive == "active"

        // 4. Log file freshness
        logAge := "unknown"
        logAgeSec := int64(0)
        if fi, err := os.Stat("/var/log/bpftune-met-live.log"); err == nil {
                ageSec := int64(time.Since(fi.ModTime()).Seconds())
                logAgeSec = ageSec
                if ageSec < 60 {
                        logAge = fmt.Sprintf("%ds", ageSec)
                } else if ageSec < 3600 {
                        logAge = fmt.Sprintf("%dm", ageSec/60)
                } else {
                        logAge = fmt.Sprintf("%dh", ageSec/3600)
                }
        }
        health["log_age"] = logAge
        health["log_age_sec"] = logAgeSec
        health["log_fresh_ok"] = logAgeSec >= 0 && logAgeSec < 120 // fresh if <2 min old

        // 5. Explore_pct
        expPct := explorePctValue()
        health["explore_pct"] = expPct
        health["explore_pct_ok"] = expPct > 0

        // 6. Trace buffer size
        bufSize := 0
        if data, err := os.ReadFile("/sys/kernel/debug/tracing/buffer_size_kb"); err == nil {
                bufSize, _ = strconv.Atoi(strings.TrimSpace(string(data)))
        }
        health["trace_buffer_kb"] = bufSize
        health["trace_buffer_ok"] = bufSize >= 65536 // 64MB minimum

        // v0.9.68: ctrld DNS cache integration status
        ctrldStatus := getCtrldStatus()
        health["ctrld_available"] = ctrldStatus["available"]
        health["ctrld_entry_count"] = ctrldStatus["entry_count"]
        health["ctrld_last_fetch"] = ctrldStatus["last_fetch"]
        health["ctrld_ok"] = true // always OK — ctrld is optional, not a failure if absent

        // Overall health
        allOk := health["bpf_programs_ok"].(bool) &&
                health["bpftune_service_ok"].(bool) &&
                health["trace_service_ok"].(bool) &&
                health["log_fresh_ok"].(bool) &&
                health["explore_pct_ok"].(bool)
        health["all_ok"] = allOk

        return health
}

// clearStaleLogEntries checks if the log file contains events from a
// previous boot. If ANY event in the log tail has a BPF timestamp
// significantly lower than the current uptime, the log is stale and
// should be cleared.
//
// v0.9.54: This fixes "dashboard shows swaps from an hour ago" when
// swaps are actually happening now. The old log file persists across
// reboots and contains events with BPF timestamps from the previous
// boot, which the collector misinterprets as current-boot events.
//
// v0.9.55: Changed to check ALL swap events in the log, not just the
// last line. The last line might be a fresh estab event while old
// swap events from the previous boot are still in the 8MB tail.
func clearStaleLogEntries(logPath string) {
        // Read the current uptime
        uptime := readProcUptime()
        if uptime <= 0 {
                return // can't determine, skip
        }

        // Read the log file and check for stale swap events
        f, err := os.Open(logPath)
        if err != nil {
                return // file doesn't exist yet, nothing to clear
        }
        defer f.Close()

        fi, _ := f.Stat()
        if fi.Size() == 0 {
                return // empty file, nothing to clear
        }

        // Read the last 8MB (same as collector's log tail)
        readSize := int64(8 * 1024 * 1024)
        if fi.Size() < readSize {
                readSize = fi.Size()
        }
        f.Seek(fi.Size()-readSize, 0)
        buf := make([]byte, readSize)
        n, _ := f.Read(buf)
        lines := strings.Split(string(buf[:n]), "\n")

        // Check if ANY swap event has a stale timestamp
        staleFound := false
        for _, line := range lines {
                if !strings.Contains(line, "swap cookie") {
                        continue
                }
                idx := strings.Index(line, ": bpf_trace_printk")
                if idx < 0 {
                        continue
                }
                // Walk backwards to find the timestamp
                start := idx
                for start > 0 {
                        c := line[start-1]
                        if (c >= '0' && c <= '9') || c == '.' {
                                start--
                        } else {
                                break
                        }
                }
                if start >= idx {
                        continue
                }
                tsStr := line[start:idx]
                ts, err := strconv.ParseFloat(tsStr, 64)
                if err != nil || ts <= 0 {
                        continue
                }
                // If this swap event's timestamp is more than 60 seconds
                // behind the current uptime, it's from a previous boot
                if uptime-ts > 60 {
                        staleFound = true
                        break
                }
        }

        if staleFound {
                fmt.Fprintf(os.Stderr, "  trace log: clearing stale entries (found swap events from previous boot, uptime=%.1f)\n", uptime)
                exec.Command("systemctl", "stop", "bpftune-met-trace").Run()
                os.WriteFile(logPath, []byte{}, 0644)
                exec.Command("systemctl", "start", "bpftune-met-trace").Run()
        }
}
