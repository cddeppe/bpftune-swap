package main

// System info helpers — shell out to dpkg-query / git / systemctl to
// get the bpftune package version, dashboard git commit, and service
// status.  All cached for 5 minutes (service status cached 30s since
// it changes more frequently).
//
// Mirrors Python's bpftune_data.py:data_build (lines 40-70).

import (
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// Shell-cached helpers
// ============================================================================

type shellCacheEntry struct {
	val string
	at  time.Time
}

var (
	shellCacheMu sync.Mutex
	shellCache   = map[string]shellCacheEntry{}
)

// shellCached runs cmd and caches the trimmed output for `ttl`.
// On error, returns the previous cached value (if any) or `fallback`.
func shellCached(name string, cmd *exec.Cmd, ttl time.Duration, fallback string) string {
	shellCacheMu.Lock()
	defer shellCacheMu.Unlock()
	if entry, ok := shellCache[name]; ok && entry.val != "" && time.Since(entry.at) < ttl {
		return entry.val
	}
	output, err := cmd.Output()
	if err != nil {
		// Keep old value if we have one
		if entry, ok := shellCache[name]; ok && entry.val != "" {
			return entry.val
		}
		// Cache the fallback so we don't keep retrying
		shellCache[name] = shellCacheEntry{fallback, time.Now()}
		return fallback
	}
	v := strings.TrimSpace(string(output))
	if v == "" {
		v = fallback
	}
	shellCache[name] = shellCacheEntry{v, time.Now()}
	return v
}

// ============================================================================
// bpftuneVersion — runs `dpkg-query -W -f=${Version} bpftune`
// ============================================================================

func bpftuneVersion() string {
	cmd := exec.Command("dpkg-query", "-W", "-f=${Version}", "bpftune")
	return shellCached("bpftune_version", cmd, 5*time.Minute, "?")
}

// ============================================================================
// dashVersion — runs `git -C <repo> rev-parse --short HEAD`
// Tries common repo locations: /root/bpftune, /opt/bpftune, /usr/src/bpftune
// ============================================================================

var dashVersionStr = ""

func dashVersion() string {
	// 1. If set at build time (ldflags), use that
	if dashVersionStr != "" {
		return strings.TrimPrefix(dashVersionStr, "v")
	}
	// 2. Try latest git tag (works from any branch)
	for _, repo := range []string{"/root/bpftune", "/opt/bpftune", "/usr/src/bpftune"} {
		cmd := exec.Command("git", "-C", repo, "tag", "--sort=-creatordate")
		output, err := cmd.Output()
		if err == nil {
			lines := strings.Split(strings.TrimSpace(string(output)), "\n")
			if len(lines) > 0 && lines[0] != "" {
				v := strings.TrimPrefix(lines[0], "v")  // strip v prefix
				shellCacheMu.Lock()
				shellCache["dash_version"] = shellCacheEntry{v, time.Now()}
				shellCacheMu.Unlock()
				return v
			}
		}
	}
	// 3. Fall back to commit hash
	for _, repo := range []string{"/root/bpftune", "/opt/bpftune", "/usr/src/bpftune"} {
		cmd := exec.Command("git", "-C", repo, "rev-parse", "--short", "HEAD")
		output, err := cmd.Output()
		if err == nil {
			v := strings.TrimSpace(string(output))
			if v != "" {
				return v
			}
		}
	}
	return "?"
}

// ============================================================================
// bpftuneServiceActive — runs `systemctl is-active bpftune`
// ============================================================================

func bpftuneServiceActive() string {
	cmd := exec.Command("systemctl", "is-active", "bpftune")
	return shellCached("bpftune_service", cmd, 30*time.Second, "unknown")
}

// ============================================================================
// bpftuneServiceStartedAt — runs `systemctl show bpftune -p ActiveEnterTimestamp --value`
// Returns the time the bpftune service started, or the collector's start time
// as fallback (so uptime still works in containers without systemd).
// ============================================================================

var systemdTsRx = regexp.MustCompile(`(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})`)

func bpftuneServiceStartedAt(fallback time.Time) time.Time {
	shellCacheMu.Lock()
	if entry, ok := shellCache["bpftune_started"]; ok && time.Since(entry.at) < 30*time.Second {
		shellCacheMu.Unlock()
		// Parse back to time
		if t, err := time.ParseInLocation("2006-01-02 15:04:05", entry.val, time.Local); err == nil {
			return t
		}
	} else {
		shellCacheMu.Unlock()
	}
	cmd := exec.Command("systemctl", "show", "bpftune", "-p", "ActiveEnterTimestamp", "--value")
	output, err := cmd.Output()
	if err != nil {
		return fallback
	}
	ts := strings.TrimSpace(string(output))
	if ts == "" {
		return fallback
	}
	m := systemdTsRx.FindStringSubmatch(ts)
	if m == nil {
		return fallback
	}
	t, err := time.ParseInLocation("2006-01-02 15:04:05", m[1], time.Local)
	if err != nil {
		return fallback
	}
	shellCacheMu.Lock()
	shellCache["bpftune_started"] = shellCacheEntry{m[1], time.Now()}
	shellCacheMu.Unlock()
	return t
}

// ============================================================================
// startedUTC — returns "HH:MM:SS" form (matches Python data_build)
// ============================================================================

func startedUTC() string {
	t := bpftuneServiceStartedAt(time.Now())
	return t.UTC().Format("15:04:05")
}

// ============================================================================
// uptimeMin — minutes since bpftune service started
// ============================================================================

func uptimeMin() int {
	t := bpftuneServiceStartedAt(time.Now())
	return int(time.Since(t).Minutes())
}

func readSystemInfo() map[string]interface{} {
	out := map[string]interface{}{
		"kernel":     readProc("/proc/sys/kernel/osrelease"),
		"default_cc": readProc("/proc/sys/net/ipv4/tcp_congestion_control"),
		"cpu_count":  runtime.NumCPU(),
	}
	if la, err := os.ReadFile("/proc/loadavg"); err == nil {
		parts := strings.Fields(string(la))
		if len(parts) >= 3 {
			if v, err := strconv.ParseFloat(parts[0], 64); err == nil {
				out["load_1"] = round2(v)
			}
			if v, err := strconv.ParseFloat(parts[1], 64); err == nil {
				out["load_5"] = round2(v)
			}
			if v, err := strconv.ParseFloat(parts[2], 64); err == nil {
				out["load_15"] = round2(v)
			}
		}
		if len(parts) >= 4 && strings.Contains(parts[3], "/") {
			ps := strings.SplitN(parts[3], "/", 2)
			if len(ps) == 2 {
				if v, err := strconv.Atoi(ps[0]); err == nil {
					out["procs_running"] = v
				}
				if v, err := strconv.Atoi(ps[1]); err == nil {
					out["procs_total"] = v
				}
			}
		}
	}
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		parts := strings.Fields(string(data))
		if len(parts) > 0 {
			if v, err := strconv.ParseFloat(parts[0], 64); err == nil {
				out["host_uptime_s"] = int(v)
			}
		}
	}
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		mi := map[string]int64{}
		for _, line := range strings.Split(string(data), "\n") {
			kv := strings.SplitN(line, ":", 2)
			if len(kv) != 2 {
				continue
			}
			key := strings.TrimSpace(kv[0])
			bits := strings.Fields(strings.TrimSpace(kv[1]))
			if len(bits) > 0 {
				if v, err := strconv.ParseInt(bits[0], 10, 64); err == nil {
					mi[key] = v * 1024
				}
			}
		}
		total := mi["MemTotal"]
		avail := mi["MemAvailable"]
		if avail == 0 {
			avail = mi["MemFree"]
		}
		if total > 0 && avail >= 0 {
			used := total - avail
			out["mem_total_bytes"] = total
			out["mem_avail_bytes"] = avail
			out["mem_used_bytes"] = used
			out["mem_used_pct"] = round1(float64(used) * 100.0 / float64(total))
		}
	}
	return out
}
