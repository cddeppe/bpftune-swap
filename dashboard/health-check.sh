#!/bin/bash
# health-check.sh — Comprehensive bpftune-swap pipeline health check
# Checks the entire chain: kernel BPF → trace capture → bpftune daemon →
# Go collector → current.json → SSE → static files → SQLite
#
# Usage:
#   sudo bash health-check.sh           # full check
#   sudo bash health-check.sh --fix     # check + auto-fix common issues
#   sudo bash health-check.sh --quiet   # only show problems (exit 0 if healthy)
#
set -o pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

FIX=0
QUIET=0

for arg in "$@"; do
    case $arg in
        --fix)   FIX=1 ;;
        --quiet) QUIET=1 ;;
    esac
done

PASS=0
WARN=0
FAIL=0

ok()   { if [ $QUIET -eq 0 ]; then echo -e "  ${GREEN}✓${NC} $1"; fi; PASS=$((PASS+1)); }
warn() { echo -e "  ${YELLOW}⚠${NC} $1"; WARN=$((WARN+1)); }
fail() { echo -e "  ${RED}✗${NC} $1"; FAIL=$((FAIL+1)); }
hdr()  { if [ $QUIET -eq 0 ]; then echo -e "\n${CYAN}=== $1 ===${NC}"; fi; }

if [ $QUIET -eq 0 ]; then
    echo "bpftune-swap Pipeline Health Check"
    echo "Host: $(hostname)  Time: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo ""
fi

# ============================================================================
# 1. Kernel: BPF programs loaded
# ============================================================================
hdr "1. BPF Kernel Programs"

# Check if BPF sockops program is loaded
BPF_PROG=$(bpftool prog show 2>/dev/null | grep -c "bpftune_conn_tuner")
if [ "$BPF_PROG" -ge 1 ]; then
    ok "BPF sockops program loaded ($BPF_PROG program(s))"
else
    fail "BPF sockops program NOT loaded"
    if [ $FIX -eq 1 ]; then
        echo "  → Restarting bpftune..."
        systemctl restart bpftune 2>/dev/null
        sleep 3
        BPF_PROG=$(bpftool prog show 2>/dev/null | grep -c "bpftune_conn_tuner")
        if [ "$BPF_PROG" -ge 1 ]; then
            ok "BPF program loaded after restart"
        else
            fail "BPF program still not loaded after restart — check: journalctl -u bpftune"
        fi
    fi
fi

# Check BPF maps exist
for map_name in remote_host_map tuner_config_map sk_storage_map; do
    if bpftool map show name "$map_name" >/dev/null 2>&1; then
        ok "BPF map '$map_name' exists"
    else
        fail "BPF map '$map_name' NOT found"
    fi
done

# Check explore_pct value
EXPLORE_PCT=$(bpftool map lookup pinned /sys/fs/bpf/bpftune/tcp_conn/explore key hex 00 00 00 00 2>/dev/null | grep '"value"' | grep -oP '\d+')
if [ -n "$EXPLORE_PCT" ]; then
    if [ "$EXPLORE_PCT" -eq 100 ]; then
        ok "explore_pct = 100 (full exploration)"
    elif [ "$EXPLORE_PCT" -ge 5 ]; then
        warn "explore_pct = $EXPLORE_PCT (expected 100 for full exploration)"
    else
        fail "explore_pct = $EXPLORE_PCT (very low — only greedy/cubic)"
    fi
else
    fail "Cannot read explore_pct from BPF map"
    if [ $FIX -eq 1 ] && [ -f /sys/fs/bpf/bpftune/tcp_conn/explore ]; then
        bpftool map update pinned /sys/fs/bpf/bpftune/tcp_conn/explore key hex 00 00 00 00 value hex 64 00 00 00 2>/dev/null
        ok "Set explore_pct to 100"
    fi
fi

# Check available congestion control algorithms
AVAIL_CC=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null)
CC_COUNT=$(echo "$AVAIL_CC" | wc -w)
if [ "$CC_COUNT" -ge 16 ]; then
    ok "All 16 CC algorithms available ($CC_COUNT found)"
else
    warn "Only $CC_COUNT CC algorithms available (expected 16): $AVAIL_CC"
    if [ $FIX -eq 1 ]; then
        for mod in tcp_bbr tcp_htcp tcp_dctcp tcp_vegas tcp_veno tcp_westwood tcp_reno tcp_illinois tcp_yeah tcp_lp tcp_bic tcp_highspeed tcp_hybla tcp_nv tcp_scalable; do
            modprobe "$mod" 2>/dev/null
        done
        CC_COUNT=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | wc -w)
        ok "After modprobe: $CC_COUNT CC algorithms available"
    fi
fi

# ============================================================================
# 2. bpftune daemon
# ============================================================================
hdr "2. bpftune Daemon"

if systemctl is-active --quiet bpftune 2>/dev/null; then
    ok "bpftune service is active"
else
    fail "bpftune service is NOT active"
    if [ $FIX -eq 1 ]; then
        systemctl start bpftune 2>/dev/null
        sleep 3
        if systemctl is-active --quiet bpftune; then
            ok "bpftune started"
        else
            fail "bpftune failed to start — check: journalctl -u bpftune"
        fi
    fi
fi

# Check bpftune version
BPFTUNE_VER=$(dpkg-query -W -f='${Version}' bpftune 2>/dev/null)
if [ -n "$BPFTUNE_VER" ]; then
    ok "bpftune version: $BPFTUNE_VER"
else
    fail "bpftune package not installed"
fi

# Check if bpftune is crashing (restart count)
RESTART_COUNT=$(systemctl show bpftune -p NRestarts 2>/dev/null | cut -d= -f2)
if [ -n "$RESTART_COUNT" ] && [ "$RESTART_COUNT" -gt 3 ]; then
    warn "bpftune restarted $RESTART_COUNT times (may be unstable)"
else
    ok "bpftune restart count: ${RESTART_COUNT:-0}"
fi

# Check service file for Restart=always
RESTART_POLICY=$(systemctl show bpftune -p Restart 2>/dev/null | cut -d= -f2)
if [ "$RESTART_POLICY" = "on-failure" ]; then
    warn "bpftune Restart=on-failure (should be Restart=always — clean exits aren't restarted)"
    if [ $FIX -eq 1 ]; then
        SERVICE_FILE=$(systemctl show bpftune -p FragmentPath 2>/dev/null | cut -d= -f2)
        if [ -n "$SERVICE_FILE" ] && [ -f "$SERVICE_FILE" ]; then
            sed -i 's/Restart=on-failure/Restart=always/' "$SERVICE_FILE"
            systemctl daemon-reload
            ok "Changed Restart=on-failure → Restart=always"
        fi
    fi
elif [ "$RESTART_POLICY" = "always" ]; then
    ok "bpftune Restart=always"
fi

# ============================================================================
# 3. Trace capture (BPF trace_pipe → log file)
# ============================================================================
hdr "3. Trace Capture"

TRACE_PIPE="/sys/kernel/tracing/trace_pipe"
LOG_FILE="/var/log/bpftune-met-live.log"

# Check if trace pipe exists
if [ -f "$TRACE_PIPE" ]; then
    ok "Trace pipe exists: $TRACE_PIPE"
else
    # Some kernels use /sys/kernel/debug/tracing/trace_pipe
    TRACE_PIPE="/sys/kernel/debug/tracing/trace_pipe"
    if [ -f "$TRACE_PIPE" ]; then
        ok "Trace pipe exists: $TRACE_PIPE (debugfs)"
    else
        fail "Trace pipe NOT found"
    fi
fi

# Check if log file exists
if [ -f "$LOG_FILE" ]; then
    LOG_SIZE=$(stat -c%s "$LOG_FILE" 2>/dev/null || stat -f%z "$LOG_FILE" 2>/dev/null)
    LOG_AGE=$(($(date +%s) - $(stat -c%Y "$LOG_FILE" 2>/dev/null || stat -f%m "$LOG_FILE" 2>/dev/null)))
    if [ "$LOG_AGE" -lt 60 ]; then
        ok "Log file exists: $LOG_FILE (${LOG_SIZE} bytes, updated ${LOG_AGE}s ago)"
    elif [ "$LOG_AGE" -lt 300 ]; then
        warn "Log file exists but stale (${LOG_AGE}s old, ${LOG_SIZE} bytes)"
    else
        fail "Log file exists but very stale (${LOG_AGE}s = $((LOG_AGE/60))min old)"
        if [ $FIX -eq 1 ]; then
            # Check if trace capture process is running
            if ! pgrep -f "trace_pipe" >/dev/null 2>&1; then
                echo "  → Starting trace capture..."
                nohup sh -c "cat $TRACE_PIPE" > "$LOG_FILE" 2>&1 &
                sleep 3
                if [ -f "$LOG_FILE" ]; then
                    ok "Trace capture started"
                else
                    fail "Trace capture failed to start"
                fi
            fi
        fi
    fi
else
    fail "Log file NOT found: $LOG_FILE"
    if [ $FIX -eq 1 ]; then
        echo "  → Starting trace capture..."
        nohup sh -c "cat $TRACE_PIPE" > "$LOG_FILE" 2>&1 &
        sleep 3
        if [ -f "$LOG_FILE" ]; then
            NEW_SIZE=$(stat -c%s "$LOG_FILE" 2>/dev/null || stat -f%z "$LOG_FILE" 2>/dev/null)
            ok "Trace capture started (${NEW_SIZE} bytes)"
        else
            fail "Trace capture failed to start — check: cat $TRACE_PIPE | head -1"
        fi
    fi
fi

# Check if any process is reading trace_pipe
TRACE_PID=$(pgrep -f "trace_pipe" 2>/dev/null | head -1)
if [ -n "$TRACE_PID" ]; then
    ok "Trace capture process running (PID $TRACE_PID)"
else
    warn "No trace_pipe reader process found"
    if [ $FIX -eq 1 ] && [ -f "$TRACE_PIPE" ]; then
        nohup sh -c "cat $TRACE_PIPE" > "$LOG_FILE" 2>&1 &
        sleep 3
        ok "Trace capture process started"
    fi
fi

# Check if log has recent BPF events
if [ -f "$LOG_FILE" ]; then
    LAST_TS=$(tail -1 "$LOG_FILE" 2>/dev/null | grep -oP '^\s+\S+\s+\[\d+\]\s+\S+\s+\K[\d.]+' | tail -1)
    UPTIME=$(awk '{print $1}' /proc/uptime 2>/dev/null)
    if [ -n "$LAST_TS" ] && [ -n "$UPTIME" ]; then
        AGE=$(echo "$UPTIME - $LAST_TS" | bc 2>/dev/null)
        if [ -n "$AGE" ]; then
            if [ "$(echo "$AGE < 60" | bc 2>/dev/null)" = "1" ]; then
                ok "Log events are fresh (newest: ${AGE}s ago)"
            elif [ "$(echo "$AGE < 300" | bc 2>/dev/null)" = "1" ]; then
                warn "Log events are stale (newest: ${AGE}s = $((AGE/60))min ago)"
            else
                fail "Log events are very stale (newest: ${AGE}s = $((AGE/60))min ago)"
            fi
        fi
    fi
fi

# Check log content for different event types
if [ -f "$LOG_FILE" ]; then
    for event_type in estab met srate swap proof midsamp closport; do
        COUNT=$(grep -c "$event_type cookie=" "$LOG_FILE" 2>/dev/null || echo 0)
        if [ "$COUNT" -gt 0 ]; then
            ok "Log has $COUNT '$event_type' events"
        else
            warn "No '$event_type' events in log"
        fi
    done
fi

# ============================================================================
# 4. Dashboard collector (Go binary)
# ============================================================================
hdr "4. Dashboard Collector"

if systemctl is-active --quiet bpftune-collector-go 2>/dev/null; then
    ok "Collector service is active"
else
    fail "Collector service is NOT active"
    if [ $FIX -eq 1 ]; then
        systemctl start bpftune-collector-go 2>/dev/null
        sleep 3
        if systemctl is-active --quiet bpftune-collector-go; then
            ok "Collector started"
        else
            fail "Collector failed to start — check: journalctl -u bpftune-collector-go"
        fi
    fi
fi

# Check collector version
COLLECTOR_BIN="/opt/bpftune-dashboard/bin/bpftune-collector-go"
if [ -x "$COLLECTOR_BIN" ]; then
    ok "Collector binary exists and is executable"
    BIN_SIZE=$(stat -c%s "$COLLECTOR_BIN" 2>/dev/null || stat -f%z "$COLLECTOR_BIN" 2>/dev/null)
    ok "Collector binary size: ${BIN_SIZE} bytes"
else
    fail "Collector binary missing or not executable: $COLLECTOR_BIN"
fi

# Check dashboard.js
DASH_JS="/opt/bpftune-dashboard/bin/dashboard.js"
if [ -f "$DASH_JS" ]; then
    JS_SIZE=$(stat -c%s "$DASH_JS" 2>/dev/null || stat -f%z "$DASH_JS" 2>/dev/null)
    ok "dashboard.js exists (${JS_SIZE} bytes)"
else
    fail "dashboard.js NOT found: $DASH_JS"
fi

# Check other static assets
for asset in index.html dashboard.css chart.umd.min.js chartjs-adapter-date-fns.bundle.min.js; do
    if [ -f "/opt/bpftune-dashboard/bin/$asset" ]; then
        ok "Static asset: $asset"
    else
        warn "Static asset missing: $asset"
    fi
done

# Check collector mode
COLLECTOR_MODE=$(ps -p $(pidof bpftune-collector-go 2>/dev/null) -o args= 2>/dev/null | grep -oP '\-\-collector-mode \S+' | cut -d' ' -f2)
if [ -z "$COLLECTOR_MODE" ]; then
    COLLECTOR_MODE="normal (default)"
fi
ok "Collector mode: $COLLECTOR_MODE"

# Check for degraded mode in collector logs
if journalctl -u bpftune-collector-go --since '5 min ago' --no-pager 2>/dev/null | grep -q "degraded mode"; then
    fail "Collector is in DEGRADED MODE — BPF map read failing"
    if [ $FIX -eq 1 ]; then
        systemctl restart bpftune-collector-go 2>/dev/null
        sleep 3
        if ! journalctl -u bpftune-collector-go --since '10 sec ago' --no-pager 2>/dev/null | grep -q "degraded mode"; then
            ok "Collector no longer in degraded mode after restart"
        fi
    fi
else
    ok "Collector is NOT in degraded mode"
fi

# ============================================================================
# 5. current.json (the dashboard data)
# ============================================================================
hdr "5. current.json Data"

if curl -s --max-time 5 http://localhost:8080/current.json >/dev/null 2>&1; then
    ok "Dashboard responding on port 8080"
else
    fail "Dashboard NOT responding on port 8080"
    exit 1
fi

# Parse current.json
CURRENT_JSON=$(curl -s --max-time 5 http://localhost:8080/current.json 2>/dev/null)

# Check now_mono vs uptime
NOW_MONO=$(echo "$CURRENT_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('now_mono',0))" 2>/dev/null)
UPTIME=$(awk '{print $1}' /proc/uptime 2>/dev/null)

if [ -n "$NOW_MONO" ] && [ -n "$UPTIME" ]; then
    DIFF=$(echo "$UPTIME - $NOW_MONO" | bc 2>/dev/null)
    if [ -n "$DIFF" ]; then
        DIFF_ABS=${DIFF#-}  # absolute value
        if [ "$(echo "$DIFF_ABS < 60" | bc 2>/dev/null)" = "1" ]; then
            ok "now_mono matches uptime (diff: ${DIFF}s)"
        elif [ "$(echo "$DIFF_ABS < 300" | bc 2>/dev/null)" = "1" ]; then
            warn "now_mono drift: ${DIFF}s (should be near 0)"
        else
            fail "now_mono is wrong: now_mono=$NOW_MONO, uptime=$UPTIME (diff: ${DIFF}s)"
        fi
    fi
fi

# Check buckets
BUCKET_COUNT=$(echo "$CURRENT_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('buckets',[])))" 2>/dev/null)
if [ -n "$BUCKET_COUNT" ]; then
    if [ "$BUCKET_COUNT" -ge 3 ]; then
        ok "Buckets: $BUCKET_COUNT"
    elif [ "$BUCKET_COUNT" -ge 1 ]; then
        warn "Only $BUCKET_COUNT buckets (low traffic or degraded mode)"
    else
        fail "0 buckets — BPF map not loading or no connections"
    fi
fi

# Check degraded flag
DEGRADED=$(echo "$CURRENT_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('degraded',False))" 2>/dev/null)
if [ "$DEGRADED" = "True" ]; then
    fail "Dashboard is in DEGRADED mode (BPF map read failure)"
else
    ok "Dashboard is NOT in degraded mode"
fi

# Check recent_swaps
SWAPS_COUNT=$(echo "$CURRENT_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('recent_swaps',[])))" 2>/dev/null)
if [ -n "$SWAPS_COUNT" ]; then
    if [ "$SWAPS_COUNT" -ge 1 ]; then
        ok "recent_swaps: $SWAPS_COUNT entries"
    else
        warn "recent_swaps is empty (no swaps in log or CSV fallback)"
    fi
fi

# Check recent_proofs
PROOFS_COUNT=$(echo "$CURRENT_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('recent_proofs',[])))" 2>/dev/null)
if [ -n "$PROOFS_COUNT" ]; then
    if [ "$PROOFS_COUNT" -ge 1 ]; then
        ok "recent_proofs: $PROOFS_COUNT entries"
    else
        warn "recent_proofs is empty (no proofs in log or CSV fallback)"
    fi
fi

# Check rate progression
RATE_COUNT=$(echo "$CURRENT_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('rate',[])))" 2>/dev/null)
if [ -n "$RATE_COUNT" ]; then
    if [ "$RATE_COUNT" -ge 1 ]; then
        ok "rate progression: $RATE_COUNT rows"
    else
        warn "rate progression is empty (no midsamp events)"
    fi
fi

# Check proof leaderboard
PROOF_LB_COUNT=$(echo "$CURRENT_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('proof',[])))" 2>/dev/null)
if [ -n "$PROOF_LB_COUNT" ]; then
    if [ "$PROOF_LB_COUNT" -ge 1 ]; then
        ok "proof leaderboard: $PROOF_LB_COUNT algs"
    else
        warn "proof leaderboard is empty"
    fi
fi

# Check swap_outcomes.swaps_list
SWAPS_LIST_COUNT=$(echo "$CURRENT_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('swap_outcomes',{}).get('swaps_list',[])))" 2>/dev/null)
if [ -n "$SWAPS_LIST_COUNT" ]; then
    if [ "$SWAPS_LIST_COUNT" -ge 1 ]; then
        ok "swap_outcomes.swaps_list: $SWAPS_LIST_COUNT entries"
    else
        warn "swap_outcomes.swaps_list is empty"
    fi
fi

# Check metric_by_bucket has non-zero rate_ema
RATE_EMA_NONZERO=$(echo "$CURRENT_JSON" | python3 -c "
import json,sys
d=json.load(sys.stdin)
count=0
for bid, rows in d.get('metric_by_bucket',{}).items():
    for r in rows:
        if r.get('rate_ema',0) > 0:
            count += 1
print(count)
" 2>/dev/null)
if [ -n "$RATE_EMA_NONZERO" ]; then
    if [ "$RATE_EMA_NONZERO" -gt 0 ]; then
        ok "metric_by_bucket has $RATE_EMA_NONZERO algs with non-zero rate_ema"
    else
        warn "metric_by_bucket has 0 algs with non-zero rate_ema (all app-limited or no data)"
    fi
fi

# Check version display
TUNER_VER=$(echo "$CURRENT_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('build',{}).get('version','?'))" 2>/dev/null)
DASH_VER=$(echo "$CURRENT_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('build',{}).get('dash_version','?'))" 2>/dev/null)
ok "Versions: tuner=$TUNER_VER, dashboard=$DASH_VER"

# ============================================================================
# 6. CSV files
# ============================================================================
hdr "6. CSV Files"

DATA_DIR="/var/lib/bpftune/history"
for csv in swaps.csv proofs.csv buckets.v2.csv srate.csv midsamp.csv; do
    if [ -f "$DATA_DIR/$csv" ]; then
        CSV_SIZE=$(stat -c%s "$DATA_DIR/$csv" 2>/dev/null || stat -f%z "$DATA_DIR/$csv" 2>/dev/null)
        CSV_LINES=$(wc -l < "$DATA_DIR/$csv" 2>/dev/null)
        ok "$csv: ${CSV_LINES} lines, ${CSV_SIZE} bytes"
    else
        warn "$csv: NOT found"
    fi
done

# ============================================================================
# 7. SQLite database
# ============================================================================
hdr "7. SQLite Database"

SQLITE_DB="$DATA_DIR/buckets.db"
if [ -f "$SQLITE_DB" ]; then
    DB_SIZE=$(stat -c%s "$SQLITE_DB" 2>/dev/null || stat -f%z "$SQLITE_DB" 2>/dev/null)
    ok "buckets.db exists (${DB_SIZE} bytes)"
else
    warn "buckets.db NOT found (SQLite migration hasn't run yet)"
fi

# ============================================================================
# 8. SSE (Server-Sent Events)
# ============================================================================
hdr "8. SSE (Real-time Updates)"

# Check if SSE endpoint responds
SSE_TEST=$(timeout 3 curl -s -N http://localhost:8080/sse 2>/dev/null | head -1)
if [ -n "$SSE_TEST" ]; then
    ok "SSE endpoint responding"
else
    warn "SSE endpoint not responding (timeout — may need active connections)"
fi

# ============================================================================
# 9. Static data files
# ============================================================================
hdr "9. Static Data Files"

for f in meta.json swaps.json fleet.json; do
    if [ -f "$DATA_DIR/data/$f" ]; then
        ok "data/$f exists"
    else
        warn "data/$f NOT found (renderToDisk hasn't run yet or failed)"
    fi
done

# ============================================================================
# Summary
# ============================================================================
hdr "SUMMARY"

TOTAL=$((PASS + WARN + FAIL))
echo ""
echo -e "  ${GREEN}Pass: $PASS${NC}  ${YELLOW}Warn: $WARN${NC}  ${RED}Fail: $FAIL${NC}  Total: $TOTAL"
echo ""

if [ $FAIL -gt 0 ]; then
    echo -e "  ${RED}❌ $FAIL issue(s) need attention${NC}"
    if [ $FIX -eq 0 ]; then
        echo "  Run with --fix to auto-fix common issues:"
        echo "    sudo bash $0 --fix"
    fi
    exit 1
elif [ $WARN -gt 0 ]; then
    echo -e "  ${YELLOW}⚠ $WARN warning(s) — system is running but may need attention${NC}"
    exit 0
else
    echo -e "  ${GREEN}✅ All checks passed — pipeline is healthy${NC}"
    exit 0
fi
