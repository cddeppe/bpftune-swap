#!/bin/bash
# deploy-and-check.sh — One-command deploy + health check for bpftune-swap
# Downloads latest tuner .deb + dashboard binary + dashboard.js, installs
# everything, starts trace capture, sets explore_pct, runs health check.
#
# Usage:
#   sudo bash deploy-and-check.sh                    # deploy latest + check
#   sudo bash deploy-and-check.sh --tuner-only        # just update tuner
#   sudo bash deploy-and-check.sh --dashboard-only    # just update dashboard
#   sudo bash deploy-and-check.sh --check-only        # just health check
#   sudo bash deploy-and-check.sh v0.4.99 v0.9.26     # specific versions
#
set -o pipefail

# ============================================================================
# Config
# ============================================================================
REPO="cddeppe/bpftune-swap"
INSTALL_DIR="/opt/bpftune-dashboard/bin"
DATA_DIR="/var/lib/bpftune/history"
TRACE_PIPE="/sys/kernel/tracing/trace_pipe"
LOG_FILE="/var/log/bpftune-met-live.log"
API_URL="http://localhost:8080"
GITHUB_API="https://api.github.com/repos/$REPO"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

ok()   { echo -e "  ${GREEN}✓${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1"; }
warn() { echo -e "  ${YELLOW}⚠${NC} $1"; }
hdr()  { echo -e "\n${CYAN}=== $1 ===${NC}"; }

# Parse args
TUNER_VERSION=""
DASH_VERSION=""
TUNER_ONLY=0
DASH_ONLY=0
CHECK_ONLY=0

if [ "$1" = "--check-only" ]; then
    CHECK_ONLY=1
elif [ "$1" = "--tuner-only" ]; then
    TUNER_ONLY=1
elif [ "$1" = "--dashboard-only" ]; then
    DASH_ONLY=1
elif [ -n "$1" ]; then
    TUNER_VERSION="$1"
    [ -n "$2" ] && DASH_VERSION="$2"
fi

# ============================================================================
# Detect architecture
# ============================================================================
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64) ARCH_NAME="amd64"; DASH_ASSET="bpftune-dashboard-amd64" ;;
    aarch64|arm64) ARCH_NAME="arm64"; DASH_ASSET="bpftune-dashboard-arm64" ;;
    *) echo "ERROR: Unsupported architecture: $ARCH"; exit 1 ;;
esac

# ============================================================================
# Get latest versions from GitHub if not specified
# ============================================================================
if [ -z "$TUNER_VERSION" ] && [ $CHECK_ONLY -eq 0 ]; then
    hdr "Detecting latest versions"
    LATEST=$(curl -s "$GITHUB_API/releases" | python3 -c "
import json,sys
releases = json.load(sys.stdin)
tuner_ver = None
dash_ver = None
for r in releases:
    tag = r.get('tag_name','')
    if tag.startswith('v0.4.') and not tuner_ver:
        tuner_ver = tag
    if tag.startswith('v0.9.') and not dash_ver:
        dash_ver = tag
    if tuner_ver and dash_ver:
        break
print(f'{tuner_ver or \"none\"} {dash_ver or \"none\"}')
" 2>/dev/null)
    TUNER_VERSION=$(echo "$LATEST" | cut -d' ' -f1)
    DASH_VERSION=$(echo "$LATEST" | cut -d' ' -f2)
    ok "Latest tuner: $TUNER_VERSION"
    ok "Latest dashboard: $DASH_VERSION"
fi

# ============================================================================
# Step 1: Install tuner .deb
# ============================================================================
if [ $CHECK_ONLY -eq 0 ] && [ $DASH_ONLY -eq 0 ]; then
    hdr "1. Installing Tuner ($TUNER_VERSION)"

    CURRENT_VER=$(dpkg-query -W -f='${Version}' bpftune 2>/dev/null || echo "not installed")
    ok "Current tuner version: $CURRENT_VER"

    TARGET_VER=$(echo "$TUNER_VERSION" | sed 's/^v//')
    if [ "$CURRENT_VER" = "$TARGET_VER" ]; then
        ok "Already on $TARGET_VER — skipping tuner install"
    else
        DEB_NAME="bpftune_${TARGET_VER}_${ARCH_NAME}.deb"
        DEB_URL="https://github.com/$REPO/releases/download/$TUNER_VERSION/$DEB_NAME"

        echo "  Downloading $DEB_NAME..."
        if wget -q -O "/tmp/$DEB_NAME" "$DEB_URL"; then
            DEB_SIZE=$(stat -c%s "/tmp/$DEB_NAME" 2>/dev/null || stat -f%z "/tmp/$DEB_NAME" 2>/dev/null)
            ok "Downloaded: ${DEB_SIZE} bytes"

            echo "  Stopping bpftune..."
            systemctl stop bpftune 2>/dev/null
            sleep 2

            echo "  Removing state file (metric semantics change)..."
            rm -f /var/lib/bpftune/tcp_conn_tuner.state

            echo "  Installing .deb..."
            if dpkg -i "/tmp/$DEB_NAME" 2>&1 | grep -q "Setting up\|Unpacking"; then
                ok "Installed $TARGET_VER"
            else
                fail "dpkg install failed"
                dpkg -i "/tmp/$DEB_NAME" 2>&1 | tail -5
            fi

            rm -f "/tmp/$DEB_NAME"
        else
            fail "Download failed: $DEB_URL"
        fi
    fi
fi

# ============================================================================
# Step 2: Install dashboard binary + JS
# ============================================================================
if [ $CHECK_ONLY -eq 0 ] && [ $TUNER_ONLY -eq 0 ]; then
    hdr "2. Installing Dashboard ($DASH_VERSION)"

    mkdir -p "$INSTALL_DIR"

    # Download Go binary
    DASH_URL="https://github.com/$REPO/releases/download/$DASH_VERSION/$DASH_ASSET"
    echo "  Downloading $DASH_ASSET..."
    if wget -q -O "$INSTALL_DIR/bpftune-collector-go.new" "$DASH_URL"; then
        DASH_SIZE=$(stat -c%s "$INSTALL_DIR/bpftune-collector-go.new" 2>/dev/null || stat -f%z "$INSTALL_DIR/bpftune-collector-go.new" 2>/dev/null)
        if [ "$DASH_SIZE" -gt 1000000 ]; then
            chmod +x "$INSTALL_DIR/bpftune-collector-go.new"
            mv "$INSTALL_DIR/bpftune-collector-go.new" "$INSTALL_DIR/bpftune-collector-go"
            ok "Dashboard binary installed: ${DASH_SIZE} bytes"
        else
            fail "Downloaded file too small (${DASH_SIZE} bytes) — download failed"
            rm -f "$INSTALL_DIR/bpftune-collector-go.new"
        fi
    else
        fail "Download failed: $DASH_URL"
    fi

    # Download dashboard.js
    JS_URL="https://github.com/$REPO/releases/download/$DASH_VERSION/dashboard.js"
    echo "  Downloading dashboard.js..."
    if wget -q -O "$INSTALL_DIR/dashboard.js" "$JS_URL"; then
        JS_SIZE=$(stat -c%s "$INSTALL_DIR/dashboard.js" 2>/dev/null || stat -f%z "$INSTALL_DIR/dashboard.js" 2>/dev/null)
        if [ "$JS_SIZE" -gt 10000 ]; then
            ok "dashboard.js installed: ${JS_SIZE} bytes"
        else
            warn "dashboard.js too small (${JS_SIZE} bytes) — keeping existing"
        fi
    else
        warn "dashboard.js download failed — keeping existing version"
    fi

    # Download missing static assets
    for ASSET in index.html dashboard.css chart.umd.min.js chartjs-adapter-date-fns.bundle.min.js; do
        if [ ! -f "$INSTALL_DIR/$ASSET" ]; then
            wget -q -O "$INSTALL_DIR/$ASSET" \
                "https://raw.githubusercontent.com/$REPO/dashboard/dashboard/bin/$ASSET" 2>/dev/null
            [ -s "$INSTALL_DIR/$ASSET" ] && ok "Downloaded missing: $ASSET" || rm -f "$INSTALL_DIR/$ASSET"
        fi
    done
fi

# ============================================================================
# Step 3: Start/restart services
# ============================================================================
if [ $CHECK_ONLY -eq 0 ]; then
    hdr "3. Starting Services"

    # Fix Restart policy
    SERVICE_FILE=$(systemctl show bpftune -p FragmentPath 2>/dev/null | cut -d= -f2)
    if [ -n "$SERVICE_FILE" ] && [ -f "$SERVICE_FILE" ]; then
        if ! grep -q "Restart=always" "$SERVICE_FILE" 2>/dev/null; then
            sed -i 's/Restart=on-failure/Restart=always/' "$SERVICE_FILE" 2>/dev/null
            systemctl daemon-reload
            ok "Fixed: Restart=on-failure → Restart=always"
        fi
    fi

    # Start bpftune
    echo "  Starting bpftune..."
    systemctl restart bpftune 2>/dev/null
    sleep 3
    if systemctl is-active --quiet bpftune; then
        ok "bpftune is active"
        VER=$(dpkg-query -W -f='${Version}' bpftune 2>/dev/null)
        ok "Tuner version: $VER"
    else
        fail "bpftune failed to start"
        journalctl -u bpftune --since '10 sec ago' --no-pager | tail -10
    fi

    # Set explore_pct to 100
    echo "  Setting explore_pct to 100..."
    if [ -f /sys/fs/bpf/bpftune/tcp_conn/explore ]; then
        bpftool map update pinned /sys/fs/bpf/bpftune/tcp_conn/explore \
            key hex 00 00 00 00 value hex 64 00 00 00 2>/dev/null
        EXPLORE=$(bpftool map lookup pinned /sys/fs/bpf/bpftune/tcp_conn/explore \
            key hex 00 00 00 00 2>/dev/null | grep '"value"' | grep -oP '\d+')
        if [ "$EXPLORE" = "100" ]; then
            ok "explore_pct = 100"
        else
            warn "explore_pct = ${EXPLORE:-unknown} (expected 100)"
        fi
    else
        warn "BPF map not pinned yet — explore_pct will be set by bpftune init (default 5)"
        warn "Run this after 5s: bpftool map update pinned /sys/fs/bpf/bpftune/tcp_conn/explore key hex 00 00 00 00 value hex 64 00 00 00"
    fi

    # Install trace capture systemd service (replaces fragile nohup)
    echo "  Installing trace capture service..."
    cat > /etc/systemd/system/bpftune-met-trace.service << TRACEEOF
[Unit]
Description=bpftune trace_pipe capture
After=bpftune.service
Wants=bpftune.service
ConditionPathExists=$TRACE_PIPE

[Service]
Type=simple
ExecStart=/bin/cat $TRACE_PIPE
StandardOutput=file:$LOG_FILE
StandardError=file:$LOG_FILE
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
TRACEEOF

    # Kill old nohup trace capture (don't delete log — trace service will append)
    pkill -f "trace_pipe" 2>/dev/null
    sleep 1

    # Enable and start the trace service
    systemctl daemon-reload
    systemctl enable bpftune-met-trace 2>/dev/null
    systemctl restart bpftune-met-trace
    sleep 3
    if systemctl is-active --quiet bpftune-met-trace; then
        ok "Trace capture service installed and running"
    else
        warn "Trace service failed — falling back to nohup"
        nohup sh -c "cat $TRACE_PIPE" > "$LOG_FILE" 2>&1 &
        sleep 3
    fi

    if [ -f "$LOG_FILE" ]; then
        LOG_SIZE=$(stat -c%s "$LOG_FILE" 2>/dev/null || stat -f%z "$LOG_FILE" 2>/dev/null)
        ok "Log file: $LOG_FILE (${LOG_SIZE} bytes)"
    else
        fail "Log file NOT created"
    fi

    # Install logrotate config
    echo "  Installing logrotate..."
    cat > /etc/logrotate.d/bpftune-met << LOGEOF
$LOG_FILE {
    daily
    rotate 14
    size 100M
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
    create 0644 root root
}
LOGEOF
    ok "Logrotate installed (daily, 100M max, 14 rotations)"

    # Restart dashboard collector
    echo "  Starting dashboard collector..."
    systemctl restart bpftune-collector-go 2>/dev/null
    sleep 5
    if systemctl is-active --quiet bpftune-collector-go; then
        ok "Dashboard collector is active"
    else
        fail "Dashboard collector failed to start"
        journalctl -u bpftune-collector-go --since '10 sec ago' --no-pager | tail -10
    fi

    # Wait for first collect cycle
    echo "  Waiting for first collect cycle (10s)..."
    sleep 10
fi

# ============================================================================
# Step 4: Health Check
# ============================================================================
hdr "4. Health Check"

PASS=0; WARN=0; FAIL=0

# --- BPF ---
BPF_PROG=$(bpftool prog show 2>/dev/null | grep -c "bpftune_conn_tuner")
[ "$BPF_PROG" -ge 1 ] && ok "BPF program loaded ($BPF_PROG)" || { fail "BPF program NOT loaded"; }

bpftool map show name remote_host_map >/dev/null 2>&1 && ok "BPF map: remote_host_map" || fail "BPF map: remote_host_map NOT found"
bpftool map show name sk_storage_map >/dev/null 2>&1 && ok "BPF map: sk_storage_map" || fail "BPF map: sk_storage_map NOT found"

EXPLORE=$(bpftool map lookup pinned /sys/fs/bpf/bpftune/tcp_conn/explore key hex 00 00 00 00 2>/dev/null | grep '"value"' | grep -oP '\d+')
[ "$EXPLORE" = "100" ] && ok "explore_pct = 100" || warn "explore_pct = ${EXPLORE:-unknown}"

CC_COUNT=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | wc -w)
[ "$CC_COUNT" -ge 16 ] && ok "CC algorithms: $CC_COUNT" || warn "CC algorithms: $CC_COUNT (expected 16+)"

# --- bpftune ---
systemctl is-active --quiet bpftune && ok "bpftune: active" || fail "bpftune: NOT active"
VER=$(dpkg-query -W -f='${Version}' bpftune 2>/dev/null)
ok "Tuner version: ${VER:-unknown}"
RESTART=$(systemctl show bpftune -p Restart 2>/dev/null | cut -d= -f2)
[ "$RESTART" = "always" ] && ok "Restart=always" || warn "Restart=${RESTART:-unknown} (should be always)"

# --- Trace capture ---
if [ -f "$LOG_FILE" ]; then
    LOG_SIZE=$(stat -c%s "$LOG_FILE" 2>/dev/null || stat -f%z "$LOG_FILE" 2>/dev/null)
    LOG_AGE=$(($(date +%s) - $(stat -c%Y "$LOG_FILE" 2>/dev/null || stat -f%m "$LOG_FILE" 2>/dev/null)))
    if [ "$LOG_AGE" -lt 60 ]; then
        ok "Log file: ${LOG_SIZE}B, ${LOG_AGE}s ago"
    else
        warn "Log file stale: ${LOG_AGE}s ago"
    fi
    # Count events (fix the grep -c bug)
    for evt in estab met srate swap proof midsamp closport; do
        EVT_COUNT=$(grep -c "$evt cookie=" "$LOG_FILE" 2>/dev/null || true)
        EVT_COUNT=$(echo "$EVT_COUNT" | tail -1)  # take last line if multi-line
        if [ -n "$EVT_COUNT" ] && [ "$EVT_COUNT" -gt 0 ] 2>/dev/null; then
            ok "Log: $EVT_COUNT '$evt' events"
        else
            warn "Log: no '$evt' events"
        fi
    done
else
    fail "Log file NOT found"
fi

pgrep -f trace_pipe >/dev/null 2>&1 && ok "Trace capture: running" || { fail "Trace capture: NOT running"; }

# --- Collector ---
systemctl is-active --quiet bpftune-collector-go && ok "Collector: active" || fail "Collector: NOT active"
[ -x "$INSTALL_DIR/bpftune-collector-go" ] && ok "Binary: exists" || fail "Binary: missing"
[ -f "$INSTALL_DIR/dashboard.js" ] && ok "dashboard.js: exists" || fail "dashboard.js: missing"

# --- current.json ---
CURRENT_JSON=$(curl -s --max-time 5 "$API_URL/current.json" 2>/dev/null)
if [ -n "$CURRENT_JSON" ]; then
    ok "Dashboard: responding"

    NOW_MONO=$(echo "$CURRENT_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('now_mono',0))" 2>/dev/null)
    UPTIME=$(awk '{print $1}' /proc/uptime 2>/dev/null)
    if [ -n "$NOW_MONO" ] && [ -n "$UPTIME" ]; then
        DIFF=$(python3 -c "print(round($UPTIME - $NOW_MONO, 1))" 2>/dev/null)
        DIFF_ABS=${DIFF#-}
        python3 -c "exit(0 if abs($DIFF) < 60 else 1)" 2>/dev/null && ok "now_mono: diff=${DIFF}s" || warn "now_mono drift: ${DIFF}s"
    fi

    BUCKETS=$(echo "$CURRENT_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('buckets',[])))" 2>/dev/null)
    [ -n "$BUCKETS" ] && [ "$BUCKETS" -ge 3 ] 2>/dev/null && ok "Buckets: $BUCKETS" || warn "Buckets: ${BUCKETS:-0} (low)"

    DEGRADED=$(echo "$CURRENT_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('degraded',False))" 2>/dev/null)
    [ "$DEGRADED" = "False" ] && ok "Not degraded" || fail "DEGRADED MODE"

    SWAPS=$(echo "$CURRENT_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('recent_swaps',[])))" 2>/dev/null)
    [ -n "$SWAPS" ] && [ "$SWAPS" -ge 1 ] 2>/dev/null && ok "recent_swaps: $SWAPS" || warn "recent_swaps: empty"

    PROOFS=$(echo "$CURRENT_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('recent_proofs',[])))" 2>/dev/null)
    [ -n "$PROOFS" ] && [ "$PROOFS" -ge 1 ] 2>/dev/null && ok "recent_proofs: $PROOFS" || warn "recent_proofs: empty"

    RATE=$(echo "$CURRENT_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('rate',[])))" 2>/dev/null)
    [ -n "$RATE" ] && [ "$RATE" -ge 1 ] 2>/dev/null && ok "rate: $RATE rows" || warn "rate: empty"

    PROOF_LB=$(echo "$CURRENT_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('proof',[])))" 2>/dev/null)
    [ -n "$PROOF_LB" ] && [ "$PROOF_LB" -ge 1 ] 2>/dev/null && ok "proof leaderboard: $PROOF_LB algs" || warn "proof leaderboard: empty"

    RATE_EMA=$(echo "$CURRENT_JSON" | python3 -c "
import json,sys
d=json.load(sys.stdin)
count=sum(1 for rows in d.get('metric_by_bucket',{}).values() for r in rows if r.get('rate_ema',0)>0)
print(count)
" 2>/dev/null)
    [ -n "$RATE_EMA" ] && [ "$RATE_EMA" -gt 0 ] 2>/dev/null && ok "rate_ema non-zero: $RATE_EMA algs" || warn "rate_ema: all zero (app-limited)"

    TUNER_VER=$(echo "$CURRENT_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('build',{}).get('version','?'))" 2>/dev/null)
    DASH_VER=$(echo "$CURRENT_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('build',{}).get('dash_version','?'))" 2>/dev/null)
    ok "Versions: tuner=$TUNER_VER dashboard=$DASH_VER"
else
    fail "Dashboard: NOT responding"
fi

# --- CSV files ---
for csv in swaps.csv proofs.csv buckets.v2.csv srate.csv midsamp.csv; do
    [ -f "$DATA_DIR/$csv" ] && ok "$csv: exists" || warn "$csv: NOT found"
done

# --- SQLite ---
[ -f "$DATA_DIR/buckets.db" ] && ok "SQLite: exists" || warn "SQLite: NOT found"

# --- SSE ---
timeout 3 curl -s -N "$API_URL/sse" 2>/dev/null | head -1 | grep -q . && ok "SSE: responding" || warn "SSE: no response"

# --- Static files ---
for f in meta.json swaps.json fleet.json; do
    [ -f "$DATA_DIR/data/$f" ] && ok "data/$f: exists" || warn "data/$f: NOT found"
done

# ============================================================================
# Summary
# ============================================================================
hdr "SUMMARY"
echo ""
echo -e "  ${GREEN}Pass: $PASS${NC}  ${YELLOW}Warn: $WARN${NC}  ${RED}Fail: $FAIL${NC}"
echo ""

if [ $FAIL -gt 0 ]; then
    echo -e "  ${RED}❌ $FAIL issue(s) need attention${NC}"
    exit 1
elif [ $WARN -gt 0 ]; then
    echo -e "  ${YELLOW}⚠ $WARN warning(s)${NC}"
    exit 0
else
    echo -e "  ${GREEN}✅ All checks passed${NC}"
    exit 0
fi
