#!/bin/bash
# install.sh — bpftune fork installer (atomic, single-file)
#
# Installs the bpftune kernel module (.deb) + optional Go dashboard collector.
# The Go collector serves everything on port 8080 directly (no nginx needed).
#
# Usage:
#   sudo bash install.sh                 # interactive: asks about dashboard
#   sudo bash install.sh --yes            # non-interactive, defaults to dashboard=yes
#   sudo bash install.sh --no-dashboard   # tuner only, no dashboard
#   sudo bash install.sh --dashboard-only # dashboard only, skip .deb
#   sudo bash install.sh --help
#
# Idempotent: re-running upgrades in place rather than breaking the install.
# Works on: Debian / Ubuntu on amd64 or arm64.
# Dashboard binary: pre-built from GitHub Releases or built from source (needs Go).

set -Eeuo pipefail

# ---------- Pretty output ----------
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

ok()    { printf "${GREEN}✓${NC} %s\n" "$1"; }
fail()  { printf "${RED}✗${NC} %s\n" "$1" >&2; exit 1; }
warn()  { printf "${YELLOW}!${NC} %s\n" "$1"; }
step()  { printf "\n${BOLD}== %s ==${NC}\n" "$1"; }

trap 'fail "Aborted at line $LINENO (exit code $?)"' ERR

# ---------- Parse args ----------
DASHBOARD_UNSPECIFIED=1
DASHBOARD=1
DEB_INSTALL=1
ASSUME_YES=0
FORCE_DOWNGRADE=0
SHOW_HELP=0

for arg in "$@"; do
    case "$arg" in
        --no-dashboard)    DASHBOARD_UNSPECIFIED=0; DASHBOARD=0; DEB_INSTALL=1 ;;
        --dashboard-only)  DASHBOARD_UNSPECIFIED=0; DASHBOARD=1; DEB_INSTALL=0 ;;
        --yes|-y)          ASSUME_YES=1 ;;
        --force-downgrade) FORCE_DOWNGRADE=1 ;;
        --help|-h)         SHOW_HELP=1 ;;
        *)                 fail "Unknown flag: $arg (try --help)" ;;
    esac
done

if [ "$SHOW_HELP" = 1 ]; then
    awk 'NR==1,/^set -Eeuo pipefail$/' "$0" | sed '$d'
    exit 0
fi

# ---------- Pre-flight ----------
[ "$(id -u)" = "0" ] || fail "Run as root (use: sudo bash install.sh)"
command -v curl    >/dev/null || fail "curl not found (apt-get install curl)"
command -v python3 >/dev/null || fail "python3 not found (apt-get install python3)"
command -v dpkg    >/dev/null || fail "dpkg not found — this script targets Debian/Ubuntu"
command -v systemctl >/dev/null || fail "systemctl not found — needs systemd"

ARCH=$(dpkg --print-architecture 2>/dev/null || uname -m)
case "$ARCH" in
    amd64|x86_64) ARCH=amd64 ;;
    arm64|aarch64) ARCH=arm64 ;;
    *) fail "Unsupported architecture: $ARCH" ;;
esac

HAVE_NGINX=0; command -v nginx >/dev/null && HAVE_NGINX=1
HAVE_GIT=0;   command -v git   >/dev/null && HAVE_GIT=1 || warn "git not found — dashboard install needs git"

REPO="${BPFTUNE_REPO:-cddeppe/bpftune-swap-swap}"
BACKUP_DIR="${BPFTUNE_BACKUP_DIR:-/mnt/backup}"

printf "\n${BOLD}=== bpftune fork installer ===${NC}\n"
printf "  arch:            %s\n" "$ARCH"
printf "  install .deb:    %s\n" "$([ $DEB_INSTALL = 1 ] && echo yes || echo 'no (--dashboard-only)')"
printf "  dashboard:       %s\n" "$([ $DASHBOARD = 1 ] && echo yes || echo 'no (--no-dashboard)')"
printf "  non-interactive: %s\n" "$([ $ASSUME_YES = 1 ] && echo yes || echo no)"
printf "  nginx present:   %s\n" "$([ $HAVE_NGINX = 1 ] && echo yes || echo 'no (will skip)')"
printf "  git present:      %s\n" "$([ $HAVE_GIT = 1 ] && echo yes || echo 'no')"
[ "$HAVE_GIT" = 0 ] && [ "$DASHBOARD" = 1 ] && fail "git is required for dashboard install"

# ---------- Step 1: install/upgrade bpftune .deb ----------
if [ "$DEB_INSTALL" = 1 ]; then
    step "1. Install bpftune (.deb)"

    ALREADY_INSTALLED=0
    if dpkg-query -W -f='${Status}' bpftune 2>/dev/null | grep -q "install ok installed"; then
        ALREADY_INSTALLED=1
        CURRENT_VER=$(dpkg-query -W -f='${Version}' bpftune)
        warn "bpftune $CURRENT_VER already installed"
        if [ "$ASSUME_YES" = 1 ]; then
            REPLY=n
        else
            printf "  Reinstall/upgrade? [y/N] "
            read -r REPLY; REPLY="${REPLY:-n}"
        fi
        if [[ ! "$REPLY" =~ ^[Yy]$ ]]; then
            ok "skipping .deb install (keeping $CURRENT_VER)"
        else
            _DO_DEB=1
        fi
    else
        _DO_DEB=1
    fi

    if [ "${_DO_DEB:-0}" = 1 ]; then
        DEB=""
        if [ -d "$BACKUP_DIR" ]; then
            DEB=$(ls "$BACKUP_DIR"/bpftune-custom-*-"$ARCH".deb 2>/dev/null | sort -V | tail -1 || true)
        fi

        if [ -z "$DEB" ]; then
            printf "  No local .deb — querying GitHub releases for %s/%s...\n" "$REPO" "$ARCH"
            DEB_URL=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
                | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for a in d.get('assets', []):
    if '${ARCH}' in a.get('name', '') and 'bpftune-custom' in a.get('name', ''):
        print(a.get('browser_download_url', ''))
        break
" 2>/dev/null || true)
            if [ -n "$DEB_URL" ]; then
                curl -fsSL "$DEB_URL" -o /tmp/bpftune-"$ARCH".deb
                DEB=/tmp/bpftune-"$ARCH".deb
                ok "downloaded .deb from GitHub"
            else
                fail "No .deb available. Either:
   (a) build on the builder host:
       cd /root/bpftune && git pull && sudo dpkg-buildpackage -b -us -uc
   (b) create a GitHub release with the .deb assets
   (c) place a bpftune-custom-*-${ARCH}.deb in ${BACKUP_DIR}/"
            fi
        fi

        NEW_VER=$(dpkg-deb -f "$DEB" Version 2>/dev/null || echo "?")

        SKIP_DOWNGRADE=0
        if [ "$ALREADY_INSTALLED" = 1 ] && dpkg --compare-versions "$NEW_VER" lt "$CURRENT_VER" 2>/dev/null; then
            warn "Found $NEW_VER but installed is $CURRENT_VER — this would be a DOWNGRADE"
            if [ "$FORCE_DOWNGRADE" = 1 ]; then
                ok "proceeding with downgrade (--force-downgrade)"
            elif [ "$ASSUME_YES" = 1 ]; then
                warn "--yes implies no downgrade — skipping"
                SKIP_DOWNGRADE=1
            else
                printf "  Proceed with downgrade? [y/N] "
                read -r REPLY; REPLY="${REPLY:-n}"
                [[ "$REPLY" =~ ^[Yy]$ ]] || SKIP_DOWNGRADE=1
            fi
        fi

        if [ "$SKIP_DOWNGRADE" = 1 ]; then
            ok "keeping installed version $CURRENT_VER"
        else
            printf "  installing %s\n" "$NEW_VER"
            systemctl stop bpftune 2>/dev/null || true
            if ! dpkg -i "$DEB"; then
                fail "dpkg -i failed — fix apt with 'apt-get install -f' and re-run"
            fi
            systemctl restart bpftune
            ok "bpftune $(dpkg-query -W -f='${Version}' bpftune) installed and started"
        fi
    fi
fi

# ---------- Step 2: optional prompt (only if unspecified) ----------
if [ "$DASHBOARD_UNSPECIFIED" = 1 ] && [ "$DASHBOARD" = 1 ] && [ "$ASSUME_YES" = 0 ]; then
    printf "\n  Install dashboard? [Y/n] "
    read -r REPLY; REPLY="${REPLY:-y}"
    [[ "$REPLY" =~ ^[Nn]$ ]] && DASHBOARD=0
fi

# ---------- Step 3: dashboard (Go collector) ----------
if [ "$DASHBOARD" = 1 ]; then
    step "2. Install dashboard (Go collector)"

    DASH_BIN=/opt/bpftune-dashboard/bin
    SERVED=/var/lib/bpftune/history

    # --- 3a. git clone or update (for frontend files + Go source) ---
    if [ -d /root/bpftune/.git ]; then
        cd /root/bpftune
        git fetch origin --prune
        git checkout dashboard 2>/dev/null || git checkout -B dashboard origin/dashboard
        git pull --rebase --autostash
        ok "git checkout updated (branch: dashboard)"
    else
        rm -rf /root/bpftune
        git clone --branch dashboard --depth 50 https://github.com/${REPO} /root/bpftune
        cd /root/bpftune
        ok "git cloned (branch: dashboard)"
    fi
    DASH_HASH=$(git rev-parse --short HEAD)
    printf "  head: %s\n" "$DASH_HASH"

    # --- 3b. Get the Go binary (try GitHub Releases first, then build from source) ---
    GO_BIN="$DASH_BIN/bpftune-collector-go"
    mkdir -p "$DASH_BIN"

    # Try to download pre-built binary from GitHub Releases
    BIN_URL="https://github.com/${REPO}/releases/latest/download/bpftune-collector-go-${ARCH}"
    if curl -fsSL "$BIN_URL" -o /tmp/bpftune-collector-go-"$ARCH" 2>/dev/null; then
        cp /tmp/bpftune-collector-go-"$ARCH" "$GO_BIN"
        chmod +x "$GO_BIN"
        ok "downloaded Go binary from GitHub Releases ($ARCH)"
    elif [ -f "$BACKUP_DIR/bpftune-collector-go-$ARCH" ]; then
        cp "$BACKUP_DIR/bpftune-collector-go-$ARCH" "$GO_BIN"
        chmod +x "$GO_BIN"
        ok "copied Go binary from $BACKUP_DIR"
    elif command -v go >/dev/null 2>&1; then
        printf "  building Go binary from source...\n"
        cd /root/bpftune/dashboard/bin/go
        CGO_ENABLED=0 go build -ldflags "-X main.dashVersionStr=0.7.5p" -o "$GO_BIN" .
        chmod +x "$GO_BIN"
        ok "built Go binary from source"
        cd /root/bpftune
    else
        fail "Could not get Go binary. Options:
   (a) Create a GitHub release with bpftune-collector-go-{amd64,arm64} assets
   (b) Install Go: apt-get install -y golang-go && re-run install.sh
   (c) Pre-build on another host and copy to $BACKUP_DIR/bpftune-collector-go-$ARCH"
    fi

    # --- 3c. Deploy frontend files ---
    cp dashboard/bin/dashboard.js dashboard/bin/dashboard.css "$DASH_BIN"/ 2>/dev/null || true
    cp dashboard/bin/index.html "$DASH_BIN"/ 2>/dev/null || true
    cp dashboard/bin/labels-api.py "$DASH_BIN"/ 2>/dev/null || true
    chmod 644 "$DASH_BIN"/*.css "$DASH_BIN"/*.js 2>/dev/null || true
    chmod 755 "$DASH_BIN"/labels-api.py 2>/dev/null || true
    ok "frontend files deployed to $DASH_BIN"

    # --- 3d. Handle nginx port 8080 conflict (if present) ---
    if [ "$HAVE_NGINX" = 1 ]; then
        if grep -rq 'listen.*8080' /etc/nginx/ 2>/dev/null; then
            warn "nginx has a server block on port 8080 — removing (conflicts with Go collector)"
            # Remove any 8080 server block from nginx.conf
            python3 - <<'NGINX_CLEANUP'
import re, sys
path = "/etc/nginx/nginx.conf"
try:
    s = open(path).read()
except:
    sys.exit(0)
for anchor in ["listen 0.0.0.0:8080", "listen 8080"]:
    idx = s.find(anchor)
    if idx != -1:
        break
else:
    sys.exit(0)
server_start = s.rfind("server {", 0, idx)
if server_start == -1:
    sys.exit(0)
brace_start = s.find("{", server_start)
depth = 0; i = brace_start; end = None
while i < len(s):
    if s[i] == "{": depth += 1
    elif s[i] == "}":
        depth -= 1
        if depth == 0: end = i + 1; break
    i += 1
if end is None:
    sys.exit(0)
line_start = s.rfind("\n", 0, server_start) + 1
s = s[:line_start] + s[end:]
s = re.sub(r"\n\n\n+", "\n\n", s)
open(path, "w").write(s)
NGINX_CLEANUP
            nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null || true
            ok "nginx 8080 block removed"
        else
            ok "nginx present, no 8080 conflict"
        fi
    fi

    # Kill any lingering process on port 8080
    fuser -k 8080/tcp 2>/dev/null || true

    # --- 3f. Install Go collector systemd service ---
    cat > /etc/systemd/system/bpftune-collector-go.service <<EOF
[Unit]
Description=bpftune dashboard collector (Go) — replaces Python collector
After=network.target bpftune.service
Wants=bpftune.service

[Service]
Type=simple
ExecStart=$DASH_BIN/bpftune-collector-go --port 8080 --bind 0.0.0.0
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
ProtectSystem=full
ReadWritePaths=/var/lib/bpftune
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable bpftune-collector-go
    ok "bpftune-collector-go.service installed + enabled"

    # --- 3g. Ensure bpftune-met-trace service (trace_pipe capture) ---
    if ! systemctl is-enabled bpftune-met-trace 2>/dev/null | grep -q enabled; then
        cat > /etc/systemd/system/bpftune-met-trace.service <<'EOF'
[Unit]
Description=bpftune trace_pipe capture to /var/log/bpftune-met-live.log
After=bpftune.service
Wants=bpftune.service

[Service]
Type=simple
ExecStart=/bin/sh -c 'while true; do cat /sys/kernel/tracing/trace_pipe >> /var/log/bpftune-met-live.log 2>&1; sleep 0.1; done'
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable --now bpftune-met-trace 2>/dev/null || true
        ok "bpftune-met-trace.service installed (trace_pipe capture)"
    else
        ok "bpftune-met-trace.service already running"
    fi

    # --- 3h. Remove old render cron (Go collector renders internally) ---
    rm -f /etc/cron.d/bpftune-history 2>/dev/null || true
    ok "removed old render cron (Go collector handles rendering every 5 min)"

    # --- 3i. Keep state backup cron ---
    cat > /etc/cron.d/bpftune-state-backup <<'EOF'
# managed by bpftune install.sh
0 3 * * * root cp /var/lib/bpftune/tcp_conn_tuner.state /mnt/backup/tcp_conn_tuner.state.$(date +\%A) 2>/dev/null || true
EOF
    chmod 644 /etc/cron.d/bpftune-state-backup
    ok "state backup cron configured (3am daily)"

    # --- 3j. Start Go collector + verify ---
    mkdir -p "$SERVED/data"
    systemctl start bpftune-collector-go
    sleep 5

    if systemctl is-active bpftune-collector-go >/dev/null 2>&1; then
        ok "bpftune-collector-go is running"
    else
        fail "bpftune-collector-go failed to start — check: journalctl -u bpftune-collector-go -n 30"
    fi

    sleep 5
    if curl -fsS http://127.0.0.1:8080/current.json 2>/dev/null \
        | python3 -c "import json,sys; d=json.load(sys.stdin); print(f'  current.json OK, {len(d.get(\"buckets\",[]))} buckets')" 2>/dev/null; then
        ok "dashboard responding on port 8080"
    else
        warn "dashboard not yet responding (first collect takes ~10s — retry in a moment)"
    fi
fi

# ---------- Summary ----------
step "Installation Summary"
printf "  bpftune version: %s\n" "$(dpkg-query -W -f='${Version}' bpftune 2>/dev/null || echo 'not installed')"
printf "  arch:            %s\n" "$ARCH"

svc_status() {
    local s
    s=$(systemctl is-active "$1" 2>/dev/null || echo "inactive")
    case "$s" in
        active)   ok "$1: active" ;;
        inactive|failed) warn "$1: $s" ;;
        *)        warn "$1: $s" ;;
    esac
}
svc_status bpftune
if [ "$DASHBOARD" = 1 ]; then
    svc_status bpftune-collector-go
    svc_status bpftune-met-trace
    ok "dashboard URL: http://$(hostname -I 2>/dev/null | awk '{print $1}' || hostname):8080/"
fi

printf "\nDone.\n"
