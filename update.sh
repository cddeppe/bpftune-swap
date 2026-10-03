#!/bin/bash
# update.sh — bpftune fork updater (atomic, single-file)
#
# Updates the bpftune .deb + Go dashboard collector.
#
# Usage:
#   sudo bash update.sh                # check + upgrade .deb and dashboard
#   sudo bash update.sh --tuner-only    # only update .deb, skip dashboard
#   sudo bash update.sh --dashboard-only # only update dashboard, skip .deb
#   sudo bash update.sh --help
#
# Idempotent: re-running when already up-to-date is a no-op.
# Checks (in order): local /mnt/backup .deb → GitHub releases → skip if not newer.
# Go binary: downloaded from GitHub Releases or built from source (needs Go).

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
DO_TUNER=1
DO_DASHBOARD=1
FORCE_DOWNGRADE=0
SHOW_HELP=0

for arg in "$@"; do
    case "$arg" in
        --tuner-only)       DO_DASHBOARD=0 ;;
        --dashboard-only)   DO_TUNER=0 ;;
        --force-downgrade)  FORCE_DOWNGRADE=1 ;;
        --help|-h)          SHOW_HELP=1 ;;
        *)                  fail "Unknown flag: $arg (try --help)" ;;
    esac
done

if [ "$SHOW_HELP" = 1 ]; then
    awk 'NR==1,/^set -Eeuo pipefail$/' "$0" | sed '$d'
    exit 0
fi

# ---------- Pre-flight ----------
[ "$(id -u)" = "0" ] || fail "Run as root (use: sudo bash update.sh)"
command -v curl      >/dev/null || fail "curl not found"
command -v python3   >/dev/null || fail "python3 not found"
command -v systemctl >/dev/null || fail "systemctl not found"

ARCH=$(dpkg --print-architecture 2>/dev/null || uname -m)
case "$ARCH" in
    amd64|x86_64)  ARCH=amd64 ;;
    arm64|aarch64) ARCH=arm64 ;;
    *) fail "Unsupported architecture: $ARCH" ;;
esac

REPO="${BPFTUNE_REPO:-cddeppe/bpftune-swap}"
BACKUP_DIR="${BPFTUNE_BACKUP_DIR:-/mnt/backup}"
DASH_BIN=/opt/bpftune-dashboard/bin
SERVED=/var/lib/bpftune/history

CURRENT_VER=$(dpkg-query -W -f='${Version}' bpftune 2>/dev/null || echo "not-installed")
printf "${BOLD}=== bpftune fork updater ===${NC}\n"
printf "  arch:           %s\n" "$ARCH"
printf "  current tuner: %s\n" "$CURRENT_VER"
printf "  update tuner:    %s\n" "$([ $DO_TUNER = 1 ] && echo yes || echo 'no (--dashboard-only)')"
printf "  update dashboard: %s\n" "$([ $DO_DASHBOARD = 1 ] && echo yes || echo 'no (--tuner-only)')"

# ---------- Step 1: tuner ----------
if [ "$DO_TUNER" = 1 ]; then
    step "1. Check for newer bpftune .deb"

    LOCAL_DEB=""
    if [ -d "$BACKUP_DIR" ]; then
        LOCAL_DEB=$(ls "$BACKUP_DIR"/bpftune-custom-*-"$ARCH".deb 2>/dev/null | sort -V | tail -1 || true)
    fi

    NEW_VER=""
    DEB_TO_INSTALL=""

    if [ -n "$LOCAL_DEB" ]; then
        NEW_VER=$(dpkg-deb -f "$LOCAL_DEB" Version 2>/dev/null || echo "?")
        DEB_TO_INSTALL="$LOCAL_DEB"
        printf "  found local .deb: %s (%s)\n" "$LOCAL_DEB" "$NEW_VER"
    else
        printf "  no local .deb — checking GitHub releases for %s/%s...\n" "$REPO" "$ARCH"
        DEB_URL=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
            | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for a in d.get('assets', []):
    if '${ARCH}' in a.get('name', '') and 'bpftune-custom' in a.get('name', ''):
        tag = d.get('tag_name', '').lstrip('v')
        if tag:
            print(tag + ' ' + a.get('browser_download_url', ''))
        break
" 2>/dev/null || true)
        if [ -n "$DEB_URL" ]; then
            NEW_VER=$(printf "%s" "$DEB_URL" | awk '{print $1}')
            URL=$(printf "%s" "$DEB_URL" | awk '{print $2}')
            curl -fsSL "$URL" -o /tmp/bpftune-"$ARCH".deb
            DEB_TO_INSTALL=/tmp/bpftune-"$ARCH".deb
            printf "  found GitHub release: %s\n" "$NEW_VER"
        fi
    fi

    if [ -z "$DEB_TO_INSTALL" ]; then
        warn "no .deb found in $BACKUP_DIR or GitHub releases — skipping tuner update"
        if [ "$CURRENT_VER" = "not-installed" ]; then
            fail "bpftune is not installed. Run install.sh first."
        fi
    elif [ "$NEW_VER" = "$CURRENT_VER" ]; then
        ok "already at latest version ($CURRENT_VER) — skipping .deb install"
    elif dpkg --compare-versions "$NEW_VER" lt "$CURRENT_VER" 2>/dev/null; then
        warn "Found $NEW_VER but installed is $CURRENT_VER — this would be a DOWNGRADE"
        if [ "$FORCE_DOWNGRADE" = 1 ]; then
            ok "proceeding with downgrade (--force-downgrade)"
            printf "  downgrading: %s → %s\n" "$CURRENT_VER" "$NEW_VER"
            systemctl stop bpftune 2>/dev/null || true
            if ! dpkg -i "$DEB_TO_INSTALL"; then
                fail "dpkg -i failed — run 'apt-get install -f' then re-run this script"
            fi
            systemctl restart bpftune
            sleep 1
            ok "bpftune downgraded to $(dpkg-query -W -f='${Version}' bpftune)"
        else
            fail "Refusing to downgrade $CURRENT_VER → $NEW_VER without --force-downgrade.
   If you really want to downgrade, re-run with: bash update.sh --force-downgrade"
        fi
    else
        printf "  upgrading: %s → %s\n" "$CURRENT_VER" "$NEW_VER"
        systemctl stop bpftune 2>/dev/null || true
        if ! dpkg -i "$DEB_TO_INSTALL"; then
            fail "dpkg -i failed — run 'apt-get install -f' then re-run this script"
        fi
        systemctl restart bpftune
        sleep 1
        ok "bpftune upgraded to $(dpkg-query -W -f='${Version}' bpftune)"
    fi
fi

# ---------- Step 2: dashboard (Go collector) ----------
if [ "$DO_DASHBOARD" = 1 ]; then
    step "2. Update dashboard (Go collector)"

    if [ ! -d /root/bpftune/.git ]; then
        warn "no /root/bpftune git checkout — run install.sh --dashboard-only to bootstrap"
    else
        cd /root/bpftune
        OLD_HASH=$(git rev-parse --short HEAD 2>/dev/null || echo "?")
        git fetch origin --prune
        git checkout dashboard 2>/dev/null || git checkout -B dashboard origin/dashboard
        if ! git pull --rebase --autostash origin dashboard; then
            warn "git pull --rebase failed — inspect with 'cd /root/bpftune && git status'"
        fi
        NEW_HASH=$(git rev-parse --short HEAD)
        if [ "$OLD_HASH" = "$NEW_HASH" ]; then
            ok "dashboard code already at latest ($NEW_HASH)"
        else
            ok "dashboard code updated: $OLD_HASH → $NEW_HASH"
        fi

        DASH_BIN=/opt/bpftune-dashboard/bin
        SERVED=/var/lib/bpftune/history
        GO_BIN="$DASH_BIN/bpftune-collector-go"
        mkdir -p "$DASH_BIN" "$SERVED/data"

        # --- 2a. Get updated Go binary ---
        BIN_URL="https://github.com/${REPO}/releases/latest/download/bpftune-collector-go-${ARCH}"
        if curl -fsSL "$BIN_URL" -o /tmp/bpftune-collector-go-"$ARCH" 2>/dev/null; then
            # Stop service before swapping binary (avoid "Text file busy")
            systemctl stop bpftune-collector-go 2>/dev/null || true
            sleep 2
            cp /tmp/bpftune-collector-go-"$ARCH" "$GO_BIN"
            chmod +x "$GO_BIN"
            ok "Go binary updated from GitHub Releases"
        elif command -v go >/dev/null 2>&1; then
            printf "  building Go binary from source...\n"
            systemctl stop bpftune-collector-go 2>/dev/null || true
            sleep 2
            cd /root/bpftune/dashboard/bin/go
            CGO_ENABLED=0 go build -ldflags "-X main.dashVersionStr=0.7.5p" -o "$GO_BIN" .
            chmod +x "$GO_BIN"
            ok "Go binary rebuilt from source"
            cd /root/bpftune
        else
            warn "could not update Go binary (no GitHub release, no Go installed) — keeping existing binary"
        fi

        # --- 2b. Deploy frontend files ---
        cp dashboard/bin/dashboard.js dashboard/bin/dashboard.css "$DASH_BIN"/ 2>/dev/null || true
        cp dashboard/bin/index.html "$DASH_BIN"/ 2>/dev/null || true
        cp dashboard/bin/labels-api.py "$DASH_BIN"/ 2>/dev/null || true
        chmod 644 "$DASH_BIN"/*.css "$DASH_BIN"/*.js 2>/dev/null || true
        chmod 755 "$DASH_BIN"/labels-api.py 2>/dev/null || true
        ok "frontend files synced"

        # --- 2c. Handle nginx port 8080 conflict ---
        if command -v nginx >/dev/null 2>&1; then
            if grep -rq 'listen.*8080' /etc/nginx/ 2>/dev/null; then
                rm -f /etc/nginx/conf.d/bpftune-dashboard.conf 2>/dev/null || true
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
                ok "removed nginx 8080 block"
            fi
        fi

        # Kill any lingering process on 8080
        fuser -k 8080/tcp 2>/dev/null || true

        # --- 2d. Start/restart Go collector ---
        systemctl restart bpftune-collector-go 2>/dev/null || systemctl start bpftune-collector-go 2>/dev/null || true
        sleep 5

        if systemctl is-active bpftune-collector-go >/dev/null 2>&1; then
            ok "bpftune-collector-go restarted"
        else
            warn "bpftune-collector-go failed to start — check: journalctl -u bpftune-collector-go -n 30"
        fi

        # --- 2e. Verify ---
        sleep 5
        if curl -fsS http://127.0.0.1:8080/current.json 2>/dev/null \
            | python3 -c "import json,sys; d=json.load(sys.stdin); print(f'  current.json OK, {len(d.get(\"buckets\",[]))} buckets')" 2>/dev/null; then
            ok "dashboard responding on port 8080"
        else
            warn "dashboard not yet responding (first collect takes ~10s)"
        fi
    fi
fi

# ---------- Summary ----------
step "Update Complete"
printf "  bpftune:   %s\n" "$(dpkg-query -W -f='${Version}' bpftune 2>/dev/null || echo 'not installed')"
if [ -d /root/bpftune/.git ]; then
    cd /root/bpftune 2>/dev/null
    printf "  dashboard: %s (branch: %s)\n" \
        "$(git rev-parse --short HEAD 2>/dev/null || echo '?')" \
        "$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?')"
else
    printf "  dashboard: not installed\n"
fi

svc_status() {
    local s
    s=$(systemctl is-active "$1" 2>/dev/null || echo "inactive")
    case "$s" in
        active) ok "$1: active" ;;
        *)      warn "$1: $s" ;;
    esac
}
svc_status bpftune
[ "$DO_DASHBOARD" = 1 ] && [ -d /root/bpftune/.git ] && {
    svc_status bpftune-collector-go
    svc_status bpftune-met-trace
}

printf "\nDone.\n"
