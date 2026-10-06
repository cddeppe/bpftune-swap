#!/bin/bash
# deploy-this-host.sh — atomic per-host deploy of bpftune 0.4.94 + dashboard v0.9.0
#
# Run ON the host you want to update (root required):
#   sudo bash deploy-this-host.sh
#
# Optional flags:
#   --tuner-only        Skip dashboard (Go binary) update
#   --dashboard-only    Skip .deb (tuner) update
#   --clean-state        Wipe tcp_conn_tuner.state before restart (loses
#                        accumulated learning — use only if 0.0.0.0
#                        bucket persists after deploy)
#
# Prereqs:
#   - /mnt/backup/ mounted (NFS-shared between all hosts)
#   - /root/bpftune git checkout (for update.sh which we don't use here,
#     but the dashboard frontend files come from this checkout)
#
# This script is intentionally minimal — no SSH, no fleet loop, no orchestration.
# Just one host, one shot.

set -Eeuo pipefail

G='\033[0;32m'; R='\033[0;31m'; Y='\033[0;33m'; B='\033[1m'; N='\033[0m'
ok()   { printf "${G}✓${N} %s\n" "$1"; }
fail() { printf "${R}✗${N} %s\n" "$1" >&2; exit 1; }
warn() { printf "${Y}!${N} %s\n" "$1"; }
step() { printf "\n${B}== %s ==${N}\n" "$1"; }

trap 'fail "Aborted at line $LINENO (exit code $?)"' ERR

# ---------- Args ----------
DO_TUNER=1
DO_DASHBOARD=1
CLEAN_STATE=0
for arg in "$@"; do
    case "$arg" in
        --tuner-only)       DO_TUNER=0; DO_DASHBOARD=0; DO_TUNER=1 ;;
        --dashboard-only)   DO_TUNER=0; DO_DASHBOARD=0; DO_DASHBOARD=1 ;;
        --clean-state)      CLEAN_STATE=1 ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) fail "Unknown arg: $arg (try --help)" ;;
    esac
done

# ---------- Pre-flight ----------
[ "$(id -u)" = "0" ] || fail "Run as root: sudo bash $0"

ARCH=$(dpkg --print-architecture 2>/dev/null || uname -m)
case "$ARCH" in
    amd64|x86_64)  ARCH=amd64 ;;
    arm64|aarch64) ARCH=arm64 ;;
    *) fail "Unsupported arch: $ARCH" ;;
esac

EXPECTED_TUNER_VER="0.4.94"
BACKUP_DIR="/mnt/backup"

printf "${B}=== bpftune deploy-this-host ===${N}\n"
printf "  arch:           %s\n" "$ARCH"
printf "  expected tuner: %s\n" "$EXPECTED_TUNER_VER"
printf "  update tuner:    %s\n" "$([ $DO_TUNER = 1 ] && echo yes || echo 'no (--dashboard-only)')"
printf "  update dashboard: %s\n" "$([ $DO_DASHBOARD = 1 ] && echo yes || echo 'no (--tuner-only)')"
printf "  clean state:     %s\n" "$([ $CLEAN_STATE = 1 ] && echo yes || echo no)"

CURRENT_TUNER_VER=$(dpkg-query -W -f='${Version}' bpftune 2>/dev/null || echo "not-installed")
printf "  current tuner:  %s\n" "$CURRENT_TUNER_VER"

# ---------- Step 1: tuner (.deb) ----------
if [ "$DO_TUNER" = 1 ]; then
    step "1. Update tuner (.deb)"

    DEB="$BACKUP_DIR/bpftune-custom-${EXPECTED_TUNER_VER}-${ARCH}.deb"
    [ -f "$DEB" ] || fail "missing $DEB (build on $ARCH builder first)"

    # Check for downgrade — by default refuse, allow with --force-downgrade
    if [ "$CURRENT_TUNER_VER" != "not-installed" ]; then
        if dpkg --compare-versions "$EXPECTED_TUNER_VER" lt "$CURRENT_TUNER_VER" 2>/dev/null; then
            warn "this would be a DOWNGRADE: $CURRENT_TUNER_VER → $EXPECTED_TUNER_VER"
            for arg in "$@"; do
                [ "$arg" = "--force-downgrade" ] && break
            done
            if [ "$arg" != "--force-downgrade" ]; then
                fail "refusing downgrade without --force-downgrade"
            fi
            ok "proceeding with downgrade (--force-downgrade)"
        fi
    fi

    # Stop bpftune before installing (avoid "Text file busy" on the .so files)
    systemctl stop bpftune 2>/dev/null || true

    # Optional: clean state (v0.4.94 changes bucketing — old :: entries
    # will be orphaned, but harmless and age out in ~24h)
    if [ "$CLEAN_STATE" = 1 ]; then
        warn "wiping /var/lib/bpftune/tcp_conn_tuner.state (loses learning)"
        rm -f /var/lib/bpftune/tcp_conn_tuner.state
    fi

    if ! dpkg -i "$DEB"; then
        fail "dpkg -i failed — fix with: apt-get install -f && sudo bash $0"
    fi

    # Restart bpftune
    systemctl daemon-reload
    systemctl restart bpftune
    sleep 1
    if systemctl is-active --quiet bpftune; then
        ok "bpftune running: $(dpkg-query -W -f='${Version}' bpftune)"
    else
        fail "bpftune failed to start — check: journalctl -u bpftune -n 30"
    fi
fi

# ---------- Step 2: dashboard (Go binary + frontend) ----------
if [ "$DO_DASHBOARD" = 1 ]; then
    step "2. Update dashboard (Go binary + frontend)"

    GO_BIN="/opt/bpftune-dashboard/bin/bpftune-collector-go"
    NEW_BIN="$BACKUP_DIR/bpftune-collector-go-${ARCH}"
    [ -f "$NEW_BIN" ] || fail "missing $NEW_BIN (build on $ARCH builder first)"

    # Verify the binary actually runs on this host before swapping
    # (catches arch mismatch — e.g. arm64 binary on amd64 host)
    if ! "$NEW_BIN" --help >/dev/null 2>&1; then
        fail "$NEW_BIN doesn't run on this host — arch mismatch? Try: file $NEW_BIN"
    fi
    ok "binary runs on this host ($ARCH)"

    # Stop service before swapping (avoid "Text file busy")
    systemctl stop bpftune-collector-go 2>/dev/null || true
    sleep 2

    mkdir -p "$(dirname "$GO_BIN")"
    cp "$NEW_BIN" "$GO_BIN.tmp"
    mv -f "$GO_BIN.tmp" "$GO_BIN"
    chmod 755 "$GO_BIN"
    ok "Go binary installed: $GO_BIN"

    # Sync frontend files from /root/bpftune/dashboard/bin/ if the
    # git checkout exists. The Go binary needs index.html, dashboard.js,
    # dashboard.css alongside it.
    REPO_DIR="${REPO_DIR:-/root/bpftune}"
    if [ -d "$REPO_DIR/.git" ]; then
        cd "$REPO_DIR"
        git fetch origin --no-tags --prune 2>&1 | tail -3
        git checkout dashboard 2>&1 | tail -1
        git pull --ff-only origin dashboard 2>&1 | tail -2

        for f in dashboard.js dashboard.css index.html labels-api.py; do
            src="$REPO_DIR/dashboard/bin/$f"
            dst="$(dirname "$GO_BIN")/$f"
            [ -f "$src" ] && cp "$src" "$dst" && chmod $([ "$f" = "labels-api.py" ] && echo 755 || echo 644) "$dst"
        done
        ok "frontend files synced from $REPO_DIR"

        # Also symlink index.html into /var/lib/bpftune/history/ (where
        # the Go collector serves it from)
        HIST_DIR="/var/lib/bpftune/history"
        mkdir -p "$HIST_DIR/data"
        for f in dashboard.js dashboard.css index.html; do
            src="$(dirname "$GO_BIN")/$f"
            dst="$HIST_DIR/$f"
            [ -f "$src" ] && {
                [ -L "$dst" -o -f "$dst" ] && rm -f "$dst"
                ln -sf "$src" "$dst"
            }
        done
        ok "symlinks created in $HIST_DIR"
    else
        warn "$REPO_DIR is not a git checkout — skipping frontend sync"
        warn "the Go binary will use whatever frontend files are already in $(dirname $GO_BIN)"
    fi

    # Restart the collector
    systemctl daemon-reload
    systemctl restart bpftune-collector-go || systemctl start bpftune-collector-go
    sleep 3

    if systemctl is-active --quiet bpftune-collector-go; then
        ok "bpftune-collector-go running"
    else
        fail "bpftune-collector-go failed to start — check: journalctl -u bpftune-collector-go -n 30"
    fi
fi

# ---------- Step 3: verify ----------
step "3. Verify"

echo "  bpftune service:    $(systemctl is-active bpftune 2>/dev/null || echo inactive)"
echo "  bpftune version:    $(dpkg-query -W -f='${Version}' bpftune 2>/dev/null || echo not-installed)"
echo "  dashboard service: $(systemctl is-active bpftune-collector-go 2>/dev/null || echo inactive)"

# Quick HTTP check if the dashboard is supposed to be running
if systemctl is-active --quiet bpftune-collector-go; then
    if curl -fsS --max-time 5 http://127.0.0.1:8080/current.json >/dev/null 2>&1; then
        ok "dashboard responds on :8080"
    else
        warn "dashboard not responding on :8080 (may be normal if --port was customized)"
    fi
fi

# Truth file checks
TRUTH="/var/lib/bpftune/history/swapscore_truth.jsonl"
if [ -f "$TRUTH" ]; then
    TOTAL=$(wc -l < "$TRUTH" | tr -d ' ')
    # grep -c returns exit code 1 when count is 0, which under `set -e`
    # would fail the script. Use `|| true` to swallow the exit code,
    # then default to 0 if empty (the `|| echo 0` form was producing
    # "0\n0" multi-line values that broke `[ -gt 0 ]`).
    IPV6=$(grep -c '"dest":"[^"]*:' "$TRUTH" 2>/dev/null || true)
    IPV6=${IPV6:-0}
    IPV6=$(echo "$IPV6" | head -1)
    echo "  truth file rows:    $TOTAL"
    echo "  IPv6 truth rows:    $IPV6  (was 0 before v0.9.0)"
    if [ "$IPV6" -gt 0 ] 2>/dev/null; then
        ok "IPv6 swaps now being tracked (the dashboard v0.9.0 fix is working)"
    else
        warn "no IPv6 truth rows yet — may take a few minutes for IPv6 traffic to swap"
    fi
fi

# Cookie→dest persistence file (new in v0.9.0)
CDEST="/var/lib/bpftune/history/cookie_dest.json"
if [ -f "$CDEST" ]; then
    N=$(wc -l < "$CDEST")
    ok "cookie_dest.json present ($N bytes — populated by v0.9.0 collector)"
else
    warn "cookie_dest.json not yet present — collector will create it on first cycle (30s)"
fi

echo
printf "${B}=== deploy complete ===${N}\n"
echo
echo "Next: open the dashboard at http://$(hostname):8080/ and check the proofs panel."
echo "      Dest labels should now show real IPs/hostnames — no more dash."
echo
echo "If the 0.0.0.0 mystery bucket persists after 24h, re-run with --clean-state:"
echo "  sudo bash $0 --clean-state"
echo "  (this wipes accumulated learning — only do if absolutely needed)"
