#!/bin/bash
# update.sh - bpftune fork updater (atomic, single-file)
#
# Updates the bpftune .deb + Go dashboard collector from GitHub Releases.
#
# Usage:
#   sudo bash update.sh                   # check + upgrade .deb and dashboard
#   sudo bash update.sh --tuner-only       # only update .deb, skip dashboard
#   sudo bash update.sh --dashboard-only   # only update dashboard, skip .deb
#   sudo bash update.sh --clean-state      # also wipe tcp_conn_tuner.state before restart
#   sudo bash update.sh --help
#
# Idempotent: re-running when already up-to-date is a no-op.
# Always downloads from GitHub Releases (never /mnt/backup/).
# Bootstrap-safe: if /root/bpftune doesn't exist, clones it from GitHub.
# Force-push-safe: uses `git fetch + git reset --hard` instead of `git pull --rebase`
#                  so a force-push on the remote dashboard branch doesn't break updates.
#
# Remote one-shot (matches README):
#   curl -fsSL https://raw.githubusercontent.com/cddeppe/bpftune-swap/main/update.sh | sudo bash
#   curl -fsSL https://raw.githubusercontent.com/cddeppe/bpftune-swap/main/update.sh | sudo bash -s -- --dashboard-only
#
#   NOTE: do NOT use `sudo bash <(curl ...)` process substitution -
#   sudo closes fd >= 3 by default, so /dev/fd/63 doesn't exist
#   inside the bash that sudo launches. The pipe form above is correct.
# Optional env overrides:
#   BPFTUNE_REPO=cddeppe/bpftune-swap   (default; for forks)
#   BPFTUNE_BRANCH=dashboard             (default; for forks using different branch name)

set -Eeuo pipefail

# ---------- Pretty output ----------
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BOLD='\033[0;1m'
NC='\033[0m'

ok()    { printf "${GREEN}OK${NC} %s\n" "$1"; }
fail()  { printf "${RED}FAIL${NC} %s\n" "$1" >&2; exit 1; }
warn()  { printf "${YELLOW}!${NC} %s\n" "$1"; }
step()  { printf "\n${BOLD}== %s ==${NC}\n" "$1"; }

trap 'fail "Aborted at line $LINENO (exit code $?)"' ERR

# ---------- Parse args ----------
DO_TUNER=1
DO_DASHBOARD=1
FORCE_DOWNGRADE=0
CLEAN_STATE=0
SHOW_HELP=0

for arg in "$@"; do
    case "$arg" in
        --tuner-only)       DO_DASHBOARD=0 ;;
        --dashboard-only)   DO_TUNER=0 ;;
        --force-downgrade)  FORCE_DOWNGRADE=1 ;;
        --clean-state)      CLEAN_STATE=1 ;;
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
BRANCH="${BPFTUNE_BRANCH:-dashboard}"
DASH_BIN=/opt/bpftune-dashboard/bin
SERVED=/var/lib/bpftune/history

CURRENT_VER=$(dpkg-query -W -f='${Version}' bpftune 2>/dev/null || echo "not-installed")
printf "${BOLD}=== bpftune fork updater ===${NC}\n"
printf "  repo:           %s\n" "$REPO"
printf "  arch:           %s\n" "$ARCH"
printf "  current tuner:  %s\n" "$CURRENT_VER"
printf "  update tuner:    %s\n" "$([ $DO_TUNER = 1 ] && echo yes || echo 'no (--dashboard-only)')"
printf "  update dashboard: %s\n" "$([ $DO_DASHBOARD = 1 ] && echo yes || echo 'no (--tuner-only)')"

# =====================================================================
# Helper: bootstrap /root/bpftune if missing.
# v0.9.104 fix: previous version SKIPPED the entire dashboard update
# if /root/bpftune/.git didn't exist. Now we clone it instead.
# =====================================================================
ensure_git_checkout() {
    if [ ! -d /root/bpftune/.git ]; then
        step "0. Bootstrap /root/bpftune (first run on this host)"
        if command -v git >/dev/null 2>&1; then
            printf "  cloning %s (branch %s)...\n" "$REPO" "$BRANCH"
            if git clone --branch "$BRANCH" --depth 1 \
                    "https://github.com/${REPO}" /root/bpftune; then
                ok "cloned to /root/bpftune"
            else
                # Branch may not exist on this fork's remote — try main.
                warn "branch $BRANCH not found, falling back to main"
                if git clone --depth 1 "https://github.com/${REPO}" /root/bpftune; then
                    ( cd /root/bpftune && git checkout "$BRANCH" 2>/dev/null || git checkout main 2>/dev/null || true )
                    ok "cloned to /root/bpftune"
                else
                    fail "git clone failed - check network and repo URL"
                fi
            fi
        else
            warn "git not installed - frontend files won't update (binary still will)"
            warn "install git with: apt-get install -y git"
            return 1
        fi
    fi
    return 0
}

# =====================================================================
# Helper: sync local dashboard checkout to remote tip without breaking
# on force-pushes. v0.9.104 fix: was `git pull --rebase --autostash`
# which DIES on force-push (because the local commits no longer exist
# on the remote). Switched to fetch + reset --hard origin/$BRANCH.
# =====================================================================
sync_dashboard_checkout() {
    [ -d /root/bpftune/.git ] || return 1
    cd /root/bpftune

    # Fetch latest refs from remote (does not touch working tree).
    if ! git fetch origin --prune 2>&1 | sed 's/^/  git: /'; then
        warn "git fetch failed - proceeding with existing checkout"
        return 0
    fi

    # Make sure we're on the right branch.
    current_branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
    if [ "$current_branch" != "$BRANCH" ]; then
        # Check if local branch exists; create tracking branch if not.
        if ! git rev-parse --verify "$BRANCH" >/dev/null 2>&1; then
            git checkout -B "$BRANCH" "origin/$BRANCH" 2>&1 | sed 's/^/  git: /' || true
        else
            git checkout "$BRANCH" 2>&1 | sed 's/^/  git: /' || true
        fi
    fi

    # Reset to remote tip. This is force-push-safe - if the remote was
    # force-pushed (e.g. v0.9.103 SQLite-disable was dropped), local
    # commits are discarded and we move to the new remote HEAD.
    # Stash any local changes first so user work isn't lost.
    if ! git diff --quiet 2>/dev/null || ! git diff --cached --quiet 2>/dev/null; then
        warn "local changes detected - stashing before reset"
        git stash 2>&1 | sed 's/^/  git: /' || true
    fi

    OLD_HASH=$(git rev-parse --short HEAD 2>/dev/null || echo "?")
    if ! git reset --hard "origin/$BRANCH" >/dev/null 2>&1; then
        warn "git reset --hard origin/$BRANCH failed - proceeding with current HEAD"
        return 0
    fi
    NEW_HASH=$(git rev-parse --short HEAD)
    if [ "$OLD_HASH" = "$NEW_HASH" ]; then
        ok "dashboard code already at latest ($NEW_HASH)"
    else
        ok "dashboard code updated: $OLD_HASH -> $NEW_HASH"
    fi
    return 0
}

# ---------- Step 1: tuner .deb ----------
if [ "$DO_TUNER" = 1 ]; then
    step "1. Check for newer bpftune .deb"

    NEW_VER=""
    DEB_TO_INSTALL=""

    printf "  checking GitHub releases for %s/%s...\n" "$REPO" "$ARCH"
    DEB_INFO=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases?per_page=30" 2>/dev/null \
        | python3 -c "
import json, sys
try:
    releases = json.load(sys.stdin)
except Exception:
    sys.exit(0)

# v0.4.95 fix: collect ALL .deb assets across ALL releases, parse the
# version from each, then pick the one with the highest version number.
# Supports both naming conventions:
#   - new: bpftune-custom-0.4.95-amd64.deb
#   - old: bpftune_0.4.93_amd64.deb

import re
candidates = []
for r in releases:
    tag = r.get('tag_name', '').lstrip('v')
    for a in r.get('assets', []):
        name = a.get('name', '')
        url = a.get('browser_download_url', '')
        if not url:
            continue
        m = re.match(r'^bpftune-custom-([0-9.]+)-${ARCH}\.deb\$', name)
        if m:
            ver = m.group(1)
            candidates.append((tuple(int(x) for x in ver.split('.')), ver, url))
            continue
        m = re.match(r'^bpftune_([0-9.]+)_${ARCH}\.deb\$', name)
        if m:
            ver = m.group(1)
            candidates.append((tuple(int(x) for x in ver.split('.')), ver, url))
            continue

if not candidates:
    sys.exit(0)

candidates.sort(key=lambda c: c[0], reverse=True)
best = candidates[0]
print(best[1] + ' ' + best[2])
" 2>/dev/null || true)

    if [ -n "$DEB_INFO" ]; then
        NEW_VER=$(printf "%s" "$DEB_INFO" | awk '{print $1}')
        URL=$(printf "%s" "$DEB_INFO" | awk '{print $2}')
        printf "  found GitHub release: %s\n" "$NEW_VER"
        printf "  downloading .deb...\n"
        curl -fsSL "$URL" -o /tmp/bpftune-"$ARCH".deb
        DEB_TO_INSTALL=/tmp/bpftune-"$ARCH".deb
    else
        warn "no .deb found in GitHub releases - skipping tuner update"
    fi

    if [ -n "$DEB_TO_INSTALL" ]; then
        if [ "$CURRENT_VER" = "not-installed" ]; then
            fail "bpftune is not installed. Run install.sh first."
        elif [ "$NEW_VER" = "$CURRENT_VER" ]; then
            ok "already at latest version ($CURRENT_VER) - skipping .deb install"
        elif dpkg --compare-versions "$NEW_VER" lt "$CURRENT_VER" 2>/dev/null; then
            warn "Found $NEW_VER but installed is $CURRENT_VER - this would be a DOWNGRADE"
            if [ "$FORCE_DOWNGRADE" = 1 ]; then
                ok "proceeding with downgrade (--force-downgrade)"
                printf "  downgrading: %s -> %s\n" "$CURRENT_VER" "$NEW_VER"
                systemctl stop bpftune 2>/dev/null || true
                [ "$CLEAN_STATE" = 1 ] && rm -f /var/lib/bpftune/tcp_conn_tuner.state
                dpkg -i "$DEB_TO_INSTALL" || fail "dpkg -i failed"
                systemctl restart bpftune
                sleep 1
                ok "bpftune downgraded to $(dpkg-query -W -f='${Version}' bpftune)"
            else
                fail "Refusing to downgrade $CURRENT_VER -> $NEW_VER without --force-downgrade"
            fi
        else
            printf "  upgrading: %s -> %s\n" "$CURRENT_VER" "$NEW_VER"
            systemctl stop bpftune 2>/dev/null || true
            [ "$CLEAN_STATE" = 1 ] && rm -f /var/lib/bpftune/tcp_conn_tuner.state
            dpkg -i "$DEB_TO_INSTALL" || fail "dpkg -i failed"
            systemctl restart bpftune
            sleep 1
            ok "bpftune upgraded to $(dpkg-query -W -f='${Version}' bpftune)"
        fi
    fi
fi

# ---------- Step 2: dashboard (Go collector) ----------
if [ "$DO_DASHBOARD" = 1 ]; then
    step "2. Update dashboard (Go collector + frontend)"

    # v0.9.104 fix: bootstrap /root/bpftune if missing (was: skip entire update)
    if ! ensure_git_checkout; then
        warn "/root/bpftune not available - only binary will be updated"
    fi

    # v0.9.104 fix: force-push-safe sync (was: git pull --rebase which
    # dies when remote was force-pushed, leaving hosts stuck on old code)
    if [ -d /root/bpftune/.git ]; then
        sync_dashboard_checkout
    fi

    DASH_BIN=/opt/bpftune-dashboard/bin
    SERVED=/var/lib/bpftune/history
    GO_BIN="$DASH_BIN/bpftune-collector-go"
    mkdir -p "$DASH_BIN" "$SERVED/data"

    # --- 2a. Find the GitHub release with the dashboard binary ---
    # v0.9.104 fix: explicitly initialize BIN_URL="" so the next
    # `if [ -n "${BIN_URL:-}" ]` check doesn't trip on set -u.
    BIN_URL=""
    DASH_TAG=""

    printf "  checking GitHub releases for bpftune-dashboard-%s...\n" "$ARCH"
    # v0.9.104 fix: distinguish "API call failed" from "release not found"
    # so we know whether to retry or fall back. Save API response to a temp
    # file so we can inspect it if parsing fails.
    API_TMP=$(mktemp /tmp/bpftune-releases.XXXXXX.json)
    API_HTTP=$(curl -sSL -w "%{http_code}" -o "$API_TMP" \
        "https://api.github.com/repos/${REPO}/releases?per_page=30" 2>/dev/null || echo 000)
    if [ "$API_HTTP" != "200" ]; then
        warn "GitHub API returned HTTP $API_HTTP (rate-limited? network down? cache lag?)"
        warn "if this is right after a fresh release, wait 2-5 min for CDN cache to refresh"
        rm -f "$API_TMP"
    else
        DASH_TAG=$(python3 -c "
import json, sys, re
try:
    with open('$API_TMP') as f:
        releases = json.load(f)
except Exception as e:
    sys.stderr.write(f'parse failed: {e}\n')
    sys.exit(0)
candidates = []
for r in releases:
    tag = r.get('tag_name', '')
    m = re.match(r'^v?(\d+\.\d+\.\d+)\$', tag.lstrip('v'))
    if not m:
        continue
    ver_tuple = tuple(int(x) for x in m.group(1).split('.'))
    for a in r.get('assets', []):
        if a.get('name') == 'bpftune-dashboard-${ARCH}':
            candidates.append((ver_tuple, r['tag_name']))
            break
if not candidates:
    # List what tags we DID see, for debugging
    tags = [r.get('tag_name','?') for r in releases[:5]]
    sys.stderr.write(f'no matching release. saw tags: {tags}\n')
    sys.exit(0)
candidates.sort(key=lambda c: c[0], reverse=True)
print(candidates[0][1])
" 2>&1 || true)
        rm -f "$API_TMP"
    fi

    if [ -n "$DASH_TAG" ]; then
        BIN_URL="https://github.com/${REPO}/releases/download/${DASH_TAG}/bpftune-dashboard-${ARCH}"
    fi

    # --- 2b. Download + swap binary (stop service first to avoid "Text file busy") ---
    BINARY_UPDATED=0
    if [ -n "$BIN_URL" ]; then
        printf "  downloading binary from %s\n" "$BIN_URL"
        if curl -fsSL "$BIN_URL" -o /tmp/bpftune-dashboard-"$ARCH" 2>/dev/null; then
            # Stop service BEFORE copying - avoids "Text file busy" on Linux
            # when the running binary has an open file handle.
            systemctl stop bpftune-collector-go 2>/dev/null || true
            sleep 2
            cp /tmp/bpftune-dashboard-"$ARCH" "$GO_BIN"
            chmod +x "$GO_BIN"
            ok "Go binary updated from GitHub Releases (tag $DASH_TAG)"
            BINARY_UPDATED=1
        else
            warn "download failed for $BIN_URL - will try source build or skip"
        fi
    else
        warn "no GitHub release with bpftune-dashboard-$ARCH asset found"
        warn "  this is normal right after a new release (CDN cache lag of 2-5 min)"
        warn "  or you may be rate-limited (unauthenticated API: 60 req/hour per IP)"
        warn "  will try source build or keep existing binary"""
    fi

    # --- 2c. Fallback: build from source if Go is installed ---
    if [ "$BINARY_UPDATED" = "0" ] && [ -d /root/bpftune/.git ] && command -v go >/dev/null 2>&1; then
        printf "  building Go binary from source...\n"
        systemctl stop bpftune-collector-go 2>/dev/null || true
        sleep 2
        cd /root/bpftune/dashboard/bin/go
        CGO_ENABLED=0 go build -ldflags "-X main.dashVersionStr=0.9.104" -o "$GO_BIN" .
        chmod +x "$GO_BIN"
        ok "Go binary rebuilt from source"
        BINARY_UPDATED=1
        cd /root/bpftune
    fi

    [ "$BINARY_UPDATED" = "0" ] && warn "could not update Go binary - keeping existing"

    # --- 2d. Deploy frontend files ---
    if [ -d /root/bpftune/dashboard/bin ]; then
        cp /root/bpftune/dashboard/bin/dashboard.js "$DASH_BIN"/ 2>/dev/null || true
        cp /root/bpftune/dashboard/bin/dashboard.css "$DASH_BIN"/ 2>/dev/null || true
        cp /root/bpftune/dashboard/bin/index.html "$DASH_BIN"/ 2>/dev/null || true
        cp /root/bpftune/dashboard/bin/labels-api.py "$DASH_BIN"/ 2>/dev/null || true
        cp /root/bpftune/dashboard/bin/chart.umd.min.js "$DASH_BIN"/ 2>/dev/null || true
        cp /root/bpftune/dashboard/bin/chartjs-adapter-date-fns.bundle.min.js "$DASH_BIN"/ 2>/dev/null || true
        # ALSO copy to SERVED (histDir) - Go HTTP handler looks for index.html here
        cp "$DASH_BIN"/index.html "$SERVED"/ 2>/dev/null || true
        cp "$DASH_BIN"/dashboard.js "$SERVED"/ 2>/dev/null || true
        cp "$DASH_BIN"/dashboard.css "$SERVED"/ 2>/dev/null || true
        cp "$DASH_BIN"/chart.umd.min.js "$SERVED"/ 2>/dev/null || true
        cp "$DASH_BIN"/chartjs-adapter-date-fns.bundle.min.js "$SERVED"/ 2>/dev/null || true
        chmod 644 "$SERVED"/*.css "$SERVED"/*.js 2>/dev/null || true
        chmod 644 "$DASH_BIN"/*.css "$DASH_BIN"/*.js 2>/dev/null || true
        chmod 755 "$DASH_BIN"/labels-api.py 2>/dev/null || true
        ok "frontend files synced"
    else
        warn "no frontend files to sync (no /root/bpftune/dashboard/bin)"
    fi

    # --- 2e. Restart Go collector ---
    # v0.9.8: strip --collector-mode flag from service file (lean is default)
    SERVICE_FILE="/etc/systemd/system/bpftune-collector-go.service"
    if [ -f "$SERVICE_FILE" ] && grep -q "collector-mode" "$SERVICE_FILE" 2>/dev/null; then
        sed -i 's/ --collector-mode=[a-z]*//g' "$SERVICE_FILE"
        systemctl daemon-reload
    fi

    systemctl restart bpftune-collector-go 2>/dev/null \
        || systemctl start bpftune-collector-go 2>/dev/null \
        || true
    sleep 5

    if systemctl is-active bpftune-collector-go >/dev/null 2>&1; then
        ok "bpftune-collector-go restarted"
        # Show PID + RSS so user can verify the update took effect
        PID=$(systemctl show -p MainPID --value bpftune-collector-go 2>/dev/null || echo "")
        if [ -n "$PID" ] && [ "$PID" != "0" ]; then
            RSS_KB=$(awk '/^VmRSS:/ {print $2}' /proc/$PID/status 2>/dev/null || echo 0)
            RSS_MB=$((RSS_KB / 1024))
            VER_LINE=$(journalctl -u bpftune-collector-go -n 30 --no-pager 2>/dev/null \
                | grep -E "version|v0\.9\." | tail -1 || echo "")
            printf "  PID=%s  RSS=%dMB  %s\n" "$PID" "$RSS_MB" "$VER_LINE"
        fi
    else
        warn "bpftune-collector-go failed to start - check: journalctl -u bpftune-collector-go -n 30"
    fi

    # --- 2f. Verify dashboard responds ---
    sleep 5
    for p in 8082 8080; do
        if curl -fsS "http://127.0.0.1:$p/current.json" 2>/dev/null \
            | python3 -c "import json,sys; d=json.load(sys.stdin); b=d.get('buckets',[]); print(f'  current.json OK on port $p, {len(b)} buckets')" 2>/dev/null; then
            ok "dashboard responding on port $p"
            break
        fi
    done
fi

# ---------- Step 3: trace service fix (always overwrite) ----------
# v0.9.104 fix: trace service used 'cat trace_pipe' which BLOCKS indefinitely
# when no BPF events are being generated (idle hosts). The cat syscall hangs,
# the 'sleep' never runs, the log file's mtime never updates, dashboard shows
# 'Issues detected - Log Freshness: 14m old' even though bpftune is fine.
#
# Always overwrite the trace service file with the unblocking version.
# Idempotent - safe to run on every update.sh invocation.
if [ "$DO_DASHBOARD" = 1 ]; then
    step "3. Fix trace service (unblock cat trace_pipe)"
    TRACE_SVC=/etc/systemd/system/bpftune-met-trace.service
    cat > "$TRACE_SVC" <<'EOF'
[Unit]
Description=bpftune trace_pipe capture to /var/log/bpftune-met-live.log
After=bpftune.service
Wants=bpftune.service

[Service]
Type=simple
ExecStart=/bin/sh -c 'while true; do timeout 1 cat /sys/kernel/tracing/trace_pipe >> /var/log/bpftune-met-live.log 2>/dev/null; touch /var/log/bpftune-met-live.log; sleep 1; done'
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable bpftune-met-trace 2>/dev/null || true
    if systemctl is-active bpftune-met-trace >/dev/null 2>&1; then
        systemctl restart bpftune-met-trace 2>/dev/null || true
        ok "trace service restarted with unblocking ExecStart"
    else
        systemctl start bpftune-met-trace 2>/dev/null || true
        ok "trace service started with unblocking ExecStart"
    fi
    sleep 2
    # Verify the log file mtime is now fresh (< 5s old)
    if [ -f /var/log/bpftune-met-live.log ]; then
        LOG_AGE=$(($(date +%s) - $(stat -c %Y /var/log/bpftune-met-live.log)))
        printf "  log freshness: %ds old (target: < 5s)\n" "$LOG_AGE"
    fi

    # v0.9.104 cache-invalidation fix: the dashboard collector's
    # getServiceHealth() result is cached for 5 minutes (added in v0.9.104
    # to reduce CPU). If the collector restarted in Step 2 BEFORE the trace
    # service was fixed in Step 3, the first collect() cycle would have
    # cached the STALE log freshness (mtime was still old at that moment).
    # The cache would then show stale data for 5 minutes despite the trace
    # service now being healthy.
    #
    # Fix: restart the collector AFTER the trace service is fixed. This
    # invalidates the cache, and the first collect() cycle (within ~30s)
    # reads the now-fresh file mtime and caches the correct value.
    printf "  restarting collector to invalidate service_health cache...\n"
    systemctl restart bpftune-collector-go 2>/dev/null || true
    sleep 5
    if systemctl is-active bpftune-collector-go >/dev/null 2>&1; then
        ok "collector restarted (cache invalidated, will read fresh log mtime on next collect)"
    fi
fi

# ---------- Step 4: GODEBUG=madvdontneed=1 (v0.9.105 memory fix) ----------
# v0.9.105: Go uses MADV_FREE by default (freed pages stay in RSS).
# This sets MADV_DONTNEED which returns freed pages to OS immediately.
# Combined with the streaming JSON fix in the binary, RSS drops from
# ~210 MB to ~40-60 MB on low-RAM hosts.
if [ "$DO_DASHBOARD" = 1 ]; then
    step "4. Ensure GODEBUG=madvdontneed=1 in collector service"
    COLLECTOR_SVC=/etc/systemd/system/bpftune-collector-go.service
    if [ -f "$COLLECTOR_SVC" ]; then
        if ! grep -q 'GODEBUG=madvdontneed=1' "$COLLECTOR_SVC" 2>/dev/null; then
            # Add the Environment line after the existing Environment=PATH line
            sed -i '/^Environment=PATH/a Environment=GODEBUG=madvdontneed=1  # v0.9.105: return freed pages to OS immediately' "$COLLECTOR_SVC"
            systemctl daemon-reload
            # The collector will be restarted in Step 2's flow on next update.sh run,
            # or we restart it now if already running
            if systemctl is-active bpftune-collector-go >/dev/null 2>&1; then
                systemctl restart bpftune-collector-go 2>/dev/null || true
            fi
            ok "added GODEBUG=madvdontneed=1 to collector service (RSS will drop to ~40-60MB)"
        else
            ok "GODEBUG=madvdontneed=1 already present in collector service"
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
[ "$DO_DASHBOARD" = 1 ] && svc_status bpftune-collector-go
[ "$DO_DASHBOARD" = 1 ] && [ -d /root/bpftune/.git ] && svc_status bpftune-met-trace

printf "\nDone.\n"
