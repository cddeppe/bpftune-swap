#!/bin/bash
# deploy-fleet.sh — deploy the staged 0.4.94 .deb + v0.9.0 Go binary
# to all hosts in the fleet via SSH.
#
# Run from one of the builder hosts (or any host that has SSH access to
# the fleet + can read /mnt/backup/):
#   bash scripts/deploy-fleet.sh
#
# Or deploy just the tuner (skip dashboard):
#   bash scripts/deploy-fleet.sh --tuner-only
#
# Or deploy just the dashboard (skip tuner):
#   bash scripts/deploy-fleet.sh --dashboard-only
#
# Customize the HOSTS list below to match your SSH aliases.

set -Eeuo pipefail

G='\033[0;32m'; R='\033[0;31m'; Y='\033[0;33m'; B='\033[1m'; N='\033[0m'
ok()   { printf "${G}✓${N} %s\n" "$1"; }
fail() { printf "${R}✗${N} %s\n" "$1" >&2; exit 1; }
warn() { printf "${Y}!${N} %s\n" "$1"; }
step() { printf "\n${B}== %s ==${N}\n" "$1"; }

# ---------- Args ----------
UPDATE_FLAG=""
for arg in "$@"; do
    case "$arg" in
        --tuner-only|--dashboard-only) UPDATE_FLAG="$arg" ;;
        -h|--help)
            sed -n '2,15p' "$0"
            exit 0
            ;;
        *) fail "Unknown arg: $arg (try --help)" ;;
    esac
done

# ---------- Fleet ----------
# Format: SSH-alias:ARCH:role-name
# Edit to match your ~/.ssh/config aliases.
HOSTS=(
    "vps-3959:amd64:builder-amd64"
    "instance-20250225-1017:arm64:builder-arm64"
    "instance-20260905-0931:arm64:heavy-traffic"
    "ip-172-26-13-90:amd64:idle-target"
    "al:amd64:nginx-dashboard"
)

BACKUP_DIR="/mnt/backup"
EXPECTED_TUNER_VER="0.4.94"

# Pre-flight: ensure the staged artifacts exist locally
[ -f "$BACKUP_DIR/bpftune-custom-${EXPECTED_TUNER_VER}-amd64.deb" ] || \
    fail "missing $BACKUP_DIR/bpftune-custom-${EXPECTED_TUNER_VER}-amd64.deb (build on amd64 first)"
[ -f "$BACKUP_DIR/bpftune-custom-${EXPECTED_TUNER_VER}-arm64.deb" ] || \
    fail "missing $BACKUP_DIR/bpftune-custom-${EXPECTED_TUNER_VER}-arm64.deb (build on arm64 first)"

# Don't require Go binaries if --tuner-only
if [ "$UPDATE_FLAG" != "--tuner-only" ]; then
    [ -f "$BACKUP_DIR/bpftune-collector-go-amd64" ] || \
        fail "missing $BACKUP_DIR/bpftune-collector-go-amd64"
    [ -f "$BACKUP_DIR/bpftune-collector-go-arm64" ] || \
        fail "missing $BACKUP_DIR/bpftune-collector-go-arm64"
fi

ok "all staged artifacts present in $BACKUP_DIR/"

# ---------- Deploy loop ----------
FAILED=()
SKIPPED=()
for entry in "${HOSTS[@]}"; do
    IFS=':' read -r SSH_TARGET ARCH ROLE <<< "$entry"
    step "Deploy to $SSH_TARGET ($ARCH, $ROLE)"

    # Each host can read /mnt/backup/ via NFS — no scp needed.
    # SSH in, make sure the local git checkout is on the main branch (for
    # update.sh), then run update.sh with the requested flags.
    if ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new \
        -o BatchMode=yes \
        "$SSH_TARGET" "
        set -e
        cd /root/bpftune 2>/dev/null || {
            echo '  /root/bpftune not found — bootstrap with install.sh first'
            exit 1
        }
        git fetch origin --no-tags --prune 2>&1 | tail -3
        git checkout main 2>&1 | tail -1
        git pull --ff-only origin main 2>&1 | tail -2

        echo
        echo '--- running update.sh $UPDATE_FLAG ---'
        sudo bash update.sh $UPDATE_FLAG
    " 2>&1 | sed 's/^/  /'; then
        ok "$SSH_TARGET deployed"

        # Post-deploy verification
        echo
        echo "  -- verifying $SSH_TARGET --"
        ssh -o BatchMode=yes "$SSH_TARGET" "
            echo -n '  tuner:  '
            dpkg-query -W -f='\${Version}' bpftune 2>/dev/null || echo 'not-installed'
            echo -n '  bpftune service: '
            systemctl is-active bpftune 2>/dev/null || echo 'inactive'
            echo -n '  dashboard:       '
            systemctl is-active bpftune-collector-go 2>/dev/null || echo 'inactive'
            if [ -f /var/lib/bpftune/history/swapscore_truth.jsonl ]; then
                echo -n '  truth file rows: '
                sudo wc -l < /var/lib/bpftune/history/swapscore_truth.jsonl
                echo -n '  IPv6 truth rows: '
                sudo grep -c '\"dest\":\"[^\"]*:' /var/lib/bpftune/history/swapscore_truth.jsonl 2>/dev/null || echo 0
            fi
        " 2>&1 | sed 's/^/  /'
    else
        warn "deploy to $SSH_TARGET failed (exit \$?)"
        FAILED+=("$SSH_TARGET")
    fi
done

# ---------- Summary ----------
echo
step "Summary"
TOTAL=${#HOSTS[@]}
SUCCESS=$((TOTAL - ${#FAILED[@]}))
printf "  hosts deployed: %d/%d\n" "$SUCCESS" "$TOTAL"
if [ ${#FAILED[@]} -gt 0 ]; then
    fail "failed hosts: ${FAILED[*]}"
    exit 1
fi
ok "all $TOTAL hosts deployed successfully"
echo
echo "Next: check the dashboard at http://<any-host>:8080/ — proofs panel should"
echo "now show real dest labels (no more dash), and the 0.0.0.0 mystery bucket"
echo "should disappear as v4-in-v6 connections get properly attributed."
