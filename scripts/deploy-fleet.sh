#!/bin/bash
# deploy-fleet.sh — deploy the staged 0.4.94 .deb + v0.9.0 Go binary
# to all hosts in the fleet via SSH.
#
# Run from one of the builder hosts (or any host that has SSH access to
# the fleet + can read /mnt/backup/):
#   bash deploy-fleet.sh
#
# Customize the HOSTS list below to match your fleet.

set -Eeuo pipefail

G='\033[0;32m'; R='\033[0;31m'; Y='\033[0;33m'; B='\033[1m'; N='\033[0m'
ok()   { printf "${G}✓${N} %s\n" "$1"; }
fail() { printf "${R}✗${N} %s\n" "$1" >&2; exit 1; }
warn() { printf "${Y}!${N} %s\n" "$1"; }
step() { printf "\n${B}== %s ==${N}\n" "$1"; }

# ---------- Fleet ----------
# Update with your real SSH target strings (user@host or aliases from
# ~/.ssh/config). Keep the arch comment in sync so the script knows
# which .deb to push.
HOSTS=(
    # alias                       arch    role
    "vps-3959:amd64:builder-amd64"           # builder + main git pusher
    "instance-20250225-1017:arm64:builder-arm64"  # arm64 builder
    "instance-20260905-0931:arm64:heavy-traffic" # xray/YouTube host
    "ip-172-26-13-90:amd64:idle-target"
    "al:amd64:nginx-dashboard"
)

BACKUP_DIR="/mnt/backup"
EXPECTED_TUNER_VER="0.4.94"
EXPECTED_DASH_VER="0.9.0"

# Pre-flight: ensure the staged artifacts exist locally
[ -f "$BACKUP_DIR/bpftune-custom-${EXPECTED_TUNER_VER}-amd64.deb" ] || \
    fail "missing $BACKUP_DIR/bpftune-custom-${EXPECTED_TUNER_VER}-amd64.deb (build on amd64 first)"
[ -f "$BACKUP_DIR/bpftune-custom-${EXPECTED_TUNER_VER}-arm64.deb" ] || \
    fail "missing $BACKUP_DIR/bpftune-custom-${EXPECTED_TUNER_VER}-arm64.deb (build on arm64 first)"
[ -f "$BACKUP_DIR/bpftune-collector-go-amd64" ] || \
    fail "missing $BACKUP_DIR/bpftune-collector-go-amd64"
[ -f "$BACKUP_DIR/bpftune-collector-go-arm64" ] || \
    fail "missing $BACKUP_DIR/bpftune-collector-go-arm64"

ok "all 4 staged artifacts present in $BACKUP_DIR/"

# ---------- Deploy loop ----------
FAILED=()
for entry in "${HOSTS[@]}"; do
    IFS=':' read -r SSH_TARGET ARCH ROLE <<< "$entry"
    step "Deploy to $SSH_TARGET ($ARCH, $ROLE)"

    # Each host can read /mnt/backup/ via NFS, so we don't need to scp.
    # We just SSH in and run update.sh.

    ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new \
        "$SSH_TARGET" "
        set -e
        # Pull latest install.sh/update.sh from main branch (in case the
        # local checkout is stale; update.sh is on main, not dashboard)
        cd /root/bpftune 2>/dev/null && git checkout main 2>/dev/null && git pull --ff-only 2>/dev/null || true

        # Run the updater
        if [ -f /root/bpftune/update.sh ]; then
            sudo bash /root/bpftune/update.sh
        else
            echo '  /root/bpftune/update.sh not found — bootstrap via install.sh first'
            exit 1
        fi

        # Verify
        echo '---'
        echo '  tuner:  '\$(dpkg-query -W -f='\${Version}' bpftune 2>/dev/null || echo 'not-installed')
        echo '  dash:   '\$(systemctl is-active bpftune-collector-go 2>/dev/null || echo 'inactive')
        echo '  proof check: '
        sudo grep -c '\"dest\":\"' /var/lib/bpftune/history/swapscore_truth.jsonl 2>/dev/null | xargs -I{} echo '    truth file rows: {}' || true
        sudo grep -c '\"dest\":\"[^\"]*:' /var/lib/bpftune/history/swapscore_truth.jsonl 2>/dev/null | xargs -I{} echo '    IPv6 truth rows: {}' || true
    " 2>&1 | sed 's/^/  /' || {
        warn "deploy to $SSH_TARGET failed"
        FAILED+=("$SSH_TARGET")
        continue
    }

    ok "$SSH_TARGET deployed"
done

# ---------- Summary ----------
echo
step "Summary"
if [ ${#FAILED[@]} -eq 0 ]; then
    ok "all ${#HOSTS[@]} hosts deployed successfully"
else
    fail "${#FAILED[@]} host(s) failed: ${FAILED[*]}"
    exit 1
fi
