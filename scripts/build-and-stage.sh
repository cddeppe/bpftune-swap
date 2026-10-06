#!/bin/bash
# build-and-stage.sh — build bpftune .deb + Go binary, stage to /mnt/backup/.
# Run on EACH builder arch (vps-3959 amd64 + instance-20250225-1017 arm64)
# in parallel.
#
# Usage:
#   sudo bash scripts/build-and-stage.sh

set -Eeuo pipefail

G='\033[0;32m'; R='\033[0;31m'; Y='\033[0;33m'; B='\033[1m'; N='\033[0m'
ok()   { printf "${G}✓${N} %s\n" "$1"; }
fail() { printf "${R}✗${N} %s\n" "$1" >&2; exit 1; }
warn() { printf "${Y}!${N} %s\n" "$1"; }
step() { printf "\n${B}== %s ==${N}\n" "$1"; }

trap 'fail "Aborted at line $LINENO (exit code $?)"' ERR

[ "$(id -u)" = "0" ] || fail "Run as root: sudo bash $0"

ARCH=$(dpkg --print-architecture 2>/dev/null || uname -m)
case "$ARCH" in
    amd64|x86_64)  ARCH=amd64 ;;
    arm64|aarch64) ARCH=arm64 ;;
    *) fail "Unsupported arch: $ARCH" ;;
esac

REPO_DIR="${REPO_DIR:-/root/bpftune}"
BACKUP_DIR="/mnt/backup"

# Read the version from debian/changelog on main branch
cd "$REPO_DIR"
git fetch origin --no-tags --prune 2>&1 | tail -2
git checkout main 2>&1 | tail -1
git pull --ff-only origin main 2>&1 | tail -2
TUNER_VER=$(head -1 debian/changelog | sed -n 's/^bpftune (\([^)]*\)).*/\1/p')
[ -n "$TUNER_VER" ] || fail "could not parse version from debian/changelog"
MAIN_HASH=$(git rev-parse --short HEAD)

printf "${B}=== build-and-stage ===${N}\n"
printf "  arch:        %s\n" "$ARCH"
printf "  tuner ver:   %s\n" "$TUNER_VER"
printf "  main hash:   %s\n" "$MAIN_HASH"
printf "  backup dir:  %s\n" "$BACKUP_DIR"

# ---------- 1. Build tuner .deb ----------
step "1. Build tuner ${TUNER_VER} .deb"

cd src
make clean
rm -f *.skel.h *.bpf.o *.o
ok "cleaned src/"

cd "$REPO_DIR"
dpkg-buildpackage -b -us -uc 2>&1 | tail -10

DEB=$(ls -t ../bpftune_*_"${ARCH}".deb 2>/dev/null | head -1 || true)
[ -n "$DEB" ] || fail "no bpftune_*_${ARCH}.deb produced"

DEB_VER=$(echo "$DEB" | sed -n 's|.*/bpftune_\([^_]*\)_.*|\1|p')
[ "$DEB_VER" = "$TUNER_VER" ] || fail "filename version mismatch: got $DEB_VER, expected $TUNER_VER"
ok "built $(basename "$DEB")"

# ---------- 2. Stage .deb ----------
step "2. Stage .deb to ${BACKUP_DIR}"

# Use both naming conventions (install.sh looks for bpftune-custom-*)
STAGED_DEB="$BACKUP_DIR/bpftune-custom-${TUNER_VER}-${ARCH}.deb"
HIST_DEB="$BACKUP_DIR/bpftune_${TUNER_VER}_${ARCH}.deb"
cp "$DEB" "$STAGED_DEB"
cp "$DEB" "$HIST_DEB"
chmod 644 "$STAGED_DEB" "$HIST_DEB"
ok "staged $STAGED_DEB"
ok "staged $HIST_DEB"

# ---------- 3. Build Go binary ----------
step "3. Build dashboard Go binary"

git checkout dashboard 2>&1 | tail -1
git pull --ff-only origin dashboard 2>&1 | tail -2
DASH_HASH=$(git rev-parse --short HEAD)

# Install Go if missing
if ! command -v go >/dev/null 2>&1; then
    warn "go not in PATH — installing via apt"
    apt-get update -qq
    apt-get install -y -qq golang-go >/dev/null 2>&1 && ok "installed golang-go" || \
        fail "apt install golang-go failed"
fi
ok "Go: $(go version)"

cd dashboard/bin/go
rm -f bpftune-collector-go bpftune-collector-go-*

CGO_ENABLED=0 go build \
    -ldflags "-s -w -X main.dashVersionStr=v0.9.0-${DASH_HASH}" \
    -o "bpftune-collector-go-${ARCH}" \
    .

# Verify it runs
./"bpftune-collector-go-${ARCH}" --help >/dev/null 2>&1 && ok "binary runs" || \
    fail "binary doesn't run"

# Run sanity tests
go test -count=1 -run 'Test' ./... 2>&1 | tail -3 && ok "tests pass" || warn "tests failed"

# ---------- 4. Stage Go binary ----------
step "4. Stage Go binary to ${BACKUP_DIR}"

STAGED_BIN="$BACKUP_DIR/bpftune-collector-go-${ARCH}"
cp "bpftune-collector-go-${ARCH}" "$STAGED_BIN"
chmod 755 "$STAGED_BIN"
ok "staged $STAGED_BIN"

# ---------- 5. Summary ----------
step "5. Summary"

git checkout main 2>&1 | tail -1  # restore to main

echo
printf "${B}=== build-and-stage complete ===${N}\n"
printf "  staged .deb:  %s\n" "$STAGED_DEB"
printf "  staged bin:   %s\n" "$STAGED_BIN"
printf "  tuner ver:    %s (main %s)\n" "$TUNER_VER" "$MAIN_HASH"
printf "  dash hash:    %s (dashboard)\n" "$DASH_HASH"
echo
echo "Next: on vps-3959, create the GitHub release:"
echo "  gh release create v${TUNER_VER} \\"
echo "    $STAGED_DEB \\"
echo "    $BACKUP_DIR/bpftune-collector-go-amd64 \\"
echo "    $BACKUP_DIR/bpftune-collector-go-arm64 \\"
echo "    --title \"v${TUNER_VER}\" \\"
echo "    --notes \"see debian/changelog\" \\"
echo "    --repo cddeppe/bpftune-swap"
echo
echo "(after both builders have run this script)"
