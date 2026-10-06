#!/bin/bash
# build-and-stage.sh — build bpftune .deb + Go binary, stage to /mnt/backup/.
# Run on EACH builder arch (vps-3959 amd64 + instance-20250225-1017 arm64)
# in parallel.
#
# Usage:
#   sudo bash scripts/build-and-stage.sh
#
# Can be run from any directory — uses absolute paths.

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

REPO_DIR="/root/bpftune"
BACKUP_DIR="/mnt/backup"

[ -d "$REPO_DIR/.git" ] || fail "$REPO_DIR is not a git checkout"
[ -d "$BACKUP_DIR" ] || fail "$BACKUP_DIR not present (NFS mount missing?)"

# ---------- 0. Read version from debian/changelog on main ----------
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

cd "$REPO_DIR/src"
make clean
rm -f *.skel.h *.bpf.o *.o
ok "cleaned src/"

cd "$REPO_DIR"
dpkg-buildpackage -b -us -uc 2>&1 | tail -10

# Find the .deb (in the parent dir, named bpftune_VERSION_ARCH.deb)
DEB="$REPO_DIR/../bpftune_${TUNER_VER}_${ARCH}.deb"
[ -f "$DEB" ] || fail "$DEB not found (dpkg-buildpackage output)"

# Verify version inside the .deb matches
DEB_VER_INTERNAL=$(dpkg-deb -f "$DEB" Version 2>/dev/null || echo "?")
[ "$DEB_VER_INTERNAL" = "$TUNER_VER" ] || \
    warn "internal Version: $DEB_VER_INTERNAL (expected $TUNER_VER)"
ok "built $(basename "$DEB")"

# ---------- 2. Stage .deb ----------
step "2. Stage .deb to ${BACKUP_DIR}"

STAGED_DEB="$BACKUP_DIR/bpftune-custom-${TUNER_VER}-${ARCH}.deb"
HIST_DEB="$BACKUP_DIR/bpftune_${TUNER_VER}_${ARCH}.deb"
cp "$DEB" "$STAGED_DEB"
cp "$DEB" "$HIST_DEB"
chmod 644 "$STAGED_DEB" "$HIST_DEB"
ok "staged $STAGED_DEB"
ok "staged $HIST_DEB"

# ---------- 3. Build Go binary ----------
step "3. Build dashboard Go binary"

cd "$REPO_DIR"
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

GO_DIR="$REPO_DIR/dashboard/bin/go"
[ -f "$GO_DIR/go.mod" ] || fail "$GO_DIR/go.mod not found"
cd "$GO_DIR"
rm -f bpftune-collector-go bpftune-collector-go-*

CGO_ENABLED=0 go build \
    -ldflags "-s -w -X main.dashVersionStr=0.9.4" \
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

# Restore to main
cd "$REPO_DIR"
git checkout main 2>&1 | tail -1

echo
printf "${B}=== build-and-stage complete ===${N}\n"
printf "  staged .deb:  %s\n" "$STAGED_DEB"
printf "  staged bin:   %s\n" "$STAGED_BIN"
printf "  tuner ver:    %s (main %s)\n" "$TUNER_VER" "$MAIN_HASH"
printf "  dash hash:    %s (dashboard)\n" "$DASH_HASH"
echo
echo "Next: on vps-3959, create the GitHub release (after BOTH builders finish):"
echo "  gh release create v${TUNER_VER} \\"
echo "    /mnt/backup/bpftune-custom-${TUNER_VER}-amd64.deb \\"
echo "    /mnt/backup/bpftune-custom-${TUNER_VER}-arm64.deb \\"
echo "    /mnt/backup/bpftune-collector-go-amd64 \\"
echo "    /mnt/backup/bpftune-collector-go-arm64 \\"
echo "    --title v${TUNER_VER} \\"
echo "    --notes 'Fix: skip passive connections in vote path' \\"
echo "    --repo cddeppe/bpftune-swap"
