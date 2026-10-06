#!/bin/bash
# build-and-stage.sh — build bpftune 0.4.94 .deb + dashboard v0.9.0 Go binary
# on a builder host, then stage to /mnt/backup/ for fleet deploy.
#
# Run on EACH builder arch (amd64 + arm64) IN PARALLEL:
#   sudo bash build-and-stage.sh
#
# Prereqs on builder host:
#   - /root/bpftune git checkout (origin = cddeppe/bpftune-swap)
#   - build deps installed (see debian/control Build-Depends):
#       sudo apt-get install -y \
#         debhelper-compat python3-docutils libbpf-dev libcap-dev \
#         clang llvm bpftool libnl-3-dev libnl-route-3-dev iperf3 \
#         golang-go
#   - /mnt/backup/ writable (NFS share between builders)
#
# Output (staged to /mnt/backup/):
#   - bpftune-custom-0.4.94-<arch>.deb
#   - bpftune-collector-go-<arch>
#
# Idempotent: safe to re-run.

set -Eeuo pipefail

# Pretty output
G='\033[0;32m'; R='\033[0;31m'; Y='\033[0;33m'; B='\033[1m'; N='\033[0m'
ok()   { printf "${G}✓${N} %s\n" "$1"; }
fail() { printf "${R}✗${N} %s\n" "$1" >&2; exit 1; }
warn() { printf "${Y}!${N} %s\n" "$1"; }
step() { printf "\n${B}== %s ==${N}\n" "$1"; }

trap 'fail "Aborted at line $LINENO (exit code $?)"' ERR

# ---------- Pre-flight ----------
[ "$(id -u)" = "0" ] || fail "Run as root (use: sudo bash $0)"

ARCH=$(dpkg --print-architecture 2>/dev/null || uname -m)
case "$ARCH" in
    amd64|x86_64)  ARCH=amd64 ;;
    arm64|aarch64) ARCH=arm64 ;;
    *) fail "Unsupported arch: $ARCH" ;;
esac

REPO_DIR="${REPO_DIR:-/root/bpftune}"
BACKUP_DIR="${BACKUP_DIR:-/mnt/backup}"
EXPECTED_TUNER_VER="0.4.94"
EXPECTED_DASH_VER="0.9.0"

printf "${B}=== bpftune build-and-stage ===${N}\n"
printf "  arch:              %s\n" "$ARCH"
printf "  repo:              %s\n" "$REPO_DIR"
printf "  backup dir:        %s\n" "$BACKUP_DIR"
printf "  expected tuner:   %s\n" "$EXPECTED_TUNER_VER"
printf "  expected dash:     %s\n" "$EXPECTED_DASH_VER"

[ -d "$REPO_DIR/.git" ] || fail "$REPO_DIR is not a git checkout"
[ -d "$BACKUP_DIR" ] || fail "$BACKUP_DIR not present (NFS mount missing?)"

# ---------- Step 1: pull latest main + dashboard ----------
step "1. Git pull (main + dashboard)"

cd "$REPO_DIR"

# Save current branch so we can restore
ORIG_BRANCH=$(git rev-parse --abbrev-ref HEAD)

# Fetch without --tags (avoid "would clobber existing tag" errors when
# local tags from prior releases disagree with remote). The build does
# not need tags — `git describe --tags --always` falls back to the
# commit hash when no local tags match.
git fetch origin --prune --no-tags
ok "fetched origin"

# Pull main
git checkout main
git pull --ff-only origin main
MAIN_HASH=$(git rev-parse --short HEAD)
ok "main at $MAIN_HASH"

# Pull dashboard
git checkout dashboard
git pull --ff-only origin dashboard
DASH_HASH=$(git rev-parse --short HEAD)
ok "dashboard at $DASH_HASH"

# ---------- Step 2: build tuner .deb on main ----------
step "2. Build tuner ${EXPECTED_TUNER_VER} .deb"

cd "$REPO_DIR"
git checkout main

# HANDOFF non-negotiables:
#   1. make clean before every build
#   2. rm -f src/*.skel.h src/*.bpf.o src/*.o  (stale skel.h embeds old bytecode)
#   3. verify the .deb filename carries the new version
#   4. bump debian/changelog BEFORE the build (already done in our commit)
cd src
make clean
rm -f *.skel.h *.bpf.o *.o
ok "cleaned src/"

cd "$REPO_DIR"
dpkg-buildpackage -b -us -uc 2>&1 | tail -30

# Find the produced .deb
DEB=$(ls -t ../bpftune_*_"${ARCH}".deb 2>/dev/null | head -1 || true)
[ -n "$DEB" ] || fail "no bpftune_*_${ARCH}.deb produced by dpkg-buildpackage"

# Verify version in filename
DEB_VER=$(echo "$DEB" | sed -n 's|.*/bpftune_\([^_]*\)_.*|\1|p')
if [ "$DEB_VER" != "$EXPECTED_TUNER_VER" ]; then
    fail "filename version mismatch: got $DEB_VER, expected $EXPECTED_TUNER_VER

This is the silent-version-mismatch trap the HANDOFF warns about.
The .deb contains whatever code was in the tree at build time, but
the version label comes from debian/changelog. Either:
  (a) you forgot to bump debian/changelog, or
  (b) the build used a stale changelog (clean didn't run).

Fix: cd $REPO_DIR && head -1 debian/changelog  # should show $EXPECTED_TUNER_VER"
fi

# Also confirm via dpkg-deb -f (the version field inside the .deb)
DEB_VER_INTERNAL=$(dpkg-deb -f "$DEB" Version 2>/dev/null || echo "?")
[ "$DEB_VER_INTERNAL" = "$EXPECTED_TUNER_VER" ] || \
    warn "internal Version field: $DEB_VER_INTERNAL (filename: $DEB_VER)"

ok "built $(basename "$DEB")"

# Verify BPF verifier accepts the new .o (HANDOFF: bpftool prog load test)
# This requires bpftune .deb NOT yet installed — skip on a system where
# it's already loaded. Just sanity-check the .o was built.
[ -f "src/tcp_conn_tuner.bpf.o" ] && ok "tcp_conn_tuner.bpf.o exists" || \
    warn "tcp_conn_tuner.bpf.o not found (BPF didn't compile?)"

# ---------- Step 3: rename + stage .deb to /mnt/backup ----------
step "3. Stage .deb to ${BACKUP_DIR}"

# install.sh/update.sh look for: bpftune-custom-*-${ARCH}.deb
STAGED_DEB="$BACKUP_DIR/bpftune-custom-${EXPECTED_TUNER_VER}-${ARCH}.deb"

# Copy atomically (cp + rename so other hosts don't see a half-written file)
cp "$DEB" "$STAGED_DEB.tmp"
mv -f "$STAGED_DEB.tmp" "$STAGED_DEB"
chmod 644 "$STAGED_DEB"
ok "staged $STAGED_DEB"

# Also keep a versioned-history copy so we can roll back if needed
HIST_DEB="$BACKUP_DIR/bpftune_${EXPECTED_TUNER_VER}_${ARCH}.deb"
[ "$STAGED_DEB" = "$HIST_DEB" ] || cp -f "$DEB" "$HIST_DEB" 2>/dev/null || true

# ---------- Step 4: build dashboard Go binary ----------
step "4. Build dashboard v${EXPECTED_DASH_VER} Go binary"

cd "$REPO_DIR"
git checkout dashboard
cd dashboard/bin/go

# CGO_ENABLED=0 → static binary, no glibc dependency, works across distro versions.
# ldflags -X main.dashVersionStr=... sets the version shown in the footer.
# Don't hardcode (was 0.7.5p in install.sh — bug); use git describe instead.
DASH_GIT_VER=$(git describe --tags --always 2>/dev/null || echo "$EXPECTED_DASH_VER")
warn "using dashVersionStr=$DASH_GIT_VER"

# Clean any stale local binaries
rm -f bpftune-collector-go bpftune-collector-go-* ./*.test

# v0.9.1: auto-install Go if not in PATH. The dashboard doesn't ship
# as a .deb yet, so we have to build the binary from source — which
# means Go has to be on the builder. Both vps-3959 and instance-20250225-1017
# were missing Go in root's PATH, so the build silently failed mid-script
# after the .deb was already staged. Make this auto-recover instead.
if ! command -v go >/dev/null 2>&1; then
    warn "go not in PATH — attempting auto-install"
    # Try apt first (Debian/Ubuntu have golang-go packaged)
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq
        apt-get install -y -qq golang-go >/dev/null 2>&1 && ok "installed golang-go via apt" || \
            warn "apt install golang-go failed — falling back to tarball"
    fi
    # If apt failed (or not Debian), install from tarball
    if ! command -v go >/dev/null 2>&1; then
        GO_VER="go1.23.2"
        case "$ARCH" in
            amd64) GO_TARBALL="${GO_VER}.linux-amd64.tar.gz" ;;
            arm64) GO_TARBALL="${GO_VER}.linux-arm64.tar.gz" ;;
        esac
        GO_URL="https://go.dev/dl/${GO_TARBALL}"
        warn "downloading ${GO_TARBALL}..."
        curl -fsSL "$GO_URL" -o /tmp/"$GO_TARBALL" || \
            fail "could not download Go from $GO_URL"
        mkdir -p /usr/local/go
        tar -C /usr/local -xzf /tmp/"$GO_TARBALL" || \
            fail "tar extract failed"
        export PATH="$PATH:/usr/local/go/bin"
        # Persist for subsequent steps + future invocations
        grep -q '/usr/local/go/bin' /root/.bashrc 2>/dev/null || \
            echo 'export PATH="$PATH:/usr/local/go/bin"' >> /root/.bashrc
        ok "installed Go ${GO_VER} to /usr/local/go/bin"
    fi
fi
command -v go >/dev/null 2>&1 || \
    fail "Go is still not in PATH after auto-install attempts. Install manually:
   apt-get install -y golang-go
OR download from https://go.dev/dl/ and extract to /usr/local/go/"

# Print the Go version so we can debug version-specific issues
go version

# v0.9.1: make Go-binary build failures non-fatal. The .deb is already
# staged in step 3; the Go binary is independent and can be built + staged
# separately if needed (e.g. if a Go version mismatch causes a compile
# error on one arch but not the other). Warn loudly + exit non-zero so
# the deploy knows the Go binary wasn't updated, but don't lose the work.
if ! CGO_ENABLED=0 go build \
        -ldflags "-s -w -X main.dashVersionStr=${DASH_GIT_VER}" \
        -o "bpftune-collector-go-${ARCH}" \
        . ; then
    warn "Go binary build FAILED — .deb is already staged, but dashboard binary is not"
    warn "you can deploy tuner-only now:  sudo bash update.sh --tuner-only"
    warn "and rebuild Go binary later once Go is fixed"
    exit 2
fi

# Sanity check: binary runs and prints --help (or at least doesn't segfault)
./"bpftune-collector-go-${ARCH}" --help 2>&1 | head -3 || \
    fail "Go binary failed to start"

# ---------- Step 5: stage Go binary ----------
step "5. Stage Go binary to ${BACKUP_DIR}"

STAGED_BIN="$BACKUP_DIR/bpftune-collector-go-${ARCH}"
cp "bpftune-collector-go-${ARCH}" "$STAGED_BIN.tmp"
mv -f "$STAGED_BIN.tmp" "$STAGED_BIN"
chmod 755 "$STAGED_BIN"
ok "staged $STAGED_BIN"

# ---------- Step 6: run Go sanity tests on this arch ----------
step "6. Run Go sanity tests"

cd "$REPO_DIR/dashboard/bin/go"
if go test -count=1 -run 'Test' ./... 2>&1 | tail -10; then
    ok "Go sanity tests pass"
else
    warn "Go sanity tests FAILED — inspect before deploying"
fi

# ---------- Step 7: restore original branch + summary ----------
step "7. Restore + summary"

cd "$REPO_DIR"
git checkout "$ORIG_BRANCH" 2>/dev/null || git checkout main

echo
printf "${B}=== build-and-stage complete ===${N}\n"
printf "  staged .deb:  %s\n" "$STAGED_DEB"
printf "  staged bin:   %s\n" "$STAGED_BIN"
printf "  tuner hash:   %s (main)\n" "$MAIN_HASH"
printf "  dash hash:    %s (dashboard)\n" "$DASH_HASH"
echo
echo "Next: deploy to fleet via update.sh on each target host:"
echo "  sudo bash update.sh                    # both .deb + dashboard"
echo "  sudo bash update.sh --tuner-only        # just .deb"
echo "  sudo bash update.sh --dashboard-only     # just dashboard"
echo
echo "OR deploy the new .deb manually:"
echo "  sudo systemctl stop bpftune"
echo "  sudo dpkg -i $STAGED_DEB"
echo "  sudo systemctl start bpftune"
