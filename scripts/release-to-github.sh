#!/bin/bash
# release-to-github.sh — create the v0.4.94 release using gh CLI.
#
# Matches the workflow in RELEASING.md (commit bf6ad74):
#   - cross-compile BOTH arches on this builder (one builder, no parallel)
#   - use `gh release create` (already authenticated via `gh auth login`)
#   - upload BOTH versioned and non-versioned asset names (update.sh
#     uses non-versioned, direct URLs use versioned)
#
# Run on vps-3959 (the amd64 builder that's already `gh auth login`-ed).
# Cross-compiles arm64 too, so no need to run on instance-20250225-1017.
#
# Usage:
#   sudo bash scripts/release-to-github.sh
#
# Prereqs:
#   - gh CLI installed + authenticated (gh auth login)
#   - Go installed (auto-installed by build-and-stage.sh if missing)
#   - /mnt/backup/bpftune-custom-0.4.94-{amd64,arm64}.deb (from build-and-stage.sh
#     on both builders — /mnt/backup/ may not be shared, so build on each
#     builder first and stage)

set -Eeuo pipefail

G='\033[0;32m'; R='\033[0;31m'; Y='\033[0;33m'; B='\033[1m'; N='\033[0m'
ok()   { printf "${G}✓${N} %s\n" "$1"; }
fail() { printf "${R}✗${N} %s\n" "$1" >&2; exit 1; }
warn() { printf "${Y}!${N} %s\n" "$1"; }
step() { printf "\n${B}== %s ==${N}\n" "$1"; }

trap 'fail "Aborted at line $LINENO (exit code $?)"' ERR

# ---------- Config ----------
REPO="cddeppe/bpftune-swap"
VERSION="0.4.95"
DASH_VERSION="0.9.0"
TAG="v${VERSION}"

RELEASE_TITLE="v${VERSION} — IPv4-mapped IPv6 + dashboard v${DASH_VERSION} (cookie→dest persistence)"
RELEASE_NOTES=$(cat <<EOF
## What's new

### Tuner ${VERSION} (main branch)
- **Fix:** IPv4-mapped IPv6 connections (\`::ffff:1.2.3.4\`) were not folded
  to v4 in the BPF bucket path. Dual-stack \`AF_INET6\` sockets connecting
  to v4 peers were bucketed under \`::/32\` (which dashboard read as
  \`0.0.0.0\`), lumping every v4 peer into a single useless bucket.
  Now routed through the v4 bucket path (with \`prefix4\` masking).
- All 9 \`bpf_printk\` sites that emit \`dest=\` now log the correct v4
  address for v4-in-v6 connections (was 0 because \`ops->remote_ip4\`
  is only populated for \`AF_INET\`).

### Dashboard v${DASH_VERSION} (dashboard branch)
- **Fix:** Cookie→dest map was rebuilt from only 2MB log tail every 30s;
  cookies from older \`estab\` events were missing → dest="" → bare middot
  in the proofs panel (the user-reported "dash" bug).
- **Fix:** \`rxEstab\` regex now captures \`dest6b=\` group (was missing
  entirely); \`cdest\` map type \`[2]string\` → \`[3]string{v4,v6,v6b}\` so
  \`/64\` IPv6 labels can match.
- **New:** \`cookie_dest.go\` — persistent cookie→dest map across cycles
  + restarts. Atomic save, throttled, content-hashed, FIFO eviction
  at 200k entries.
- **Fix:** Truth file (\`swapscore_truth.jsonl\`) now gets IPv6 entries —
  was 100% IPv4-only before.
- **Fix:** Frontend \`shortAddr()\` handles full \`/64\` IPv6 form;
  renders \`(unknown)\` for genuine empty dests instead of bare middot.

### Sanity tests
7 Go sanity tests pass on both amd64 + arm64:
- rxEstab captures dest6b group
- destStr produces full /64 form when v6b present
- destStr falls back to v6:hex when v6b absent (backward compat)
- cookieDestMap stores v6b
- cookieDestMap merge does not overwrite with empty fields
- proof events resolve dest via cdest
- rxSwap still matches v4-only swap events

## Deployment

Run \`scripts/deploy-this-host.sh\` on each fleet host:
\`\`\`
sudo bash scripts/deploy-this-host.sh
\`\`\`

Or use \`update.sh\` (auto-downloads from this release):
\`\`\`
sudo bash update.sh
\`\`\`
EOF
)

# ---------- Pre-flight ----------
[ "$(id -u)" = "0" ] || fail "Run as root (for /mnt/backup access)"

command -v gh >/dev/null 2>&1 || fail "gh CLI not installed.
Install with: apt-get install -y gh
Then authenticate: gh auth login"

# Verify gh is authenticated
if ! gh auth status >/dev/null 2>&1; then
    fail "gh not authenticated. Run: gh auth login"
fi
GH_USER=$(gh api user --jq .login 2>/dev/null || echo "?")
ok "gh authenticated as $GH_USER"

command -v go >/dev/null 2>&1 || {
    warn "Go not installed — installing via apt"
    apt-get install -y -qq golang-go >/dev/null 2>&1 || fail "apt install golang-go failed"
}
ok "Go available: $(go version)"

BACKUP_DIR="/mnt/backup"

# Detect local arch (used below to decide whether to auto-run build-and-stage.sh)
ARCH=$(dpkg --print-architecture 2>/dev/null || uname -m)
case "$ARCH" in
    amd64|x86_64)  ARCH=amd64 ;;
    arm64|aarch64) ARCH=arm64 ;;
esac

printf "${B}=== release-to-github ===${N}\n"
printf "  repo:          %s\n" "$REPO"
printf "  tag:           %s\n" "$TAG"
printf "  release title: %s\n" "$RELEASE_TITLE"
echo

# ---------- Step 1: ensure both arch .debs are staged ----------
step "1. Verify staged .deb files"

DEB_AMD64=""
DEB_ARM64=""
# 0.4.95: support both naming conventions (see deploy-this-host.sh).
for p in "$BACKUP_DIR/bpftune-custom-${VERSION}-amd64.deb" \
         "$BACKUP_DIR/bpftune_${VERSION}_amd64.deb"; do
    [ -f "$p" ] && DEB_AMD64="$p" && break
done
for p in "$BACKUP_DIR/bpftune-custom-${VERSION}-arm64.deb" \
         "$BACKUP_DIR/bpftune_${VERSION}_arm64.deb"; do
    [ -f "$p" ] && DEB_ARM64="$p" && break
done

# If the local arch .deb is missing, run build-and-stage.sh first
# (uses the same naming-convention-flexible lookup as above)
LOCAL_DEB=""
case "$ARCH" in
    amd64) LOCAL_DEB="$DEB_AMD64" ;;
    arm64) LOCAL_DEB="$DEB_ARM64" ;;
esac

if [ -z "$LOCAL_DEB" ] || [ ! -f "$LOCAL_DEB" ]; then
    warn "missing local arch ${ARCH} .deb — running build-and-stage.sh first"
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    bash "$SCRIPT_DIR/build-and-stage.sh" || fail "build-and-stage.sh failed"
    # Re-detect after build
    for p in "$BACKUP_DIR/bpftune-custom-${VERSION}-${ARCH}.deb" \
             "$BACKUP_DIR/bpftune_${VERSION}_${ARCH}.deb"; do
        [ -f "$p" ] && LOCAL_DEB="$p" && break
    done
    case "$ARCH" in
        amd64) DEB_AMD64="$LOCAL_DEB" ;;
        arm64) DEB_ARM64="$LOCAL_DEB" ;;
    esac
fi

# Check both arches are staged
if [ ! -f "$DEB_AMD64" ]; then
    fail "missing $DEB_AMD64

/mnt/backup/ is NOT shared between hosts (HANDOFF warns about this).
You need to build on BOTH builders, OR scp the .deb from the other
builder to /mnt/backup/ on this host.

To build on this host only (cross-compile arm64 .deb):
  (this script doesn't do that — dpkg-buildpackage only builds the
  local arch.  Run build-and-stage.sh on instance-20250225-1017 too.)
"
fi

if [ ! -f "$DEB_ARM64" ]; then
    warn "missing $DEB_ARM64 — arm64 .deb not built yet"
    warn "  run build-and-stage.sh on instance-20250225-1017 (arm64 builder)"
    warn "  then scp /mnt/backup/bpftune-custom-${VERSION}-arm64.deb to this host"
    warn "  OR if /mnt/backup/ is shared between builders, just re-run this script"

    # Don't fail — proceed with what we have. User can upload arm64 .deb
    # separately if /mnt/backup/ isn't shared.
    DO_ARM64_DEB=0
else
    DO_ARM64_DEB=1
fi

[ -f "$DEB_AMD64" ] && ok "found $DEB_AMD64"
[ "$DO_ARM64_DEB" = 1 ] && ok "found $DEB_ARM64" || warn "skipping arm64 .deb upload (not staged)"

# ---------- Step 2: cross-compile Go binaries for BOTH arches ----------
step "2. Cross-compile Go binaries (amd64 + arm64)"

REPO_DIR="${REPO_DIR:-/root/bpftune}"
[ -d "$REPO_DIR/.git" ] || fail "$REPO_DIR is not a git checkout"
cd "$REPO_DIR"
git fetch origin --no-tags --prune 2>&1 | tail -2
git checkout dashboard 2>&1 | tail -1
git pull --ff-only origin dashboard 2>&1 | tail -2
DASH_HASH=$(git rev-parse --short HEAD)
ok "dashboard at $DASH_HASH"

cd dashboard/bin/go
rm -f /tmp/bpftune-collector-go-* /tmp/bpftune-collector-go

# Versioned names (used by direct download URLs in RELEASING.md)
warn "building amd64..."
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build \
    -ldflags "-s -w -X main.dashVersionStr=v${DASH_VERSION}-${DASH_HASH}" \
    -o "/tmp/bpftune-collector-go-v${DASH_VERSION}-amd64" .
ok "built amd64"

warn "building arm64..."
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build \
    -ldflags "-s -w -X main.dashVersionStr=v${DASH_VERSION}-${DASH_HASH}" \
    -o "/tmp/bpftune-collector-go-v${DASH_VERSION}-arm64" .
ok "built arm64"

# Verify both binaries (writebackStreaks symbol count >= 7 — proves
# the streak_writeback.go code is in the binary)
for arch in amd64 arm64; do
    bin="/tmp/bpftune-collector-go-v${DASH_VERSION}-${arch}"
    count=$(strings "$bin" | grep -c writebackStreaks || true)
    if [ "$count" -lt 7 ]; then
        warn "$bin: writebackStreaks count=$count (expected >=7) — streak_writeback may not be linked"
    fi
    # Verify it runs on this arch (catches cross-compile bugs)
    if [ "$arch" = "$ARCH" ]; then
        "$bin" --help >/dev/null 2>&1 && ok "$arch binary runs on this host" || \
            fail "$arch binary doesn't run"
    fi
done

# Copy to non-versioned names (used by update.sh — looks for
# 'bpftune-collector-go-{arch}' without version)
cp "/tmp/bpftune-collector-go-v${DASH_VERSION}-amd64" /tmp/bpftune-collector-go-amd64
cp "/tmp/bpftune-collector-go-v${DASH_VERSION}-arm64" /tmp/bpftune-collector-go-arm64
ok "non-versioned copies created"

# ---------- Step 3: create the release ----------
step "3. Create GitHub release $TAG"

# Build asset list (always include both Go binaries)
ASSETS=(
    "/tmp/bpftune-collector-go-v${DASH_VERSION}-amd64"
    "/tmp/bpftune-collector-go-v${DASH_VERSION}-arm64"
    "/tmp/bpftune-collector-go-amd64"
    "/tmp/bpftune-collector-go-arm64"
)
[ -f "$DEB_AMD64" ]  && ASSETS+=("$DEB_AMD64")
[ "$DO_ARM64_DEB" = 1 ] && ASSETS+=("$DEB_ARM64")

# Check if release already exists
if gh release view "$TAG" --repo "$REPO" >/dev/null 2>&1; then
    warn "release $TAG already exists — uploading assets to it"
    # Upload assets (gh release upload is idempotent — duplicates will
    # be skipped, but with --clobber it overwrites)
    gh release upload "$TAG" \
        "${ASSETS[@]}" \
        --repo "$REPO" \
        --clobber
    ok "assets uploaded (overwrote existing if any)"
else
    # Create new release with all assets
    gh release create "$TAG" \
        "${ASSETS[@]}" \
        --title "$RELEASE_TITLE" \
        --notes "$RELEASE_NOTES" \
        --repo "$REPO"
    ok "release $TAG created with ${#ASSETS[@]} assets"
fi

# ---------- Step 4: verify ----------
step "4. Verify release"

echo
gh release view "$TAG" --repo "$REPO" --json assets --jq '.assets[] | "  " + .name + " (" + (.size|tostring) + " bytes)"'

echo
printf "${B}=== release complete ===${N}\n"
echo
echo "Release URL: https://github.com/$REPO/releases/tag/$TAG"
echo
echo "Next: on each fleet host (especially instance-20250225-1017 which has"
echo "a stale Go binary from a Ctrl-C'd deploy), run:"
echo "  sudo bash /root/bpftune/update.sh"
echo "  (auto-downloads from this release)"
