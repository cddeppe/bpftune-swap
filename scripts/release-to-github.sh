#!/bin/bash
# release-to-github.sh — create a GitHub release for v0.4.94 + v0.9.0
# and upload this builder's staged artifacts (.deb + Go binary).
#
# Run on EACH builder (vps-3959 amd64 + instance-20250225-1017 arm64).
# Both upload to the SAME release (idempotent — if the release already
# exists, just upload this arch's files to it).
#
# Usage:
#   GH_TOKEN=ghp_xxxxx sudo bash scripts/release-to-github.sh
#
# Prereqs:
#   - /mnt/backup/bpftune-custom-0.4.94-${ARCH}.deb (built by build-and-stage.sh)
#   - /mnt/backup/bpftune-collector-go-${ARCH}     (built by build-and-stage.sh)
#   - curl, jq
#   - GitHub Personal Access Token with `repo` scope
#     (create at https://github.com/settings/tokens)
#
# After both builders have run this, the release will have 4 assets:
#   bpftune-custom-0.4.94-amd64.deb
#   bpftune-custom-0.4.94-arm64.deb
#   bpftune-collector-go-amd64
#   bpftune-collector-go-arm64
#
# Then any host can run `update.sh` and it'll find the new release.

set -Eeuo pipefail

G='\033[0;32m'; R='\033[0;31m'; Y='\033[0;33m'; B='\033[1m'; N='\033[0m'
ok()   { printf "${G}✓${N} %s\n" "$1"; }
fail() { printf "${R}✗${N} %s\n" "$1" >&2; exit 1; }
warn() { printf "${Y}!${N} %s\n" "$1"; }
step() { printf "\n${B}== %s ==${N}\n" "$1"; }

trap 'fail "Aborted at line $LINENO (exit code $?)"' ERR

# ---------- Config ----------
REPO="cddeppe/bpftune-swap"
TAG="v0.4.94"
RELEASE_NAME="v0.4.94 — IPv4-mapped IPv6 + dashboard v0.9.0 (cookie→dest persistence)"
RELEASE_BODY=$(cat <<'EOF'
## What's new

### Tuner 0.4.94 (main branch)
- **Fix:** IPv4-mapped IPv6 connections (`::ffff:1.2.3.4`) were not folded
  to v4 in the BPF bucket path. Dual-stack `AF_INET6` sockets connecting
  to v4 peers were bucketed under `::/32` (which dashboard read as
  `0.0.0.0`), lumping every v4 peer into a single useless bucket.
  Now routed through the v4 bucket path (with `prefix4` masking).
- All 9 `bpf_printk` sites that emit `dest=` now log the correct v4
  address for v4-in-v6 connections (was 0 because `ops->remote_ip4`
  is only populated for `AF_INET`).

### Dashboard v0.9.0 (dashboard branch)
- **Fix:** Cookie→dest map was rebuilt from only 2MB log tail every 30s;
  cookies from older `estab` events were missing → dest="" → bare middot
  in the proofs panel (the user-reported "dash" bug).
- **Fix:** `rxEstab` regex now captures `dest6b=` group (was missing
  entirely); `cdest` map type `[2]string` → `[3]string{v4,v6,v6b}` so
  `/64` IPv6 labels can match.
- **New:** `cookie_dest.go` — persistent cookie→dest map across cycles
  + restarts. Atomic save, throttled, content-hashed, FIFO eviction
  at 200k entries.
- **Fix:** Truth file (`swapscore_truth.jsonl`) now gets IPv6 entries —
  was 100% IPv4-only before.
- **Fix:** Frontend `shortAddr()` handles full `/64` IPv6 form;
  renders `(unknown)` for genuine empty dests instead of bare middot.

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

Run `scripts/deploy-this-host.sh` on each fleet host:
```
sudo bash scripts/deploy-this-host.sh
```

Or use `update.sh` (auto-downloads from this release):
```
sudo bash update.sh
```
EOF
)

# ---------- Pre-flight ----------
[ "$(id -u)" = "0" ] || fail "Run as root (for /mnt/backup access)"

ARCH=$(dpkg --print-architecture 2>/dev/null || uname -m)
case "$ARCH" in
    amd64|x86_64)  ARCH=amd64 ;;
    arm64|aarch64) ARCH=arm64 ;;
    *) fail "Unsupported arch: $ARCH" ;;
esac

BACKUP_DIR="/mnt/backup"
EXPECTED_TUNER_VER="0.4.94"

DEB="$BACKUP_DIR/bpftune-custom-${EXPECTED_TUNER_VER}-${ARCH}.deb"
BIN="$BACKUP_DIR/bpftune-collector-go-${ARCH}"

# Auto-rebuild if .deb is missing (saves the user a manual step).
# /mnt/backup/ may not be shared between hosts (HANDOFF warns about this),
# so the .deb built on one builder might not be visible on another.
if [ ! -f "$DEB" ] || [ ! -f "$BIN" ]; then
    warn "missing staged artifacts in $BACKUP_DIR/ — running build-and-stage.sh first"
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    if [ ! -x "$SCRIPT_DIR/build-and-stage.sh" ]; then
        fail "$SCRIPT_DIR/build-and-stage.sh not found or not executable.
This script needs build-and-stage.sh in the same scripts/ directory."
    fi
    bash "$SCRIPT_DIR/build-and-stage.sh" || fail "build-and-stage.sh failed"
    # Re-check after build
    [ -f "$DEB" ] || fail "$DEB still missing after build-and-stage.sh"
    [ -f "$BIN" ] || fail "$BIN still missing after build-and-stage.sh"
    ok "artifacts now staged"
fi

# Need a GitHub token.  Handle three cases:
#   1. GH_TOKEN is empty (user forgot to set it)
#   2. GH_TOKEN is the literal placeholder 'ghp_xxxxx...' (user copy-pasted the
#      example from the script comment)
#   3. GH_TOKEN looks valid (starts with 'ghp_' or 'github_pat_')
GH_TOKEN="${GH_TOKEN:-}"
if [ -z "$GH_TOKEN" ]; then
    fail "GH_TOKEN env var not set (or was stripped by sudo).
Create a token at https://github.com/settings/tokens (needs 'repo' scope), then:

  export GH_TOKEN=ghp_YOUR_REAL_TOKEN
  sudo -E bash $0

OR (without exporting):
  sudo GH_TOKEN=\$GH_TOKEN bash $0

The 'sudo -E' preserves env vars; without it sudo strips GH_TOKEN."
fi
case "$GH_TOKEN" in
    ghp_xxx*|ghp_your*|ghp_REAL*|ghp_PLACEHOLDER*)
        fail "GH_TOKEN looks like a placeholder ($GH_TOKEN).
Create a REAL token at https://github.com/settings/tokens and re-run."
        ;;
    ghp_*|github_pat_*)
        ok "GH_TOKEN looks valid"
        ;;
    *)
        warn "GH_TOKEN doesn't start with 'ghp_' or 'github_pat_' — proceeding anyway"
        ;;
esac

command -v curl >/dev/null || fail "curl not found"
command -v jq   >/dev/null || {
    warn "jq not installed — installing via apt"
    apt-get install -y -qq jq >/dev/null 2>&1 || fail "apt install jq failed"
}

printf "${B}=== release-to-github ===${N}\n"
printf "  arch:        %s\n" "$ARCH"
printf "  repo:        %s\n" "$REPO"
printf "  tag:         %s\n" "$TAG"
printf "  release:     %s\n" "$RELEASE_NAME"
printf "  .deb:        %s\n" "$DEB"
printf "  Go binary:   %s\n" "$BIN"
echo

# ---------- Step 1: create the release (idempotent) ----------
step "1. Create release (or use existing)"

# Check if release already exists
RELEASE_JSON=$(curl -fsSL \
    -H "Authorization: token $GH_TOKEN" \
    -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/$REPO/releases/tags/$TAG" 2>/dev/null || echo "")

RELEASE_ID=$(echo "$RELEASE_JSON" | jq -r '.id // empty')
UPLOAD_URL_BASE=$(echo "$RELEASE_JSON" | jq -r '.upload_url // empty' | sed 's/{?name,label}//')

if [ -z "$RELEASE_ID" ]; then
    warn "release $TAG doesn't exist yet — creating"
    PAYLOAD=$(jq -n \
        --arg tag "$TAG" \
        --arg name "$RELEASE_NAME" \
        --arg body "$RELEASE_BODY" \
        '{tag_name:$tag, name:$name, body:$body, draft:false, prerelease:false}')

    RELEASE_JSON=$(curl -fsSL -X POST \
        -H "Authorization: token $GH_TOKEN" \
        -H "Accept: application/vnd.github+json" \
        "https://api.github.com/repos/$REPO/releases" \
        -d "$PAYLOAD")

    RELEASE_ID=$(echo "$RELEASE_JSON" | jq -r '.id')
    UPLOAD_URL_BASE=$(echo "$RELEASE_JSON" | jq -r '.upload_url' | sed 's/{?name,label}//')

    [ -n "$RELEASE_ID" ] && [ "$RELEASE_ID" != "null" ] || \
        fail "release creation failed: $RELEASE_JSON"

    ok "release created (id=$RELEASE_ID)"
else
    ok "release already exists (id=$RELEASE_ID)"
fi

# Also create the git tag if it doesn't exist yet (so update.sh can find it)
git tag -l "$TAG" | grep -q "^$TAG$" || {
    warn "creating git tag $TAG on current HEAD"
    git tag "$TAG" HEAD 2>/dev/null || warn "could not create tag locally"
    git push origin "$TAG" 2>/dev/null || warn "could not push tag to origin"
}

# ---------- Step 2: upload this arch's .deb ----------
step "2. Upload .deb"

upload_asset() {
    local file="$1"
    local name="$2"
    local content_type="$3"

    # Check if asset with this name already exists in the release
    EXISTING_ASSET_ID=$(echo "$RELEASE_JSON" | \
        jq -r --arg name "$name" '.assets[] | select(.name == $name) | .id' | head -1)

    if [ -n "$EXISTING_ASSET_ID" ]; then
        warn "asset $name already exists (id=$EXISTING_ASSET_ID) — deleting"
        curl -fsSL -X DELETE \
            -H "Authorization: token $GH_TOKEN" \
            -H "Accept: application/vnd.github+json" \
            "https://api.github.com/repos/$REPO/releases/assets/$EXISTING_ASSET_ID" \
            >/dev/null || warn "delete failed (will overwrite)"
    fi

    # Upload
    curl -fsSL -X POST \
        -H "Authorization: token $GH_TOKEN" \
        -H "Accept: application/vnd.github+json" \
        -H "Content-Type: $content_type" \
        --data-binary @"$file" \
        "${UPLOAD_URL_BASE}?name=$name" | jq -r '.name + " (" + (.size|tostring) + " bytes)"' | \
        xargs -I{} ok "uploaded: {}"
}

upload_asset "$DEB" "bpftune-custom-${EXPECTED_TUNER_VER}-${ARCH}.deb" "application/vnd.debian.binary-package"

# ---------- Step 3: upload Go binary ----------
step "3. Upload Go binary"

upload_asset "$BIN" "bpftune-collector-go-${ARCH}" "application/octet-stream"

# ---------- Step 4: summary ----------
step "4. Summary"

# Re-fetch the release to show all uploaded assets
RELEASE_JSON=$(curl -fsSL \
    -H "Authorization: token $GH_TOKEN" \
    -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/$REPO/releases/tags/$TAG")

echo
echo "Assets in release $TAG:"
echo "$RELEASE_JSON" | jq -r '.assets[] | "  " + .name + " (" + (.size|tostring) + " bytes)"'

echo
ok "done. Other arch builder can now run this same script to add their files."
echo
echo "Once both builders have run this, any fleet host can deploy via:"
echo "  sudo bash update.sh              # both .deb + Go binary"
echo "  sudo bash update.sh --tuner-only # just .deb"
echo "  sudo bash update.sh --dashboard-only # just Go binary"
