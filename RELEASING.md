# Releasing a new dashboard version

## Prerequisites

- Go installed on the builder (vps-3959)
- `gh` CLI authenticated (`gh auth login`)
- On the `dashboard` branch with all changes committed + pushed

## Build + release (one-shot)

    cd /root/bpftune/dashboard/bin/go
    git checkout dashboard
    git pull origin dashboard

    VERSION=0.8.1  # <-- change this

    # Cross-compile both architectures
    GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build \
        -ldflags "-X main.dashVersionStr=$VERSION" \
        -o /tmp/bpftune-collector-go-$VERSION-amd64 .

    GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build \
        -ldflags "-X main.dashVersionStr=$VERSION" \
        -o /tmp/bpftune-collector-go-$VERSION-arm64 .

    # Verify both binaries
    strings /tmp/bpftune-collector-go-$VERSION-amd64 | grep -c writebackStreaks  # >= 7
    strings /tmp/bpftune-collector-go-$VERSION-arm64 | grep -c writebackStreaks  # >= 7

    # Copy to non-versioned names (for update.sh)
    cp /tmp/bpftune-collector-go-$VERSION-amd64 /tmp/bpftune-collector-go-amd64
    cp /tmp/bpftune-collector-go-$VERSION-arm64 /tmp/bpftune-collector-go-arm64

    # Create GitHub Release with versioned assets
    gh release create v$VERSION \
        /tmp/bpftune-collector-go-$VERSION-amd64 \
        /tmp/bpftune-collector-go-$VERSION-arm64 \
        --title "v$VERSION - <short description>" \
        --notes "<longer description>" \
        --repo cddeppe/bpftune-swap

    # Upload non-versioned assets (for update.sh compatibility)
    gh release upload v$VERSION \
        /tmp/bpftune-collector-go-amd64 \
        /tmp/bpftune-collector-go-arm64 \
        --repo cddeppe/bpftune-swap

    # Verify 4 assets exist
    gh release view v$VERSION --repo cddeppe/bpftune-swap --json assets

## Deploy to all servers

On each server (5 total):

    # Option A: use update.sh (downloads from GitHub Releases)
    curl -fsSL https://raw.githubusercontent.com/cddeppe/bpftune-swap/main/update.sh | sudo bash -s -- --dashboard-only

    # Option B: direct download
    systemctl stop bpftune-collector-go
    ARCH=$(uname -m); [ "$ARCH" = "x86_64" ] && ARCH=amd64; [ "$ARCH" = "aarch64" ] && ARCH=arm64
    curl -L -o /opt/bpftune-dashboard/bin/bpftune-collector-go \
        https://github.com/cddeppe/bpftune-swap/releases/download/v$VERSION/bpftune-collector-go-$VERSION-$ARCH
    chmod +x /opt/bpftune-dashboard/bin/bpftune-collector-go
    systemctl start bpftune-collector-go
    sleep 35

    # Verify
    strings /opt/bpftune-dashboard/bin/bpftune-collector-go | grep -c writebackStreaks
    curl -s http://localhost:8080/current.json | python3 -c "import json,sys;d=json.load(sys.stdin);print('dash_version:', d['build']['dash_version'])"

## Server architecture mapping

| Server | Arch | Binary |
|---|---|---|
| vps-3959 | amd64 | bpftune-collector-go-*-amd64 |
| al | amd64 | bpftune-collector-go-*-amd64 |
| ip-172-26-13-90 | amd64 | bpftune-collector-go-*-amd64 |
| instance-20250225-1017 | arm64 | bpftune-collector-go-*-arm64 |
| instance-20260905-0931 | arm64 | bpftune-collector-go-*-arm64 |

## Important notes

- **Always stop the service before replacing the binary** - otherwise you get "Text file busy" error.
- **Always upload BOTH versioned and non-versioned asset names** - update.sh uses non-versioned, direct URLs use versioned.
- **The ldflags variable is `main.dashVersionStr`** (not `main.dashVersion`). If the version shows as a git hash, the ldflags weren't injected.
- **`CGO_ENABLED=0`** ensures a static binary that works on any Linux of that architecture.
