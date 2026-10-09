#!/bin/bash
# update-dashboard.sh — Full dashboard updater for bpftune-swap
# Downloads and installs the latest Go binary + all static assets.
#
# Usage:
#   sudo bash update-dashboard.sh           # auto-detect arch, use latest release
#   sudo bash update-dashboard.sh v0.9.15   # specify version
#   sudo bash update-dashboard.sh --check   # check what's installed vs latest
#
set -e

REPO="cddeppe/bpftune-swap"
INSTALL_DIR="/opt/bpftune-dashboard/bin"
SERVICE="bpftune-collector-go"

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64) ASSET_NAME="bpftune-dashboard-amd64" ;;
    aarch64|arm64) ASSET_NAME="bpftune-dashboard-arm64" ;;
    *) echo "ERROR: Unsupported architecture: $ARCH"; exit 1 ;;
esac

# Functions
get_latest_release() {
    curl -s "https://api.github.com/repos/$REPO/releases/latest" | \
        python3 -c "import sys,json; print(json.load(sys.stdin).get('tag_name',''))" 2>/dev/null
}

get_installed_version() {
    if [ -x "$INSTALL_DIR/bpftune-collector-go" ]; then
        "$INSTALL_DIR/bpftune-collector-go" -version 2>/dev/null | head -1 | grep -oP 'v[\d.]+' || echo "unknown"
    else
        echo "not installed"
    fi
}

check_mode() {
    echo "=== bpftune-swap dashboard status ==="
    echo ""
    
    # Get latest release from GitHub
    LATEST=$(get_latest_release)
    if [ -z "$LATEST" ]; then
        echo "ERROR: Cannot reach GitHub API"
        exit 1
    fi
    echo "Latest release:  $LATEST"
    
    # Check installed binary
    if [ -x "$INSTALL_DIR/bpftune-collector-go" ]; then
        BIN_SIZE=$(stat -c%s "$INSTALL_DIR/bpftune-collector-go" 2>/dev/null || stat -f%z "$INSTALL_DIR/bpftune-collector-go" 2>/dev/null || echo "?")
        BIN_DATE=$(stat -c%y "$INSTALL_DIR/bpftune-collector-go" 2>/dev/null | cut -d. -f1 || stat -f%Sm "$INSTALL_DIR/bpftune-collector-go" 2>/dev/null || echo "?")
        echo "Installed binary: $INSTALL_DIR/bpftune-collector-go"
        echo "  Size: $BIN_SIZE bytes"
        echo "  Modified: $BIN_DATE"
    else
        echo "Installed binary: NOT FOUND"
    fi
    echo ""
    
    # Check dashboard.js
    if [ -f "$INSTALL_DIR/dashboard.js" ]; then
        JS_DATE=$(stat -c%y "$INSTALL_DIR/dashboard.js" 2>/dev/null | cut -d. -f1 || stat -f%Sm "$INSTALL_DIR/dashboard.js" 2>/dev/null || echo "?")
        JS_SIZE=$(stat -c%s "$INSTALL_DIR/dashboard.js" 2>/dev/null || stat -f%z "$INSTALL_DIR/dashboard.js" 2>/dev/null || echo "?")
        echo "dashboard.js: $INSTALL_DIR/dashboard.js"
        echo "  Size: $JS_SIZE bytes"
        echo "  Modified: $JS_DATE"
    else
        echo "dashboard.js: NOT FOUND"
    fi
    echo ""
    
    # Check other assets
    for ASSET in index.html dashboard.css chart.umd.min.js chartjs-adapter-date-fns.bundle.min.js labels-api.py; do
        if [ -f "$INSTALL_DIR/$ASSET" ]; then
            echo "  ✓ $ASSET"
        else
            echo "  ✗ $ASSET (missing)"
        fi
    done
    echo ""
    
    # Check service status
    if systemctl is-active --quiet "$SERVICE" 2>/dev/null; then
        echo "Service: ACTIVE (running)"
    else
        echo "Service: INACTIVE or not found"
    fi
    echo ""
    
    # Check what the dashboard reports as its version
    if curl -s http://localhost:8080/current.json 2>/dev/null | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    b=d.get('build',{})
    print(f\"Dashboard reports: v{b.get('dash_version','?')}\")
    print(f\"Tuner version: {b.get('version','?')}\")
    print(f\"Buckets: {len(d.get('buckets',[]))}\")
    print(f\"Degraded: {d.get('degraded',False)}\")
except:
    print('Dashboard not responding on port 8080')
" 2>/dev/null; then
        true
    fi
    echo ""
    echo "To update: sudo bash $0"
    exit 0
}

# Parse args
VERSION=""
if [ "$1" = "--check" ] || [ "$1" = "-c" ]; then
    check_mode
elif [ -n "$1" ]; then
    VERSION="$1"
fi

# Get version to download
if [ -z "$VERSION" ]; then
    VERSION=$(get_latest_release)
    if [ -z "$VERSION" ]; then
        echo "ERROR: Cannot determine latest release. Specify version manually:"
        echo "  sudo bash $0 v0.9.15"
        exit 1
    fi
fi

echo "=== Updating bpftune-swap dashboard to $VERSION ==="
echo "Architecture: $ARCH ($ASSET_NAME)"
echo "Install dir: $INSTALL_DIR"
echo ""

# Stop service
echo "[1/6] Stopping service..."
systemctl stop "$SERVICE" 2>/dev/null || true
echo "  Done."
echo ""

# Backup current files
echo "[2/6] Backing up current files..."
BACKUP_DIR="$INSTALL_DIR/backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"
for f in bpftune-collector-go dashboard.js index.html dashboard.css chart.umd.min.js chartjs-adapter-date-fns.bundle.min.js labels-api.py; do
    if [ -f "$INSTALL_DIR/$f" ]; then
        cp "$INSTALL_DIR/$f" "$BACKUP_DIR/$f"
    fi
done
echo "  Backup saved to: $BACKUP_DIR"
echo ""

# Download Go binary
echo "[3/6] Downloading Go binary ($ASSET_NAME)..."
BIN_URL="https://github.com/$REPO/releases/download/$VERSION/$ASSET_NAME"
curl -L -f -o "$INSTALL_DIR/bpftune-collector-go.new" "$BIN_URL"
if [ ! -s "$INSTALL_DIR/bpftune-collector-go.new" ]; then
    echo "  ERROR: Download failed or empty file"
    rm -f "$INSTALL_DIR/bpftune-collector-go.new"
    exit 1
fi
chmod +x "$INSTALL_DIR/bpftune-collector-go.new"
mv "$INSTALL_DIR/bpftune-collector-go.new" "$INSTALL_DIR/bpftune-collector-go"
echo "  Done: $(stat -c%s "$INSTALL_DIR/bpftune-collector-go" 2>/dev/null || stat -f%z "$INSTALL_DIR/bpftune-collector-go") bytes"
echo ""

# Download dashboard.js
echo "[4/6] Downloading dashboard.js..."
JS_URL="https://github.com/$REPO/releases/download/$VERSION/dashboard.js"
curl -L -f -o "$INSTALL_DIR/dashboard.js" "$JS_URL"
if [ ! -s "$INSTALL_DIR/dashboard.js" ]; then
    echo "  WARNING: dashboard.js download failed — keeping existing version"
    cp "$BACKUP_DIR/dashboard.js" "$INSTALL_DIR/dashboard.js" 2>/dev/null || true
fi
echo "  Done: $(stat -c%s "$INSTALL_DIR/dashboard.js" 2>/dev/null || stat -f%z "$INSTALL_DIR/dashboard.js") bytes"
echo ""

# Download other static assets (from the dashboard branch, not releases)
# v0.9.32: always download dashboard.css and index.html (they may have
# changed). Only skip the large vendor files (chart.umd, chartjs-adapter)
# and labels-api.py if they already exist.
echo "[5/6] Checking static assets..."
for ASSET in index.html dashboard.css; do
    echo "  Downloading $ASSET..."
    curl -sL -f -o "$INSTALL_DIR/$ASSET" \
        "https://github.com/$REPO/releases/download/$VERSION/$ASSET" 2>/dev/null
    if [ ! -s "$INSTALL_DIR/$ASSET" ]; then
        # Fallback to raw.githubusercontent if not in release
        curl -sL -f -o "$INSTALL_DIR/$ASSET" \
            "https://raw.githubusercontent.com/$REPO/dashboard/dashboard/bin/$ASSET" 2>/dev/null || true
    fi
    if [ -s "$INSTALL_DIR/$ASSET" ]; then
        echo "    ✓ Downloaded"
    else
        echo "    ✗ Failed (non-critical)"
    fi
done
for ASSET in chart.umd.min.js chartjs-adapter-date-fns.bundle.min.js labels-api.py; do
    if [ ! -f "$INSTALL_DIR/$ASSET" ]; then
        echo "  Downloading $ASSET..."
        curl -sL -f -o "$INSTALL_DIR/$ASSET" \
            "https://raw.githubusercontent.com/$REPO/dashboard/dashboard/bin/$ASSET" 2>/dev/null || true
        if [ -s "$INSTALL_DIR/$ASSET" ]; then
            echo "    ✓ Downloaded"
        else
            echo "    ✗ Failed (non-critical)"
            rm -f "$INSTALL_DIR/$ASSET"
        fi
    else
        echo "  ✓ $ASSET already present"
    fi
done
echo ""

# Start service
echo "[6/6] Starting service..."
systemctl start "$SERVICE"
sleep 2
if systemctl is-active --quiet "$SERVICE"; then
    echo "  Service started successfully"
else
    echo "  ERROR: Service failed to start"
    echo "  Check: journalctl -u $SERVICE --since '1 min ago'"
    exit 1
fi
echo ""

# Verify
echo "=== Verification ==="
sleep 3
curl -s http://localhost:8080/current.json 2>/dev/null | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    b=d.get('build',{})
    print(f\"Dashboard version: v{b.get('dash_version','?')}\")
    print(f\"Tuner version: {b.get('version','?')}\")
    print(f\"Buckets: {len(d.get('buckets',[]))}\")
    print(f\"Degraded: {d.get('degraded',False)}\")
    print(f\"Generated: {d.get('generated_ts','?')}\")
    sw = d.get('swap_outcomes',{}).get('swaps_list',[])
    print(f\"Swaps list: {len(sw)} entries\")
    if sw:
        ts = [s.get('ts',0) for s in sw[:3]]
        print(f\"  First 3 timestamps: {ts}\")
except Exception as e:
    print(f'ERROR reading current.json: {e}')
" 2>/dev/null || echo "Dashboard not responding yet (may need a few more seconds)"
echo ""

echo "=== Update complete ==="
echo "Backup: $BACKUP_DIR"
echo ""
echo "IMPORTANT: Hard-refresh your browser (Ctrl+Shift+R) to clear cached JS."
echo ""
echo "If something looks wrong, check:"
echo "  journalctl -u $SERVICE --since '2 min ago'"
echo "  curl -s http://localhost:8080/current.json | python3 -m json.tool | head -30"
