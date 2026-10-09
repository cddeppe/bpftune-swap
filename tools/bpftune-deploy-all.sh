#!/bin/bash
# bpftune dashboard - deploy on this host.
#
# 1. Ensures a systemd unit is capturing bpftune's trace_pipe into
#    /var/log/bpftune-met-live.log (idempotent).
# 2. Pulls the repo.
# 3. Runs the dashboard installer.
#
# Skips hosts where bpftune is not loaded.
#
# Usage:  sudo bash tools/bpftune-deploy-all.sh

set -e

TRACE_OUT=/var/log/bpftune-met-live.log
TRACE_UNIT=/etc/systemd/system/bpftune-met-trace.service

# bpftune loaded? Its map existing is the definitive check.
if ! bpftool map dump name remote_host_map > /dev/null 2>&1; then
    echo "[deploy] remote_host_map not present - bpftune not loaded here."
    echo "[deploy] skipping this host."
    exit 0
fi

# ---- 1. trace capture ----

TRACE_PIPE=""
for p in /sys/kernel/tracing/trace_pipe /sys/kernel/debug/tracing/trace_pipe; do
    [ -e "$p" ] && TRACE_PIPE="$p" && break
done

if [ -z "$TRACE_PIPE" ]; then
    echo "[deploy] no trace_pipe mounted - dashboard will run, but log-driven"
    echo "[deploy] sections (swaps, divergence, proof) will stay empty."
elif systemctl is-active --quiet bpftune-met-trace.service 2>/dev/null; then
    echo "[deploy] trace capture already running"
else
    echo "[deploy] setting up trace capture: $TRACE_PIPE -> $TRACE_OUT"
    pkill -f "cat $TRACE_PIPE" 2>/dev/null || true
    touch "$TRACE_OUT"

    cat > "$TRACE_UNIT" <<UNIT
[Unit]
Description=bpftune trace_pipe capture
After=network.target bpftune.service
Wants=bpftune.service

[Service]
Type=simple
ExecStart=/bin/cat $TRACE_PIPE
StandardOutput=append:$TRACE_OUT
StandardError=append:$TRACE_OUT
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
UNIT

    systemctl daemon-reload
    systemctl enable --now bpftune-met-trace.service
    sleep 2
    if systemctl is-active --quiet bpftune-met-trace.service; then
        echo "[deploy] trace service: active"
    else
        echo "[deploy] trace service failed to start - inspect with:"
        echo "         systemctl status bpftune-met-trace.service"
    fi
fi

# ---- 2. repo ----

REPO=""
for d in "$HOME/bpftune" /home/*/bpftune /root/bpftune /opt/bpftune; do
    [ -d "$d/.git" ] && REPO="$d" && break
done

if [ -z "$REPO" ]; then
    echo "[deploy] cloning to $HOME/bpftune"
    git clone https://github.com/cddeppe/bpftune "$HOME/bpftune"
    REPO="$HOME/bpftune"
fi

echo "[deploy] repo: $REPO"
cd "$REPO"

echo "[deploy] pulling latest"
if ! git pull --ff-only 2>/dev/null; then
    echo "[deploy] pull blocked - clearing generated tools and retrying"
    git checkout -- tools/bpftune-collector.py tools/bpftune-render.py 2>/dev/null || true
    git pull --ff-only
fi

# ---- 3. installer ----

echo "[deploy] running installer"
sudo python3 tools/bpftune-dashboard-install.py

echo
echo "[deploy] done."
echo "         dashboard: http://<this-host>:8080/"
echo "         collector log: /var/log/bpftune-collector.log"
echo "         trace service: systemctl status bpftune-met-trace"
