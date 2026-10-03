# Installation Guide

This guide covers installing bpftune (the kernel module) and the optional
dashboard (the web UI). bpftune works fine without the dashboard — install
the dashboard only where you want local monitoring.

## Prerequisites

- **Linux kernel 5.10+** (for BPF support)
- **root or sudo access**
- **curl or wget** (for downloading the install script)
- **Supported distro**: Debian 12+, Ubuntu 22.04+, Oracle Cloud (Oracle Linux),
  AWS (any distro with `apt`, `dnf`, or `yum`)
- **Architecture**: x86_64 (amd64) or aarch64 (arm64)

### Check your system

```bash
# Kernel version (need 5.10+)
uname -r

# Architecture (need amd64 or arm64)
uname -m

# Root access
sudo -v

# Disk space (need ~50MB for binaries + ~1MB/day for CSV)
df -h /opt
```

## Option A: Install both (bpftune + dashboard)

### Interactive (recommended for first-time users)

```bash
curl -sSL https://raw.githubusercontent.com/cddeppe/bpftune-swap/main/dashboard/install.sh | bash
```

The installer prompts:
```
bpftune works perfectly fine without the dashboard.
The dashboard is a web UI for monitoring/visualization — optional.

Install the dashboard? [Y/n]
```

Answer `Y` (or press Enter for yes).

### Non-interactive (for automation/scripts)

```bash
curl -sSL https://raw.githubusercontent.com/cddeppe/bpftune-swap/main/dashboard/install.sh | bash -s -- --with-dashboard
```

### What it does

1. Builds + installs the bpftune kernel module (if not already installed)
2. Starts the `bpftune.service` systemd service
3. Downloads the pre-built dashboard binary from GitHub Releases (auto-detects
   amd64 or arm64)
4. Downloads frontend files (dashboard.js, index.html, dashboard.css,
   labels-api.py)
5. Installs everything to `/opt/bpftune-dashboard/bin/`
6. Checks for nginx port 8080 conflict → removes the conflicting server block
7. Installs the `bpftune-collector-go.service` systemd service
8. Starts the service + verifies HTTP responds

### After install

```bash
# Check bpftune is running
systemctl status bpftune.service

# Check the dashboard is running
systemctl status bpftune-collector-go.service

# Open the dashboard
# http://<your-server-ip>:8080/
```

Wait 5 minutes for the first `renderToDisk` cycle to generate static JSON
files. Charts will populate as data accumulates.

## Option B: Install bpftune only (headless)

```bash
curl -sSL https://raw.githubusercontent.com/cddeppe/bpftune-swap/main/dashboard/install.sh | bash -s -- --no-dashboard
```

This installs only the bpftune kernel module. No web UI. bpftune runs
transparently — your applications benefit from better TCP tuning without
any monitoring overhead.

### Verify

```bash
systemctl status bpftune.service
journalctl -u bpftune.service -f
```

### Install the dashboard later

```bash
bash dashboard/install.sh --dashboard-only
```

## Option C: Install dashboard only (bpftune already running)

Use this if bpftune is already installed and you just want to add the
monitoring dashboard:

```bash
curl -sSL https://raw.githubusercontent.com/cddeppe/bpftune-swap/main/dashboard/install.sh | bash -s -- --dashboard-only
```

### Verify bpftune is installed first

```bash
bpftune --version
# Should output something like: bpftune v6.12.107+deb13-amd64-...
```

If not installed, use Option A or B instead.

## Custom configuration

### Custom port

```bash
curl -sSL ... | bash -s -- --with-dashboard --port 8081
```

### Specific version

```bash
curl -sSL ... | bash -s -- --with-dashboard --version v0.7.5p
```

### Dry-run (see what would be done)

```bash
bash dashboard/install.sh --dry-run
```

## Build from source (advanced)

If you can't download pre-built binaries (air-gapped, custom kernel, etc.):

### Prerequisites

- Go 1.21+ (for building the dashboard)
- Build tools: make, clang, llvm, libbpf-dev, libcap-dev, kernel headers

### Build bpftune

```bash
git clone https://github.com/oracle/bpftune.git
cd bpftune
make -j$(nproc)
sudo make install
sudo systemctl enable --now bpftune.service
```

### Build the dashboard

```bash
git clone https://github.com/cddeppe/bpftune-swap.git
cd bpftune/dashboard/bin/go

# Build for the current architecture
go build -o /opt/bpftune-dashboard/bin/bpftune-collector-go .

# Or cross-compile:
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o bpftune-collector-go-arm64 .
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bpftune-collector-go-amd64 .

# Copy frontend files
cp ../dashboard.js ../index.html ../dashboard.css ../labels-api.py \
   /opt/bpftune-dashboard/bin/

# Create the systemd service (see install.sh for the unit file)
```

## Troubleshooting

### Service won't start: "Exec format error"

The binary architecture doesn't match the system. Check:

```bash
file /opt/bpftune-dashboard/bin/bpftune-collector-go
# Should say: ELF 64-bit LSB executable, ARM aarch64 (on ARM servers)
# OR: ELF 64-bit LSB executable, x86-64 (on x86 servers)
```

If it's the wrong architecture, re-run the installer (it auto-detects) or
manually download the correct binary from GitHub Releases.

### Port 8080 already in use

The installer automatically removes nginx server blocks on port 8080. If
something else is using the port:

```bash
# Find what's using port 8080
ss -tlnp | grep :8080

# Kill it
fuser -k 8080/tcp

# Or use a different port
sed -i 's/--port 8080/--port 8081/' /etc/systemd/system/bpftune-collector-go.service
systemctl daemon-reload
systemctl restart bpftune-collector-go
```

### High CPU usage

The dashboard should use 0-6% CPU average (brief spike every 30s during
collect). If it's using constant high CPU:

```bash
# Check if crash-looping
systemctl show -p NRestarts bpftune-collector-go

# Check the journal
journalctl -u bpftune-collector-go -n 30 --no-pager

# Check memory (should be <300MB)
systemctl status bpftune-collector-go --no-pager | grep Memory
```

If NRestarts > 0, the service is crash-looping. Check the journal for the
error. Common causes: port conflict, OOM (on very small instances with huge
CSVs — the streaming reader should prevent this).

### Dashboard shows no data

The dashboard needs time to accumulate data:

- **1h chart**: populates within 30s (from ring buffer)
- **24h chart**: populates within 5 min (from CSV tail)
- **7d/30d/all charts**: populate within 30-60s (from streaming CSV reader)

If charts are empty after 10 minutes:

```bash
# Check current.json is being generated
curl -s http://localhost:8080/current.json | python3 -c "
import json, sys
d = json.load(sys.stdin)
print('buckets:', len(d.get('buckets', [])))
print('generated_ts:', d.get('generated_ts'))
"

# Check static files exist
ls /var/lib/bpftune/history/data/

# Check the journal for errors
journalctl -u bpftune-collector-go -n 50 --no-pager | grep -E "error|fail|panic"
```

### OOM on small instances (1.9GB RAM)

If you have a very large CSV (200MB+) on a small instance, the streaming
reader should prevent OOM. But if it still happens:

```bash
# Check if OOM-killed
dmesg | grep -i "oom\|killed" | tail -10

# Check CSV size
ls -lh /var/lib/bpftune/history/buckets.v2.csv

# Temporarily disable slow renders (7d/30d/all)
# (This skips reading the full CSV — 1h/24h still work)
```

### SSE not updating (charts stale)

If charts stop updating (but the service is running):

1. Hard-refresh the browser (Ctrl+Shift+R) — this re-establishes the SSE
   connection
2. Check the browser console (F12) for "SSE failed" messages
3. Verify SSE on the server:
   ```bash
   curl -N -H "Accept: text/event-stream" http://localhost:8080/sse
   # Should see: data: {"__t":"f","v":{...}}
   ```

### Labels not showing

Labels are empty by default. Click "Edit Labels" in the dashboard UI to
assign names to IP groups, or edit manually:

```bash
# Edit /var/lib/bpftune/aliases.labels.json
{
    "2001:db8::": "home-sco",
    "89.0.0.0": "vps-de"
}

# Restart to pick up changes
systemctl restart bpftune-collector-go
```

## FAQ

**Q: Can I run the dashboard on a different server than bpftune?**

Not currently — the dashboard reads the local BPF maps via `bpftool`, which
only works on the same server. For remote monitoring, use a fleet dashboard
that aggregates from multiple servers.

**Q: How much disk does the CSV use?**

~1MB per day per bucket (at 30s intervals × 80 columns). With 8 buckets,
that's ~8MB/day = ~3GB/year. The streaming reader handles any CSV size with
low memory, so you don't need to prune unless disk is tight.

**Q: Can I run multiple dashboards on the same server?**

Yes — use different ports:
```bash
bpftune-collector-go --port 8080
bpftune-collector-go --port 8081 --data-root /var/lib/bpftune-2
```

**Q: Does it work with Docker/LXC?**

The BPF maps require kernel access, so bpftune needs to run on the host
(not in a container). The dashboard can run in a container if it has access
to the BPF maps + log files.
