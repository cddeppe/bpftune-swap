# bpftune

**Automatic Linux TCP tuning with BPF.** bpftune uses eBPF to monitor TCP
connections and automatically tune congestion control algorithms, buffer
sizes, and other kernel parameters — no manual configuration needed.

An optional **dashboard** provides a real-time web UI for monitoring what
bpftune is doing: per-bucket metrics, swap events, algorithm leaderboards,
and historical charts.

## Quick start

### Install bpftune + dashboard (recommended)

```bash
curl -sSL https://raw.githubusercontent.com/cddeppe/bpftune-swap/main/dashboard/install.sh | bash
```

This installs the bpftune kernel module AND the dashboard. The installer
prompts whether you want the dashboard — answer `Y` (or use `--with-dashboard`
for non-interactive use).

### Install bpftune only (headless)

```bash
curl -sSL https://raw.githubusercontent.com/cddeppe/bpftune-swap/main/dashboard/install.sh | bash -s -- --no-dashboard
```

bpftune runs perfectly fine without the dashboard. Use this on production
servers where you don't need local monitoring.

### Install dashboard only (bpftune already running)

```bash
curl -sSL https://raw.githubusercontent.com/cddeppe/bpftune-swap/main/dashboard/install.sh | bash -s -- --dashboard-only
```

## What is bpftune?

bpftune is a kernel-level TCP optimization tool that uses eBPF to:

- **Monitor** TCP connections in real-time (per-remote-host metrics)
- **Tune** congestion control algorithms automatically (cubic, bbr, htcp,
  dctcp, vegas, and 11 others)
- **Swap** algorithms when a better one is found for a specific destination
- **Track** swap outcomes (win/loss/null) to verify tuning decisions

bpftune runs as a systemd service and requires no user interaction once
installed. It works transparently — your applications benefit from better
TCP tuning without any code changes.

## What is the dashboard?

The dashboard is an **optional** Go binary that provides a web UI for
monitoring bpftune's activity. It reads the BPF maps + kernel logs and
presents:

- **NOW card** — current state per bucket (instances, rate, RTT, best alg)
- **Rate EMA per algorithm** — time series of rate estimates
- **Swap Score per algorithm** — 256 = neutral, above = helping
- **Bad/Null Streaks** — picker penalty indicators
- **Swaps per bin** — swap event frequency over time
- **Swap Target Pick** — penalty-weighted score race (which algorithm the
  picker would choose right now)
- **Proof leaderboard** — proven max / sustained avg / sustained max rates
- **Top destination buckets** — live table of busiest destinations
- **Coverage** — % of snapshots with rate data (fleet health)

### Dashboard features

- **5 time ranges**: 1h, 24h, 7d, 30d, all
- **Real-time SSE** — charts update every 30s via Server-Sent Events
- **Low memory** — streaming CSV reader uses ~50-264MB (not GBs)
- **Multi-arch** — pre-built binaries for amd64 + arm64
- **Edit Labels UI** — assign human-readable names to IP groups
- **Dark/light theme** — auto-detects + toggle

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Kernel (BPF)                          │
│  remote_host_map  │  bpftune service  │  journal logs   │
└───────┬───────────┴──────┬───────────┴──────┬──────────┘
        │                  │                  │
        │ bpftool dump     │ systemd          │ journalctl
        │                  │                  │
┌───────▼──────────────────▼──────────────────▼──────────┐
│              bpftune-collector-go (Go)                   │
│                                                          │
│  ┌─────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐ │
│  │ collect  │  │ render   │  │ stream   │  │  SSE    │ │
│  │ (30s)    │  │ ToDisk   │  │ CSV      │  │ server  │ │
│  │          │  │ (5 min)  │  │ reader   │  │         │ │
│  └────┬─────┘  └────┬─────┘  └──────────┘  └────┬────┘ │
│       │              │                           │       │
│       ▼              ▼                           │       │
│  current.json   bucket_*.json                   │       │
│  buckets.csv    meta.json                       │       │
│  swaps.csv      fleet.json                      │       │
│  srate.csv      swaps.json                      │       │
└─────────────────────────────────────────────────┼───────┘
                                                  │ SSE
                                                  ▼
                                         ┌───────────────┐
                                         │   Browser     │
                                         │  dashboard.js │
                                         └───────────────┘
```

### Key design decisions

- **Streaming CSV reader** — reads 223MB CSVs line-by-line using ~3-5MB of
  memory (not 680MB-2.5GB like loading all rows into structs)
- **Ring buffer** — 1h of data in memory (120 entries × 30s), not the full
  history
- **Async slow renders** — `renderSlowToDisk` (7d/30d/all) runs in a
  background goroutine so HTTP starts in ~5s, not 60s
- **SSE with keepalive** — 25s keepalive comment prevents proxy timeouts;
  no per-second polling (was a 9% CPU bug)
- **Multi-arch** — single binary per arch (amd64 + arm64), no CGO dependencies

See [docs/architecture.md](docs/architecture.md) for the full technical
deep-dive.

## Requirements

- **Linux kernel 5.10+** (for BPF support)
- **root or sudo** (for kernel module + systemd)
- **Supported distros**: Debian 12+, Ubuntu 22.04+, Oracle Cloud, AWS
  (any Linux with `apt`, `dnf`, or `yum`)
- **Architectures**: x86_64 (amd64), aarch64 (arm64)
- **Memory**: 256MB+ for bpftune + dashboard (tested on 1.9GB instances)
- **Disk**: 50MB for binaries + ~1MB/day CSV growth per bucket

## Installation

See [INSTALL.md](INSTALL.md) for detailed step-by-step instructions,
troubleshooting, and configuration options.

## Migrating from the Python dashboard

If you're running the old Python dashboard (commit d7a8227), use the
migration script to upgrade to the Go collector:

```bash
# Build the migration bundle on your source server
bash dashboard/build-migration-bundle.sh

# On each target server:
cp /path/to/bpftune-migration-v0.7.5.tar.gz /root/
cd /root && tar xzf bpftune-migration-v0.7.5.tar.gz
bash migrate.sh            # dry-run
bash migrate.sh --apply    # real migration
```

The migration script:
- Stops + disables + masks old Python services
- Backs up old files to `.python-backup.<timestamp>`
- Installs Go binary + frontend + labels
- Removes nginx port 8080 conflicts automatically
- Preserves historical CSV data
- Auto-detects architecture (amd64/arm64)

## Configuration

### Dashboard

The dashboard runs with sensible defaults:
- **Port**: 8080 (override with `--port`)
- **Data root**: `/var/lib/bpftune`
- **Labels**: empty by default — edit via the "Edit Labels" button in the UI

To change the port, edit the systemd service:
```bash
sed -i 's/--port 8080/--port 8081/' /etc/systemd/system/bpftune-collector-go.service
systemctl daemon-reload
systemctl restart bpftune-collector-go
```

### Labels

Labels map IP addresses to human-readable names (e.g., `2606:1a40::` →
`home-sco`). Edit them via the dashboard's "Edit Labels" button, or
manually edit `/var/lib/bpftune/aliases.labels.json`:

```json
{
    "2606:1a40::": "home-sco",
    "89.168.0.0": "vps-de",
    "76.76.2.0": "vps-aws"
}
```

IP groups (for v6 → v4 folding) go in `/etc/bpftune/aliases`:
```
2606:50c0:0:0:0:0:0:0 = 76.76.2.0 home-sco
```

## Uninstall

### Dashboard only

```bash
systemctl stop bpftune-collector-go
systemctl disable bpftune-collector-go
rm -rf /opt/bpftune-dashboard/bin
rm /etc/systemd/system/bpftune-collector-go.service
systemctl daemon-reload
```

### Everything (bpftune + dashboard)

```bash
# Remove dashboard
systemctl stop bpftune-collector-go
systemctl disable bpftune-collector-go
rm -rf /opt/bpftune-dashboard/bin
rm /etc/systemd/system/bpftune-collector-go.service

# Remove bpftune
systemctl stop bpftune
systemctl disable bpftune
# (bpftune uninstall is distro-specific — check the bpftune docs)

systemctl daemon-reload
```

## Documentation

- [INSTALL.md](INSTALL.md) — detailed installation guide + troubleshooting
- [docs/architecture.md](docs/architecture.md) — technical architecture
- [CHANGELOG.md](CHANGELOG.md) — version history
- [dashboard/bin/](dashboard/bin/) — Go source + frontend files

## License

Same as the bpftune project (GPL-2.0).

## Acknowledgements

- bpftune is developed by Oracle
- This dashboard is a Go rewrite of the original Python dashboard,
  optimized for low memory + low CPU on small VPS instances
