#!/bin/bash
# update_readme.sh — atomic README pusher for cddeppe/bpftune
#
# Usage:  bash update_readme.sh
#
# Does: stash dirty tree → checkout main → pull → write new README.md
#       → commit → push → restore original branch → unstash
#
# Three fixes in one commit:
#   1. Tuning & Customization section with REAL CLI flags (--prefix4, --prefix6, --exp)
#   2. Building & deploying section using install.sh / update.sh one-liners
#   3. Dashboard mockup updated to current layout (bucket dropdown, range selector,
#      Edit Labels, NOW panel, IPv6 keys, real version/hash)

set -euo pipefail
cd /root/bpftune

ORIG=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo main)
STASHED=0
if ! git diff --quiet || ! git diff --cached --quiet; then
    git stash push -u -m "readme-update: $(date -Iseconds)"
    STASHED=1
fi
git fetch --prune origin
git checkout main 2>/dev/null || git checkout -B main origin/main
git pull --rebase --autostash origin main
echo "on main @ $(git rev-parse --short HEAD)"

cat > README.md <<'READMEEOF'
# bpftune fork — per-destination TCP congestion control learning

Custom fork of Oracle's [bpftune](https://github.com/oracle/bpftune). The original bpftune is a general-purpose BPF auto-tuner that handles TCP buffer sizing, net device budgets, route tables, and more. This fork keeps all of that and **extends the TCP connection tuner** with per-destination algorithm learning, mid-socket swapping, sustained-rate scoring, and a full web dashboard with real-time SSE updates.

All original bpftune features (TCP buffer auto-sizing, netdev tuning, route table management, sysctl adjustment, etc.) are preserved and still run alongside the extended tuner.

Runs in production across 5 hosts (amd64 + aarch64) on mixed-workload VPS instances.

---

## What it does

### Per-destination learning

Instead of picking one congestion control algorithm globally, this fork learns which algorithm works best for **each destination IP independently**. A connection to a streaming service might get BBR (great for high-bandwidth), while a connection to a remote VPS gets htcp (better for that path). The learning state is persisted across reboots.

```
                    ┌──────────────────────────────────────────┐
                    │            BPF kernel programs           │
                    │         (sockops + sk_storage)           │
                    │                                          │
  TCP ESTABLISHED ──┼──► bucket key = remote_ip (masked /16    │
                    │                          or /32 for v6)  │
                    │                          │               │
                    │   ┌────────────────────┘                 │
                    │   │                                      │
                    │   ▼                                      │
                    │  remote_host_map (LRU_HASH, 4096)        │
                    │  ┌────────────────────────────────────┐  │
                    │  │ 203.0.113.0  inst=820  best=cubic  │  │
                    │  │ 198.51.100.0 inst=300  best=htcp   │  │
                    │  │ 2001:db8::   inst=229  best=dctcp  │  │
                    │  │ 2001:db8:1:: inst=12K   best=bbr   │  │
                    │  │ ...                                │  │
                    │  │                                    │  │
                    │  │ Each bucket has per-algorithm:     │  │
                    │  │   metric_value (incremental mean)  │  │
                    │  │   rate_ema (exponential moving avg)│  │
                    │  │   swap_score (256 = neutral)       │  │
                    │  │   bad_streak / null_streak         │  │
                    │  │   sockets_alive / good / proved    │  │
                    │  └────────────────────────────────────┘  │
                    │                                          │
  RTT_CB (every    ─┼──► metric sample at 10K/25K/100K/500K/1M │
   checkpoint)      │     segments → vote for best algorithm   │
                    │                                          │
                    │   if socket's metric >= 1.25x best:      │
                    │    → mid-socket swap via                 │
                    │       bpf_setsockopt(TCP_CONGESTION)     │
                    │    → score swap outcome (sustained rate) │
                    │                                          │
                    └──────────────────────────────────────────┘
```

### 16 congestion control algorithms

The fork expanded from the original 4 to **16 algorithms**, each with different strengths:

| Algorithm | Best for |
|---|---|
| cubic | General-purpose (Linux default) |
| bbr | High-bandwidth, low-loss paths |
| htcp | Long-distance, high-RTT |
| dctcp | Datacenter, low-latency |
| vegas | Low-latency, low-loss |
| westwood | Lossy wireless / satellite |
| illinois | Mixed RTT |
| scalable | Datacenter |
| yeah | Mixed congestion |
| lp | Low-priority background |
| bic | Long-distance |
| highspeed | High-speed |
| hybla | Satellite / high-RTT |
| nv | Experimental |
| reno | Classic |
| veno | Wireless |

The tuner explores all 16 per destination, learns which performs best, then exploits the winner. Exploration is epsilon-greedy (1/20 when exploring, picks best when exploiting).

### Mid-socket algorithm swapping

If a long-lived connection (like a 30-minute video stream) gets a bad algorithm at ESTABLISHED, the tuner can **swap it mid-stream** without dropping the connection:

```
Time ──►

ESTABLISHED           RTT_CB (bad metric)         swap            RTT_CB (good metric)
    │                      │                       │                    │
    ▼                      ▼                       ▼                    ▼
    ├──── cubic ───────────┤                       ├──► bbr ────────────┤
    │   (drawn badly)      │                       │   (rescued)        │
    │                      │                       │                    │
    │              metric >= 1.25x best            │                    │
    │              2 consecutive bad checkpoints   │                    │
    │              → bpf_setsockopt(TCP_CONGESTION, "bbr")              │
    │                      │                       │                    │
    │                      │    score = sustained rate (60-300s)        │
    │                      │    ratio = peak_rate / pre_swap_rate       │
    │                      │                       │                    │
    │                      │    ratio >= 1.10 → WIN                     │
    │                      │    ratio <= 0.90 → LOSS                    │
    │                      │    otherwise     → NULL                    │
```

The swap trigger uses:
- `SWAP_BAD_FIRST=1` — first rescue fires on 1 bad checkpoint (fast for 30s+ videos)
- `SWAP_BAD_LATER=2` — subsequent swaps need 2 bad checkpoints (anti-thrash)
- `SWAP_MAX=2` — max 2 swaps per socket
- `T_SETTLE_NS` — 5-second settle window after swap (ignore cold-start readings)
- `MIN_LEADER_TRUST=3` — a leader needs 3 votes before it can be a swap target

### Sustained-rate swap scoring

Instead of judging a swap by a single point-in-time sample, the fork uses **sustained rate measurements** over 60-300 seconds:

```
swap at t=0    post-swap rate samples (srate)
    │
    ▼
    ├──► [60s window: sustained rate = median of srate samples]
    │
    │    ratio_q = peak_post_swap_rate × 256 / pre_swap_rate
    │
    │    ratio_q >= 282  →  WIN   (ratio >= 1.10)
    │    ratio_q <= 230  →  LOSS  (ratio <= 0.90)
    │    otherwise       →  NULL
    │
    │    WIN  → bad_streak=0, null_streak=0  (reset)
    │    LOSS → bad_streak++, null_streak=0   (penalty)
    │    NULL → null_streak++                 (penalty)
    │
    │    penalty = 1.0 - (bad_streak × 0.2 + null_streak × 0.1)
    │    swap_score = rate_ema × raw_score / 256 × penalty
    │
    ▼
    streak_writeback: corrects kernel streak counters from
    authoritative sustained outcomes (runs every collection cycle)
```

### Destination aliasing (IP grouping)

Multiple IPs that lead to the same server are grouped into one bucket via BPF aliases:

```
/etc/bpftune/aliases:
    203.0.113.15           = 203.0.113.0    location-a
    2001:db8:1::abcd       = 203.0.113.0    location-a
    198.51.100.20          = 198.51.100.0   location-b
    ...

BPF lookup at ESTABLISHED:
    socket dest = 203.0.113.15
    → alias map hit → bucket key = 203.0.113.0
    → all IPs in the group share one bucket's stats (instances, rate_ema, swaps)
```

The alias map is a `BPF_MAP_TYPE_HASH` (struct in6_addr → struct in6_addr) pinned at `/sys/fs/bpf/bpftune/tcp_conn/aliases`. Updated live via `bpftool` — no daemon restart needed.

Configurable prefix masking: `bpftune --prefix4=24 --prefix6=64` (runtime, takes effect on next ESTABLISHED, persists across restarts). See [Tuning & Customization](#tuning--customization) for details.

---

## Dashboard

Full web dashboard with real-time SSE (Server-Sent Events) updates:

```
┌─────────────────────────────────────────────────────────────────────────┐
│  bpftune   [bucket ▼ home-sco (1)]   [range 1h|24h|7d|all]   Edit Labels │
│                                       updated 18s ago                    │
├─────────────────────────────────────────────────────────────────────────┤
│  NOW (home-sco)                                                         │
│  instances 820   rate best 87.2 Mb/s   ref rate 0.0   min RTT 34.9 ms  │
│  best alg dctcp   streak 3   swaps 12   algs 16                        │
│  (no live rates for this bucket)  ← shown when bucket has no live data  │
├──────────────────────────────┬──────────────────────────────────────────┤
│  BUILD / SERVICE             │  SYSTEM FACTS                            │
│  version    0.4.83           │  kernel     6.12.197+deb13-amd64         │
│  dashboard  4bd8c86          │  default CC scalable                    │
│  service    active           │  cpu cores   2                           │
│  uptime     13h 56m          │  load        0.51 0.74 0.66              │
│  started    04:08:09 UTC     │  memory      1.39 GB / 4.11 GB (34%)     │
│                              │  host uptime 10d 5h 28m                 │
├──────────────────────────────┴──────────────────────────────────────────┤
│  BPFTUNE-MANAGED TUNABLES                                               │
│  core.netdev_budget=14300        core.netdev_budget_usecs=47681          │
│  ipv4.tcp_rmem=4096 87380 2500000                                       │
│  ipv4.tcp_wmem=4096 65536 67108864                                      │
│  core.rmem_default=1048576                                               │
├─────────────────────────────────────────────────────────────────────────┤
│  TOP DESTINATION BUCKETS                                                │
│  dest          inst    rtt    ref     best     algs  coverage           │
│  v6:26061a40   12K     0.0    0.0     cubic    16    —                 │
│  home-sco      820     34.9   0.0     dctcp    16    —                  │
│  91.123.0.0    1.6K    65.1   67.1    scalable 15    —                   │
│  ...                                                                    │
├──────────────────────────────┬──────────────────────────────────────────┤
│  SWAP TARGET LEADERBOARD      │  PROOF LEADERBOARD                      │
│  alg      re    ss  pen score │  alg       good  prvd  p_max  s_avg    │
│  westwood 87.2  256 1.0 109  │  scalable  9     29    351.3  62.9      │
│  lp       90.4  256 0.8 90.4 │  cubic     2      4    235.2  18.1      │
│  cubic    88.8  256 0.8 88.8 │  dctcp     5      7    229.2  44.7      │
│  ...                          │  ...                                    │
├──────────────────────────────┴──────────────────────────────────────────┤
│  SWAP OUTCOMES (sustained)            RECENT SWAPS                      │
│  win   55  46%                       htcp→highspeed   home-sco · 9s    │
│  null  53  44%                       dctcp→highspeed  home-sco · 21s   │
│  loss  13  11%                       bbr→highspeed    home-sco · 3m    │
│  loss recovery: 5 rescued / 8 full   ...                               │
├──────────────────────────────┬──────────────────────────────────────────┤
│  RECENT PROOFS                │  RATE PROGRESSION                       │
│  westwood  home-sco  63.4    │  thr      n    mean   min   max         │
│  scalable  home-sco  62.9    │  1000     92   2.1    0.0   29.1        │
│  dctcp     91.123    44.7    │  10000    60   2.1    0.0   29.1        │
│  ...                          │  ...                                    │
├──────────────────────────────┴──────────────────────────────────────────┤
│  [All Buckets ▼]   — dropdown filters ALL panels by bucket             │
│                                                                         │
│  Rate EMA per algorithm — Mb/s   ████▆▆▅▅▄▄▃▃  (1h: last 60min)       │
│  Swap Score per algorithm       ██████████████                          │
│  Bad Streak / Null Streak       ▁▁▂▂▃▃▄▄                                │
│  Swaps per bin                  ▃ ▅▇█▇▅▃ ▁▁  (same axis as above)     │
└─────────────────────────────────────────────────────────────────────────┘
```

### Two-tier real-time collection

```
bpftune-collector.service (daemon)
  ├─ SSE server (port 8082, HTTP/1.1)
  │    pushes to browser when data changes
  ├─ 30s lightweight loop
  │    BPF map dump (~50ms, no log parsing)
  │    + incremental log parsing (new lines only, ~10-50 lines)
  │    → NOW panel, buckets, recent_swaps, recent_proofs,
  │      swap_outcomes, churn, swaps_per_bin chart
  └─ 5min full loop
       full collect_all() (2MB log tail)
       → proof leaderboard, rate progression, divergence

browser
  EventSource("/sse") → renderLiveState(doc) on push
  fallback: 30s polling if SSE fails
```

### "All Buckets" + per-bucket filtering

The dropdown defaults to "All Buckets" (aggregate view). Select a specific bucket → ALL panels filter to that bucket's data (swap outcomes, proof leaderboard, rate progression, recent swaps/proofs, swaps-per-bin chart). Filtering is client-side, instant on bucket change.

### IP Label Editor

Group IPs by label. The `labels-api` (port 8081) manages:
- `labels.json` — display labels (IP → name)
- `/etc/bpftune/aliases` — BPF fold rules (FROM = TO [label])
- BPF aliases map — live kernel updates via `bpftool`
- `auto_fold` — when 2+ IPs share a label, automatically picks a canonical (most BPF instances) and folds the others via BPF aliases

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Kernel (BPF)                             │
│                                                                 │
│  tcp_conn_tuner.bpf.c (sockops)                                 │
│    ESTABLISHED → bucket key, alias lookup, prefix mask          │
│    RTT_CB → metric vote, mid-socket swap trigger                │
│    STATE_CB → skip if already voted                             │
│    CLOSE → final vote                                           │
│                                                                 │
│  Maps:                                                          │
│    remote_host_map (LRU_HASH 4096) — per-dest state             │
│    dest_alias_map (HASH 1024) — IP folding                      │
│    sk_storage_map — per-socket state (swap count, settle)       │
│    tuner_config_map — prefix4, prefix6, exp_pct                 │
│                                                                 │
│  State: tcp_conn_tuner.state (persisted, version-checked)       │
└──────────────────────────┬──────────────────────────────────────┘
                           │ bpf_trace_printk → trace_pipe
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Userspace (daemon)                          │
│                                                                 │
│  bpftune (C daemon)                                             │
│    loads aliases → dest_alias_map                               │
│    loads state → remote_host_map                                │
│    saves state on fini (atomic write)                           │
│                                                                 │
│  bpftune-met-trace.service                                      │
│    cat /sys/kernel/tracing/trace_pipe → /var/log/bpftune-*.log  │
│                                                                 │
│  bpftune-collector.service (daemon, Python)                     │
│    30s: BPF map + incremental log → current.json + SSE push     │
│    5min: full log parsing → swap outcomes, proofs, charts       │
│    streak_writeback: corrects kernel streaks from sustained     │
│                                                                 │
│  labels-api.service (port 8081, Python)                         │
│    IP label editor + auto_fold + BPF aliases map management     │
│                                                                 │
│  bpftune-render.py (hourly cron)                                │
│    CSV → data/*.json (historical pages, swaps.json, fleet.json) │
└──────────────────────────┬──────────────────────────────────────┘
                           │ nginx (port 8080)
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Browser (dashboard.js)                     │
│                                                                 │
│  EventSource("/sse") → real-time data push                      │
│  renderLiveState(doc) → all panels                              │
│  _filterByBucket(doc, label) → per-bucket filtering             │
│  _reFilterPanels() → instant re-render on bucket change         │
│  Chart.js → rate_ema, swap_score, streak, swaps-per-bin         │
└─────────────────────────────────────────────────────────────────┘
```

---

## Branches

- **`main`** — BPF tuner only (C code in `src/`)
- **`dashboard`** — dashboard only (Python + HTML + JS in `dashboard/bin/`)

Never commit dashboard files to main or vice versa.

## Dashboard code structure

```
dashboard/bin/
  bpftune_log.py       — base: constants, TypedDicts, log parsing, labels, map reader
  bpftune_data.py      — data functions + outcomes + writeback
  bpftune-cli.py       — entry point: collect_all, collect_lightweight, render
  bpftune-collector.py — daemon: 30s lightweight + 5min full + SSE server
  labels-api.py        — IP label editor + auto_fold + BPF aliases management
  bpftune-render.py    — hourly historical renderer (CSV → JSON)
  streak_writeback.py  — sustained→kernel streak correction
  dashboard.js         — frontend (renderLiveState, filtering, charts)
  dashboard.css        — styling
  index.html           — HTML structure
  test_bpftune_cli.py  — 58 tests (31 unit + 27 integration)
```

CI: GitHub Actions runs 58 tests on every push to `dashboard`.

---

## Compared to the original bpftune

The original [bpftune](https://github.com/oracle/bpftune) is a general-purpose BPF auto-tuner — it monitors system behaviour via BPF and adjusts sysctl parameters (TCP buffer sizes, net device budgets, congestion control, route table, etc.). This fork extends the TCP connection tuner specifically.

| | Original (Oracle) | This fork |
|---|---|---|
| Scope | General-purpose (sysctls, buffers, netdev, routes) | TCP connection tuner only (extended) |
| Congestion control | Global sysctl change (cubic → bbr on loss) | Per-destination (16 algorithms, learned per IP) |
| Algorithm selection | Global (one algorithm for all connections) | Per-destination (best algorithm per remote IP) |
| Mid-socket swap | No (global sysctl, affects new connections only) | Yes (bpf_setsockopt at RTT_CB, live socket) |
| Swap scoring | Loss rate threshold | Sustained rate (60-300s, peak vs pre-swap) |
| Environment | Datacenter (single-path) | Mixed-workload (multi-path, VPS) |
| IP grouping | No | Yes (BPF aliases + label editor) |
| Dashboard | None | Full web UI (SSE, charts, per-bucket filtering) |
| Prefix masking | N/A (global) | Runtime-configurable (`--prefix4`, `--prefix6`) |
| State persistence | No (re-learning on restart) | Yes (version-checked, atomic write) |
| Streak correction | No | Yes (sustained→kernel writeback) |
| Exploration | N/A (reactive, not exploratory) | Epsilon-greedy (coverage=2, adaptive) |
| Real-time updates | syslog only | SSE push to browser (30s lightweight + 5min full) |

---

## Tuning & Customization

`bpftune` exposes standard CLI flags plus three custom flags added by this fork. The custom flags are NOT in `bpftune --help` (help text never updated), but they work — call them directly.

### Standard CLI flags

| Flag | Purpose |
|---|---|
| `-r, --learning_rate N` | 0=conservative (1.0625%), 4=aggressive (25%, **default**). Higher = change tunables more often. |
| `-d, --debug` | Debug output |
| `-D, --daemon` | Daemon mode |
| `-s, --stderr` | Log to stderr (not syslog) |
| `-R, --rollback` | Revert sysctl changes on exit (testing mode) |
| `-S, --support` | Probe BPF feature support |
| `-c, --cgroup PATH` | Filter by cgroup |
| `-l, --libdir PATH` | Plugin dir (default `/usr/local/lib64/bpftune`) |
| `--print-libdir` | Print compiled-in plugin dir, exit |
| `-p, --port PORT` | Query TCP port (default: ephemeral) |
| `-a, --allow NAME.so` | Allow only specific tuner(s) |
| `-L, --legacy` | Force legacy mode |
| `-q, --query QUERY` | Query state (see below) |
| `-V, --version` / `-h, --help` | Version / help |

### Custom fork flags (work, but not in `--help`)

Write to `/var/lib/bpftune/` for persistence; daemon restores on restart. Live updates take effect on next `ESTABLISHED`.

**`--prefix4=N`** (added 0.4.79) — IPv4 bucket prefix width, 1-32. Default 16 (`/16` grouping). `--prefix4=32` = no grouping. `--prefix4=24` = group /24s. Does NOT wipe learned state — only new sockets land under the new prefix. Persists to `/var/lib/bpftune/prefix4`. Mechanism: `tuner_config_map` BPF ARRAY slot 1.

**`--prefix6=N`** (added later) — IPv6 bucket prefix width, 1-128. Default 32 (`/32`). `--prefix6=48` = group /48s (ISP allocation). `--prefix6=64` = group /64s (end-site). Persists to `/var/lib/bpftune/prefix6`. Slot 2.

**`--exp` / `--exp=N`** (added 0.4.64) — Exploration %, 0-100. `--exp` prints current. `--exp=0` = deterministic (no exploration). `--exp=100` = explore every fresh socket (**default**). Persists to `/var/lib/bpftune/explore_pct`. Slot 0. BPF map pinned at `/sys/fs/bpf/bpftune/tcp_conn/explore`.

### Querying state

```bash
bpftune -q summary      # changes made by tuners
bpftune -q tuners       # loaded tuners + state
bpftune -q tunables     # supported tunables
bpftune -q jtunables    # JSON version
bpftune -q status       # current tunable status
bpftune -q jstatus      # JSON version
bpftune -q rollback     # changes to roll back
bpftune -q help         # list of queries
```

### Learning rate levels

| Rate | Sensitivity |
|---|---|
| 0 | 1.0625% — very conservative |
| 1 | 3.125% — conservative |
| 2 | 6.25% — moderate |
| 3 | 12.5% — aggressive |
| 4 (default) | 25% — very aggressive |

### IP grouping via aliases (`/etc/bpftune/aliases`)

```
203.0.113.15     = 203.0.113.0    location-a
2001:db8:1::abcd = 203.0.113.0    location-a
198.51.100.20    = 198.51.100.0   location-b
```

`FROM = TO` folds `FROM` into `TO`'s bucket. Optional `label` shows in the dashboard. Live updates via the dashboard's **IP Label Editor** modal (labels-api writes file + reloads BPF map via `bpftool`, no daemon restart). Manual edits need `systemctl restart bpftune`.

### Advanced BPF map knobs (recompile-only)

In the BPF program, not CLI-tunable:
- `SWAP_BAD_FIRST=1`, `SWAP_BAD_LATER=2`, `SWAP_MAX=2` — swap trigger thresholds
- `T_SETTLE_NS=5e9` — 5s settle window after swap
- `MIN_LEADER_TRUST=3` — votes before a leader can be a swap target

### Sustained-rate scoring

- `ratio_q >= 282` → WIN (ratio >= 1.10)
- `ratio_q <= 230` → LOSS (ratio <= 0.90)
- otherwise → NULL
- Penalty: `1.0 - (bad_streak × 0.2 + null_streak × 0.1)`

### State file — reset learning

```bash
systemctl stop bpftune
rm /var/lib/bpftune/tcp_conn_tuner.state
systemctl start bpftune
```

Daily backup at `/mnt/backup/tcp_conn_tuner.state.$(date +%A)` (7-day rotation).

### Dashboard-managed sysctls

The **BPFTUNE-MANAGED TUNABLES** panel shows sysctls bpftune is auto-tuning. Don't `sysctl -w` them — bpftune overrides on next cycle.

### systemd overrides

```bash
systemctl edit bpftune.service
[Service]
ExecStart=
ExecStart=/usr/sbin/bpftune -r 2 --prefix4=24 --prefix6=48 --exp=10
systemctl daemon-reload && systemctl restart bpftune
```

Override lives at `/etc/systemd/system/bpftune.service.d/override.conf`, survives `dpkg -i`.

---

## Building & deploying

### Quick install (fresh host)

```bash
curl -fsSL https://raw.githubusercontent.com/cddeppe/bpftune/main/install.sh | sudo bash -s -- --yes
```

Flags: `--yes` (non-interactive), `--no-dashboard` (tuner only), `--dashboard-only` (dashboard only), `--help`.

The installer detects arch (amd64/arm64), finds `.deb` in `/mnt/backup/` or downloads from GitHub releases, installs via `dpkg -i`, optionally deploys the dashboard (git clone `dashboard` branch, systemd services, nginx `:8080`, cron, tests).

### Update an existing host

```bash
curl -fsSL https://raw.githubusercontent.com/cddeppe/bpftune/main/update.sh | sudo bash
```

Flags: `--tuner-only`, `--dashboard-only`, `--force-downgrade` (if needed), `--help`.

The updater checks installed vs latest GitHub release, refuses to downgrade without `--force-downgrade`, upgrades `.deb` if newer, pulls `dashboard` branch, syncs files to `/opt/bpftune-dashboard/bin/` + `/var/lib/bpftune/history/`, restarts services, runs tests.

### Cut a new release (builder host)

On the builder (`vps-3959` for amd64, `instance-20250225-1017` for arm64):

```bash
cd /root/bpftune
git checkout main
rm -f src/*.skel.h src/*.bpf.o src/*.o    # mandatory — stale objects bite
make clean
dpkg-buildpackage -b -us -uc
cp ../bpftune_*_*.deb /mnt/backup/
```

Then on `vps-3959` (after both arch `.deb`s are in `/mnt/backup/`), run the atomic release pusher to create the GitHub release with `bpftune-custom-<ver>-<arch>.deb` assets. The release is what `install.sh` and `update.sh` download from.

### Deploy dashboard to other hosts

On each target host:

```bash
curl -fsSL https://raw.githubusercontent.com/cddeppe/bpftune/main/update.sh | sudo bash -s -- --dashboard-only
```

Pulls `origin/dashboard`, syncs to `/opt/bpftune-dashboard/bin/` + `/var/lib/bpftune/history/`, restarts `bpftune-collector` + `bpftune-labels-api`, runs tests.

## Verify

```bash
# BPF programs attached
sudo bpftool cgroup tree 2>/dev/null | grep -c conn_tuner   # want 2

# BPF maps loaded
sudo bpftool map show | grep -E 'remote_host|dest_alias'    # want both

# Dashboard tests
python3 /opt/bpftune-dashboard/bin/test_bpftune_cli.py       # 58 tests

# Dashboard renders
python3 /opt/bpftune-dashboard/bin/bpftune-cli.py --once | head -10

# SSE real-time
curl -s http://localhost:8082/current.json | python3 -c "import json,sys; print(len(json.load(sys.stdin)), 'keys')"

# Version
dpkg-query -W -f='${Version}' bpftune                        # 0.4.83
```

---

## License

Same as upstream bpftune (GPL-2.0).
READMEEOF

echo "  README.md written ($(wc -l < README.md) lines)"

git add README.md
if git diff --cached --quiet; then
    echo "  no changes"
else
    git commit -m "docs: update README — real CLI flags, install.sh/update.sh, current dashboard mockup

1. Tuning & Customization section: corrected to list the REAL CLI flags
   (--prefix4, --prefix6, --exp) with version annotations (0.4.64, 0.4.79)
   and persistence file paths. Sourced from release notes + strings dump
   + actual 'bpftune --exp' output.

2. Building & deploying section: replaced manual build+deploy steps with
   curl-install/curl-update one-liners (install.sh + update.sh). Kept
   manual dpkg-buildpackage steps for the builder host.

3. Dashboard mockup: updated to match current layout — bucket dropdown,
   range selector (1h|24h|7d|all), Edit Labels button, 'updated Xs ago'
   timestamp, NOW panel, IPv6 bucket keys, real version 0.4.83, real
   dashboard hash, fixed-axis charts note.

Also fixed: aliasing section now mentions 'persists across restarts' for
the prefix masking flags. Comparison table row already had the correct
'Runtime-configurable (--prefix4, --prefix6)' claim from a prior commit."
    git push origin main
    echo "  pushed to main @ $(git rev-parse --short main)"
fi

[ "$ORIG" != "main" ] && [ "$ORIG" != "HEAD" ] && {
    git checkout "$ORIG" 2>/dev/null || true
    echo "  back on $ORIG"
}
[ "$STASHED" = 1 ] && git stash pop 2>/dev/null || true

echo
echo "=== Done ==="
echo "  view: https://github.com/cddeppe/bpftune/blob/main/README.md"
