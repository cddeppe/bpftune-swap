# bpftune (fork)

A fork of [Oracle's bpftune](https://github.com/oracle/bpftune) that adds
**destination-keyed congestion control selection**. Built for hosts that
see mixed-workload traffic — multiple path classes, multiple destinations
— where picking one algorithm for the whole machine is the wrong answer.

## Who this is for

If you run a host where every destination looks the same (a datacenter with
one uplink, a fixed-vendor CDN edge), upstream's model is fine and you
probably don't need this fork.

If you run a host where different destinations genuinely behave
differently — a home-lab edge, a multi-region relay, a router with several
upstreams — this fork tries to learn which algorithm fits each one.

## What's different from upstream

Upstream `main` is frozen at `0.4-2`; every change below is unmerged there.

- **Destination keying.** Buckets are keyed by remote destination IP, not
  next-hop gateway. Upstream's gateway key collapses every destination
  behind a router into one bucket; this fork keeps them separate. This is
  the architectural change the rest of the fork depends on.
- **Algorithms.** Upstream ships 4; this fork extends the pool to 16.
  Selection is by per-destination accumulated metric.
- **Metric.** `rtt_term + rate_term + loss_term`, where
  - `rtt_term` uses queueing delay (`avg_rtt − bucket_min_rtt`), not
    min-vs-min (which is path-constant)
  - `rate_term` measures this socket's delivery rate against the bucket's
    best, not the algorithm's all-time best
  - `loss_term` penalises retransmits as a fraction of sent segments
  - Each algorithm's accumulated value is a count-based incremental mean,
    not a fixed-rate decay
- **Coverage phase.** On a fresh bucket, the first N connections round-robin
  through every algorithm before exploitation begins, so no algorithm is
  excluded by an unlucky first sample.
- **Mid-socket swap.** If a socket's own metric falls far below the current
  leader's on its bucket, the tuner can switch it to the leader mid-flight
  via `bpf_setsockopt(TCP_CONGESTION)` from `RTT_CB`.
- **Persistent state.** Per-destination learning survives restart,
  stop/start, and reboot. Only buckets above a minimum instance count are
  persisted.

## Fixes inherited from upstream

Some (still present upstream):

- IPv4 no-gateway bucket pollution
- IPv6 no-gateway fall-through in the family switch
- Rate term truncation (bytes/µs → bytes/sec)
- Rate term frozen per algorithm

One introduced by the algorithm expansion and fixed here:

- `cdg` metric loop — kernel rejects `cdg` from `bpf_setsockopt`; the
  failure path wasn't checked, so `cdg`'s metric stayed at 0 and won
  every comparison.

## Status

**Actively developed. Not production-hardened. Do not run this on a host
you cannot afford to debug.**

- Tested on a small fleet (4 hosts, 2 architectures)
- Metric and mechanism have been verified on real traffic; the *benefit*
  is not yet proven across a broad set of workloads. On paths where the
  application or the receiver is the bottleneck, congestion-control choice
  may have no measurable effect — the tuner will correctly report that
  rather than fabricate a preference.
- Some design decisions are principled estimates, not measurements. See
  `HANDOFF.md` for the working log, known-open questions, and the
  observation window currently in flight.

## Read more

- `HANDOFF.md` — full development log, design rationale, verification
  methods, and open questions.
- `src/tcp_conn_tuner.bpf.c` — the tuner itself.
- `tools/bucket-leaders.py` — per-destination leaderboard view.

## Build and install

See `HANDOFF.md`. Short version: `make clean && dpkg-buildpackage -b -us -uc`
from the repo root. **`make clean` is mandatory** — the Makefile does not
track the `.bpf.c → .skel.h → .o` chain correctly, and skipping it will
silently produce a package with old code.
