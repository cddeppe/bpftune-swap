#!/usr/bin/env python3
"""
bpftune dashboard installer. Idempotent - safe to re-run.

    sudo python3 tools/bpftune-dashboard-install.py

Writes three scripts beside itself, migrates old CSVs, installs
/etc/cron.d/bpftune-history, runs both once, verifies output.

`collected_ts` (wall clock) is the only date-safe column. Swap rows
also carry `boot_ts` (monotonic seconds from the log) - never derive
a calendar date from boot_ts.
"""
from __future__ import annotations

import csv
import os
import subprocess
import sys
import time

HIST           = "/var/lib/bpftune/history"
CRON           = "/etc/cron.d/bpftune-history"
BUCKETS_V1     = os.path.join(HIST, "buckets.v1.csv")
BUCKETS_V2     = os.path.join(HIST, "buckets.v2.csv")
BUCKETS_LEGACY = os.path.join(HIST, "buckets.csv")
SWAPS_V1       = os.path.join(HIST, "swaps.v1.csv")
SWAPS          = os.path.join(HIST, "swaps.csv")
SRATE          = os.path.join(HIST, "srate.csv")
SWAPS_POS_V1   = os.path.join(HIST, ".swaps_pos")
SWAPS_POS_V2   = os.path.join(HIST, ".swaps_pos.json")
CURRENT_JSON   = os.path.join(HIST, "current.json")

SELF_DIR  = os.path.dirname(os.path.abspath(__file__))
COLLECTOR = os.path.join(SELF_DIR, "bpftune-collector.py")
RENDERER  = os.path.join(SELF_DIR, "bpftune-render.py")
CLI       = os.path.join(SELF_DIR, "bpftune-cli.py")

CONGS = ["cubic", "bbr", "htcp", "dctcp", "scalable", "vegas", "veno",
         "westwood", "reno", "illinois", "yeah", "lp", "bic", "highspeed",
         "hybla", "nv"]

SCORE_COLS = (["ss_" + a for a in CONGS]
              + ["bs_" + a for a in CONGS]
              + ["ns_" + a for a in CONGS])

SWAP_COLS_REQUIRED = ["socket_rate_before", "dest", "dest_raw",
                      "f_ema", "t_ema", "srate_before"]


def _c(code, s):
    return "\033[" + code + "m" + s + "\033[0m"


def say(m):
    print(_c("1;34", "[installer]") + " " + m, flush=True)


def warn(m):
    print(_c("1;33", "[installer]") + " " + m, flush=True)


def die(m):
    print(_c("1;31", "[installer] FATAL:") + " " + m,
          file=sys.stderr, flush=True)
    sys.exit(1)


def write_file(path, text, mode=0o644):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(text)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def _append_columns(path, new_cols):
    with open(path, newline="") as f:
        rd = csv.reader(f)
        try:
            header = next(rd)
        except StopIteration:
            return
        rows = list(rd)
    new_header = header + list(new_cols)
    tmp = path + ".tmp"
    with open(tmp, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(new_header)
        pad = [""] * len(new_cols)
        for r in rows:
            while len(r) < len(header):
                r.append("")
            w.writerow(r + pad)
    os.replace(tmp, path)


def migrate():
    if os.path.exists(BUCKETS_LEGACY) and not os.path.exists(BUCKETS_V1):
        os.rename(BUCKETS_LEGACY, BUCKETS_V1)
        say("  migrated buckets.csv -> buckets.v1.csv")
    elif os.path.exists(BUCKETS_V1):
        say("  buckets.v1.csv already present")
    else:
        say("  no buckets.csv to migrate")

    if os.path.exists(BUCKETS_V2):
        with open(BUCKETS_V2, newline="") as f:
            first = f.readline().strip()
        cols = first.split(",") if first else []
        missing = [c for c in SCORE_COLS if c not in cols]
        if missing and cols:
            say("  appending %d score/streak columns to buckets.v2.csv "
                "(one-time rewrite of %d MB - be patient)"
                % (len(missing),
                   os.path.getsize(BUCKETS_V2) // (1024 * 1024) or 1))
            _append_columns(BUCKETS_V2, missing)
            say("  buckets.v2.csv migrated")
        else:
            say("  buckets.v2.csv already has ss_*/bs_*/ns_* columns")

    if os.path.exists(SWAPS):
        with open(SWAPS, newline="") as f:
            first = f.readline().strip()
        cols = first.split(",") if first else []
        if "ts_epoch" in cols and "collected_ts" not in cols:
            os.rename(SWAPS, SWAPS_V1)
            say("  migrated swaps.csv -> swaps.v1.csv (schema v1)")
            cols = []
        missing = [c for c in SWAP_COLS_REQUIRED if c not in cols]
        if missing and os.path.exists(SWAPS) and cols:
            _append_columns(SWAPS, missing)
            say("  appended swaps.csv columns: " + ", ".join(missing))
        elif not missing:
            say("  swaps.csv already has all required columns")
    else:
        say("  no swaps.csv yet (will be created)")

    if os.path.exists(SRATE):
        rows = 0
        try:
            with open(SRATE) as f:
                rows = max(0, sum(1 for _ in f) - 1)
        except Exception:
            pass
        say("  srate.csv present (%d rows)" % rows)
    else:
        say("  srate.csv will be created on first 0.4.53+ vote")


def write_cron():
    body = (
        "# managed by bpftune-dashboard-install.py\n"
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
        "* * * * * root %s >> /var/log/bpftune-collector.log 2>&1\n"
        "*/15 * * * * root %s >> /var/log/bpftune-collector.log 2>&1\n"
        % (COLLECTOR, RENDERER)
    )
    write_file(CRON, body, 0o644)


def count_data_rows(path):
    if not os.path.exists(path):
        return 0
    with open(path, newline="") as f:
        return max(0, sum(1 for _ in f) - 1)


def run_and_verify():
    before = count_data_rows(BUCKETS_V2)
    r = subprocess.run([sys.executable, COLLECTOR],
                       capture_output=True, text=True)
    print("    collector:", r.stdout.strip() or "(no output)")
    if r.returncode != 0:
        print(r.stderr)
        die("collector exited non-zero")

    after = count_data_rows(BUCKETS_V2)
    if after == 0:
        die("collector wrote zero rows - is bpftune running and "
            "bpftool able to dump remote_host_map?")
    if after <= before:
        warn("collector added no rows (map unchanged)")
    else:
        say("  buckets.v2.csv now has %d rows" % after)

    if not os.path.exists(CURRENT_JSON):
        warn("current.json not written - CLI snapshot failed")
    else:
        say("  current.json: %d bytes" % os.path.getsize(CURRENT_JSON))

    r = subprocess.run([sys.executable, RENDERER],
                       capture_output=True, text=True)
    print("    renderer:", r.stdout.strip() or "(no output)")
    if r.returncode != 0:
        print(r.stderr)
        die("renderer exited non-zero")

    for p in (os.path.join(HIST, "index.html"),
              os.path.join(HIST, "data", "meta.json")):
        if not os.path.exists(p):
            die("expected output missing: " + p)


# =================== CLI ===================

CLI_SRC = r'''#!/usr/bin/env python3
#!/usr/bin/env python3
"""bpftune live dashboard.

Default: human-readable text (two columns).
--json : single JSON object of the same data - used by the collector.

Three outcome scales are reported:

  composite  - met `val=` ratio (post/pre), from the composite metric.
  srate      - first per-vote `srate=` (raw bytes/sec) after the swap.
  sustained  - median of srate samples in [t+60, t+300]. Excludes the
               immediate cwnd-reset dip after a swap; this is the
               accurate throughput measure. Higher is better.
"""
import argparse, csv, io, json, os, re, socket, struct, subprocess, sys, time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


_LABELS_CACHE = None
_LABELS_MTIME = None

def _load_labels():
    """0.4.79: /var/lib/bpftune/aliases.labels.json {canonical_ip: label}."""
    global _LABELS_CACHE, _LABELS_MTIME
    import os as _os, json as _json
    path = "/var/lib/bpftune/aliases.labels.json"
    try:
        m = _os.path.getmtime(path)
    except OSError:
        _LABELS_CACHE = {}
        _LABELS_MTIME = None
        return _LABELS_CACHE
    if _LABELS_CACHE is not None and _LABELS_MTIME == m:
        return _LABELS_CACHE
    try:
        with open(path) as f:
            d = _json.load(f)
        _LABELS_CACHE = d if isinstance(d, dict) else {}
    except Exception:
        _LABELS_CACHE = {}
    _LABELS_MTIME = m
    return _LABELS_CACHE



def _canon_bucket(addr):
    """Collapse to /16 (v4) or /32 (v6)."""
    if not addr:
        return addr
    if addr.startswith('v6:'):
        return addr
    p = addr.split('.')
    if len(p) == 4:
        return '%s.%s.0.0' % (p[0], p[1])
    return addr


_FOLD_CACHE = None
_FOLD_MTIME = None

def _load_fold():
    """0.4.79: {"v6:XXXXXXXX": "canonical"} from /32-form entries in
    /etc/bpftune/aliases.  Line form:
        2603:c020:0:0:0:0:0:0 = 89.168.0.0 [label]
    Only lines where groups 2..7 are all zero are treated as /32 folds."""
    global _FOLD_CACHE, _FOLD_MTIME
    import os as _os
    path = "/etc/bpftune/aliases"
    try:
        m = _os.path.getmtime(path)
    except OSError:
        _FOLD_CACHE = {}
        _FOLD_MTIME = None
        return _FOLD_CACHE
    if _FOLD_CACHE is not None and _FOLD_MTIME == m:
        return _FOLD_CACHE
    out = {}
    try:
        with open(path) as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                lhs, rhs = line.split("=", 1)
                lhs = lhs.strip()
                bits = rhs.strip().split()
                if not bits:
                    continue
                to = bits[0]
                if "." not in to:
                    continue
                if ":" not in lhs:
                    continue
                groups = lhs.split(":")
                if len(groups) != 8:
                    continue
                if not all(g in ("0", "0000", "") for g in groups[2:]):
                    continue
                key = "v6:" + (groups[0].zfill(4) + groups[1].zfill(4)).lower()
                out[key] = to
    except Exception:
        out = {}
    _FOLD_CACHE = out
    _FOLD_MTIME = m
    return out


def _fold_v6(addr):
    """0.4.79: replace a v6 /32 bucket key with its canonical v4 bucket
    if that /32 is declared in /etc/bpftune/aliases."""
    if not addr or not addr.startswith("v6:"):
        return addr
    return _load_fold().get(addr, addr)


def _label_for(addr):
    if not addr:
        return addr
    addr = _fold_v6(addr)
    addr = _canon_bucket(addr)
    return _load_labels().get(addr, addr)


CONGS = ["cubic","bbr","htcp","dctcp","scalable","vegas","veno","westwood",
         "reno","illinois","yeah","lp","bic","highspeed","hybla","nv"]
LOG_TAIL_BYTES = 2_000_000
BPS_TO_MBPS = 1_000_000.0 / 8.0

RULE   = "\u2500"
DRULE  = "\u2550"
ARROW  = "\u25b8"
VBAR   = "\u2502"
MIDDOT = "\u00b7"

SUSTAINED_LO_S = 60.0
SUSTAINED_HI_S = 300.0


def sh(cmd, timeout=15):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True,
                              text=True, timeout=timeout).stdout
    except Exception:
        return ""


def sh_noshell(args, timeout=12):
    try:
        return subprocess.run(args, capture_output=True, text=True,
                              timeout=timeout).stdout
    except Exception:
        return ""


def median(xs):
    if not xs:
        return None
    s = sorted(xs)
    n = len(s)
    if n % 2:
        return float(s[n // 2])
    return (s[n // 2 - 1] + s[n // 2]) / 2.0


def find_log():
    files = list(Path("/var/log").glob("bpftune-met-*.log"))
    return max(files, key=lambda p: p.stat().st_mtime) if files else None


def tail_recent(budget=LOG_TAIL_BYTES):
    paths = sorted(Path("/var/log").glob("bpftune-met-*.log"),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    if not paths:
        return ""
    chunks = []
    remaining = budget
    for p in paths:
        if remaining <= 0:
            break
        try:
            size = p.stat().st_size
        except OSError:
            continue
        take = min(size, remaining)
        try:
            with open(p, "rb") as f:
                f.seek(size - take)
                chunks.append(f.read().decode("utf-8", errors="replace"))
        except OSError:
            continue
        remaining -= take
    return "".join(reversed(chunks))


def read_map():
    cached = os.environ.get("BPFTUNE_MAP_DUMP_JSON")
    if cached and os.path.exists(cached):
        try:
            with open(cached) as f:
                out = f.read()
        except OSError:
            out = ""
    else:
        out = sh("bpftool --json map dump name remote_host_map 2>/dev/null")
    try:
        data = json.loads(out)
    except Exception:
        return None
    if not isinstance(data, list):
        return None
    entries = []
    for e in data:
        if not isinstance(e, dict):
            continue
        fmt = e.get("formatted") or {}
        v = fmt.get("value"); k = fmt.get("key") or {}
        if not isinstance(v, dict):
            continue
        try:
            inst = int(v.get("instances", 0))
        except Exception:
            continue
        addr = "?"
        b = k.get("in6_u", {}).get("u6_addr8")
        if isinstance(b, list) and len(b) == 16:
            if b[10] == 0xff and b[11] == 0xff:
                addr = ".".join(str(x) for x in b[12:16])
            else:
                v6 = (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]
                addr = "v6:%08x" % v6 if v6 else "0.0.0.0"
        entries.append((inst, _label_for(addr), v))
    # 0.4.79: two map keys can decode to the same final label
    # (an exact-alias entry and a prefix-fold entry for the same
    # physical location).  Merge by final addr -- sum instances,
    # keep the entry with more instances for the other fields.
    _merged = {}
    for _inst, _addr, _v in entries:
        if _addr in _merged:
            _p, _pv = _merged[_addr]
            _merged[_addr] = (_p + _inst, _pv)
            if _inst > _p:
                _merged[_addr] = (_p + _inst, _v)
        else:
            _merged[_addr] = (_inst, _v)
    entries = [(i, a, v) for a, (i, v) in _merged.items()]
    if not entries:
        return None
    entries.sort(key=lambda x: -x[0])
    return entries


def data_build(logpath):
    v = sh("dpkg-query -W -f='${Version}' bpftune").strip() or "?"
    a = sh("systemctl is-active bpftune").strip() or "?"
    ts = sh("systemctl show bpftune -p ActiveEnterTimestamp --value").strip()
    uptime_min = None
    started = ""
    m = re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", ts)
    if m:
        started = m.group(1)[11:19]
        try:
            t = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=timezone.utc)
            uptime_min = int((datetime.now(timezone.utc) - t).total_seconds() // 60)
        except Exception:
            pass
    return {
        "version":     v,
        "service":     a,
        "uptime_min":  uptime_min,
        "started_utc": started,
        "log_path":    str(logpath) if logpath else None,
    }


def data_system():
    out = {
        "kernel":     sh_noshell(["uname", "-r"]).strip(),
        "default_cc": sh_noshell(["sysctl", "-n",
                                  "net.ipv4.tcp_congestion_control"]).strip(),
    }
    try:
        out["cpu_count"] = os.cpu_count()
    except Exception:
        pass
    try:
        la = os.getloadavg()
        out["load_1"] = round(la[0], 2)
        out["load_5"] = round(la[1], 2)
        out["load_15"] = round(la[2], 2)
    except Exception:
        pass
    try:
        with open("/proc/loadavg") as f:
            parts = f.read().split()
        if len(parts) >= 4 and "/" in parts[3]:
            a, b = parts[3].split("/")
            out["procs_running"] = int(a)
            out["procs_total"] = int(b)
    except Exception:
        pass
    try:
        with open("/proc/uptime") as f:
            out["host_uptime_s"] = int(float(f.read().split()[0]))
    except Exception:
        pass
    try:
        mi = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k, _, rest = line.partition(":")
                bits = rest.strip().split()
                if bits:
                    try:
                        mi[k] = int(bits[0]) * 1024
                    except ValueError:
                        pass
        total = mi.get("MemTotal")
        avail = mi.get("MemAvailable")
        if avail is None:
            avail = mi.get("MemFree")
        if total and avail is not None:
            out["mem_total_bytes"] = total
            out["mem_avail_bytes"] = avail
            out["mem_used_bytes"]  = total - avail
            out["mem_used_pct"]    = round(
                100.0 * (total - avail) / total, 1)
    except Exception:
        pass
    return out


def data_tunables():
    j = sh_noshell(["journalctl", "-b", "-u", "bpftune",
                                        "--no-pager", "-q",
                                        "--since", "-24h"])
    names = sorted(set(re.findall(r"sysctl '(net\.[A-Za-z0-9_.]+)'", j)))
    items = []
    for n in names:
        v = sh_noshell(["sysctl", "-n", n]).strip()
        if not v:
            continue
        short = n[4:]
        if "allowed_congestion_control" in n:
            v = "%d algorithms" % len(v.split())
        items.append({"key": short, "value": v})

    def gkey(short):
        parts = short.split(".", 2)
        if len(parts) < 2:
            return short
        return parts[0] + "." + parts[1].split("_", 1)[0]

    groups = {}
    order = []
    for it in items:
        g = gkey(it["key"])
        if g not in groups:
            groups[g] = []
            order.append(g)
        groups[g].append(it)
    return [{"group": g, "items": groups[g]} for g in order]


def data_buckets(hosts, n=8):
    if not hosts:
        return []
    rows = []
    for inst, addr, v in hosts:
        if addr in ("0.0.0.1", "?"):
            continue
        if addr.startswith(("127.", "169.254.", "0.")):
            continue
        if inst < 2:
            continue
        mrv = v.get("max_rate_delivered", 0) or 0
        rtt = v.get("min_rtt", 0) or 0
        bi  = v.get("best_i", 0) or 0
        metrics = v.get("metrics") or []
        used = sum(1 for m in metrics if isinstance(m, dict)
                   and int(m.get("metric_count", 0) or 0) > 0)
        try:
            ref = int(mrv) / BPS_TO_MBPS
        except Exception:
            ref = 0.0
        rows.append({
            "dest":     addr,
            "inst":     inst,
            "rtt_us":   int(rtt),
            "ref_mbps": round(ref, 1),
            "best_alg": CONGS[int(bi)] if int(bi) < 16 else str(bi),
            "n_alg":    used,
        })
        if len(rows) >= n:
            break
    return rows


def _vote_sum(v):
    """Total metric_count across all algs for one bucket. Used to pick
    the bucket whose leaderboard is most informative: a bucket that
    went quiet hours ago has a huge lifetime `instances` count but no
    votes, which would leave the leaderboard empty except for whichever
    alg was last tried on it."""
    metrics = v.get("metrics") or []
    total = 0
    for m in metrics:
        if isinstance(m, dict):
            try:
                total += int(m.get("metric_count", 0) or 0)
            except (TypeError, ValueError):
                pass
    return total


def data_metric(hosts):
    """Swap target leaderboard.

    Sourced from the busiest bucket by total metric_count.

    The picker's score is a three-way product:

        score = rate_ema * (swap_score / 256) * penalty

    where penalty is the recent-failure decay:

        penalty = 16 / (16 + bad_streak*4 + null_streak*2)

    penalty is 1.0 when bad_streak and null_streak are both zero
    (no failures to decay), falls as streaks grow, and always stays
    positive - it's a multiplier, not a gate. The old hard exclusion
    (alg excluded if bad>=2 or null>=3) is gone. Sorted by score; the
    top row is what the picker would choose right now."""
    if not hosts:
        return []
    picked = max(hosts, key=lambda x: _vote_sum(x[2]))
    metrics = picked[2].get("metrics") or []
    rows = []
    for i in range(16):
        m = metrics[i] if i < len(metrics) and isinstance(metrics[i], dict) else {}
        try:
            val = int(m.get("metric_value", 0) or 0)
            mc  = int(m.get("metric_count", 0) or 0)
            a   = int(m.get("sockets_alive", 0) or 0)
            ss  = int(m.get("swap_score", 0) or 0)
            bs  = int(m.get("bad_streak", 0) or 0)
            ns  = int(m.get("null_streak", 0) or 0)
            re_ = int(m.get("rate_ema", 0) or 0)
        except Exception:
            val, mc, a, ss, bs, ns, re_ = 0, 0, 0, 0, 0, 0, 0
        if val in (0, (1<<64)-1):
            val = 0
        penalty = 16.0 / (16.0 + bs * 4.0 + ns * 2.0)
        score   = (re_ * (ss / 256.0)) * penalty
        # Only cells where the alg has any history.
        active = (mc > 0) or (a > 0) or (re_ > 0) or (ss > 0)
        rows.append({
            "alg":    CONGS[i],
            "metric": round(val / 1e6, 1) if val else 0,
            "votes":  mc,
            "alive":  a,
            "rate_ema":    re_,
            "swap_score":  ss,
            "penalty":     round(penalty, 3),
            "score":       round(score, 2),
            "bad_streak":  bs,
            "null_streak": ns,
            "active":      active,
        })
    # Sort: active algs first by score desc; inactive (never tried on
    # this bucket) fall to the bottom in stable order.
    rows.sort(key=lambda r: (0 if r["active"] else 1, -r["score"]))
    return rows


def data_metric_by_bucket(hosts):
    """Per-bucket picker leaderboard, keyed by bucket id.

    Same row shape as data_metric, but for every bucket (sorted by
    total vote count descending).  The frontend picks the entry for
    the bucket currently shown in the dropdown, so the leaderboard
    follows the selection instead of always showing the busiest."""
    if not hosts:
        return {}
    ordered = sorted(hosts, key=lambda x: -_vote_sum(x[2]))
    out = {}
    for inst, addr, v in ordered:
        if addr in ("0.0.0.1", "?"):
            continue
        if addr.startswith(("127.", "169.254.", "0.")):
            continue
        if inst < 2:
            continue
        metrics = v.get("metrics") or []
        rows = []
        for i in range(16):
            m = metrics[i] if i < len(metrics) and isinstance(metrics[i], dict) else {}
            try:
                val = int(m.get("metric_value", 0) or 0)
                mc  = int(m.get("metric_count", 0) or 0)
                a   = int(m.get("sockets_alive", 0) or 0)
                ss  = int(m.get("swap_score", 0) or 0)
                bs  = int(m.get("bad_streak", 0) or 0)
                ns  = int(m.get("null_streak", 0) or 0)
                re_ = int(m.get("rate_ema", 0) or 0)
            except Exception:
                val, mc, a, ss, bs, ns, re_ = 0, 0, 0, 0, 0, 0, 0
            if val in (0, (1<<64)-1):
                val = 0
            penalty = 16.0 / (16.0 + bs * 4.0 + ns * 2.0)
            score   = (re_ * (ss / 256.0)) * penalty
            active  = (mc > 0) or (a > 0) or (re_ > 0) or (ss > 0)
            rows.append({
                "alg":         CONGS[i],
                "metric":      round(val / 1e6, 1) if val else 0,
                "votes":       mc,
                "alive":       a,
                "rate_ema":    re_,
                "swap_score":  ss,
                "penalty":     round(penalty, 3),
                "score":       round(score, 2),
                "bad_streak":  bs,
                "null_streak": ns,
                "active":      active,
            })
        rows.sort(key=lambda r: (0 if r["active"] else 1, -r["score"]))
        out[addr] = rows
    return out


BUCKET_HISTORY_CSV = "/var/lib/bpftune/history/buckets.v2.csv"
LIVE_CHART_MIN      = 65   # 65 min x 60s = 65 pts per series; covers 1h with margin
LIVE_CHART_WIDTH_S  = 60


def data_bucket_live():
    """Live per-bucket 1h chart data, built from the tail of
    buckets.v2.csv.  Only the re_* columns, only the last
    LIVE_CHART_MIN minutes.

    The frontend prefers this for the 1h range so the chart refreshes
    with the browser's 30s tick instead of the renderer's 15-minute
    cron.  Longer ranges still come from data/bucket_*.json."""
    p = Path(BUCKET_HISTORY_CSV)
    if not p.exists():
        return {}

    # Read the real header from the top of the file.  A DictReader
    # over a mid-file chunk would treat the first data row as the
    # header and thus lose every column name.
    with open(p, newline="") as f:
        try:
            header = next(csv.reader(f))
        except StopIteration:
            return {}

    with open(p, "rb") as f:
        f.seek(0, 2)
        size = f.tell()
        take = min(size, 800 * 1024)
        f.seek(size - take)
        if f.tell() > 0:
            f.readline()   # skip partial line
        text = f.read().decode("utf-8", errors="replace")

    rd = csv.DictReader(io.StringIO(text), fieldnames=header)
    now = int(time.time())
    lo  = now - LIVE_CHART_MIN * 60
    per = {}

    for row in rd:
        addr = row.get("addr") or ""
        if not addr or addr in ("0.0.0.1",):
            continue
        if addr.startswith(("127.", "169.254.", "0.")):
            continue
        try:
            t = int(row.get("collected_ts") or 0)
        except (TypeError, ValueError):
            continue
        if t < lo:
            continue
        try:
            inst = int(row.get("instances") or 0)
        except (TypeError, ValueError):
            inst = 0
        if inst < 2:
            continue
        bucket = per.setdefault(_label_for(addr), {"ts": [], "cols": {}})
        bucket["ts"].append(t)
        for alg in CONGS:
            for pre in ("re_", "ss_", "bs_", "ns_"):
                c = row.get(pre + alg)
                try:
                    v = int(c) if c not in (None, "") else None
                except (TypeError, ValueError):
                    v = None
                bucket["cols"].setdefault(pre + alg, []).append(v)

    # bin to LIVE_CHART_WIDTH_S
    for addr, d in per.items():
        pd = {}
        for c, vals in d["cols"].items():
            bins = {}
            for ts_v, v in zip(d["ts"], vals):
                if v is None:
                    continue
                key = ts_v // LIVE_CHART_WIDTH_S
                bins.setdefault(key, []).append(v)
            keys = sorted(bins)
            pd[c] = [[k * LIVE_CHART_WIDTH_S, sum(bins[k]) / len(bins[k])]
                     for k in keys]
        cs = {c: [v for _, v in arr] for c, arr in pd.items()}
        # 0.4.79 fix: pd entries are already [bin*width, value].
        # The previous form multiplied by width a second time, so
        # a 65-minute ring came out as 65 hours on the chart.
        ts = sorted({k for arr in pd.values() for k, _ in arr})
        per[addr] = {"ts": ts, "cols": cs}

    return per


def data_recent_swaps_by_bucket(text, n_per_bucket=16):
    """Same rows as data_recent_swaps, grouped by destination /16 so
    the panel can follow the bucket dropdown.  Returns
    {bucket_str: [row, ...]} ordered newest-first within each."""
    rows = data_recent_swaps(text, n=200)
    out = {}
    # Iterate newest-first so each bucket gets its newest
    # n_per_bucket entries, not the oldest of the window.
    for r in reversed(rows):
        b = r.get("_bucket") or ""
        if not b:
            continue
        lst = out.setdefault(b, [])
        if len(lst) < n_per_bucket:
            lst.append(r)
    # strip the internal key before handing off
    for b, lst in out.items():
        for r in lst:
            r.pop("_bucket", None)
    return out


def _proof_events(text):
    MET_WINDOW_S = 60.0
    lines = text.splitlines()

    events = defaultdict(lambda: {"good": 0, "proved": 0, "proven_max": 0})
    samples = defaultdict(lambda: {"sum": 0, "n": 0, "samp_max": 0})
    met_by_cookie = defaultdict(list)

    for line in lines:
        if "proof cookie=" in line:
            m = re.search(r"alg=(\d+) rate=(\d+) tier=(\d+)", line)
            if m:
                a = int(m.group(1))
                rate = int(m.group(2))
                tier = m.group(3)
                if tier == "2":
                    events[a]["proved"] += 1
                else:
                    events[a]["good"] += 1
                if rate > events[a]["proven_max"]:
                    events[a]["proven_max"] = rate
            continue
        mm = re.search(
            r"(\d+\.\d+): .*met cookie=(\d+) rport=\d+ alg=(\d+) ",
            line)
        if mm:
            ts = float(mm.group(1))
            c  = int(mm.group(2))
            a  = int(mm.group(3))
            met_by_cookie[c].append((ts, a))

    for line in lines:
        ms = re.search(
            r"(\d+\.\d+): .*midsamp cookie=(\d+) .* srate=(\d+)",
            line)
        if not ms:
            continue
        ts = float(ms.group(1))
        c  = int(ms.group(2))
        r  = int(ms.group(3))
        if r <= 0:
            continue
        cand = met_by_cookie.get(c)
        if not cand:
            continue
        best_a = None
        best_d = None
        for (mts, a) in cand:
            d = abs(mts - ts)
            if best_d is None or d < best_d:
                best_d = d
                best_a = a
        if best_a is None or best_d is None or best_d > MET_WINDOW_S:
            continue
        samples[best_a]["sum"] += r
        samples[best_a]["n"] += 1
        if r > samples[best_a]["samp_max"]:
            samples[best_a]["samp_max"] = r

    return events, samples


def data_proof(text):
    events, samples = _proof_events(text)
    if not events and not samples:
        return []
    algs = set(events) | set(samples)
    rows = []
    for a in algs:
        e = events.get(a, {"good": 0, "proved": 0, "proven_max": 0})
        s = samples.get(a, {"sum": 0, "n": 0, "samp_max": 0})
        row = {
            "alg":         CONGS[a] if a < 16 else "alg%d" % a,
            "good":        e["good"],
            "proved":      e["proved"],
            "proven_max":  round(e["proven_max"] / BPS_TO_MBPS, 1)
                           if e["proven_max"] else None,
            "sampled_avg": round(s["sum"] / s["n"] / BPS_TO_MBPS, 1)
                           if s["n"] else None,
            "sampled_max": round(s["samp_max"] / BPS_TO_MBPS, 1)
                           if s["samp_max"] else None,
            "samples":     s["n"] or None,
        }
        rows.append(row)
    rows.sort(key=lambda r: -(r["proven_max"] or 0))
    return rows


def data_rate(text):
    out_map = defaultdict(list)
    for line in text.splitlines():
        if "midsamp" not in line:
            continue
        mt = re.search(r"thr=(\d+)", line)
        mr = re.search(r"rport=(\d+)", line)
        ms = re.search(r"srate=(\d+)", line)
        if not (mt and mr and ms):
            continue
        if mr.group(1) == "443":
            continue
        out_map[int(mt.group(1))].append(int(ms.group(1)))
    rows = []
    for thr in sorted(out_map.keys()):
        vs = out_map[thr]
        rows.append({
            "thr":  thr,
            "n":    len(vs),
            "mean": round(sum(vs) / len(vs) / BPS_TO_MBPS, 1),
            "min":  round(min(vs) / BPS_TO_MBPS, 1),
            "max":  round(max(vs) / BPS_TO_MBPS, 1),
        })
    return rows


def _swaps_mets_srates(text):
    sw = []
    met = defaultdict(list)
    srate = defaultdict(list)
    rx_sw = re.compile(r"(\d+\.\d+): bpf_trace_printk: "
                       r"swap cookie=(\d+) from=(\d+) to=(\d+) "
                       r"bc=(\d+) ac=(\d+) d=(\d+)"
                       r"(?: mt=(\d+) rb=(\d+))?"
                       r"(?: dest=(\d+))?"
                       r"(?: dest6=(\d+))?")
    rx_mt = re.compile(r"(\d+\.\d+): bpf_trace_printk: "
                       r"met cookie=(\d+) rport=(\d+) alg=(\d+) segs=(\d+) val=(\d+)")
    rx_sr = re.compile(r"(\d+\.\d+): bpf_trace_printk: "
                       r"srate cookie=(\d+) alg=(\d+) srate=(\d+)")
    for line in text.splitlines():
        m = rx_sw.search(line)
        if m:
            sw.append((float(m.group(1)), int(m.group(2)),
                       int(m.group(3)), int(m.group(4)),
                       int(m.group(5)), int(m.group(6)), m.group(7),
                       m.group(8), m.group(9), m.group(10), m.group(11), line))
            continue
        v = rx_mt.search(line)
        if v:
            met[int(v.group(2))].append((float(v.group(1)), int(v.group(6))))
            continue
        s = rx_sr.search(line)
        if s:
            srate[int(s.group(2))].append((float(s.group(1)), int(s.group(4))))
    return sw, met, srate


def _outcome_composite(met, c, ts):
    tl = met.get(c, [])
    pre = post = None
    for (mts, mval) in tl:
        if mts < ts + 0.001:
            pre = mval
        elif ts + 3.0 <= mts <= ts + 300.0:
            post = mval; break
    if not pre or not post:
        return None
    r = post / pre
    if r <= 0.9:  return "win"
    if r >= 1.1:  return "loss"
    return "null"


def _outcome_srate(srate, c, ts):
    tl = srate.get(c, [])
    pre = post = None
    for (sts, sr) in tl:
        if sts < ts:
            pre = sr
        elif sts > ts:
            post = sr; break
    if not pre or not post:
        return None
    r = post / pre
    if r >= 1.1:  return "win"
    if r <= 0.9:  return "loss"
    return "null"


def _outcome_sustained(srate, c, ts):
    tl = srate.get(c, [])
    pre = None
    post = []
    for (sts, sr) in tl:
        if sts < ts:
            pre = sr
        elif SUSTAINED_LO_S <= (sts - ts) <= SUSTAINED_HI_S:
            post.append(sr)
    if not pre or not post:
        return None
    pm = median(post)
    if pm is None or pre <= 0:
        return None
    r = pm / pre
    if r >= 1.1:  return "win"
    if r <= 0.9:  return "loss"
    return "null"


def _finalize_outcome(counts):
    total = counts["win"] + counts["null"] + counts["loss"]
    def pct(x):
        return round(100.0 * x / total, 1) if total else 0
    return {
        "measurable":    total,
        "unmeasurable":  counts["skip"],
        "win":           counts["win"],
        "win_pct":       pct(counts["win"]),
        "null":          counts["null"],
        "null_pct":      pct(counts["null"]),
        "loss":          counts["loss"],
        "loss_pct":      pct(counts["loss"]),
    }


def data_swap_outcomes(text):
    sw, met, srate = _swaps_mets_srates(text)
    c_counts = {"win": 0, "null": 0, "loss": 0, "skip": 0}
    s_counts = {"win": 0, "null": 0, "loss": 0, "skip": 0}
    sust_counts = {"win": 0, "null": 0, "loss": 0, "skip": 0}
    for row in sw:
        ts, c = row[0], row[1]
        o = _outcome_composite(met, c, ts)
        if o is None: c_counts["skip"] += 1
        else: c_counts[o] += 1
        o2 = _outcome_srate(srate, c, ts)
        if o2 is None: s_counts["skip"] += 1
        else: s_counts[o2] += 1
        o3 = _outcome_sustained(srate, c, ts)
        if o3 is None: sust_counts["skip"] += 1
        else: sust_counts[o3] += 1
    return {
        "composite": _finalize_outcome(c_counts),
        "srate":     _finalize_outcome(s_counts),
        "sustained": _finalize_outcome(sust_counts),
    }


def data_divergence(text):
    sw, met, srate = _swaps_mets_srates(text)
    keys = ("rate==metric", "rate!=metric", "pre-0.4.45")
    groups = {k: {"total": 0,
                  "win": 0, "null": 0, "loss": 0,
                  "win_s": 0, "null_s": 0, "loss_s": 0,
                  "win_u": 0, "null_u": 0, "loss_u": 0}
              for k in keys}
    for row in sw:
        ts, c = row[0], row[1]
        mt_i, rb_i = row[7], row[8]
        if mt_i is None or rb_i is None: key = "pre-0.4.45"
        elif mt_i == rb_i:               key = "rate==metric"
        else:                            key = "rate!=metric"
        g = groups[key]
        g["total"] += 1
        o = _outcome_composite(met, c, ts)
        if o: g[o] += 1
        o2 = _outcome_srate(srate, c, ts)
        if o2: g[o2 + "_s"] += 1
        o3 = _outcome_sustained(srate, c, ts)
        if o3: g[o3 + "_u"] += 1

    rows = []
    for k in keys:
        g = groups[k]
        cmeas = g["win"] + g["null"] + g["loss"]
        smeas = g["win_s"] + g["null_s"] + g["loss_s"]
        umeas = g["win_u"] + g["null_u"] + g["loss_u"]
        def cp(x):
            return round(100.0 * x / cmeas, 1) if cmeas else 0
        def sp(x):
            return round(100.0 * x / smeas, 1) if smeas else 0
        def up(x):
            return round(100.0 * x / umeas, 1) if umeas else 0
        rows.append({
            "category":  k,
            "measured":  cmeas,
            "win_pct":   cp(g["win"]),
            "null_pct":  cp(g["null"]),
            "loss_pct":  cp(g["loss"]),
            "win":       g["win"],
            "null":      g["null"],
            "loss":      g["loss"],
            "skipped":   g["total"] - cmeas,
            "measured_srate": smeas,
            "win_pct_srate":  sp(g["win_s"]),
            "null_pct_srate": sp(g["null_s"]),
            "loss_pct_srate": sp(g["loss_s"]),
            "win_srate":      g["win_s"],
            "null_srate":     g["null_s"],
            "loss_srate":     g["loss_s"],
            "skipped_srate":  g["total"] - smeas,
            "measured_sustained": umeas,
            "win_pct_sustained":  up(g["win_u"]),
            "null_pct_sustained": up(g["null_u"]),
            "loss_pct_sustained": up(g["loss_u"]),
            "win_sustained":      g["win_u"],
            "null_sustained":     g["null_u"],
            "loss_sustained":     g["loss_u"],
            "skipped_sustained":  g["total"] - umeas,
        })
    return rows


def data_churn(text):
    sw, _met, _sr = _swaps_mets_srates(text)
    counts = defaultdict(int)
    for row in sw:
        counts[row[1]] += 1
    if not counts:
        return {"cookies": 0, "one": 0, "mid": 0, "many": 0, "max": 0}
    one  = sum(1 for v in counts.values() if v == 1)
    mid  = sum(1 for v in counts.values() if 2 <= v <= 4)
    many = sum(1 for v in counts.values() if v >= 5)
    return {"cookies": len(counts), "one": one, "mid": mid,
            "many": many, "max": max(counts.values())}


def _dest_str(v4, v6):
    """Display string for a destination.  Prefers v6 when present."""
    try: n6 = int(v6) if v6 not in (None, "") else 0
    except (TypeError, ValueError): n6 = 0
    if n6:
        return "v6:%08x" % (n6 & 0xFFFFFFFF)
    return _dest_ip(v4)


def _bucket_of(v4, v6):
    try: n6 = int(v6) if v6 not in (None, "") else 0
    except (TypeError, ValueError): n6 = 0
    if n6:
        return "v6:%08x" % (n6 & 0xFFFFFFFF)
    if not v4:
        return ""
    try: n = int(v4)
    except (TypeError, ValueError):
        return ""
    first = (n >> 24) & 0xFF
    if first in (0, 127):
        return ""
    return "%d.%d.0.0" % ((n >> 24) & 0xFF, (n >> 16) & 0xFF)


def _dest_ip(s):
    if s is None or s in ("", "1"):
        return ""
    try:
        n = int(s)
    except (TypeError, ValueError):
        return ""
    first = (n >> 24) & 0xFF
    if first == 0 or first == 127:
        return ""
    try:
        return socket.inet_ntoa(struct.pack(">I", n & 0xFFFFFFFF))
    except Exception:
        return ""


_SWAP_DEST_RX = re.compile(
    r"swap cookie=(\d+) from=\d+ to=\d+ bc=\d+ ac=\d+ d=\d+"
    r"(?: mt=\d+ rb=\d+)? dest=(\d+)(?: dest6=(\d+))?")
_ESTAB_DEST_RX = re.compile(
    r"estab cookie=(\d+) alg=\d+ forced=\d+ dest=(\d+)(?: dest6=(\d+))?")


def _cookie_dest_map(text):
    out = {}
    for line in text.splitlines():
        m = _SWAP_DEST_RX.search(line)
        if m:
            out[m.group(1)] = (m.group(2), m.group(3))
            continue
        m = _ESTAB_DEST_RX.search(line)
        if m:
            out[m.group(1)] = (m.group(2), m.group(3))
    return out


def data_recent_swaps(text, n=10):
    sw, met, srate = _swaps_mets_srates(text)
    rows = []
    for row in sw:
        ts, c, fa, ta = row[0], row[1], row[2], row[3]
        d, mt_i, rb_i = row[6], row[7], row[8]
        o  = _outcome_composite(met, c, ts)
        o2 = _outcome_srate(srate, c, ts)
        o3 = _outcome_sustained(srate, c, ts)
        mt_alg = (CONGS[int(mt_i) & 15]
                  if mt_i and mt_i.isdigit() else None)
        rb_alg = (CONGS[int(rb_i) & 15]
                  if rb_i and rb_i.isdigit() else None)
        rows.append({
            "boot_ts":  ts,
            "from_alg": CONGS[fa] if fa < 16 else str(fa),
            "to_alg":   CONGS[ta] if ta < 16 else str(ta),
            "d":        int(d),
            "outcome":            o,
            "outcome_srate":      o2,
            "outcome_sustained":  o3,
            "mt_alg":   mt_alg,
            "rb_alg":   rb_alg,
            "dest":     _label_for(_fold_v6(_dest_str(row[9] if len(row) > 9 else None,
                                   row[10] if len(row) > 10 else None))),
            "_bucket":  _label_for(_fold_v6(_bucket_of(row[9] if len(row) > 9 else None,
                                    row[10] if len(row) > 10 else None))),
        })
    return rows[-n:]


def data_recent_proofs(text, n=16):
    lines = [l for l in text.splitlines() if "proof cookie=" in l][-n:]
    cdest = _cookie_dest_map(text)
    out = []
    for l in lines:
        m = re.search(r"(\d+\.\d+): .*proof cookie=(\d+) alg=(\d+) rate=(\d+) tier=(\d+)", l)
        if not m:
            continue
        ts = float(m.group(1))
        c = m.group(2)
        a = int(m.group(3))
        out.append({
            "boot_ts":  ts,
            "alg":  CONGS[a] if a < 16 else "alg%d" % a,
            "mbps": round(int(m.group(4)) / BPS_TO_MBPS, 1),
            "tier": "proved" if m.group(5) == "2" else "good",
            "dest": _dest_str(*(cdest.get(c) or (None, None))),
        })
    return out


MIN_LEADER_TRUST = 10   # matches tcp_conn_tuner.h
LIVE_TOP_N       = 6
LIVE_MAX_BUCKETS = 8


def data_live_leaders(hosts):
    """Compute the picker's live ranking per bucket.

    Uses the exact formula from reanchor_best (tcp_conn_tuner.c):
        weighted = rate_ema * swap_score / 256
        pen      = 16 + bad_streak*4 + null_streak*2
        weighted = weighted * 16 / pen
    Filters to metric_count >= MIN_LEADER_TRUST, matching the
    picker's own trust floor.  Sorted descending; the first entry
    is what the reanchor would pick right now.

    Delivered via current.json, which the browser polls every 30s.
    The historical leaderboard (bucket_*.json) still comes from the
    renderer on its 5-minute cron."""
    out = []
    if not hosts:
        return out
    for inst, addr, v in hosts:
        if addr in ("0.0.0.1", "?"):
            continue
        if addr.startswith(("127.", "169.254.", "0.")):
            continue
        if inst < 2:
            continue
        metrics = v.get("metrics") or []
        cands = []
        for i in range(16):
            m = metrics[i] if i < len(metrics) and isinstance(metrics[i], dict) else {}
            try:
                cnt = int(m.get("metric_count", 0) or 0)
                rv  = int(m.get("rate_ema", 0) or 0)
                ss  = int(m.get("swap_score", 0) or 0)
                bad = int(m.get("bad_streak", 0) or 0)
                nul = int(m.get("null_streak", 0) or 0)
            except (TypeError, ValueError):
                continue
            if cnt < MIN_LEADER_TRUST:
                continue
            if rv == 0:
                continue
            ss_eff = ss if ss else 256
            weighted = rv * ss_eff // 256
            pen = 16 + bad * 4 + nul * 2
            weighted = weighted * 16 // pen
            cands.append((weighted, rv, ss, bad, nul, cnt, i))
        if not cands:
            continue
        cands.sort(key=lambda x: -x[0])
        rows = []
        for (w, rv, ss, bad, nul, cnt, i) in cands[:LIVE_TOP_N]:
            rows.append({
                "alg":        CONGS[i],
                "weighted":   int(w),
                "rate_ema":   rv,
                "swap_score": ss,
                "bad":        bad,
                "null":       nul,
                "count":      cnt,
            })
        out.append({"dest": addr, "inst": inst, "top": rows})
        if len(out) >= LIVE_MAX_BUCKETS:
            break
    return out


def _uptime_now():
    try:
        with open('/proc/uptime') as f:
            return float(f.read().split()[0])
    except Exception:
        return 0.0


def collect_all():
    logpath = find_log()
    hosts   = read_map()
    text    = tail_recent()
    return {
        "generated_ts":   int(time.time()),
        "now_mono":       _uptime_now(),
        "hostname":       os.uname().nodename,
        "build":          data_build(logpath),
        "system":         data_system(),
        "tunables":       data_tunables(),
        "buckets":        data_buckets(hosts),
        "metric":         data_metric(hosts),
        "metric_by_bucket": data_metric_by_bucket(hosts),
        "bucket_live":      data_bucket_live(),
        "live_leaders":   data_live_leaders(hosts),
        "proof":          data_proof(text),
        "rate":           data_rate(text),
        "swap_outcomes":  data_swap_outcomes(text),
        "divergence":     data_divergence(text),
        "churn":          data_churn(text),
        "recent_swaps":   data_recent_swaps(text),
        "recent_swaps_by_bucket": data_recent_swaps_by_bucket(text),
        "recent_proofs":  data_recent_proofs(text),
    }


# ---------- text renderer ----------

CW   = 58
GAP  = "  " + VBAR + "  "
FULL = CW*2 + len(GAP)


def _twocol(title_l, lines_l, title_r, lines_r):
    out = [f"{ARROW} {title_l:<{CW-2}}{GAP}{ARROW} {title_r}",
           f"{RULE*CW}{GAP}{RULE*CW}"]
    rows = max(len(lines_l), len(lines_r))
    for i in range(rows):
        l = lines_l[i] if i < len(lines_l) else ""
        r = lines_r[i] if i < len(lines_r) else ""
        out.append(f"{l[:CW]:<{CW}}{GAP}{r[:CW]}")
    return out


def _full(title, lines):
    out = [f"{ARROW} {title}", RULE*FULL]
    out += [l[:FULL] for l in lines]
    return out


def _system_lines(s):
    rows = []
    rows.append(f"kernel       {s.get('kernel','')}")
    rows.append(f"default CC   {s.get('default_cc','')}")
    if s.get("cpu_count") is not None:
        rows.append(f"cpu cores    {s['cpu_count']}")
    if s.get("load_1") is not None:
        rows.append("load avg     %.2f %.2f %.2f"
                    % (s["load_1"], s["load_5"], s["load_15"]))
    if s.get("procs_total") is not None:
        rows.append("processes    %s running / %s total"
                    % (s.get("procs_running", 0), s["procs_total"]))
    if s.get("host_uptime_s") is not None:
        dt = s["host_uptime_s"]
        dd, r = divmod(dt, 86400)
        hh, r = divmod(r, 3600)
        mm = r // 60
        rows.append("host uptime  %s%dh %dm" % (("%dd " % dd) if dd else "",
                                                hh, mm))
    if s.get("mem_total_bytes"):
        used = s.get("mem_used_bytes", 0)
        tot  = s["mem_total_bytes"]
        rows.append("memory       %.1f / %.1f GB  (%.0f%%)"
                    % (used / 1e9, tot / 1e9, s.get("mem_used_pct", 0)))
    return rows


def _tun_lines(tunables):
    out = []
    for g in tunables:
        out.append(f"  [{g['group']}]")
        for it in g["items"]:
            out.append(f"    {it['key']:<28} {it['value']}")
    if not out:
        out = ["  (none seen in journal for this boot)"]
    return out


def _outcome_lines(so, label):
    return [
        f"  {label}",
        f"    measurable    {so['measurable']:>4}  (unmeasurable {so['unmeasurable']})",
        f"    win           {so['win']:>4}  {so['win_pct']:.0f}%",
        f"    null          {so['null']:>4}  {so['null_pct']:.0f}%",
        f"    loss          {so['loss']:>4}  {so['loss_pct']:.0f}%",
    ]


def render_text(d):
    b = d["build"]
    lines = []
    lines.append(f"version    {b['version']}   service  {b['service']}")
    if b["uptime_min"] is not None:
        h, m = divmod(b["uptime_min"], 60)
        lines.append(f"uptime     {h}h {m}m   (started {b['started_utc']} UTC)")
    lines.append(f"log        {b['log_path'] or '(not found)'}")
    log_lines = lines

    print(DRULE * (FULL + 2))
    ts = datetime.fromtimestamp(d["generated_ts"], timezone.utc)\
                .strftime('%Y-%m-%dT%H:%M:%SZ')
    print(f"  bpftune  {MIDDOT}  {d['hostname']}  {MIDDOT}  {ts}")
    print(DRULE * (FULL + 2))
    print()
    for row in _twocol("BUILD / SERVICE", log_lines,
                       "SYSTEM FACTS",    _system_lines(d["system"])):
        print(row)
    print()
    for row in _full("BPFTUNE-MANAGED TUNABLES", _tun_lines(d["tunables"])):
        print(row)
    print()
    bk = [f"  {'dest':<16}{'inst':>6}{'rtt_us':>9}{'ref_Mbps':>10}"
          f"{'best_i':>10}{'n_alg':>7}"]
    for r in d["buckets"]:
        bk.append(f"  {r['dest']:<16}{r['inst']:>6}{r['rtt_us']:>9}"
                  f"{r['ref_mbps']:>10.1f}{r['best_alg']:>10}{r['n_alg']:>7}")
    for row in _full("TOP DESTINATION BUCKETS", bk):
        print(row)
    print()
    # Swap target picker: score = rate_ema * ss/256 * penalty.
    mt = [f"  {'alg':<10}{'metric':>9}{'re':>6}{'ss':>6}"
          f"{'pen':>6}{'score':>9}{'bad':>5}{'null':>6}"]
    for r in d["metric"]:
        pen = r.get("penalty", 1.0)
        pen_s = f"{pen:.2f}"
        mt.append(f"  {r['alg']:<10}{r['metric']:>9.1f}"
                  f"{r.get('rate_ema',0):>6}"
                  f"{r.get('swap_score',0):>6}"
                  f"{pen_s:>6}"
                  f"{r.get('score',0):>9.1f}"
                  f"{r.get('bad_streak',0):>5}"
                  f"{r.get('null_streak',0):>6}")
    pr = [f"  {'alg':<9}{'good':>5}{'prvd':>5}{'p_max':>8}"
          f"{'s_avg':>8}{'s_max':>8}{'n':>5}"]
    for r in d["proof"]:
        pm = f"{r['proven_max']:.1f}" if r["proven_max"] is not None else "-"
        sa = f"{r['sampled_avg']:.1f}" if r["sampled_avg"] is not None else "-"
        sm = f"{r['sampled_max']:.1f}" if r["sampled_max"] is not None else "-"
        n  = f"{r['samples']}" if r["samples"] is not None else "-"
        pr.append(f"  {r['alg']:<9}{r['good']:>5}{r['proved']:>5}"
                  f"{pm:>8}{sa:>8}{sm:>8}{n:>5}")
    for row in _twocol("SWAP TARGET LEADERBOARD (score = re*ss/256*pen)",
                       mt, "PROOF LEADERBOARD (speed)", pr):
        print(row)
    print()
    rt = [f"  {'thr':>7}{'n':>5}{'mean':>9}{'min':>9}{'max':>9}"]
    for r in d["rate"]:
        rt.append(f"  {r['thr']:>7}{r['n']:>5}{r['mean']:>9.1f}"
                  f"{r['min']:>9.1f}{r['max']:>9.1f}")
    so_lines = _outcome_lines(d["swap_outcomes"]["composite"], "composite") + \
               _outcome_lines(d["swap_outcomes"]["sustained"],
                              "sustained (accurate)")
    for row in _twocol("RATE PROGRESSION (client, Mbps)", rt,
                       "SWAP OUTCOMES", so_lines):
        print(row)
    print()
    dv = [f"  {'category':<20}{'meas':>5}{'win':>7}{'null':>7}{'loss':>7}{'skipped':>9}",
          RULE*62]
    for r in d["divergence"]:
        dv.append(f"  {r['category']:<20}{r['measured']:>5}"
                  f"{r['win_pct']:>6.0f}%{r['null_pct']:>6.0f}%"
                  f"{r['loss_pct']:>6.0f}%{r['skipped']:>9}")
    for row in _full("DIVERGENCE composite", dv):
        print(row)
    print()
    dvs = [f"  {'category':<20}{'meas':>5}{'win':>7}{'null':>7}{'loss':>7}{'skipped':>9}",
           RULE*62]
    for r in d["divergence"]:
        dvs.append(f"  {r['category']:<20}{r['measured_sustained']:>5}"
                   f"{r['win_pct_sustained']:>6.0f}%"
                   f"{r['null_pct_sustained']:>6.0f}%"
                   f"{r['loss_pct_sustained']:>6.0f}%"
                   f"{r['skipped_sustained']:>9}")
    for row in _full("DIVERGENCE sustained (srate, accurate)", dvs):
        print(row)
    print()
    ch = d["churn"]
    ch_lines = [
        f"  cookies swapped     {ch['cookies']}",
        f"    1x                {ch['one']}",
        f"    2-4x              {ch['mid']}",
        f"    5x+               {ch['many']}",
        f"    max per cookie    {ch['max']}",
    ]
    rp = [f"  {r['alg']:<9} {r['mbps']:>7.1f} Mbps   {r['tier']}"
          for r in d["recent_proofs"]] or ["  (none)"]
    for row in _twocol("COOKIE CHURN", ch_lines,
                       "RECENT PROOF EVENTS", rp):
        print(row)
    print()
    rs = []
    for r in d["recent_swaps"]:
        c = {"win": "W", "loss": "L", "null": "n"}.get(r["outcome"], "?")
        s = {"win": "W", "loss": "L", "null": "n"}.get(r["outcome_sustained"], "?")
        rs.append(f"  {r['from_alg']:>9} -> {r['to_alg']:<9} "
                  f"comp={c} sust={s} mt={r['mt_alg'] or '-':<8} "
                  f"rb={r['rb_alg'] or '-':<8}")
    if not rs:
        rs = ["  (none in tail)"]
    for row in _full("RECENT SWAPS (comp vs sustained)", rs):
        print(row)
    print()


def main():
    try:
        os.nice(19)
    except (OSError, AttributeError):
        pass
    p = argparse.ArgumentParser()
    p.add_argument("-i", "--interval", type=int, default=10)
    p.add_argument("--once", action="store_true")
    p.add_argument("--json", action="store_true")
    a = p.parse_args()

    if a.json:
        json.dump(collect_all(), sys.stdout, separators=(",", ":"))
        return

    try:
        while True:
            if not a.once:
                sys.stdout.write("\x1b[2J\x1b[H")
            render_text(collect_all())
            if a.once:
                break
            print(f"  refreshing every {a.interval}s (Ctrl-C to exit)")
            time.sleep(a.interval)
    except KeyboardInterrupt:
        print()


if __name__ == "__main__":
    main()
'''


# =================== collector ===================

COLLECTOR_SRC = r'''#!/usr/bin/env python3
#!/usr/bin/env python3
"""bpftune collector. Run once per minute from cron.

Buckets from `bpftool --json map dump name remote_host_map`. Each
bucket's per-alg row carries:

  mv_<alg>  metric_value
  re_<alg>  rate_ema
  ss_<alg>  swap_score  (256 = neutral, higher = swaps into this alg helped)
  bs_<alg>  bad_streak  (feeds the picker's penalty; no longer a gate)
  ns_<alg>  null_streak (feeds the picker's penalty; no longer a gate)

Swaps from all /var/log/bpftune-met-*.log (per-file byte offsets in
.swaps_pos.json).
Raw srate events from the same logs -> /var/lib/bpftune/history/srate.csv.
Snapshot: `bpftune-cli.py --json` -> /var/lib/bpftune/history/current.json

`collected_ts` is wall clock. `boot_ts` is monotonic (log seconds).

Outcome / direction
-------------------
A swap's outcome needs a post-swap met line, which almost never lands
in the same 60-second cron run as the swap.  Rows are held in
`state["pending_swaps"]` and resolved on a later run once the post
line arrives.  Rows whose [boot_ts+3, boot_ts+300] window has closed
with no post are written with outcome="no_post".  The collector never
writes an unresolved row to swaps.csv.

`direction` is "origin" when the socket's rport == 443, else "client".
Sourced from the met line's rport: the last pre-swap vote, or the post
at resolve time.  Matches tools/swap-outcomes-bydir.py.

`met_cache` is a per-cookie list of recent met events, pruned to
MET_CACHE_TTL_S.  It must hold more than the latest event so a swap
followed by two votes can still find the first in-window post.

STATE_VERSION 2: pending_swaps / rport / met-list added.  On version
mismatch the state is reset; only caches and in-flight pendings are
lost (at most 300 seconds of unresolved swaps).
"""
import csv, json, os, re, socket, struct, subprocess, sys, tempfile, time
from pathlib import Path


_LABELS_CACHE = None
_LABELS_MTIME = None

def _load_labels():
    """0.4.79: /var/lib/bpftune/aliases.labels.json {canonical_ip: label}."""
    global _LABELS_CACHE, _LABELS_MTIME
    import os as _os, json as _json
    path = "/var/lib/bpftune/aliases.labels.json"
    try:
        m = _os.path.getmtime(path)
    except OSError:
        _LABELS_CACHE = {}
        _LABELS_MTIME = None
        return _LABELS_CACHE
    if _LABELS_CACHE is not None and _LABELS_MTIME == m:
        return _LABELS_CACHE
    try:
        with open(path) as f:
            d = _json.load(f)
        _LABELS_CACHE = d if isinstance(d, dict) else {}
    except Exception:
        _LABELS_CACHE = {}
    _LABELS_MTIME = m
    return _LABELS_CACHE


_FOLD_CACHE = None
_FOLD_MTIME = None

def _load_fold():
    """0.4.79: {"v6:XXXXXXXX": "canonical"} from /32-form entries in
    /etc/bpftune/aliases.  Line form:
        2603:c020:0:0:0:0:0:0 = 89.168.0.0 [label]
    Only lines where groups 2..7 are all zero are treated as /32 folds."""
    global _FOLD_CACHE, _FOLD_MTIME
    import os as _os
    path = "/etc/bpftune/aliases"
    try:
        m = _os.path.getmtime(path)
    except OSError:
        _FOLD_CACHE = {}
        _FOLD_MTIME = None
        return _FOLD_CACHE
    if _FOLD_CACHE is not None and _FOLD_MTIME == m:
        return _FOLD_CACHE
    out = {}
    try:
        with open(path) as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                lhs, rhs = line.split("=", 1)
                lhs = lhs.strip()
                bits = rhs.strip().split()
                if not bits:
                    continue
                to = bits[0]
                if "." not in to:
                    continue
                if ":" not in lhs:
                    continue
                groups = lhs.split(":")
                if len(groups) != 8:
                    continue
                if not all(g in ("0", "0000", "") for g in groups[2:]):
                    continue
                key = "v6:" + (groups[0].zfill(4) + groups[1].zfill(4)).lower()
                out[key] = to
    except Exception:
        out = {}
    _FOLD_CACHE = out
    _FOLD_MTIME = m
    return out


def _fold_v6(addr):
    """0.4.79: replace a v6 /32 bucket key with its canonical v4 bucket
    if that /32 is declared in /etc/bpftune/aliases."""
    if not addr or not addr.startswith("v6:"):
        return addr
    return _load_fold().get(addr, addr)


def _label_for(addr):
    if not addr:
        return addr
    return _load_labels().get(addr, addr)


HIST = Path("/var/lib/bpftune/history")
HIST.mkdir(parents=True, exist_ok=True)
BUCKETS_CSV  = HIST / "buckets.v2.csv"
SWAPS_CSV    = HIST / "swaps.csv"
SRATE_CSV    = HIST / "srate.csv"
SWAPS_POS    = HIST / ".swaps_pos.json"
CURRENT_JSON = HIST / "current.json"

STATE_VERSION = 3

SELF_DIR = Path(__file__).resolve().parent
CLI      = SELF_DIR / "bpftune-cli.py"

CONGS = ["cubic", "bbr", "htcp", "dctcp", "scalable", "vegas", "veno",
         "westwood", "reno", "illinois", "yeah", "lp", "bic", "highspeed",
         "hybla", "nv"]
MIN_INST = 2

MET_CACHE_TTL_S = 600.0

SWAP_FIELDS = [
    "collected_ts", "boot_ts", "cookie", "from_alg", "to_alg", "d",
    "mt_alg", "rb_alg", "diverges", "outcome", "socket_rate_before",
    "dest", "dest_raw", "f_ema", "t_ema", "srate_before",
    "direction", "rport",
]
SRATE_FIELDS = ["collected_ts", "boot_ts", "cookie", "alg", "srate"]

# 0.4.76: sustained classification truth, consumed by the tuner's
# reanchor worker.  One line per resolved swap; the worker reads and
# truncates each pass (~30s), so growth is bounded.
SWAPS_TRUTH = HIST / "swapscore_truth.jsonl"

# 0.4.76-live: rolling JSON file the dashboard reads on a fast cadence.
# Mirrors every row that lands in swaps.csv.  No effect on the CSV.
DATA_DIR = HIST / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
SWAPS_LIVE = DATA_DIR / "swaps-live.json"
LIVE_MAX = 100

SWAP_RX = re.compile(
    r"(\d+\.\d+): bpf_trace_printk: swap cookie=(\d+) "
    r"from=(\d+) to=(\d+) bc=(\d+) ac=(\d+) d=(\d+)"
    r"(?: mt=(\d+) rb=(\d+))?"
    r"(?: dest=(\d+))?"
    r"(?: dest6=(\d+))?")
ESTAB_DEST_RX = re.compile(
    r"(\d+\.\d+): bpf_trace_printk: estab cookie=(\d+) "
    r"alg=(\d+) forced=\d+ dest=(\d+)(?: dest6=(\d+))?")
MET_RX = re.compile(
    r"(\d+\.\d+): bpf_trace_printk: met cookie=(\d+) "
    r"rport=(\d+) alg=(\d+) segs=(\d+) val=(\d+)")
SRATE_RX = re.compile(
    r"(\d+\.\d+): bpf_trace_printk: srate cookie=(\d+) "
    r"alg=(\d+) srate=(\d+)")


def sh(args, timeout=15):
    try:
        return subprocess.run(args, capture_output=True, text=True,
                              timeout=timeout).stdout
    except Exception:
        return ""


def tcp_rmem():
    out = sh(["sysctl", "-n", "net.ipv4.tcp_rmem"]).split()
    if len(out) != 3:
        return "", "", ""
    try:
        return int(out[0]), int(out[1]), int(out[2])
    except ValueError:
        return "", "", ""


_CSV_HEADER_CACHE = {}
_CSV_BUFFERS = {}


def _csv_header(path, default_cols):
    key = str(path)
    h = _CSV_HEADER_CACHE.get(key)
    if h is not None:
        return h
    p = Path(path)
    if p.exists() and p.stat().st_size > 0:
        with open(p, "r", newline="", encoding="utf-8") as f:
            try:
                h = next(csv.reader(f))
            except StopIteration:
                h = list(default_cols)
    else:
        h = list(default_cols)
    _CSV_HEADER_CACHE[key] = h
    return h


# 0.4.76-live: rolling in-memory ring of the last LIVE_MAX rows.
# Loaded lazily at first append; flushed once by main() after the
# CSV buffers flush.  Bounded: LIVE_MAX * ~400B = ~40KB.
_LIVE_RING = None
_LIVE_DIRTY = False


def _live_load():
    global _LIVE_RING
    if _LIVE_RING is not None:
        return
    _LIVE_RING = []
    if SWAPS_LIVE.exists():
        try:
            with open(SWAPS_LIVE) as f:
                d = json.load(f)
            if isinstance(d, list):
                _LIVE_RING = d[-LIVE_MAX:]
        except Exception:
            _LIVE_RING = []


def _live_append(row):
    global _LIVE_DIRTY
    _live_load()
    _LIVE_RING.append(row)
    del _LIVE_RING[:-LIVE_MAX]
    _LIVE_DIRTY = True


def _live_flush():
    global _LIVE_DIRTY
    if not _LIVE_DIRTY or _LIVE_RING is None:
        return
    tmp = str(SWAPS_LIVE) + ".tmp"
    try:
        with open(tmp, "w") as f:
            json.dump(_LIVE_RING, f, separators=(",", ":"))
        os.replace(tmp, str(SWAPS_LIVE))
        _LIVE_DIRTY = False
    except Exception as e:
        print("collector: live flush failed: %s" % e, file=sys.stderr)


def buffer_csv(path, row, fields=None):
    key = str(path)
    cols = _csv_header(key, fields or list(row.keys()))
    _CSV_BUFFERS.setdefault(key, []).append([row.get(c, "") for c in cols])
    if key == str(SWAPS_CSV):
        _live_append(row)


def flush_csv_buffers():
    for key, rows in _CSV_BUFFERS.items():
        if not rows:
            continue
        p = Path(key)
        needs_header = not (p.exists() and p.stat().st_size > 0)
        with open(p, "a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            if needs_header:
                w.writerow(_CSV_HEADER_CACHE[key])
            w.writerows(rows)
    _CSV_BUFFERS.clear()


def list_logs():
    return sorted(Path("/var/log").glob("bpftune-met-*.log"),
                  key=lambda p: p.stat().st_mtime)


def read_map_data():
    out = sh(["bpftool", "--json", "map", "dump", "name",
              "remote_host_map"])
    try:
        data = json.loads(out)
    except Exception:
        return None, ""
    if not isinstance(data, list):
        return None, ""
    result = {}
    for e in data:
        if not isinstance(e, dict):
            continue
        fmt = e.get("formatted") or {}
        v = fmt.get("value")
        k = fmt.get("key") or {}
        if not isinstance(v, dict):
            continue
        b = k.get("in6_u", {}).get("u6_addr8")
        if not isinstance(b, list) or len(b) != 16:
            continue
        if b[10] == 0xff and b[11] == 0xff:
            addr = ".".join(str(x) for x in b[12:16])
        else:
            v6 = (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]
            addr = "v6:%08x" % v6 if v6 else "0.0.0.0"
        result[addr] = v
    return result, out


def collect_buckets(ts_epoch, map_data):
    if not map_data:
        return 0
    rm_min, rm_def, rm_max = tcp_rmem()
    n = 0
    # 0.4.79: pre-fold and merge.  Two map keys can fold to the
    # same canonical (exact-address entry and prefix-fold entry
    # for the same location); the CSV wants one row per bucket
    # per tick, not two.
    _folded = {}
    for _a, _v in map_data.items():
        _k = _fold_v6(_a)
        if _k in _folded:
            _pv = _folded[_k]
            _pi = int(_pv.get('instances', 0) or 0)
            _ci = int(_v.get('instances', 0) or 0)
            _merged = dict(_v if _ci > _pi else _pv)
            _merged['instances'] = _pi + _ci
            _folded[_k] = _merged
        else:
            _folded[_k] = _v
    map_data = _folded
    for addr, v in map_data.items():
        try:
            inst = int(v.get("instances", 0))
        except Exception:
            continue
        if inst < MIN_INST:
            continue
        if addr == "0.0.0.1" or addr.startswith(("127.", "169.254.", "0.")):
            continue
        try:
            best_i = int(v.get("best_i", 0) or 0)
        except Exception:
            best_i = 0
        row = {
            "collected_ts": ts_epoch,
            "addr": addr,
            "instances": inst,
            "min_rtt": int(v.get("min_rtt", 0) or 0),
            "ref_rate": int(v.get("max_rate_delivered", 0) or 0),
            "best_i": best_i,
            "best_alg": CONGS[best_i & 15],
            "rate_best_i": int(v.get("rate_best_i", 0) or 0),
            "rate_best_v": int(v.get("rate_best_v", 0) or 0),
        }
        metrics = v.get("metrics") or []
        for i in range(16):
            m = metrics[i] if i < len(metrics) and isinstance(metrics[i], dict) else {}
            row["mv_" + CONGS[i]] = int(m.get("metric_value", 0) or 0)
            row["re_" + CONGS[i]] = int(m.get("rate_ema", 0) or 0)
            row["ss_" + CONGS[i]] = int(m.get("swap_score", 0) or 0)
            row["bs_" + CONGS[i]] = int(m.get("bad_streak", 0) or 0)
            row["ns_" + CONGS[i]] = int(m.get("null_streak", 0) or 0)
        row["tcp_rmem_min"] = rm_min
        row["tcp_rmem_def"] = rm_def
        row["tcp_rmem_max"] = rm_max
        buffer_csv(BUCKETS_CSV, row)
        n += 1
    return n


def _read_state():
    if not SWAPS_POS.exists():
        return None
    try:
        d = json.loads(SWAPS_POS.read_text())
    except Exception:
        return None
    if not isinstance(d, dict):
        return None
    if d.get("state_version") != STATE_VERSION:
        return None
    if "file_offsets" not in d or "met_cache" not in d:
        return None
    d.setdefault("srate_cache", {})
    d.setdefault("pending_swaps", [])
    return d


def _new_state():
    return {"state_version": STATE_VERSION,
            "file_offsets": {}, "met_cache": {},
            "srate_cache": {}, "pending_swaps": []}


def _write_state(state):
    tmp = str(SWAPS_POS) + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, str(SWAPS_POS))


def _lookup_ema(map_data, dest_ip, alg_index):
    if not dest_ip or not map_data or alg_index is None:
        return ""
    key = dest_ip
    parts = dest_ip.split(".")
    if len(parts) == 4:
        key = "%s.%s.0.0" % (parts[0], parts[1])
    v = map_data.get(key)
    if not v:
        v = map_data.get(dest_ip)
    if not v:
        return ""
    try:
        ai = int(alg_index)
    except (TypeError, ValueError):
        return ""
    if ai < 0 or ai >= 16:
        return ""
    metrics = v.get("metrics") or []
    if ai >= len(metrics):
        return ""
    m = metrics[ai]
    if not isinstance(m, dict):
        return ""
    ema = m.get("rate_ema")
    if ema is None:
        return ""
    try:
        return int(ema)
    except (TypeError, ValueError):
        return ""


def _decode_dest6(s):
    try: n6 = int(s) if s not in (None, "") else 0
    except (TypeError, ValueError): n6 = 0
    if not n6:
        return ""
    return "v6:%08x" % (n6 & 0xFFFFFFFF)


def _decode_dest(n):
    if n is None or n == 1:
        return ""
    try:
        n = int(n)
    except (TypeError, ValueError):
        return ""
    first = (n >> 24) & 0xFF
    if first == 0 or first == 127:
        return ""
    try:
        return socket.inet_ntoa(struct.pack(">I", n & 0xFFFFFFFF))
    except Exception:
        return ""


def _direction_from_rport(rport):
    if rport in ("", None):
        return ""
    return "origin" if str(rport) == "443" else "client"


def _truth_write(row):
    """Append one line for the tuner: bucket, target alg, sustained cls."""
    dest = row.get("dest") or ""
    to_alg = row.get("to_alg") or ""
    outcome = (row.get("outcome") or "").lower()
    if not dest or not to_alg or outcome not in ("win", "null", "loss"):
        return
    # 0.4.79: accept v6:XXXXXXXX (top 32 bits of remote_ip6[0])
    # as well as dotted-quad v4.  Previously any non-dotted string
    # was silently dropped, so every IPv6 swap was ignored by the
    # score reconciler.
    if dest.startswith("v6:"):
        bucket = dest
    else:
        parts = dest.split(".")
        if len(parts) != 4:
            return
        bucket = "%s.%s.0.0" % (parts[0], parts[1])
    rec = {"bucket": bucket, "tgt": to_alg, "cls": outcome}
    try:
        with open(SWAPS_TRUTH, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, separators=(",", ":")) + "\n")
    except OSError:
        pass


def _resolve_pending(pending, met_cache, srate_cache, newest_ts, now_epoch):
    keep = []
    for row in pending:
        cookie = row["cookie"]
        boot_ts = row["boot_ts"]
        pre = row.get("srate_before")
        try:
            pre_v = float(pre) if pre not in ("", None) else None
        except (TypeError, ValueError):
            pre_v = None

        # direction still comes from the met line's rport
        post_rport = None
        for entry in met_cache.get(cookie, ()):
            ts = entry[0]
            if boot_ts + 3.0 <= ts <= boot_ts + 300.0:
                post_rport = entry[2]
                break

        # 0.4.76: sustained-ruler classification.  Median of srate
        # in [T+60, T+300] vs pre-swap srate.  Higher rate = win,
        # lower = loss (opposite of the old metric ruler).
        samples = [rate for (ts, rate) in srate_cache.get(cookie, ())
                   if boot_ts + 60.0 <= ts <= boot_ts + 300.0]
        post_v = None
        # 0.4.76b: match the renderer's rule -- accept a single sample.
        # The renderer (bpftune-render.py _attach_sustained_outcomes)
        # classifies on >=1 sample in the same window; the collector
        # was the strict one at >=2, so CSV and CLI disagreed on
        # every swap the collector marked no_post.  Single-sample
        # agreement with the eventual median is ~80% on 345 testable
        # swaps -- correct 4 out of 5, at 2x the coverage.
        if len(samples) >= 1:
            sv = sorted(samples)
            ns = len(sv)
            post_v = (float(sv[ns // 2]) if ns % 2 else
                      (sv[ns // 2 - 1] + sv[ns // 2]) / 2.0)

        if pre_v and post_v:
            ratio = post_v / pre_v
            row["outcome"] = ("win" if ratio >= 1.1 else
                              "loss" if ratio <= 0.9 else "null")
            if not row.get("direction") and post_rport not in ("", None):
                row["direction"] = _direction_from_rport(str(post_rport))
                row["rport"] = str(post_rport)
            _truth_write(row)   # 0.4.76: sustained truth for the tuner
            buffer_csv(SWAPS_CSV, row, SWAP_FIELDS)
        elif boot_ts + 300.0 < newest_ts:
            row["outcome"] = "no_post"
            buffer_csv(SWAPS_CSV, row, SWAP_FIELDS)
        else:
            keep.append(row)
    return keep


def _parse_swaps_from(text, now_epoch, met_cache, srate_cache, map_data,
                      state):
    lines = text.splitlines()

    chunk_met = {}
    chunk_srate = {}
    for line in lines:
        m = MET_RX.search(line)
        if m:
            c = int(m.group(2))
            chunk_met.setdefault(c, []).append(
                (float(m.group(1)), int(m.group(6)), int(m.group(3))))
            continue
        s = SRATE_RX.search(line)
        if s:
            c   = int(s.group(2))
            alg = int(s.group(3))
            sr  = int(s.group(4))
            chunk_srate.setdefault(c, []).append(
                (float(s.group(1)), alg, sr))

    newest_met_ts = 0.0
    for entries in chunk_met.values():
        for e in entries:
            if e[0] > newest_met_ts:
                newest_met_ts = e[0]
    newest_srate_ts = 0.0
    for entries in chunk_srate.values():
        for e in entries:
            if e[0] > newest_srate_ts:
                newest_srate_ts = e[0]
    newest_ts = max(newest_met_ts, newest_srate_ts)

    pending = state.setdefault("pending_swaps", [])

    n = 0
    for line in lines:
        m = SWAP_RX.search(line)
        if not m:
            continue
        boot_ts = float(m.group(1))
        c   = int(m.group(2))
        fa  = int(m.group(3))
        ta  = int(m.group(4))
        d   = int(m.group(7))
        mt_i = m.group(8)
        rb_i = m.group(9)
        dest_s = m.group(10)
        dest6_s = m.group(11) if m.lastindex and m.lastindex >= 11 else None

        pre = None
        pre_ts = -1.0
        pre_rport = ""
        for entry in met_cache.get(c, ()):
            ts = entry[0]
            if ts < boot_ts + 0.001 and ts > pre_ts:
                pre = entry[1]
                pre_ts = ts
                pre_rport = entry[2]
        for entry in chunk_met.get(c, ()):
            ts = entry[0]
            if ts < boot_ts + 0.001 and ts > pre_ts:
                pre = entry[1]
                pre_ts = ts
                pre_rport = entry[2]

        post = None
        post_rport = ""
        for entry in chunk_met.get(c, ()):
            ts = entry[0]
            if boot_ts + 3.0 <= ts <= boot_ts + 300.0:
                post = entry[1]
                post_rport = entry[2]
                break

        srate_pre = None
        srate_pre_ts = -1.0
        for entry_s in srate_cache.get(c, ()):
            ts = entry_s[0]
            if ts < boot_ts and ts > srate_pre_ts:
                srate_pre = entry_s[1]
                srate_pre_ts = ts
        for (sts, _a, sr) in chunk_srate.get(c, ()):
            if sts < boot_ts and sts > srate_pre_ts:
                srate_pre = sr
                srate_pre_ts = sts

        mt_alg = CONGS[int(mt_i) & 15] if mt_i and mt_i.isdigit() else ""
        rb_alg = CONGS[int(rb_i) & 15] if rb_i and rb_i.isdigit() else ""

        dest_ip = ""
        dest_raw = ""
        if dest_s:
            dest_raw = dest_s
            try:
                dest_ip = _decode_dest(int(dest_s))
            except (TypeError, ValueError):
                dest_ip = ""
        # 0.4.78.2: dest=0 means the socket is IPv6 (remote_ip4
        # unset).  Prefer the dest6 field in that case; without
        # this, every v6 swap reached _truth_write with an empty
        # dest and was silently dropped.
        if not dest_ip and dest6_s:
            dest_ip = _decode_dest6(dest6_s)
            if dest_ip and not dest_raw:
                dest_raw = dest6_s

        f_ema = _lookup_ema(map_data, dest_ip, fa)
        t_ema = _lookup_ema(map_data, dest_ip, ta)

        rp = pre_rport or post_rport or ""
        row = {
            "collected_ts": now_epoch,
            "boot_ts": boot_ts,
            "cookie": c,
            "from_alg": CONGS[fa] if fa < 16 else str(fa),
            "to_alg": CONGS[ta] if ta < 16 else str(ta),
            "d": d,
            "mt_alg": mt_alg,
            "rb_alg": rb_alg,
            "diverges": "1" if (mt_alg and rb_alg and mt_alg != rb_alg) else "0",
            "outcome": "",
            "socket_rate_before": pre if pre is not None else "",
            "dest": dest_ip,
            "dest_raw": dest_raw,
            "f_ema": f_ema,
            "t_ema": t_ema,
            "srate_before": srate_pre if srate_pre is not None else "",
            "direction": _direction_from_rport(str(rp)) if rp else "",
            "rport": str(rp) if rp else "",
        }

        # 0.4.76: entire classification deferred.  The resolve path
        # uses the sustained median srate in [T+60, T+300] vs the
        # pre-swap srate; the metric-ruler classification is gone.
        if srate_pre is not None:
            pending.append(row)
        else:
            row["outcome"] = "no_srate_pre"
            buffer_csv(SWAPS_CSV, row, SWAP_FIELDS)

        n += 1

    for c, entries in chunk_met.items():
        bucket = met_cache.setdefault(c, [])
        if not isinstance(bucket, list):
            bucket = []
            met_cache[c] = bucket
        seen = {e[0] for e in bucket if isinstance(e, list) and len(e) >= 3}
        for entry in entries:
            if entry[0] not in seen:
                bucket.append([entry[0], entry[1], entry[2]])

    for c, entries in chunk_srate.items():
        bucket = srate_cache.setdefault(c, [])
        if not isinstance(bucket, list):
            bucket = []
            srate_cache[c] = bucket
        seen = {e[0] for e in bucket
                if isinstance(e, list) and len(e) >= 2}
        for (sts, alg, sr) in entries:
            if sts not in seen:
                bucket.append([sts, sr])
            buffer_csv(SRATE_CSV, {
                "collected_ts": now_epoch,
                "boot_ts": sts,
                "cookie": c,
                "alg": CONGS[alg] if 0 <= alg < 16 else str(alg),
                "srate": sr,
            }, SRATE_FIELDS)

    # Prune met_cache to MET_CACHE_TTL_S. If we saw nothing this run,
    # skip the prune so a quiet interval does not wipe live entries.
    if newest_met_ts > 0:
        cutoff = newest_met_ts - MET_CACHE_TTL_S
        for c in list(met_cache.keys()):
            bucket = met_cache[c]
            if not isinstance(bucket, list):
                del met_cache[c]
                continue
            bucket[:] = [e for e in bucket
                         if isinstance(e, list) and len(e) >= 3
                         and e[0] >= cutoff]
            if not bucket:
                del met_cache[c]

    state["pending_swaps"] = _resolve_pending(
        pending, met_cache, srate_cache, newest_ts, now_epoch)

    return n


def collect_swaps(map_data):
    state = _read_state()
    if state is None:
        state = _new_state()
    file_offsets = state["file_offsets"]
    met_cache    = state["met_cache"]
    srate_cache  = state["srate_cache"]

    first_run = not file_offsets
    now_epoch = int(time.time())
    n = 0

    for logpath in list_logs():
        key = logpath.name
        try:
            size = logpath.stat().st_size
        except OSError:
            continue

        if first_run or key not in file_offsets:
            file_offsets[key] = size
            continue

        pos = file_offsets.get(key, 0)
        if size < pos:
            pos = 0
        if size == pos:
            continue

        try:
            with open(logpath, "rb") as f:
                f.seek(pos)
                chunk = f.read().decode("utf-8", errors="replace")
                file_offsets[key] = f.tell()
        except OSError:
            continue

        n += _parse_swaps_from(chunk, now_epoch, met_cache,
                               srate_cache, map_data, state)

    # 0.4.76: srate_cache prunes per entry, same as met_cache.
    if srate_cache:
        valid_ts = [e[0] for bucket in srate_cache.values()
                    if isinstance(bucket, list)
                    for e in bucket
                    if isinstance(e, list) and len(e) >= 2]
        if valid_ts:
            cutoff = max(valid_ts) - MET_CACHE_TTL_S
            for c in list(srate_cache.keys()):
                bucket = srate_cache[c]
                if not isinstance(bucket, list):
                    del srate_cache[c]
                    continue
                bucket[:] = [e for e in bucket
                             if isinstance(e, list) and len(e) >= 2
                             and e[0] >= cutoff]
                if not bucket:
                    del srate_cache[c]

    _write_state(state)
    return n


def run_cli_snapshot(map_raw=""):
    if not CLI.exists():
        return None
    env = os.environ.copy()
    tmp_map = None
    try:
        if map_raw:
            try:
                fd, tmp_map = tempfile.mkstemp(
                    prefix=".map-", suffix=".json", dir=str(HIST))
                with os.fdopen(fd, "w") as f:
                    f.write(map_raw)
                env["BPFTUNE_MAP_DUMP_JSON"] = tmp_map
            except OSError:
                tmp_map = None
        r = subprocess.run([sys.executable, str(CLI), "--json"],
                           capture_output=True, text=True, timeout=90,
                           env=env)
        if r.returncode != 0:
            print("collector: CLI exited %d" % r.returncode, file=sys.stderr)
            return None
        doc = json.loads(r.stdout)
        tmp = str(CURRENT_JSON) + ".tmp"
        with open(tmp, "w") as f:
            json.dump(doc, f, separators=(",", ":"))
        os.replace(tmp, str(CURRENT_JSON))
        return doc
    except Exception as e:
        print("collector: CLI snapshot failed: %s" % e, file=sys.stderr)
        return None
    finally:
        if tmp_map:
            try:
                os.unlink(tmp_map)
            except OSError:
                pass


def main():
    try:
        os.nice(19)
    except (OSError, AttributeError):
        pass
    ts_epoch = int(time.time())
    map_data, map_raw = read_map_data()
    nb = collect_buckets(ts_epoch, map_data)
    ns = collect_swaps(map_data)
    flush_csv_buffers()
    _live_flush()
    doc = run_cli_snapshot(map_raw)
    print("collector: buckets=%d swaps=%d cli=%s ts=%d"
          % (nb, ns, "ok" if doc else "fail", ts_epoch))


if __name__ == "__main__":
    main()
'''


# =================== renderer ===================
# Bounded-memory load_csv: deque on the DictReader keeps only the last
# N rows in memory regardless of file size.
#
# Per-alg series include re_<alg>, ss_<alg>, bs_<alg>, ns_<alg>.
#
# Swap target leaderboard: score = rate_ema * ss/256 * penalty, where
# penalty = 16 / (16 + bad*4 + null*2). No exclusions - streaks are a
# multiplier, not a gate.
#
# Frontend refreshes:
#   * `now` card + currently selected chart: every 30 s.
#   * full dashboard: every 5 min to match the renderer cron cadence.

RENDERER_SRC = r'''#!/usr/bin/env python3
#!/usr/bin/env python3
"""bpftune renderer - static Chart.js dashboard + live CLI panel.

Cron: every 5 minutes. Reads buckets.v2.csv + swaps.csv + srate.csv,
writes index.html and data/*.json. The browser also fetches
current.json (every 30s).

load_csv is bounded-memory: keeps the last N rows only.
"""
import bisect, csv, io, json, math, os, time
from pathlib import Path
from collections import defaultdict, deque

HIST = "/var/lib/bpftune/history"
DATA = os.path.join(HIST, "data")

_LABELS_CACHE = None
_LABELS_MTIME = None

def _load_labels():
    """0.4.79: {canonical_ip: label} from aliases.labels.json."""
    global _LABELS_CACHE, _LABELS_MTIME
    path = "/var/lib/bpftune/aliases.labels.json"
    try:
        m = os.path.getmtime(path)
    except OSError:
        _LABELS_CACHE = {}
        _LABELS_MTIME = None
        return _LABELS_CACHE
    if _LABELS_CACHE is not None and _LABELS_MTIME == m:
        return _LABELS_CACHE
    try:
        with open(path) as f:
            d = json.load(f)
        _LABELS_CACHE = d if isinstance(d, dict) else {}
    except Exception:
        _LABELS_CACHE = {}
    _LABELS_MTIME = m
    return _LABELS_CACHE


def _canon_bucket(addr):
    """0.4.79: collapse to /16 (v4) or /32 (v6).  During the
    prefix4/6 testing the collector wrote some rows at /24 and
    /32, so identical physical buckets ended up as two keys.
    This makes meta.json and bucket_live agree."""
    if not addr:
        return addr
    if addr.startswith('v6:'):
        return addr
    p = addr.split('.')
    if len(p) == 4:
        return '%s.%s.0.0' % (p[0], p[1])
    return addr


def _label_for(addr):
    if not addr:
        return addr
    addr = _canon_bucket(addr)
    return _load_labels().get(addr, addr)

RANGES = {
    "1h":  (3600,       60),
    "24h": (86400,      300),
    "7d":  (7 * 86400,  3600),
    "all": (None,       21600),
}

MAX_ROWS_BUCKETS = 150000
MIN_BUCKET_ROWS  = 20
MAX_BUCKETS      = 60
MAX_ROWS_PER_BUCKET = 500
MIN_BUCKET_ROWS  = 5        # skip buckets too small to plot
MAX_ROWS_PER_BUCKET = 4000   # cap work per bucket
MAX_ROWS_SWAPS   =  50000
MAX_ROWS_SRATE   = 150000

EXTRA_COLS = ["ref_rate", "rate_best_i", "rate_best_v", "instances",
              "tcp_rmem_min", "tcp_rmem_def", "tcp_rmem_max"]

SUSTAINED_LO_S = 60.0
SUSTAINED_HI_S = 300.0


def to_float(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def truthy(v):
    return str(v).strip().lower() in ("1", "true", "yes", "y")


def median(xs):
    if not xs:
        return None
    s = sorted(xs)
    n = len(s)
    if n % 2:
        return float(s[n // 2])
    return (s[n // 2 - 1] + s[n // 2]) / 2.0


def ts_of(row):
    t = to_float(row.get("collected_ts"))
    if t is None:
        t = to_float(row.get("ts_epoch"))
    return t


def wilson(w, n, z=1.96):
    if n == 0:
        return None, None
    p = w / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (c - h) / d, (c + h) / d


def buckets_source():
    for n in ("buckets.v2.csv", "buckets.v1.csv"):
        p = os.path.join(HIST, n)
        if os.path.exists(p) and os.path.getsize(p) > 0:
            return p
    return None


def load_csv(path, max_rows=None):
    if not path or not os.path.exists(path):
        return [], []
    size = os.path.getsize(path)
    if size == 0:
        return [], []
    if max_rows is None:
        with open(path, newline="", encoding="utf-8") as f:
            rd = csv.DictReader(f)
            return list(rd.fieldnames or []), list(rd)
    want = max_rows + 1
    block = 262144
    chunks = []
    nl_count = 0
    with open(path, "rb") as f:
        pos = size
        while pos > 0 and nl_count < want:
            step = min(block, pos)
            pos -= step
            f.seek(pos)
            buf = f.read(step)
            nl_count += buf.count(b"\n")
            chunks.append(buf)
    data = b"".join(reversed(chunks))
    walked = (pos == 0)
    lines = data.split(b"\n")
    if walked:
        header_bytes = lines[0]
        body = lines[1:]
    else:
        with open(path, "r", newline="", encoding="utf-8") as f:
            header_bytes = f.readline().rstrip("\n").encode("utf-8")
        body = lines[1:]
    rows_bytes = b"\n".join(body[-max_rows:])
    if not rows_bytes.strip():
        return header_bytes.decode("utf-8").split(","), []
    header = next(csv.reader(io.StringIO(header_bytes.decode("utf-8"))))
    reader = csv.DictReader(
        io.StringIO(rows_bytes.decode("utf-8", errors="replace")),
        fieldnames=header)
    return header, list(reader)


def bin_series(rows, lo, width, cols):
    acc = defaultdict(list)
    for r in rows:
        t = ts_of(r)
        if t is None or (lo is not None and t < lo):
            continue
        acc[int((t - (lo or 0)) // width)].append(r)
    base = lo if lo is not None else 0
    ts, out = [], {c: [] for c in cols}
    for b in sorted(acc):
        ts.append(int(base + b * width + width / 2))
        for c in cols:
            vals = [to_float(r.get(c)) for r in acc[b]]
            vals = [v for v in vals if v is not None]
            out[c].append(sum(vals) / len(vals) if vals else None)
    return ts, out


def bin_series_parsed(parsed, lo, width, cols):
    """Bin rows whose cells are already floats. parsed = list of
    {"_t": float, "<col>": float|None}."""
    acc = defaultdict(list)
    for r in parsed:
        t = r["_t"]
        if lo is not None and t < lo:
            continue
        acc[int((t - (lo or 0)) // width)].append(r)
    base = lo if lo is not None else 0
    ts = []
    out = {c: [] for c in cols}
    for b in sorted(acc):
        ts.append(int(base + b * width + width / 2))
        grp = acc[b]
        for c in cols:
            total = 0.0
            count = 0
            for r in grp:
                v = r.get(c)
                if v is not None:
                    total += v
                    count += 1
            out[c].append(total / count if count else None)
    return ts, out


def write_json(name, obj):
    os.makedirs(DATA, exist_ok=True)
    path = os.path.join(DATA, name)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, separators=(",", ":"))
    os.replace(tmp, path)



def aggregate_all(bfile, algs, now):
    """Single streaming pass over buckets.v2.csv.

    Pass 1 counts rows per addr (retains nothing). Pass 2 aggregates
    values into per-range bins as it reads. No row retention at all,
    so peak memory is a few MB regardless of file size, and every row
    in the file contributes to the 7d/all ranges.

    Returns (header, cols, docs, meta_stats).
    """
    MAX_BUCKETS = 60
    MIN_BUCKET_ROWS = 5

    with open(bfile, "r", newline="") as f:
        rd = csv.reader(f)
        try:
            header = next(rd)
        except StopIteration:
            return [], {}, [], {}
        cols = {c: i for i, c in enumerate(header)}
        ai = cols.get("addr")
        ti = cols.get("collected_ts")
        if ai is None or ti is None:
            return header, cols, [], {}
        counts = {}
        for row in rd:
            a = row[ai] if ai < len(row) else ""
            a = a or "unknown"
            a = _label_for(a)
            if a.count(".") == 3 and not a.endswith(".0.0"):
                continue
            counts[a] = counts.get(a, 0) + 1

    ranked = sorted(counts, key=lambda a: -counts[a])
    top = [a for a in ranked if counts[a] >= MIN_BUCKET_ROWS][:MAX_BUCKETS]
    topset = set(top)

    wanted = []
    for c in EXTRA_COLS:
        if c in cols:
            wanted.append((c, cols[c]))
    for a in algs:
        for pre in ("re_", "ss_", "bs_", "ns_", "mv_"):
            c = pre + a
            if c in cols:
                wanted.append((c, cols[c]))
    wn = len(wanted)

    rkeys = list(RANGES.keys())
    rspecs = [RANGES[k] for k in rkeys]

    acc  = {}
    last_row = {}
    meta_stats = {}
    inst_i = cols.get("instances")
    rbv_i  = cols.get("rate_best_v")

    with open(bfile, "r", newline="") as f:
        rd = csv.reader(f)
        next(rd)
        hlen = len(header)
        for row in rd:
            if len(row) < hlen:
                continue
            a = row[ai]
            a = _label_for(a)
            if a not in topset:
                continue
            t_raw = row[ti]
            if not t_raw:
                continue
            try:
                t = float(t_raw)
            except ValueError:
                continue
            last_row[a] = row

            ms = meta_stats.get(a)
            if ms is None:
                ms = meta_stats[a] = {"last_ts": 0.0, "inst_sum": 0.0,
                                      "inst_n": 0, "pts24": 0}
            if t > ms["last_ts"]:
                ms["last_ts"] = t
            if t > now - 86400:
                ms["pts24"] += 1
                if inst_i is not None and inst_i < len(row):
                    iv = row[inst_i]
                    if iv:
                        try:
                            ms["inst_sum"] += float(iv)
                            ms["inst_n"] += 1
                        except ValueError:
                            pass
                # 0.4.78.2: 5-min bin coverage for the fleet chart.
                # A bucket is "covered" in a bin if any row in that
                # bin had rate_best_v > 0 (i.e. a rate leader existed).
                if "co_seen" not in ms:
                    ms["co_seen"] = set()
                    ms["co_have"] = set()
                b5 = int(t // 300)
                ms["co_seen"].add(b5)
                if rbv_i is not None and rbv_i < len(row):
                    rv = row[rbv_i]
                    if rv:
                        try:
                            if float(rv) > 0:
                                ms["co_have"].add(b5)
                        except ValueError:
                            pass

            buck = acc.get(a)
            if buck is None:
                buck = acc[a] = {}
            for ri, (span, width) in enumerate(rspecs):
                lo = None if span is None else now - span
                if lo is not None and t < lo:
                    continue
                b = int((t - (lo or 0)) // width)
                key = (ri, b)
                cell = buck.get(key)
                if cell is None:
                    cell = buck[key] = [[0.0, 0] for _ in range(wn)]
                for ci, (_, cidx) in enumerate(wanted):
                    raw = row[cidx] if cidx < len(row) else ""
                    if not raw:
                        continue
                    try:
                        v = float(raw)
                    except ValueError:
                        continue
                    slot = cell[ci]
                    slot[0] += v
                    slot[1] += 1

    docs = []
    for bid in top:
        buck = acc.get(bid, {})
        doc = {"id": bid, "series": {}}
        for ri, rkey in enumerate(rkeys):
            bins = sorted({k[1] for k in buck if k[0] == ri})
            span, width = rspecs[ri]
            lo = None if span is None else now - span
            base = lo if lo is not None else 0
            ts_out = [int(base + b * width + width / 2) for b in bins]
            series = {"ts": ts_out}
            is24 = (rkey == "24h")
            for ci, (cname, _) in enumerate(wanted):
                if cname.startswith("mv_") and not is24:
                    continue
                vals = []
                for b in bins:
                    cell = buck.get((ri, b))
                    if cell is None:
                        vals.append(None)
                        continue
                    sm, ct = cell[ci]
                    vals.append(sm / ct if ct else None)
                series[cname] = vals
            doc["series"][rkey] = series

        last = last_row.get(bid)
        if last is not None:
            def _g(name, dflt=""):
                i = cols.get(name)
                if i is None or i >= len(last):
                    return dflt
                v = last[i]
                return v if v != "" else dflt
            def _gf(name):
                v = _g(name)
                if v == "":
                    return None
                try:
                    return float(v)
                except ValueError:
                    return None
            doc["last"] = {
                "collected_ts": int(_gf("collected_ts") or 0),
                "best_alg":     _g("best_alg"),
                "best_i":       _gf("best_i"),
                "instances":    _gf("instances"),
                "ref_rate":     _gf("ref_rate"),
                "min_rtt":      _gf("min_rtt"),
                "rate_best_i":  _gf("rate_best_i"),
                "rate_best_v":  _gf("rate_best_v"),
                "tcp_rmem_max": _gf("tcp_rmem_max"),
                "re":           {a: _gf("re_" + a) for a in algs},
            }
        docs.append(doc)

    return header, cols, docs, meta_stats


def emit_meta(buckets, algs, now, primary=None):
    rows_24h = [r for r in buckets if (ts_of(r) or 0) > now - 86400]
    if not rows_24h:
        rows_24h = list(buckets)
    by = defaultdict(list)
    for r in rows_24h:
        by[r.get("addr") or "unknown"].append(r)
    entries = []
    for bid, rs in by.items():
        inst = [to_float(r.get("instances")) for r in rs]
        inst = [v for v in inst if v is not None]
        last = max((ts_of(r) or 0) for r in rs)
        entries.append({
            "id": bid,
            "points": len(rs),
            "instances_mean": round(sum(inst) / len(inst), 2) if inst else 0,
            "last_ts": int(last),
        })
    entries.sort(key=lambda e: (e["instances_mean"], e["last_ts"]),
                 reverse=True)
    write_json("meta.json", {
        "generated_ts":  now,
        "ranges":        list(RANGES),
        "algs":          algs,
        "buckets":       entries,
        "default_bucket": (
            primary if (primary and any(e["id"] == primary for e in entries))
            else (entries[0]["id"] if entries else "all")
        ),
        "has_tcp_rmem":  "tcp_rmem_max" in (
            load_csv(buckets_source(), max_rows=1)[0] or []),
    })


def emit_bucket(bid, rows, algs, now):
    """Transpose to column-major, then bin every column into every range
    in a single pass. Avoids the old 4x re-parse + per-cell dict.get
    hotspot (~11M dict lookups/run on a modest history)."""
    wanted = list(EXTRA_COLS)
    for a in algs:
        wanted.append("re_" + a)
        wanted.append("ss_" + a)
        wanted.append("bs_" + a)
        wanted.append("ns_" + a)
        wanted.append("mv_" + a)
    ncols = len(wanted)

    ts_list = []
    col_data = [[] for _ in range(ncols)]
    for r in rows:
        t = ts_of(r)
        if t is None:
            continue
        ts_list.append(t)
        for i, c in enumerate(wanted):
            v = r.get(c)
            col_data[i].append(to_float(v) if v not in (None, "") else None)
    n = len(ts_list)

    range_meta = []
    for rng, (span, width) in RANGES.items():
        lo = None if span is None else now - span
        if lo is None:
            raw_bins = [int(t // width) for t in ts_list]
            base = 0
        else:
            raw_bins = [(int((t - lo) // width) if t >= lo else -1)
                        for t in ts_list]
            base = lo
        uniq = sorted(set(b for b in raw_bins if b >= 0))
        idx = {b: i for i, b in enumerate(uniq)}
        row_bin = [idx.get(b, -1) if b >= 0 else -1 for b in raw_bins]
        ts_out = [int(base + b * width + width / 2) for b in uniq]
        range_meta.append({"rng": rng, "row_bin": row_bin,
                           "ts": ts_out, "nb": len(uniq)})

    nranges = len(range_meta)
    keep_mv = [m["rng"] == "24h" for m in range_meta]
    sums = [[[0.0] * m["nb"] for m in range_meta] for _ in range(ncols)]
    cnts = [[[0]   * m["nb"] for m in range_meta] for _ in range(ncols)]

    for i in range(n):
        row_bins = [m["row_bin"][i] for m in range_meta]
        for ci in range(ncols):
            v = col_data[ci][i]
            if v is None:
                continue
            for ri in range(nranges):
                j = row_bins[ri]
                if j < 0:
                    continue
                sums[ci][ri][j] += v
                cnts[ci][ri][j] += 1

    doc = {"id": bid, "series": {}}
    for ri, m in enumerate(range_meta):
        nb = m["nb"]
        series = {"ts": m["ts"]}
        mv_ok = keep_mv[ri]
        for ci, c in enumerate(wanted):
            if c.startswith("mv_") and not mv_ok:
                continue
            s_ci = sums[ci][ri]
            k_ci = cnts[ci][ri]
            series[c] = [(s_ci[j] / k_ci[j]) if k_ci[j] else None
                         for j in range(nb)]
        doc["series"][m["rng"]] = series

    if rows:
        last = rows[-1]
        doc["last"] = {
            "collected_ts": int(to_float(last.get("collected_ts")) or 0),
            "best_alg":     last.get("best_alg") or "",
            "best_i":       to_float(last.get("best_i")),
            "instances":    to_float(last.get("instances")),
            "ref_rate":     to_float(last.get("ref_rate")),
            "min_rtt":      to_float(last.get("min_rtt")),
            "rate_best_i":  to_float(last.get("rate_best_i")),
            "rate_best_v":  to_float(last.get("rate_best_v")),
            "tcp_rmem_max": to_float(last.get("tcp_rmem_max")),
            "re":           {a: to_float(last.get("re_" + a)) for a in algs},
        }
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in bid)
    write_json("bucket_%s.json" % safe, doc)

def _attach_sustained_outcomes(swaps, srate_rows):
    by_cookie = defaultdict(list)
    for r in srate_rows:
        c = to_float(r.get("cookie"))
        t = to_float(r.get("boot_ts"))
        s = to_float(r.get("srate"))
        if c is None or t is None or s is None:
            continue
        by_cookie[int(c)].append((t, s))
    for lst in by_cookie.values():
        lst.sort()

    for r in swaps:
        r["_outcome_sustained"] = None
        c = to_float(r.get("cookie"))
        t = to_float(r.get("boot_ts"))
        sb = to_float(r.get("srate_before"))
        if c is None or t is None or not sb or sb <= 0:
            continue
        lst = by_cookie.get(int(c))
        if not lst:
            continue
        ts_list = [x[0] for x in lst]
        pre = sb
        lo = bisect.bisect_left(ts_list, t + SUSTAINED_LO_S)
        hi = bisect.bisect_right(ts_list, t + SUSTAINED_HI_S)
        if lo >= hi:
            continue
        samples = [lst[i][1] for i in range(lo, hi)]
        pm = median(samples)
        if pm is None or pre <= 0:
            continue
        ratio = pm / pre
        r["_outcome_sustained"] = (
            "win"  if ratio >= 1.1 else
            "loss" if ratio <= 0.9 else
            "null")


def emit_swaps(rows, srate_rows, now):
    _attach_sustained_outcomes(rows, srate_rows)
    doc = {}
    for rng, (span, width) in RANGES.items():
        lo = None if span is None else now - span
        acc = defaultdict(lambda: {
            0: {"cw": 0, "cl": 0, "uu": 0, "ul": 0},
            1: {"cw": 0, "cl": 0, "uu": 0, "ul": 0},
        })
        for r in rows:
            t = ts_of(r)
            if t is None or (lo is not None and t < lo):
                continue
            b = int((t - (lo or 0)) // width)
            d = 1 if truthy(r.get("diverges")) else 0
            o = str(r.get("outcome", "")).strip().lower()
            if o == "win":
                acc[b][d]["cw"] += 1
            elif o == "loss":
                acc[b][d]["cl"] += 1
            o2 = r["_outcome_sustained"]
            if o2 == "win":
                acc[b][d]["uu"] += 1
            elif o2 == "loss":
                acc[b][d]["ul"] += 1

        base = lo if lo is not None else 0
        node = {"ts": [], "swaps": []}
        for d in (0, 1):
            node["d%d_rate"           % d] = []
            node["d%d_lo"             % d] = []
            node["d%d_hi"             % d] = []
            node["d%d_n"              % d] = []
            node["d%d_rate_sustained" % d] = []
            node["d%d_lo_sustained"   % d] = []
            node["d%d_hi_sustained"   % d] = []
            node["d%d_n_sustained"    % d] = []

        for b in sorted(acc):
            node["ts"].append(int(base + b * width + width / 2))
            total = 0
            for d in (0, 1):
                bucket = acc[b][d]
                cw, cl = bucket["cw"], bucket["cl"]
                cn = cw + cl
                total += cn
                lo_, hi_ = wilson(cw, cn)
                node["d%d_rate" % d].append(cw / cn if cn else None)
                node["d%d_lo"   % d].append(lo_)
                node["d%d_hi"   % d].append(hi_)
                node["d%d_n"    % d].append(cn)
                uw, ul = bucket["uu"], bucket["ul"]
                un = uw + ul
                lo2, hi2 = wilson(uw, un)
                node["d%d_rate_sustained" % d].append(uw / un if un else None)
                node["d%d_lo_sustained"   % d].append(lo2)
                node["d%d_hi_sustained"   % d].append(hi2)
                node["d%d_n_sustained"    % d].append(un)
            node["swaps"].append(total)
        doc[rng] = node
    write_json("swaps.json", doc)


def emit_fleet(meta_stats, now):
    """Per-bucket: fraction of 5-minute bins in the last 24h where the
    bucket's rate_best_v was > 0.  meta_stats carries the two sets
    (co_seen / co_have) filled by aggregate_all's streaming pass.
    The prior body tried to re-derive this from meta_rows, which only
    ever carried addr / instances / collected_ts -- rate_best_v was
    never present, so every bucket came back 0.0."""
    pairs = []
    for bid, ms in meta_stats.items():
        seen = ms.get("co_seen") or set()
        if not seen:
            continue
        have = len(ms.get("co_have") or ())
        pairs.append((bid, round(100.0 * have / len(seen), 1)))
    pairs.sort(key=lambda p: -p[1])
    pairs = pairs[:25]
    labels = [p[0] for p in pairs]
    cov    = [p[1] for p in pairs]
    write_json("fleet.json", {"buckets": labels, "coverage_24h": cov})


# INDEX_HTML template is now read from index.html in the same directory
# (no more embedded template - patches go to index.html, installer picks them up)
_INSTALL_DIR = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(_INSTALL_DIR, "index.html")) as _f:
    INDEX_HTML = _f.read()


def main():
    try:
        os.nice(19)
    except (OSError, AttributeError):
        pass
    now = int(time.time())
    bfile = buckets_source()
    if not bfile:
        print("renderer: no buckets CSV found yet")
        return 1

    # Peek at the header first — algs is derived from it, and
    # aggregate_all needs algs.
    with open(bfile, "r", newline="") as _f:
        _hdr = next(csv.reader(_f))
    algs = sorted({c[3:] for c in _hdr if c.startswith("re_")})

    _, swaps = load_csv(os.path.join(HIST, "swaps.csv"),
                        max_rows=MAX_ROWS_SWAPS)
    _, srate = load_csv(os.path.join(HIST, "srate.csv"),
                        max_rows=MAX_ROWS_SRATE)
    header, cols, docs, meta_stats = aggregate_all(bfile, algs, now)

    # meta needs the same stats we gathered during streaming.
    meta_rows = []
    for bid in [d["id"] for d in docs]:
        st = meta_stats.get(bid) or {}
        meta_rows.append({
            "addr": bid,
            "instances": (st.get("inst_sum", 0) / st["inst_n"]
                          if st.get("inst_n") else 0),
            "collected_ts": st.get("last_ts", 0),
            "pts24": st.get("pts24", 0),
        })

    # 0.4.71: no primary pin.  emit_meta sorts entries by
    # instances_mean; that is the default bucket.
    emit_meta(meta_rows, algs, now)

    for doc in docs:
        bid = doc["id"]
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in bid)
        write_json("bucket_%s.json" % safe, doc)

    def _safe(b):
        return "".join(c if c.isalnum() or c in "-_." else "_" for c in b)
    emitted_safes = {_safe(d["id"]) for d in docs}
    cleaned = 0
    data_dir = Path(DATA)
    if data_dir.exists():
        for stale in data_dir.glob("bucket_*.json"):
            stem = stale.stem[len("bucket_"):]
            if stem not in emitted_safes:
                try:
                    stale.unlink()
                    cleaned += 1
                except OSError:
                    pass

    emit_swaps(swaps, srate, now)
    emit_fleet(meta_stats, now)

    # 0.4.76: the main() rewrite that added streaming aggregation
    # dropped this write; the renderer has been updating JSON for
    # weeks while index.html went stale.
    with open(HIST + "/index.html", "w") as f:
        f.write(INDEX_HTML)

    globals()["_CLEANED"] = cleaned
    globals()["_EMITTED"] = len(docs)
    globals()["_SKIPPED"] = max(0, len(meta_stats) - len(docs))
    globals()["_ROWS"] = sum(
        sum(len(v) for v in d["series"]["24h"].values()
            if isinstance(v, list)) for d in docs) or 0


    print("renderer: %d buckets (%d emitted, %d skipped, %d cleaned), "
          "%d algs, %d swaps, %d srate rows"
          % (len(meta_stats), globals().get("_EMITTED", 0),
             globals().get("_SKIPPED", 0), globals().get("_CLEANED", 0),
             len(algs), len(swaps), len(srate)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


def main():
    if os.geteuid() != 0:
        die("must run as root (writes /etc/cron.d and /var/lib/bpftune)")

    os.makedirs(HIST, exist_ok=True)

    say("migrating old CSVs")
    migrate()

    say("writing CLI, collector, renderer beside installer")
    write_file(CLI,       CLI_SRC,       0o755)
    write_file(COLLECTOR, COLLECTOR_SRC, 0o755)
    write_file(RENDERER,  RENDERER_SRC,  0o755)

    say("compiling")
    for p in (CLI, COLLECTOR, RENDERER):
        r = subprocess.run([sys.executable, "-m", "py_compile", p],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stderr)
            die("py_compile failed on " + p)

    say("installing cron: " + CRON)
    write_cron()

    say("seeding + verifying")
    run_and_verify()

    print()
    say("done")
    print("    cli:       %s" % CLI)
    print("    collector: %s" % COLLECTOR)
    print("    renderer:  %s" % RENDERER)
    print("    cron:      %s" % CRON)
    print("    site:      %s/index.html" % HIST)
    print()
    print("  open http://<this-host>:8080/ in a browser")
    print("  tail -f /var/log/bpftune-collector.log")
    print()


if __name__ == "__main__":
    main()
