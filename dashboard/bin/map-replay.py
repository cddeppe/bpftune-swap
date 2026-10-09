#!/usr/bin/env python3
"""Replay every historical swap through the current score-update rule
under the sustained rider, and write the result to remote_host_map.

Idempotent: re-running is a no-op if the map already matches.
"""
import csv, json, subprocess, sys
from collections import defaultdict
from pathlib import Path

HIST  = Path("/var/lib/bpftune/history")
SRATE = HIST / "srate.csv"

METRIC_SIZE = 48
METRIC_COUNT = 16
OFF_SS   = 40
OFF_BAD  = 42
OFF_NULL = 43
WIN_T, LOSS_T, DIV, NEUTRAL = 600, 100, 8, 256

CONGS = ["cubic","bbr","htcp","dctcp","scalable","vegas","veno",
         "westwood","reno","illinois","yeah","lp","bic","highspeed",
         "hybla","nv"]

def b16(d):
    p = (d or "").split(".")
    return "%s.%s.0.0" % (p[0], p[1]) if len(p) == 4 else None

sr = defaultdict(list)
with open(SRATE) as f:
    for r in csv.DictReader(f):
        try:
            c = int(r["cookie"]); t = float(r["boot_ts"]); v = int(r["srate"])
        except (TypeError, ValueError, KeyError): continue
        if v > 0: sr[c].append((t, v))
for c in sr: sr[c].sort()

def cls_of(series, T, pre):
    s = [v for (t, v) in series if T + 60.0 <= t <= T + 300.0]
    if not s: return None
    if len(s) == 1:
        m = float(s[0])
    else:
        sv = sorted(s); n = len(sv)
        m = float(sv[n//2]) if n % 2 else (sv[n//2-1]+sv[n//2])/2.0
    r = m / pre if pre else 0
    if r >= 1.1: return "win"
    if r <= 0.9: return "loss"
    return "null"

def step(cur, c):
    if c == "win":  t = WIN_T
    elif c == "loss": t = LOSS_T
    else: return cur
    if cur < t: cur += (t - cur) // DIV
    elif cur > t: cur -= (cur - t) // DIV
    return max(0, min(1024, cur))

rows, seen = [], set()
for p in [HIST / "swaps.csv"] + sorted(HIST.glob("swaps.csv.pre-sustained-*")):
    if not p.exists(): continue
    with open(p) as f:
        for r in csv.DictReader(f):
            try:
                c = int(r["cookie"]); t = int(r["collected_ts"])
            except (KeyError, ValueError, TypeError): continue
            if (c, t) in seen: continue
            seen.add((c, t))
            b = b16(r.get("dest")); alg = r.get("to_alg")
            try: pre = float(r.get("srate_before") or 0)
            except (TypeError, ValueError): pre = 0
            try: boot = float(r.get("boot_ts") or 0)
            except (TypeError, ValueError): boot = 0
            if not b or alg not in CONGS or pre <= 0: continue
            rows.append({"c":c,"t":t,"boot":boot,"b":b,"alg":alg,"pre":pre})
rows.sort(key=lambda r: r["t"])

state = defaultdict(lambda: {"score": NEUTRAL, "bad": 0, "null": 0})
for s in rows:
    k = cls_of(sr.get(s["c"], []), s["boot"], s["pre"])
    if k is None: continue
    cell = state[(s["b"], s["alg"])]
    if k == "win":   cell["bad"] = 0; cell["null"] = 0
    elif k == "loss": cell["bad"] = min(255, cell["bad"] + 1)
    else:             cell["null"] = min(255, cell["null"] + 1)
    cell["score"] = step(cell["score"], k)

print(f"replay: {len(rows)} swaps, {len(state)} cells", file=sys.stderr)

out = subprocess.run(
    ["sudo","bpftool","-f","-j","map","dump","name","remote_host_map"],
    capture_output=True, text=True).stdout
cur = json.loads(out)

def as_bytes(seq):
    return bytes(int(x,16) if isinstance(x,str) else int(x) for x in seq)

written = errors = 0
for e in cur:
    key = as_bytes(e["key"])
    vb  = bytearray(as_bytes(e["value"]))
    bucket = "%d.%d.0.0" % (key[12], key[13])
    base = len(vb) - METRIC_COUNT * METRIC_SIZE
    changed = False
    for i, alg in enumerate(CONGS):
        cell = state.get((bucket, alg))
        if cell is None: continue
        pos_ss   = base + i*METRIC_SIZE + OFF_SS
        pos_bad  = base + i*METRIC_SIZE + OFF_BAD
        pos_null = base + i*METRIC_SIZE + OFF_NULL
        if int.from_bytes(vb[pos_ss:pos_ss+2], "little") != cell["score"]:
            vb[pos_ss:pos_ss+2] = cell["score"].to_bytes(2,"little"); changed = True
        if vb[pos_bad]  != cell["bad"]:
            vb[pos_bad] = cell["bad"]; changed = True
        if vb[pos_null] != cell["null"]:
            vb[pos_null] = cell["null"]; changed = True
    if not changed: continue
    cmd = ["sudo","bpftool","map","update","name","remote_host_map",
           "key"] + [str(x) for x in key] + ["value"] + [str(x) for x in vb]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"  ERROR {bucket}: {r.stderr.strip()[:160]}", file=sys.stderr)
        errors += 1
    else:
        written += 1
print(f"wrote {written}, {errors} errors", file=sys.stderr)
