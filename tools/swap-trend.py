#!/usr/bin/env python3
"""Classify each socket's metric trajectory at swap time; bin outcome by class.

Motivation (2026-09-15 diagnostic): the moderate swap tier has been
reading as a coin flip under IMP/WRS.  Re-binning by effect size showed
it fires on sockets whose metric is not moving -- i.e. sockets where
the current algorithm is not the limiter.  This tool confirms the
signal by classifying each socket's own last-N metric samples before
a swap and binning the outcome by shape.

Trajectory classes:

    flat          max/min over the window < 1.10
    rising        >= 70% of consecutive steps increase
    falling       >= 70% of consecutive steps decrease
    oscillating   none of the above
    insufficient  fewer than N pre-samples in the log

Result on 2026-09-14 + 2026-09-15 (340 swaps, N=3):

    class          n     win%   null%   loss%
    flat         127     7.9%   90.6%    1.6%
    rising        19    57.9%   36.8%    5.3%
    falling       11    27.3%   72.7%    0.0%
    oscillating   18    16.7%   66.7%   16.7%
    insufficient 165    42.4%   50.3%    7.3%

Flat sockets win at a rate inside the metric's own noise band.  This
is the basis for the 0.4.37 flat-gate on the moderate tier.

Also reports observed span of each window (seconds, median/p10/p90);
if class correlates with span, the signal is a proxy for socket
lifespan rather than path behavior.  It does not (spans are 80-220s
across classes).

Usage:  sudo python3 tools/swap-trend.py
        sudo python3 tools/swap-trend.py /var/log/bpftune-met-2026-09-16.log
        sudo python3 tools/swap-trend.py -N 4 /var/log/bpftune-met-2026-09-16.log
"""
import re, sys, os, glob, statistics
from collections import defaultdict

met_re  = re.compile(r'met cookie=(\d+) rport=(\d+) alg=(\d+) segs=(\d+) val=(\d+) rtt=(\d+) rate=(\d+) loss=(\d+) smrtt=(\d+) bmrtt=(\d+) avgrtt=(\d+)')
swap_re = re.compile(r'swap cookie=(\d+) from=(\d+) to=(\d+) bc=(\d+) ac=(\d+) d=(\d)')
ts_re   = re.compile(r'\s(\d+\.\d+):\s+bpf_trace_printk:')

BINS = [
    (0.0, 0.5, "big_win"),
    (0.5, 0.9, "mod_win"),
    (0.9, 1.1, "null"),
    (1.1, 1.5, "mod_loss"),
    (1.5, 2.0, "big_loss"),
    (2.0, float("inf"), "severe_loss"),
]

def classify_outcome(r):
    for lo, hi, name in BINS:
        if lo <= r < hi:
            return name
    return "?"

def classify_traj(vals):
    if len(vals) < 2:
        return "insufficient"
    lo, hi = min(vals), max(vals)
    if lo == 0:
        return "zero"
    if hi / lo < 1.10:
        return "flat"
    n = len(vals) - 1
    inc = sum(1 for i in range(1, len(vals)) if vals[i] > vals[i-1])
    dec = sum(1 for i in range(1, len(vals)) if vals[i] < vals[i-1])
    if inc / n >= 0.7 and vals[-1] > vals[0]:
        return "rising"
    if dec / n >= 0.7 and vals[-1] < vals[0]:
        return "falling"
    return "oscillating"

def parse(path):
    samples = defaultdict(list)
    swaps = []
    with open(path) as f:
        for line in f:
            tm = ts_re.search(line)
            if not tm:
                continue
            ts = float(tm.group(1))
            m = met_re.search(line)
            if m:
                c = int(m.group(1)); v = int(m.group(5))
                if v == 0 or v == (1 << 64) - 1:
                    continue
                samples[c].append((ts, v))
                continue
            m = swap_re.search(line)
            if m:
                swaps.append({
                    '_ts': ts,
                    'cookie': int(m.group(1)),
                    'from': int(m.group(2)), 'to': int(m.group(3)),
                    'd': int(m.group(6)), 'post': None, 'post_ts': None,
                })
    for s in swaps:
        for ts, v in samples.get(s['cookie'], []):
            if ts > s['_ts']:
                s['post'] = v; s['post_ts'] = ts
                break
    return samples, swaps

def window_before(samples, cookie, swap_ts, N):
    seq = [(ts, v) for ts, v in samples.get(cookie, []) if ts < swap_ts]
    if not seq:
        return []
    return seq[-N:]

def report(name, swaps, samples, N):
    done = [s for s in swaps if s['post'] is not None and s['post'] > 0]
    obs = []
    for s in done:
        seq = window_before(samples, s['cookie'], s['_ts'], N)
        vals = [v for _, v in seq]
        klass = classify_traj(vals)
        span = (seq[-1][0] - seq[0][0]) if len(seq) >= 2 else 0.0
        pre = vals[-1] if vals else 0
        if pre == 0:
            continue
        obs.append({
            'cookie': s['cookie'], 'd': s['d'],
            'from': s['from'], 'to': s['to'],
            'pre': pre, 'post': s['post'],
            'ratio': s['post'] / pre,
            'class': klass, 'span': span, 'n': len(vals),
        })
    if not obs:
        print("%s: 0 usable observations\n" % name)
        return

    classes = ["flat", "rising", "falling", "oscillating", "insufficient", "zero"]
    by_class = defaultdict(list)
    for o in obs:
        by_class[o['class']].append(o)

    print("=== %s  (window N=%d, n=%d swaps) ===" % (name, N, len(obs)))
    print("%-13s %5s %8s %8s %8s %8s %8s %8s" %
          ("traj_class", "n", "big_w%", "mod_w%", "null%", "mod_l%", "big_l%", "win%"))
    for c in classes:
        v = by_class.get(c, [])
        if not v:
            continue
        n = len(v)
        cnt = defaultdict(int)
        for o in v:
            cnt[classify_outcome(o['ratio'])] += 1
        win = (cnt["big_win"] + cnt["mod_win"]) / n * 100
        print("%-13s %5d %7.1f%% %7.1f%% %7.1f%% %7.1f%% %7.1f%% %7.1f%%" %
              (c, n,
               100.0*cnt["big_win"]/n, 100.0*cnt["mod_win"]/n,
               100.0*cnt["null"]/n, 100.0*cnt["mod_loss"]/n,
               100.0*(cnt["big_loss"]+cnt["severe_loss"])/n,
               win))

    spans = defaultdict(list)
    for o in obs:
        spans[o['class']].append(o['span'])
    print("  window span (seconds, median / p10 / p90):")
    for c in classes:
        if not spans[c]:
            continue
        s = sorted(spans[c])
        med = statistics.median(s)
        p10 = s[int(0.1*len(s))]
        p90 = s[min(len(s)-1, int(0.9*len(s)))]
        print("    %-13s %9.1f / %9.1f / %9.1f" % (c, med, p10, p90))

    for d in (0, 1):
        sub = [o for o in obs if o['d'] == d]
        if not sub:
            continue
        label = "moderate" if d == 0 else "desperate"
        bd = defaultdict(list)
        for o in sub:
            bd[o['class']].append(o)
        print("  %s (d=%d, n=%d):" % (label, d, len(sub)))
        for c in classes:
            v = bd.get(c, [])
            if not v:
                continue
            n = len(v)
            wins = sum(1 for o in v if o['ratio'] < 0.9)
            nulls = sum(1 for o in v if 0.9 <= o['ratio'] <= 1.1)
            losses = sum(1 for o in v if o['ratio'] > 1.1)
            print("    %-13s n=%-4d win=%5.1f%% null=%5.1f%% loss=%5.1f%%" %
                  (c, n, 100.0*wins/n, 100.0*nulls/n, 100.0*losses/n))
    print()

if __name__ == "__main__":
    args = sys.argv[1:]
    N = 3
    # v0.4.104: support both "-N4" and "-N 4" forms
    if args and args[0].startswith("-N"):
        try:
            val = args[0][2:]
            if not val and len(args) > 1:
                # "-N 4" form — value is the next arg
                val = args[1]
                args = args[1:]
            N = int(val)
            args = args[1:]
        except ValueError:
            sys.exit("bad -N value: %s" % args[0])
    files = args if args else sorted(glob.glob("/var/log/bpftune-met-*.log"))[-4:]
    if not files:
        sys.exit("no met logs found")

    all_samples = defaultdict(list)
    all_swaps = []
    for p in files:
        samples, swaps = parse(p)
        for c, seq in samples.items():
            all_samples[c].extend(seq)
        all_swaps.extend(swaps)

    print("analyzing: %s" % " ".join(os.path.basename(p) for p in files))
    print("total swaps parsed: %d\n" % len(all_swaps))

    if len(files) == 1:
        report(os.path.basename(files[0]), all_swaps, all_samples, N)
    else:
        for N_ in (3, 4, 6):
            report("ALL swaps", all_swaps, all_samples, N_)
