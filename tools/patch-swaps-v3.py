#!/usr/bin/env python3
"""
Patch: add socket_rate_before column to swaps.csv (schema v2 -> v3).

    python3 tools/patch-swaps-v3.py

Edits tools/bpftune-dashboard-install.py in place. Idempotent - safe
to re-run. Every anchor is checked for uniqueness before any write.
"""
import os
import sys

TARGET = os.path.join("tools", "bpftune-dashboard-install.py")


def die(msg):
    print("FATAL: " + msg, file=sys.stderr, flush=True)
    sys.exit(1)


def apply(src, anchor, replacement):
    n = src.count(anchor)
    if n != 1:
        die("anchor matched %d times, expected 1. anchor head: %r"
            % (n, anchor[:70]))
    return src.replace(anchor, replacement, 1)


if not os.path.exists(TARGET):
    die("not found: " + TARGET + " (run from the repo root)")

src = open(TARGET).read()
orig = src

# 1. import csv at top of installer
src = apply(
    src,
    "import os\nimport subprocess\nimport sys\nimport time\n",
    "import csv\nimport os\nimport subprocess\nimport sys\nimport time\n",
)

# 2. add helper just before migrate()
src = apply(
    src,
    "def migrate():\n",
    '''def _append_swaps_column(path, new_col):
    """Append a column to swaps.csv in place, empty for existing rows.
    Preserves history. Consumers that treat empty as null (DictReader,
    the renderer) do not need a change."""
    with open(path, newline="") as f:
        rd = csv.reader(f)
        try:
            header = next(rd)
        except StopIteration:
            return
        rows = list(rd)
    new_header = header + [new_col]
    tmp = path + ".tmp"
    with open(tmp, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(new_header)
        for r in rows:
            while len(r) < len(header):
                r.append("")
            w.writerow(r + [""])
    os.replace(tmp, path)


def migrate():
''',
)

# 3. migration check: v2 -> v3
src = apply(
    src,
    '''        if "collected_ts" in cols:
            say("  swaps.csv already schema v2")
        elif "ts_epoch" in cols:''',
    '''        if "socket_rate_before" in cols:
            say("  swaps.csv already schema v3 (has socket_rate_before)")
        elif "collected_ts" in cols:
            _append_swaps_column(SWAPS, "socket_rate_before")
            say("  appended socket_rate_before column to swaps.csv")
        elif "ts_epoch" in cols:''',
)

# 4. collector row: add socket_rate_before
src = apply(
    src,
    '''            "diverges": "1" if (mt_alg and rb_alg and mt_alg != rb_alg) else "0",
            "outcome": outcome,
        })
        n += 1
    return n
''',
    '''            "diverges": "1" if (mt_alg and rb_alg and mt_alg != rb_alg) else "0",
            "outcome": outcome,
            "socket_rate_before": pre if pre is not None else "",
        })
        n += 1
    return n
''',
)

if src == orig:
    print("already patched, nothing to do")
    sys.exit(0)

tmp = TARGET + ".tmp"
with open(tmp, "w") as f:
    f.write(src)
os.replace(tmp, TARGET)
print("patched " + TARGET)
print("  + import csv")
print("  + _append_swaps_column()")
print("  + migration: v2 -> v3")
print("  + collector row: socket_rate_before")
