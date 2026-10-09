#!/usr/bin/env python3
"""bpftune-dashboard installer. Idempotent."""
from __future__ import annotations

import argparse
import csv
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT  = Path(__file__).resolve().parent
BIN_SRC    = REPO_ROOT / "bin"
SYSD_SRC   = REPO_ROOT / "systemd"
LOGROT_SRC = REPO_ROOT / "logrotate"

INSTALL_DIR   = Path("/opt/bpftune-dashboard")
INSTALL_BIN   = INSTALL_DIR / "bin"
HIST          = Path("/var/lib/bpftune/history")
CRON          = Path("/etc/cron.d/bpftune-history")
LOGROTATE     = Path("/etc/logrotate.d/bpftune-dashboard")
SYSTEMD_DIR   = Path("/etc/systemd/system")
TRACE_UNIT    = SYSTEMD_DIR / "bpftune-met-trace.service"
HTTP_UNIT     = SYSTEMD_DIR / "bpftune-dashboard-http.service"
TRACE_LOG     = Path("/var/log/bpftune-met-live.log")
COLLECTOR_LOG = Path("/var/log/bpftune-collector.log")

CLI       = INSTALL_BIN / "bpftune-cli.py"
COLLECTOR = INSTALL_BIN / "bpftune-collector.py"
RENDERER  = INSTALL_BIN / "bpftune-render.py"

BUCKETS_LEGACY = HIST / "buckets.csv"
BUCKETS_V1     = HIST / "buckets.v1.csv"
BUCKETS_V2     = HIST / "buckets.v2.csv"
SWAPS_V1       = HIST / "swaps.v1.csv"
SWAPS          = HIST / "swaps.csv"
SRATE          = HIST / "srate.csv"
CURRENT_JSON   = HIST / "current.json"

CONGS = ["cubic", "bbr", "htcp", "dctcp", "scalable", "vegas", "veno",
         "westwood", "reno", "illinois", "yeah", "lp", "bic", "highspeed",
         "hybla", "nv"]

SCORE_COLS = (["ss_" + a for a in CONGS]
              + ["bs_" + a for a in CONGS]
              + ["ns_" + a for a in CONGS])

SWAP_COLS_REQUIRED = ["socket_rate_before", "dest", "dest_raw",
                      "f_ema", "t_ema", "srate_before"]

HTTP_PORT_DEFAULT = 8080


def _c(code, s): return "\033[" + code + "m" + s + "\033[0m"
def say(m):  print(_c("1;34", "[install]") + " " + m, flush=True)
def warn(m): print(_c("1;33", "[install]") + " " + m, flush=True)


def die(m):
    print(_c("1;31", "[install] FATAL:") + " " + m,
          file=sys.stderr, flush=True)
    sys.exit(1)


def write_file(path, text, mode=0o644):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, str(path))
    except Exception:
        try: os.unlink(tmp)
        except OSError: pass
        raise


def copy_file(src, dst, mode=0o755):
    data = Path(src).read_bytes()
    dst = Path(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=str(dst.parent))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, str(dst))
    except Exception:
        try: os.unlink(tmp)
        except OSError: pass
        raise


def _append_columns(path, new_cols):
    new_cols = list(new_cols)
    path = Path(path)
    fd, tmp = tempfile.mkstemp(prefix=".col-", dir=str(path.parent))
    replaced = False
    try:
        with open(path, "r", newline="", encoding="utf-8") as src, \
             os.fdopen(fd, "w", newline="", encoding="utf-8") as dst:
            rd = csv.reader(src)
            wr = csv.writer(dst)
            try:
                header = next(rd)
            except StopIteration:
                return
            wr.writerow(header + new_cols)
            pad  = [""] * len(new_cols)
            hlen = len(header)
            for row in rd:
                if len(row) < hlen:
                    row.extend([""] * (hlen - len(row)))
                wr.writerow(row + pad)
            dst.flush()
            os.fsync(dst.fileno())
        os.replace(tmp, str(path))
        replaced = True
    finally:
        if not replaced:
            try: os.unlink(tmp)
            except OSError: pass


def migrate():
    if BUCKETS_LEGACY.exists() and not BUCKETS_V1.exists():
        BUCKETS_LEGACY.rename(BUCKETS_V1)
        say("  migrated buckets.csv -> buckets.v1.csv")
    elif BUCKETS_V1.exists():
        say("  buckets.v1.csv already present")
    else:
        say("  no buckets.csv to migrate")

    if BUCKETS_V2.exists():
        with open(BUCKETS_V2, newline="") as f:
            first = f.readline().strip()
        cols = first.split(",") if first else []
        missing = [c for c in SCORE_COLS if c not in cols]
        if missing and cols:
            mb = max(1, BUCKETS_V2.stat().st_size // (1024 * 1024))
            say("  appending %d score/streak cols to buckets.v2.csv "
                "(streaming rewrite, %d MB)" % (len(missing), mb))
            _append_columns(BUCKETS_V2, missing)
            say("  buckets.v2.csv migrated")
        else:
            say("  buckets.v2.csv already has ss_*/bs_*/ns_* columns")

    if SWAPS.exists():
        with open(SWAPS, newline="") as f:
            first = f.readline().strip()
        cols = first.split(",") if first else []
        if "ts_epoch" in cols and "collected_ts" not in cols:
            SWAPS.rename(SWAPS_V1)
            say("  migrated swaps.csv -> swaps.v1.csv (schema v1)")
            cols = []
        missing = [c for c in SWAP_COLS_REQUIRED if c not in cols]
        if missing and SWAPS.exists() and cols:
            _append_columns(SWAPS, missing)
            say("  appended swaps.csv columns: " + ", ".join(missing))
        elif cols and not missing:
            say("  swaps.csv already has all required columns")
    else:
        say("  no swaps.csv yet (will be created)")

    if SRATE.exists():
        try:
            with open(SRATE) as f:
                rows = max(0, sum(1 for _ in f) - 1)
        except OSError:
            rows = 0
        say("  srate.csv present (%d rows)" % rows)
    else:
        say("  srate.csv will be created on first 0.4.53+ vote")


TRACE_CANDIDATES = [
    Path("/sys/kernel/tracing/trace_pipe"),
    Path("/sys/kernel/debug/tracing/trace_pipe"),
]


def find_trace_pipe(try_mount=True):
    for p in TRACE_CANDIDATES:
        if p.exists():
            return p
    if not try_mount:
        return None
    say("  tracefs not mounted - attempting mount")
    subprocess.run(["mount", "-t", "tracefs", "tracefs",
                    "/sys/kernel/tracing"], capture_output=True)
    for p in TRACE_CANDIDATES:
        if p.exists():
            return p
    return None


def bpftune_loaded():
    if not shutil.which("bpftool"):
        return False
    r = subprocess.run(["bpftool", "map", "dump", "name", "remote_host_map"],
                       capture_output=True)
    return r.returncode == 0


def install_trace_unit(trace_pipe):
    tmpl = (SYSD_SRC / "bpftune-met-trace.service.in").read_text()
    unit = (tmpl.replace("@TRACE_PIPE@", str(trace_pipe))
                .replace("@TRACE_LOG@",  str(TRACE_LOG)))
    write_file(TRACE_UNIT, unit, 0o644)
    say("  wrote %s (pipe=%s)" % (TRACE_UNIT, trace_pipe))


def install_http_unit(port):
    tmpl = (SYSD_SRC / "bpftune-dashboard-http.service").read_text()
    unit = tmpl.replace("@PORT@", str(port)).replace("@HIST@", str(HIST))
    write_file(HTTP_UNIT, unit, 0o644)
    say("  wrote %s (port=%d)" % (HTTP_UNIT, port))


def install_logrotate():
    text = (LOGROT_SRC / "bpftune-dashboard").read_text()
    text = (text.replace("@TRACE_LOG@", str(TRACE_LOG))
                .replace("@COLLECTOR_LOG@", str(COLLECTOR_LOG)))
    write_file(LOGROTATE, text, 0o644)
    say("  wrote %s" % LOGROTATE)


def install_cron():
    # 0.4.128: collector cron DISABLED — the bpftune-collector.service
    # daemon handles all collection (full every 5min via main() loop +
    # lightweight every 30s via _lightweight_loop). The per-minute
    # one-shot cron was redundant and fought with the daemon over
    # current.json writes. Keep the renderer cron — the daemon doesn't
    # render data/*.json.
    body = (
        "# managed by bpftune-dashboard/install.py\n"
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
        "SHELL=/bin/sh\n"
        "# DISABLED 0.4.128: daemon handles this now — "
        "* * * * * root %s >> %s 2>&1\n"
        "2-59/5 * * * * root %s >> %s 2>&1\n"
        % (COLLECTOR, COLLECTOR_LOG, RENDERER, COLLECTOR_LOG)
    )
    write_file(CRON, body, 0o644)
    say("  wrote %s" % CRON)


def reload_systemd():
    subprocess.run(["systemctl", "daemon-reload"], check=False)


def _start_unit(name):
    subprocess.run(["systemctl", "enable", "--now", name],
                   capture_output=True)
    r = subprocess.run(["systemctl", "is-active", "--quiet", name])
    if r.returncode == 0:
        say("  %s: active" % name)
    else:
        warn("  %s did not start cleanly" % name)
        warn("  inspect: systemctl status %s" % name)


def selinux_relabel():
    if not Path("/sys/fs/selinux").exists():
        return
    if not shutil.which("restorecon"):
        return
    for p in (CRON, TRACE_UNIT, HTTP_UNIT, LOGROTATE):
        subprocess.run(["restorecon", "-F", str(p)], capture_output=True)
    say("  selinux: relabeled cron + unit + logrotate files")


BIN_FILES = ["bpftune-cli.py", "bpftune-collector.py", "bpftune-render.py",
             "bpftune_log.py", "bpftune_data.py", "streak_writeback.py",
             "labels-api.py", "bpftune_labels_api.py",
             "bpftune-csv-to-sqlite.py"]
ASSET_FILES = ["index.html", "dashboard.js", "dashboard.css"]


def _port_in_use(port):
    """True if something already listens on the port. Used to detect
    nginx (or any other server) owning :8080 so we skip the bundled
    HTTP unit automatically."""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))
        return False
    except OSError:
        return True
    finally:
        try: s.close()
        except OSError: pass


def install_bin():
    INSTALL_BIN.mkdir(parents=True, exist_ok=True)
    for name in BIN_FILES:
        src = BIN_SRC / name
        if not src.exists():
            die("missing source: %s" % src)
        copy_file(src, INSTALL_BIN / name, 0o755)
    for name in ASSET_FILES:
        src = BIN_SRC / name
        if src.exists():
            copy_file(src, INSTALL_BIN / name, 0o644)
    say("  installed %d scripts + %d assets into %s"
        % (len(BIN_FILES), len(ASSET_FILES), INSTALL_BIN))
    # 0.4.91: symlink asset files from HIST so nginx/http.server can
    # serve them.  index.html already had a symlink; dashboard.js and
    # dashboard.css need one too or the browser gets 404 / stale copies.
    HIST.mkdir(parents=True, exist_ok=True)
    for name in ASSET_FILES:
        src = INSTALL_BIN / name
        dst = HIST / name
        if src.exists():
            try:
                if dst.is_symlink() or dst.exists():
                    dst.unlink()
                os.symlink(str(src), str(dst))
            except OSError:
                pass  # maybe no permission, or already correct
    for name in BIN_FILES:
        r = subprocess.run(
            [sys.executable, "-m", "py_compile", str(INSTALL_BIN / name)],
            capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stderr)
            die("py_compile failed on " + name)
    say("  all scripts compile cleanly")


def count_data_rows(path):
    if not path.exists():
        return 0
    with open(path, newline="") as f:
        return max(0, sum(1 for _ in f) - 1)


def run_and_verify():
    before = count_data_rows(BUCKETS_V2)
    r = subprocess.run([sys.executable, str(COLLECTOR)],
                       capture_output=True, text=True)
    print("    collector:", (r.stdout or "").strip() or "(no output)")
    if r.returncode != 0:
        print(r.stderr)
        die("collector exited non-zero")
    if "collector: buckets=0" in (r.stdout or ""):
        warn("collector saw zero buckets - is bpftune loaded?")
    after = count_data_rows(BUCKETS_V2)
    if after == 0:
        die("collector wrote zero rows")
    if after <= before:
        warn("collector added no rows (map unchanged)")
    else:
        say("  buckets.v2.csv now has %d rows" % after)
    if not CURRENT_JSON.exists():
        warn("current.json not written - CLI snapshot failed")
    else:
        say("  current.json: %d bytes" % CURRENT_JSON.stat().st_size)
    r = subprocess.run([sys.executable, str(RENDERER)],
                       capture_output=True, text=True)
    print("    renderer:", (r.stdout or "").strip() or "(no output)")
    if r.returncode != 0:
        print(r.stderr)
        die("renderer exited non-zero")
    for p in (HIST / "index.html", HIST / "data" / "meta.json"):
        if not p.exists():
            die("expected output missing: %s" % p)
    say("  index.html + data/meta.json present")


def dry_run_report(port):
    tp = find_trace_pipe(try_mount=False)
    say("dry-run plan:")
    print("    install dir    %s" % INSTALL_DIR)
    print("    history dir    %s" % HIST)
    print("    trace pipe     %s" % (tp or "<not mounted>"))
    print("    trace log      %s" % TRACE_LOG)
    print("    collector cron every 1m -> %s" % COLLECTOR)
    print("    renderer  cron every 5m -> %s" % RENDERER)
    print("    http unit      %s (port %d)" % (HTTP_UNIT, port))
    print("    logrotate      %s" % LOGROTATE)
    print("    cron file      %s" % CRON)
    print()
    print("    no files will be written.")


def main():
    ap = argparse.ArgumentParser(
        description="Install bpftune-dashboard (idempotent).")
    ap.add_argument("--port", type=int, default=HTTP_PORT_DEFAULT,
                    help="HTTP dashboard port (default %d)" % HTTP_PORT_DEFAULT)
    ap.add_argument("--dry-run", action="store_true",
                    help="print actions and exit")
    ap.add_argument("--no-verify", action="store_true",
                    help="skip running collector/renderer once")
    ap.add_argument("--force", action="store_true",
                    help="install even if bpftune is not loaded")
    ap.add_argument("--no-http", action="store_true",
                    help="skip the bundled HTTP unit (e.g. nginx owns the port)")
    a = ap.parse_args()

    if os.geteuid() != 0:
        die("must run as root")
    if not a.force and not bpftune_loaded():
        die("remote_host_map not present - bpftune not loaded on this host "
            "(use --force to override)")
    if not a.no_http and _port_in_use(a.port):
        say("  port %d already in use - skipping bundled HTTP unit "
            "(nginx / other server owns it)" % a.port)
        a.no_http = True

    if a.dry_run:
        dry_run_report(a.port)
        return 0

    HIST.mkdir(parents=True, exist_ok=True)
    INSTALL_DIR.mkdir(parents=True, exist_ok=True)

    say("stage 1/6: bin/ -> %s" % INSTALL_BIN)
    install_bin()

    say("stage 2/6: migrate history CSVs")
    migrate()

    say("stage 3/6: trace capture")
    tp = find_trace_pipe(try_mount=True)
    if tp:
        install_trace_unit(tp)
    else:
        warn("no trace_pipe on this host; log-driven panels will stay empty")

    say("stage 4/6: cron + logrotate + http units")
    install_cron()
    install_logrotate()
    if a.no_http:
        say("  --no-http: skipping bundled HTTP unit")
    else:
        install_http_unit(a.port)

    say("stage 5/6: reload systemd and start services")
    reload_systemd()
    if tp:
        _start_unit("bpftune-met-trace.service")
    if not a.no_http:
        _start_unit("bpftune-dashboard-http.service")
    selinux_relabel()

    if a.no_verify:
        say("stage 6/6: skipped (--no-verify)")
    else:
        say("stage 6/6: seed + verify")
        run_and_verify()

    print()
    say("done")
    print("    install   %s" % INSTALL_DIR)
    print("    history   %s" % HIST)
    print("    cron      %s" % CRON)
    print("    logrotate %s" % LOGROTATE)
    print("    site      http://<this-host>:%d/" % a.port)
    print()
    print("  tail -f %s" % COLLECTOR_LOG)
    print("  systemctl status bpftune-met-trace bpftune-dashboard-http")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
