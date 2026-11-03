# HANDOFF — full state + exact instructions (READ EVERY WORD)

Date: 2026-11-03. Every SHA below was verified via the GitHub API today.
Do not deviate from this document. Do not "improve" anything not listed.

## 0. HARD RULES (violated repeatedly this week; every failure traced to these)

1. A release MUST have a git tag that resolves to the exact build commit.
   Before publishing: `git tag <ver> <sha> && git push origin <ver>`, then
   verify `git ls-remote --tags origin <ver>` shows it. Releases without a
   resolvable tag are UNTRUSTED (see v0.9.116 and v0.4.107 below).
2. Compile fixes get COMMITTED to the branch BEFORE building. Never build
   with local-only edits — that is why branches and release binaries
   diverged (the v0.9.111-lean4 branch still does not compile because two
   fixes were applied only in a local build tree).
3. Gates before publishing (both must pass on the EXACT commit being built):
   - tuner: `cd src && make -j"$(nproc)"` then
     `sudo bpftool prog load src/tcp_conn_tuner.bpf.o /sys/fs/bpf/t`
     MUST print nothing (any verifier output = do not publish). Then
     `sudo rm -f /sys/fs/bpf/t`.
   - collector: `cd dashboard/bin/go && go build ./... && go vet ./... && go test ./...`
     all green.
4. Release notes must cite the commit SHA. Expect them to be audited.
5. NEVER touch tuning semantics: metric calc, swap engine, RL scoring,
   reanchor rules, win/null/loss logic. Everything we ship is logging,
   structure, and robustness only.

## 1. TUNER (src/, include/) — primary task

**Source of truth: branch `v0.4.107-lean`, tip `b1945b0bf9bf5ef6e22e4d2112b308ad9f22f219`.**

Content: v0.4.106 (`eb4d8ba`) semantics, unchanged, PLUS this session's
work in 5 commits:
- `4b343fe` — T1: feed/diagnostics log split (feed lines estab/met/srate/
  midsamp/swap/proof + action records unconditional; cwnd/swapctx/
  swapscore/closport/heal_* gated by bpftune_debug, default 0); T6 config
  read moved past early-exit gates; T7 cookie hoisted; T8 srate dedup
- `1bd3909` — T2: reanchor per-bucket journal line -> DEBUG, one aggregate
  line/cycle; bpf-debug default 0 in pin_explore_map; T3: ENOBUFS path
  now sampled (udp_buffer_tuner.bpf.c); T3b: UDP log line -> DEBUG
- `ed9c5e1` — T4: tcp_sndbuf_expand now sampled + registered;
  T9: ringbuf poll 100ms -> 1000ms (bpftune.c)
- `306194e` — T10: bpftune_sample adaptive-rate clamp at 256x (storm-proof)
- `b1945b0` — VERIFIER FIX: the 16-iter ESTABLISHED rescan replaced by
  tracker reads (kills the E2BIG 'Processed 1000001 insn' rejection)

**STATE PROBLEM**: release `v0.4.107` exists with
`bpftune_0.4.107_amd64.deb` but there is NO `v0.4.107` git tag —
provenance unverifiable (get_commit and ref lookup both fail). It was
installed on hosts by update.sh. Host symptoms after install (CPU burn,
dead/frozen dashboard) match a broken (pre-verifier-fix) build in a
restart loop. TREAT THIS BINARY AS UNKNOWN.

### TASK 1A — decision (operator picks one):
- OPTION "108" (recommended): rebuild from b1945b0, get this session's
  fixes, publish v0.4.108. Steps below.
- OPTION "106" (trusted rollback): delete the v0.4.107 release + reinstall
  the v0.4.106 .deb on any host that got 0.4.107. v0.4.106 is verified
  (tag -> eb4d8ba) and fleet-proven, but lacks this session's work.

### TASK 1B — build v0.4.108 (if OPTION 108):
1. `git fetch origin v0.4.107-lean && git checkout -B build b1945b0bf9bf5ef6e22e4d2112b308ad9f22f219`
2. `git rev-parse HEAD` must print exactly `b1945b0bf9bf5ef6e22e4d2112b308ad9f22f219`.
3. Bump the package version to **0.4.108** in the .deb packaging
   (debian/changelog or equivalent) — REQUIRED so update.sh's
   highest-version picker prefers it over the installed 0.4.107.
   The artifact name must be `bpftune_0.4.108_amd64.deb`
   (update.sh matches `^bpftune_([0-9.]+)_amd64\.deb$`).
4. Build the .deb with the same packaging flow used for 0.4.106/0.4.107.
5. GATE (before publishing — non-negotiable):
   `cd src && make -j"$(nproc)" && sudo bpftool prog load src/tcp_conn_tuner.bpf.o /sys/fs/bpf/t`
   -> must print NOTHING. Any output = stop, report, do not publish.
6. Publish WITH THE TAG:
   `git tag v0.4.108 b1945b0bf9bf5ef6e22e4d2112b308ad9f22f219 && git push origin v0.4.108`
   `gh release create v0.4.108 bpftune_0.4.108_amd64.deb -t "v0.4.108 — verified rebuild of b1945b0" -n "Built from tag v0.4.108 -> commit b1945b0. Gate: bpftool prog load silent. v0.4.106 semantics preserved; adds T1-T10 + verifier fix."`
7. Verify: `git ls-remote --tags origin v0.4.108` returns the tag.
8. Neutralize the unknown artifact: `gh release delete v0.4.107 --yes`
   (or `gh release edit v0.4.107 --draft`). It must NOT stay installable.

### TASK 1C — deploy + verify on ONE host (al) before fleet:
```
curl -fsSL https://raw.githubusercontent.com/cddeppe/bpftune-swap/main/update.sh | sudo bash
journalctl -u bpftune --since '-5 min' | grep -cE 'too large|failed to load|verifier'   # must print 0
bpftool prog show | grep -c bpftune                                                      # >= 2
```
Then confirm dashboard swaps/proofs flow within minutes and CPU is quiet.
Fleet rollout only after this passes.

## 2. COLLECTOR (dashboard/bin/go/) — v0.9.x

**Operator decision (do NOT re-apply):** the v0.9.117 "always merge fresh"
frozen-leaderboard fix is REVERTED. v0.9.115 behavior (with its known
stale-merge tradeoff) is accepted. Do not reintroduce it.

**Branch `v0.9.111-lean4`, tip `58ed62ce07de8f8b1390f225906612c1d418d170`**
= v0.9.115 behavior (all rounds 1–6 of the optimization work) with the
fix reverted. Known-good binary: the `v0.9.115` release asset (ab8e8db).

**THE BRANCH DOES NOT COMPILE — two fixes were made only in a local build
tree and never committed. COMMIT THESE FIRST (they are the exact fixes
that produced the working v0.9.117 binary):**
1. `dashboard/bin/go/streak_writeback.go` (getMapFD):
   `fd, err := bpfMapGetFDByID(uint32(mapID))`
   -> `fd, _, err := bpfMapGetFDByIDVerified(uint32(mapID), "")`
   (bpf_syscall.go no longer exports bpfMapGetFDByID)
2. `dashboard/bin/go/sqlite.go` (~line 380):
   `buf = fmt.Fprintf(h, ...)` -> `fmt.Fprintf(h, ...)`
   (fmt.Fprintf returns (int, error); cannot assign to one var)

### TASK 2A — build + publish v0.9.118:
1. Commit the two fixes above on `v0.9.111-lean4` (small, focused commits).
2. `cd dashboard/bin/go && go build ./... && go vet ./... && go test ./...` — green.
3. `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-X main.dashVersionStr=0.9.118" -o bpftune-dashboard-amd64 .`
4. Tag from the build commit, then release:
   `git tag v0.9.118 <build commit sha> && git push origin v0.9.118`
   `gh release create v0.9.118 bpftune-dashboard-amd64 -t "v0.9.118 — v0.9.115 behavior, buildable" -n "Built from tag v0.9.118 -> <sha>. Compile fixes committed. Contains ALL optimization work (v0.9.108–115); the v0.9.117 cache change is NOT included (reverted by operator decision)."`
5. Verify `git ls-remote --tags origin v0.9.118`.
6. Neutralize traps (update.sh installs the HIGHEST version, so these two
   keep getting installed unless removed):
   - `v0.9.117` (contains the REVERTED fix) -> delete or draft AFTER 118 is up
   - `v0.9.116` (claimed fix never existed in its source) -> delete or draft

## 3. FRONTEND (dashboard/bin/dashboard.js, index.html, *.css, chart*.js)

NEVER modified by us. NO changes wanted. update.sh copies frontend from
the git checkout; since main@f0af024 the source-build fallback checks out
the release TAG first, so frontend stays consistent with the release.
Do not "fix" or "improve" dashboard.js.

## 4. DEPLOYMENT SCRIPTS (install.sh, update.sh on `main`)

main tip = `f0af0247f23d19fdf12359deabdbd1501311508b` (update.sh source
fallback now builds the release's source: fetch+checkout the resolved
tag; version string derived from tag). Already live (hosts curl main).
Do NOT change the version-picking logic — it picks the highest .deb /
release tag on purpose; the version numbers above depend on it.

## 5. FINAL VERIFICATION MATRIX (after everything ships)

```
# tuner
dpkg-query -W -f='${Version}\n' bpftune           # 0.4.108
journalctl -u bpftune --since '-10 min' | grep -cE 'too large|failed to load'   # 0
bpftool prog show | grep -c bpftune                # >= 2

# collector
systemctl is-active bpftune-collector-go          # active
curl -s http://localhost:8080/current.json | python3 -c "import json,sys; d=json.load(sys.stdin); b=d.get('metric_by_bucket') or {}; print(len(b), 'buckets')"   # 8+
ps -o pid,etime,time,%cpu,rss -p $(pidof bpftune-collector-go)   # CPU < 2% steady, RSS sane

# dashboard
# swaps/proofs panels live; leaderboard present (known stale-merge
# tradeoff accepted — do NOT "fix" it again)

# updater idempotent
curl -fsSL https://raw.githubusercontent.com/cddeppe/bpftune-swap/main/update.sh | sudo bash   # "already at latest"
```

## 6. DO-NOT-TOUCH list

- Tuning semantics anywhere (metric calc, swap engine, scores, streaks,
  reanchor rules, truth corrections)
- Watchdog constants (tests assert them)
- dashboard.js / index.html / css
- update.sh version-picking logic
- The v0.9.117 cache behavior (operator explicitly rejected it)

## 7. Verified facts (for auditing)

- `v0.4.106` tag -> `eb4d8ba5a80a0f5e400690e6c9c3349ec0dce77e` (inspectable)
- `v0.4.107-lean` tip -> `b1945b0bf9bf5ef6e22e4d2112b308ad9f22f219` (our chain, fingerprinted)
- `v0.4.107` tag: DOES NOT EXIST (release orphaned -> untrusted)
- `v0.9.116` tag -> `ab8e8db...` but its claimed fix is absent from source
- `v0.9.111-lean4` tip -> `58ed62ce07de8f8b1390f225906612c1d418d170`
- `main` tip -> `f0af0247f23d19fdf12359deabdbd1501311508b`
