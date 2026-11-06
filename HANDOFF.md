# HANDOFF — full state + exact instructions (READ EVERY WORD)

Date: 2026-11-06 (updated). Every SHA below was verified via the GitHub API.
Do not deviate from this document. Do not "improve" anything not listed.

## 0. HARD RULES (violated repeatedly; every failure traced to these)

1. A release MUST have a git tag that resolves to the exact build commit.
   Before publishing: `git tag <ver> <sha> && git push origin <ver>`, then
   verify `git ls-remote --tags origin <ver>` shows it. Releases without a
   resolvable tag are UNTRUSTED (v0.9.116, v0.4.107).
2. Compile fixes get COMMITTED to the branch BEFORE building. Never build
   with local-only edits — that is why branches and release binaries
   diverged.
3. Gates before publishing (on the EXACT commit being built):
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

## 1. TUNER (src/, include/) — REOPENED 2026-11-06 (corpse-map fix, base 0.4.106)

**OPERATOR DECISION (2026-11-06): the tuner fix is cut from v0.4.106
EXACTLY — NOT from 0.4.107.** 0.4.107 is a mystery (release exists, NO
tag, provenance unverifiable, never shipped to the fleet); all hosts run
0.4.106. The former source of truth `v0.4.107-lean` tip `b1945b0` is
SUPERSEDED — do not build that lineage.

**Source of truth: branch `v0.4.108-corpse-fix`, tip
`735026d7487acdcc61e942b466483367aeb946c1`** (parent: tag `v0.4.106` →
`eb4d8ba5a80a0f5e400690e6c9c3349ec0dce77e`). Content: v0.4.106 semantics
unchanged PLUS the corpse-map leak fix (four leaks closed: basename-
matched inotify IN_DELETE fini; duplicate-tuner fini before append;
multi-detach sweep for ALLOW_MULTI zombies; reanchor retarget on
re-init) + an init-time `N leftover remote_host_map generation(s)`
diagnostic. No `.bpf.c` file is touched (rule 5 holds). Full notes in the
release body and in `release-notes-tuner-v0.4.108.md` on the branch.

### TASK 1B — build + publish v0.4.108 (CURRENT, atomic — GitHub only)

Everything ships from GitHub: the branch is pushed, and this `main`
carries the builder script `build-tuner-v0.4.108.sh`. On EACH arch
builder (amd64 first — creates the release; arm64 second — adds its
deb):

    git clone https://github.com/cddeppe/bpftune-swap.git && cd bpftune-swap
    read -rs GH_TOKEN && export GH_TOKEN   # paste your PAT (Enter); stays out of shell history
    bash build-tuner-v0.4.108.sh

NO gh CLI needed (the repo is public — clone is anonymous; only the tag
push + release creation use the token, via curl). Works as root (no
sudo needed) and on non-root. If the gh CLI IS present and authed, the
script picks up its token automatically instead.

(or `bash build-tuner-v0.4.108.sh --no-publish` for a build + verifier
gate dry run that pushes nothing). The script enforces §0 end-to-end:
fresh clone of the PINNED tip `735026d` (aborts if the branch moved or
the parent is not v0.4.106), aborts if any `.bpf.c` changed, installs
Build-Depends (explicit list — stock VPS images lack deb-src entries),
Build-Depends, builds, runs the silent `bpftool prog load` gate,
builds `bpftune_0.4.108_<arch>.deb`, pushes tag `v0.4.108` → `735026d`
and verifies it on the remote BEFORE creating the release (with
SHA-citing notes, `--latest=false` so releases/latest stays on the
collector), then neutralizes the orphaned v0.4.107 if it ever exists.

Post-deploy check per host: `journalctl -u bpftune | grep "leftover
remote_host_map"` — no line = clean; `N > 0` = holders survived that
restart, send the line back.

### TASK 1A — SUPERSEDED 2026-11-06 (kept for the record; 107 lineage)

History: `v0.4.107-lean` (5 commits on top of v0.4.106 semantics —
`4b343fe` T1 log split, `1bd3909` T2 reanchor journal to DEBUG,
`ed9c5e1` T4 sndbuf sampling + ringbuf poll 1000ms, `306194e` T10
sampler clamp, `b1945b0` verifier E2BIG fix) was the 2026-11-03 source
of truth. The 2026-11-03 operator decision ("tuner will NOT be
rebuilt") was superseded on 2026-11-06: the tuner fix was REOPENED and
re-cut from v0.4.106 exactly (TASK 1B above), because the orphaned
release `v0.4.107` has NO git tag (provenance unverifiable — a mystery)
and was never the deployed base. The old TASK 1A steps (build v0.4.108
from `b1945b0`: checkout, bump changelog, build .deb, silent
`bpftool prog load` gate, tag+push, `gh release create`, verify
`ls-remote --tags`, delete the orphaned v0.4.107 release) are retained
in git history (HANDOFF.md at `main` before commit `e2da390`).

## 2. COLLECTOR (dashboard/bin/go/) — v0.9.x — ACTIVE TASK

**Operator decision (do NOT re-apply):** the v0.9.117 "always merge fresh"
frozen-leaderboard fix is REVERTED (commit 4f58a68). v0.9.115 behavior
(with its known stale-merge tradeoff) is accepted. Do not reintroduce it.

**COMPILE STATUS: FIXED (2026-11-03).** The two fixes that previously
existed only in a local build tree are now COMMITTED to the branch:
- `a5f2fb6` — sqlite.go snapshotPreHash: `buf = fmt.Fprintf(...)` assigned
  (int, error) to one var; now a plain statement (hash semantics unchanged)
- `6a64e40` — streak_writeback.go getMapFD: bpfMapGetFDByID (removed in the
  v0.9.114 bpf_syscall rewrite) -> bpfMapGetFDByIDVerified(mapID, "")
The branch builds from a clean checkout. Start at TASK 2A step 2.

**Branch `v0.9.111-lean4`, tip `6a64e40fff021e2c8f548a53a9a7178cbd8e84e3`**
= v0.9.115 behavior (all optimization work, rounds 1–6) + compile fixes.
Known-good deployed binary: the `v0.9.115` release asset.

### TASK 2A — build + publish v0.9.118:
1. (DONE — see compile status above.)
2. `cd dashboard/bin/go && go build ./... && go vet ./... && go test ./...` — green.
3. `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-X main.dashVersionStr=0.9.118" -o bpftune-dashboard-amd64 .`
4. Tag from the build commit, then release:
   `git tag v0.9.118 <build commit sha> && git push origin v0.9.118`
   `gh release create v0.9.118 bpftune-dashboard-amd64 -t "v0.9.118 — v0.9.115 behavior, buildable" -n "Built from tag v0.9.118 -> <sha>. Contains ALL optimization work (v0.9.108–115); the v0.9.117 cache change is NOT included (reverted by operator decision)."`
5. Verify `git ls-remote --tags origin v0.9.118`.
6. Neutralize traps (update.sh installs the HIGHEST version — these keep
   getting installed unless removed):
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
- `v0.9.111-lean4` tip -> `6a64e40fff021e2c8f548a53a9a7178cbd8e84e3` (buildable)
- `main` tip -> `f0af0247f23d19fdf12359deabdbd1501311508b`
