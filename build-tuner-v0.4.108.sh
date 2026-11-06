#!/bin/bash
# build-tuner-v0.4.108.sh — ATOMIC builder for bpftune 0.4.108 (corpse-map leak fix)
#
# One command on a builder. Follows HANDOFF.md (§0 hard rules + tuner task),
# with the operator decision (2026-11-06): the fix bases off v0.4.106 EXACTLY —
# NOT the unreleased, untagged 0.4.107 (mystery provenance):
#
#   source of truth : branch v0.4.108-corpse-fix = 735026d7487acdcc61e942b466483367aeb946c1
#   parent          : tag v0.4.106              = eb4d8ba5a80a0f5e400690e6c9c3349ec0dce77e
#   artifact        : bpftune_0.4.108_<arch>.deb
#
# Run on EACH arch builder (amd64 first — it creates the release;
# arm64 second — it only adds its .deb). Idempotent; safe to rerun.
#
#   bash build-tuner-v0.4.108.sh               # build → gate → tag → release
#   bash build-tuner-v0.4.108.sh --no-publish  # build + verifier gate only
#
# NO gh CLI needed. The repo is public (clone/push-verify is anonymous);
# only the tag push + release creation need a GitHub token. Provide one of:
#   export GH_TOKEN=<your PAT>            # e.g. via:  read -rs GH_TOKEN
#   gh auth login                         # if the gh CLI happens to exist
#
# Hard rules enforced (HANDOFF §0):
#   R1 the release tag resolves to the EXACT build commit — verified on the
#      remote BEFORE the release is created
#   R2 fresh clone of the pinned branch tip — no local-only edits can enter
#      the build, and the build aborts if the branch has moved
#   R3 the bpftool verifier gate must be SILENT or NOTHING is published
#   R4 release notes cite the commit SHA
#   R5 tuning semantics untouched — aborts if any .bpf.c file changed
set -euo pipefail

REPO='cddeppe/bpftune-swap'
REPO_URL="https://github.com/${REPO}.git"
COMMIT='735026d7487acdcc61e942b466483367aeb946c1'   # v0.4.108-corpse-fix tip
BASE='eb4d8ba5a80a0f5e400690e6c9c3349ec0dce77e'     # tag v0.4.106
BRANCH='v0.4.108-corpse-fix'
TAG='v0.4.108'
VER='0.4.108'
WORK="bpftune-${VER}-build"
TITLE='v0.4.108 — stop the corpse-map leak (base 0.4.106 exactly, no 0.4.107 content)'

say() { printf '\n== %s ==\n' "$*"; }
die() { printf 'FATAL: %s\n' "$*" >&2; exit 1; }

PUBLISH=1
[ "${1:-}" = "--no-publish" ] && PUBLISH=0

# ---------- 0. preflight ----------
say "0. preflight"
for tool in git curl python3 dpkg-buildpackage sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || die "missing tool: $tool — install it and rerun"
done
# root needs no sudo; non-root needs sudo
if [ "$(id -u)" = 0 ]; then
    sudo() { "$@"; }
    echo "   running as root — sudo bypassed"
else
    command -v sudo >/dev/null 2>&1 || die "missing sudo (run as root, or install sudo)"
fi
# resolve a token for the publish steps (gh CLI optional, GH_TOKEN preferred)
API_TOKEN=""
if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    API_TOKEN="$(gh auth token)"
    echo "   gh CLI authenticated — using its token"
elif [ -n "${GH_TOKEN:-}" ]; then
    API_TOKEN="$GH_TOKEN"
    echo "   using \$GH_TOKEN from the environment"
else
    [ "$PUBLISH" = 1 ] && die "publishing needs a GitHub token:  read -rs GH_TOKEN; export GH_TOKEN  (paste your PAT; or install+auth the gh CLI)  — or rerun with --no-publish"
    echo "   no token (fine for --no-publish)"
fi
# git wrapper: wires the token into push/ls-remote when we have one
CRED_HELPER='!f() { echo username=x-access-token; echo password=$GH_TOKEN; }; f'
if [ -n "$API_TOKEN" ]; then
    export GH_TOKEN="$API_TOKEN"
    git_auth() { git -c "credential.helper=$CRED_HELPER" "$@"; }
else
    git_auth() { git "$@"; }   # public repo: reads work anonymously; push prompts
fi
echo "   tools ok (publish=$PUBLISH)"

# ---------- 1. exact-commit checkout ----------
say "1. exact-commit checkout (fresh clone of the pinned branch tip)"
rm -rf "$WORK"
git clone -q "$REPO_URL" "$WORK" || die "clone failed — check network access to github.com"
cd "$WORK"
git fetch -q origin "refs/heads/${BRANCH}:refs/remotes/origin/${BRANCH}"
BRANCH_SHA="$(git rev-parse "refs/remotes/origin/${BRANCH}")"
[ "$BRANCH_SHA" = "$COMMIT" ] || \
    die "origin/${BRANCH} = ${BRANCH_SHA:0:12}, expected ${COMMIT:0:12} — the branch moved; do NOT build a moving target (re-pin or revert it first)"
git checkout -q -B build "$COMMIT"
[ "$(git rev-parse HEAD)"  = "$COMMIT" ] || die "HEAD is not $COMMIT"
[ "$(git rev-parse HEAD^)" = "$BASE"   ] || die "parent is NOT v0.4.106 — refusing to build"
[ -z "$(git status --porcelain)" ]     || die "working tree not clean"
echo "   HEAD = ${COMMIT:0:12}  (parent = v0.4.106 ${BASE:0:12})  tree clean"

# ---------- 2. semantics guard ----------
say "2. semantics guard — no .bpf.c may change, changelog must be ${VER}"
CHANGED="$(git diff --name-only "$BASE" HEAD)"
echo "   changed vs v0.4.106:"; printf '     %s\n' $CHANGED
if printf '%s\n' $CHANGED | grep -qE '\.bpf\.c$'; then
    die "a .bpf.c file was modified — tuning semantics guard tripped, aborting"
fi
grep -q "^bpftune (${VER})" debian/changelog || die "debian/changelog is not bumped to ${VER}"

# ---------- 3. build dependencies ----------
say "3. build dependencies (debian/control: clang, llvm, bpftool, libbpf-dev, …)"
if dpkg-checkbuilddeps >/dev/null 2>&1; then
    echo "   all Build-Depends satisfied"
else
    echo "   missing Build-Depends — installing (explicit list; apt-get build-dep"
    echo "   needs deb-src entries that stock VPS images often lack)"
    sudo apt-get update -qq || true
    if ! sudo apt-get install -y build-essential fakeroot debhelper python3-docutils \
            libbpf-dev libcap-dev clang llvm bpftool libnl-3-dev libnl-route-3-dev iperf3; then
        dpkg-checkbuilddeps || true
        die "apt install of Build-Depends failed — install the packages listed above, then rerun"
    fi
fi
for tool in clang bpftool; do
    command -v "$tool" >/dev/null 2>&1 \
        || die "$tool still missing after build-dep — install it manually and rerun"
done
echo "   clang + bpftool present"

# ---------- 4. build ----------
say "4. build (cd src && make -j)"
( cd src && make -j"$(nproc)" )
[ -f src/tcp_conn_tuner.bpf.o ] || die "src/tcp_conn_tuner.bpf.o was not produced"

# ---------- 5. verifier gate ----------
say "5. verifier gate — bpftool prog load MUST print NOTHING"
GATE_OUT="$(sudo bpftool prog load src/tcp_conn_tuner.bpf.o /sys/fs/bpf/t 2>&1 || true)"
sudo rm -f /sys/fs/bpf/t
[ -z "$GATE_OUT" ] || { printf 'GATE FAILED — verifier output:\n%s\n' "$GATE_OUT" >&2; exit 1; }
echo "   gate passed (silent)"

# ---------- 6. .deb ----------
say "6. build the .deb (same packaging flow as 0.4.106)"
ARCH="$(dpkg --print-architecture)"
dpkg-buildpackage -us -uc -b
DEB="$(readlink -f "../bpftune_${VER}_${ARCH}.deb")"
[ -f "$DEB" ] || { echo "expected bpftune_${VER}_${ARCH}.deb not produced; found:"; ls -1 ../*.deb 2>/dev/null || true; exit 1; }
[ "$(dpkg-deb -f "$DEB" Version)" = "$VER" ] || die "deb Version is '$(dpkg-deb -f "$DEB" Version)', expected $VER"
echo "   built: $DEB  (Version: $VER)"

if [ "$PUBLISH" = 0 ]; then
    say "DONE (--no-publish)"
    echo "   .deb:   $DEB"
    sha256sum "$DEB"
    echo "   gate passed; nothing was pushed or published"
    exit 0
fi

# ---------- API helpers (curl; no gh CLI required, no cross-subshell state) ----------
github_api() { # METHOD URL [json-file] -> prints body, LAST line is the HTTP status
    local method="$1" url="$2" payload="${3:-}"
    local args=(-s --max-time 120 -w '\n%{http_code}' -X "$method"
                -H "Authorization: Bearer ${API_TOKEN}"
                -H "Accept: application/vnd.github+json"
                -H "X-GitHub-Api-Version: 2022-11-28")
    if [ -n "$payload" ]; then
        args+=(-H 'Content-Type: application/json' --data-binary "@$payload")
    fi
    curl "${args[@]}" "$url" || echo ''$'\n''000'
}
api_status() { printf '%s' "${1##*$'\n'}"; }            # last line of github_api output
api_body()   { printf '%s' "${1%$'\n'*}"; }              # everything but the last line
release_id_for_tag() { # prints the release id for a tag, or nothing
    local out; out="$(github_api GET "https://api.github.com/repos/${REPO}/releases/tags/$1")"
    [ "$(api_status "$out")" = 200 ] || return 0
    api_body "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' 2>/dev/null || true
}
upload_asset() { # RELEASE_ID FILE -> 0 on success; sets UPLOAD_HTTP
    local name; name="$(basename "$2")"
    local code
    code="$(curl -s --max-time 600 -o /dev/null -w '%{http_code}' -X POST \
        -H "Authorization: Bearer ${API_TOKEN}" \
        -H "Content-Type: application/octet-stream" \
        --data-binary "@$2" \
        "https://uploads.github.com/repos/${REPO}/releases/$1/assets?name=${name}")"
    UPLOAD_HTTP="$code"
    [ "$code" = 201 ] || [ "$code" = 200 ]
}

# ---------- 7. tag the exact build commit ----------
say "7. tag ${TAG} -> ${COMMIT:0:12} and push"
if git rev-parse -q --verify "refs/tags/${TAG}" >/dev/null; then
    [ "$(git rev-parse "${TAG}^{}" 2>/dev/null || git rev-parse "$TAG")" = "$COMMIT" ] \
        || die "local tag ${TAG} does not point at ${COMMIT:0:12}"
    echo "   local tag already correct"
else
    git tag "$TAG" "$COMMIT"
    echo "   tagged"
fi
git_auth push origin "refs/tags/${TAG}"   # no-op on the second arch builder
sleep 2
REMOTE_TAGS="$(git_auth ls-remote --tags origin "refs/tags/${TAG}")"
PEELED="$(printf '%s\n' "$REMOTE_TAGS" | awk -v t="refs/tags/${TAG}^{}" '$2==t {print $1}')"
DIRECT="$(printf '%s\n' "$REMOTE_TAGS" | awk -v t="refs/tags/${TAG}" '$2==t {print $1}')"
[ "${PEELED:-${DIRECT:-}}" = "$COMMIT" ] \
    || die "remote tag ${TAG} does not resolve to ${COMMIT:0:12} — NOT publishing"
echo "   verified on remote: refs/tags/${TAG} -> ${COMMIT:0:12}"

# ---------- 8. release ----------
say "8. GitHub release (make_latest=false — /releases/latest stays on the collector)"
BODY="$(mktemp)"
cat >"$BODY" <<'NOTES'
# bpftune (tuner) v0.4.108 — stop the corpse-map leak

**Built from tag `v0.4.108` → commit `735026d7487acdcc61e942b466483367aeb946c1`** (parent: tag `v0.4.106` → `eb4d8ba5a80a0f5e400690e6c9c3349ec0dce77e`). Gate on the exact build commit: `bpftool prog load src/tcp_conn_tuner.bpf.o` silent. Branch: `v0.4.108-corpse-fix`.

**Base: v0.4.106 exactly** — the version deployed on all hosts. The unreleased 0.4.107 (tail-call split of `bpftune_conn_tuner`) is deliberately **not** included: the branch is cut from the `v0.4.106` tag, so the .deb delta is exactly these fixes. **No BPF-side (`.bpf.c`) file is touched** — logging, structure and robustness only.

## Why

`remote_host_map` generations accumulate on hosts (16+ observed). The collector has merged them all since v0.9.128 ("corpse" maps: frozen values, still referenced, nothing writing them), and a daemon restart does not reliably clear them. This release closes every path in the 0.4.106 source that creates them under a running daemon, and makes the leftover situation observable at every start.

## The four leaks (all in the 0.4.106 source)

1. **inotify IN_DELETE never matched a tuner** (`src/bpftune.c`): `strstr(event->name, tuner->name)` compared the bare file name (`libtcp_conn_tuner.so`) against the tuner's full path — always longer, never a substring, so *never* a match. A removed `.so` left its tuner registered forever: skeleton fds open (map generations alive), sockops programs still attached.
2. **inotify IN_CREATE appended a duplicate tuner** (`src/libbpftune.c`): re-creating the same `.so` under a running daemon `dlopen`ed and appended a *second* tuner without fini'ing the first. The old object leaked: old map generation alive on the old skeleton's fds, old sockops progs attached, old reanchor worker stuck on the old fd (stale `rate_best_*` swap targets — the collector has patched around this since v0.9.129).
3. **the startup sweep detached once, but ALLOW_MULTI can attach many** (`src/libbpftune.c`): `bpf_prog_detach2` removes ONE attachment per call; the 0.4.79 restart race could double-attach. A zombie attached program **pins its maps** — the mechanism behind generations that survive even a killed daemon.
4. **`start_reanchor` refused to retarget** (`src/tcp_conn_tuner.c`): `if (reanchor_started) return;` kept the reanchor worker on the PREVIOUS map fd across any re-init without fini.

## The fixes

- `bpftune.c` — IN_DELETE matches on the **basename** of `tuner->name`.
- `libbpftune.c` — `__bpftuner_init` finis (detach + save state + destroy skeleton) any ACTIVE same-name tuner **before** the new `init()`; no duplicate is ever appended, and the new restore reads the freshest saved state.
- `libbpftune.c` — the old-attachment sweep loops `bpf_prog_detach2` until it fails (max 8) and logs the count at LOG_NOTICE.
- `tcp_conn_tuner.c` — `start_reanchor` retargets (stop + restart on the new fd) instead of returning.
- **Diagnostics**: `init()` logs `init: N leftover remote_host_map generation(s) after old-attachment sweep` (only when N > 0) before creating our own map. One restart per host now **proves** whether the sweep works and names the hosts where it doesn't.

## Deploy

`update.sh` picks this up automatically (highest `bpftune_*_<arch>.deb` version). After install + `systemctl restart bpftune`, check:

    journalctl -u bpftune | grep "leftover remote_host_map"

- no line → clean; generations stop accumulating from this restart on.
- `N > 0` → zombie holders survived this restart — send that journal line back; it names the exact situation to hunt next.

Independent of collector v0.9.133 (flat regardless of N); ship in either order.

## Files changed (vs v0.4.106)

- `src/bpftune.c` — basename-matched IN_DELETE fini
- `src/libbpftune.c` — duplicate-tuner fini + multi-detach sweep
- `src/tcp_conn_tuner.c` — reanchor retarget + leftover-count log
- `debian/changelog` — 0.4.108 entry
- `HANDOFF.md` — session note (2026-11-06)
NOTES

REL_ID="$(release_id_for_tag "$TAG")"
if [ -n "$REL_ID" ]; then
    echo "   release ${TAG} already exists (id ${REL_ID}) — uploading the ${ARCH} .deb only"
else
    echo "   creating release ${TAG}…"
    PAYLOAD="$(mktemp)"
    TAG_ARG="$TAG" COMMIT_ARG="$COMMIT" TITLE_ARG="$TITLE" BODY_ARG="$BODY" \
    python3 - > "$PAYLOAD" <<'PY'
import json, os
print(json.dumps({
    'tag_name': os.environ['TAG_ARG'],
    'target_commitish': os.environ['COMMIT_ARG'],
    'name': os.environ['TITLE_ARG'],
    'body': open(os.environ['BODY_ARG']).read(),
    'draft': False, 'prerelease': False, 'make_latest': 'false',
}))
PY
    api_code_out="$(github_api POST "https://api.github.com/repos/${REPO}/releases" "$PAYLOAD")"
    if [ "$(api_status "$api_code_out")" != 201 ]; then
        printf 'release create failed: HTTP %s\n%s\n' "$(api_status "$api_code_out")" "$(api_body "$api_code_out")" >&2
        exit 1
    fi
    REL_ID="$(release_id_for_tag "$TAG")"
    [ -n "$REL_ID" ] || die "release created but id lookup failed — check ${REPO} releases and rerun (idempotent)"
    echo "   release created (id ${REL_ID})"
fi
# idempotent asset upload: drop same-named asset first, then upload
asset_list_out="$(github_api GET "https://api.github.com/repos/${REPO}/releases/${REL_ID}/assets")"
[ "$(api_status "$asset_list_out")" = 200 ] || die "asset list fetch failed (HTTP $(api_status "$asset_list_out"))"
api_body "$asset_list_out" \
    | python3 -c '
import json, sys
for a in json.load(sys.stdin):
    print(a["id"], a["name"])
' | while read -r aid aname; do
    [ "$aname" = "$(basename "$DEB")" ] || continue
    del_out="$(github_api DELETE "https://api.github.com/repos/${REPO}/releases/assets/${aid}")"
    [ "$(api_status "$del_out")" = 204 ] || die "asset delete failed for $aname (HTTP $(api_status "$del_out"))"
    echo "   replaced existing asset: $aname"
done
upload_asset "$REL_ID" "$DEB" || die "asset upload failed (HTTP ${UPLOAD_HTTP:-?})"
echo "   uploaded: $(basename "$DEB")"

# ---------- 9. neutralize the orphaned v0.4.107, if it ever exists ----------
say "9. neutralize the orphaned v0.4.107 artifact (if any)"
ORPHAN_ID="$(release_id_for_tag v0.4.107)"
if [ -n "$ORPHAN_ID" ]; then
    del_out="$(github_api DELETE "https://api.github.com/repos/${REPO}/releases/${ORPHAN_ID}")"
    [ "$(api_status "$del_out")" = 204 ] || die "failed to delete v0.4.107 (HTTP $(api_status "$del_out"))"
    echo "   deleted release v0.4.107 (no tag ever existed — untrusted)"
else
    echo "   no v0.4.107 release exists — nothing to neutralize"
fi

# ---------- 10. final verification ----------
say "10. final verification"
echo "   remote tag:"
git_auth ls-remote --tags origin "refs/tags/${TAG}"
echo "   release assets:"
rel_view="$(github_api GET "https://api.github.com/repos/${REPO}/releases/tags/${TAG}")"
[ "$(api_status "$rel_view")" = 200 ] || die "release verify fetch failed (HTTP $(api_status "$rel_view"))"
api_body "$rel_view" \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); print("   ", d["html_url"]); [print("    -", a["name"]) for a in d["assets"]]'
echo "   checksum:"
sha256sum "$DEB"
echo
echo "DONE — bpftune ${VER} (${ARCH}) built, gated, tagged, released"
