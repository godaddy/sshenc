#!/usr/bin/env bash
# Test-Sshenc-MacOS.sh
#
# macOS-side test harness for sshenc + gitenc. Designed to run both
# locally (Apple Silicon with Secure Enclave + Touch ID enrolled) and
# in CI on `macos-latest` (SE present but no biometric/passcode
# enrolled, so the SE path can't actually prompt).
#
# Safety contract:
#   * Test keys are created in an isolated keys directory under
#     $TMPDIR/sshenc-test-XXXXXX/keys (via SSHENC_KEYS_DIR), never in
#     the user's ~/.sshenc/keys/.
#   * Cleanup is snapshot+diff: the script lists keys at start, lists
#     again at end, and only deletes labels that are new in this run.
#     A pre-existing key visible to the agent will NEVER be deleted
#     by this script, even if the script crashes mid-run.
#   * The agent is started on a per-test Unix socket under $TMPDIR,
#     not the user's standard ~/.sshenc/agent.sock, so the user's
#     session agent is left alone.
#
# Backend mode (auto-detected at runtime):
#   - se-touchid -> Apple Silicon SE present AND running interactively
#                   (Touch ID prompts can be answered). Wrapping-key
#                   Data Protection keychain ACL fires per cache TTL.
#   - se         -> SE present, non-interactive context. Per-key
#                   presence-required tests skip; default-policy keys
#                   exercise the SE backend silently after first
#                   wrapping-key prompt.
#   - software   -> --software passed OR Intel without T2 OR CI
#                   environment. SSHENC_FORCE_SOFTWARE=1 routes
#                   through the test-software backend (requires the
#                   binary to have been built with `force-software`).
#
# OpenSSH + git e2e is exercised against a Docker-hosted sshd
# container (the same image the Rust e2e suite uses, at
# `crates/sshenc-e2e/docker/`). On hosts where docker is unavailable
# the e2e block is skipped gracefully.
#
# This file is pure ASCII. The matching CI workflow asserts that.
#
# Usage:
#   ./scripts/Test-Sshenc-MacOS.sh [--strict] [--software]
#                                  [--no-cleanup]
#                                  [--sshenc-bin-dir <path>]
#                                  [--interactive]
#                                  [--skip-docker]

set -u
set +e  # we tally failures, don't abort on first

# ---- args -------------------------------------------------------------------
STRICT=0
USE_SOFTWARE=0
NO_CLEANUP=0
INTERACTIVE=0
SKIP_DOCKER=0
SSHENC_BIN_DIR=""

while [ $# -gt 0 ]; do
    case "$1" in
        --strict)             STRICT=1 ;;
        --software)           USE_SOFTWARE=1 ;;
        --no-cleanup)         NO_CLEANUP=1 ;;
        --interactive|-i)     INTERACTIVE=1 ;;
        --skip-docker)        SKIP_DOCKER=1 ;;
        --sshenc-bin-dir)
            shift
            [ $# -gt 0 ] || { echo "missing value for --sshenc-bin-dir" >&2; exit 2; }
            SSHENC_BIN_DIR="$1"
            ;;
        -h|--help)
            sed -n '2,49p' "$0"
            exit 0
            ;;
        *)
            echo "Unknown flag: $1" >&2
            exit 2
            ;;
    esac
    shift
done

if [ -n "${SSHENC_TEST_INTERACTIVE:-}" ] && [ "$SSHENC_TEST_INTERACTIVE" != "0" ]; then
    INTERACTIVE=1
fi

# CI environments default to software backend: macOS CI runners have
# SE present on Apple Silicon but no biometric / passcode enrolled,
# so any keychain-touching op blocks waiting for a UI that never
# appears.
if [ -n "${GITHUB_ACTIONS:-}" ] || [ -n "${CI:-}" ]; then
    USE_SOFTWARE=1
fi

# ---- result tally -----------------------------------------------------------
PASS=0
FAIL=0
SKIP=0

C_GREEN=$(printf '\033[32m')
C_RED=$(printf '\033[31m')
C_YEL=$(printf '\033[33m')
C_CYA=$(printf '\033[36m')
C_WHT=$(printf '\033[37m')
C_GRY=$(printf '\033[90m')
C_END=$(printf '\033[0m')

record() {
    local status="$1" test="$2" detail="${3:-}"
    case "$status" in
        P) PASS=$((PASS + 1)); printf '  %s[PASS]%s %s' "$C_GREEN" "$C_END" "$test" ;;
        F) FAIL=$((FAIL + 1)); printf '  %s[FAIL]%s %s' "$C_RED"   "$C_END" "$test" ;;
        S) SKIP=$((SKIP + 1)); printf '  %s[SKIP]%s %s' "$C_YEL"   "$C_END" "$test" ;;
    esac
    if [ -n "$detail" ]; then
        printf ' %s- %s%s\n' "$C_GRY" "$detail" "$C_END"
    else
        printf '\n'
    fi
}

banner() {
    printf '\n%s========================================%s\n' "$C_CYA" "$C_END"
    printf '%s%s%s\n' "$C_CYA" "$1" "$C_END"
    printf '%s========================================%s\n' "$C_CYA" "$C_END"
}

section() {
    printf '\n  %s-- %s --%s\n' "$C_WHT" "$1" "$C_END"
}

test_command() {
    local name="$1" cmd="$2" expect="${3:-}"
    local out rc
    out=$(eval "$cmd" 2>&1)
    rc=$?
    if [ $rc -ne 0 ]; then
        local trim="${out%$'\n'}"
        record F "$name" "exit $rc: ${trim:0:120}"
        return
    fi
    if [ -n "$expect" ] && ! grep -qE "$expect" <<<"$out"; then
        local trim="${out%$'\n'}"
        record F "$name" "expected /$expect/, got: ${trim:0:120}"
        return
    fi
    record P "$name"
}

# ---------------------------------------------------------------------
# Backend detection. See header for semantics.
# ---------------------------------------------------------------------
detect_backend() {
    if [ "$USE_SOFTWARE" = "1" ]; then
        echo "software"
        return
    fi
    local apple_silicon=0
    if [ "$(sysctl -n hw.optional.arm64 2>/dev/null || echo 0)" = "1" ]; then
        apple_silicon=1
    fi
    if [ "$apple_silicon" = "0" ]; then
        echo "software"
        return
    fi
    if [ "$INTERACTIVE" = "1" ] && [ -t 0 ]; then
        echo "se-touchid"
    else
        echo "se"
    fi
}

resolve_sshenc_bin() {
    local override="$1"
    if [ -n "$override" ]; then
        local bin="$override/sshenc"
        if [ -x "$bin" ]; then
            python3 -c "import os, sys; print(os.path.abspath(sys.argv[1]))" "$bin"
            return 0
        fi
        echo "sshenc binary not found in --sshenc-bin-dir '$override'" >&2
        return 1
    fi
    local cmd
    cmd="$(command -v sshenc 2>/dev/null)"
    if [ -n "$cmd" ]; then
        echo "$cmd"
        return 0
    fi
    echo "sshenc not on PATH and no --sshenc-bin-dir provided" >&2
    return 1
}

# ---- backend mode + env setup ----------------------------------------------
BACKEND_MODE=$(detect_backend)
if [ "$BACKEND_MODE" = "software" ]; then
    export SSHENC_FORCE_SOFTWARE=1
fi

KEYGEN_AUTH_ARGS=()
if [ "$STRICT" = "0" ]; then
    KEYGEN_AUTH_ARGS=(--auth-policy none)
fi

# ---- isolated test workspace ------------------------------------------------
# Every key the script generates lives under $TEST_TMP, which is
# torn down on exit. SSHENC_KEYS_DIR redirects sshenc's per-key
# artifacts (.handle / .meta / .meta.hmac) there. The agent runs on
# a per-test Unix socket here too -- the user's
# ~/.sshenc/agent.sock is never touched.
TEST_TMP=$(mktemp -d "${TMPDIR:-/tmp}/sshenc-test-XXXXXX")
TEST_KEYS_DIR="$TEST_TMP/keys"
TEST_SSH_DIR="$TEST_TMP/ssh"  # standin for ~/.ssh; .pub files land here
TEST_AGENT_SOCK="$TEST_TMP/agent.sock"
TEST_AGENT_LOG="$TEST_TMP/agent.log"
mkdir -p "$TEST_KEYS_DIR" "$TEST_SSH_DIR"

export SSHENC_KEYS_DIR="$TEST_KEYS_DIR"
# `sshenc keygen --write-pub` writes the .pub at the path we
# specify, so we don't need to override HOME or touch ~/.ssh.

# Resolve binary up front.
SSHENC_BIN=$(resolve_sshenc_bin "$SSHENC_BIN_DIR") || exit 1
SSHENC_DIR=$(dirname "$SSHENC_BIN")
AGENT_BIN="$SSHENC_DIR/sshenc-agent"
GITENC_BIN="$SSHENC_DIR/gitenc"
[ -x "$AGENT_BIN" ]  || AGENT_BIN=$(command -v sshenc-agent 2>/dev/null || true)
[ -x "$GITENC_BIN" ] || GITENC_BIN=$(command -v gitenc 2>/dev/null || true)

# ---- safety: cleanup on exit ------------------------------------------------
# shellcheck disable=SC2329  # invoked via the EXIT trap below
cleanup() {
    # Stop the per-test agent.
    if [ -n "${TEST_AGENT_PID:-}" ]; then
        kill "$TEST_AGENT_PID" 2>/dev/null
        wait "$TEST_AGENT_PID" 2>/dev/null
    fi
    # Stop any sshd container we started.
    if [ -n "${SSHD_CONTAINER_ID:-}" ]; then
        docker rm -f "$SSHD_CONTAINER_ID" >/dev/null 2>&1
    fi
    # SSHENC_KEYS_DIR was isolated, so on-disk artifacts go away with
    # the temp dir. The SE side, however, persists keys until
    # explicitly deleted: if NO_CLEANUP isn't set, walk the diff
    # between snapshot and post-run and delete only NEW labels.
    if [ "$NO_CLEANUP" = "0" ] && [ -n "${POST_LABELS:-}" ]; then
        # POST_LABELS / PRE_LABELS are populated in main flow.
        local label
        while IFS= read -r label; do
            [ -z "$label" ] && continue
            grep -qFx "$label" <<<"$PRE_LABELS" && continue  # pre-existing, leave alone
            "$SSHENC_BIN" delete -y --delete-pub --if-exists "$label" >/dev/null 2>&1
        done <<<"$POST_LABELS"
    fi
    if [ "$NO_CLEANUP" = "0" ]; then
        rm -rf "$TEST_TMP"
    else
        printf '  %s[INFO]%s --no-cleanup: leaving %s in place for inspection\n' \
            "$C_GRY" "$C_END" "$TEST_TMP"
    fi
}
trap cleanup EXIT

# ---- helpers ----------------------------------------------------------------

start_test_agent() {
    rm -f "$TEST_AGENT_SOCK"
    SSHENC_FORCE_SOFTWARE="${SSHENC_FORCE_SOFTWARE:-}" \
    SSHENC_KEYS_DIR="$TEST_KEYS_DIR" \
        "$AGENT_BIN" --socket "$TEST_AGENT_SOCK" --foreground \
        >"$TEST_AGENT_LOG" 2>&1 &
    TEST_AGENT_PID=$!
    # Poll for socket bind.
    local i
    for i in 1 2 3 4 5 6 7 8 9 10; do
        : "$i"
        [ -S "$TEST_AGENT_SOCK" ] && return 0
        sleep 0.5
    done
    return 1
}


# ---- banners ----------------------------------------------------------------
banner "sshenc macOS test matrix ($BACKEND_MODE mode)"
echo "  Binary:    $SSHENC_BIN"
echo "  macOS:     $(sw_vers -productVersion 2>/dev/null) ($(sw_vers -buildVersion 2>/dev/null))"
echo "  arch:      $(arch)"
echo "  policy:    $(if [ "$STRICT" = "1" ]; then echo strict; else echo "no-presence"; fi)"
echo "  test dir:  $TEST_TMP"
echo "  keys dir:  $TEST_KEYS_DIR"
echo "  agent:     $TEST_AGENT_SOCK"
case "$BACKEND_MODE" in
    se-touchid)
        printf '  %s[INFO]%s Apple Silicon SE + interactive; full hardware coverage available\n' "$C_GREEN" "$C_END"
        ;;
    se)
        printf '  %s[INFO]%s Apple Silicon SE, non-interactive; presence-required tests will skip\n' "$C_GRY" "$C_END"
        ;;
    software)
        printf '  %s[INFO]%s software backend (SSHENC_FORCE_SOFTWARE=1)\n' "$C_YEL" "$C_END"
        printf '         %sRequires sshenc to have been built with --features force-software.%s\n' "$C_GRY" "$C_END"
        ;;
esac

# ---- pre-flight: snapshot existing keys, start isolated agent --------------
banner "Pre-flight: snapshot existing key set, start isolated agent"

# We need an agent on the standard socket to read the user's
# pre-existing labels (those entries are scoped to the user's normal
# keys dir + login keychain, which our isolated agent can't see).
# But in software mode SSHENC_KEYS_DIR isolates everything anyway,
# and there are no "user keys" to preserve. Snapshot via the
# isolated agent in that case.
start_test_agent || { echo "FATAL: failed to start test agent" >&2; exit 1; }
record P "test agent listening on $TEST_AGENT_SOCK"

# In software mode the isolated agent has its own (empty) view, so
# the snapshot is empty and any label we create will be flagged as
# net-new at cleanup. In SE mode the isolated agent uses
# SSHENC_KEYS_DIR for .handle storage but the SE itself is system-
# wide; we still snapshot via the isolated agent because the
# agent's `list` only shows labels it knows about (read from
# SSHENC_KEYS_DIR). Pre-existing user keys live under the user's
# normal keys dir, are invisible to the isolated agent, and thus
# can't be seen OR deleted by this script.
PRE_LABELS=$(SSH_AUTH_SOCK="$TEST_AGENT_SOCK" "$SSHENC_BIN" list --json 2>/dev/null \
    | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)
if isinstance(data, dict):
    data = [data]
for k in data:
    label = (k.get("metadata") or {}).get("label")
    if label:
        print(label)
' | LC_ALL=C sort)
PRE_COUNT=$(printf '%s' "$PRE_LABELS" | grep -c . || true)
printf '  %s[INFO]%s pre-existing labels visible to test agent: %s\n' "$C_GRY" "$C_END" "$PRE_COUNT"

# ---- per-run unique labels -------------------------------------------------
RUN_ID="$(date +%s)-$$-$RANDOM"
LABEL_A="sshenc-matrix-$RUN_ID-a"
LABEL_B="sshenc-matrix-$RUN_ID-b"

# ---- generate the two test keys --------------------------------------------
banner "Lifecycle: keygen + introspection"

if SSH_AUTH_SOCK="$TEST_AGENT_SOCK" "$SSHENC_BIN" keygen -l "$LABEL_A" \
    -C "matrix-test-a" "${KEYGEN_AUTH_ARGS[@]}" \
    --write-pub "$TEST_SSH_DIR/$LABEL_A.pub" >/dev/null 2>&1; then
    record P "sshenc keygen $LABEL_A"
else
    record F "sshenc keygen $LABEL_A"
fi

if SSH_AUTH_SOCK="$TEST_AGENT_SOCK" "$SSHENC_BIN" keygen -l "$LABEL_B" \
    -C "matrix-test-b" "${KEYGEN_AUTH_ARGS[@]}" \
    --write-pub "$TEST_SSH_DIR/$LABEL_B.pub" >/dev/null 2>&1; then
    record P "sshenc keygen $LABEL_B"
else
    record F "sshenc keygen $LABEL_B"
fi

# Restart the agent so its in-memory identity cache picks up the
# two keys we just generated. The agent's cache is warmed at startup
# only; new keys created mid-run don't refresh it, so subsequent
# sign requests would fail with "key not found" against the cached
# (empty) view. Tracked as a follow-up bug; this restart is the
# test-script workaround.
kill "$TEST_AGENT_PID" 2>/dev/null
wait "$TEST_AGENT_PID" 2>/dev/null
start_test_agent || { echo "FATAL: failed to restart test agent" >&2; exit 1; }

FP_A=$(SSH_AUTH_SOCK="$TEST_AGENT_SOCK" "$SSHENC_BIN" export-pub "$LABEL_A" --fingerprint 2>&1 | tr -d '\r\n')
FP_B=$(SSH_AUTH_SOCK="$TEST_AGENT_SOCK" "$SSHENC_BIN" export-pub "$LABEL_B" --fingerprint 2>&1 | tr -d '\r\n')
if [[ "$FP_A" == SHA256:* ]] && [[ "$FP_B" == SHA256:* ]] && [ "$FP_A" != "$FP_B" ]; then
    record P "keys have distinct fingerprints"
else
    record F "keys have distinct fingerprints" "A=$FP_A B=$FP_B"
fi

test_command "sshenc inspect $LABEL_A" \
    "SSH_AUTH_SOCK='$TEST_AGENT_SOCK' '$SSHENC_BIN' inspect '$LABEL_A'" "ecdsa"
test_command "sshenc export-pub $LABEL_A" \
    "SSH_AUTH_SOCK='$TEST_AGENT_SOCK' '$SSHENC_BIN' export-pub '$LABEL_A'" "ecdsa-sha2-nistp256"

# ---- smoke (backend-irrelevant) --------------------------------------------
banner "Smoke tests (backend-irrelevant)"
section "sshenc"
test_command "sshenc --version"        "'$SSHENC_BIN' --version"        "sshenc"
test_command "sshenc config path"      "'$SSHENC_BIN' config path"
test_command "sshenc config show"      "'$SSHENC_BIN' config show"      "socket_path"
test_command "sshenc completions bash" "'$SSHENC_BIN' completions bash" "_sshenc"
test_command "sshenc completions zsh"  "'$SSHENC_BIN' completions zsh"  "compdef"
test_command "sshenc delete --if-exists missing" \
    "SSH_AUTH_SOCK='$TEST_AGENT_SOCK' '$SSHENC_BIN' delete -y --if-exists never-existed-12345"

if [ -x "$GITENC_BIN" ]; then
    section "gitenc"
    test_command "gitenc -h"     "'$GITENC_BIN' -h"     "Git wrapper"
    test_command "gitenc --help" "'$GITENC_BIN' --help" "sshenc"
    gitenc_ver=$("$GITENC_BIN" --version 2>&1)
    if [[ "$gitenc_ver" =~ ^gitenc\ [0-9] ]]; then
        record P "gitenc --version"
    else
        record F "gitenc --version" "$gitenc_ver"
    fi
fi

# ---- local sign (no remote) ------------------------------------------------
banner "Local sign via $BACKEND_MODE backend"
PUB_FILE="$TEST_SSH_DIR/$LABEL_A.pub"
if [ -f "$PUB_FILE" ]; then
    SIGN_OUT=$(echo "matrix sign test (bash)" \
        | SSH_AUTH_SOCK="$TEST_AGENT_SOCK" \
            ssh-keygen -Y sign -f "$PUB_FILE" -n "matrix-test" 2>&1)
    if grep -q "BEGIN SSH SIGNATURE" <<<"$SIGN_OUT"; then
        record P "sign via $BACKEND_MODE ($LABEL_A)"
    else
        record F "sign via $BACKEND_MODE ($LABEL_A)" "no signature: ${SIGN_OUT:0:150}"
    fi
else
    record F "sign via $BACKEND_MODE ($LABEL_A)" "no .pub file at $PUB_FILE"
fi

# ---- shell wrapper consistency: zsh ----------------------------------------
banner "Lifecycle (zsh)"
ZSH_BIN=$(command -v zsh 2>/dev/null || echo "")
if [ -z "$ZSH_BIN" ]; then
    record S "zsh not available on this host"
else
    ZSH_SCRIPT=$(mktemp "$TEST_TMP/zsh-runner.XXXXXX.sh")
    cat >"$ZSH_SCRIPT" <<ZSHEOF
#!/usr/bin/env zsh
set -e
SSHENC=$(printf '%q' "$SSHENC_BIN")
LABEL=$(printf '%q' "$LABEL_A")
PUB=$(printf '%q' "$PUB_FILE")
SOCK=$(printf '%q' "$TEST_AGENT_SOCK")
\$SSHENC --version | grep -q sshenc && echo PASS zsh-version || echo FAIL zsh-version
SSH_AUTH_SOCK=\$SOCK \$SSHENC list >/dev/null && echo PASS zsh-list || echo FAIL zsh-list
SSH_AUTH_SOCK=\$SOCK \$SSHENC inspect \$LABEL 2>&1 | grep -q ecdsa && echo PASS zsh-inspect || echo FAIL zsh-inspect
SSH_AUTH_SOCK=\$SOCK \$SSHENC export-pub \$LABEL 2>&1 | grep -q ecdsa-sha2-nistp256 && echo PASS zsh-export-pub || echo FAIL zsh-export-pub
SIG=\$(echo "matrix sign test (zsh)" | SSH_AUTH_SOCK=\$SOCK /usr/bin/ssh-keygen -Y sign -f \$PUB -n matrix-test 2>&1 || true)
echo "\$SIG" | grep -q "BEGIN SSH SIGNATURE" && echo PASS zsh-sign || echo FAIL zsh-sign
ZSHEOF
    while IFS= read -r line; do
        if [[ "$line" =~ ^PASS\ (.+)$ ]]; then
            record P "${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^FAIL\ (.+)$ ]]; then
            record F "${BASH_REMATCH[1]}"
        fi
    done < <("$ZSH_BIN" "$ZSH_SCRIPT" 2>&1)
fi

# ---- Docker e2e: OpenSSH + git against a containerized server --------------
banner "E2E: OpenSSH + git against Docker container"

if [ "$SKIP_DOCKER" = "1" ]; then
    record S "docker e2e" "skipped via --skip-docker"
elif ! command -v docker >/dev/null 2>&1; then
    record S "docker e2e" "docker not installed; install Docker Desktop / colima to enable"
elif ! docker info >/dev/null 2>&1; then
    record S "docker e2e" "docker daemon unreachable; start Docker Desktop / colima"
else
    DOCKER_DIR="$(dirname "$(dirname "$SSHENC_BIN")")"
    # When --sshenc-bin-dir is target/release, the Dockerfile lives
    # at crates/sshenc-e2e/docker/ relative to the repo root.
    REPO_ROOT=""
    for candidate in \
        "$DOCKER_DIR" \
        "$DOCKER_DIR/.." \
        "$(pwd)" \
        "$(pwd)/.." \
    ; do
        if [ -f "$candidate/crates/sshenc-e2e/docker/Dockerfile" ]; then
            REPO_ROOT="$candidate"
            break
        fi
    done

    if [ -z "$REPO_ROOT" ]; then
        record S "docker e2e" "couldn't locate crates/sshenc-e2e/docker/Dockerfile"
    else
        IMAGE_TAG="sshenc-e2e-test:matrix"
        if ! docker image inspect "$IMAGE_TAG" >/dev/null 2>&1; then
            printf '  %s[INFO]%s building docker image %s ...\n' "$C_GRY" "$C_END" "$IMAGE_TAG"
            if ! docker build -q -t "$IMAGE_TAG" "$REPO_ROOT/crates/sshenc-e2e/docker/" >/dev/null 2>&1; then
                record F "docker e2e: build image"
                IMAGE_TAG=""
            else
                record P "docker e2e: build image"
            fi
        else
            record P "docker e2e: image cached"
        fi

        if [ -n "$IMAGE_TAG" ]; then
            AUTH_FILE="$TEST_TMP/authorized_keys"
            cat "$TEST_SSH_DIR/$LABEL_A.pub" "$TEST_SSH_DIR/$LABEL_B.pub" 2>/dev/null \
                | grep -E '^ecdsa-sha2-nistp256' >"$AUTH_FILE"
            chmod 644 "$AUTH_FILE"

            SSHD_CONTAINER_ID=$(docker run --rm -d \
                -p 127.0.0.1:0:22 \
                -v "$AUTH_FILE:/authorized_keys:ro" \
                "$IMAGE_TAG" 2>&1)
            if [ -z "$SSHD_CONTAINER_ID" ] || ! docker inspect "$SSHD_CONTAINER_ID" >/dev/null 2>&1; then
                record F "docker e2e: start container" "$SSHD_CONTAINER_ID"
                SSHD_CONTAINER_ID=""
            else
                record P "docker e2e: start container"
                # Pull the host-side mapped port.
                CONTAINER_PORT=$(docker port "$SSHD_CONTAINER_ID" 22/tcp 2>/dev/null \
                    | head -1 | sed -E 's/.*:([0-9]+)$/\1/')
                # Wait for sshd to accept connections.
                for _ in 1 2 3 4 5 6 7 8 9 10; do
                    if nc -z 127.0.0.1 "$CONTAINER_PORT" 2>/dev/null; then break; fi
                    sleep 0.5
                done

                CONTAINER_KH="$TEST_TMP/container-known-hosts"
                ssh-keyscan -p "$CONTAINER_PORT" 127.0.0.1 >"$CONTAINER_KH" 2>/dev/null

                SSH_OPTS=(-o "BatchMode=yes" -o "ConnectTimeout=10"
                          -o "UserKnownHostsFile=$CONTAINER_KH"
                          -o "StrictHostKeyChecking=yes"
                          -o "PreferredAuthentications=publickey"
                          -F /dev/null
                          -p "$CONTAINER_PORT")

                # Pubkey auth via the test agent.
                if SSH_AUTH_SOCK="$TEST_AGENT_SOCK" \
                    ssh "${SSH_OPTS[@]}" sshtest@127.0.0.1 echo ok 2>&1 | grep -q ok; then
                    record P "docker e2e: ssh auth via agent"
                else
                    record F "docker e2e: ssh auth via agent"
                fi

                # Git over SSH: clone a bare repo we set up in the
                # container. The image ships git + git-daemon so we
                # can `git init --bare` over SSH.
                docker exec --user sshtest "$SSHD_CONTAINER_ID" \
                    sh -c 'git init --bare /home/sshtest/test.git >/dev/null 2>&1 && \
                           git -c init.defaultBranch=main init /tmp/work >/dev/null 2>&1 && \
                           cd /tmp/work && \
                           git -c user.email=t@t -c user.name=t commit --allow-empty -m init >/dev/null 2>&1 && \
                           git push --quiet /home/sshtest/test.git main >/dev/null 2>&1' 2>/dev/null
                CLONE_DST="$TEST_TMP/clone"
                if SSH_AUTH_SOCK="$TEST_AGENT_SOCK" \
                    GIT_SSH_COMMAND="ssh ${SSH_OPTS[*]}" \
                    git clone -q "sshtest@127.0.0.1:test.git" "$CLONE_DST" 2>/dev/null \
                    && [ -d "$CLONE_DST/.git" ]; then
                    record P "docker e2e: git clone via SSH"
                else
                    record F "docker e2e: git clone via SSH"
                fi
            fi
        fi
    fi
fi

# ---- post-flight: list final labels for cleanup diff -----------------------
POST_LABELS=$(SSH_AUTH_SOCK="$TEST_AGENT_SOCK" "$SSHENC_BIN" list --json 2>/dev/null \
    | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)
if isinstance(data, dict):
    data = [data]
for k in data:
    label = (k.get("metadata") or {}).get("label")
    if label:
        print(label)
' | LC_ALL=C sort)

if [ "$NO_CLEANUP" = "0" ]; then
    banner "Post-flight: assert no pre-existing key was deleted"
    leaked_count=0
    while IFS= read -r label; do
        [ -z "$label" ] && continue
        if ! grep -qFx "$label" <<<"$POST_LABELS"; then
            record F "pre-existing label preserved: $label" "label is gone after run"
            leaked_count=$((leaked_count + 1))
        fi
    done <<<"$PRE_LABELS"
    if [ "$leaked_count" = "0" ]; then
        record P "all pre-existing labels still present"
    fi
fi

# Cleanup runs in `cleanup` via the EXIT trap.

# ---- summary ----------------------------------------------------------------
banner "SUMMARY"
TOTAL=$((PASS + FAIL + SKIP))
printf '  %s%d pass%s, %s%d fail%s, %s%d skip%s (%d total)\n' \
    "$C_GREEN" "$PASS" "$C_END" \
    "$C_RED"   "$FAIL" "$C_END" \
    "$C_YEL"   "$SKIP" "$C_END" \
    "$TOTAL"

if [ $FAIL -gt 0 ]; then
    exit 1
fi
exit 0
