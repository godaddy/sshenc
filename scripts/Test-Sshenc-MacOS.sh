#!/usr/bin/env bash
# Test-Sshenc-MacOS.sh
#
# macOS-side test harness for sshenc + gitenc. Designed to run both
# locally (Apple Silicon with Secure Enclave + Touch ID enrolled) and
# in CI on `macos-latest` (SE present but no biometric/passcode
# enrolled, so the SE path can't actually prompt).
#
# Detects backend at runtime and picks a mode:
#
#   - se-touchid -> exercises the production SE path (Touch ID prompts
#                   fire and require a human to answer)
#   - se         -> SE present but biometric not enrolled / can't be
#                   prompted (rare; treated like software for safety)
#   - software   -> Intel without T2 OR --software passed; falls back
#                   to the test-only software backend via
#                   SSHENC_FORCE_SOFTWARE=1, requires the sshenc binary
#                   to have been compiled with the `force-software`
#                   Cargo feature
#
# Coverage that runs in EITHER mode (backend-irrelevant): version
# output, config commands, completions emission, key lifecycle (keygen
# / list / inspect / export-pub / sign / delete), shell-wrapper
# consistency across bash / zsh, gitenc smoke + signing, agent Unix
# socket binding, socket -> ssh-keygen sign round-trip.
#
# Coverage that requires SE (skipped in software mode): the actual
# CryptoKit / SecureEnclave.P256 code path, wrapping-key Data
# Protection keychain access, kSecAttrAccessControl(.userPresence)
# round-trips. Hardware regressions in those paths are caught by the
# developer's local matrix run on a real Apple Silicon host.
#
# This file is pure ASCII. Mirrors the Windows-side `Test-Sshenc-Windows.ps1`
# discipline: bash on macOS reads .sh files using whatever the
# user's locale dictates, and shellcheck warns on UTF-8 quotes /
# em-dashes that look fine in an editor but trip parser corners.
# Use `--` for em-dash, plain ASCII quotes only.
#
# Usage:
#   ./scripts/Test-Sshenc-MacOS.sh [--strict] [--software]
#                                  [--reset-shared-keys] [--no-cleanup]
#                                  [--sshenc-bin-dir <path>]
#                                  [--interactive]

set -u
set +e  # we tally failures, don't abort on first

# ---- args -------------------------------------------------------------------
STRICT=0
USE_SOFTWARE=0
RESET_SHARED=0
NO_CLEANUP=0
INTERACTIVE=0
SSHENC_BIN_DIR=""

while [ $# -gt 0 ]; do
    case "$1" in
        --strict)              STRICT=1 ;;
        --software)            USE_SOFTWARE=1 ;;
        --reset-shared-keys)   RESET_SHARED=1 ;;
        --no-cleanup)          NO_CLEANUP=1 ;;
        --interactive|-i)      INTERACTIVE=1 ;;
        --sshenc-bin-dir)
            shift
            [ $# -gt 0 ] || { echo "missing value for --sshenc-bin-dir" >&2; exit 2; }
            SSHENC_BIN_DIR="$1"
            ;;
        -h|--help)
            sed -n '2,46p' "$0"
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
# Backend detection. Returns one of:
#   "se-touchid"  Apple Silicon (SE present) AND running interactively
#                 (Touch ID prompts can be answered)
#   "se"          Apple Silicon, but non-interactive -- SE present but
#                 the wrapping-key UserPresence ACL can't actually
#                 prompt; treated like software for the per-key tests
#   "software"    Intel without T2, OR --software, OR CI environment
#
# This is a SOFT signal. The real backend selection happens inside
# the sshenc binary via `enclaveapp_app_storage::AppSigningBackend::init`.
# The mode label here only affects:
#   1. Whether interactive-only tests can run (Touch ID prompts)
#   2. Whether to flip SSHENC_FORCE_SOFTWARE on (when --software passed)
#   3. The banner output
# A wrong detection in the script doesn't break the tests -- the
# binary is the source of truth.
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
        # Could be Intel with T2; we don't try to detect T2 specifically.
        # The binary will fall back to software where appropriate. Without
        # explicit knowledge, treat Intel as software-only here.
        echo "software"
        return
    fi
    if [ "$INTERACTIVE" = "1" ] && [ -t 0 ]; then
        echo "se-touchid"
    else
        echo "se"
    fi
}

# ---------------------------------------------------------------------
# Resolve the sshenc binary. --sshenc-bin-dir overrides PATH; useful
# in CI where we want to test a freshly-built target/release/sshenc.
# ---------------------------------------------------------------------
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

# `sshenc keygen` extra-args toggle. Empty under --strict (lets the
# v0.6.44+ default-flip kick in on Touch ID-enrolled hosts);
# `--auth-policy none` for unattended/CI runs.
KEYGEN_AUTH_ARGS=()
if [ "$STRICT" = "0" ]; then
    KEYGEN_AUTH_ARGS=(--auth-policy none)
fi

# ---- shared persistent keys -------------------------------------------------
# Mirrors the Windows side: one pair per policy mode, reused across
# runs so we don't repeatedly trigger the wrapping-key Touch ID
# prompt on local matrix-test laptops.
if [ "$STRICT" = "1" ]; then
    SHARED_KEY_MODE="strict"
else
    SHARED_KEY_MODE="silent"
fi
SHARED_KEY_A="matrix-a-$SHARED_KEY_MODE"
SHARED_KEY_B="matrix-b-$SHARED_KEY_MODE"
SHARED_KEYS=("$SHARED_KEY_A" "$SHARED_KEY_B")
ALL_SHARED_KEYS=("matrix-a-silent" "matrix-b-silent" "matrix-a-strict" "matrix-b-strict")

# Resolve binary up front so a missing-tool error fires before banner output.
SSHENC_BIN=$(resolve_sshenc_bin "$SSHENC_BIN_DIR") || exit 1
SSHENC_DIR=$(dirname "$SSHENC_BIN")
AGENT_BIN="$SSHENC_DIR/sshenc-agent"
GITENC_BIN="$SSHENC_DIR/gitenc"
[ -x "$AGENT_BIN" ]  || AGENT_BIN=$(command -v sshenc-agent 2>/dev/null || true)
[ -x "$GITENC_BIN" ] || GITENC_BIN=$(command -v gitenc 2>/dev/null || true)

# ---- helpers ----------------------------------------------------------------

# sshenc-agent process management. Mirrors the Windows
# Test-SshencKeyExists / Reset-SshencKeys semantics. Each call to
# `sshenc list --json` requires an agent on the standard socket.
ensure_agent_running() {
    if pgrep -f 'sshenc-agent --socket .*/\.sshenc/agent\.sock' >/dev/null 2>&1; then
        return 0
    fi
    rm -f "$HOME/.sshenc/agent.sock" "$HOME/.sshenc/agent.pid"
    "$AGENT_BIN" --socket "$HOME/.sshenc/agent.sock" >/dev/null 2>&1
    sleep 1
}

test_sshenc_key_exists() {
    local label="$1"
    "$SSHENC_BIN" inspect "$label" >/dev/null 2>&1
}

# Idempotent cleanup. Removes any managed key not in $1 (allowlist).
# Returns the number of keys deleted on stdout. Requires --if-exists
# (sshenc v0.6.50+); older binaries error here.
reset_sshenc_keys() {
    local keep_csv="$1"
    ensure_agent_running

    local list_json count
    if ! list_json=$("$SSHENC_BIN" list --json 2>&1) || [ -z "$list_json" ]; then
        echo 0
        return
    fi
    count=0
    # Parse labels via python3 (always present on macOS) rather than
    # adding a jq dependency.
    local labels
    labels=$(printf '%s' "$list_json" | python3 -c '
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
')
    while IFS= read -r label; do
        [ -z "$label" ] && continue
        case ",$keep_csv," in
            *,"$label",*) continue ;;
        esac
        "$SSHENC_BIN" delete -y --delete-pub --if-exists "$label" >/dev/null 2>&1
        count=$((count + 1))
    done <<<"$labels"
    echo "$count"
}

ensure_shared_keys() {
    # Caller captures the integer count from stdout; route all
    # human-readable INFO / WARN messages to stderr so they don't
    # contaminate the count.
    local force_reset="$1"; shift
    local labels=("$@")
    ensure_agent_running
    local created=0
    for lbl in "${labels[@]}"; do
        if [ "$force_reset" = "1" ]; then
            "$SSHENC_BIN" delete -y --delete-pub --if-exists "$lbl" >/dev/null 2>&1
        fi
        if ! test_sshenc_key_exists "$lbl"; then
            local out
            out=$("$SSHENC_BIN" keygen -l "$lbl" -C "matrix-shared" "${KEYGEN_AUTH_ARGS[@]}" 2>&1)
            if grep -q "Generated" <<<"$out"; then
                created=$((created + 1))
                printf '  %s[INFO]%s Created shared key: %s\n' "$C_GRY" "$C_END" "$lbl" >&2
            else
                printf '  %s[WARN]%s Failed to create %s: %s\n' "$C_YEL" "$C_END" "$lbl" "$(head -1 <<<"$out")" >&2
            fi
        fi
    done
    echo "$created"
}

# ---- banners ----------------------------------------------------------------
banner "sshenc macOS test matrix ($BACKEND_MODE mode)"
echo "  Binary:   $SSHENC_BIN"
echo "  macOS:    $(sw_vers -productVersion 2>/dev/null) ($(sw_vers -buildVersion 2>/dev/null))"
echo "  arch:     $(arch)"
echo "  Policy:   $SHARED_KEY_MODE (Strict=$STRICT)"
echo "  Shared:   ${SHARED_KEYS[*]}"
case "$BACKEND_MODE" in
    se-touchid)
        printf '  %s[INFO]%s Apple Silicon SE + interactive; full hardware coverage available\n' "$C_GREEN" "$C_END"
        ;;
    se)
        printf '  %s[INFO]%s Apple Silicon SE, non-interactive; presence-required tests will skip\n' "$C_GRY" "$C_END"
        ;;
    software)
        if [ "$USE_SOFTWARE" = "1" ]; then
            printf '  %s[INFO]%s --software flag set or CI detected; using software backend (SSHENC_FORCE_SOFTWARE=1)\n' "$C_YEL" "$C_END"
        else
            printf '  %s[INFO]%s No SE detected; using software backend (SSHENC_FORCE_SOFTWARE=1)\n' "$C_YEL" "$C_END"
        fi
        printf '         %sRequires sshenc to have been built with --features force-software.%s\n' "$C_GRY" "$C_END"
        ;;
esac

banner "Pre-flight: clean transients, ensure shared keys"
PRE_COUNT=$(reset_sshenc_keys "$(IFS=,; echo "${ALL_SHARED_KEYS[*]}")")
if [ "$PRE_COUNT" -gt 0 ]; then
    printf '  %s[INFO]%s Cleaned %s transient key(s) from prior runs\n' "$C_YEL" "$C_END" "$PRE_COUNT"
else
    printf '  %s[INFO]%s No transient keys to clean\n' "$C_GRY" "$C_END"
fi
CREATED=$(ensure_shared_keys "$RESET_SHARED" "${SHARED_KEYS[@]}")
if [ "$CREATED" -gt 0 ]; then
    printf '  %s[INFO]%s Created %s new shared key(s); future runs will reuse\n' "$C_YEL" "$C_END" "$CREATED"
else
    printf '  %s[INFO]%s All %s shared keys already exist\n' "$C_GREEN" "$C_END" "${#SHARED_KEYS[@]}"
fi
for k in "${SHARED_KEYS[@]}"; do
    if ! test_sshenc_key_exists "$k"; then
        record F "shared key available: $k" "could not be created or read"
    fi
done

# ---- smoke tests (backend-irrelevant) ---------------------------------------
banner "Smoke tests (backend-irrelevant)"
section "sshenc"
test_command "sshenc --version"          "'$SSHENC_BIN' --version"          "sshenc"
test_command "sshenc config path"        "'$SSHENC_BIN' config path"
test_command "sshenc config show"        "'$SSHENC_BIN' config show"        "socket_path"
test_command "sshenc list"               "'$SSHENC_BIN' list"
test_command "sshenc completions bash"   "'$SSHENC_BIN' completions bash"   "_sshenc"
test_command "sshenc completions zsh"    "'$SSHENC_BIN' completions zsh"    "compdef"
test_command "sshenc delete --if-exists missing" "'$SSHENC_BIN' delete -y --if-exists never-existed-12345"

if [ -x "$GITENC_BIN" ]; then
    section "gitenc"
    test_command "gitenc -h"      "'$GITENC_BIN' -h"      "Git wrapper"
    test_command "gitenc --help"  "'$GITENC_BIN' --help"  "sshenc"
    gitenc_ver=$("$GITENC_BIN" --version 2>&1)
    if [[ "$gitenc_ver" =~ ^gitenc\ [0-9] ]]; then
        record P "gitenc --version"
    else
        record F "gitenc --version" "$gitenc_ver"
    fi
fi

# ---- lifecycle (bash) -------------------------------------------------------
banner "Lifecycle (bash -> $BACKEND_MODE backend)"

FP_A=$("$SSHENC_BIN" export-pub "$SHARED_KEY_A" --fingerprint 2>&1 | tr -d '\r\n')
FP_B=$("$SSHENC_BIN" export-pub "$SHARED_KEY_B" --fingerprint 2>&1 | tr -d '\r\n')
if [[ "$FP_A" == SHA256:* ]] && [[ "$FP_B" == SHA256:* ]] && [ "$FP_A" != "$FP_B" ]; then
    record P "shared keys have distinct fingerprints"
else
    record F "shared keys have distinct fingerprints" "A=$FP_A B=$FP_B"
fi

test_command "sshenc inspect $SHARED_KEY_A"     "'$SSHENC_BIN' inspect '$SHARED_KEY_A'"     "ecdsa"
test_command "sshenc export-pub $SHARED_KEY_A"  "'$SSHENC_BIN' export-pub '$SHARED_KEY_A'"  "ecdsa-sha2-nistp256"

# Sign via the agent's Unix socket. Mirrors the Windows
# `\\.\pipe\openssh-ssh-agent` test, just over a local socket.
PUB_FILE="$HOME/.ssh/$SHARED_KEY_A.pub"
if [ -f "$PUB_FILE" ]; then
    SIGN_OUT=$(echo "matrix sign test (bash)" \
        | SSH_AUTH_SOCK="$HOME/.sshenc/agent.sock" \
            ssh-keygen -Y sign -f "$PUB_FILE" -n "matrix-test" 2>&1)
    if grep -q "BEGIN SSH SIGNATURE" <<<"$SIGN_OUT"; then
        record P "sign via $BACKEND_MODE ($SHARED_KEY_A)"
    else
        record F "sign via $BACKEND_MODE ($SHARED_KEY_A)" "no signature: ${SIGN_OUT:0:150}"
    fi
else
    record S "sign via $BACKEND_MODE ($SHARED_KEY_A)" "no .pub file at $PUB_FILE"
fi

# ---- lifecycle (zsh) --------------------------------------------------------
# zsh is the macOS default shell since Catalina (10.15). Validates
# that wrapper / argument quoting holds across both shells.
banner "Lifecycle (zsh)"
ZSH_BIN=$(command -v zsh 2>/dev/null || echo "")
if [ -z "$ZSH_BIN" ]; then
    record S "zsh not available on this host"
else
    ZSH_SCRIPT=$(mktemp "/tmp/sshenc-zsh-$$.XXXXXX.sh")
    cat >"$ZSH_SCRIPT" <<ZSHEOF
#!/usr/bin/env zsh
set -e
SSHENC=$(printf '%q' "$SSHENC_BIN")
LABEL=$(printf '%q' "$SHARED_KEY_A")
PUB=$(printf '%q' "$PUB_FILE")
\$SSHENC --version | grep -q sshenc && echo PASS zsh-version || echo FAIL zsh-version
\$SSHENC list >/dev/null && echo PASS zsh-list || echo FAIL zsh-list
\$SSHENC inspect \$LABEL 2>&1 | grep -q ecdsa && echo PASS zsh-inspect || echo FAIL zsh-inspect
\$SSHENC export-pub \$LABEL 2>&1 | grep -q ecdsa-sha2-nistp256 && echo PASS zsh-export-pub || echo FAIL zsh-export-pub
SIG=\$(echo "matrix sign test (zsh)" | SSH_AUTH_SOCK="$HOME/.sshenc/agent.sock" /usr/bin/ssh-keygen -Y sign -f \$PUB -n matrix-test 2>&1 || true)
echo "\$SIG" | grep -q "BEGIN SSH SIGNATURE" && echo PASS zsh-sign || echo FAIL zsh-sign
ZSHEOF
    while IFS= read -r line; do
        if [[ "$line" =~ ^PASS\ (.+)$ ]]; then
            record P "${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^FAIL\ (.+)$ ]]; then
            record F "${BASH_REMATCH[1]}"
        fi
    done < <("$ZSH_BIN" "$ZSH_SCRIPT" 2>&1)
    rm -f "$ZSH_SCRIPT"
fi

# ---- post-flight ------------------------------------------------------------
if [ "$NO_CLEANUP" = "0" ]; then
    banner "Post-flight: verify no transient keys leaked"
    POST_COUNT=$(reset_sshenc_keys "$(IFS=,; echo "${ALL_SHARED_KEYS[*]}")")
    if [ "$POST_COUNT" -gt 0 ]; then
        record F "post-flight: no transient keys leaked" "$POST_COUNT key(s) leaked; auto-cleaned"
    else
        record P "post-flight: no transient keys leaked"
    fi
    for k in "${SHARED_KEYS[@]}"; do
        if test_sshenc_key_exists "$k"; then
            record P "post-flight: shared key preserved ($k)"
        else
            record F "post-flight: shared key preserved ($k)" "removed during run"
        fi
    done
fi

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
