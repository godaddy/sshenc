# Design: Window Server / Touch ID Availability Mitigations

**Status: Complete** — all four mitigations merged (libenclaveapp #151, sshenc #229)

## Problem

When `sshenc-agent` is launched outside of launchd (e.g. `sshenc-agent &` in a
shell, or started from a script that isn't a launchd job), the process has no
connection to the macOS window server. Touch ID requires window server access to
display its prompt; without it, `LAContext.evaluatePolicy` returns `systemCancel`
immediately and all biometric sign operations silently fail with what was
previously an opaque "error code 10" (`errSecInteractionRequired`).

The failure mode is invisible: the agent starts, accepts connections, returns
errors on every sign, and the user sees no indication of why or how to fix it.

We also want to distinguish "no window server at all" from "screen is locked" —
both currently surface as `KeychainInteractionRequired`, but they have different
recovery paths ("restart via launchd" vs "unlock your screen").

## Mitigations

These four layers are complementary and non-conflicting. Each catches the
problem at a different point in the lifecycle.

---

### Mitigation 1 — Startup probe + warning

**Where:** `sshenc-agent/src/main.rs`, macOS-only (`#[cfg(target_os = "macos")]`)

**What:** At agent startup (before entering the accept loop), probe whether
Touch ID is evaluable. If `LAContext().canEvaluatePolicy(.deviceOwnerAuthentication)`
returns false, emit a prominent warning to both stderr and `sshenc.log`:

```
WARNING: Touch ID is not available (no window server access).
Biometric sign operations will fail until the agent is restarted via launchd.
Run: launchctl load ~/Library/LaunchAgents/com.godaddy.sshenc.agent.plist
```

**Scope:** macOS only. The `enclaveapp_se_touch_id_available()` bridge function
needs to be added to libenclaveapp's Swift bridge and exposed via FFI.

**Why not enough alone:** The user may not be watching stderr, and the warning
doesn't stop the bad agent from running.

- [x] Add `enclaveapp_se_touch_id_available() -> Int32` to
      `libenclaveapp/crates/enclaveapp-apple/swift/bridge.swift`
- [x] Add FFI declaration in
      `libenclaveapp/crates/enclaveapp-apple/src/ffi.rs`
- [x] Add `touch_id_available() -> bool` in
      `libenclaveapp/crates/enclaveapp-apple/src/sign.rs`
- [x] Export from `enclaveapp-apple/src/lib.rs`
- [x] In `sshenc-agent/src/main.rs`, call `check_window_server_or_relaunch()`
      before daemonize; emits warning if Touch ID unavailable

---

### Mitigation 2 — Startup auto-reload via launchd

**Where:** `sshenc-agent/src/main.rs`, macOS-only

**What:** Detect whether the agent was launched by launchd by checking the
`XPC_SERVICE_NAME` environment variable (launchd sets this to the job label;
shell launches leave it unset). If not set AND the LaunchAgent plist exists on
disk, automatically:

1. Run `launchctl bootout gui/$(id -u) <plist>` (idempotent, safe to run even
   if not loaded)
2. Run `launchctl bootstrap gui/$(id -u) <plist>`
3. Print to stderr: "Restarted via launchd for Touch ID access."
4. Exit 0

Launchd then starts the real agent with window server access.

If the plist does not exist, fall through to Mitigation 1's warning (the user
hasn't installed yet; nothing to reload to).

**Why this is safe:** `launchctl bootstrap` is idempotent for a freshly-booted
job. The current (non-launchd) agent exits immediately, so there's no socket
conflict. The launchd-started agent binds the same socket path.

**Edge cases to handle:**
- Plist doesn't exist → skip auto-reload, fall through to warning
- `launchctl` not on PATH → skip auto-reload, fall through to warning  
- `XPC_SERVICE_NAME` is set but to a different label (unusual) → treat as
  launchd-managed, don't reload

**Reuse:** `crates/sshenc-cli/src/launchagent.rs` already has `plist_path()`,
`is_loaded()`, and the `launchctl` invocation pattern. Extract the bootstrap
call into a shared helper or duplicate the minimal call in `main.rs`.

- [x] `check_window_server_or_relaunch()` in `sshenc-agent/src/main.rs`:
      checks `XPC_SERVICE_NAME` (launchd child?), calls `touch_id_available()`,
      runs `launchctl bootout` + `bootstrap` if plist exists, exits 0 on success
- [x] Falls through to Mitigation 1 warning if plist missing or bootstrap fails

---

### Mitigation 3 — Distinguish "no window server" from "screen locked"

**Where:** `libenclaveapp/crates/enclaveapp-apple/swift/bridge.swift` + error
types

**What:** Currently both "screen locked" and "no window server" map to
`KeychainInteractionRequired`. They have different recovery messages:

- Screen locked: "unlock your screen and retry"
- No window server: "restart agent via launchd"

Use `CGSessionCopyCurrentDictionary()` (CoreGraphics) to distinguish:
- Returns nil → no window server session → `KeychainNoWindowServer`
- Returns dict with `CGSSessionScreenIsLocked = true` → screen locked →
  existing `KeychainInteractionRequired`
- Returns dict with screen not locked → something else failed; keep
  `KeychainInteractionRequired`

Add new error variant `KeychainNoWindowServer { label: String }` in
`enclaveapp-core/src/error.rs` with message:
```
"no window server access for '{label}': the agent must be started via launchd
for Touch ID to work. Run: launchctl load ~/Library/LaunchAgents/com.godaddy.sshenc.agent.plist"
```

Update `should_evict_lacontext` in `enclaveapp-apple/src/sign.rs` to also
suppress eviction for `KeychainNoWindowServer` (same reasoning as
`KeychainInteractionRequired`: token was 0, nothing cached to evict).

- [x] Add `import CoreGraphics` and `SE_ERR_KEYCHAIN_NO_WINDOW_SERVER = 15`
      in `bridge.swift`
- [x] In `errSecInteractionRequired` handler in `tryLoad()`, call
      `CGSessionCopyCurrentDictionary()` and return 14 vs 15 accordingly
- [x] Add `KeychainNoWindowServer { label: String }` variant to
      `enclaveapp-core/src/error.rs` with launchctl remediation message
- [x] Add rc=15 handler in `enclaveapp-apple/src/keychain_wrap.rs`
- [x] Update `should_evict_lacontext` in `enclaveapp-apple/src/sign.rs` to
      include `KeychainNoWindowServer`
- [x] `sshenc-agent/src/server.rs` already logs error strings verbatim —
      the new message surfaces automatically

---

### Mitigation 4 — `sshenc agent` and `sshenc install` detect and fix a rogue agent

**Where:** `sshenc-cli/src/commands.rs`, macOS-only

**What:** When `sshenc agent` or `sshenc install` runs and finds an agent
already listening on the socket, check whether it's the launchd-managed instance
by comparing the listening process's PID against the PID reported by
`launchctl list com.godaddy.sshenc.agent`. If they don't match (rogue shell-
started agent):

1. Kill the rogue agent (send SIGTERM, wait up to 2s, then SIGKILL)
2. Run `launchctl bootstrap gui/$(id -u) <plist>` to start the proper one
3. Wait for the socket to become responsive (reuse the existing
   `verify_agent_responsive` logic from `sshenc-agent-proto`)
4. Print: "Replaced shell-started agent with launchd-managed instance."

If the plist doesn't exist yet (user hasn't run `sshenc install`), skip the
kill-and-reload and print a warning instead.

**How to get the PID of the process listening on the socket:** Use
`lsof -U <socket_path>` or read `/proc` (Linux) — on macOS `lsof -U` is
simplest. Alternatively, use the launchd PID directly: `launchctl list
com.godaddy.sshenc.agent` emits a PID in the first column when running; if a
process is on the socket but doesn't match that PID, it's rogue.

- [x] Add `launchd_agent_pid() -> Option<u32>` in `sshenc-cli/src/launchagent.rs`
- [x] Add `socket_listener_pid(socket: &Path) -> Option<u32>` (`lsof -U -F p`)
- [x] Add `replace_rogue_agent(socket: &Path) -> Result<bool>`: compare PIDs,
      SIGTERM→SIGKILL rogue, `launchctl bootout` + `bootstrap`, returns true
      if replacement occurred
- [x] Called from `ensure_agent_running` in `commands.rs` (macOS only, when
      agent is already running); logs replacement, returns `AgentStartStatus::Started`
- [x] `install()` in `commands.rs` calls `ensure_agent_running` indirectly —
      rogue-agent replacement fires on install as well

---

## Scope

Changes span two repositories:

| Repo | Crates touched |
|------|---------------|
| libenclaveapp | `enclaveapp-apple` (Swift bridge + Rust), `enclaveapp-core` (error types) |
| sshenc | `sshenc-agent` (main.rs), `sshenc-cli` (commands.rs, launchagent.rs) |

libenclaveapp changes land first (Mitigations 1 partial, 3); sshenc changes
follow once the new libenclaveapp is on `main` and CI is green.

## Implementation Order

1. **libenclaveapp PR**: Mitigation 3 (new error variant + CGSession check) +
   Mitigation 1 FFI function (`enclaveapp_se_touch_id_available`)
2. **sshenc PR**: Mitigation 1 probe in agent startup + Mitigation 2
   auto-reload + Mitigation 4 CLI rogue-agent detection

These can be done in a single PR each since they're logically coupled within
each repo.

## Out of Scope

- Windows / Linux: no Touch ID, no window server concept; these mitigations
  are all `#[cfg(target_os = "macos")]`
- Mitigation 5 (permanent `KeychainAuthDenied` ACL fix): requires user
  interaction in Keychain Access; no code path can recover automatically.
  Already handled: `should_evict_lacontext` suppresses the retry loop, and
  the error message names the cause.
