# Codex Change Review Report

**Date:** 2026-04-14
**Reviewer:** Claude Opus 4.6
**Scope:** All changes from commit `7abb2b1` (PR #4 merge, 2026-04-13 ~5:55 PM) through `190e05b` (PR #12 merge, 2026-04-14 ~3:20 PM)
**Method:** Full diff review, file-by-file analysis, CI status verification

---

## Executive Summary

Codex produced **25 non-merge commits** across **8 merged PRs** (#5 through #12), touching **32 files** with **+3,756 / -1,527 lines** of changes. All PRs passed CI on all three platforms (macOS, Windows, Linux). The changes are substantial and mostly well-structured, adding significant Windows platform support, key backup safety, binary discovery, access policy improvements, and git signing integration.

However, the review identified **5 high-severity issues**, **8 medium-severity issues**, and **numerous low-severity findings** detailed below. The most critical finding is that the user verification / prompt policy feature (`PromptPolicy`) is entirely non-functional -- it is threaded through the codebase but never enforced on any platform.

---

## CI Status

All 8 merged PRs passed CI on all three platforms:

| PR | Title | macOS | Windows | Linux |
|----|-------|-------|---------|-------|
| #5 | Fix Windows SSH agent and git integration | PASS | PASS | PASS |
| #6 | Verify Windows Hello before signing with user-presence keys | PASS | PASS | PASS |
| #7 | Fix sshenc install signing and config defects | PASS | PASS | PASS |
| #8 | Make ssh key backups rollback safe | PASS | PASS | PASS |
| #9 | Fix OpenSSH agent compatibility | PASS | PASS | PASS |
| #10 | Make ssh key backups rollback safe | PASS | PASS | PASS |
| #11 | docs: refresh current workspace docs | PASS | PASS | PASS |
| #12 | Integrate access-policy and git signing improvements | PASS | PASS | PASS |

**Note:** The workspace cannot be built locally because it depends on sibling `enclaveapp-*` crates (referenced via `path = "../crates/..."`) that are not present in this checkout. All analysis was performed via diff review and reading the current source.

---

## Change Overview

### New Modules
- **`sshenc-core/src/backup.rs`** (304 lines) -- Transactional backup/rollback for key material files
- **`sshenc-core/src/bin_discovery.rs`** (295 lines) -- Trusted binary discovery without `$PATH` lookup

### Major Modifications
- **`sshenc-cli/src/commands.rs`** (+2,040 lines) -- Windows install/uninstall state machine, rollback logic, SSH wrapper, git signing, default key promotion
- **`sshenc-agent/src/main.rs`** (+331 lines) -- Daemonization rewrite with ready-file protocol, PID file management
- **`sshenc-agent/src/server.rs`** (+277 lines) -- Socket path preparation, Windows AF_UNIX bridge, prompt policy plumbing
- **`sshenc-gitenc/src/main.rs`** (+407 lines) -- Access policy validation, key metadata loading, repo configuration
- **`sshenc-cli/src/main.rs`** (+103 lines) -- Access policy CLI args, new subcommands

### API Changes
- `KeyGenOptions.requires_user_presence: bool` replaced with `KeyGenOptions.access_policy: AccessPolicy`
- `KeyMetadata::new()` signature changed to accept `AccessPolicy` instead of `bool`
- `sshenc_keys_dir()` newly exported from `sshenc-se`
- New `PromptPolicy` enum (`Always`, `Never`, `KeyDefault`) threaded through agent and CLI
- New `AccessPolicy` enum (`None`, `Any`, `Biometric`, `Password`) replaces bare bool

### Test Coverage
- **~50 new `#[test]` functions** added across the workspace
- Good coverage on backup rollback, bin discovery, Windows action validation, git signing, key promotion rollback, agent launcher lifecycle, and SSH config install/uninstall
- Notable gaps documented below

---

## High-Severity Findings

### H1. `PromptPolicy` / user verification is entirely non-functional

**Files:** `sshenc-agent/src/server.rs:445-459`, `sshenc-cli/src/commands.rs:1552-1571`

The `PromptPolicy` config field is threaded through the entire codebase (agent server, CLI ssh signing, config model) but **never actually enforces user verification on any platform**:

- **Agent server (`server.rs:445-459`):** `should_verify` is computed but when `true`, only a debug log is emitted on Windows. On macOS/Linux the `if should_verify` block compiles to nothing (the only content is `#[cfg(target_os = "windows")]`). Signing proceeds unconditionally.

- **CLI git signing (`commands.rs:1552-1571`):** `maybe_verify_user_presence()` is a no-op on all platforms. On Windows it computes `_should_prompt` (underscore-prefixed = intentionally unused) and returns `Ok(())`. On non-Windows it ignores all arguments and returns `Ok(())`.

**Impact:** Users who set `prompt_policy = "always"` in their config get zero actual protection. This is a **false sense of security** for a security-critical feature.

**Remediation:** Implement the verification on each platform. The plumbing is already correctly threaded; only the leaf verification calls are missing.

**macOS/Linux (agent server, `server.rs:445-459`):** On macOS, the Secure Enclave already enforces user presence at the hardware level for keys created with `AccessPolicy::Any` or `AccessPolicy::Biometric` -- the `SecKeyCreateSignature` call will trigger the Touch ID / password prompt natively. So the agent-side `should_verify` check is actually redundant for SE-backed keys on macOS because the backend's `.sign()` call already enforces it. Verify this is happening correctly by testing with a key created with `--access-policy any` and confirming Touch ID fires on sign. If the enclaveapp backend already handles this (likely -- that's the purpose of `AccessPolicy` being passed to `generate()`), then the agent just needs to NOT suppress the prompt. The current code is correct in that it doesn't suppress anything -- the no-op is fine because the hardware handles it.

**However**, for the software backend (Linux) and for the CLI signing path, there is no hardware enforcement. For these cases:
- In `maybe_verify_user_presence` for non-macOS Unix: implement a terminal-based confirmation prompt (`"Confirm signing (y/n)?"`) when `should_verify` is true, returning `Err` if the user declines. This is the same UX as `ssh-agent -c` (confirm mode).
- On Windows, implement verification via `enclaveapp-windows`'s Windows Hello API (which is already a dependency, see M3). Call the verification API when `should_verify` is true.

**CLI git signing (`commands.rs:1552-1571`):** The `maybe_verify_user_presence` function should call the same platform-appropriate verification. On macOS, the SE handles it during `.sign()`. On Windows, call Windows Hello verification. On Linux, prompt on stderr.

**Key insight:** The macOS path may already work correctly because the SE enforces access policy at signing time. The gap is primarily on Windows (where the `enclaveapp-windows` dep exists but isn't used) and Linux (where a software prompt is needed).

### H2. Windows daemonize doesn't forward `--labels`, `--config`, or `--debug` to child

**File:** `sshenc-agent/src/main.rs:348-358`

When daemonizing on Windows via re-exec, only `--socket` and `--_internal-daemon` are forwarded:

```rust
let mut child = std::process::Command::new(&exe)
    .arg("--socket")
    .arg(pipe_name)
    .arg("--_internal-daemon")
    // Missing: --labels, --config, --debug
```

The Unix `fork()` path inherits the parent's memory so this isn't an issue there. On Windows, any `--labels` or `--config` or `--debug` flags are silently dropped, and the daemon child uses defaults.

**Impact:** Windows users who start the agent with `--labels work,personal` will get an agent that serves all keys, not just the specified ones. This is a **security-relevant** data leak.

**Remediation:** In the `daemonize` function on Windows (`sshenc-agent/src/main.rs:338`), forward all relevant CLI args to the child process. Collect the original `Cli` struct fields and re-serialize them:

```rust
let mut cmd = std::process::Command::new(&exe);
cmd.arg("--socket").arg(pipe_name).arg("--_internal-daemon");
if cli.debug { cmd.arg("--debug"); }
if let Some(ref config) = cli.config { cmd.arg("--config").arg(config); }
if !cli.labels.is_empty() { cmd.arg("--labels").arg(cli.labels.join(",")); }
```

This requires passing the `Cli` struct (or its relevant fields) into `daemonize`. The function signature should change from `fn daemonize(pipe_name: &str)` to `fn daemonize(cli: &Cli)`. Add a test that constructs a `Cli` with labels/config/debug set and verifies the child command includes all of them.

### H3. Backup files are never cleaned up on success

**File:** `sshenc-core/src/backup.rs:54-74`

When `with_existing_key_material_backup` succeeds (the `Ok(value)` arm at line 65), the `.bak` backup files are never removed. There is no `BackupPlan::cleanup()` method and no `Drop` implementation. On each successful keygen that overwrites existing keys, orphaned `.bak` files containing **old key material** accumulate on disk in `~/.ssh/` with predictable names (`{filename}.{pid}.{nanos}.bak`).

**Impact:** Old private key material persists on disk indefinitely in a key management tool.

**Remediation:** Add a `cleanup` method to `BackupPlan` that removes backup files, and call it on the success path:

```rust
impl BackupPlan {
    pub fn cleanup(&self) {
        for entry in &self.entries {
            let _ = std::fs::remove_file(&entry.backup);
        }
    }
}
```

Then in `with_existing_key_material_backup`, call `plan.cleanup()` before returning `Ok`:

```rust
match operation() {
    Ok(value) => {
        plan.cleanup();
        Ok(value)
    }
    Err(operation) => match plan.restore() { ... }
}
```

Also add a test that verifies `.bak` files do not exist after a successful operation. The callers in `sshenc-keygen-cli/src/main.rs` and `sshenc-cli/src/main.rs` that print "Existing SSH key pair will be backed up" should clarify that the backup is temporary and only survives if the operation fails.

### H4. `/tmp` fallback when home directory is unset

**Files:** `sshenc-core/src/config.rs:82,104,165,169`, `sshenc-agent/src/main.rs:57,71`

Multiple locations fall back to `/tmp` when `dirs::home_dir()` returns `None`:

```rust
dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"))
```

On multi-user systems where `$HOME` is unset, the socket path becomes `/tmp/.sshenc/agent.sock`, and the config file goes to `/tmp/.config/sshenc/config.toml`. `/tmp` is world-writable, making these paths vulnerable to symlink attacks or preemptive directory creation by other users.

**Remediation:** Replace every `dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"))` with a function that returns `Result`:

```rust
fn require_home_dir() -> Result<PathBuf> {
    dirs::home_dir().ok_or_else(|| anyhow!("could not determine home directory; set $HOME"))
}
```

Apply this in `config.rs` (default paths), `sshenc-agent/src/main.rs` (default socket/pid paths), and `sshenc-core/src/ssh_config.rs`. There are ~6 call sites. Each currently uses `unwrap_or_else` with `/tmp`; change them to propagate the error. This is a straightforward find-and-replace. The agent's `default_socket_or_pipe()` and `default_pid_path()` need to become fallible (return `Result<String>` / `Result<PathBuf>`), which requires updating `Cli`'s `default_value_t` to use a builder pattern or a sentinel value.

### H5. `dylib_path` not backslash-normalized on Windows in SSH config

**File:** `sshenc-core/src/ssh_config.rs:73-89`

The socket path correctly gets backslash-to-forward-slash replacement on Windows (line 74-75), but the `dylib_path` for `PKCS11Provider` does not. The comment at lines 70-72 explains that OpenSSH's config parser treats backslashes as escape characters, mangling `\\.\pipe\...` into `\.\pipe\...`. The same mangling would apply to any `PKCS11Provider` path containing backslashes.

**Note:** This is currently mitigated because PKCS#11 is skipped on Windows (`dylib_path` is always `None` on Windows). But the code is incorrect if this guard is ever removed.

**Remediation:** Apply the same `replace('\\', "/")` treatment to the dylib path. In `ssh_config.rs:82-88`:

```rust
let dylib_str = dylib.display().to_string();
#[cfg(target_os = "windows")]
let dylib_str = dylib_str.replace('\\', "/");
```

This is a one-line fix. Even though the Windows codepath currently skips PKCS#11, fixing it now prevents a latent bug.

---

## Medium-Severity Findings

### M1. Rollback error masking in `backup_existing_files`

**File:** `sshenc-core/src/backup.rs:99-101`

If `rename` fails and then `rollback_backups` also fails, the rollback error is propagated (via `?`) and the original rename error is discarded. The caller never learns what actually went wrong. This is inconsistent with `with_existing_key_material_backup` which preserves both errors in `BackupExecutionError::Rollback`.

**Remediation:** Preserve both errors. Replace the `?` on `rollback_backups` with explicit error handling that wraps both:

```rust
if let Err(err) = std::fs::rename(path, &backup) {
    if let Err(rollback_err) = rollback_backups(&entries) {
        return Err(Error::from(format!(
            "backup failed: {err}; rollback also failed: {rollback_err}"
        )));
    }
    return Err(err.into());
}
```

### M2. `rollback_backups` fails fast instead of best-effort

**File:** `sshenc-core/src/backup.rs:112-124`

If restoring entry N fails (the `?` returns early), entries 0..N-1 remain un-restored. For a rollback function, best-effort semantics (continue restoring remaining entries, collect all errors) would be safer.

**Remediation:** Collect errors and continue:

```rust
fn rollback_backups(entries: &[FileBackup]) -> Result<()> {
    let mut errors = Vec::new();
    for entry in entries.iter().rev() {
        if !entry.backup.exists() { continue; }
        if entry.original.exists() {
            if let Err(e) = std::fs::remove_file(&entry.original) {
                errors.push(format!("{}: {e}", entry.original.display()));
                continue;
            }
        }
        if let Err(e) = std::fs::rename(&entry.backup, &entry.original) {
            errors.push(format!("{}: {e}", entry.original.display()));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(Error::from(format!("rollback failures: {}", errors.join("; "))))
    }
}
```

### M3. Unused `enclaveapp-windows` dependency in sshenc-agent

**File:** `sshenc-agent/Cargo.toml`

`enclaveapp-windows` was added as a Windows dependency but is never imported or used in either `main.rs` or `server.rs`. The `should_verify` block only logs -- it doesn't call any Windows verification API.

**Remediation:** This dependency was added to support H1 (user verification on Windows). Implement the Windows Hello verification in the `should_verify` block in `server.rs:452-458` using this crate's verification API. Once the verification code is in place, the dependency is justified. See H1 remediation for the implementation approach.

### M4. Windows AF_UNIX bridge thread swallows all errors silently

**File:** `sshenc-agent/src/server.rs:300-348`

The `handle_blocking_connection` function returns silently on any error (read, parse, or handling). Unlike `handle_connection` which logs "connection error", the blocking handler produces zero diagnostics, making debugging Git Bash/MINGW SSH issues very difficult.

**Remediation:** Add `tracing::warn!` calls matching the async handler's pattern:

```rust
Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return,
Err(e) => { tracing::warn!("unix socket connection error: {e}"); return; }
```

Apply to all four silent `Err(_) => return` sites in `handle_blocking_connection` (lines ~317, 327, 333, 338).

### M5. `requires_user_presence` can desync from `access_policy` on deserialization

**File:** `sshenc-core/src/key.rs:122-125`

Both `access_policy` and `requires_user_presence` are serialized. `requires_user_presence` is computed from `access_policy` in `new()`, but on deserialization both are read independently with no validation. Manually-edited JSON with `access_policy: "none"` and `requires_user_presence: true` would produce an inconsistent `KeyMetadata`.

**Remediation:** Mark `requires_user_presence` as derived, not independently serialized:

```rust
#[serde(skip)]
pub requires_user_presence: bool,
```

Then add a custom `Deserialize` impl or a `#[serde(default)]` with a post-deserialize fixup. The simplest approach: implement `serde::Deserialize` manually for `KeyMetadata` that derives `requires_user_presence` from `access_policy` after reading all fields. Alternatively, keep `#[serde(skip)]` and add `#[serde(default)]` so the field defaults to `false`, then add a `fn fixup(&mut self)` that sets `requires_user_presence = access_policy != AccessPolicy::None`, and call it after every deserialization point.

### M6. No symlink resolution in "trusted" binary discovery

**File:** `sshenc-core/src/bin_discovery.rs:97-98`

The function is named "trusted binary" discovery but performs no symlink resolution. On Unix, `is_file()` follows symlinks, so a symlink in a trusted directory pointing to an attacker-controlled location would pass validation. No ownership checks are performed either.

**Remediation:** Add `canonicalize()` and verify the resolved path is still within a trusted directory:

```rust
fn is_trusted_binary_candidate(path: &Path) -> bool {
    let resolved = match path.canonicalize() {
        Ok(p) => p,
        Err(_) => return false,
    };
    resolved.is_file() && candidate_looks_executable(&resolved)
}
```

Optionally, on Unix, check that the file is owned by root or the current user (`metadata.uid() == 0 || metadata.uid() == libc::getuid()`). This prevents a scenario where a non-root user plants a binary in a world-writable directory that happens to be in the candidate list (unlikely given the current hardcoded dirs, but defense in depth).

### M7. `restrict_file_permissions` on Windows SSH config may break OpenSSH

**File:** `sshenc-core/src/ssh_config.rs:165-168`

On non-Unix platforms, `write_ssh_config` calls `restrict_file_permissions` which sets restrictive ACLs. This may prevent OpenSSH from reading `~/.ssh/config` on Windows if the SSH process runs under a different user context.

**Remediation:** On Windows, `~/.ssh/config` should be readable by the current user and SYSTEM (the account OpenSSH's agent service runs under). Replace the `restrict_file_permissions` call in the `#[cfg(not(unix))]` block with a no-op or a Windows-specific function that sets the ACL to allow the current user + SYSTEM read access. The simplest fix: just remove the `#[cfg(not(unix))]` block entirely -- on Windows, the default file permissions (inherited from parent directory) are typically correct for `~/.ssh/config`.

### M8. `install()` function has deeply nested duplicated rollback logic

**File:** `sshenc-cli/src/commands.rs:780-945`

The `install()` function is ~165 lines with 4 nested rollback points on Windows, each repeating similar rollback sequences. The same check-uninstall-restore pattern appears at lines 813-831, 851-878, and 901-924. This should use an RAII guard or be refactored to avoid duplication and reduce audit surface.

**Remediation:** Create an `InstallGuard` struct that tracks what has been done and rolls back on `Drop` if not explicitly committed:

```rust
struct InstallGuard {
    ssh_config_installed: bool,
    ssh_config_path: PathBuf,
    windows_state: Option<WindowsInstallState>,
    committed: bool,
}

impl Drop for InstallGuard {
    fn drop(&mut self) {
        if self.committed { return; }
        if self.ssh_config_installed {
            let _ = sshenc_core::ssh_config::uninstall_block(&self.ssh_config_path);
        }
        #[cfg(target_os = "windows")]
        if let Some(ref state) = self.windows_state {
            let _ = restore_windows_state_with(state, apply_windows_actions, remove_windows_install_state);
        }
    }
}
```

Then `install()` becomes linear: create the guard, do each step, and call `guard.committed = true` at the end. Each step just sets a flag on the guard. Errors propagate naturally via `?` and the guard handles cleanup. This eliminates all four duplicated rollback blocks.

---

## Low-Severity Findings

### L1. Dead `#[cfg(target_os = "windows")]` inside non-Windows function

**File:** `sshenc-cli/src/commands.rs:952-953`

`find_launcher_dylib()` is gated with `#[cfg(not(target_os = "windows"))]`, but contains an inner `#[cfg(target_os = "windows")]` binding for `lib_name`. This is dead code that can never be compiled.

**Remediation:** Remove the `#[cfg(target_os = "windows")]` block inside the function. The function is already non-Windows; the Windows lib name is unreachable.

### L2. `parse_sc_running_state` relies on fragile substring matching

**File:** `sshenc-cli/src/commands.rs:346-360`

The check `normalized.contains("STATE")` also matches lines containing `START_TYPE`. Works in practice because `START_TYPE` lines don't contain "RUNNING" or "STOPPED", but the logic is fragile. `starts_with("STATE")` after trimming would be more robust.

**Remediation:** Change `normalized.contains("STATE")` to check for `STATE` as a standalone token. Simplest: `normalized.trim_start().starts_with("STATE")` or split on whitespace and check if the first token is `"STATE"`.

### L3. `default_ssh_dir()` redundantly loads config in `ssh_wrapper`

**File:** `sshenc-cli/src/commands.rs:1114,1194`

`ssh_wrapper` calls `Config::load_default()` on line 1185, then `default_ssh_dir()` on line 1194 which calls `Config::load_default()` again. The config file is parsed twice unnecessarily.

**Remediation:** Use `config.pub_dir` directly instead of calling `default_ssh_dir()`. Replace line 1194 `let ssh_dir = default_ssh_dir()?;` with `let ssh_dir = config.pub_dir.clone();`.

### L4. `sc config` argument format may not be canonical

**File:** `sshenc-cli/src/commands.rs:279`

Arguments passed as `["config", service, "start=", mode]` with `start=` and value as separate array elements. Windows `sc.exe` is permissive about this, but the canonical form is `"start=disabled"` as one string.

**Remediation:** Combine into one argument: `command_output("sc", &["config", service, &format!("start={}", mode.as_sc_value())])`. Verify on a Windows machine that this works identically.

### L5. Signature path construction is unnecessarily convoluted

**File:** `sshenc-cli/src/commands.rs:1606-1618`

The `sig_path` is computed with `with_extension`, then immediately recomputed with `format!` for the no-extension case. The simpler `format!("{}.sig", data_file.display())` produces the correct result in both cases.

**Remediation:** Replace lines 1606-1618 with: `let sig_path = PathBuf::from(format!("{}.sig", sign_args.data_file.display()));`

### L6. Missing `~/.cargo/bin` in Unix candidate dirs

**File:** `sshenc-core/src/bin_discovery.rs:64-72`

The Unix candidate directory list includes `/opt/homebrew/bin` (macOS-specific) on all non-Windows platforms, but omits `~/.cargo/bin` -- the most likely install path for a Rust tool installed via `cargo install`.

**Remediation:** Add `home_dir.join(".cargo").join("bin")` to the Unix candidate list, after `~/.local/bin` and before the system paths. This covers the `cargo install` case without introducing a PATH lookup.

### L7. TOCTOU race on backup path uniqueness

**File:** `sshenc-core/src/backup.rs:126-137`

`unique_backup_path` generates a path using PID + nanosecond timestamp with no existence check. Collision risk is extremely low but for a security tool, `O_EXCL`-style semantics would be more robust.

**Remediation:** Add a loop with a counter suffix that retries if the path exists:

```rust
fn unique_backup_path(path: &Path) -> PathBuf {
    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("backup");
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
    for attempt in 0..100 {
        let candidate = if attempt == 0 {
            path.with_file_name(format!("{file_name}.{pid}.{nanos}.bak"))
        } else {
            path.with_file_name(format!("{file_name}.{pid}.{nanos}.{attempt}.bak"))
        };
        if !candidate.exists() { return candidate; }
    }
    path.with_file_name(format!("{file_name}.{pid}.{nanos}.bak")) // fallback
}
```

### L8. `sshenc-core` doc comment claims "no platform-specific code"

**File:** `sshenc-core/src/lib.rs:6-7`

The crate description says "This crate contains no platform-specific code" but now contains `#[cfg(unix)]`, `#[cfg(windows)]`, and `#[cfg(target_os)]` blocks in `bin_discovery.rs`, `ssh_config.rs`, and `config.rs`.

**Remediation:** Update the doc comment in `sshenc-core/src/lib.rs:6-7` to reflect reality: "This crate provides foundational types and platform-aware utilities used across all other sshenc crates."

### L9. Windows named pipe name conflicts with OpenSSH agent

**File:** `sshenc-agent/src/main.rs:66`

Default Windows named pipe `\\.\pipe\openssh-ssh-agent` is the same pipe the Windows OpenSSH agent uses. If the Windows ssh-agent service is running, sshenc-agent will fail to bind with a generic error.

**Remediation:** This is intentional design (sshenc replaces the Windows ssh-agent). The `install()` function stops and disables the Windows ssh-agent service before starting sshenc-agent. The fix is better error messaging: when `ServerOptions::create` fails with a pipe-already-exists error, detect it and print "Another agent is already listening on the default pipe. Run 'sshenc install' to configure sshenc as the default agent, or use '--socket' to specify a different pipe name."

### L10. Tilde expansion only runs on `Config::load()`, not raw deserialization

**File:** `sshenc-core/src/config.rs:119-122`

`expand_paths()` is called in `Config::load()` but not during `toml::from_str()` or `serde_json::from_str()`. Internal callers who deserialize directly will get unexpanded tilde paths.

**Remediation:** Implement a custom `Deserialize` for `Config` that calls `expand_paths()` after field deserialization, or add a doc comment on `Config` warning that `Config::load()` / `Config::load_default()` must be used instead of raw deserialization. The doc comment approach is simpler and sufficient since there are currently no external consumers.

### L11. Inconsistent `#[cfg(target_os = "windows")]` vs `#[cfg(windows)]`

**File:** `sshenc-core/src/ssh_config.rs:74` vs the rest of the codebase

The codebase mixes `target_os = "windows"` and `windows`. They're functionally equivalent on current Rust targets, but the inconsistency is confusing.

**Remediation:** Standardize on `#[cfg(windows)]` and `#[cfg(unix)]` everywhere. Do a workspace-wide search-and-replace of `target_os = "windows"` to `windows`. The only exception should be where `target_os = "macos"` or `target_os = "linux"` is needed to distinguish between Unix variants.

### L12. `selected_access_policy` catch-all maps to `AccessPolicy::None`

**File:** `sshenc-cli/src/main.rs:424`

The `_ =>` catch-all arm silently maps unrecognized policy strings to `AccessPolicy::None`. While unreachable due to clap's value parser, a future refactor could silently disable access control.

**Remediation:** Replace the `_ =>` catch-all with an explicit `"none" =>` match and add `_ => bail!("unknown access policy: {value}")` as the catch-all. This makes the match exhaustive over known values and fails loudly if a new clap value is added without updating the mapping.

### L13. Redundant `AccessPolicy` import in tests

**File:** `sshenc-cli/src/commands.rs:1689`

`AccessPolicy` is imported from `enclaveapp_core` but is already in scope via `use super::*`. Only `KeyType` needs the separate import.

**Remediation:** Change `use enclaveapp_core::{AccessPolicy, KeyType};` to `use enclaveapp_core::KeyType;`.

### L14. Windows AF_UNIX bridge thread never exits cleanly

**File:** `sshenc-agent/src/server.rs:165-211`

The `std::thread` for the AF_UNIX socket bridge runs a blocking `accept()` loop. On Ctrl+C, the main loop breaks but the bridge thread continues blocking. It's never joined or signaled.

**Remediation:** Set a non-blocking accept timeout on the socket (`socket.set_nonblocking(true)` or `socket.set_read_timeout(Some(Duration::from_secs(1)))`) and use an `AtomicBool` shutdown flag. The main loop sets the flag on Ctrl+C; the bridge thread checks it after each accept timeout. Alternatively, close the socket from the main thread, which will cause the blocking `accept()` to return an error, breaking the loop.

### L15. Agent startup uses hardcoded 500ms sleep

**File:** `sshenc-cli/src/commands.rs:1188`

After spawning the agent, `ssh_wrapper` sleeps 500ms then checks. An exponential backoff would be more robust on loaded systems.

**Remediation:** Replace the single 500ms sleep with a retry loop. The agent already writes a ready-file; leverage the same `wait_for_ready_file` pattern used by the daemonize path, or implement a simpler connect-retry loop:

```rust
let mut attempts = 0;
while attempts < 5 && !agent_is_running(&config.socket_path) {
    std::thread::sleep(std::time::Duration::from_millis(100 << attempts));
    attempts += 1;
}
```

This tries at 100ms, 200ms, 400ms, 800ms, 1600ms -- total ~3.1s worst case, with fast success on the common path.

---

## Test Coverage Gaps

Functions with **zero test coverage** in the changed code:

| Function | File | Risk |
|----------|------|------|
| `install()` | `commands.rs:780` | Very high -- most complex function, 165 lines, Windows rollback logic |
| `uninstall()` | `commands.rs:1018` | High -- Windows state restoration |
| `resolve_signing_label()` | `commands.rs:1522` | Medium -- key matching logic |
| `set_identity()` | `commands.rs:1445` | Medium -- metadata mutation |
| `ssh_binary()` | `commands.rs:1118` | Low -- platform detection |
| `default_ssh_dir()` | `commands.rs:1114` | Low |
| `find_launcher_dylib()` | `commands.rs:949` | Low |
| Prompt policy enforcement | `server.rs:445` | High -- security-relevant |
| Windows daemonize arg forwarding | `main.rs:338` | High (H2 bug) |

**Tested but shallow:** The `handle_request` tests in `server.rs` only use `PromptPolicy::KeyDefault` -- no tests for `Always` or `Never` policies.

**Remediation:** Prioritize by risk:
1. **`install()` / `uninstall()`**: Extract the core logic into testable functions that accept injected dependencies (filesystem ops, Windows service calls). Use trait objects or closures for `apply_windows_actions`, `capture_windows_install_state`, etc. -- the `restore_windows_state_with` pattern already demonstrates this approach and should be extended to the full install flow.
2. **Prompt policy**: Add `handle_request` tests with `PromptPolicy::Always` on a key with `AccessPolicy::None` (should still sign, no verification needed), and `PromptPolicy::Always` on a key with `AccessPolicy::Any` (should trigger verification). Once H1 is implemented, these tests verify the behavior.
3. **`resolve_signing_label()`**: Test with a pub file matching one key, matching no keys, and matching multiple keys.
4. **`set_identity()`**: Test metadata mutation roundtrip.
5. **Windows daemonize**: Test that the constructed `Command` includes all expected args by extracting command construction into a testable function.

---

## Documentation Changes

PR #11 refreshed all workspace docs (ARCHITECTURE.md, DEVELOPMENT.md, TESTING.md, TEST_PLAN.md, SECURITY.md, THREAT_MODEL.md). These changes are largely deletions/simplifications (-794 lines, +232 lines). The docs were trimmed to be more concise.

**Notable:** The ARCHITECTURE.md and TESTING.md correctly reflect the new modules (backup, bin_discovery) and the access policy changes. The README.md was updated with platform support information.

---

## Positive Observations

1. **Consistent error handling pattern:** The Windows install/uninstall state machine properly captures pre-install state and rolls back on failure, including cascading rollback with error aggregation.

2. **Good test hygiene:** Tests use atomic test counters and PID-namespaced temp dirs to avoid flakiness from parallel execution.

3. **Clean API evolution:** The `requires_user_presence: bool` to `AccessPolicy` enum migration is a good design improvement that enables richer access policies.

4. **Security improvements:** Atomic file writes (`atomic_write`), restricted file permissions, stale socket detection, and label validation before shell command construction are all meaningful hardening.

5. **Centralized binary discovery:** Replacing ad-hoc `which`/`where` calls and PATH lookups with a centralized trusted-path-only discovery module (`bin_discovery`) is a security improvement.

6. **Backup/rollback system:** The `backup.rs` module provides a solid foundation for safe key material operations, with proper rollback ordering (LIFO).

7. **Comprehensive Windows support:** The named pipe agent, AF_UNIX bridge for MINGW SSH, Windows service management, and registry environment variable handling demonstrate thorough platform integration work.

---

## Recommendations (Priority Order)

1. **Implement H1 (PromptPolicy verification):** The plumbing is there. Implement the actual verification calls per-platform: confirm macOS SE enforces it natively, add Windows Hello verification via `enclaveapp-windows`, add terminal confirmation prompt on Linux.

2. **Fix H2 (Windows daemon arg forwarding):** Forward `--labels`, `--config`, and `--debug` to the re-exec'd child process. This is a security-relevant data leak.

3. **Fix H3 (backup cleanup):** Add `BackupPlan::cleanup()` and call it on the success path. Old key material must not persist.

4. **Fix H4 (error on missing HOME):** Return an error instead of falling back to `/tmp`.

5. **Add integration tests for `install()`/`uninstall()`:** These are the most complex and security-critical functions with zero test coverage. Mock the filesystem and Windows service operations.

6. **Refactor M8 (install rollback):** Use an `InstallGuard` RAII pattern to eliminate duplicated rollback logic.

7. **Implement prompt policy tests** covering `PromptPolicy::Always`, `Never`, and `KeyDefault` with keys of varying `AccessPolicy`.

---

## Installer Concern

### I1. `Return="check"` on uninstall custom action may block MSI uninstallation

**File:** `installer/sshenc.wxs:83`

Both install and uninstall custom actions changed from `Return="ignore"` to `Return="check"`. For install, this is an improvement (user learns about failures). For uninstall, this is risky: if `sshenc uninstall` exits non-zero (e.g., agent still running, file locked, registry error), the entire MSI uninstall will fail and roll back, leaving the user unable to uninstall the software.

**Remediation:** Keep `Return="check"` for the install action. Change the uninstall action back to `Return="ignore"` -- an uninstall must always succeed so users can remove the software. Additionally, harden `sshenc uninstall` itself to be as resilient as possible: catch and log errors from registry/service operations rather than returning non-zero, since those operations are best-effort during uninstall.

---

## Documentation Accuracy Issues

### D1. README.md omits `gpg.ssh.program` from `gitenc --config` documentation

The README shows 4 git config values being set by `gitenc --config`, but the code (`gitenc/src/main.rs:254-258`) sets 5 values including `gpg.ssh.program` pointing to the sshenc binary. This is the mechanism that enables SSH commit signing -- its absence from docs is misleading.

**Remediation:** Add `gpg.ssh.program = /path/to/sshenc` to the README's `gitenc --config` documentation block, and explain that this is what enables `ssh-keygen -Y sign` compatibility for git commit signing.

### D2. CLAUDE.md references stale architecture

CLAUDE.md still references `sshenc-ffi-apple` as a current crate, describes the old per-platform architecture rather than the `enclaveapp-*` delegation model, lists only 41 tests, and doesn't mention `sshenc-gitenc`. Since CLAUDE.md is used as LLM guidance, this staleness will cause AI assistants to generate incorrect code.

**Remediation:** Update CLAUDE.md to reflect the current architecture:
- Replace `sshenc-ffi-apple` references with the `enclaveapp-*` delegation model via `enclaveapp-app-storage`
- Add `sshenc-gitenc` to the crate listing with a description of its purpose
- Add the new modules (`backup.rs`, `bin_discovery.rs`) to the sshenc-core description
- Update the test count to reflect current state (~90+ tests across the workspace)
- Mention the `AccessPolicy` enum and `PromptPolicy` config
- Note that `sshenc-core` now contains platform-specific code in `bin_discovery.rs` and `ssh_config.rs`

### D3. THREAT_MODEL.md prompt policy values corrected

The old doc had `"key_default"` (with underscore) which would not deserialize. The new doc correctly uses `"keydefault"`. This is a legitimate bug fix.

**Remediation:** None needed -- this is a correct fix.

### D4. Significant content removed from ARCHITECTURE.md

The detailed key storage file layout, data flow sequences, CryptoKit API mapping, auth policy table, and security boundaries sections were all removed. While the new doc avoids staleness risk, these sections were valuable for security review and onboarding.

**Remediation:** Restore the key storage file layout section (what files live in `~/.sshenc/keys/` and their format), the data flow sequences (keygen, signing, identity enumeration), and the security boundaries section. Update them to reflect the current `enclaveapp-*` architecture rather than the old direct CryptoKit calls. The auth policy table should be updated to document `AccessPolicy::None`, `Any`, `Biometric`, and `Password`.

### D5. TEST_PLAN.md lost all specific test targets

The granular per-function test checklists and Miri/fuzz testing roadmap were removed. The new plan is process guidance only with no specific test cases listed.

**Remediation:** Restore the sshenc-specific test target checklists (covering `sshenc-core`, `sshenc-se`, `sshenc-agent-proto`, `sshenc-cli`, `sshenc-pkcs11`, `sshenc-gitenc`). Update them to reflect the new modules and test functions. Retain the Miri and fuzz testing roadmap sections as aspirational targets.

---

## Additional Findings from Remaining Crates

### R1. `run_with_existing_key_backup` is duplicated verbatim

**Files:** `sshenc-cli/src/main.rs:17-44` and `sshenc-keygen-cli/src/main.rs:52-79`

This ~27-line function is copy-pasted between the two binaries. It should be extracted to `sshenc-core::backup` as a convenience method.

**Remediation:** Move `run_with_existing_key_backup` into `sshenc-core::backup` as a public function. Both `sshenc-cli/src/main.rs` and `sshenc-keygen-cli/src/main.rs` should import and call the shared version. The function converts `BackupExecutionError` to `anyhow::Error`, which requires `sshenc-core` to depend on `anyhow` (it already does via `thiserror`, or the conversion can use `thiserror`-based error types). Alternatively, put it in a thin shared utility in `sshenc-core::backup` that returns the crate's own `Error` type and let callers convert to `anyhow`.

### R2. Backup messages no longer show file paths

**File:** `sshenc-keygen-cli/src/main.rs:113`

The old keygen printed source and destination paths for backups. The new code prints a generic "Existing SSH key pair will be backed up before generation" with no way for the user to find where their backup files went (they have dynamically generated names with PID + nanosecond timestamp).

**Remediation:** Have `with_existing_key_material_backup` (or `run_with_existing_key_backup`) return the `BackupPlan` alongside the operation result so callers can print the backup paths. Change the return type to include the plan:

```rust
pub fn with_existing_key_material_backup<T, E, F>(...) -> Result<(T, BackupPlan), BackupExecutionError<E>>
```

Then in the keygen CLI, after a successful operation, iterate `plan.entries()` and print each `entry.original()` -> `entry.backup()` path. Given H3's remediation (cleanup on success), this messaging should instead say "backed up to {path}, will be cleaned up on success" or just print the paths on failure only.

### R3. PKCS#11 binary discovery is a security improvement

The old PKCS#11 agent client used `which` (Unix) and `where` (Windows) to find `sshenc-agent` from `$PATH`, which is a classic binary planting / PATH injection vulnerability. The new code uses `sshenc_core::bin_discovery::find_trusted_binary` which only searches trusted install locations. This is a clear and meaningful security improvement.

**Remediation:** None needed -- this is a correct and valuable improvement.

### R4. No unit tests for `persisted_pub_file_path`

**File:** `sshenc-se/src/unified.rs:103-109`

The new `persisted_pub_file_path` method (which checks metadata for a stored pub file path before falling back to filesystem scan) has no test coverage for any of its code paths.

**Remediation:** Add three unit tests in `sshenc-se/src/unified.rs`:
1. Metadata with `pub_file_path` set to a valid string -> returns that path
2. Metadata with `pub_file_path` set to `null` -> falls through to `find_pub_file`
3. Metadata without `pub_file_path` field (old format) -> falls through to `find_pub_file`

These can use the mock backend or construct `KeyMeta` directly.

### R5. `pub_file_path: null` in metadata may cause unexpected fallback

**File:** `sshenc-se/src/unified.rs:148`

When `write_pub_path` is `None`, the code sets `pub_file_path` to `serde_json::Value::Null`. `persisted_pub_file_path` then falls through to `find_pub_file()` because `as_str()` on `Null` returns `None`. This means if someone generates a key with `--no-pub-file` but later manually creates a `.pub` file, it will be silently picked up. The design intent is unclear.

**Remediation:** Decide the intended behavior and implement it explicitly. If `null` means "no pub file was requested, don't report one": change `persisted_pub_file_path` to return `None` early when the field is present but null (check `value.is_null()` before `as_str()`). If `null` means "no pub file was requested, but discover one if it exists later": the current behavior is correct, but add a comment documenting this intent.

### R6. Cargo.lock has dual `toml` versions

Two versions of `toml` coexist: 0.8 (workspace direct) and 1.1.2 (transitive via `winresource`). Minor dependency hygiene issue, not a correctness problem.

**Remediation:** Check if `winresource` has a newer version that uses `toml` 0.8, or if there's a feature flag to avoid the `toml` dependency. If not, this is acceptable -- transitive dependency version duplication is common and doesn't affect correctness or security.
