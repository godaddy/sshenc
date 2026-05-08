// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Shell rc-file management for `SSH_AUTH_SOCK`.
//!
//! `sshenc install` writes a guarded snippet to the user's shell rc
//! that points `SSH_AUTH_SOCK` at the sshenc-agent socket. Without
//! it, `git commit -S` (signing via `ssh-keygen -Y sign`) talks to
//! whatever ssh-agent the OS has selected — on macOS that's
//! launchd's `/var/run/com.apple.launchd.*/Listeners`, which has no
//! sshenc keys, and the commit fails with "No private key found
//! for public key …". The `IdentityAgent` directive in
//! `~/.ssh/config` fixes the OpenSSH client side (ssh, scp, sftp)
//! but ssh-keygen ignores it — that's why we need a rc-file edit
//! too.
//!
//! Same comment-delimited block pattern as
//! [`crate::ssh_config`]. Idempotent install/uninstall.

use crate::error::{Error, Result};
use enclaveapp_core::config_block::{self, BlockMarkers};
use std::path::{Path, PathBuf};

fn markers() -> BlockMarkers {
    // Reuse the same standard marker shape ssh_config uses so the
    // visual signature in shell rc files is consistent with the
    // ssh_config block. Both render with `#` comments which is
    // exactly what shells want.
    BlockMarkers::standard("sshenc")
}

/// Detected user shell, narrowed to the families we know how to
/// edit. Anything else returns [`Shell::Unknown`] and the caller
/// prints a guidance message rather than mangling an unfamiliar
/// rc file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    Zsh,
    Bash,
    /// fish — POSIX-incompatible syntax (`set -gx`, `if/end`,
    /// builtin `test -S`).
    Fish,
    /// PowerShell 7 (cross-platform `pwsh`) and Windows PowerShell
    /// 5.1. Single variant — the only difference is the `$PROFILE`
    /// path, which `rc_path_for` resolves by probing.
    PowerShell,
    /// Any shell we don't know how to edit. The install path
    /// should print a manual-config hint to stderr and skip the
    /// rc-file write.
    Unknown,
}

/// Detect the user's shell from `$SHELL`. Falls back to
/// [`Shell::Unknown`] for any unrecognized value (including a
/// completely missing `$SHELL`).
///
/// Note on Windows: `$SHELL` is typically unset under cmd.exe and
/// PowerShell native sessions, so this returns `Unknown` there.
/// That's correct — Windows users get `SSH_AUTH_SOCK` set via the
/// persistent-user-env (`setx`) flow in the CLI, which doesn't
/// rely on shell-rc edits.
pub fn detect_shell_from_env() -> Shell {
    let shell_path = std::env::var_os("SHELL");
    let s = match shell_path {
        Some(s) => s.to_string_lossy().to_string(),
        None => return Shell::Unknown,
    };
    let basename = Path::new(&s)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    // Trim a trailing `.exe` so a pwsh.exe / powershell.exe value
    // (which can show up under WSL or Git Bash with PSCore on PATH)
    // matches the same arms.
    let trimmed = basename.strip_suffix(".exe").unwrap_or(basename);
    match trimmed {
        "zsh" => Shell::Zsh,
        "bash" => Shell::Bash,
        "fish" => Shell::Fish,
        "pwsh" | "powershell" => Shell::PowerShell,
        _ => Shell::Unknown,
    }
}

/// Compute the rc path for `shell` rooted at `home`. Returns `None`
/// for [`Shell::Unknown`].
///
/// - zsh → `<home>/.zshrc` (interactive shells; what
///   terminal-emulator sessions source).
/// - bash on macOS → `<home>/.bash_profile` (login shells; macOS
///   Terminal.app launches each new tab as a login shell, so this
///   is what gets sourced).
/// - bash on other Unix → `<home>/.bashrc` (interactive non-login).
/// - fish → `$XDG_CONFIG_HOME/fish/config.fish` if `XDG_CONFIG_HOME`
///   is set, else `<home>/.config/fish/config.fish`.
/// - PowerShell → probes likely `$PROFILE` paths in order:
///   1. `<home>/Documents/PowerShell/Microsoft.PowerShell_profile.ps1`
///      (PowerShell 7 on Windows; preferred default)
///   2. `<home>/Documents/WindowsPowerShell/Microsoft.PowerShell_profile.ps1`
///      (Windows PowerShell 5.1) — used only if the dir already
///      exists and the PS7 dir does not
///   3. `<home>/.config/powershell/Microsoft.PowerShell_profile.ps1`
///      (pwsh on macOS / Linux)
///
///   The "PS7 default" branch is used when no probe hits — biased
///   toward the modern install since 5.1 is end-of-life.
pub fn rc_path_for(shell: Shell, home: &Path) -> Option<PathBuf> {
    match shell {
        Shell::Zsh => Some(home.join(".zshrc")),
        Shell::Bash => {
            #[cfg(target_os = "macos")]
            {
                Some(home.join(".bash_profile"))
            }
            #[cfg(not(target_os = "macos"))]
            {
                Some(home.join(".bashrc"))
            }
        }
        Shell::Fish => Some(fish_rc_path(home)),
        Shell::PowerShell => Some(powershell_rc_path(home)),
        Shell::Unknown => None,
    }
}

fn fish_rc_path(home: &Path) -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home.join(".config"));
    base.join("fish").join("config.fish")
}

fn powershell_rc_path(home: &Path) -> PathBuf {
    let ps7 = home
        .join("Documents")
        .join("PowerShell")
        .join("Microsoft.PowerShell_profile.ps1");
    let ps51 = home
        .join("Documents")
        .join("WindowsPowerShell")
        .join("Microsoft.PowerShell_profile.ps1");
    let unix_pwsh = home
        .join(".config")
        .join("powershell")
        .join("Microsoft.PowerShell_profile.ps1");

    // Prefer the path whose parent directory already exists. PS7 is
    // checked first so a co-installed PS7 + 5.1 host writes the
    // modern profile.
    for candidate in [&ps7, &ps51, &unix_pwsh] {
        if candidate.parent().is_some_and(Path::is_dir) {
            return candidate.clone();
        }
    }

    // Nothing exists yet. On Windows default to PS7 (pwsh is the
    // recommended modern shell); elsewhere default to the Unix path.
    #[cfg(windows)]
    {
        ps7
    }
    #[cfg(not(windows))]
    {
        // ps7 and ps51 are already consumed by the probe loop
        // above (via `&` borrows that end at the loop), so they're
        // not unused — they just drop naturally at scope end here.
        unix_pwsh
    }
}

/// Body of the snippet we write into the rc file, in the syntax of
/// the target shell. Conditional on the agent socket existing so
/// the file is harmless on machines where the agent isn't running.
///
/// Returns `None` for shells with no rc-file pattern
/// ([`Shell::Unknown`] never reaches this).
fn snippet_body(shell: Shell, socket_path: &Path) -> Option<String> {
    match shell {
        Shell::Zsh | Shell::Bash => Some(posix_snippet_body(socket_path)),
        Shell::Fish => Some(fish_snippet_body(socket_path)),
        Shell::PowerShell => Some(powershell_snippet_body(socket_path)),
        Shell::Unknown => None,
    }
}

const SNIPPET_HEADER: &str = "\
# Route SSH_AUTH_SOCK at sshenc-agent so git commit signing
# (`ssh-keygen -Y sign`) talks to the right agent. macOS's stock
# launchd ssh-agent has no sshenc-managed keys; without this,
# `git commit -S` fails with \"No private key found for public key\".
# ~/.ssh/config's IdentityAgent directive only covers the OpenSSH
# client (ssh, scp, sftp); ssh-keygen ignores it, so an env-var
# override is the cleanest fix.
";

fn posix_snippet_body(socket_path: &Path) -> String {
    // Use `$HOME` rather than the absolute path so the file is
    // portable across user accounts (some users sync dotfiles via
    // a homedir symlink farm).
    let socket_str = home_relative(socket_path, "$HOME")
        .map(|s| format!("\"{s}\""))
        .unwrap_or_else(|| {
            // Falls back to the absolute literal if `$HOME` doesn't
            // prefix the socket. Shouldn't happen for a default
            // install but is sound either way.
            posix_single_quote(socket_path.to_string_lossy().as_ref())
        });
    format!(
        "{SNIPPET_HEADER}\
         if [ -S {socket_str} ]; then\n\
         \x20\x20\x20\x20export SSH_AUTH_SOCK={socket_str}\n\
         fi\n"
    )
}

fn fish_snippet_body(socket_path: &Path) -> String {
    // fish accepts `$HOME` expansion inside double-quoted strings.
    // Single-quoted strings are literal; the only escapes inside
    // them are `\\` and `\'`, which `fish_single_quote` handles.
    let socket_str = home_relative(socket_path, "$HOME")
        .map(|s| format!("\"{s}\""))
        .unwrap_or_else(|| fish_single_quote(socket_path.to_string_lossy().as_ref()));
    format!(
        "{SNIPPET_HEADER}\
         if test -S {socket_str}\n\
         \x20\x20\x20\x20set -gx SSH_AUTH_SOCK {socket_str}\n\
         end\n"
    )
}

fn powershell_snippet_body(socket_path: &Path) -> String {
    // PowerShell's `$HOME` automatic variable is set on every host
    // (Windows, macOS, Linux), so it's a portable basis for paths
    // that live under the user's home dir. Double-quoted strings
    // expand `$HOME`; single-quoted are literal (used as a
    // fall-through for non-home paths like Windows named pipes).
    let socket_str = home_relative(socket_path, "$HOME")
        .map(|s| format!("\"{s}\""))
        .unwrap_or_else(|| powershell_single_quote(socket_path.to_string_lossy().as_ref()));
    format!(
        "{SNIPPET_HEADER}\
         if (Test-Path {socket_str}) {{\n\
         \x20\x20\x20\x20$env:SSH_AUTH_SOCK = {socket_str}\n\
         }}\n"
    )
}

/// Express `path` relative to `dirs::home_dir()` using `home_var` as
/// the variable prefix (e.g. `$HOME`). Returns `None` if the path
/// isn't under home (named pipes, custom socket paths, etc.) or if
/// the resulting suffix isn't valid UTF-8.
fn home_relative(path: &Path, home_var: &str) -> Option<String> {
    let home = dirs::home_dir()?;
    let suffix = path.strip_prefix(home).ok()?.to_str()?;
    // Use forward slashes so the rendered string is stable across
    // platforms; bash/zsh/fish/PowerShell all accept them. (PowerShell
    // converts on Windows; the others are POSIX.)
    let normalized = suffix.replace('\\', "/");
    Some(format!("{home_var}/{normalized}"))
}

/// POSIX-shell single-quote: wrap in `'...'`, escape internal `'`
/// as `'\''`.
fn posix_single_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// fish single-quote: wrap in `'...'`, escape internal `'` as `\'`
/// and `\` as `\\`. (Fish single-quoted strings recognize only
/// these two escapes.)
fn fish_single_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            other => out.push(other),
        }
    }
    out.push('\'');
    out
}

/// PowerShell single-quote: wrap in `'...'`, escape internal `'`
/// as `''` (single-quoted PowerShell strings are otherwise fully
/// literal — backslashes are NOT special, which is why named-pipe
/// paths like `\\.\pipe\openssh-ssh-agent` quote cleanly).
fn powershell_single_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Result of an install operation.
#[derive(Debug, PartialEq, Eq)]
pub enum InstallResult {
    Installed,
    AlreadyPresent,
    Repaired,
    /// We knew the shell but skipped writing because we couldn't
    /// resolve a `$HOME` to root the rc file at.
    NoHome,
    /// Detected shell wasn't one we know how to edit. Caller should
    /// print a manual-config message.
    UnknownShell,
}

/// Result of an uninstall operation.
#[derive(Debug, PartialEq, Eq)]
pub enum UninstallResult {
    Removed,
    NotPresent,
    NoHome,
    UnknownShell,
}

/// Install the SSH_AUTH_SOCK snippet into the detected user shell's
/// rc file.
///
/// Idempotent: if a guarded sshenc block is already present and its
/// body matches what we'd write today, returns `AlreadyPresent`. If
/// it's stale (different socket path), returns `Repaired`.
pub fn install_for_detected_shell(socket_path: &Path) -> Result<(Shell, InstallResult)> {
    let shell = detect_shell_from_env();
    if shell == Shell::Unknown {
        return Ok((shell, InstallResult::UnknownShell));
    }
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return Ok((shell, InstallResult::NoHome)),
    };
    let rc = match rc_path_for(shell, &home) {
        Some(p) => p,
        None => return Ok((shell, InstallResult::UnknownShell)),
    };
    let result = install_block(shell, &rc, socket_path)?;
    Ok((shell, result))
}

/// Uninstall the snippet from the detected shell's rc file.
pub fn uninstall_for_detected_shell() -> Result<(Shell, UninstallResult)> {
    let shell = detect_shell_from_env();
    if shell == Shell::Unknown {
        return Ok((shell, UninstallResult::UnknownShell));
    }
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return Ok((shell, UninstallResult::NoHome)),
    };
    let rc = match rc_path_for(shell, &home) {
        Some(p) => p,
        None => return Ok((shell, UninstallResult::UnknownShell)),
    };
    let result = uninstall_block(&rc)?;
    Ok((shell, result))
}

/// Install the snippet at an explicit rc path. Exposed for testing
/// and for the rare deployment that wants to override which file
/// gets touched.
pub fn install_block(shell: Shell, rc_path: &Path, socket_path: &Path) -> Result<InstallResult> {
    let markers = markers();

    let content = match std::fs::read_to_string(rc_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(Error::Config(e.to_string())),
    };

    let body = snippet_body(shell, socket_path)
        .ok_or_else(|| Error::Config(format!("no rc-file snippet defined for shell {shell:?}")))?;
    let block = config_block::build_block(&markers, &body);
    let had_block = content.contains(&markers.begin);
    let new_content = config_block::upsert_block(&content, &markers, &block);

    if new_content == content {
        return Ok(InstallResult::AlreadyPresent);
    }

    write_rc(rc_path, &new_content)?;

    Ok(if had_block {
        InstallResult::Repaired
    } else {
        InstallResult::Installed
    })
}

/// Remove the snippet from an explicit rc path.
pub fn uninstall_block(rc_path: &Path) -> Result<UninstallResult> {
    let markers = markers();
    if !rc_path.exists() {
        return Ok(UninstallResult::NotPresent);
    }

    let content = std::fs::read_to_string(rc_path).map_err(|e| Error::Config(e.to_string()))?;
    if !content.contains(&markers.begin) {
        return Ok(UninstallResult::NotPresent);
    }

    if config_block::find_block(&content, &markers).is_none() {
        return Err(Error::Config(format!(
            "malformed sshenc block in {}: found BEGIN marker but no END marker; refusing to modify",
            rc_path.display()
        )));
    }

    let (result, status) = config_block::remove_block(&content, &markers);
    if status == config_block::BlockRemoveResult::Removed {
        write_rc(rc_path, &result)?;
    }
    Ok(UninstallResult::Removed)
}

fn write_rc(path: &Path, content: &str) -> Result<()> {
    // fish (`~/.config/fish/`) and PowerShell (`~/Documents/PowerShell/`)
    // both live under directories that may not exist on a fresh
    // user profile. atomic_write requires an existing parent — so
    // create it first. zsh / bash rcs land directly under `$HOME`
    // which always exists, so this is a no-op for those.
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent).map_err(|e| Error::Config(e.to_string()))?;
        }
    }
    // Shell rc files are normally 0o644 (the user's shell sources
    // them on every interactive session). atomic_write handles the
    // rename-into-place; we don't tighten the bits because doing
    // so would block multi-user shells that share rc files.
    enclaveapp_core::metadata::atomic_write(path, content.as_bytes())
        .map_err(|e| Error::Config(e.to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // ---- quoting helpers ---------------------------------------

    #[test]
    fn posix_single_quote_basic() {
        assert_eq!(posix_single_quote("/tmp/sock"), "'/tmp/sock'");
    }

    #[test]
    fn posix_single_quote_embedded_single_quote() {
        assert_eq!(posix_single_quote("o'malley"), "'o'\\''malley'");
    }

    #[test]
    fn fish_single_quote_basic() {
        assert_eq!(fish_single_quote("/tmp/sock"), "'/tmp/sock'");
    }

    #[test]
    fn fish_single_quote_escapes_quote_and_backslash() {
        // fish's only escapes inside single-quoted strings are `\\`
        // and `\'`. Verify both translate correctly.
        assert_eq!(fish_single_quote("o'malley"), "'o\\'malley'");
        assert_eq!(fish_single_quote("a\\b"), "'a\\\\b'");
    }

    #[test]
    fn powershell_single_quote_basic() {
        assert_eq!(powershell_single_quote("/tmp/sock"), "'/tmp/sock'");
    }

    #[test]
    fn powershell_single_quote_embedded_quote_doubles() {
        // PowerShell's single-quoted string escapes `'` as `''`.
        assert_eq!(powershell_single_quote("o'malley"), "'o''malley'");
    }

    #[test]
    fn powershell_single_quote_named_pipe_passes_through() {
        // Backslashes in single-quoted PowerShell strings are
        // literal — named-pipe paths must round-trip cleanly.
        assert_eq!(
            powershell_single_quote(r"\\.\pipe\openssh-ssh-agent"),
            r"'\\.\pipe\openssh-ssh-agent'"
        );
    }

    // ---- detection ---------------------------------------------

    /// Save / restore `$SHELL` around a closure so the test can
    /// drive `detect_shell_from_env()` deterministically without
    /// leaking state to neighboring tests. Tests that touch
    /// `$SHELL` must be marked single-threaded by acquiring the
    /// shared mutex below — Rust's test runner is multithreaded by
    /// default and `set_var` is process-global.
    fn with_shell_env<R>(value: Option<&str>, f: impl FnOnce() -> R) -> R {
        use std::sync::Mutex;
        static LOCK: Mutex<()> = Mutex::new(());
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prior = std::env::var_os("SHELL");
        match value {
            Some(v) => std::env::set_var("SHELL", v),
            None => std::env::remove_var("SHELL"),
        }
        let out = f();
        match prior {
            Some(v) => std::env::set_var("SHELL", v),
            None => std::env::remove_var("SHELL"),
        }
        out
    }

    #[test]
    fn detect_shell_recognizes_fish() {
        with_shell_env(Some("/usr/bin/fish"), || {
            assert_eq!(detect_shell_from_env(), Shell::Fish);
        });
    }

    #[test]
    fn detect_shell_recognizes_pwsh_and_powershell() {
        with_shell_env(Some("/usr/local/bin/pwsh"), || {
            assert_eq!(detect_shell_from_env(), Shell::PowerShell);
        });
        with_shell_env(Some("/usr/bin/powershell"), || {
            assert_eq!(detect_shell_from_env(), Shell::PowerShell);
        });
        // Git Bash / WSL surface a PowerShell-on-Windows install via
        // a forward-slash path with `.exe` suffix; the `.exe` trim
        // path needs to fire there. (A literal backslash path like
        // `C:\Program Files\...\pwsh.exe` is NOT a valid $SHELL on
        // Unix — `Path::file_name()` would treat the whole string
        // as a single name — so we don't test that variant; native
        // Windows users don't go through `detect_shell_from_env`.)
        with_shell_env(Some("/c/Program Files/PowerShell/7/pwsh.exe"), || {
            assert_eq!(detect_shell_from_env(), Shell::PowerShell)
        });
    }

    // ---- rc_path resolution ------------------------------------

    #[test]
    fn rc_path_for_fish_uses_xdg_when_set() {
        let dir = tempdir();
        let xdg = dir.join("xdg-config");
        std::fs::create_dir_all(&xdg).unwrap();
        // XDG_CONFIG_HOME is process-global; serialize.
        use std::sync::Mutex;
        static LOCK: Mutex<()> = Mutex::new(());
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prior = std::env::var_os("XDG_CONFIG_HOME");
        std::env::set_var("XDG_CONFIG_HOME", &xdg);
        let path = rc_path_for(Shell::Fish, Path::new("/home/u")).unwrap();
        match prior {
            Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
        assert_eq!(path, xdg.join("fish").join("config.fish"));
        cleanup(&dir);
    }

    #[test]
    fn rc_path_for_fish_falls_back_to_dot_config() {
        // Clear XDG_CONFIG_HOME so the home-relative fallback fires.
        use std::sync::Mutex;
        static LOCK: Mutex<()> = Mutex::new(());
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prior = std::env::var_os("XDG_CONFIG_HOME");
        std::env::remove_var("XDG_CONFIG_HOME");
        let path = rc_path_for(Shell::Fish, Path::new("/home/u")).unwrap();
        if let Some(v) = prior {
            std::env::set_var("XDG_CONFIG_HOME", v);
        }
        assert_eq!(path, PathBuf::from("/home/u/.config/fish/config.fish"));
    }

    #[test]
    fn rc_path_for_powershell_prefers_existing_profile_dir() {
        let dir = tempdir();
        let home = dir.join("home");
        let ps7_dir = home.join("Documents").join("PowerShell");
        std::fs::create_dir_all(&ps7_dir).unwrap();
        let path = rc_path_for(Shell::PowerShell, &home).unwrap();
        assert_eq!(
            path,
            ps7_dir.join("Microsoft.PowerShell_profile.ps1"),
            "PS7 dir exists; should be selected"
        );
        cleanup(&dir);
    }

    #[test]
    fn rc_path_for_powershell_falls_back_to_5_1_when_only_that_exists() {
        let dir = tempdir();
        let home = dir.join("home");
        let ps51_dir = home.join("Documents").join("WindowsPowerShell");
        std::fs::create_dir_all(&ps51_dir).unwrap();
        let path = rc_path_for(Shell::PowerShell, &home).unwrap();
        assert_eq!(path, ps51_dir.join("Microsoft.PowerShell_profile.ps1"));
        cleanup(&dir);
    }

    // ---- snippet_body shape ------------------------------------

    #[test]
    fn snippet_body_posix_uses_home_when_socket_under_home() {
        let home = dirs::home_dir().unwrap();
        let body = snippet_body(Shell::Zsh, &home.join(".sshenc/agent.sock")).unwrap();
        assert!(
            body.contains("\"$HOME/.sshenc/agent.sock\""),
            "expected $HOME-rooted path in body:\n{body}"
        );
        assert!(body.contains("if [ -S "));
        assert!(body.contains("export SSH_AUTH_SOCK="));
    }

    #[test]
    fn snippet_body_fish_uses_fish_syntax() {
        let home = dirs::home_dir().unwrap();
        let body = snippet_body(Shell::Fish, &home.join(".sshenc/agent.sock")).unwrap();
        assert!(
            body.contains("if test -S \"$HOME/.sshenc/agent.sock\""),
            "fish should use `if test -S` and $HOME expansion:\n{body}"
        );
        assert!(
            body.contains("set -gx SSH_AUTH_SOCK"),
            "fish should use `set -gx`:\n{body}"
        );
        assert!(body.trim_end().ends_with("end"));
        // Fish forbids POSIX `if/then/fi` and `[ -S ]` — make sure
        // we didn't accidentally render that syntax. We check for
        // the keywords at line boundaries so prose words like
        // "fix" in the comment header don't false-positive.
        assert!(!body.contains("; then"));
        assert!(!body.lines().any(|l| l.trim() == "fi"));
        assert!(!body.contains("if [ -S"));
    }

    #[test]
    fn snippet_body_powershell_uses_test_path_and_env_var() {
        let home = dirs::home_dir().unwrap();
        let body = snippet_body(Shell::PowerShell, &home.join(".sshenc/agent.sock")).unwrap();
        assert!(
            body.contains("if (Test-Path \"$HOME/.sshenc/agent.sock\")"),
            "PowerShell should use Test-Path with $HOME expansion:\n{body}"
        );
        assert!(
            body.contains("$env:SSH_AUTH_SOCK ="),
            "PowerShell should set $env:SSH_AUTH_SOCK:\n{body}"
        );
        assert!(body.contains('{') && body.contains('}'));
    }

    #[test]
    fn snippet_body_powershell_quotes_named_pipe_literally() {
        // Windows named-pipe socket path doesn't live under $HOME;
        // verify the snippet quotes it as a literal single-quoted
        // string so the backslashes pass through unchanged.
        let pipe = Path::new(r"\\.\pipe\openssh-ssh-agent");
        let body = snippet_body(Shell::PowerShell, pipe).unwrap();
        assert!(
            body.contains(r"'\\.\pipe\openssh-ssh-agent'"),
            "PowerShell named-pipe path should be a literal single-quoted string:\n{body}"
        );
    }

    // ---- install_block / uninstall_block per-shell -------------

    fn run_shell_suite(shell: Shell, rc_name: &str) {
        let socket = dirs::home_dir().unwrap().join(".sshenc/agent.sock");
        let stale = dirs::home_dir().unwrap().join(".sshenc/old.sock");

        // 1. install on missing rc → Installed, file created with
        //    markers + SSH_AUTH_SOCK.
        let dir = tempdir();
        let rc = dir.join(rc_name);
        assert_eq!(
            install_block(shell, &rc, &socket).unwrap(),
            InstallResult::Installed
        );
        let content = std::fs::read_to_string(&rc).unwrap();
        assert!(content.contains("BEGIN sshenc"));
        assert!(content.contains("END sshenc"));
        assert!(content.contains("SSH_AUTH_SOCK"));
        cleanup(&dir);

        // 2. install twice → AlreadyPresent.
        let dir = tempdir();
        let rc = dir.join(rc_name);
        install_block(shell, &rc, &socket).unwrap();
        assert_eq!(
            install_block(shell, &rc, &socket).unwrap(),
            InstallResult::AlreadyPresent
        );
        cleanup(&dir);

        // 3. install with a different socket path → Repaired and
        //    the old path is gone.
        let dir = tempdir();
        let rc = dir.join(rc_name);
        install_block(shell, &rc, &stale).unwrap();
        assert_eq!(
            install_block(shell, &rc, &socket).unwrap(),
            InstallResult::Repaired
        );
        let content = std::fs::read_to_string(&rc).unwrap();
        assert!(content.contains("agent.sock"));
        assert!(!content.contains("old.sock"));
        cleanup(&dir);

        // 4. uninstall after install → Removed and content empty
        //    of our markers.
        let dir = tempdir();
        let rc = dir.join(rc_name);
        install_block(shell, &rc, &socket).unwrap();
        assert_eq!(uninstall_block(&rc).unwrap(), UninstallResult::Removed);
        let content = std::fs::read_to_string(&rc).unwrap();
        assert!(!content.contains("BEGIN sshenc"));
        assert!(!content.contains("SSH_AUTH_SOCK"));
        cleanup(&dir);

        // 5. uninstall on missing file → NotPresent.
        let dir = tempdir();
        let rc = dir.join(rc_name);
        assert_eq!(uninstall_block(&rc).unwrap(), UninstallResult::NotPresent);
        cleanup(&dir);

        // 6. uninstall on file without our markers → NotPresent and
        //    content is preserved verbatim.
        let dir = tempdir();
        let rc = dir.join(rc_name);
        // Use a comment line — `#` is the comment char in zsh,
        // bash, fish, and PowerShell, so the same fixture works
        // for every shell.
        let foreign = "# user-managed config below\n";
        std::fs::write(&rc, foreign).unwrap();
        assert_eq!(uninstall_block(&rc).unwrap(), UninstallResult::NotPresent);
        let content = std::fs::read_to_string(&rc).unwrap();
        assert_eq!(content, foreign);
        cleanup(&dir);

        // 7. install on existing rc with foreign content preserves
        //    that content and appends the block.
        let dir = tempdir();
        let rc = dir.join(rc_name);
        std::fs::write(&rc, foreign).unwrap();
        install_block(shell, &rc, &socket).unwrap();
        let content = std::fs::read_to_string(&rc).unwrap();
        assert!(content.starts_with(foreign));
        assert!(content.contains("BEGIN sshenc"));
        cleanup(&dir);

        // 8. uninstall removes only our block, leaving foreign
        //    content untouched.
        let dir = tempdir();
        let rc = dir.join(rc_name);
        std::fs::write(&rc, foreign).unwrap();
        install_block(shell, &rc, &socket).unwrap();
        uninstall_block(&rc).unwrap();
        let content = std::fs::read_to_string(&rc).unwrap();
        assert!(content.contains(foreign));
        assert!(!content.contains("BEGIN sshenc"));
        cleanup(&dir);
    }

    #[test]
    fn shell_suite_zsh() {
        run_shell_suite(Shell::Zsh, ".zshrc");
    }

    #[test]
    fn shell_suite_bash() {
        run_shell_suite(Shell::Bash, ".bashrc");
    }

    #[test]
    fn shell_suite_fish() {
        run_shell_suite(Shell::Fish, "config.fish");
    }

    #[test]
    fn shell_suite_powershell() {
        run_shell_suite(Shell::PowerShell, "Microsoft.PowerShell_profile.ps1");
    }

    fn tempdir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sshenc-shell-env-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn cleanup(dir: &Path) {
        drop(std::fs::remove_dir_all(dir));
    }
}
