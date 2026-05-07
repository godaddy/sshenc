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
    /// Any shell we don't know how to edit. The install path
    /// should print a manual-config hint to stderr and skip the
    /// rc-file write.
    Unknown,
}

/// Detect the user's shell from `$SHELL`. Falls back to
/// [`Shell::Unknown`] for any unrecognized value (including a
/// completely missing `$SHELL`).
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
    match basename {
        "zsh" => Shell::Zsh,
        "bash" => Shell::Bash,
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
        Shell::Unknown => None,
    }
}

/// Body of the snippet we write into the rc file. Conditional on
/// the agent socket existing so the file is harmless on machines
/// where the agent isn't running yet.
fn snippet_body(socket_path: &Path) -> String {
    // Use `$HOME` rather than the absolute path so the file is
    // portable across user accounts (some users sync dotfiles via
    // a homedir symlink farm).
    let socket_str = socket_path
        .strip_prefix(dirs::home_dir().unwrap_or_else(|| PathBuf::from("/")))
        .ok()
        .and_then(|p| p.to_str())
        .map(|s| format!("\"$HOME/{s}\""))
        .unwrap_or_else(|| {
            // Falls back to the absolute literal if `$HOME` doesn't
            // prefix the socket. Shouldn't happen for a default
            // install but is sound either way.
            shell_quote(socket_path.to_string_lossy().as_ref())
        });
    format!(
        "# Route SSH_AUTH_SOCK at sshenc-agent so git commit signing\n\
         # (`ssh-keygen -Y sign`) talks to the right agent. macOS's stock\n\
         # launchd ssh-agent has no sshenc-managed keys; without this,\n\
         # `git commit -S` fails with \"No private key found for public key\".\n\
         # ~/.ssh/config's IdentityAgent directive only covers the OpenSSH\n\
         # client (ssh, scp, sftp); ssh-keygen ignores it, so an env-var\n\
         # override is the cleanest fix.\n\
         if [ -S {socket_str} ]; then\n\
         \x20\x20\x20\x20export SSH_AUTH_SOCK={socket_str}\n\
         fi\n"
    )
}

/// Single-quote a string for a POSIX-shell `if [ -S ... ]` test.
/// Conservative: any embedded single quote turns into the canonical
/// `'\''` escape sequence.
fn shell_quote(s: &str) -> String {
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
    let result = install_block(&rc, socket_path)?;
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
pub fn install_block(rc_path: &Path, socket_path: &Path) -> Result<InstallResult> {
    let markers = markers();

    let content = match std::fs::read_to_string(rc_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(Error::Config(e.to_string())),
    };

    let body = snippet_body(socket_path);
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

    #[test]
    fn shell_quote_basic() {
        assert_eq!(shell_quote("/tmp/sock"), "'/tmp/sock'");
    }

    #[test]
    fn shell_quote_embedded_single_quote() {
        assert_eq!(shell_quote("o'malley"), "'o'\\''malley'");
    }

    #[test]
    fn snippet_body_uses_home_when_socket_under_home() {
        let home = dirs::home_dir().unwrap();
        let body = snippet_body(&home.join(".sshenc/agent.sock"));
        assert!(
            body.contains("\"$HOME/.sshenc/agent.sock\""),
            "expected $HOME-rooted path in body:\n{body}"
        );
    }

    #[test]
    fn install_block_writes_guarded_snippet_when_rc_missing() {
        let dir = tempdir();
        let rc = dir.join(".zshrc");
        let result =
            install_block(&rc, &dirs::home_dir().unwrap().join(".sshenc/agent.sock")).unwrap();
        assert_eq!(result, InstallResult::Installed);
        let content = std::fs::read_to_string(&rc).unwrap();
        assert!(content.contains("BEGIN sshenc"));
        assert!(content.contains("END sshenc"));
        assert!(content.contains("SSH_AUTH_SOCK"));
        cleanup(&dir);
    }

    #[test]
    fn install_block_is_idempotent() {
        let dir = tempdir();
        let rc = dir.join(".zshrc");
        let socket = dirs::home_dir().unwrap().join(".sshenc/agent.sock");
        install_block(&rc, &socket).unwrap();
        let result = install_block(&rc, &socket).unwrap();
        assert_eq!(result, InstallResult::AlreadyPresent);
        cleanup(&dir);
    }

    #[test]
    fn install_block_repairs_stale_socket_path() {
        let dir = tempdir();
        let rc = dir.join(".zshrc");
        install_block(&rc, &dirs::home_dir().unwrap().join(".sshenc/old.sock")).unwrap();
        let result =
            install_block(&rc, &dirs::home_dir().unwrap().join(".sshenc/agent.sock")).unwrap();
        assert_eq!(result, InstallResult::Repaired);
        let content = std::fs::read_to_string(&rc).unwrap();
        assert!(content.contains("agent.sock"));
        assert!(!content.contains("old.sock"));
        cleanup(&dir);
    }

    #[test]
    fn uninstall_removes_block() {
        let dir = tempdir();
        let rc = dir.join(".zshrc");
        install_block(&rc, &dirs::home_dir().unwrap().join(".sshenc/agent.sock")).unwrap();
        let result = uninstall_block(&rc).unwrap();
        assert_eq!(result, UninstallResult::Removed);
        let content = std::fs::read_to_string(&rc).unwrap();
        assert!(!content.contains("BEGIN sshenc"));
        assert!(!content.contains("SSH_AUTH_SOCK"));
        cleanup(&dir);
    }

    #[test]
    fn uninstall_on_missing_file_is_not_present() {
        let dir = tempdir();
        let rc = dir.join(".zshrc");
        let result = uninstall_block(&rc).unwrap();
        assert_eq!(result, UninstallResult::NotPresent);
        cleanup(&dir);
    }

    #[test]
    fn uninstall_on_file_without_block_is_not_present() {
        let dir = tempdir();
        let rc = dir.join(".zshrc");
        std::fs::write(&rc, "alias ll='ls -l'\n").unwrap();
        let result = uninstall_block(&rc).unwrap();
        assert_eq!(result, UninstallResult::NotPresent);
        let content = std::fs::read_to_string(&rc).unwrap();
        assert_eq!(content, "alias ll='ls -l'\n");
        cleanup(&dir);
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
