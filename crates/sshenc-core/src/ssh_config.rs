// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! SSH config file management for sshenc install/uninstall.
//!
//! Manages a comment-delimited block in `~/.ssh/config` that configures
//! `IdentityAgent` to point at the sshenc agent socket for all hosts.

use crate::error::{Error, Result};
use enclaveapp_core::config_block::{self, BlockMarkers};
use enclaveapp_core::metadata::ensure_dir;
use enclaveapp_core::quoting::quote_ssh_path;
use std::path::Path;

fn markers() -> BlockMarkers {
    BlockMarkers::standard("sshenc")
}

/// Result of an install operation.
#[derive(Debug, PartialEq, Eq)]
pub enum InstallResult {
    Installed,
    AlreadyPresent,
    /// The managed block already existed but its rendered content was stale
    /// (e.g. the `PKCS11Provider` dylib path has moved); the block was
    /// rewritten with the current values.
    Repaired,
}

/// Result of an uninstall operation.
#[derive(Debug, PartialEq, Eq)]
pub enum UninstallResult {
    Removed,
    NotPresent,
}

/// Check whether the sshenc managed block is present in the SSH config file.
pub fn is_installed(ssh_config_path: &Path) -> Result<bool> {
    if !ssh_config_path.exists() {
        return Ok(false);
    }
    let content = std::fs::read_to_string(ssh_config_path)?;
    Ok(content.contains(&markers().begin))
}

/// Install the sshenc block into the SSH config file.
///
/// Adds a `Host *` block with `IdentityAgent` pointing at the sshenc agent socket,
/// and optionally a `PKCS11Provider` pointing at the launcher dylib (which auto-starts
/// the agent when SSH loads it).
///
/// Creates `~/.ssh/` and the config file if they don't exist.
/// Idempotent: returns `AlreadyPresent` if the block is already there.
pub fn install_block(
    ssh_config_path: &Path,
    socket_path: &Path,
    dylib_path: Option<&Path>,
) -> Result<InstallResult> {
    let markers = markers();

    // Ensure parent directory exists with 0700 permissions (SSH requirement).
    if let Some(parent) = ssh_config_path.parent() {
        if !parent.exists() {
            ensure_dir(parent).map_err(|e| Error::Config(e.to_string()))?;
        }
    }

    let content = config_block::read_config_file(ssh_config_path)
        .map_err(|e| Error::Config(e.to_string()))?
        .unwrap_or_default();

    // Build the SSH config body.
    let socket_quoted = quote_ssh_path(socket_path);
    let mut body = format!("Host *\n    IdentityAgent {socket_quoted}\n");
    if let Some(dylib) = dylib_path {
        let dylib_quoted = quote_ssh_path(dylib);
        body.push_str(&format!("    PKCS11Provider {dylib_quoted}\n"));
    }

    let block = config_block::build_block(&markers, &body);
    let had_block = content.contains(&markers.begin);
    let new_content = config_block::upsert_block(&content, &markers, &block);

    // If nothing would change, leave the file untouched. This keeps the
    // operation cheap and idempotent even when run repeatedly.
    if new_content == content {
        return Ok(InstallResult::AlreadyPresent);
    }

    write_ssh_config(ssh_config_path, &new_content)?;

    Ok(if had_block {
        InstallResult::Repaired
    } else {
        InstallResult::Installed
    })
}

/// Remove the sshenc managed block from the SSH config file.
///
/// Removes everything between (and including) the BEGIN and END markers,
/// plus any single blank line immediately before the block.
pub fn uninstall_block(ssh_config_path: &Path) -> Result<UninstallResult> {
    let markers = markers();

    if !ssh_config_path.exists() {
        return Ok(UninstallResult::NotPresent);
    }

    let content = config_block::read_config_file(ssh_config_path)
        .map_err(|e| Error::Config(e.to_string()))?
        .unwrap_or_default();

    if !content.contains(&markers.begin) {
        return Ok(UninstallResult::NotPresent);
    }

    // Check for BEGIN without END (malformed block).
    if config_block::find_block(&content, &markers).is_none() {
        return Err(Error::Config(format!(
            "malformed sshenc block in {}: found BEGIN marker but no END marker; refusing to modify",
            ssh_config_path.display()
        )));
    }

    let (result, status) = config_block::remove_block(&content, &markers);
    if status == config_block::BlockRemoveResult::Removed {
        write_ssh_config(ssh_config_path, &result)?;
    }

    Ok(UninstallResult::Removed)
}

/// Write the SSH config file with appropriate permissions (0o644 on Unix).
///
/// SSH config files need to be world-readable (unlike secrets which use 0o600),
/// because `~/.ssh/config` is a configuration file, not a private key.
fn write_ssh_config(path: &Path, content: &str) -> Result<()> {
    enclaveapp_core::metadata::atomic_write(path, content.as_bytes())
        .map_err(|e| Error::Config(e.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))?;
    }
    #[cfg(not(unix))]
    {
        // On Windows, leave default file permissions — OpenSSH and other
        // processes need to read ~/.ssh/config.  The parent directory
        // (~/.ssh/) already inherits restrictive ACLs from the user profile.
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sshenc-test-{}-{name}", std::process::id()));
        drop(std::fs::remove_dir_all(&dir));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O + libc::chmod not supported by Miri
    fn test_install_new_file() {
        let dir = temp_dir("new-file");
        let config_path = dir.join("config");
        let socket = PathBuf::from("/tmp/.sshenc/agent.sock");

        let result = install_block(&config_path, &socket, None).unwrap();
        assert_eq!(result, InstallResult::Installed);

        let content = std::fs::read_to_string(&config_path).unwrap();
        assert!(content.contains(&markers().begin));
        assert!(content.contains("IdentityAgent /tmp/.sshenc/agent.sock"));
        assert!(content.contains(&markers().end));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O + libc::chmod not supported by Miri
    fn test_install_existing_file() {
        let dir = temp_dir("existing-file");
        let config_path = dir.join("config");
        let socket = PathBuf::from("/tmp/.sshenc/agent.sock");

        std::fs::write(&config_path, "Host example.com\n    User jay\n").unwrap();

        let result = install_block(&config_path, &socket, None).unwrap();
        assert_eq!(result, InstallResult::Installed);

        let content = std::fs::read_to_string(&config_path).unwrap();
        assert!(content.starts_with("Host example.com"));
        assert!(content.contains(&markers().begin));
        // Blank separator line between existing content and block
        assert!(content.contains("User jay\n\n"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O
    fn test_install_ignores_preexisting_legacy_tmp_file() {
        let dir = temp_dir("stale-tmp");
        let config_path = dir.join("config");
        let socket = PathBuf::from("/tmp/.sshenc/agent.sock");

        std::fs::write(dir.join(".config.tmp"), "stale").unwrap();

        let result = install_block(&config_path, &socket, None).unwrap();
        assert_eq!(result, InstallResult::Installed);
        assert!(std::fs::read_to_string(&config_path)
            .unwrap()
            .contains("IdentityAgent /tmp/.sshenc/agent.sock"));
        assert_eq!(
            std::fs::read_to_string(dir.join(".config.tmp")).unwrap(),
            "stale"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O + libc::chmod not supported by Miri
    fn test_install_no_trailing_newline() {
        let dir = temp_dir("no-trailing-nl");
        let config_path = dir.join("config");
        let socket = PathBuf::from("/tmp/.sshenc/agent.sock");

        std::fs::write(&config_path, "Host foo\n    User bar").unwrap(); // no trailing newline

        let result = install_block(&config_path, &socket, None).unwrap();
        assert_eq!(result, InstallResult::Installed);

        let content = std::fs::read_to_string(&config_path).unwrap();
        // Should have added newline before the block
        assert!(!content.contains("bar#"));
        assert!(content.contains(&markers().begin));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O + libc::chmod not supported by Miri
    fn test_install_idempotent() {
        let dir = temp_dir("idempotent");
        let config_path = dir.join("config");
        let socket = PathBuf::from("/tmp/.sshenc/agent.sock");

        install_block(&config_path, &socket, None).unwrap();
        let content_after_first = std::fs::read_to_string(&config_path).unwrap();

        let result = install_block(&config_path, &socket, None).unwrap();
        assert_eq!(result, InstallResult::AlreadyPresent);

        let content_after_second = std::fs::read_to_string(&config_path).unwrap();
        assert_eq!(content_after_first, content_after_second);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O + libc::chmod not supported by Miri
    fn test_uninstall() {
        let dir = temp_dir("uninstall");
        let config_path = dir.join("config");
        let socket = PathBuf::from("/tmp/.sshenc/agent.sock");

        std::fs::write(&config_path, "Host foo\n    User bar\n").unwrap();
        install_block(&config_path, &socket, None).unwrap();

        let result = uninstall_block(&config_path).unwrap();
        assert_eq!(result, UninstallResult::Removed);

        let content = std::fs::read_to_string(&config_path).unwrap();
        assert!(!content.contains(&markers().begin));
        assert!(!content.contains(&markers().end));
        assert!(!content.contains("IdentityAgent"));
        assert!(content.contains("Host foo"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O not supported under Miri isolation
    fn test_uninstall_not_present() {
        let dir = temp_dir("uninstall-absent");
        let config_path = dir.join("config");

        std::fs::write(&config_path, "Host foo\n    User bar\n").unwrap();

        let result = uninstall_block(&config_path).unwrap();
        assert_eq!(result, UninstallResult::NotPresent);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O not supported under Miri isolation
    fn test_uninstall_missing_file() {
        let result = uninstall_block(Path::new("/nonexistent/config")).unwrap();
        assert_eq!(result, UninstallResult::NotPresent);
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O + libc::chmod not supported by Miri
    fn test_is_installed() {
        let dir = temp_dir("is-installed");
        let config_path = dir.join("config");
        let socket = PathBuf::from("/tmp/.sshenc/agent.sock");

        assert!(!is_installed(&config_path).unwrap());

        install_block(&config_path, &socket, None).unwrap();
        assert!(is_installed(&config_path).unwrap());

        uninstall_block(&config_path).unwrap();
        assert!(!is_installed(&config_path).unwrap());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O + libc::chmod not supported by Miri
    fn test_install_creates_parent_dir() {
        let dir = temp_dir("creates-parent");
        let ssh_dir = dir.join("newssh");
        let config_path = ssh_dir.join("config");
        let socket = PathBuf::from("/tmp/.sshenc/agent.sock");

        assert!(!ssh_dir.exists());
        install_block(&config_path, &socket, None).unwrap();
        assert!(ssh_dir.exists());
        assert!(config_path.exists());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O + libc::chmod not supported by Miri
    fn test_install_with_dylib_path() {
        let dir = temp_dir("with-dylib");
        let config_path = dir.join("config");
        let socket = PathBuf::from("/tmp/.sshenc/agent.sock");
        let dylib = PathBuf::from("/usr/local/lib/sshenc-launcher.dylib");

        let result = install_block(&config_path, &socket, Some(&dylib)).unwrap();
        assert_eq!(result, InstallResult::Installed);

        let content = std::fs::read_to_string(&config_path).unwrap();
        assert!(content.contains("IdentityAgent /tmp/.sshenc/agent.sock"));
        assert!(content.contains("PKCS11Provider /usr/local/lib/sshenc-launcher.dylib"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O + libc::chmod not supported by Miri
    fn test_install_without_dylib_path() {
        let dir = temp_dir("without-dylib");
        let config_path = dir.join("config");
        let socket = PathBuf::from("/tmp/.sshenc/agent.sock");

        let result = install_block(&config_path, &socket, None).unwrap();
        assert_eq!(result, InstallResult::Installed);

        let content = std::fs::read_to_string(&config_path).unwrap();
        assert!(content.contains("IdentityAgent /tmp/.sshenc/agent.sock"));
        assert!(!content.contains("PKCS11Provider"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O + libc::chmod not supported by Miri
    fn test_uninstall_removes_block_with_dylib() {
        let dir = temp_dir("uninstall-dylib");
        let config_path = dir.join("config");
        let socket = PathBuf::from("/tmp/.sshenc/agent.sock");
        let dylib = PathBuf::from("/usr/local/lib/sshenc-launcher.dylib");

        std::fs::write(&config_path, "Host foo\n    User bar\n").unwrap();
        install_block(&config_path, &socket, Some(&dylib)).unwrap();

        // Verify PKCS11Provider was written
        let content = std::fs::read_to_string(&config_path).unwrap();
        assert!(content.contains("PKCS11Provider"));

        // Uninstall should remove the entire block including PKCS11Provider
        let result = uninstall_block(&config_path).unwrap();
        assert_eq!(result, UninstallResult::Removed);

        let content = std::fs::read_to_string(&config_path).unwrap();
        assert!(!content.contains(&markers().begin));
        assert!(!content.contains(&markers().end));
        assert!(!content.contains("IdentityAgent"));
        assert!(!content.contains("PKCS11Provider"));
        assert!(content.contains("Host foo"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O + libc::chmod not supported by Miri
    fn test_install_block_empty_file_creates_new() {
        let dir = temp_dir("empty-file");
        let config_path = dir.join("config");
        let socket = PathBuf::from("/tmp/.sshenc/agent.sock");

        // File does not exist at all
        assert!(!config_path.exists());

        let result = install_block(&config_path, &socket, None).unwrap();
        assert_eq!(result, InstallResult::Installed);

        let content = std::fs::read_to_string(&config_path).unwrap();
        assert!(content.contains(&markers().begin));
        assert!(content.contains("IdentityAgent"));
        assert!(content.contains(&markers().end));
        // No blank separator line at the start (no prior content)
        assert!(!content.starts_with('\n'));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O + libc::chmod not supported by Miri
    fn test_install_repairs_stale_dylib_path() {
        let dir = temp_dir("repair-dylib");
        let config_path = dir.join("config");
        let socket = PathBuf::from("/tmp/.sshenc/agent.sock");
        let old_dylib = PathBuf::from("/opt/homebrew/lib/libsshenc_pkcs11.dylib");
        let new_dylib = PathBuf::from("/Users/dev/sshenc/target/release/libsshenc_pkcs11.dylib");

        let first = install_block(&config_path, &socket, Some(&old_dylib)).unwrap();
        assert_eq!(first, InstallResult::Installed);
        let content_first = std::fs::read_to_string(&config_path).unwrap();
        assert!(content_first.contains("/opt/homebrew/lib/libsshenc_pkcs11.dylib"));

        // Re-running with a different dylib path should rewrite the block.
        let second = install_block(&config_path, &socket, Some(&new_dylib)).unwrap();
        assert_eq!(second, InstallResult::Repaired);

        let content_second = std::fs::read_to_string(&config_path).unwrap();
        assert!(
            !content_second.contains("/opt/homebrew/lib/libsshenc_pkcs11.dylib"),
            "stale dylib path should be gone"
        );
        assert!(content_second.contains(&new_dylib.display().to_string()));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O + libc::chmod not supported by Miri
    fn test_install_repairs_by_dropping_dylib_when_gone() {
        let dir = temp_dir("repair-drop-dylib");
        let config_path = dir.join("config");
        let socket = PathBuf::from("/tmp/.sshenc/agent.sock");
        let stale_dylib = PathBuf::from("/opt/homebrew/lib/libsshenc_pkcs11.dylib");

        install_block(&config_path, &socket, Some(&stale_dylib)).unwrap();

        // User rebuilt / reinstalled without a locatable dylib: second call
        // omits the PKCS11Provider line, which is a content change.
        let second = install_block(&config_path, &socket, None).unwrap();
        assert_eq!(second, InstallResult::Repaired);

        let content = std::fs::read_to_string(&config_path).unwrap();
        assert!(!content.contains("PKCS11Provider"));
        assert!(content.contains("IdentityAgent"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O + libc::chmod not supported by Miri
    fn test_install_idempotent_leaves_file_alone() {
        use std::time::SystemTime;

        let dir = temp_dir("idempotent-mtime");
        let config_path = dir.join("config");
        let socket = PathBuf::from("/tmp/.sshenc/agent.sock");
        let dylib = PathBuf::from("/opt/homebrew/lib/libsshenc_pkcs11.dylib");

        install_block(&config_path, &socket, Some(&dylib)).unwrap();
        let mtime_before = std::fs::metadata(&config_path)
            .unwrap()
            .modified()
            .unwrap_or(SystemTime::UNIX_EPOCH);

        // Sleep long enough that a rewrite would be observable.
        std::thread::sleep(std::time::Duration::from_millis(20));

        let result = install_block(&config_path, &socket, Some(&dylib)).unwrap();
        assert_eq!(result, InstallResult::AlreadyPresent);

        let mtime_after = std::fs::metadata(&config_path)
            .unwrap()
            .modified()
            .unwrap_or(SystemTime::UNIX_EPOCH);
        assert_eq!(
            mtime_before, mtime_after,
            "AlreadyPresent must not rewrite the file"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    #[cfg_attr(miri, ignore)] // libc::chmod not supported by Miri
    fn test_install_block_sets_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir("perms");
        let config_path = dir.join("config");
        let socket = PathBuf::from("/tmp/.sshenc/agent.sock");

        install_block(&config_path, &socket, None).unwrap();

        let metadata = std::fs::metadata(&config_path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "ssh config file should be 0644");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O + libc::chmod not supported by Miri
    fn test_uninstall_block_multiple_blank_lines_around_block() {
        let dir = temp_dir("multi-blanks");
        let config_path = dir.join("config");
        let socket = PathBuf::from("/tmp/.sshenc/agent.sock");

        // Write content with multiple blank lines before where the block will go
        std::fs::write(&config_path, "Host foo\n    User bar\n\n\n").unwrap();
        install_block(&config_path, &socket, None).unwrap();

        let result = uninstall_block(&config_path).unwrap();
        assert_eq!(result, UninstallResult::Removed);

        let content = std::fs::read_to_string(&config_path).unwrap();
        assert!(!content.contains(&markers().begin));
        assert!(content.contains("Host foo"));
        // Should not have excessive blank lines piling up
        assert!(
            !content.contains("\n\n\n\n"),
            "should not accumulate excessive blank lines"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O not supported under Miri isolation
    fn test_is_installed_with_partial_marker_begin_only() {
        let dir = temp_dir("partial-marker");
        let config_path = dir.join("config");

        // Write a file that has BEGIN marker but no END marker (corrupted/partial)
        let content = format!(
            "Host foo\n    User bar\n\n{}\nHost *\n    IdentityAgent /tmp/sock\n",
            markers().begin
        );
        std::fs::write(&config_path, &content).unwrap();

        // is_installed only checks for BEGIN marker, so this should return true
        assert!(is_installed(&config_path).unwrap());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_uninstall_refuses_truncated_block() {
        let dir = temp_dir("truncated-block");
        let config_path = dir.join("config");
        let content = format!(
            "Host foo\n    User bar\n\n{}\nHost *\n    IdentityAgent /tmp/sock\n",
            markers().begin
        );
        std::fs::write(&config_path, &content).unwrap();

        let result = uninstall_block(&config_path);
        assert!(result.is_err(), "should refuse to modify a truncated block");
        // Original content should be untouched
        assert_eq!(std::fs::read_to_string(&config_path).unwrap(), content);

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
