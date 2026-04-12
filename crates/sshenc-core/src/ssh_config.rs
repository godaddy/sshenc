// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! SSH config file management for sshenc install/uninstall.
//!
//! Manages a comment-delimited block in `~/.ssh/config` that configures
//! `IdentityAgent` to point at the sshenc agent socket for all hosts.

use crate::error::Result;
use std::path::Path;

const BEGIN_MARKER: &str = "# BEGIN sshenc managed block -- do not edit";
const END_MARKER: &str = "# END sshenc managed block";

/// Result of an install operation.
#[derive(Debug, PartialEq, Eq)]
pub enum InstallResult {
    Installed,
    AlreadyPresent,
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
    Ok(content.contains(BEGIN_MARKER))
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
    // Ensure parent directory exists with 0700 permissions
    if let Some(parent) = ssh_config_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
            }
        }
    }

    let content = if ssh_config_path.exists() {
        std::fs::read_to_string(ssh_config_path)?.replace("\r\n", "\n")
    } else {
        String::new()
    };

    if content.contains(BEGIN_MARKER) {
        return Ok(InstallResult::AlreadyPresent);
    }

    // Quote paths in case they contain spaces
    let socket_str = socket_path.display().to_string();
    let socket_quoted = if socket_str.contains(' ') {
        format!("\"{socket_str}\"")
    } else {
        socket_str
    };
    let mut lines = format!("{BEGIN_MARKER}\nHost *\n    IdentityAgent {socket_quoted}\n");
    if let Some(dylib) = dylib_path {
        let dylib_str = dylib.display().to_string();
        let dylib_quoted = if dylib_str.contains(' ') {
            format!("\"{dylib_str}\"")
        } else {
            dylib_str
        };
        lines.push_str(&format!("    PKCS11Provider {dylib_quoted}\n"));
    }
    lines.push_str(&format!("{END_MARKER}\n"));
    let block = lines;

    let mut new_content = content;
    // Ensure existing content ends with newline
    if !new_content.is_empty() && !new_content.ends_with('\n') {
        new_content.push('\n');
    }
    // Add blank separator line if there's existing content
    if !new_content.is_empty() {
        new_content.push('\n');
    }
    new_content.push_str(&block);

    std::fs::write(ssh_config_path, &new_content)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(ssh_config_path, std::fs::Permissions::from_mode(0o644))?;
    }

    Ok(InstallResult::Installed)
}

/// Remove the sshenc managed block from the SSH config file.
///
/// Removes everything between (and including) the BEGIN and END markers,
/// plus any single blank line immediately before the block.
pub fn uninstall_block(ssh_config_path: &Path) -> Result<UninstallResult> {
    if !ssh_config_path.exists() {
        return Ok(UninstallResult::NotPresent);
    }

    let content = std::fs::read_to_string(ssh_config_path)?.replace("\r\n", "\n");
    if !content.contains(BEGIN_MARKER) {
        return Ok(UninstallResult::NotPresent);
    }

    let lines: Vec<&str> = content.lines().collect();
    let mut new_lines: Vec<&str> = Vec::new();
    let mut in_block = false;

    for line in &lines {
        if line.contains(BEGIN_MARKER) {
            in_block = true;
            // Remove a trailing blank line before the block
            if let Some(last) = new_lines.last() {
                if last.is_empty() {
                    new_lines.pop();
                }
            }
            continue;
        }
        if line.contains(END_MARKER) {
            in_block = false;
            continue;
        }
        if !in_block {
            new_lines.push(line);
        }
    }

    // Rebuild content
    let mut new_content = new_lines.join("\n");
    if !new_content.is_empty() {
        new_content.push('\n');
    }

    std::fs::write(ssh_config_path, &new_content)?;
    Ok(UninstallResult::Removed)
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
    fn test_install_new_file() {
        let dir = temp_dir("new-file");
        let config_path = dir.join("config");
        let socket = PathBuf::from("/tmp/.sshenc/agent.sock");

        let result = install_block(&config_path, &socket, None).unwrap();
        assert_eq!(result, InstallResult::Installed);

        let content = std::fs::read_to_string(&config_path).unwrap();
        assert!(content.contains(BEGIN_MARKER));
        assert!(content.contains("IdentityAgent /tmp/.sshenc/agent.sock"));
        assert!(content.contains(END_MARKER));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_install_existing_file() {
        let dir = temp_dir("existing-file");
        let config_path = dir.join("config");
        let socket = PathBuf::from("/tmp/.sshenc/agent.sock");

        std::fs::write(&config_path, "Host example.com\n    User jay\n").unwrap();

        let result = install_block(&config_path, &socket, None).unwrap();
        assert_eq!(result, InstallResult::Installed);

        let content = std::fs::read_to_string(&config_path).unwrap();
        assert!(content.starts_with("Host example.com"));
        assert!(content.contains(BEGIN_MARKER));
        // Blank separator line between existing content and block
        assert!(content.contains("User jay\n\n"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
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
        assert!(content.contains(BEGIN_MARKER));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
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
    fn test_uninstall() {
        let dir = temp_dir("uninstall");
        let config_path = dir.join("config");
        let socket = PathBuf::from("/tmp/.sshenc/agent.sock");

        std::fs::write(&config_path, "Host foo\n    User bar\n").unwrap();
        install_block(&config_path, &socket, None).unwrap();

        let result = uninstall_block(&config_path).unwrap();
        assert_eq!(result, UninstallResult::Removed);

        let content = std::fs::read_to_string(&config_path).unwrap();
        assert!(!content.contains(BEGIN_MARKER));
        assert!(!content.contains(END_MARKER));
        assert!(!content.contains("IdentityAgent"));
        assert!(content.contains("Host foo"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_uninstall_not_present() {
        let dir = temp_dir("uninstall-absent");
        let config_path = dir.join("config");

        std::fs::write(&config_path, "Host foo\n    User bar\n").unwrap();

        let result = uninstall_block(&config_path).unwrap();
        assert_eq!(result, UninstallResult::NotPresent);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_uninstall_missing_file() {
        let result = uninstall_block(Path::new("/nonexistent/config")).unwrap();
        assert_eq!(result, UninstallResult::NotPresent);
    }

    #[test]
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
        assert!(!content.contains(BEGIN_MARKER));
        assert!(!content.contains(END_MARKER));
        assert!(!content.contains("IdentityAgent"));
        assert!(!content.contains("PKCS11Provider"));
        assert!(content.contains("Host foo"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_install_block_empty_file_creates_new() {
        let dir = temp_dir("empty-file");
        let config_path = dir.join("config");
        let socket = PathBuf::from("/tmp/.sshenc/agent.sock");

        // File does not exist at all
        assert!(!config_path.exists());

        let result = install_block(&config_path, &socket, None).unwrap();
        assert_eq!(result, InstallResult::Installed);

        let content = std::fs::read_to_string(&config_path).unwrap();
        assert!(content.contains(BEGIN_MARKER));
        assert!(content.contains("IdentityAgent"));
        assert!(content.contains(END_MARKER));
        // No blank separator line at the start (no prior content)
        assert!(!content.starts_with('\n'));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
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
        assert!(!content.contains(BEGIN_MARKER));
        assert!(content.contains("Host foo"));
        // Should not have excessive blank lines piling up
        assert!(
            !content.contains("\n\n\n\n"),
            "should not accumulate excessive blank lines"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_is_installed_with_partial_marker_begin_only() {
        let dir = temp_dir("partial-marker");
        let config_path = dir.join("config");

        // Write a file that has BEGIN marker but no END marker (corrupted/partial)
        let content = format!(
            "Host foo\n    User bar\n\n{}\nHost *\n    IdentityAgent /tmp/sock\n",
            BEGIN_MARKER
        );
        std::fs::write(&config_path, &content).unwrap();

        // is_installed only checks for BEGIN marker, so this should return true
        assert!(is_installed(&config_path).unwrap());

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
