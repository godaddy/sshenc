// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Trusted sshenc binary discovery helpers.

use std::path::PathBuf;

#[cfg(windows)]
use std::io::Read;

#[derive(Debug, Clone, Default)]
struct BinaryDiscoveryContext {
    current_exe: Option<PathBuf>,
    home_dir: Option<PathBuf>,
    #[cfg(windows)]
    local_app_data: Option<PathBuf>,
    #[cfg(windows)]
    program_files: Option<PathBuf>,
    #[cfg(windows)]
    program_files_x86: Option<PathBuf>,
}

impl BinaryDiscoveryContext {
    fn current() -> Self {
        Self {
            current_exe: std::env::current_exe().ok(),
            home_dir: dirs::home_dir(),
            #[cfg(windows)]
            local_app_data: std::env::var_os("LOCALAPPDATA").map(PathBuf::from),
            #[cfg(windows)]
            program_files: std::env::var_os("ProgramFiles").map(PathBuf::from),
            #[cfg(windows)]
            program_files_x86: std::env::var_os("ProgramFiles(x86)").map(PathBuf::from),
        }
    }
}

fn candidate_dirs(context: &BinaryDiscoveryContext) -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    if let Some(current_exe) = context.current_exe.as_ref() {
        if let Some(parent) = current_exe.parent() {
            dirs.push(parent.to_path_buf());
        }
    }

    #[cfg(windows)]
    {
        if let Some(local_app_data) = context.local_app_data.as_ref() {
            dirs.push(local_app_data.join("sshenc").join("bin"));
        }
        if let Some(program_files) = context.program_files.as_ref() {
            dirs.push(program_files.join("sshenc"));
            dirs.push(program_files.join("sshenc").join("bin"));
        }
        if let Some(program_files_x86) = context.program_files_x86.as_ref() {
            dirs.push(program_files_x86.join("sshenc"));
            dirs.push(program_files_x86.join("sshenc").join("bin"));
        }
    }

    #[cfg(not(windows))]
    {
        if let Some(home_dir) = context.home_dir.as_ref() {
            dirs.push(home_dir.join(".local").join("bin"));
        }
        dirs.push(PathBuf::from("/opt/homebrew/bin"));
        dirs.push(PathBuf::from("/usr/local/bin"));
        dirs.push(PathBuf::from("/usr/bin"));
    }

    let mut unique_dirs = Vec::new();
    for dir in dirs {
        if !unique_dirs.iter().any(|existing| existing == &dir) {
            unique_dirs.push(dir);
        }
    }
    unique_dirs
}

fn find_trusted_binary_with_context(
    binary_name: &str,
    context: &BinaryDiscoveryContext,
) -> Option<PathBuf> {
    candidate_dirs(context)
        .into_iter()
        .map(|dir| dir.join(binary_name))
        .find(|candidate| is_trusted_binary_candidate(candidate))
}

pub fn find_trusted_binary(binary_name: &str) -> Option<PathBuf> {
    find_trusted_binary_with_context(binary_name, &BinaryDiscoveryContext::current())
}

fn is_trusted_binary_candidate(path: &std::path::Path) -> bool {
    path.is_file() && candidate_looks_executable(path)
}

#[cfg(unix)]
fn candidate_looks_executable(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    std::fs::metadata(path)
        .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(windows)]
fn candidate_looks_executable(path: &std::path::Path) -> bool {
    path.extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
        && has_pe_header(path)
}

#[cfg(windows)]
fn has_pe_header(path: &std::path::Path) -> bool {
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let mut header = [0_u8; 2];
    file.read_exact(&mut header).is_ok() && header == *b"MZ"
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_dir(name: &str) -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "sshenc-bin-discovery-test-{}-{}-{name}",
            std::process::id(),
            id
        ));
        let _unused = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_test_binary(path: &std::path::Path) {
        #[cfg(unix)]
        {
            std::fs::write(path, b"#!/bin/sh\nexit 0\n").unwrap();
            let mut permissions = std::fs::metadata(path).unwrap().permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(path, permissions).unwrap();
        }

        #[cfg(windows)]
        {
            std::fs::write(path, b"MZtest-binary").unwrap();
        }
    }

    #[test]
    fn discovery_prefers_current_exe_sibling() {
        let root = test_dir("sibling");
        let bin_dir = root.join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        let current_exe = bin_dir.join("sshenc");
        let sibling = bin_dir.join("sshenc-agent");
        write_test_binary(&current_exe);
        write_test_binary(&sibling);

        let context = BinaryDiscoveryContext {
            current_exe: Some(current_exe.clone()),
            home_dir: Some(root.join("home")),
            #[cfg(windows)]
            local_app_data: Some(root.join("LocalAppData")),
            #[cfg(windows)]
            program_files: Some(root.join("ProgramFiles")),
            #[cfg(windows)]
            program_files_x86: Some(root.join("ProgramFilesX86")),
        };

        assert_eq!(
            find_trusted_binary_with_context("sshenc-agent", &context).as_deref(),
            Some(sibling.as_path())
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn discovery_uses_known_install_dirs_without_path_lookup() {
        let root = test_dir("known-dirs");
        #[cfg(windows)]
        let trusted = root
            .join("LocalAppData")
            .join("sshenc")
            .join("bin")
            .join("sshenc.exe");
        #[cfg(not(windows))]
        let trusted = root.join("home").join(".local").join("bin").join("sshenc");
        std::fs::create_dir_all(trusted.parent().unwrap()).unwrap();
        write_test_binary(&trusted);

        let context = BinaryDiscoveryContext {
            current_exe: None,
            home_dir: Some(root.join("home")),
            #[cfg(windows)]
            local_app_data: Some(root.join("LocalAppData")),
            #[cfg(windows)]
            program_files: Some(root.join("ProgramFiles")),
            #[cfg(windows)]
            program_files_x86: Some(root.join("ProgramFilesX86")),
        };

        #[cfg(windows)]
        let binary_name = "sshenc.exe";
        #[cfg(not(windows))]
        let binary_name = "sshenc";

        assert_eq!(
            find_trusted_binary_with_context(binary_name, &context).as_deref(),
            Some(trusted.as_path())
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn discovery_skips_non_executable_file_and_falls_back() {
        let root = test_dir("invalid-file");
        #[cfg(not(windows))]
        let invalid = root.join("home").join(".local").join("bin").join("sshenc");
        #[cfg(windows)]
        let invalid = root
            .join("LocalAppData")
            .join("sshenc")
            .join("bin")
            .join("sshenc.exe");
        std::fs::create_dir_all(invalid.parent().unwrap()).unwrap();
        std::fs::write(&invalid, b"not-an-executable").unwrap();

        let fallback_dir = root.join("current-bin");
        std::fs::create_dir_all(&fallback_dir).unwrap();
        #[cfg(not(windows))]
        let current_exe = fallback_dir.join("sshenc");
        #[cfg(windows)]
        let current_exe = fallback_dir.join("sshenc.exe");
        #[cfg(not(windows))]
        let fallback = fallback_dir.join("sshenc-agent");
        #[cfg(windows)]
        let fallback = fallback_dir.join("sshenc-agent.exe");
        write_test_binary(&current_exe);
        write_test_binary(&fallback);

        let context = BinaryDiscoveryContext {
            current_exe: Some(current_exe),
            home_dir: Some(root.join("home")),
            #[cfg(windows)]
            local_app_data: Some(root.join("LocalAppData")),
            #[cfg(windows)]
            program_files: Some(root.join("ProgramFiles")),
            #[cfg(windows)]
            program_files_x86: Some(root.join("ProgramFilesX86")),
        };

        #[cfg(not(windows))]
        let binary_name = "sshenc-agent";
        #[cfg(windows)]
        let binary_name = "sshenc-agent.exe";

        assert_eq!(
            find_trusted_binary_with_context(binary_name, &context).as_deref(),
            Some(fallback.as_path())
        );

        std::fs::remove_dir_all(&root).unwrap();
    }
}
