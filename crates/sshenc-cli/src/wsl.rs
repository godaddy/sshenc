// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! WSL (Windows Subsystem for Linux) integration.
//!
//! When `sshenc install` runs on Windows, it detects installed WSL distros
//! and configures them for sshenc via the shared enclaveapp-wsl library:
//!
//! - Downloads the matching Linux release tarball from
//!   `github.com/godaddy/sshenc` (gnu / musl picked by libc detection)
//!   and extracts `sshenc`, `sshenc-agent`, `sshenc-keygen`, `gitenc`
//!   into `/usr/local/bin/`.
//! - Injects a managed `.bashrc` / `.zshrc` block that starts
//!   `sshenc-agent` on a Unix socket and points `SSH_AUTH_SOCK` at it.
//!
//! The shell block has a single transport — the native agent — and no
//! socat / npiperelay fallback. The previous fallback existed because
//! the native binary wasn't installed automatically; now that it is,
//! the fallback is dead code that only obscured the real path.

#![cfg(windows)]

use enclaveapp_wsl::install::{LinuxReleaseSpec, WslInstallConfig};

/// Tag of the matching sshenc release. Bumped per release; pinned to
/// the workspace version rather than read from `CARGO_PKG_VERSION`
/// at install time so that a `sshenc install` run from a v0.6.36
/// binary always installs v0.6.36 Linux binaries even when GitHub
/// has a newer release available.
///
/// For local development builds the version stays at the workspace
/// placeholder `0.0.0-dev` (the release pipeline patches it to the
/// real tag at build time). Don't try to download a tarball for the
/// placeholder — there's no `v0.0.0-dev` release on GitHub and the
/// install would 404 on every WSL distro. See [`is_release_build`].
const SSHENC_PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

fn is_release_build() -> bool {
    // Workspace `version = "0.0.0-dev"` is the dev placeholder; the
    // release workflow rewrites it to the actual `X.Y.Z` tag before
    // compiling. Anything that isn't the placeholder is a real build.
    !SSHENC_PKG_VERSION.contains("dev")
}

/// Convert a Windows absolute path (e.g. `C:\Users\foo\bar.exe`) to the
/// equivalent WSL path (`/mnt/c/Users/foo/bar.exe`).
///
/// Returns `None` if the path doesn't start with a recognised drive letter.
fn windows_path_to_wsl(path: &std::path::Path) -> Option<String> {
    let s = path.to_string_lossy();
    let mut chars = s.chars();
    let drive = chars.next()?.to_lowercase().next()?;
    let colon = chars.next()?;
    let sep = chars.next()?;
    if colon != ':' || sep != '\\' {
        return None;
    }
    let rest = s[3..].replace('\\', "/");
    Some(format!("/mnt/{drive}/{rest}"))
}

/// Find `sshenc-tpm-bridge.exe` next to the running binary and return its WSL
/// path.  Returns `None` if the bridge isn't present or the path can't be
/// converted (e.g. a UNC path).
fn bridge_wsl_path() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let bridge = dir.join("sshenc-tpm-bridge.exe");
    if !bridge.exists() {
        return None;
    }
    windows_path_to_wsl(&bridge)
}

fn make_config() -> WslInstallConfig {
    const AGENT_BLOCK: &str = r#"# sshenc: start the native sshenc-agent for this shell. The agent
# handles SSH-protocol traffic locally and uses the JSON-RPC TPM
# bridge to Windows for actual signing — no SSH-protocol stream
# traverses the WSL/Windows boundary, which avoids the
# socat+npiperelay race the previous transport hit on the
# GenerateKey extension.
if command -v sshenc-agent >/dev/null 2>&1; then
    export SSH_AUTH_SOCK="$HOME/.sshenc/agent.sock"
    _sshenc_pid="$HOME/.sshenc/agent.pid"
    if [ ! -S "$SSH_AUTH_SOCK" ] || ! kill -0 "$(cat "$_sshenc_pid" 2>/dev/null)" 2>/dev/null; then
        mkdir -p "$HOME/.sshenc"
        rm -f "$SSH_AUTH_SOCK"
        sshenc-agent --socket "$SSH_AUTH_SOCK" >/dev/null 2>&1
    fi
    unset _sshenc_pid
fi"#;

    // Prepend SSHENC_BRIDGE_PATH when we can locate the bridge next to the
    // current binary.  This is necessary for Scoop installs where the bridge
    // lives at a per-user path that `find_bridge` doesn't probe by default.
    // Admin installs land in well-known paths that `find_bridge` already
    // checks, so the export is redundant but harmless there.  The guard
    // (`-z`) preserves any value the user has already set manually.
    let shell_block = match bridge_wsl_path() {
        Some(bridge_path) => format!(
            "if [ -z \"$SSHENC_BRIDGE_PATH\" ]; then\n\
             \texport SSHENC_BRIDGE_PATH=\"{bridge_path}\"\n\
             fi\n\
             {AGENT_BLOCK}"
        ),
        None => AGENT_BLOCK.to_string(),
    };

    WslInstallConfig {
        app_name: "sshenc".to_string(),
        shell_block,
        linux_binary_path: None,
        linux_binary_target: None,
        // Only attempt the GitHub-release download on real release
        // builds. Dev builds (`cargo build` from a local checkout
        // without the release workflow's version-patching step)
        // would otherwise try to fetch `v0.0.0-dev` — a tag that
        // doesn't exist — and surface a noisy 404 warning on every
        // WSL distro. The shell-block injection still happens, so
        // a developer running `sshenc install` from a local build
        // gets the bashrc updated; binary installation is a no-op
        // they can do manually with the locally-built artifacts.
        auto_install_linux_release: if is_release_build() {
            Some(LinuxReleaseSpec {
                repo: "godaddy/sshenc".to_string(),
                tag: format!("v{SSHENC_PKG_VERSION}"),
                asset_gnu: "sshenc-x86_64-unknown-linux-gnu.tar.gz".to_string(),
                asset_musl: "sshenc-x86_64-unknown-linux-musl.tar.gz".to_string(),
                binaries: vec![
                    "sshenc".to_string(),
                    "sshenc-agent".to_string(),
                    "sshenc-keygen".to_string(),
                    "gitenc".to_string(),
                ],
            })
        } else {
            None
        },
    }
}

/// Configure all detected WSL distros for sshenc.
pub fn configure_wsl_distros() {
    let config = make_config();
    let results = enclaveapp_wsl::install::configure_all_distros(&config);

    if results.is_empty() {
        return;
    }

    println!();
    println!("Detected {} WSL distribution(s):", results.len());

    for result in &results {
        println!("  Configuring {}...", result.distro_name);
        match &result.outcome {
            Ok(actions) => {
                for action in actions {
                    println!("    {action}");
                }
            }
            Err(e) => {
                eprintln!("    warning: {e}");
            }
        }
    }
}

/// Remove sshenc configuration from all WSL distros.
pub fn unconfigure_wsl_distros() {
    let config = make_config();
    let results = enclaveapp_wsl::install::unconfigure_all_distros(&config);

    for result in &results {
        match &result.outcome {
            Ok(actions) => {
                for action in actions {
                    println!("    {action}");
                }
            }
            Err(e) => {
                eprintln!(
                    "warning: could not clean WSL distro {}: {e}",
                    result.distro_name
                );
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_windows_path_to_wsl_c_drive() {
        let path = Path::new(r"C:\Users\foo\scoop\apps\sshenc\current\sshenc-tpm-bridge.exe");
        assert_eq!(
            windows_path_to_wsl(path).unwrap(),
            "/mnt/c/Users/foo/scoop/apps/sshenc/current/sshenc-tpm-bridge.exe"
        );
    }

    #[test]
    fn test_windows_path_to_wsl_program_files() {
        let path = Path::new(r"C:\Program Files\sshenc\sshenc-tpm-bridge.exe");
        assert_eq!(
            windows_path_to_wsl(path).unwrap(),
            "/mnt/c/Program Files/sshenc/sshenc-tpm-bridge.exe"
        );
    }

    #[test]
    fn test_windows_path_to_wsl_d_drive() {
        let path = Path::new(r"D:\tools\sshenc\sshenc-tpm-bridge.exe");
        assert_eq!(
            windows_path_to_wsl(path).unwrap(),
            "/mnt/d/tools/sshenc/sshenc-tpm-bridge.exe"
        );
    }

    #[test]
    fn test_windows_path_to_wsl_uppercase_drive() {
        let path = Path::new(r"C:\foo\bar");
        let result = windows_path_to_wsl(path).unwrap();
        // Drive letter is lowercased
        assert!(result.starts_with("/mnt/c/"));
    }

    #[test]
    fn test_windows_path_to_wsl_non_windows_path_returns_none() {
        let path = Path::new("/usr/local/bin/sshenc");
        assert!(windows_path_to_wsl(path).is_none());
    }

    #[test]
    fn test_make_config_has_app_name() {
        let config = make_config();
        assert_eq!(config.app_name, "sshenc");
    }

    #[test]
    fn test_make_config_shell_block_contains_agent_start() {
        let config = make_config();
        assert!(config.shell_block.contains("sshenc-agent"));
        assert!(config.shell_block.contains("SSH_AUTH_SOCK"));
    }
}
