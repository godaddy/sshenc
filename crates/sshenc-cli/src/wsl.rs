// Copyright 2024 Jay Gowdy
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

fn make_config() -> WslInstallConfig {
    WslInstallConfig {
        app_name: "sshenc".to_string(),
        shell_block: r#"# sshenc: start the native sshenc-agent for this shell. The agent
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
fi"#
        .to_string(),
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
