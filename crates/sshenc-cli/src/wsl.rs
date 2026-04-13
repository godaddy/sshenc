// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! WSL (Windows Subsystem for Linux) integration.
//!
//! When `sshenc install` runs on Windows, it detects installed WSL distros
//! and configures them for sshenc via the shared enclaveapp-wsl library.

#![cfg(target_os = "windows")]

use enclaveapp_wsl::install::WslInstallConfig;

fn make_config() -> WslInstallConfig {
    WslInstallConfig {
        app_name: "sshenc".to_string(),
        shell_block: r#"# sshenc: Bridge WSL to Windows sshenc-agent via named pipe relay.
# All SSH operations (ssh, git, scp, sftp) use the Windows TPM keys.
if command -v socat >/dev/null 2>&1 && command -v npiperelay.exe >/dev/null 2>&1; then
    export SSH_AUTH_SOCK="$HOME/.sshenc/agent.sock"
    _sshenc_pid="$HOME/.sshenc/bridge.pid"
    # Start bridge if not already running (atomic check via pid file)
    if [ ! -S "$SSH_AUTH_SOCK" ] || ! kill -0 "$(cat "$_sshenc_pid" 2>/dev/null)" 2>/dev/null; then
        mkdir -p "$HOME/.sshenc"
        rm -f "$SSH_AUTH_SOCK"
        socat UNIX-LISTEN:"$SSH_AUTH_SOCK",fork \
            EXEC:"npiperelay.exe -ei -s //./pipe/openssh-ssh-agent" &
        echo $! > "$_sshenc_pid"
        disown 2>/dev/null
    fi
    unset _sshenc_pid
else
    # Fallback: at least git works via Windows SSH
    export GIT_SSH_COMMAND="/mnt/c/Windows/System32/OpenSSH/ssh.exe"
fi"#
        .to_string(),
        install_bridge_deps: true,
        linux_binary_path: None,
        linux_binary_target: None,
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
