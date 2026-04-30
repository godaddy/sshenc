// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! WSL (Windows Subsystem for Linux) integration.
//!
//! When `sshenc install` runs on Windows, it detects installed WSL distros
//! and configures them for sshenc via the shared enclaveapp-wsl library.

#![cfg(windows)]

use enclaveapp_wsl::install::WslInstallConfig;

fn make_config() -> WslInstallConfig {
    WslInstallConfig {
        app_name: "sshenc".to_string(),
        shell_block: r#"# sshenc: pick the best available agent transport for this WSL distro.
#
# Preference order:
#   1. Native sshenc-agent installed inside the distro. The native agent
#      handles SSH-protocol traffic locally and uses the JSON-RPC TPM
#      bridge to Windows for actual signing — no SSH-protocol stream
#      traverses the WSL/Windows boundary, which avoids the
#      socat+npiperelay race that intermittently surfaces as
#      "sshenc-agent refused generate" on the GenerateKey extension.
#   2. socat + npiperelay relay to the Windows agent's named pipe.
#      Works for everyday sign / list operations; the GenerateKey
#      extension is racy under this transport.
#   3. Plain Windows SSH for git only — last-resort fallback when
#      neither option is available.
if command -v sshenc-agent >/dev/null 2>&1; then
    export SSH_AUTH_SOCK="$HOME/.sshenc/agent.sock"
    _sshenc_pid="$HOME/.sshenc/agent.pid"
    if [ ! -S "$SSH_AUTH_SOCK" ] || ! kill -0 "$(cat "$_sshenc_pid" 2>/dev/null)" 2>/dev/null; then
        mkdir -p "$HOME/.sshenc"
        rm -f "$SSH_AUTH_SOCK"
        sshenc-agent --socket "$SSH_AUTH_SOCK" >/dev/null 2>&1
    fi
    unset _sshenc_pid
elif command -v socat >/dev/null 2>&1 && command -v npiperelay.exe >/dev/null 2>&1; then
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
