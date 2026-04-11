// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! WSL (Windows Subsystem for Linux) integration.
//!
//! When `sshenc install` runs on Windows, it detects installed WSL distros
//! and configures them for sshenc:
//!
//! Level 1: Sets GIT_SSH_COMMAND in .bashrc/.zshrc so git uses Windows SSH
//! Level 2: Sets up socat + npiperelay bridge for full ssh/scp support

#![cfg(target_os = "windows")]

use std::path::PathBuf;

/// A detected WSL distribution.
struct WslDistro {
    name: String,
    /// Path to the distro's home directory from Windows side
    /// e.g., \\wsl$\Ubuntu\home\username
    home_path: PathBuf,
}

/// The sshenc block markers for shell configs.
const BEGIN_MARKER: &str = "# BEGIN sshenc managed block -- do not edit";
const END_MARKER: &str = "# END sshenc managed block";

/// Configure all detected WSL distros for sshenc.
pub fn configure_wsl_distros() {
    let distros = detect_wsl_distros();
    if distros.is_empty() {
        return;
    }

    println!();
    println!("Detected {} WSL distribution(s):", distros.len());

    for distro in &distros {
        println!("  Configuring {}...", distro.name);
        if let Err(e) = configure_distro(distro) {
            eprintln!("    warning: {e}");
        }
    }
}

/// Remove sshenc configuration from all WSL distros.
pub fn unconfigure_wsl_distros() {
    let distros = detect_wsl_distros();
    for distro in &distros {
        if let Err(e) = unconfigure_distro(distro) {
            eprintln!("warning: could not clean WSL distro {}: {e}", distro.name);
        }
    }
}

/// Detect installed WSL distributions by running `wsl --list --quiet`.
fn detect_wsl_distros() -> Vec<WslDistro> {
    let output = match std::process::Command::new("wsl")
        .args(["--list", "--quiet"])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };

    // wsl --list outputs UTF-16LE on some Windows versions
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut distros = Vec::new();

    for line in stdout.lines() {
        let name = line.trim().trim_matches('\0').to_string();
        if name.is_empty() {
            continue;
        }

        // Find the home directory by asking WSL
        if let Some(home_path) = find_wsl_home(&name) {
            distros.push(WslDistro { name, home_path });
        }
    }

    distros
}

/// Find the WSL user's home directory path from Windows.
fn find_wsl_home(distro: &str) -> Option<PathBuf> {
    // Run `wsl -d <distro> -- echo $HOME` to get the Linux home path
    let output = std::process::Command::new("wsl")
        .args(["-d", distro, "--", "echo", "$HOME"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let linux_home = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if linux_home.is_empty() {
        return None;
    }

    // Convert Linux path to Windows UNC path: /home/user → \\wsl$\<distro>\home\user
    let win_path = format!(r"\\wsl$\{}{}", distro, linux_home.replace('/', r"\"));
    let path = PathBuf::from(&win_path);
    if path.exists() {
        Some(path)
    } else {
        // Try wsl.localhost (newer Windows versions)
        let win_path = format!(
            r"\\wsl.localhost\{}{}",
            distro,
            linux_home.replace('/', r"\")
        );
        let path = PathBuf::from(&win_path);
        if path.exists() {
            Some(path)
        } else {
            None
        }
    }
}

/// Configure a single WSL distro (Level 1 + Level 2).
fn configure_distro(distro: &WslDistro) -> Result<(), String> {
    let shell_block = generate_shell_block();

    // Configure .bashrc
    let bashrc = distro.home_path.join(".bashrc");
    if bashrc.exists() {
        inject_block(&bashrc, &shell_block).map_err(|e| format!(".bashrc: {e}"))?;
        println!("    Updated .bashrc");
    }

    // Configure .zshrc if it exists
    let zshrc = distro.home_path.join(".zshrc");
    if zshrc.exists() {
        inject_block(&zshrc, &shell_block).map_err(|e| format!(".zshrc: {e}"))?;
        println!("    Updated .zshrc");
    }

    // Install npiperelay for Level 2 (full SSH support)
    install_npiperelay(distro)?;

    Ok(())
}

/// Remove sshenc configuration from a WSL distro.
fn unconfigure_distro(distro: &WslDistro) -> Result<(), String> {
    for name in &[".bashrc", ".zshrc"] {
        let path = distro.home_path.join(name);
        if path.exists() {
            remove_block(&path).map_err(|e| format!("{name}: {e}"))?;
        }
    }
    Ok(())
}

/// Generate the shell block to inject into .bashrc/.zshrc.
fn generate_shell_block() -> String {
    format!(
        r#"{BEGIN_MARKER}
# Level 1: Git uses Windows SSH for hardware key support
export GIT_SSH_COMMAND="/mnt/c/Windows/System32/OpenSSH/ssh.exe"

# Level 2: Bridge Unix socket to Windows named pipe for full ssh/scp
if command -v socat >/dev/null 2>&1 && command -v npiperelay.exe >/dev/null 2>&1; then
    export SSH_AUTH_SOCK="$HOME/.sshenc/agent.sock"
    if [ ! -S "$SSH_AUTH_SOCK" ]; then
        mkdir -p "$HOME/.sshenc"
        (setsid socat UNIX-LISTEN:"$SSH_AUTH_SOCK",fork,unlink-early \
            EXEC:"npiperelay.exe -ei -s //./pipe/sshenc-agent" &) >/dev/null 2>&1
    fi
fi
{END_MARKER}"#
    )
}

/// Inject the sshenc block into a shell config file.
fn inject_block(path: &PathBuf, block: &str) -> Result<(), String> {
    let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;

    // Already present?
    if content.contains(BEGIN_MARKER) {
        return Ok(());
    }

    let mut new_content = content;
    if !new_content.ends_with('\n') {
        new_content.push('\n');
    }
    new_content.push('\n');
    new_content.push_str(block);
    new_content.push('\n');

    std::fs::write(path, &new_content).map_err(|e| e.to_string())
}

/// Remove the sshenc block from a shell config file.
fn remove_block(path: &PathBuf) -> Result<(), String> {
    let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    if !content.contains(BEGIN_MARKER) {
        return Ok(());
    }

    let lines: Vec<&str> = content.lines().collect();
    let mut new_lines: Vec<&str> = Vec::new();
    let mut in_block = false;

    for line in &lines {
        if line.contains(BEGIN_MARKER) {
            in_block = true;
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

    let mut result = new_lines.join("\n");
    if !result.is_empty() {
        result.push('\n');
    }
    std::fs::write(path, &result).map_err(|e| e.to_string())
}

/// Install npiperelay.exe into the WSL distro for Level 2 support.
fn install_npiperelay(distro: &WslDistro) -> Result<(), String> {
    // Check if npiperelay.exe is already accessible from WSL
    let check = std::process::Command::new("wsl")
        .args(["-d", &distro.name, "--", "command", "-v", "npiperelay.exe"])
        .output();

    if let Ok(o) = &check {
        if o.status.success() {
            println!("    npiperelay.exe already available");
            return Ok(());
        }
    }

    // Install via Go if available
    let go_install = std::process::Command::new("wsl")
        .args([
            "-d",
            &distro.name,
            "--",
            "bash",
            "-c",
            "command -v go >/dev/null 2>&1 && GOBIN=/usr/local/bin go install github.com/jstarks/npiperelay@latest 2>/dev/null && echo OK || echo NOGO",
        ])
        .output();

    if let Ok(o) = &go_install {
        let out = String::from_utf8_lossy(&o.stdout);
        if out.contains("OK") {
            println!("    Installed npiperelay.exe via Go");
            return Ok(());
        }
    }

    // Check if socat is available
    let socat_check = std::process::Command::new("wsl")
        .args(["-d", &distro.name, "--", "command", "-v", "socat"])
        .output();

    let has_socat = socat_check
        .as_ref()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !has_socat {
        println!("    note: install socat for full SSH support (apt install socat)");
    }

    println!("    note: install npiperelay for full SSH support:");
    println!("      go install github.com/jstarks/npiperelay@latest");
    println!("    or download from https://github.com/jstarks/npiperelay/releases");

    Ok(())
}
