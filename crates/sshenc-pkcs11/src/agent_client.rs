// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Agent launcher for the PKCS#11 dylib.
//!
//! Starts the sshenc-agent if it's not already running. The dylib doesn't
//! serve keys or sign — it's just a boot hook to ensure the agent is up
//! before SSH tries to use IdentityAgent.

use std::path::PathBuf;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::net::UnixStream;

#[cfg(unix)]
fn default_socket_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".sshenc")
        .join("agent.sock")
}

#[cfg(windows)]
fn default_pipe_name() -> String {
    r"\\.\pipe\sshenc-agent".to_string()
}

/// Check whether the agent is reachable.
#[cfg(unix)]
fn agent_is_reachable() -> bool {
    UnixStream::connect(default_socket_path()).is_ok()
}

#[cfg(windows)]
fn agent_is_reachable() -> bool {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&default_pipe_name())
        .is_ok()
}

/// Ensure the sshenc-agent is running. Starts it if needed.
pub fn ensure_agent_running() -> Result<(), String> {
    // Already running?
    if agent_is_reachable() {
        return Ok(());
    }

    // Find and start the agent
    let agent_bin = find_agent_binary()?;

    #[cfg(unix)]
    {
        let socket_path = default_socket_path();
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }

        let mut child = std::process::Command::new(&agent_bin)
            .arg("--socket")
            .arg(&socket_path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| format!("failed to start agent ({agent_bin:?}): {e}"))?;

        // Wait for it to be ready, checking for early exit (crash)
        for _ in 0..50 {
            std::thread::sleep(Duration::from_millis(100));
            if UnixStream::connect(&socket_path).is_ok() {
                return Ok(());
            }
            if let Ok(Some(status)) = child.try_wait() {
                return Err(format!("agent exited immediately ({})", status));
            }
        }
    }

    #[cfg(windows)]
    {
        let pipe_name = default_pipe_name();
        let mut child = std::process::Command::new(&agent_bin)
            .arg("--socket")
            .arg(&pipe_name)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| format!("failed to start agent ({agent_bin:?}): {e}"))?;

        // Wait for it to be ready, checking for early exit (crash)
        for _ in 0..50 {
            std::thread::sleep(Duration::from_millis(100));
            if agent_is_reachable() {
                return Ok(());
            }
            if let Ok(Some(status)) = child.try_wait() {
                return Err(format!("agent exited immediately ({})", status));
            }
        }
    }

    Err("agent failed to start (timeout)".into())
}

#[cfg(unix)]
fn find_agent_binary() -> Result<PathBuf, String> {
    let common = ["/opt/homebrew/bin", "/usr/local/bin"];
    for dir in &common {
        let candidate = PathBuf::from(dir).join("sshenc-agent");
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    if let Ok(output) = std::process::Command::new("which")
        .arg("sshenc-agent")
        .output()
    {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Ok(PathBuf::from(path));
            }
        }
    }

    Err("sshenc-agent not found".into())
}

#[cfg(windows)]
fn find_agent_binary() -> Result<PathBuf, String> {
    // Check common install locations
    if let Ok(program_files) = std::env::var("ProgramFiles") {
        let candidate = PathBuf::from(&program_files)
            .join("sshenc")
            .join("sshenc-agent.exe");
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    // Search PATH using `where`
    if let Ok(output) = std::process::Command::new("where")
        .arg("sshenc-agent.exe")
        .output()
    {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout)
                .lines()
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            if !path.is_empty() {
                return Ok(PathBuf::from(path));
            }
        }
    }

    Err("sshenc-agent.exe not found".into())
}
