// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Agent launcher for the PKCS#11 dylib.
//!
//! Starts the sshenc-agent if it's not already running. The dylib doesn't
//! serve keys or sign — it's just a boot hook to ensure the agent is up
//! before SSH tries to use IdentityAgent.

use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

fn default_socket_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".sshenc")
        .join("agent.sock")
}

/// Ensure the sshenc-agent is running. Starts it if needed.
pub fn ensure_agent_running() -> Result<(), String> {
    let socket_path = default_socket_path();

    // Already running?
    if UnixStream::connect(&socket_path).is_ok() {
        return Ok(());
    }

    // Find and start the agent
    let agent_bin = find_agent_binary()?;

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
        // Check if the agent exited immediately (e.g., crashed)
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!("agent exited immediately ({})", status));
        }
    }

    Err("agent failed to start (timeout)".into())
}

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
