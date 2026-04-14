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
    r"\\.\pipe\openssh-ssh-agent".to_string()
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
        .open(default_pipe_name())
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
    sshenc_core::bin_discovery::find_trusted_binary("sshenc-agent")
        .ok_or_else(|| "sshenc-agent not found in trusted install locations".into())
}

#[cfg(windows)]
fn find_agent_binary() -> Result<PathBuf, String> {
    sshenc_core::bin_discovery::find_trusted_binary("sshenc-agent.exe")
        .ok_or_else(|| "sshenc-agent.exe not found in trusted install locations".into())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    #[cfg(unix)]
    fn test_default_socket_path_format() {
        let path = default_socket_path();
        let path_str = path.to_string_lossy();
        assert!(
            path_str.ends_with(".sshenc/agent.sock"),
            "expected path ending with .sshenc/agent.sock, got: {path_str}"
        );
        // Should be an absolute path
        assert!(path.is_absolute(), "socket path should be absolute");
    }

    #[test]
    #[cfg(unix)]
    fn test_default_socket_path_under_home() {
        let path = default_socket_path();
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
        assert!(
            path.starts_with(&home),
            "socket path should be under home dir: {} vs {}",
            path.display(),
            home.display()
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_agent_is_reachable_returns_false_when_no_agent() {
        // No agent should be running on the default socket during tests.
        // If one happens to be running, this test is still valid (it just returns true).
        // We verify it doesn't panic.
        let _reachable = agent_is_reachable();
    }

    #[test]
    #[cfg(unix)]
    fn test_find_agent_binary_does_not_panic() {
        // find_agent_binary should either return Ok with a path or Err with a message.
        // It should never panic.
        let result = find_agent_binary();
        match result {
            Ok(path) => {
                // If found, the path should be non-empty and absolute
                assert!(
                    path.is_absolute(),
                    "agent binary path should be absolute: {}",
                    path.display()
                );
            }
            Err(msg) => {
                assert!(
                    msg.contains("not found"),
                    "error should indicate not found: {msg}"
                );
            }
        }
    }

    #[test]
    #[cfg(unix)]
    fn test_ensure_agent_running_returns_error_or_ok() {
        // This test verifies ensure_agent_running doesn't panic.
        // It may return Ok (agent already running) or Err (can't find/start agent).
        let result = ensure_agent_running();
        // We don't assert success/failure since it depends on the environment,
        // but we verify it returns a valid Result.
        match result {
            Ok(()) => {} // Agent was already running or started successfully
            Err(msg) => {
                // Should be a descriptive error message
                assert!(!msg.is_empty(), "error message should not be empty");
            }
        }
    }
}
