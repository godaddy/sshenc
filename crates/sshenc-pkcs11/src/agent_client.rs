// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Synchronous SSH agent protocol client.
//!
//! Connects to the sshenc-agent Unix socket and proxies PKCS#11 operations
//! as SSH agent protocol messages. Starts the agent if it's not running.

use sshenc_agent_proto::message::{self, AgentRequest, AgentResponse, Identity};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Default socket path for the agent.
fn default_socket_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".sshenc")
        .join("agent.sock")
}

/// Connection to the sshenc agent.
pub struct AgentConnection {
    stream: UnixStream,
}

impl AgentConnection {
    /// Connect to the agent, starting it if necessary.
    pub fn connect() -> Result<Self, String> {
        let socket_path = default_socket_path();

        // Try connecting first
        if let Ok(conn) = Self::try_connect(&socket_path) {
            return Ok(conn);
        }

        // Agent not running — start it
        start_agent(&socket_path)?;

        // Wait for agent to be ready (up to 5 seconds)
        for _ in 0..50 {
            std::thread::sleep(Duration::from_millis(100));
            if let Ok(conn) = Self::try_connect(&socket_path) {
                return Ok(conn);
            }
        }

        Err(format!(
            "agent failed to start at {}",
            socket_path.display()
        ))
    }

    fn try_connect(socket_path: &Path) -> Result<Self, String> {
        let stream =
            UnixStream::connect(socket_path).map_err(|e| format!("connect failed: {e}"))?;
        stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(10))).ok();
        Ok(AgentConnection { stream })
    }

    /// Request all identities from the agent.
    pub fn request_identities(&mut self) -> Result<Vec<Identity>, String> {
        let request = message::serialize_request(&AgentRequest::RequestIdentities);
        self.send_message(&request)?;
        let response_payload = self.read_message()?;
        match message::parse_response(&response_payload).map_err(|e| e.to_string())? {
            AgentResponse::IdentitiesAnswer(ids) => Ok(ids),
            AgentResponse::Failure => Ok(Vec::new()),
            other => Err(format!("unexpected response: {other:?}")),
        }
    }

    /// Request the agent to sign data with a specific key.
    pub fn sign(&mut self, key_blob: &[u8], data: &[u8], flags: u32) -> Result<Vec<u8>, String> {
        let request = message::serialize_request(&AgentRequest::SignRequest {
            key_blob: key_blob.to_vec(),
            data: data.to_vec(),
            flags,
        });
        self.send_message(&request)?;
        let response_payload = self.read_message()?;
        match message::parse_response(&response_payload).map_err(|e| e.to_string())? {
            AgentResponse::SignResponse { signature_blob } => Ok(signature_blob),
            AgentResponse::Failure => Err("agent refused to sign".into()),
            other => Err(format!("unexpected response: {other:?}")),
        }
    }

    fn send_message(&mut self, payload: &[u8]) -> Result<(), String> {
        let len = (payload.len() as u32).to_be_bytes();
        self.stream
            .write_all(&len)
            .map_err(|e| format!("write failed: {e}"))?;
        self.stream
            .write_all(payload)
            .map_err(|e| format!("write failed: {e}"))?;
        self.stream
            .flush()
            .map_err(|e| format!("flush failed: {e}"))?;
        Ok(())
    }

    fn read_message(&mut self) -> Result<Vec<u8>, String> {
        let mut len_buf = [0u8; 4];
        self.stream
            .read_exact(&mut len_buf)
            .map_err(|e| format!("read failed: {e}"))?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len == 0 || len > 256 * 1024 {
            return Err(format!("invalid message length: {len}"));
        }
        let mut buf = vec![0u8; len];
        self.stream
            .read_exact(&mut buf)
            .map_err(|e| format!("read failed: {e}"))?;
        Ok(buf)
    }
}

/// Start the sshenc-agent as a background process.
fn start_agent(socket_path: &Path) -> Result<(), String> {
    // Find the agent binary next to our dylib or in PATH
    let agent_bin = find_agent_binary()?;

    // Ensure socket directory exists
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    std::process::Command::new(&agent_bin)
        .arg("--socket")
        .arg(socket_path)
        .arg("--foreground")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to start agent ({agent_bin:?}): {e}"))?;

    Ok(())
}

/// Find the sshenc-agent binary.
fn find_agent_binary() -> Result<PathBuf, String> {
    // Check next to the dylib (same directory as the current module)
    if let Some(dir) = current_dylib_dir() {
        let candidate = dir.join("sshenc-agent");
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    // Check PATH
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

    Err("sshenc-agent not found — install it or add it to PATH".into())
}

/// Try to determine the directory containing the current dylib.
fn current_dylib_dir() -> Option<PathBuf> {
    // On macOS we can use _dyld_get_image_name to find our path,
    // but a simpler heuristic: check common install locations.
    let common = ["/usr/local/bin", "/opt/homebrew/bin"];
    for dir in &common {
        let candidate = PathBuf::from(dir).join("sshenc-agent");
        if candidate.exists() {
            return Some(PathBuf::from(dir));
        }
    }
    None
}
