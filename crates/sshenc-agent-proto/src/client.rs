// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Proxy secret-touching operations through a running `sshenc-agent`.
//!
//! This module is the client half of the "agent is the sole
//! keychain / Secure-Enclave / TPM toucher" contract that sshenc's
//! CLI binaries (`sshenc`, `sshenc-keygen`, `gitenc`) hold to on
//! every platform. The agent holds the wrapping-key cache, owns the
//! Apple `SecItem*` / Windows CNG / Linux keyring calls, and
//! services every write-side op over a local IPC endpoint:
//!
//! - **Unix** (macOS, Linux, WSLv2 running Linux): a Unix domain
//!   socket (`UnixStream`).
//! - **Windows** (native, Git Bash, PowerShell, cmd.exe — anything
//!   running the Windows `sshenc.exe` binary): a named pipe
//!   ([`PipeStream`](crate::pipe::PipeStream), built on
//!   `CreateFileW` + `ReadFile` / `WriteFile`).
//!
//! Three sshenc-specific extensions (`SSH_AGENTC_SSHENC_DELETE_KEY`
//! etc.) sit alongside the standard ssh-agent opcodes so the same
//! endpoint serves OpenSSH authentications and our own key-
//! management RPCs. Standard ssh-agents reply `SSH_AGENT_FAILURE`
//! to unknown opcodes, so a foreign agent on the socket won't
//! confuse us — it just falls through.

use crate::message::{
    self, AgentRequest, AgentResponse, SSH_AGENTC_REQUEST_IDENTITIES, SSH_AGENTC_SIGN_REQUEST,
    SSH_AGENTC_SSHENC_CHECK_MIGRATION_MARKER, SSH_AGENTC_SSHENC_DELETE_KEY,
    SSH_AGENTC_SSHENC_GENERATE_KEY, SSH_AGENTC_SSHENC_MIGRATE_META, SSH_AGENTC_SSHENC_RENAME_KEY,
    SSH_AGENTC_SSHENC_SET_MIGRATION_MARKER,
};
use std::io::{Read, Write};
use std::path::Path;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::net::UnixStream;

#[cfg(windows)]
use crate::pipe::PipeStream;

// Timeout for agent socket I/O operations that don't require user interaction
// (connection checks, identity listing). For signing operations that require
// Touch ID or Windows Hello, we use AGENT_SIGN_TIMEOUT instead.
const AGENT_IO_TIMEOUT: Duration = Duration::from_secs(10);

// Timeout for signing operations that require user presence verification.
// Set to 1 hour because there's no reason to timeout a user-interactive
// operation. Users should be able to take as long as they need for:
// - Noticing the Touch ID prompt
// - Retrying failed biometric attempts
// - Switching to password if biometric fails
// - Dealing with interruptions
// If the user wants to cancel, they can Ctrl+C the git command.
const AGENT_SIGN_TIMEOUT: Duration = Duration::from_secs(3600);

/// Platform-native connected stream to a running `sshenc-agent`.
/// Unix: a `UnixStream`. Windows: a `PipeStream` wrapping a named-
/// pipe `HANDLE`. Both implement [`Read`] + [`Write`] so the framing
/// helpers below don't care which OS they're on.
#[cfg(unix)]
pub type AgentStream = UnixStream;
#[cfg(windows)]
pub type AgentStream = PipeStream;

/// Make sure the `sshenc-agent` at `socket_path` is reachable. On
/// Unix, spawns the agent if its socket isn't listening (via
/// `bin_discovery` + `CreateProcess`-style fork/exec); on Windows
/// we probe the named pipe and error if the agent isn't already
/// running (auto-spawn on Windows is a Services-lifecycle problem
/// we don't tackle here — users run `sshenc install` to register
/// the agent, or `sshenc-agent.exe` manually).
///
/// Callers must not fall back to local execution on error — doing
/// so would violate the centralization invariant.
#[cfg(unix)]
pub fn ensure_agent_ready(socket_path: &Path) -> Result<(), String> {
    // Delegates to the shared helper in `enclaveapp_core::daemon`.
    // sshenc is the reference consumer of that pattern; awsenc and
    // any future enclaveapp CLI gets the same semantics (trusted
    // bin discovery, exponential readiness backoff, fixed
    // `--socket <path>` invoke shape) without reimplementing.
    enclaveapp_core::daemon::ensure_daemon_ready("sshenc-agent", "sshenc", socket_path)
        .map(|_| ())
        .map_err(|e| e.to_string())?;

    // Verify the agent is actually responding to requests, not just
    // accepting connections. The agent's socket binds and accepts
    // connections before warm_backend_identities completes, so a
    // cold-start connection racing the warmup can see an empty
    // identity list or hit the agent mid-initialization. Sending a
    // test RequestIdentities here blocks until the agent is ready
    // to serve real traffic.
    verify_agent_responsive(socket_path)
}

/// Windows readiness check: probe the named pipe. The agent on
/// Windows is typically a long-lived process started by the
/// installer (or manually via `sshenc-agent.exe --foreground`);
/// auto-spawning from the CLI would require choosing between a
/// Service, a scheduled task, or a detached console window, each
/// with its own tradeoffs. For now we surface a clear "agent isn't
/// running" error if the pipe isn't answering and let the user
/// start the agent with whatever lifecycle they prefer.
#[cfg(windows)]
pub fn ensure_agent_ready(socket_path: &Path) -> Result<(), String> {
    if !PipeStream::probe(socket_path) {
        return Err(format!(
            "sshenc-agent isn't answering on {}; start it with \
             `sshenc-agent` or ensure the sshenc-agent Service is running",
            socket_path.display()
        ));
    }

    // Verify the agent is actually responding to requests.
    verify_agent_responsive(socket_path)
}

/// Verify the agent is responding to requests by sending a test
/// `RequestIdentities`. Returns `Ok(())` if the agent replies with
/// any response (empty list is fine — we just need proof the agent
/// is serving). Returns `Err` if the connection fails or times out.
///
/// This protects against the race where git/ssh-keygen connects
/// during agent startup: the socket accepts connections before
/// `warm_backend_identities` completes, so a cold-start client can
/// see an agent that technically "works" but returns an empty
/// identity list or errors because the backend isn't initialized yet.
fn verify_agent_responsive(socket_path: &Path) -> Result<(), String> {
    tracing::debug!("verifying agent responsiveness at {}", socket_path.display());

    let mut stream = connect_agent(socket_path).ok_or_else(|| {
        let err = format!(
            "agent responsiveness check failed: could not connect to {}",
            socket_path.display()
        );
        tracing::warn!("{}", err);
        err
    })?;

    let payload = message::serialize_request(&AgentRequest::RequestIdentities);
    if send_framed(&mut stream, &payload).is_none() {
        let err = format!(
            "agent responsiveness check failed: {} accepted connection but \
             failed to handle RequestIdentities (write error)",
            socket_path.display()
        );
        tracing::warn!("{}", err);
        return Err(err);
    }

    // We don't care about the response content (empty list is fine),
    // we just need proof the agent is serving requests.
    match recv_response(&mut stream) {
        Some(_) => {
            tracing::debug!("agent responsiveness check passed");
            Ok(())
        }
        None => {
            let err = format!(
                "agent responsiveness check failed: {} did not respond to \
                 RequestIdentities (read timeout or parse error)",
                socket_path.display()
            );
            tracing::warn!("{}", err);
            Err(err)
        }
    }
}

// ───── Public entry points ─────
//
// Each entry point has two shapes:
//   - `try_*_via_agent(…)`: looks the socket up from `SSH_AUTH_SOCK`
//     (or the Windows equivalent env convention); convenient for
//     legacy callers that already expect env-driven discovery.
//   - `try_*_via_socket(sock_path, …)`: explicit socket path;
//     preferred by sshenc's own CLI because it always knows the
//     configured agent socket and doesn't want `SSH_AUTH_SOCK`
//     pointing at some other ssh-agent to steer our destructive
//     ops.

#[must_use]
pub fn try_sign_via_agent(pubkey_blob: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    let sock = env_agent_socket()?;
    try_sign_via_socket(&sock, pubkey_blob, data)
}

pub fn try_sign_via_socket(sock_path: &Path, pubkey_blob: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    tracing::debug!(
        socket = %sock_path.display(),
        blob_len = pubkey_blob.len(),
        data_len = data.len(),
        "try_sign_via_socket: starting sign request"
    );

    // Use the longer timeout for sign operations since they require user interaction
    let mut stream = match connect_agent_with_timeout(sock_path, AGENT_SIGN_TIMEOUT) {
        Some(s) => s,
        None => {
            tracing::warn!(socket = %sock_path.display(), "try_sign_via_socket: failed to connect to agent");
            return None;
        }
    };

    match agent_has_identity(&mut stream, pubkey_blob) {
        Some(true) => {
            tracing::debug!("try_sign_via_socket: identity found, proceeding to sign");
        }
        Some(false) => {
            tracing::warn!("try_sign_via_socket: no matching identity in agent");
            return None;
        }
        None => {
            tracing::warn!("try_sign_via_socket: failed to check identities");
            return None;
        }
    }

    request_signature(&mut stream, pubkey_blob, data)
}

#[must_use]
pub fn try_delete_via_agent(label: &str) -> Option<()> {
    let sock = env_agent_socket()?;
    try_delete_via_socket(&sock, label)
}

pub fn try_delete_via_socket(sock_path: &Path, label: &str) -> Option<()> {
    let mut stream = connect_agent(sock_path)?;
    request_delete(&mut stream, label)
}

#[must_use]
pub fn try_generate_via_agent(
    label: &str,
    comment: Option<&str>,
    access_policy: u32,
    presence_mode: u8,
    pub_file_path: Option<&str>,
) -> Option<Vec<u8>> {
    let sock = env_agent_socket()?;
    try_generate_via_socket(
        &sock,
        label,
        comment,
        access_policy,
        presence_mode,
        pub_file_path,
    )
}

pub fn try_generate_via_socket(
    sock_path: &Path,
    label: &str,
    comment: Option<&str>,
    access_policy: u32,
    presence_mode: u8,
    pub_file_path: Option<&str>,
) -> Option<Vec<u8>> {
    let mut stream = connect_agent(sock_path)?;
    request_generate(
        &mut stream,
        label,
        comment,
        access_policy,
        presence_mode,
        pub_file_path,
    )
}

#[must_use]
pub fn try_rename_via_agent(old_label: &str, new_label: &str) -> Option<()> {
    let sock = env_agent_socket()?;
    try_rename_via_socket(&sock, old_label, new_label)
}

pub fn try_rename_via_socket(sock_path: &Path, old_label: &str, new_label: &str) -> Option<()> {
    let mut stream = connect_agent(sock_path)?;
    request_rename(&mut stream, old_label, new_label)
}

#[must_use]
pub fn try_migrate_meta_via_agent(label: &str) -> Option<()> {
    let sock = env_agent_socket()?;
    try_migrate_meta_via_socket(&sock, label)
}

pub fn try_migrate_meta_via_socket(sock_path: &Path, label: &str) -> Option<()> {
    let mut stream = connect_agent(sock_path)?;
    request_migrate_meta(&mut stream, label)
}

#[must_use]
pub fn try_check_migration_marker_via_socket(sock_path: &Path) -> Option<bool> {
    let mut stream = connect_agent(sock_path)?;
    request_check_migration_marker(&mut stream)
}

#[must_use]
pub fn try_set_migration_marker_via_socket(sock_path: &Path) -> Option<()> {
    let mut stream = connect_agent(sock_path)?;
    request_set_migration_marker(&mut stream)
}

/// Best-effort lookup of the agent socket from the environment —
/// `SSH_AUTH_SOCK` on Unix, or on Windows (cmd.exe, PowerShell, Git
/// Bash, etc.) the same variable if set. If absent, returns `None`
/// and the caller falls back to whatever configured path it knows.
fn env_agent_socket() -> Option<std::path::PathBuf> {
    let v = std::env::var_os("SSH_AUTH_SOCK")?;
    if v.is_empty() {
        return None;
    }
    Some(std::path::PathBuf::from(v))
}

// ───── Platform-specific connect ─────

#[cfg(unix)]
fn connect_agent(sock_path: &Path) -> Option<AgentStream> {
    connect_agent_with_timeout(sock_path, AGENT_IO_TIMEOUT)
}

#[cfg(unix)]
fn connect_agent_with_timeout(sock_path: &Path, timeout: Duration) -> Option<AgentStream> {
    let stream = match UnixStream::connect(sock_path) {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(error = %e, "agent proxy: connect failed, falling back");
            return None;
        }
    };
    if stream.set_read_timeout(Some(timeout)).is_err()
        || stream.set_write_timeout(Some(timeout)).is_err()
    {
        tracing::debug!("agent proxy: failed to set socket timeouts, falling back");
        return None;
    }
    Some(stream)
}

#[cfg(windows)]
fn connect_agent(sock_path: &Path) -> Option<AgentStream> {
    connect_agent_with_timeout(sock_path, AGENT_IO_TIMEOUT)
}

#[cfg(windows)]
fn connect_agent_with_timeout(sock_path: &Path, timeout: Duration) -> Option<AgentStream> {
    let mut stream = match PipeStream::connect(sock_path) {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(error = %e, "agent proxy: pipe connect failed, falling back");
            return None;
        }
    };
    if stream.set_timeouts(timeout).is_err() {
        tracing::debug!("agent proxy: failed to set pipe timeouts, falling back");
        return None;
    }
    Some(stream)
}

// ───── Protocol handlers (generic over Read + Write) ─────

fn agent_has_identity<S: Read + Write>(stream: &mut S, pubkey_blob: &[u8]) -> Option<bool> {
    let payload = message::serialize_request(&AgentRequest::RequestIdentities);
    debug_assert_eq!(payload[0], SSH_AGENTC_REQUEST_IDENTITIES);
    if send_framed(stream, &payload).is_none() {
        tracing::warn!("agent_has_identity: failed to send RequestIdentities (write error)");
        return None;
    }
    match recv_response(stream)? {
        AgentResponse::IdentitiesAnswer(ids) => {
            let has_key = ids.iter().any(|id| id.key_blob == pubkey_blob);
            tracing::debug!(
                has_key,
                total_identities = ids.len(),
                "agent_has_identity check complete"
            );
            Some(has_key)
        }
        other => {
            tracing::warn!(?other, "agent_has_identity: unexpected response type");
            None
        }
    }
}

fn request_signature<S: Read + Write>(
    stream: &mut S,
    pubkey_blob: &[u8],
    data: &[u8],
) -> Option<Vec<u8>> {
    let payload = message::serialize_request(&AgentRequest::SignRequest {
        key_blob: pubkey_blob.to_vec(),
        data: data.to_vec(),
        flags: 0,
    });
    debug_assert_eq!(payload[0], SSH_AGENTC_SIGN_REQUEST);
    if send_framed(stream, &payload).is_none() {
        tracing::warn!(
            blob_len = pubkey_blob.len(),
            data_len = data.len(),
            "request_signature: failed to send SignRequest (write error or timeout)"
        );
        return None;
    }
    match recv_response(stream)? {
        AgentResponse::SignResponse { signature_blob } if !signature_blob.is_empty() => {
            tracing::debug!(sig_len = signature_blob.len(), "request_signature: success");
            Some(signature_blob)
        }
        AgentResponse::SignResponse { .. } => {
            tracing::warn!("request_signature: agent returned empty signature blob");
            None
        }
        AgentResponse::Failure => {
            tracing::warn!("request_signature: agent returned FAILURE (no matching key or backend error)");
            None
        }
        other => {
            tracing::warn!(?other, "request_signature: unexpected response type");
            None
        }
    }
}

fn request_generate<S: Read + Write>(
    stream: &mut S,
    label: &str,
    comment: Option<&str>,
    access_policy: u32,
    presence_mode: u8,
    pub_file_path: Option<&str>,
) -> Option<Vec<u8>> {
    let payload = message::serialize_request(&AgentRequest::GenerateKey {
        label: label.as_bytes().to_vec(),
        comment: comment.map(|c| c.as_bytes().to_vec()).unwrap_or_default(),
        access_policy,
        presence_mode: Some(presence_mode),
        pub_file_path: pub_file_path.map(|p| p.as_bytes().to_vec()),
    });
    debug_assert_eq!(payload[0], SSH_AGENTC_SSHENC_GENERATE_KEY);
    send_framed(stream, &payload)?;
    match recv_response(stream)? {
        AgentResponse::GenerateResponse { public_key } if !public_key.is_empty() => {
            Some(public_key)
        }
        AgentResponse::GenerateResponse { .. } => {
            tracing::debug!("agent proxy: generate returned empty public key, falling back");
            None
        }
        AgentResponse::Failure => {
            tracing::debug!("agent proxy: generate returned FAILURE, falling back");
            None
        }
        other => {
            tracing::debug!(
                ?other,
                "agent proxy: unexpected response to generate request"
            );
            None
        }
    }
}

fn request_rename<S: Read + Write>(stream: &mut S, old_label: &str, new_label: &str) -> Option<()> {
    let payload = message::serialize_request(&AgentRequest::RenameKey {
        old_label: old_label.as_bytes().to_vec(),
        new_label: new_label.as_bytes().to_vec(),
    });
    debug_assert_eq!(payload[0], SSH_AGENTC_SSHENC_RENAME_KEY);
    send_framed(stream, &payload)?;
    match recv_response(stream)? {
        AgentResponse::Success => Some(()),
        AgentResponse::Failure => {
            tracing::debug!("agent proxy: rename returned FAILURE, falling back");
            None
        }
        other => {
            tracing::debug!(?other, "agent proxy: unexpected response to rename request");
            None
        }
    }
}

fn request_migrate_meta<S: Read + Write>(stream: &mut S, label: &str) -> Option<()> {
    let payload = message::serialize_request(&AgentRequest::MigrateMeta {
        label: label.as_bytes().to_vec(),
    });
    debug_assert_eq!(payload[0], SSH_AGENTC_SSHENC_MIGRATE_META);
    send_framed(stream, &payload)?;
    match recv_response(stream)? {
        AgentResponse::Success => Some(()),
        AgentResponse::Failure => {
            tracing::debug!("agent proxy: migrate-meta returned FAILURE");
            None
        }
        other => {
            tracing::debug!(?other, "agent proxy: unexpected response to migrate-meta");
            None
        }
    }
}

fn request_check_migration_marker<S: Read + Write>(stream: &mut S) -> Option<bool> {
    let payload = message::serialize_request(&AgentRequest::CheckMigrationMarker);
    debug_assert_eq!(payload[0], SSH_AGENTC_SSHENC_CHECK_MIGRATION_MARKER);
    send_framed(stream, &payload)?;
    // Success = marker SET. Failure = marker NOT set (or keychain
    // unreachable; the CLI treats those equivalently as "I can't
    // confirm the marker, proceed cautiously").
    match recv_response(stream)? {
        AgentResponse::Success => Some(true),
        AgentResponse::Failure => Some(false),
        other => {
            tracing::debug!(
                ?other,
                "agent proxy: unexpected response to check-migration-marker"
            );
            None
        }
    }
}

fn request_set_migration_marker<S: Read + Write>(stream: &mut S) -> Option<()> {
    let payload = message::serialize_request(&AgentRequest::SetMigrationMarker);
    debug_assert_eq!(payload[0], SSH_AGENTC_SSHENC_SET_MIGRATION_MARKER);
    send_framed(stream, &payload)?;
    match recv_response(stream)? {
        AgentResponse::Success => Some(()),
        AgentResponse::Failure => {
            tracing::debug!("agent proxy: set-migration-marker returned FAILURE");
            None
        }
        other => {
            tracing::debug!(
                ?other,
                "agent proxy: unexpected response to set-migration-marker"
            );
            None
        }
    }
}

fn request_delete<S: Read + Write>(stream: &mut S, label: &str) -> Option<()> {
    let payload = message::serialize_request(&AgentRequest::DeleteKey {
        label: label.as_bytes().to_vec(),
    });
    debug_assert_eq!(payload[0], SSH_AGENTC_SSHENC_DELETE_KEY);
    send_framed(stream, &payload)?;
    match recv_response(stream)? {
        AgentResponse::Success => Some(()),
        AgentResponse::Failure => {
            tracing::debug!("agent proxy: delete returned FAILURE, falling back");
            None
        }
        other => {
            tracing::debug!(?other, "agent proxy: unexpected response to delete request");
            None
        }
    }
}

fn send_framed<S: Write>(stream: &mut S, payload: &[u8]) -> Option<()> {
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    if let Err(e) = stream.write_all(&frame) {
        tracing::debug!(error = %e, "agent proxy: write failed");
        return None;
    }
    Some(())
}

fn recv_response<S: Read>(stream: &mut S) -> Option<AgentResponse> {
    let payload = read_frame(stream)?;
    match message::parse_response(&payload) {
        Ok(resp) => Some(resp),
        Err(e) => {
            tracing::debug!(error = %e, "agent proxy: response parse failed");
            None
        }
    }
}

fn read_frame<S: Read>(stream: &mut S) -> Option<Vec<u8>> {
    let mut len_buf = [0_u8; 4];
    if let Err(e) = stream.read_exact(&mut len_buf) {
        tracing::debug!(error = %e, "agent proxy: read length failed");
        return None;
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    // Match the 256 KiB cap the agent's wire reader uses — anything
    // larger is either malicious or indicates a framing error.
    if len == 0 || len > 256 * 1024 {
        tracing::debug!(len, "agent proxy: invalid frame length");
        return None;
    }
    let mut buf = vec![0_u8; len];
    if let Err(e) = stream.read_exact(&mut buf) {
        tracing::debug!(error = %e, "agent proxy: read body failed");
        return None;
    }
    Some(buf)
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::message::Identity;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn unique_socket_path(tag: &str) -> PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!(
            "sshenc-cli-agentproxy-{tag}-{}-{id}.sock",
            std::process::id()
        ))
    }

    /// Spawn a minimal test agent on a fresh Unix socket. The agent
    /// replies to the first `script.len()` requests in order and then
    /// closes.
    fn spawn_fake_agent(
        sock_path: &Path,
        script: Vec<AgentResponse>,
    ) -> thread::JoinHandle<Option<Vec<AgentRequest>>> {
        drop(std::fs::remove_file(sock_path));
        let listener = UnixListener::bind(sock_path).unwrap();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().ok()?;
            let mut requests = Vec::new();
            for response in script {
                let mut len_buf = [0_u8; 4];
                stream.read_exact(&mut len_buf).ok()?;
                let len = u32::from_be_bytes(len_buf) as usize;
                let mut buf = vec![0_u8; len];
                stream.read_exact(&mut buf).ok()?;
                requests.push(message::parse_request(&buf).ok()?);

                let payload = message::serialize_response(&response);
                stream
                    .write_all(&(payload.len() as u32).to_be_bytes())
                    .ok()?;
                stream.write_all(&payload).ok()?;
            }
            Some(requests)
        })
    }

    #[test]
    fn returns_none_when_socket_does_not_exist() {
        let bogus = std::env::temp_dir().join(format!(
            "sshenc-cli-agentproxy-nope-{}.sock",
            std::process::id()
        ));
        drop(std::fs::remove_file(&bogus));
        assert!(try_sign_via_socket(&bogus, &[0x01], &[0x02]).is_none());
    }

    #[test]
    fn returns_signature_when_agent_has_matching_identity() {
        let pubkey_blob = b"target-key-blob".to_vec();
        let signature_blob = b"ssh-fmt-sig".to_vec();
        let sock_path = unique_socket_path("match");

        let handle = spawn_fake_agent(
            &sock_path,
            vec![
                AgentResponse::IdentitiesAnswer(vec![Identity {
                    key_blob: pubkey_blob.clone(),
                    comment: "test".into(),
                }]),
                AgentResponse::SignResponse {
                    signature_blob: signature_blob.clone(),
                },
            ],
        );

        let got = try_sign_via_socket(&sock_path, &pubkey_blob, b"data-to-sign");
        drop(handle.join().ok());
        drop(std::fs::remove_file(&sock_path));

        assert_eq!(got, Some(signature_blob));
    }

    #[test]
    fn falls_back_when_agent_has_no_matching_identity() {
        let target = b"want-this".to_vec();
        let other = b"some-other-key".to_vec();
        let sock_path = unique_socket_path("nomatch");

        let handle = spawn_fake_agent(
            &sock_path,
            vec![AgentResponse::IdentitiesAnswer(vec![Identity {
                key_blob: other,
                comment: "other".into(),
            }])],
        );

        let got = try_sign_via_socket(&sock_path, &target, b"data");
        drop(handle.join().ok());
        drop(std::fs::remove_file(&sock_path));

        assert!(got.is_none());
    }

    #[test]
    fn falls_back_when_agent_returns_failure_on_sign() {
        let pubkey_blob = b"target".to_vec();
        let sock_path = unique_socket_path("signfail");

        let handle = spawn_fake_agent(
            &sock_path,
            vec![
                AgentResponse::IdentitiesAnswer(vec![Identity {
                    key_blob: pubkey_blob.clone(),
                    comment: "t".into(),
                }]),
                AgentResponse::Failure,
            ],
        );

        let got = try_sign_via_socket(&sock_path, &pubkey_blob, b"data");
        drop(handle.join().ok());
        drop(std::fs::remove_file(&sock_path));

        assert!(got.is_none());
    }

    #[test]
    fn falls_back_when_agent_returns_empty_signature_blob() {
        let pubkey_blob = b"target".to_vec();
        let sock_path = unique_socket_path("empty");

        let handle = spawn_fake_agent(
            &sock_path,
            vec![
                AgentResponse::IdentitiesAnswer(vec![Identity {
                    key_blob: pubkey_blob.clone(),
                    comment: "t".into(),
                }]),
                AgentResponse::SignResponse {
                    signature_blob: Vec::new(),
                },
            ],
        );

        let got = try_sign_via_socket(&sock_path, &pubkey_blob, b"data");
        drop(handle.join().ok());
        drop(std::fs::remove_file(&sock_path));

        assert!(got.is_none());
    }

    #[test]
    fn sign_request_round_trips_pubkey_and_data() {
        // End-to-end check: the request frame the proxy sends must
        // round-trip through parse_request on the agent side to the
        // exact pubkey_blob and data the caller passed.
        let pubkey_blob = b"roundtrip-pubkey".to_vec();
        let data = b"roundtrip-data-bytes".to_vec();
        let sock_path = unique_socket_path("wire");

        let handle = spawn_fake_agent(
            &sock_path,
            vec![
                AgentResponse::IdentitiesAnswer(vec![Identity {
                    key_blob: pubkey_blob.clone(),
                    comment: "x".into(),
                }]),
                AgentResponse::SignResponse {
                    signature_blob: b"ok".to_vec(),
                },
            ],
        );

        let got = try_sign_via_socket(&sock_path, &pubkey_blob, &data);
        let captured = handle.join().unwrap().expect("agent thread succeeded");
        drop(std::fs::remove_file(&sock_path));

        assert_eq!(got, Some(b"ok".to_vec()));
        assert_eq!(captured.len(), 2);
        match &captured[0] {
            AgentRequest::RequestIdentities => {}
            other => panic!("expected RequestIdentities, got {other:?}"),
        }
        match &captured[1] {
            AgentRequest::SignRequest {
                key_blob,
                data: sent_data,
                flags,
            } => {
                assert_eq!(*key_blob, pubkey_blob);
                assert_eq!(*sent_data, data);
                assert_eq!(*flags, 0);
            }
            other => panic!("expected SignRequest, got {other:?}"),
        }
    }

    // ---- delete path ----

    #[test]
    fn delete_returns_some_on_success_and_label_reaches_agent() {
        let sock_path = unique_socket_path("del-ok");
        let handle = spawn_fake_agent(&sock_path, vec![AgentResponse::Success]);

        let got = try_delete_via_socket(&sock_path, "my-label");
        let captured = handle.join().unwrap().expect("agent thread");
        drop(std::fs::remove_file(&sock_path));

        assert_eq!(got, Some(()));
        assert_eq!(captured.len(), 1);
        match &captured[0] {
            AgentRequest::DeleteKey { label } => assert_eq!(label, b"my-label"),
            other => panic!("expected DeleteKey, got {other:?}"),
        }
    }

    #[test]
    fn delete_falls_back_on_failure_response() {
        // Simulates either "label not allowed", "backend reported
        // error", or "agent doesn't know DeleteKey" — all surface as
        // FAILURE on the wire, and all should signal local fallback.
        let sock_path = unique_socket_path("del-fail");
        let handle = spawn_fake_agent(&sock_path, vec![AgentResponse::Failure]);

        let got = try_delete_via_socket(&sock_path, "x");
        drop(handle.join().ok());
        drop(std::fs::remove_file(&sock_path));

        assert!(got.is_none());
    }

    #[test]
    fn delete_falls_back_when_socket_missing() {
        let bogus = std::env::temp_dir().join(format!(
            "sshenc-cli-agentproxy-del-nope-{}.sock",
            std::process::id()
        ));
        drop(std::fs::remove_file(&bogus));
        assert!(try_delete_via_socket(&bogus, "any").is_none());
    }

    // ---- generate path ----

    #[test]
    fn generate_returns_public_key_on_success() {
        let pubkey_bytes = vec![0x04_u8; 65];
        let sock_path = unique_socket_path("gen-ok");
        let handle = spawn_fake_agent(
            &sock_path,
            vec![AgentResponse::GenerateResponse {
                public_key: pubkey_bytes.clone(),
            }],
        );

        let got = try_generate_via_socket(
            &sock_path,
            "my-gen",
            Some("jay@box"),
            0,
            0,
            Some("/home/jay/.ssh/my-gen.pub"),
        );
        let captured = handle.join().unwrap().expect("agent thread");
        drop(std::fs::remove_file(&sock_path));

        assert_eq!(got, Some(pubkey_bytes));
        assert_eq!(captured.len(), 1);
        match &captured[0] {
            AgentRequest::GenerateKey {
                label,
                comment,
                access_policy,
                presence_mode,
                pub_file_path,
            } => {
                assert_eq!(label, b"my-gen");
                assert_eq!(comment, b"jay@box");
                assert_eq!(*access_policy, 0);
                assert_eq!(*presence_mode, Some(0));
                assert_eq!(
                    pub_file_path.as_deref(),
                    Some(b"/home/jay/.ssh/my-gen.pub".as_ref())
                );
            }
            other => panic!("expected GenerateKey, got {other:?}"),
        }
    }

    #[test]
    fn generate_encodes_absent_comment_as_empty_string() {
        let sock_path = unique_socket_path("gen-nocomm");
        let handle = spawn_fake_agent(
            &sock_path,
            vec![AgentResponse::GenerateResponse {
                public_key: vec![0x04; 65],
            }],
        );

        drop(try_generate_via_socket(
            &sock_path, "label", None, 1, 0, None,
        ));
        let captured = handle.join().unwrap().expect("agent thread");
        drop(std::fs::remove_file(&sock_path));

        match &captured[0] {
            AgentRequest::GenerateKey {
                comment,
                access_policy,
                ..
            } => {
                assert!(comment.is_empty());
                assert_eq!(*access_policy, 1);
            }
            other => panic!("expected GenerateKey, got {other:?}"),
        }
    }

    #[test]
    fn generate_falls_back_on_failure_response() {
        let sock_path = unique_socket_path("gen-fail");
        let handle = spawn_fake_agent(&sock_path, vec![AgentResponse::Failure]);

        let got = try_generate_via_socket(&sock_path, "x", None, 0, 0, None);
        drop(handle.join().ok());
        drop(std::fs::remove_file(&sock_path));

        assert!(got.is_none());
    }

    #[test]
    fn generate_falls_back_on_empty_public_key() {
        let sock_path = unique_socket_path("gen-empty");
        let handle = spawn_fake_agent(
            &sock_path,
            vec![AgentResponse::GenerateResponse {
                public_key: Vec::new(),
            }],
        );

        let got = try_generate_via_socket(&sock_path, "x", None, 0, 0, None);
        drop(handle.join().ok());
        drop(std::fs::remove_file(&sock_path));

        assert!(got.is_none());
    }

    #[test]
    fn generate_falls_back_when_socket_missing() {
        let bogus = std::env::temp_dir().join(format!(
            "sshenc-cli-agentproxy-gen-nope-{}.sock",
            std::process::id()
        ));
        drop(std::fs::remove_file(&bogus));
        assert!(try_generate_via_socket(&bogus, "x", None, 0, 0, None).is_none());
    }
}
