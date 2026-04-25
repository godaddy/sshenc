// Copyright 2024 Jay Gowdy
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
    SSH_AGENTC_SSHENC_DELETE_KEY, SSH_AGENTC_SSHENC_GENERATE_KEY, SSH_AGENTC_SSHENC_RENAME_KEY,
};
use std::io::{Read, Write};
use std::path::Path;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::net::UnixStream;

#[cfg(windows)]
use crate::pipe::PipeStream;

const AGENT_IO_TIMEOUT: Duration = Duration::from_secs(10);

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
    if is_socket_ready(socket_path) {
        return Ok(());
    }

    let agent_bin =
        sshenc_core::bin_discovery::find_trusted_binary("sshenc-agent").ok_or_else(|| {
            "sshenc-agent binary not found in known install dirs; \
             install sshenc or start the agent manually before running this command"
                .to_string()
        })?;

    if let Some(parent) = socket_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("creating agent socket dir {}: {e}", parent.display()))?;
        }
    }

    use std::process::Stdio;
    std::process::Command::new(&agent_bin)
        .arg("--socket")
        .arg(socket_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawning {}: {e}", agent_bin.display()))?;

    // Exponential backoff: 100, 200, 400, 800, 1600 ms (≈3.1s max).
    for attempt in 0..5_u32 {
        std::thread::sleep(Duration::from_millis(100_u64 << attempt));
        if is_socket_ready(socket_path) {
            return Ok(());
        }
    }
    Err(format!(
        "sshenc-agent did not become ready at {} within 3.1s",
        socket_path.display()
    ))
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
    if PipeStream::probe(socket_path) {
        return Ok(());
    }
    Err(format!(
        "sshenc-agent isn't answering on {}; start it with \
         `sshenc-agent` or ensure the sshenc-agent Service is running",
        socket_path.display()
    ))
}

#[cfg(unix)]
fn is_socket_ready(socket_path: &Path) -> bool {
    socket_path.exists() && UnixStream::connect(socket_path).is_ok()
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
    let mut stream = connect_agent(sock_path)?;
    if !agent_has_identity(&mut stream, pubkey_blob)? {
        tracing::debug!("agent proxy: no matching identity, falling back");
        return None;
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
) -> Option<Vec<u8>> {
    let sock = env_agent_socket()?;
    try_generate_via_socket(&sock, label, comment, access_policy)
}

pub fn try_generate_via_socket(
    sock_path: &Path,
    label: &str,
    comment: Option<&str>,
    access_policy: u32,
) -> Option<Vec<u8>> {
    let mut stream = connect_agent(sock_path)?;
    request_generate(&mut stream, label, comment, access_policy)
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
    let stream = match UnixStream::connect(sock_path) {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(error = %e, "agent proxy: connect failed, falling back");
            return None;
        }
    };
    if stream.set_read_timeout(Some(AGENT_IO_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(AGENT_IO_TIMEOUT)).is_err()
    {
        tracing::debug!("agent proxy: failed to set socket timeouts, falling back");
        return None;
    }
    Some(stream)
}

#[cfg(windows)]
fn connect_agent(sock_path: &Path) -> Option<AgentStream> {
    let mut stream = match PipeStream::connect(sock_path) {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(error = %e, "agent proxy: pipe connect failed, falling back");
            return None;
        }
    };
    if stream.set_timeouts(AGENT_IO_TIMEOUT).is_err() {
        tracing::debug!("agent proxy: failed to set pipe timeouts, falling back");
        return None;
    }
    Some(stream)
}

// ───── Protocol handlers (generic over Read + Write) ─────

fn agent_has_identity<S: Read + Write>(stream: &mut S, pubkey_blob: &[u8]) -> Option<bool> {
    let payload = message::serialize_request(&AgentRequest::RequestIdentities);
    debug_assert_eq!(payload[0], SSH_AGENTC_REQUEST_IDENTITIES);
    send_framed(stream, &payload)?;
    match recv_response(stream)? {
        AgentResponse::IdentitiesAnswer(ids) => {
            Some(ids.into_iter().any(|id| id.key_blob == pubkey_blob))
        }
        other => {
            tracing::debug!(?other, "agent proxy: unexpected response to identities");
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
    send_framed(stream, &payload)?;
    match recv_response(stream)? {
        AgentResponse::SignResponse { signature_blob } if !signature_blob.is_empty() => {
            Some(signature_blob)
        }
        AgentResponse::SignResponse { .. } => {
            tracing::debug!("agent proxy: sign returned empty blob, falling back");
            None
        }
        AgentResponse::Failure => {
            tracing::debug!("agent proxy: agent returned FAILURE, falling back");
            None
        }
        other => {
            tracing::debug!(?other, "agent proxy: unexpected response to sign request");
            None
        }
    }
}

fn request_generate<S: Read + Write>(
    stream: &mut S,
    label: &str,
    comment: Option<&str>,
    access_policy: u32,
) -> Option<Vec<u8>> {
    let payload = message::serialize_request(&AgentRequest::GenerateKey {
        label: label.as_bytes().to_vec(),
        comment: comment.map(|c| c.as_bytes().to_vec()).unwrap_or_default(),
        access_policy,
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

        let got = try_generate_via_socket(&sock_path, "my-gen", Some("jay@box"), 0);
        let captured = handle.join().unwrap().expect("agent thread");
        drop(std::fs::remove_file(&sock_path));

        assert_eq!(got, Some(pubkey_bytes));
        assert_eq!(captured.len(), 1);
        match &captured[0] {
            AgentRequest::GenerateKey {
                label,
                comment,
                access_policy,
            } => {
                assert_eq!(label, b"my-gen");
                assert_eq!(comment, b"jay@box");
                assert_eq!(*access_policy, 0);
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

        drop(try_generate_via_socket(&sock_path, "label", None, 1));
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

        let got = try_generate_via_socket(&sock_path, "x", None, 0);
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

        let got = try_generate_via_socket(&sock_path, "x", None, 0);
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
        assert!(try_generate_via_socket(&bogus, "x", None, 0).is_none());
    }
}
