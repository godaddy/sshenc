// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Proxy secret-touching operations through a running `sshenc-agent`.
//!
//! The agent holds the wrapping-key cache for its configured TTL; by
//! routing operations through it the CLI reuses that warm cache
//! instead of cold-starting a fresh `SshencBackend` (and a fresh
//! Touch ID / passcode prompt) per invocation. This module is the
//! client half of that proxy — the server side lives in
//! `sshenc-agent`.
//!
//! Two operations are proxied today:
//!
//! - **Sign** (`SSH_AGENTC_SIGN_REQUEST`): used by `sshenc -Y sign`
//!   so `git commit -S` collapses into one prompt per TTL.
//! - **DeleteKey** (`SSH_AGENTC_SSHENC_DELETE_KEY`, sshenc-specific
//!   extension at message type `0xF0`): used by `sshenc delete` so
//!   destructive key management goes through the same cache. The
//!   custom type is outside OpenSSH's assigned range, so foreign
//!   agents cleanly reply with `SSH_AGENT_FAILURE` and the CLI falls
//!   back to local deletion.
//!
//! Every proxy is strictly an optimization:
//! - If `SSH_AUTH_SOCK` isn't set or points to a missing socket, we
//!   fall back immediately.
//! - If the agent doesn't advertise / accept the target, we fall
//!   back.
//! - If the RPC fails, we fall back.
//!
//! Only the successful path short-circuits local execution.
//!
//! Windows is not covered: `sshenc-agent` on Windows uses a named
//! pipe and `SSH_AUTH_SOCK` is typically not set — the fallback path
//! handles that case.

#[cfg(unix)]
use crate::message::{
    self, AgentRequest, AgentResponse, SSH_AGENTC_REQUEST_IDENTITIES, SSH_AGENTC_SIGN_REQUEST,
    SSH_AGENTC_SSHENC_DELETE_KEY, SSH_AGENTC_SSHENC_GENERATE_KEY,
};
#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
const AGENT_IO_TIMEOUT: Duration = Duration::from_secs(10);

/// Try to sign `data` through whatever agent `SSH_AUTH_SOCK` points
/// to. `pubkey_blob` is the SSH wire-format public key the caller
/// wants to sign with; the agent identity whose `key_blob` matches
/// is asked to produce the signature.
///
/// Returns `Some(signature_blob)` on success, where `signature_blob`
/// is the SSH-format signature
/// (`string(algo) || string(mpint(r) || mpint(s))`) ready to embed
/// verbatim in an SSHSIG envelope. Returns `None` for every fall-back
/// reason (no socket, no matching identity, protocol failure).
#[must_use]
pub fn try_sign_via_agent(pubkey_blob: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    #[cfg(unix)]
    {
        let sock_path = std::env::var_os("SSH_AUTH_SOCK")?;
        if sock_path.is_empty() {
            return None;
        }
        try_sign_via_socket(Path::new(&sock_path), pubkey_blob, data)
    }
    #[cfg(not(unix))]
    {
        let _ = (pubkey_blob, data);
        None
    }
}

#[cfg(unix)]
pub(crate) fn try_sign_via_socket(
    sock_path: &Path,
    pubkey_blob: &[u8],
    data: &[u8],
) -> Option<Vec<u8>> {
    let mut stream = connect_agent(sock_path)?;

    if !agent_has_identity(&mut stream, pubkey_blob)? {
        tracing::debug!("agent proxy: no matching identity, falling back");
        return None;
    }

    request_signature(&mut stream, pubkey_blob, data)
}

/// Try to delete the key with the given `label` through
/// `SSH_AUTH_SOCK`. Returns `Some(())` when the agent confirms the
/// delete; `None` for every fall-back reason (no socket, agent
/// doesn't support the extension, label not allowed, backend
/// reported an error). Falling back to local deletion is the
/// caller's responsibility.
#[must_use]
pub fn try_delete_via_agent(label: &str) -> Option<()> {
    #[cfg(unix)]
    {
        let sock_path = std::env::var_os("SSH_AUTH_SOCK")?;
        if sock_path.is_empty() {
            return None;
        }
        try_delete_via_socket(Path::new(&sock_path), label)
    }
    #[cfg(not(unix))]
    {
        let _ = label;
        None
    }
}

#[cfg(unix)]
pub(crate) fn try_delete_via_socket(sock_path: &Path, label: &str) -> Option<()> {
    let mut stream = connect_agent(sock_path)?;
    request_delete(&mut stream, label)
}

/// Try to generate a new key through the agent at `SSH_AUTH_SOCK`.
/// On success returns `Some(public_key_bytes)` (SEC1 uncompressed,
/// 65 bytes for P-256). Returns `None` for every fall-back reason
/// (no socket, agent refuses, bad policy, backend error); the caller
/// then does a local keygen.
///
/// The whole point: when the agent is reachable, the wrapping-key
/// entry in the login keychain is *created* by the agent binary,
/// and every later read of that entry is *also* from the agent.
/// Same creator and reader → no cross-binary ACL prompt.
#[must_use]
pub fn try_generate_via_agent(
    label: &str,
    comment: Option<&str>,
    access_policy: u32,
) -> Option<Vec<u8>> {
    #[cfg(unix)]
    {
        let sock_path = std::env::var_os("SSH_AUTH_SOCK")?;
        if sock_path.is_empty() {
            return None;
        }
        try_generate_via_socket(Path::new(&sock_path), label, comment, access_policy)
    }
    #[cfg(not(unix))]
    {
        let _ = (label, comment, access_policy);
        None
    }
}

#[cfg(unix)]
pub(crate) fn try_generate_via_socket(
    sock_path: &Path,
    label: &str,
    comment: Option<&str>,
    access_policy: u32,
) -> Option<Vec<u8>> {
    let mut stream = connect_agent(sock_path)?;
    request_generate(&mut stream, label, comment, access_policy)
}

#[cfg(unix)]
fn connect_agent(sock_path: &Path) -> Option<UnixStream> {
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

#[cfg(unix)]
fn agent_has_identity(stream: &mut UnixStream, pubkey_blob: &[u8]) -> Option<bool> {
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

#[cfg(unix)]
fn request_signature(stream: &mut UnixStream, pubkey_blob: &[u8], data: &[u8]) -> Option<Vec<u8>> {
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

#[cfg(unix)]
fn request_generate(
    stream: &mut UnixStream,
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

#[cfg(unix)]
fn request_delete(stream: &mut UnixStream, label: &str) -> Option<()> {
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

#[cfg(unix)]
fn send_framed(stream: &mut UnixStream, payload: &[u8]) -> Option<()> {
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    if let Err(e) = stream.write_all(&frame) {
        tracing::debug!(error = %e, "agent proxy: write failed");
        return None;
    }
    Some(())
}

#[cfg(unix)]
fn recv_response(stream: &mut UnixStream) -> Option<AgentResponse> {
    let payload = read_frame(stream)?;
    match message::parse_response(&payload) {
        Ok(resp) => Some(resp),
        Err(e) => {
            tracing::debug!(error = %e, "agent proxy: response parse failed");
            None
        }
    }
}

#[cfg(unix)]
fn read_frame(stream: &mut UnixStream) -> Option<Vec<u8>> {
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
