// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Proxy `sshenc -Y sign` through a running SSH agent.
//!
//! `sshenc -Y sign` is invoked by `git commit -S` once per commit.
//! A freshly constructed `SshencBackend` always starts with a cold
//! wrapping-key cache, so with `wrapping_key_user_presence = true`
//! every commit triggers a fresh Touch ID / passcode prompt. A running
//! `sshenc-agent` already holds a warm cache for the TTL configured
//! in `~/.config/sshenc/config.toml`, so proxying the signature through
//! `SSH_AUTH_SOCK` collapses the per-commit prompts into one per TTL
//! window.
//!
//! The proxy is strictly an optimization:
//! - If `SSH_AUTH_SOCK` isn't set or points to a missing socket, we
//!   fall back immediately.
//! - If the agent doesn't advertise a matching identity, we fall back.
//! - If the sign request fails or yields an empty blob, we fall back.
//!
//! Only the successful path short-circuits local signing.
//!
//! Windows is not covered: `sshenc-agent` on Windows uses a named
//! pipe and `SSH_AUTH_SOCK` is typically not set — the fallback path
//! handles that case.

#[cfg(unix)]
use sshenc_agent_proto::message::{
    self, AgentRequest, AgentResponse, SSH_AGENTC_REQUEST_IDENTITIES, SSH_AGENTC_SIGN_REQUEST,
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
    let mut stream = match UnixStream::connect(sock_path) {
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

    if !agent_has_identity(&mut stream, pubkey_blob)? {
        tracing::debug!("agent proxy: no matching identity, falling back");
        return None;
    }

    request_signature(&mut stream, pubkey_blob, data)
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
    use sshenc_agent_proto::message::Identity;
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
}
