// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Two more agent-protocol edges that complement
//! `agent_protocol_edge.rs` (oversized + zero-length frames):
//!
//! - A frame whose declared length exceeds the bytes actually
//!   delivered (peer hangs up mid-body) is treated as a clean
//!   disconnect; the agent doesn't hang waiting forever and
//!   keeps serving subsequent connections.
//! - A SignRequest carrying RSA_SHA2_256/512 flags against an
//!   ECDSA key is handled cleanly: the RSA-specific flag is
//!   silently ignored (matching OpenSSH semantics) and the
//!   agent returns a valid ECDSA signature, not a panic or
//!   wedged response.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{
    docker_skip_reason, persistent_keys_dir, run, shared_enclave_pubkey, SshencEnv,
    SHARED_ENCLAVE_LABEL,
};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
#[allow(dead_code)]
const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
const SSH_AGENT_RSA_SHA2_256: u32 = 2;

fn skip_if_no_docker(test_name: &str) -> bool {
    if let Some(reason) = docker_skip_reason() {
        eprintln!("skip {test_name}: {reason}");
        return true;
    }
    false
}

fn write_ssh_string(out: &mut Vec<u8>, body: &[u8]) {
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
}

/// Send `payload` and read back exactly one SSH response frame (length-prefixed).
/// Returns the full frame bytes (4-byte length prefix + body). Does not wait
/// for more data after the frame is received, so it returns immediately rather
/// than blocking until a read timeout.
fn read_one_ssh_frame(
    socket: &std::path::Path,
    payload: &[u8],
    timeout: Duration,
) -> std::io::Result<Vec<u8>> {
    let mut s = UnixStream::connect(socket)?;
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(Duration::from_secs(3)))?;
    s.write_all(payload)?;

    let mut len_buf = [0_u8; 4];
    s.read_exact(&mut len_buf)?;
    let body_len = u32::from_be_bytes(len_buf) as usize;
    let mut body = vec![0_u8; body_len];
    s.read_exact(&mut body)?;

    let mut result = len_buf.to_vec();
    result.extend_from_slice(&body);
    Ok(result)
}

/// Build the SSH wire-format key blob for the shared enclave key.
///
/// The `e2e-shared.pub` file in the persistent keys dir contains the raw
/// SEC1-encoded EC public key (65 bytes: 0x04 || x || y for P-256).
/// The SSH agent wire format wraps that as:
///   string("ecdsa-sha2-nistp256") || string("nistp256") || string(sec1_bytes)
fn shared_enclave_ssh_blob() -> Option<Vec<u8>> {
    let pub_path = persistent_keys_dir().join(format!("{SHARED_ENCLAVE_LABEL}.pub"));
    let sec1 = std::fs::read(&pub_path).ok()?;
    if sec1.len() != 65 {
        return None;
    }
    let mut blob = Vec::new();
    write_ssh_string(&mut blob, b"ecdsa-sha2-nistp256");
    write_ssh_string(&mut blob, b"nistp256");
    write_ssh_string(&mut blob, &sec1);
    Some(blob)
}

/// Parse an IDENTITIES_ANSWER reply and return a list of (blob, comment) pairs.
fn parse_identities(reply: &[u8]) -> Vec<(Vec<u8>, String)> {
    if reply.len() < 9 {
        return Vec::new();
    }
    let nkeys = u32::from_be_bytes([reply[5], reply[6], reply[7], reply[8]]) as usize;
    let mut p = 9_usize;
    let mut out = Vec::with_capacity(nkeys);
    for _ in 0..nkeys {
        if p + 4 > reply.len() {
            break;
        }
        let blob_len =
            u32::from_be_bytes([reply[p], reply[p + 1], reply[p + 2], reply[p + 3]]) as usize;
        p += 4;
        if p + blob_len > reply.len() {
            break;
        }
        let blob = reply[p..p + blob_len].to_vec();
        p += blob_len;

        if p + 4 > reply.len() {
            break;
        }
        let comment_len =
            u32::from_be_bytes([reply[p], reply[p + 1], reply[p + 2], reply[p + 3]]) as usize;
        p += 4;
        if p + comment_len > reply.len() {
            break;
        }
        let comment = String::from_utf8_lossy(&reply[p..p + comment_len]).into_owned();
        p += comment_len;

        out.push((blob, comment));
    }
    out
}

/// Client declares a 64-byte body, sends only 8 bytes, then
/// holds the connection without closing. The agent must time
/// out reading the rest (or close itself) without hanging the
/// accept loop. A subsequent well-behaved client succeeds.
#[test]
#[ignore = "requires docker"]
fn agent_handles_partial_frame_without_blocking_others() {
    if skip_if_no_docker("agent_handles_partial_frame_without_blocking_others") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared key"));
    env.start_agent().expect("start agent");

    // Misbehaving client: connect, declare 64-byte body, send 8.
    let stuck = std::thread::spawn({
        let socket = env.socket_path();
        move || {
            if let Ok(mut s) = UnixStream::connect(&socket) {
                drop(s.set_write_timeout(Some(Duration::from_secs(2))));
                drop(s.write_all(&64_u32.to_be_bytes()));
                drop(s.write_all(&[0_u8; 8]));
                // Hold the stream by reading; we don't actually
                // care what comes back.
                let mut tmp = [0_u8; 16];
                drop(s.set_read_timeout(Some(Duration::from_secs(1))));
                drop(s.read(&mut tmp));
            }
        }
    });

    // Give the agent a moment to register the partial frame.
    std::thread::sleep(Duration::from_millis(200));

    // Well-behaved client must still succeed in parallel.
    let listed = run(env
        .scrubbed_command("ssh-add")
        .env("SSH_AUTH_SOCK", env.socket_path())
        .arg("-L"))
    .expect("ssh-add -L");
    assert!(
        listed.succeeded(),
        "agent should serve well-behaved clients while another holds a partial frame; stderr:\n{}",
        listed.stderr
    );

    drop(stuck.join());
}

/// SignRequest with `SSH_AGENT_RSA_SHA2_256` flag against an
/// ECDSA key: the agent ignores the RSA-specific flag (matching
/// OpenSSH semantics) and returns a valid ECDSA SIGN_RESPONSE.
#[test]
#[ignore = "requires docker"]
fn sign_request_with_rsa_sha2_flag_on_ecdsa_key_signs_normally() {
    if skip_if_no_docker("sign_request_with_rsa_sha2_flag_on_ecdsa_key_signs_normally") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared key"));
    env.start_agent().expect("start agent");

    // Get the key blob for the shared no-Touch-ID key via REQUEST_IDENTITIES.
    // We specifically use SHARED_ENCLAVE_LABEL ("e2e-shared", auth-policy none)
    // rather than whichever key happens to be first: the "default" key requires
    // Touch ID and would block indefinitely if the user is not at the terminal.
    let mut req = Vec::new();
    req.extend_from_slice(&(1_u32.to_be_bytes()));
    req.push(SSH_AGENTC_REQUEST_IDENTITIES);
    let reply = read_one_ssh_frame(&env.socket_path(), &req, Duration::from_secs(10))
        .expect("REQUEST_IDENTITIES");
    assert!(
        reply.len() >= 9,
        "IDENTITIES_ANSWER too short: {} bytes",
        reply.len()
    );
    let identities = parse_identities(&reply);
    assert!(!identities.is_empty(), "agent returned no identities");

    // Find the shared key by its SSH wire-format blob (constructed from the
    // on-disk .pub SEC1 bytes).  Matching by blob is more reliable than matching
    // by comment because sshenc sets the comment to the OS username@hostname, not
    // the key label.
    let target_blob = shared_enclave_ssh_blob();
    let blob = target_blob
        .as_ref()
        .and_then(|t| {
            identities
                .iter()
                .find(|(b, _)| b == t)
                .map(|(b, _)| b.clone())
        })
        .unwrap_or_else(|| {
            // Fallback: use the first identity if we can't locate the shared key.
            // The first identity is sorted "default" first, which may require Touch ID.
            eprintln!(
                "warning: could not locate '{SHARED_ENCLAVE_LABEL}' blob in identities; \
                 using first identity (sign may require Touch ID)"
            );
            identities[0].0.clone()
        });

    // Build SignRequest: opcode + key_blob (string) + data (string) + flags (u32).
    let mut body = Vec::new();
    body.push(SSH_AGENTC_SIGN_REQUEST);
    write_ssh_string(&mut body, &blob);
    write_ssh_string(&mut body, b"some payload to sign");
    body.extend_from_slice(&SSH_AGENT_RSA_SHA2_256.to_be_bytes());

    let mut frame = Vec::new();
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);

    // Use read_one_ssh_frame so we return as soon as the response arrives rather
    // than blocking until a read timeout.  With auth-policy none the SE signs
    // without biometrics and the response should arrive in well under a second.
    let resp = read_one_ssh_frame(&env.socket_path(), &frame, Duration::from_secs(10))
        .expect("SIGN_REQUEST reply");
    assert!(
        resp.len() >= 5,
        "SIGN_REQUEST reply too short: {} bytes; agent stderr:\n{}",
        resp.len(),
        env.agent_stderr_snapshot()
    );
    let opcode = resp[4];
    assert_eq!(
        opcode,
        SSH_AGENT_SIGN_RESPONSE,
        "expected SIGN_RESPONSE (14) — agent should ignore the RSA-specific flag for an ECDSA key \
         and produce a valid signature; got opcode {opcode}; agent stderr:\n{}",
        env.agent_stderr_snapshot()
    );

    // Agent stays alive for subsequent requests.
    let listed = run(env
        .scrubbed_command("ssh-add")
        .env("SSH_AUTH_SOCK", env.socket_path())
        .arg("-L"))
    .expect("ssh-add -L");
    assert!(
        listed.succeeded(),
        "agent should still serve after RSA_SHA2 sign request; stderr:\n{}",
        listed.stderr
    );
}
