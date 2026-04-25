// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! End-to-end coverage for the agent's wire protocol over a real
//! Unix socket. Unit tests in `sshenc-agent-proto` cover the
//! parser/serializer in-process; these tests cover the
//! socket-server interaction:
//!
//! - oversize frame (`>256 KiB`) is rejected by the server's
//!   wire reader without crashing the agent.
//! - zero-length frame is rejected.
//! - truncated frame (server closes after partial body) is handled
//!   without hanging the agent.
//! - unknown opcode returns `SSH_AGENT_FAILURE` (covered by unit
//!   tests but cheap to verify e2e).
//! - multiple concurrent connections each get their own response.
//! - request-reply round-trip on a brand-new connection works
//!   after several previous connections (no state leak across
//!   connections).
//!
//! Software-mode safe; no key creation involved beyond the shared
//! one. All scenarios connect directly to the agent socket as raw
//! bytes — they don't go through the sshenc CLI.
//!
//! Unix only: the tests use `std::os::unix::net::UnixStream`
//! directly. The same protocol-level invariants on Windows would
//! need a `PipeStream`-equivalent harness; the in-process unit
//! tests in `sshenc-agent-proto::message` already cover the
//! parser/serializer for both platforms.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use sshenc_e2e::{docker_skip_reason, shared_enclave_pubkey, SshencEnv};

fn skip_if_no_docker(test_name: &str) -> bool {
    if let Some(reason) = docker_skip_reason() {
        eprintln!("skip {test_name}: {reason}");
        return true;
    }
    false
}

/// Frame `payload` with a 4-byte big-endian length prefix.
fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Connect, write `payload`, return whatever the server sends back
/// (up to a generous limit) along with whether the connection
/// closed cleanly. Returns `Err` only if connection itself failed.
fn round_trip_raw(socket: &Path, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(payload)?;
    let mut buf = Vec::new();
    // Read until EOF or timeout. Any agent reply will be small.
    let mut tmp = [0_u8; 4096];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(e) => return Err(e),
        }
        if buf.len() > 1024 * 1024 {
            // Way more than any legitimate agent response.
            break;
        }
    }
    Ok(buf)
}

const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENT_FAILURE: u8 = 5;

/// **Sanity baseline**: a normal RequestIdentities round-trip
/// returns a parseable IdentitiesAnswer. If this regresses, every
/// other test in this file is meaningless.
#[test]
#[ignore = "requires docker"]
fn baseline_request_identities_returns_answer() {
    if skip_if_no_docker("baseline_request_identities_returns_answer") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared key"));
    env.start_agent().expect("start agent");

    let reply = round_trip_raw(&env.socket_path(), &frame(&[SSH_AGENTC_REQUEST_IDENTITIES]))
        .expect("round-trip");
    assert!(reply.len() >= 5, "reply too short: {reply:?}");
    let body_len = u32::from_be_bytes([reply[0], reply[1], reply[2], reply[3]]) as usize;
    assert_eq!(reply.len(), 4 + body_len, "framing mismatch");
    assert_eq!(
        reply[4], SSH_AGENT_IDENTITIES_ANSWER,
        "expected IDENTITIES_ANSWER opcode, got {}",
        reply[4]
    );
}

/// Oversize frame (length > 256 KiB) — agent's wire reader rejects
/// it. Agent should close the connection; subsequent connections
/// must still work, proving the agent didn't crash.
#[test]
#[ignore = "requires docker"]
fn oversize_frame_rejected_without_crash() {
    if skip_if_no_docker("oversize_frame_rejected_without_crash") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared key"));
    env.start_agent().expect("start agent");

    // Claim a 1 MiB body; we don't actually have to send the whole
    // body for the wire reader to reject it on the length check.
    let mut malicious = Vec::with_capacity(8);
    malicious.extend_from_slice(&(1_024_u32 * 1024 + 1).to_be_bytes());
    malicious.push(0xAB);

    let reply = round_trip_raw(&env.socket_path(), &malicious).expect("round-trip");
    // Agent should hang up (empty reply). What matters is the
    // *next* connection still works.
    drop(reply);

    let baseline = round_trip_raw(&env.socket_path(), &frame(&[SSH_AGENTC_REQUEST_IDENTITIES]))
        .expect("baseline after oversize");
    assert!(
        !baseline.is_empty() && baseline[4] == SSH_AGENT_IDENTITIES_ANSWER,
        "agent should still serve normal requests after rejecting oversize frame; got reply: {baseline:?}"
    );
}

/// Zero-length frame — claimed body length 0 — agent rejects
/// without hanging the connection.
#[test]
#[ignore = "requires docker"]
fn zero_length_frame_rejected() {
    if skip_if_no_docker("zero_length_frame_rejected") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared key"));
    env.start_agent().expect("start agent");

    let zero = 0_u32.to_be_bytes();
    let reply = round_trip_raw(&env.socket_path(), &zero).expect("round-trip");
    drop(reply);

    let baseline = round_trip_raw(&env.socket_path(), &frame(&[SSH_AGENTC_REQUEST_IDENTITIES]))
        .expect("baseline after zero-length");
    assert!(
        !baseline.is_empty() && baseline[4] == SSH_AGENT_IDENTITIES_ANSWER,
        "agent should still serve normal requests after rejecting zero-length frame"
    );
}

/// Truncated payload — claim a body of N bytes, send fewer. Agent
/// should drop the connection on read-exact failure without
/// crashing.
#[test]
#[ignore = "requires docker"]
fn truncated_body_handled_cleanly() {
    if skip_if_no_docker("truncated_body_handled_cleanly") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared key"));
    env.start_agent().expect("start agent");

    // Promise 50 bytes, send 5.
    let mut bad = Vec::new();
    bad.extend_from_slice(&50_u32.to_be_bytes());
    bad.extend_from_slice(b"short");
    drop(round_trip_raw(&env.socket_path(), &bad).expect("round-trip"));

    let baseline = round_trip_raw(&env.socket_path(), &frame(&[SSH_AGENTC_REQUEST_IDENTITIES]))
        .expect("baseline after truncated");
    assert!(
        !baseline.is_empty() && baseline[4] == SSH_AGENT_IDENTITIES_ANSWER,
        "agent should keep serving after truncated frame"
    );
}

/// Unknown opcode — a single-byte payload of `0x7F` (an opcode
/// the agent doesn't recognize). Agent should reply with
/// `SSH_AGENT_FAILURE`, not close the socket abruptly.
#[test]
#[ignore = "requires docker"]
fn unknown_opcode_returns_failure() {
    if skip_if_no_docker("unknown_opcode_returns_failure") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared key"));
    env.start_agent().expect("start agent");

    let reply = round_trip_raw(&env.socket_path(), &frame(&[0x7F])).expect("round-trip");
    assert!(reply.len() >= 5, "reply too short: {reply:?}");
    let body_len = u32::from_be_bytes([reply[0], reply[1], reply[2], reply[3]]) as usize;
    assert_eq!(reply.len(), 4 + body_len);
    assert_eq!(
        reply[4], SSH_AGENT_FAILURE,
        "expected FAILURE for unknown opcode, got {}",
        reply[4]
    );
}

/// Multiple concurrent connections each get their own clean
/// reply. Spawns N threads, each opens its own socket and sends a
/// RequestIdentities; collects all replies and verifies each is a
/// well-formed IDENTITIES_ANSWER.
#[test]
#[ignore = "requires docker"]
fn concurrent_connections_each_get_clean_reply() {
    if skip_if_no_docker("concurrent_connections_each_get_clean_reply") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared key"));
    env.start_agent().expect("start agent");
    let socket = env.socket_path();

    const N: usize = 8;
    let mut handles = Vec::with_capacity(N);
    for _ in 0..N {
        let socket = socket.clone();
        handles.push(std::thread::spawn(move || {
            round_trip_raw(&socket, &frame(&[SSH_AGENTC_REQUEST_IDENTITIES])).expect("round-trip")
        }));
    }
    let replies: Vec<Vec<u8>> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    for (i, reply) in replies.iter().enumerate() {
        assert!(
            reply.len() >= 5,
            "connection {i} reply too short: {reply:?}"
        );
        assert_eq!(
            reply[4], SSH_AGENT_IDENTITIES_ANSWER,
            "connection {i} got opcode {}, want {}",
            reply[4], SSH_AGENT_IDENTITIES_ANSWER
        );
    }
}

/// State doesn't leak across connections: after sending malformed
/// frames on connection 1, a fresh connection 2 still gets a
/// pristine response. (Concurrency-style test, but sequential —
/// guards against the agent accidentally tracking per-client
/// state in a global.)
#[test]
#[ignore = "requires docker"]
fn fresh_connection_after_malformed_is_pristine() {
    if skip_if_no_docker("fresh_connection_after_malformed_is_pristine") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared key"));
    env.start_agent().expect("start agent");
    let socket = env.socket_path();

    // Garbage round 1.
    drop(round_trip_raw(&socket, &[0xFF, 0xFF, 0xFF, 0xFF, 0x42]).ok());
    // Garbage round 2.
    drop(round_trip_raw(&socket, &frame(&[0x7F])).ok());
    // Now a fresh connection: should see a normal answer.
    let reply = round_trip_raw(&socket, &frame(&[SSH_AGENTC_REQUEST_IDENTITIES]))
        .expect("baseline after garbage");
    assert!(reply.len() >= 5);
    assert_eq!(
        reply[4], SSH_AGENT_IDENTITIES_ANSWER,
        "agent should serve a clean answer on a fresh connection after garbage"
    );
}
