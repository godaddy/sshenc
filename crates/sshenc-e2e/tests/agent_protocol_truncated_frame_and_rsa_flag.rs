// Copyright 2024 Jay Gowdy
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

use sshenc_e2e::{docker_skip_reason, run, shared_enclave_pubkey, SshencEnv};
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

fn read_reply(socket: &std::path::Path, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut s = UnixStream::connect(socket)?;
    s.set_read_timeout(Some(Duration::from_secs(3)))?;
    s.set_write_timeout(Some(Duration::from_secs(3)))?;
    s.write_all(payload)?;
    let mut buf = Vec::new();
    let mut tmp = [0_u8; 4096];
    loop {
        match s.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => break,
            Err(_) => break,
        }
        if buf.len() > 1024 * 1024 {
            break;
        }
    }
    Ok(buf)
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

    // Get the key blob via REQUEST_IDENTITIES.
    let mut req = Vec::new();
    req.extend_from_slice(&(1_u32.to_be_bytes()));
    req.push(SSH_AGENTC_REQUEST_IDENTITIES);
    let reply = read_reply(&env.socket_path(), &req).expect("REQUEST_IDENTITIES");
    assert!(
        reply.len() >= 9,
        "IDENTITIES_ANSWER too short: {} bytes",
        reply.len()
    );
    let nkeys = u32::from_be_bytes([reply[5], reply[6], reply[7], reply[8]]);
    assert!(nkeys >= 1, "agent has no keys; got nkeys={nkeys}");
    let mut p = 9_usize;
    let blob_len =
        u32::from_be_bytes([reply[p], reply[p + 1], reply[p + 2], reply[p + 3]]) as usize;
    p += 4;
    let blob = reply[p..p + blob_len].to_vec();

    // Build SignRequest: opcode + key_blob (string) + data (string) + flags (u32).
    let mut body = Vec::new();
    body.push(SSH_AGENTC_SIGN_REQUEST);
    write_ssh_string(&mut body, &blob);
    write_ssh_string(&mut body, b"some payload to sign");
    body.extend_from_slice(&SSH_AGENT_RSA_SHA2_256.to_be_bytes());

    let mut frame = Vec::new();
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);

    let resp = read_reply(&env.socket_path(), &frame).expect("SIGN_REQUEST reply");
    assert!(
        resp.len() >= 5,
        "SIGN_REQUEST reply too short: {} bytes",
        resp.len()
    );
    let opcode = resp[4];
    assert_eq!(
        opcode, SSH_AGENT_SIGN_RESPONSE,
        "expected SIGN_RESPONSE (14) — agent should ignore the RSA-specific flag for an ECDSA key \
         and produce a valid signature; got opcode {opcode}"
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
