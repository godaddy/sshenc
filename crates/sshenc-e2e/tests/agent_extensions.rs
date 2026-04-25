// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! sshenc-specific agent-protocol extensions, exercised at the wire
//! level over the agent's Unix socket.
//!
//! The CLI's write ops (keygen, delete, the agent-mediated parts of
//! `default` promotion) all flow through `AgentProxyBackend`, which
//! emits opcodes 0xF0/0xF1/0xF3. `agent-proto` has parser unit
//! tests for these opcodes; this file exercises them end-to-end:
//!
//! - 0xF1 GenerateKey → 0xF2 GenerateResponse: a key created via the
//!   socket appears in `sshenc list`.
//! - 0xF0 DeleteKey: a key created via the CLI and then deleted via
//!   the socket no longer appears in the list.
//! - 0xF3 RenameKey: rename roundtrip via socket; old label vanishes,
//!   new label shows up.
//!
//! Software mode only — these tests need to mint extra keys, which
//! in hardware mode hits the macOS keychain prompt budget. They
//! short-circuit when neither `SSHENC_E2E_SOFTWARE` nor
//! `SSHENC_E2E_EXTENDED` is set.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{
    docker_skip_reason, extended_enabled, run, software_mode, SshencEnv, SHARED_ENCLAVE_LABEL,
};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

fn skip_if_no_docker(test_name: &str) -> bool {
    if let Some(reason) = docker_skip_reason() {
        eprintln!("skip {test_name}: {reason}");
        return true;
    }
    false
}

fn skip_unless_key_creation_cheap(test_name: &str) -> bool {
    if extended_enabled() || software_mode() {
        return false;
    }
    eprintln!(
        "skip {test_name}: needs to create extra agent-mediated keys; \
         set SSHENC_E2E_SOFTWARE=1 or SSHENC_E2E_EXTENDED=1"
    );
    true
}

// ──────────────────────────────────────────────────────────────
// Wire helpers — kept minimal so we don't pull sshenc-agent-proto
// into the e2e crate just for these tests.
// ──────────────────────────────────────────────────────────────

const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENT_SUCCESS: u8 = 6;
const SSH_AGENTC_SSHENC_DELETE_KEY: u8 = 0xF0;
const SSH_AGENTC_SSHENC_GENERATE_KEY: u8 = 0xF1;
const SSH_AGENT_SSHENC_GENERATE_RESPONSE: u8 = 0xF2;
const SSH_AGENTC_SSHENC_RENAME_KEY: u8 = 0xF3;

fn write_ssh_string(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// Frame a payload with the 4-byte BE length prefix every agent
/// message uses.
fn frame(payload: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    out
}

/// Send `request` to the agent, read the framed reply, return the
/// reply body (without the 4-byte length prefix). Panics if the
/// agent hangs up before replying.
fn round_trip(socket: &Path, request: Vec<u8>) -> Vec<u8> {
    let mut stream = UnixStream::connect(socket).expect("connect agent socket");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    stream
        .write_all(&frame(request))
        .expect("write request frame");
    let mut hdr = [0_u8; 4];
    stream.read_exact(&mut hdr).expect("read reply length");
    let len = u32::from_be_bytes(hdr) as usize;
    assert!(
        len <= 64 * 1024,
        "reply length {len} from agent is implausible"
    );
    let mut body = vec![0_u8; len];
    stream.read_exact(&mut body).expect("read reply body");
    body
}

/// Build an SSHENC_GENERATE_KEY frame body.
fn build_generate_key(label: &str, comment: &str, access_policy: u32) -> Vec<u8> {
    let mut body = vec![SSH_AGENTC_SSHENC_GENERATE_KEY];
    write_ssh_string(&mut body, label.as_bytes());
    write_ssh_string(&mut body, comment.as_bytes());
    body.extend_from_slice(&access_policy.to_be_bytes());
    body
}

fn build_delete_key(label: &str) -> Vec<u8> {
    let mut body = vec![SSH_AGENTC_SSHENC_DELETE_KEY];
    write_ssh_string(&mut body, label.as_bytes());
    body
}

fn build_rename_key(old_label: &str, new_label: &str) -> Vec<u8> {
    let mut body = vec![SSH_AGENTC_SSHENC_RENAME_KEY];
    write_ssh_string(&mut body, old_label.as_bytes());
    write_ssh_string(&mut body, new_label.as_bytes());
    body
}

/// Ensure a label is *not* present in the agent (no leftover from a
/// previous run). Best-effort delete via socket; ignores failures.
fn cleanup_via_socket(env: &SshencEnv, label: &str) {
    drop(std::panic::catch_unwind(|| {
        round_trip(&env.socket_path(), build_delete_key(label));
    }));
}

fn unique_label(prefix: &str) -> String {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{prefix}-{pid}-{nanos}")
}

// ──────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────

/// 0xF1 GenerateKey over the socket creates a real key visible to
/// `sshenc list`. Parses the 0xF2 GenerateResponse and verifies a
/// non-empty public key blob came back. Drives the agent-mediated
/// write path that AgentProxyBackend uses for `sshenc keygen`.
#[test]
#[ignore = "requires docker"]
fn agent_extension_generate_key_via_socket() {
    if skip_if_no_docker("agent_extension_generate_key_via_socket") {
        return;
    }
    if skip_unless_key_creation_cheap("agent_extension_generate_key_via_socket") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(sshenc_e2e::shared_enclave_pubkey(&env).expect("warm shared key"));
    env.start_agent().expect("start agent");

    let label = unique_label("agentext-gen");
    let body = round_trip(
        &env.socket_path(),
        build_generate_key(&label, "agentext-gen-comment", 0),
    );

    assert_eq!(
        body[0], SSH_AGENT_SSHENC_GENERATE_RESPONSE,
        "expected GenerateResponse opcode 0xF2; got opcode 0x{:02X}",
        body[0]
    );
    // Body layout after opcode byte: ssh-string(public_key).
    let len = u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize;
    assert!(
        len > 0,
        "public_key in GenerateResponse should be non-empty"
    );
    assert_eq!(body.len(), 1 + 4 + len, "GenerateResponse framing mismatch");

    // List via CLI; the new label should be there.
    let listed = run(env.sshenc_cmd().expect("sshenc").arg("list")).expect("sshenc list");
    assert!(listed.succeeded(), "sshenc list failed: {}", listed.stderr);
    assert!(
        listed.stdout.contains(&label),
        "new label {label} should be visible to sshenc list; got:\n{}",
        listed.stdout
    );

    cleanup_via_socket(&env, &label);
}

/// 0xF0 DeleteKey over the socket removes a key created via the
/// CLI. Asserts the agent replies with SUCCESS and the key is gone
/// from `sshenc list`.
#[test]
#[ignore = "requires docker"]
fn agent_extension_delete_key_via_socket() {
    if skip_if_no_docker("agent_extension_delete_key_via_socket") {
        return;
    }
    if skip_unless_key_creation_cheap("agent_extension_delete_key_via_socket") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(sshenc_e2e::shared_enclave_pubkey(&env).expect("warm shared key"));
    env.start_agent().expect("start agent");

    let label = unique_label("agentext-del");
    let kg = run(env.sshenc_cmd().expect("sshenc").args([
        "keygen",
        "--label",
        &label,
        "--auth-policy",
        "none",
        "--no-pub-file",
    ]))
    .expect("sshenc keygen");
    assert!(kg.succeeded(), "keygen failed: {}", kg.stderr);

    let body = round_trip(&env.socket_path(), build_delete_key(&label));
    assert_eq!(
        body[0], SSH_AGENT_SUCCESS,
        "DeleteKey reply should be SUCCESS (0x06); got 0x{:02X}",
        body[0]
    );

    let listed = run(env.sshenc_cmd().expect("sshenc").arg("list")).expect("sshenc list");
    assert!(
        !listed.stdout.contains(&label),
        "label {label} should be gone after socket-driven delete; got:\n{}",
        listed.stdout
    );
}

/// 0xF3 RenameKey over the socket moves a key from one label to
/// another. After the rename, the old label is gone and the new one
/// is listable.
#[test]
#[ignore = "requires docker"]
fn agent_extension_rename_key_via_socket() {
    if skip_if_no_docker("agent_extension_rename_key_via_socket") {
        return;
    }
    if skip_unless_key_creation_cheap("agent_extension_rename_key_via_socket") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(sshenc_e2e::shared_enclave_pubkey(&env).expect("warm shared key"));
    env.start_agent().expect("start agent");

    let old_label = unique_label("agentext-rename-src");
    let new_label = unique_label("agentext-rename-dst");
    let kg = run(env.sshenc_cmd().expect("sshenc").args([
        "keygen",
        "--label",
        &old_label,
        "--auth-policy",
        "none",
        "--no-pub-file",
    ]))
    .expect("sshenc keygen");
    assert!(kg.succeeded(), "keygen failed: {}", kg.stderr);

    let body = round_trip(&env.socket_path(), build_rename_key(&old_label, &new_label));
    assert_eq!(
        body[0], SSH_AGENT_SUCCESS,
        "RenameKey reply should be SUCCESS; got 0x{:02X}",
        body[0]
    );

    let listed = run(env.sshenc_cmd().expect("sshenc").arg("list")).expect("sshenc list");
    assert!(
        !listed.stdout.contains(&old_label),
        "old label {old_label} should be gone post-rename; got:\n{}",
        listed.stdout
    );
    assert!(
        listed.stdout.contains(&new_label),
        "new label {new_label} should be present post-rename; got:\n{}",
        listed.stdout
    );

    cleanup_via_socket(&env, &new_label);
}

/// 0xF0 DeleteKey for a label that doesn't exist must reply
/// FAILURE rather than crash the agent. Subsequent legitimate
/// requests still succeed.
#[test]
#[ignore = "requires docker"]
fn agent_extension_delete_unknown_label_returns_failure() {
    if skip_if_no_docker("agent_extension_delete_unknown_label_returns_failure") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(sshenc_e2e::shared_enclave_pubkey(&env).expect("warm shared key"));
    env.start_agent().expect("start agent");

    let body = round_trip(
        &env.socket_path(),
        build_delete_key("definitely-not-a-real-label"),
    );
    assert_eq!(
        body[0], SSH_AGENT_FAILURE,
        "delete-unknown should reply FAILURE (0x05); got 0x{:02X}",
        body[0]
    );

    // The shared key is still intact.
    let listed = run(env.sshenc_cmd().expect("sshenc").arg("list")).expect("sshenc list");
    assert!(
        listed.stdout.contains(SHARED_ENCLAVE_LABEL),
        "shared key should still be listed post-failure; got:\n{}",
        listed.stdout
    );
}
