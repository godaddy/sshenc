// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Windows protocol-edge mirror of `agent_protocol_edge.rs`.
//!
//! `agent_protocol_edge.rs` is `#![cfg(unix)]` because it talks
//! directly to the agent via `std::os::unix::net::UnixStream`.
//! Windows has equivalent invariants on the named-pipe transport
//! that the parser/serializer unit tests don't cover (those are
//! transport-agnostic).
//!
//! These tests:
//! - spawn `sshenc-agent.exe --socket \\.\pipe\<unique-name>`
//! - wait for the pipe to be available
//! - open it with `OpenOptions` (Win32 pipes are file-like)
//! - send framed payloads; assert the agent rejects oversize / bad
//!   frames cleanly and serves a fresh connection afterward
//!
//! Pipe naming uses a per-test PID+nanos suffix so concurrent test
//! runs don't collide on `\\.\pipe\openssh-ssh-agent`.

#![cfg(windows)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{docker_skip_reason, workspace_bin, SshencEnv};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

fn skip_if_no_docker(test_name: &str) -> bool {
    if let Some(reason) = docker_skip_reason() {
        eprintln!("skip {test_name}: {reason}");
        return true;
    }
    false
}

const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;

/// Generate a per-test pipe name unique to PID + nanos so parallel
/// tests don't collide.
fn unique_pipe_name(test: &str) -> String {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("\\\\.\\pipe\\sshenc-e2e-{test}-{pid}-{nanos}")
}

/// Spawn the agent listening on the given named pipe. Caller must
/// kill the child on test exit.
fn spawn_agent(env: &SshencEnv, pipe: &str) -> Child {
    let bin = workspace_bin("sshenc-agent").expect("agent binary");
    env.scrubbed_command(&bin)
        .arg("--foreground")
        .arg("--socket")
        .arg(pipe)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sshenc-agent")
}

/// Wait until the pipe accepts a CreateFile (i.e., the agent has
/// called CreateNamedPipeW and is in the listening state). Panics
/// on timeout.
fn wait_for_pipe(pipe: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if OpenOptions::new().read(true).write(true).open(pipe).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("pipe never became available at {pipe}");
}

/// Frame `payload` with a 4-byte big-endian length prefix.
fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Connect to the pipe, write `payload`, read a reply (best-effort
/// up to a generous limit), close. Returns the bytes read; an empty
/// vec means the agent hung up without replying.
fn round_trip_raw(pipe: &str, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut stream = OpenOptions::new().read(true).write(true).open(pipe)?;
    stream.write_all(payload)?;
    let mut buf = Vec::new();
    let mut tmp = [0_u8; 4096];
    // Pipes don't support read timeouts via std; rely on the agent
    // to either reply or hang up. For tests this is bounded by the
    // agent's behavior — bad frames cause an immediate hang up.
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => break,
            Err(e) => return Err(e),
        }
        if buf.len() > 1024 * 1024 {
            break;
        }
    }
    Ok(buf)
}

/// Stop the agent child. Best-effort kill + wait.
fn stop_agent(mut child: Child) {
    drop(child.kill());
    drop(child.wait());
}

/// Sanity baseline: a normal RequestIdentities round-trip works
/// over the Windows named pipe.
#[test]
#[ignore = "requires docker"]
fn windows_pipe_baseline_request_identities() {
    if skip_if_no_docker("windows_pipe_baseline_request_identities") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let pipe = unique_pipe_name("baseline");
    let agent = spawn_agent(&env, &pipe);
    wait_for_pipe(&pipe, Duration::from_secs(10));

    let reply = round_trip_raw(&pipe, &frame(&[SSH_AGENTC_REQUEST_IDENTITIES]))
        .expect("round-trip request-identities");
    assert!(reply.len() >= 5, "reply too short: {reply:?}");
    let body_len = u32::from_be_bytes([reply[0], reply[1], reply[2], reply[3]]) as usize;
    assert_eq!(reply.len(), 4 + body_len, "framing mismatch");
    assert_eq!(
        reply[4], SSH_AGENT_IDENTITIES_ANSWER,
        "expected IDENTITIES_ANSWER, got opcode {}",
        reply[4]
    );

    stop_agent(agent);
}

/// Oversize frame (length > 256 KiB) — agent's wire reader rejects
/// it. Subsequent connections must still work, proving the agent
/// didn't crash on the rejection.
#[test]
#[ignore = "requires docker"]
fn windows_pipe_oversize_frame_rejected_without_crash() {
    if skip_if_no_docker("windows_pipe_oversize_frame_rejected_without_crash") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let pipe = unique_pipe_name("oversize");
    let agent = spawn_agent(&env, &pipe);
    wait_for_pipe(&pipe, Duration::from_secs(10));

    // Claim 1 MiB body. The wire reader should reject on the length
    // check before the body needs to be fully transmitted.
    let mut malicious = Vec::with_capacity(8);
    malicious.extend_from_slice(&(1_024_u32 * 1024 + 1).to_be_bytes());
    malicious.push(0xAB);
    drop(round_trip_raw(&pipe, &malicious));

    // A fresh connection on the same pipe must still work. On
    // Windows pipe semantics, the second client may need to wait
    // briefly for a new server instance to come up.
    wait_for_pipe(&pipe, Duration::from_secs(5));
    let reply = round_trip_raw(&pipe, &frame(&[SSH_AGENTC_REQUEST_IDENTITIES]))
        .expect("baseline after oversize");
    assert!(
        reply.len() >= 5 && reply[4] == SSH_AGENT_IDENTITIES_ANSWER,
        "agent should still serve after rejecting oversize; got: {reply:?}"
    );

    stop_agent(agent);
}

/// Zero-length frame — claimed body length 0 — rejected without
/// hanging the connection. Same invariant as the Unix mirror.
#[test]
#[ignore = "requires docker"]
fn windows_pipe_zero_length_frame_rejected() {
    if skip_if_no_docker("windows_pipe_zero_length_frame_rejected") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let pipe = unique_pipe_name("zerolen");
    let agent = spawn_agent(&env, &pipe);
    wait_for_pipe(&pipe, Duration::from_secs(10));

    let zero = 0_u32.to_be_bytes();
    drop(round_trip_raw(&pipe, &zero));

    wait_for_pipe(&pipe, Duration::from_secs(5));
    let reply = round_trip_raw(&pipe, &frame(&[SSH_AGENTC_REQUEST_IDENTITIES]))
        .expect("baseline after zero-len");
    assert!(
        reply.len() >= 5 && reply[4] == SSH_AGENT_IDENTITIES_ANSWER,
        "agent should still serve after zero-length frame"
    );

    stop_agent(agent);
}
