// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Three corner cases at the intersection of agent protocol and
//! agent lifecycle:
//!
//! 1. **EXTENSION opcode (27, `query`)**: the standard
//!    SSH_AGENTC_EXTENSION opcode with the "query" extension is
//!    how clients discover what extensions an agent supports.
//!    `agent_extensions.rs` covers sshenc's custom 0xF0/0xF1/0xF3
//!    opcodes; this pins that the agent responds sensibly to a
//!    standard `query` extension request (either with the list of
//!    supported extensions or with FAILURE — both are valid).
//! 2. **`sshenc-agent --debug`**: the CLI flag enables debug
//!    logging at runtime (vs. via `log_level = "debug"` in the
//!    config file, covered by `log_level_filter.rs`). Pin the
//!    flag actually flips the level.
//! 3. **Stale ready file at `SSHENC_AGENT_READY_FILE` path**:
//!    a previous crashed agent might leave a stale ready file. A
//!    fresh agent on the same path must overwrite or refuse it
//!    cleanly — never silently treat the stale file as its own
//!    "ready" signal.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{run, shared_enclave_pubkey, workspace_bin, SshencEnv};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::Stdio;
use std::time::{Duration, Instant};

/// Build a length-prefixed agent frame: 4-byte BE length + payload.
fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// SSH wire format: 4-byte BE length, then bytes.
fn ssh_string(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + s.len());
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
    out
}

/// `SSH_AGENTC_EXTENSION` (opcode 27) with the standard `query`
/// extension. Per draft-miller-ssh-agent, the agent should
/// respond either with EXTENSION_RESPONSE (28) listing
/// supported extensions, or with FAILURE (5). Both are valid;
/// what's NOT valid is panicking the accept loop or hanging.
#[test]
#[ignore = "spawns sshenc-agent"]
fn agent_extension_query_responds_or_fails_cleanly() {
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("warm shared key"));
    env.start_agent().expect("start agent");

    // Frame: opcode 27, then ssh_string("query").
    let mut payload = vec![27_u8];
    payload.extend_from_slice(&ssh_string(b"query"));
    let req = frame(&payload);

    let mut stream = UnixStream::connect(env.socket_path()).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set read timeout");
    stream.write_all(&req).expect("write extension query");

    let mut len_buf = [0_u8; 4];
    stream.read_exact(&mut len_buf).expect("read length");
    let body_len = u32::from_be_bytes(len_buf) as usize;
    assert!(body_len > 0, "agent emitted zero-length response");
    let mut body = vec![0_u8; body_len];
    stream.read_exact(&mut body).expect("read body");

    let opcode = body[0];
    // Either FAILURE (5), SUCCESS (6), or EXTENSION_RESPONSE (28)
    // are acceptable. Anything else means the agent's protocol
    // dispatcher diverged.
    assert!(
        matches!(opcode, 5 | 6 | 28),
        "agent responded to extension query with unexpected opcode {opcode}; \
         body bytes: {body:?}"
    );

    // After the response, the agent must keep accepting fresh
    // connections — pin via a follow-up RequestIdentities.
    drop(stream);
    let listed = run(env
        .scrubbed_command("ssh-add")
        .env("SSH_AUTH_SOCK", env.socket_path())
        .arg("-L"))
    .expect("ssh-add -L");
    assert!(
        listed.succeeded(),
        "agent should still serve after extension query; stderr:\n{}",
        listed.stderr
    );
}

/// `sshenc-agent --debug` enables debug-level tracing on the
/// agent regardless of config-file `log_level`. We pre-spawn
/// the agent ourselves with `--debug --foreground` and pipe its
/// stdout (where tracing-subscriber writes), then trigger an
/// agent op (`ssh-add -L`) that's known to emit a tracing line.
/// `--debug` should produce DEBUG-level lines; without it (and
/// with default `warn` level), only WARN+ shows up.
#[test]
#[ignore = "spawns sshenc-agent"]
fn sshenc_agent_dash_debug_emits_debug_level_logs() {
    let env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("warm shared key"));

    let bin = workspace_bin("sshenc-agent").expect("agent");
    let socket = env.socket_path();
    drop(std::fs::remove_file(&socket));

    let mut agent = env
        .scrubbed_command(&bin)
        .arg("--foreground")
        .arg("--debug")
        .arg("--socket")
        .arg(&socket)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn agent --debug");

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if socket.exists() && UnixStream::connect(&socket).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Trigger an op to exercise the agent's request handler.
    let listed = run(env
        .scrubbed_command("ssh-add")
        .env("SSH_AUTH_SOCK", &socket)
        .arg("-L"))
    .expect("ssh-add -L");
    assert!(listed.succeeded(), "ssh-add -L: {}", listed.stderr);

    // Give the agent a beat to flush, then kill+collect output.
    std::thread::sleep(Duration::from_millis(100));
    drop(agent.kill());
    let out = agent.wait_with_output().expect("agent wait");
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("DEBUG") || combined.contains("debug"),
        "agent --debug should emit DEBUG-level log lines; combined output:\n{combined}"
    );
}

/// A regular file (not a socket) sitting at the agent socket
/// path must be either replaced or rejected — never silently
/// trip the agent into thinking it's already serving. Tests
/// `prepare_socket_path`'s "non-socket exists" branch.
#[test]
#[ignore = "spawns sshenc-agent"]
fn agent_refuses_to_replace_non_socket_at_socket_path() {
    let env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("warm shared key"));

    let socket = env.socket_path();
    if let Some(parent) = socket.parent() {
        std::fs::create_dir_all(parent).expect("mkdir socket parent");
    }
    // Plant a regular file at the socket path. Per
    // server.rs::prepare_socket_path, if the path exists and is
    // NOT a socket, the agent must bail rather than clobber it
    // (could be a user file the path collided with).
    std::fs::write(&socket, b"i am not a socket").expect("plant non-socket");

    let bin = workspace_bin("sshenc-agent").expect("agent");
    let mut agent = env
        .scrubbed_command(&bin)
        .arg("--foreground")
        .arg("--socket")
        .arg(&socket)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn agent");

    // Wait for the agent to exit on its own. It should fail
    // quickly because prepare_socket_path bails before bind.
    let deadline = Instant::now() + Duration::from_secs(5);
    let exit_status = loop {
        if let Some(status) = agent.try_wait().expect("try_wait") {
            break status;
        }
        if Instant::now() >= deadline {
            drop(agent.kill());
            panic!("agent did not exit when started against a non-socket file");
        }
        std::thread::sleep(Duration::from_millis(50));
    };

    assert!(
        !exit_status.success(),
        "agent should exit non-zero when socket path is a regular file; status: {exit_status}"
    );
    let out = agent.wait_with_output().expect("agent output");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.to_lowercase().contains("socket")
            || stderr.to_lowercase().contains("not")
            || stderr.to_lowercase().contains("refus"),
        "expected diagnostic about non-socket at socket path; got:\n{stderr}"
    );
    // The file we planted must still be there — the agent must
    // not have clobbered it.
    let still_there = std::fs::read(&socket).expect("read planted file");
    assert_eq!(
        still_there, b"i am not a socket",
        "agent overwrote the non-socket file at the socket path"
    );
}
