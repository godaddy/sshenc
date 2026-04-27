// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! When an ssh-agent client closes its socket abruptly mid-frame
//! (partial body written, then disconnect), the agent does not
//! crash or wedge. Complements `agent_protocol_edge.rs`, which
//! covers malformed and oversized frames the agent rejects on
//! its own; here the failure is on the *client* side and the
//! agent must absorb the EOF/EPIPE without affecting subsequent
//! well-behaved clients.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{docker_skip_reason, run, shared_enclave_pubkey, SshencEnv};
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::time::Duration;

fn skip_if_no_docker(test_name: &str) -> bool {
    if let Some(reason) = docker_skip_reason() {
        eprintln!("skip {test_name}: {reason}");
        return true;
    }
    false
}

/// A client that connects, writes a partial frame, then closes
/// the socket abruptly does not crash or wedge the agent. A
/// subsequent well-behaved client must succeed.
#[test]
#[ignore = "requires docker"]
fn agent_survives_client_abrupt_disconnect() {
    if skip_if_no_docker("agent_survives_client_abrupt_disconnect") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared key"));
    env.start_agent().expect("start agent");

    // Connect, declare a 64-byte body, send only 1 byte, then drop
    // the stream (close). Agent's read half is mid-read; the close
    // surfaces as EOF/EPIPE on the agent side.
    {
        let mut s = UnixStream::connect(env.socket_path()).expect("connect");
        s.set_write_timeout(Some(Duration::from_secs(2)))
            .expect("set timeout");
        drop(s.write_all(&64_u32.to_be_bytes()));
        drop(s.write_all(&[11_u8]));
    }

    std::thread::sleep(Duration::from_millis(200));

    let listed = run(env
        .scrubbed_command("ssh-add")
        .env("SSH_AUTH_SOCK", env.socket_path())
        .arg("-L"))
    .expect("ssh-add -L");
    assert!(
        listed.succeeded(),
        "agent should still serve after client abrupt disconnect; stderr:\n{}",
        listed.stderr
    );
}
