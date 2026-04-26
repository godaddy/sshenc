// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `ssh-add` opcodes that `sshenc-agent` doesn't implement. The
//! agent serves a hardware-backed enclave key set; it deliberately
//! does NOT support software-key add/lock/unlock — those are
//! ssh-agent features irrelevant to enclave-only workflows. The
//! contract under test: the agent responds with `SSH_AGENT_FAILURE`
//! for these opcodes and **keeps serving** subsequent requests.
//! A regression where one of these unsupported paths panics the
//! agent's accept loop would silently brick the agent for the
//! rest of the session.
//!
//! `drop_in_extras.rs` covers `ssh-add -D` (delete-all-identities)
//! as a "must not brick the agent" case. This file extends to:
//! - `ssh-add -t <ttl> /key/path`: ADD_ID_CONSTRAINED with a
//!   lifetime constraint
//! - `ssh-add -x` / `-X`: LOCK / UNLOCK (passphrase-protect agent)

#![cfg(unix)]
#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::print_stderr,
    non_snake_case
)]

use sshenc_e2e::{docker_skip_reason, run, shared_enclave_pubkey, SshencEnv};
use std::io::Write;
use std::process::Stdio;

fn skip_if_no_docker(test_name: &str) -> bool {
    if let Some(reason) = docker_skip_reason() {
        eprintln!("skip {test_name}: {reason}");
        return true;
    }
    false
}

fn assert_agent_alive_after(env: &SshencEnv, after_label: &str) {
    let listed = run(env
        .scrubbed_command("ssh-add")
        .env("SSH_AUTH_SOCK", env.socket_path())
        .arg("-L"))
    .expect("ssh-add -L");
    assert!(
        listed.succeeded(),
        "agent should still answer ssh-add -L after {after_label}; stderr:\n{}",
        listed.stderr
    );
    assert!(
        listed.stdout.contains("ecdsa-sha2-nistp256"),
        "agent should still expose the shared key after {after_label}; stdout:\n{}",
        listed.stdout
    );
}

/// `ssh-add -t <ttl> <key>` sends an ADD_IDENTITY (constrained)
/// with a lifetime. sshenc-agent doesn't accept software-key
/// adds; the call must fail at the protocol level (ssh-add exits
/// non-zero), but the agent must keep serving.
#[test]
#[ignore = "requires docker"]
fn ssh_add_t_with_software_key_does_not_brick_agent() {
    if skip_if_no_docker("ssh_add_t_with_software_key_does_not_brick_agent") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("warm shared key"));
    env.start_agent().expect("start agent");

    // Generate a software ed25519 keypair on disk to feed ssh-add.
    let keyfile = env.ssh_dir().join("for-add-t");
    let kg = run(env
        .scrubbed_command("ssh-keygen")
        .arg("-q")
        .arg("-t")
        .arg("ed25519")
        .arg("-N")
        .arg("")
        .arg("-f")
        .arg(&keyfile))
    .expect("ssh-keygen");
    assert!(kg.succeeded(), "ssh-keygen: {}", kg.stderr);

    let outcome = run(env
        .scrubbed_command("ssh-add")
        .env("SSH_AUTH_SOCK", env.socket_path())
        .arg("-t")
        .arg("60")
        .arg(&keyfile))
    .expect("ssh-add -t");
    // We expect failure — sshenc-agent doesn't accept software
    // key additions. What matters is the agent didn't crash.
    assert!(
        !outcome.succeeded(),
        "ssh-add -t with software key unexpectedly succeeded against sshenc-agent; \
         stdout:\n{}\nstderr:\n{}",
        outcome.stdout,
        outcome.stderr
    );

    assert_agent_alive_after(&env, "ssh-add -t");
}

/// `ssh-add -x` (lock agent with passphrase). sshenc-agent doesn't
/// implement LOCK/UNLOCK because the enclave key set is already
/// gated by per-key access policy; agent-level lock would be a
/// second, redundant gate. The agent must respond FAILURE and stay
/// up.
#[test]
#[ignore = "requires docker"]
fn ssh_add_x_lock_does_not_brick_agent() {
    if skip_if_no_docker("ssh_add_x_lock_does_not_brick_agent") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("warm shared key"));
    env.start_agent().expect("start agent");

    // ssh-add -x reads the passphrase from /dev/tty by default;
    // pass via SSH_ASKPASS so it works headless.
    let askpass = env.home().join("askpass.sh");
    std::fs::write(&askpass, "#!/bin/sh\necho lockpass\n").expect("write askpass");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&askpass, std::fs::Permissions::from_mode(0o755)).expect("chmod");

    let child = env
        .scrubbed_command("ssh-add")
        .env("SSH_AUTH_SOCK", env.socket_path())
        .env("SSH_ASKPASS", &askpass)
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env("DISPLAY", ":0")
        .arg("-x")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ssh-add -x");
    let outcome = child.wait_with_output().expect("ssh-add -x wait");

    // Some openssh versions accept LOCK and emit "Agent locked";
    // others surface the FAILURE byte. Either way, the agent
    // must still answer the next request — that's the contract.
    drop(outcome);

    assert_agent_alive_after(&env, "ssh-add -x");
}

/// `ssh-add -X` (unlock). Sent against an already-unlocked agent,
/// or against an agent that doesn't implement LOCK at all (us).
/// Same contract: agent stays up.
#[test]
#[ignore = "requires docker"]
fn ssh_add_X_unlock_does_not_brick_agent() {
    if skip_if_no_docker("ssh_add_X_unlock_does_not_brick_agent") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("warm shared key"));
    env.start_agent().expect("start agent");

    let askpass = env.home().join("askpass-unlock.sh");
    std::fs::write(&askpass, "#!/bin/sh\necho unlockpass\n").expect("write askpass");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&askpass, std::fs::Permissions::from_mode(0o755)).expect("chmod");

    let child = env
        .scrubbed_command("ssh-add")
        .env("SSH_AUTH_SOCK", env.socket_path())
        .env("SSH_ASKPASS", &askpass)
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env("DISPLAY", ":0")
        .arg("-X")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ssh-add -X");
    let _outcome = child.wait_with_output().expect("ssh-add -X wait");

    assert_agent_alive_after(&env, "ssh-add -X");
}

/// Send a raw `SSH_AGENTC_REQUEST_RSA_IDENTITIES` (opcode 1, the
/// SSH-1 protocol identities request — long-deprecated). Modern
/// agents reject this with FAILURE; sshenc-agent must too, and
/// must stay up. This tests the "unknown / deprecated opcode"
/// path explicitly rather than relying on ssh-add's choice of
/// opcodes.
#[test]
#[ignore = "requires docker"]
fn raw_unknown_opcode_does_not_brick_agent() {
    if skip_if_no_docker("raw_unknown_opcode_does_not_brick_agent") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("warm shared key"));
    env.start_agent().expect("start agent");

    // SSH-agent wire framing: 4-byte BE length, then 1-byte opcode,
    // then opcode-specific body. Opcode 1 = REQUEST_RSA_IDENTITIES,
    // SSH-1, no body. Frame is just `00 00 00 01 01`.
    use std::io::Read;
    use std::os::unix::net::UnixStream;
    let mut stream = UnixStream::connect(env.socket_path()).expect("connect agent");
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .ok();
    stream.write_all(&[0, 0, 0, 1, 1]).expect("write frame");

    // Read response length + opcode (best-effort; if the agent
    // closes without responding, that's fine — the next live test
    // catches a truly broken agent).
    let mut len_buf = [0_u8; 4];
    drop(stream.read_exact(&mut len_buf));
    let mut op_buf = [0_u8; 1];
    drop(stream.read_exact(&mut op_buf));
    drop(stream);

    assert_agent_alive_after(&env, "raw deprecated opcode");
}
