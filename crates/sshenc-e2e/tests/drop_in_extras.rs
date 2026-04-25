// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Additional drop-in compatibility scenarios beyond `drop_in.rs`.
//!
//! `drop_in.rs` covers the core "ssh-with-sshenc" contract. This
//! file extends to neighboring OpenSSH tools that share the same
//! agent socket:
//!
//! - `ssh-add -L` lists the enclave key the agent exposes.
//! - `scp` uploads a file using the agent for auth.
//! - `sftp -b` runs a batch via the agent.
//! - `ssh -i <pub-only-file>` resolves to the agent-mediated key
//!   (the pub file is just a selection hint; the agent does the
//!   signing).
//!
//! All scenarios use the same persistent enclave key the rest of
//! the suite shares, so no extra macOS keychain prompt cost.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{
    docker_skip_reason, run, shared_enclave_pubkey, SshdContainer, SshencEnv, SHARED_ENCLAVE_LABEL,
};

fn skip_if_no_docker(test_name: &str) -> bool {
    if let Some(reason) = docker_skip_reason() {
        eprintln!("skip {test_name}: {reason}");
        return true;
    }
    false
}

/// Pub-key body (second whitespace field) for containment checks
/// against `ssh-add -L` output.
fn pub_body(line: &str) -> &str {
    line.split_whitespace()
        .nth(1)
        .expect("pub line should have a body")
}

/// `ssh-add -L` (against the sshenc agent socket) prints the
/// enclave key body. This is the basic hand-off contract:
/// programs using `SSH_AUTH_SOCK` must see what the agent
/// publishes.
#[test]
#[ignore = "requires docker"]
fn ssh_add_l_lists_enclave_key_via_agent_socket() {
    if skip_if_no_docker("ssh_add_l_lists_enclave_key_via_agent_socket") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");

    let listed = run(env
        .scrubbed_command("ssh-add")
        .env("SSH_AUTH_SOCK", env.socket_path())
        .arg("-L"))
    .expect("ssh-add -L");
    assert!(
        listed.succeeded(),
        "ssh-add -L should succeed; stderr:\n{}",
        listed.stderr
    );
    assert!(
        listed.stdout.contains(pub_body(&enclave)),
        "ssh-add -L output should contain enclave key body; got:\n{}",
        listed.stdout
    );
}

/// `scp` uses `IdentityAgent` to upload a file via the sshenc
/// agent. Auth happens through the same agent that serves
/// `ssh-add -L`; if the agent → ssh handoff is broken for scp,
/// this catches it.
#[test]
#[ignore = "requires docker"]
fn scp_uploads_file_via_sshenc_agent() {
    if skip_if_no_docker("scp_uploads_file_via_sshenc_agent") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let container = SshdContainer::start(&[&enclave]).expect("sshd container");

    let local_file = env.home().join("payload.txt");
    std::fs::write(&local_file, b"scp upload via sshenc agent\n").expect("write file");

    let mut cmd = env.scp_cmd(&container);
    cmd.arg("-o")
        .arg(format!("IdentityAgent={}", env.socket_path().display()))
        .arg(&local_file)
        .arg("sshtest@127.0.0.1:/tmp/scp-uploaded.txt");
    let out = run(&mut cmd).expect("scp");
    assert!(
        out.succeeded(),
        "scp via sshenc agent failed; stdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );

    // Verify the file made it.
    let outcome = run(env
        .ssh_cmd(&container)
        .arg("-o")
        .arg(format!("IdentityAgent={}", env.socket_path().display()))
        .arg("sshtest@127.0.0.1")
        .arg("cat /tmp/scp-uploaded.txt"))
    .expect("ssh cat");
    assert!(
        outcome.succeeded(),
        "post-scp ssh cat failed; stderr:\n{}",
        outcome.stderr
    );
    assert!(
        outcome.stdout.contains("scp upload via sshenc agent"),
        "scp-uploaded content missing; got:\n{}",
        outcome.stdout
    );
}

/// `sftp -b` runs a batch through the agent: the same auth path
/// scp uses, plus a few sftp-specific protocol exchanges. Any
/// regression in agent handoff that doesn't show up under `ssh`
/// or `scp` (subsystem multiplexing, channel teardown, etc.)
/// would surface here.
#[test]
#[ignore = "requires docker"]
fn sftp_batch_runs_via_sshenc_agent() {
    if skip_if_no_docker("sftp_batch_runs_via_sshenc_agent") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let container = SshdContainer::start(&[&enclave]).expect("sshd container");

    // sftp batch: pwd then bye, all non-interactive.
    let batch = env.home().join("sftp.batch");
    std::fs::write(&batch, b"pwd\nbye\n").expect("write sftp batch");

    let mut cmd = env.sftp_cmd(&container);
    cmd.arg("-o")
        .arg(format!("IdentityAgent={}", env.socket_path().display()))
        .arg("-b")
        .arg(&batch)
        .arg("sshtest@127.0.0.1");
    let out = run(&mut cmd).expect("sftp -b");
    assert!(
        out.succeeded(),
        "sftp -b via sshenc agent failed; stdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    // The pwd command's response should appear in stdout (typically
    // a path like /home/sshtest).
    assert!(
        out.stdout.contains("/home/sshtest") || out.stdout.contains("Remote working directory"),
        "sftp pwd response missing; got:\n{}",
        out.stdout
    );
}

/// Pointing `ssh -i` at a pub-only file (no private half on disk)
/// must still succeed when the agent has the matching identity.
/// OpenSSH treats the pub file as a hint to pick the right
/// agent-published key; the agent does the actual signing.
#[test]
#[ignore = "requires docker"]
fn ssh_with_pub_only_identity_file_uses_agent() {
    if skip_if_no_docker("ssh_with_pub_only_identity_file_uses_agent") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let container = SshdContainer::start(&[&enclave]).expect("sshd container");

    // Write the pub file at a non-default path; no matching
    // private half exists.
    let pub_only = env.ssh_dir().join("pub-only-hint.pub");
    std::fs::create_dir_all(env.ssh_dir()).expect("mkdir ssh dir");
    std::fs::write(&pub_only, format!("{enclave}\n")).expect("write pub-only");

    let mut cmd = env.ssh_cmd(&container);
    cmd.arg("-o")
        .arg(format!("IdentityAgent={}", env.socket_path().display()))
        .arg("-o")
        .arg("IdentitiesOnly=yes")
        .arg("-i")
        .arg(&pub_only)
        .arg("sshtest@127.0.0.1")
        .arg("echo via-agent-pub-only-hint");
    let out = run(&mut cmd).expect("ssh -i pub-only");
    assert!(
        out.succeeded(),
        "ssh with pub-only -i failed; stdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    assert!(
        out.stdout.contains("via-agent-pub-only-hint"),
        "expected echo output; got:\n{}",
        out.stdout
    );
}

/// `ssh-add -D` (delete all identities from agent) must NOT brick
/// the agent. The sshenc agent doesn't support remove-identity
/// (it manages keys via its own extensions), so the request
/// either errors cleanly or is a no-op. Either way, subsequent
/// `ssh-add -L` still lists the enclave key.
#[test]
#[ignore = "requires docker"]
fn ssh_add_remove_all_does_not_brick_agent() {
    if skip_if_no_docker("ssh_add_remove_all_does_not_brick_agent") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");

    // ssh-add -D — best-effort; succeeds or fails, doesn't matter.
    drop(run(env
        .scrubbed_command("ssh-add")
        .env("SSH_AUTH_SOCK", env.socket_path())
        .arg("-D")));

    // Critical: ssh-add -L must still work and still see the key.
    // The agent doesn't actually remove the enclave key (the
    // remove-identity opcode falls through to FAILURE), so the
    // identity persists.
    let listed = run(env
        .scrubbed_command("ssh-add")
        .env("SSH_AUTH_SOCK", env.socket_path())
        .arg("-L"))
    .expect("ssh-add -L post -D");
    assert!(
        listed.succeeded(),
        "ssh-add -L after -D failed; stderr:\n{}",
        listed.stderr
    );
    assert!(
        listed.stdout.contains(pub_body(&enclave)),
        "enclave key should still be listed after -D (sshenc-managed identities are not removable via -D); got:\n{}",
        listed.stdout
    );
    let _ = SHARED_ENCLAVE_LABEL;
}
