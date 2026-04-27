// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! The exact pubkey blob (full base64 body) served by the agent
//! is byte-identical across an agent restart. `agent_lifecycle_corners.rs`
//! checks the algo prefix is restored; this pins the entire
//! pubkey body, catching any regression where a restart re-derives
//! the key differently or serves a stale cached version.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{docker_skip_reason, run, shared_enclave_pubkey, SshencEnv};
use std::time::Duration;

fn skip_if_no_docker(test_name: &str) -> bool {
    if let Some(reason) = docker_skip_reason() {
        eprintln!("skip {test_name}: {reason}");
        return true;
    }
    false
}

/// `ssh-add -L` output before and after an agent restart is
/// byte-identical for the same backing keys_dir.
#[test]
#[ignore = "requires docker"]
fn pubkey_body_is_byte_identical_across_restart() {
    if skip_if_no_docker("pubkey_body_is_byte_identical_across_restart") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared key"));

    env.start_agent().expect("start agent");
    let pre = run(env
        .scrubbed_command("ssh-add")
        .env("SSH_AUTH_SOCK", env.socket_path())
        .arg("-L"))
    .expect("pre ssh-add -L");
    assert!(pre.succeeded(), "pre ssh-add -L: {}", pre.stderr);
    let pre_body = pre.stdout.trim().to_string();
    assert!(!pre_body.is_empty(), "ssh-add -L returned no keys");

    env.stop_agent();
    std::thread::sleep(Duration::from_millis(100));
    env.start_agent().expect("restart agent");

    let post = run(env
        .scrubbed_command("ssh-add")
        .env("SSH_AUTH_SOCK", env.socket_path())
        .arg("-L"))
    .expect("post ssh-add -L");
    assert!(post.succeeded(), "post ssh-add -L: {}", post.stderr);
    let post_body = post.stdout.trim().to_string();

    assert_eq!(
        pre_body, post_body,
        "ssh-add -L output drifted across agent restart;\n  before:\n{pre_body}\n  after:\n{post_body}"
    );
}
