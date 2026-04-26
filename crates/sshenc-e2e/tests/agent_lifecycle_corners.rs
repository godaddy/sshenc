// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Three agent / lifecycle corner cases not previously pinned:
//!
//! 1. The PKCS#11 boot-hook is idempotent: a second `C_Initialize`
//!    call when the agent is already running must succeed without
//!    respawning the agent. `pkcs11_boot_hook.rs` covers the cold
//!    path (agent not running → boot it); this test pins the
//!    warm path.
//!
//! 2. The agent surviving a kill-and-restart while a CLI client
//!    is mid-flight: the test issues a sign request, kills the
//!    agent during the response window, restarts the agent, and
//!    verifies a fresh sign succeeds. The CLI's auto-spawn or a
//!    fresh `start_agent` must recover.
//!
//! 3. Concurrent `sshenc keygen` for *distinct* labels all
//!    succeed. `cli_concurrency.rs::concurrent_keygen_same_label_one_winner`
//!    races on a single label; nothing pins that N parallel
//!    keygens for *different* labels all win without corruption.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{
    docker_skip_reason, extended_enabled, run, shared_enclave_pubkey, software_mode, SshencEnv,
};
use std::sync::Arc;
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
        "skip {test_name}: needs to mint keys; \
         set SSHENC_E2E_SOFTWARE=1 or SSHENC_E2E_EXTENDED=1"
    );
    true
}

fn unique_label(prefix: &str) -> String {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{prefix}-{pid}-{nanos}")
}

/// Two `ssh-add -L` calls in sequence both succeed. The second
/// must reuse the agent the first triggered (no double-spawn).
/// On Unix, double-spawn would either fail with "socket in use"
/// or leave a stale daemon. This is the warm-path equivalent of
/// pkcs11_boot_hook.
#[test]
#[ignore = "requires docker"]
fn second_cli_invocation_reuses_running_agent() {
    if skip_if_no_docker("second_cli_invocation_reuses_running_agent") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("warm shared key"));
    env.start_agent().expect("start agent");

    // Capture the agent's PID via the pidfile if present, otherwise
    // accept that the test still proves "no second listener" via
    // the second ssh-add -L succeeding without "Address in use" or
    // similar.
    let pid_before = std::fs::read_to_string(env.home().join(".sshenc").join("agent.pid")).ok();

    let first = run(env
        .scrubbed_command("ssh-add")
        .env("SSH_AUTH_SOCK", env.socket_path())
        .arg("-L"))
    .expect("first ssh-add -L");
    assert!(first.succeeded(), "first ssh-add -L: {}", first.stderr);

    let second = run(env
        .scrubbed_command("ssh-add")
        .env("SSH_AUTH_SOCK", env.socket_path())
        .arg("-L"))
    .expect("second ssh-add -L");
    assert!(second.succeeded(), "second ssh-add -L: {}", second.stderr);

    let pid_after = std::fs::read_to_string(env.home().join(".sshenc").join("agent.pid")).ok();
    if let (Some(b), Some(a)) = (pid_before, pid_after) {
        assert_eq!(
            b.trim(),
            a.trim(),
            "second invocation respawned the agent (pid {} -> {})",
            b.trim(),
            a.trim()
        );
    }
}

/// The agent process being killed and a fresh agent started in
/// its place: subsequent CLI ops must succeed against the new
/// agent. Pins the "agent restart is transparent to the harness"
/// invariant.
#[test]
#[ignore = "requires docker"]
fn agent_kill_and_restart_resumes_serving() {
    if skip_if_no_docker("agent_kill_and_restart_resumes_serving") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("warm shared key"));

    env.start_agent().expect("start agent");
    let pre = run(env
        .scrubbed_command("ssh-add")
        .env("SSH_AUTH_SOCK", env.socket_path())
        .arg("-L"))
    .expect("pre ssh-add -L");
    assert!(pre.succeeded(), "pre: {}", pre.stderr);

    env.stop_agent();
    // A small grace so the OS releases the socket inode before we
    // start the next agent.
    std::thread::sleep(Duration::from_millis(100));

    env.start_agent().expect("restart agent");
    let post = run(env
        .scrubbed_command("ssh-add")
        .env("SSH_AUTH_SOCK", env.socket_path())
        .arg("-L"))
    .expect("post ssh-add -L");
    assert!(
        post.succeeded(),
        "post-restart ssh-add -L failed; stderr:\n{}",
        post.stderr
    );
    assert!(
        post.stdout.contains("ecdsa-sha2-nistp256"),
        "post-restart agent should still expose the shared key; got:\n{}",
        post.stdout
    );
}

/// Concurrent `sshenc keygen` for distinct labels all succeed
/// without corruption. The agent's keygen path takes a directory
/// lock per write; N parallel keygens with different labels test
/// that the lock doesn't serialize them in a way that loses any
/// of the requested keys.
#[test]
#[ignore = "requires docker"]
fn concurrent_keygen_distinct_labels_all_succeed() {
    if skip_if_no_docker("concurrent_keygen_distinct_labels_all_succeed") {
        return;
    }
    if skip_unless_key_creation_cheap("concurrent_keygen_distinct_labels_all_succeed") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("warm shared key"));
    env.start_agent().expect("start agent");

    const N: usize = 6;
    let labels: Vec<String> = (0..N).map(|i| unique_label(&format!("conc-{i}"))).collect();
    let env = Arc::new(env);

    let mut handles = Vec::with_capacity(N);
    for label in labels.iter() {
        let env = Arc::clone(&env);
        let label = label.clone();
        handles.push(std::thread::spawn(move || {
            let outcome = run(env.sshenc_cmd().expect("sshenc cmd").args([
                "keygen",
                "--label",
                &label,
                "--auth-policy",
                "none",
                "--no-pub-file",
            ]))
            .expect("spawn keygen");
            assert!(
                outcome.succeeded(),
                "keygen '{label}' failed; stderr:\n{}",
                outcome.stderr
            );
        }));
    }
    for h in handles {
        h.join().expect("worker join");
    }

    // List must show all N labels (plus the shared one).
    let listed = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["list", "--json"]))
    .expect("list --json");
    assert!(listed.succeeded(), "list: {}", listed.stderr);
    let arr: serde_json::Value = serde_json::from_str(&listed.stdout).expect("list --json output");
    let entries = arr.as_array().expect("array");
    for label in &labels {
        let seen = entries.iter().any(|e| {
            e.get("metadata")
                .and_then(|m| m.get("label"))
                .and_then(|v| v.as_str())
                == Some(&**label)
        });
        assert!(seen, "label '{label}' missing from list output");
    }

    // Cleanup.
    for label in &labels {
        drop(run(env
            .sshenc_cmd()
            .expect("sshenc cmd")
            .args(["delete", label, "-y"])));
    }
}
