// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `sshenc-agent --labels A` filtering must hold under concurrent
//! load. `keygen_up_and_agent_labels.rs` proves the *boundary*
//! works (one ssh-add -L call sees only A, not B), and
//! `agent_concurrency.rs` proves sign+list don't race against each
//! other on an unfiltered agent. The intersection — does the label
//! filter still hold when many clients hit the agent at once? —
//! wasn't pinned. A regression where the filter is checked outside
//! the per-connection lock, or where identity caching leaks across
//! filtered requests, would surface here and nowhere else.
//!
//! Two contracts:
//! - parallel `ssh-add -L` against an agent with `--labels A`
//!   never returns label B's pubkey, no matter how many concurrent
//!   callers there are.
//! - parallel sign requests for label A succeed; the agent doesn't
//!   reject a legitimate-but-filter-allowed key under load.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{
    docker_skip_reason, extended_enabled, run, shared_enclave_pubkey, software_mode, workspace_bin,
    SshencEnv, SHARED_ENCLAVE_LABEL,
};
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;

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
        "skip {test_name}: needs to mint extra keys; \
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

/// Spawn `sshenc-agent --foreground --labels <list>` and wait for
/// its socket to come up. Returns a Child whose stderr is piped so
/// the caller can dump it on assertion failure. Caller must kill+
/// wait the child.
fn spawn_labeled_agent(env: &SshencEnv, labels: &[&str]) -> std::process::Child {
    drop(std::fs::remove_file(env.socket_path()));
    let bin = workspace_bin("sshenc-agent").expect("agent binary");
    let mut cmd = env.scrubbed_command(&bin);
    cmd.arg("--foreground")
        .arg("--socket")
        .arg(env.socket_path())
        .arg("--labels")
        .arg(labels.join(","))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn labeled agent");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut bound = false;
    while std::time::Instant::now() < deadline {
        if env.socket_path().exists()
            && std::os::unix::net::UnixStream::connect(env.socket_path()).is_ok()
        {
            bound = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    if !bound {
        drop(child.kill());
        let out = child.wait_with_output().ok();
        let stderr = out
            .as_ref()
            .map(|o| String::from_utf8_lossy(&o.stderr).into_owned())
            .unwrap_or_default();
        panic!(
            "labeled agent did not bind socket {} in time; stderr:\n{stderr}",
            env.socket_path().display()
        );
    }
    child
}

/// Run `sshenc -Y sign -n <namespace> -f <pub_path> <data>` against
/// the active agent. Returns the outcome.
fn ssh_sign(
    env: &SshencEnv,
    namespace: &str,
    pub_path: &Path,
    data: &Path,
) -> sshenc_e2e::RunOutcome {
    let mut cmd = env.sshenc_cmd().expect("sshenc cmd");
    cmd.arg("-Y")
        .arg("sign")
        .arg("-n")
        .arg(namespace)
        .arg("-f")
        .arg(pub_path)
        .arg(data);
    run(&mut cmd).expect("sshenc -Y sign")
}

/// `ssh-add -L` against the agent socket. Returns the stdout text.
fn ssh_add_list(env: &SshencEnv) -> sshenc_e2e::RunOutcome {
    run(env
        .scrubbed_command("ssh-add")
        .env("SSH_AUTH_SOCK", env.socket_path())
        .arg("-L"))
    .expect("ssh-add -L")
}

/// N parallel `ssh-add -L` invocations against an agent started with
/// `--labels SHARED`. Every reply must contain SHARED's pubkey body
/// and never the OTHER label's pubkey body, no matter how many
/// callers hit the agent at once.
#[test]
#[ignore = "requires docker"]
fn parallel_ssh_add_against_labeled_agent_only_shows_allowed_label() {
    if skip_if_no_docker("parallel_ssh_add_against_labeled_agent_only_shows_allowed_label") {
        return;
    }
    if skip_unless_key_creation_cheap(
        "parallel_ssh_add_against_labeled_agent_only_shows_allowed_label",
    ) {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let shared = shared_enclave_pubkey(&env).expect("shared enclave");

    // Pre-start the unfiltered agent so the keygen+export-pub below
    // don't race against ensure_daemon_ready. We tear it down before
    // spawning the labeled agent.
    env.start_agent().expect("start unfiltered agent");

    // Mint a second key so the agent's underlying keys_dir has two
    // identities. With --labels SHARED, only one should surface.
    let other = unique_label("labels-conc-other");
    let kg = run(env.sshenc_cmd().expect("sshenc").args([
        "keygen",
        "--label",
        &other,
        "--auth-policy",
        "none",
        "--no-pub-file",
    ]))
    .expect("keygen other");
    assert!(kg.succeeded(), "keygen other: {}", kg.stderr);

    let other_pub = run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["export-pub", &other]))
    .expect("export-pub other");
    assert!(other_pub.succeeded(), "export-pub: {}", other_pub.stderr);
    let other_body = other_pub
        .stdout
        .split_whitespace()
        .nth(1)
        .expect("other pub body")
        .to_string();
    let shared_body = shared
        .split_whitespace()
        .nth(1)
        .expect("shared pub body")
        .to_string();

    env.stop_agent();
    let mut agent = spawn_labeled_agent(&env, &[SHARED_ENCLAVE_LABEL]);

    let env = Arc::new(env);
    const N: usize = 8;
    let mut handles = Vec::with_capacity(N);
    for i in 0..N {
        let env = Arc::clone(&env);
        let other_body = other_body.clone();
        let shared_body = shared_body.clone();
        handles.push(std::thread::spawn(move || {
            let listed = ssh_add_list(&env);
            assert!(
                listed.succeeded(),
                "worker {i} ssh-add -L failed; stderr:\n{}",
                listed.stderr
            );
            assert!(
                listed.stdout.contains(&shared_body),
                "worker {i} did not see shared key in ssh-add output:\n{}",
                listed.stdout
            );
            assert!(
                !listed.stdout.contains(&other_body),
                "worker {i} saw filtered-out label '{other_body}'; ssh-add output:\n{}",
                listed.stdout
            );
        }));
    }
    for (i, h) in handles.into_iter().enumerate() {
        h.join()
            .unwrap_or_else(|e| panic!("worker {i} panicked: {e:?}"));
    }

    drop(agent.kill());
    drop(agent.wait_with_output());
    let env = Arc::try_unwrap(env).expect("env Arc unique");
    drop(run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["delete", &other, "-y"])));
}

/// Concurrent `sshenc -Y sign` requests for the *allowed* label
/// (the shared one) all succeed against an `--labels SHARED` agent.
/// Filtering must not introduce an artificial reject for legitimate
/// traffic under load.
#[test]
#[ignore = "requires docker"]
fn parallel_sign_for_allowed_label_succeeds_under_filter() {
    if skip_if_no_docker("parallel_sign_for_allowed_label_succeeds_under_filter") {
        return;
    }
    if skip_unless_key_creation_cheap("parallel_sign_for_allowed_label_succeeds_under_filter") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let shared = shared_enclave_pubkey(&env).expect("shared enclave");

    env.start_agent().expect("start unfiltered agent");

    // Mint a second key so the keys_dir has two identities the
    // filter must distinguish between.
    let other = unique_label("labels-conc-sign-other");
    let kg = run(env.sshenc_cmd().expect("sshenc").args([
        "keygen",
        "--label",
        &other,
        "--auth-policy",
        "none",
        "--no-pub-file",
    ]))
    .expect("keygen other");
    assert!(kg.succeeded(), "keygen other: {}", kg.stderr);

    let pub_path = env.ssh_dir().join(format!("{SHARED_ENCLAVE_LABEL}.pub"));
    std::fs::create_dir_all(pub_path.parent().unwrap()).expect("mkdir ssh dir");
    std::fs::write(&pub_path, format!("{shared}\n")).expect("write pub");

    env.stop_agent();
    let mut agent = spawn_labeled_agent(&env, &[SHARED_ENCLAVE_LABEL]);

    let env = Arc::new(env);
    let pub_path = Arc::new(pub_path);
    const N: usize = 6;
    let mut handles = Vec::with_capacity(N);
    for i in 0..N {
        let env = Arc::clone(&env);
        let pub_path = Arc::clone(&pub_path);
        handles.push(std::thread::spawn(move || {
            let data = env.home().join(format!("filter-sign-{i}.txt"));
            std::fs::write(&data, format!("filter sign worker {i}\n")).expect("write data");
            let outcome = ssh_sign(&env, "git", &pub_path, &data);
            assert!(
                outcome.succeeded(),
                "worker {i} sign failed; stderr:\n{}",
                outcome.stderr
            );
            let sig = data.with_extension("txt.sig");
            assert!(sig.exists(), "worker {i} sigfile missing");
        }));
    }
    for (i, h) in handles.into_iter().enumerate() {
        h.join()
            .unwrap_or_else(|e| panic!("worker {i} panicked: {e:?}"));
    }

    drop(agent.kill());
    drop(agent.wait_with_output());
    let env = Arc::try_unwrap(env).expect("env Arc unique");
    drop(run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["delete", &other, "-y"])));
}
