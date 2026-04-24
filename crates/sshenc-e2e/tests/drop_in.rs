// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Drop-in compatibility e2e tests.
//!
//! Prove that sshenc authenticates correctly against a real OpenSSH server
//! running inside a Docker container in six distinct scenarios that together
//! cover the "drop-in replacement for ssh" contract.
//!
//! All tests are `#[ignore]` by default; run with:
//!
//! ```
//! cargo test -p sshenc-e2e -- --ignored --test-threads=1
//! ```
//!
//! `--test-threads=1` is important on macOS: the scenarios share a single
//! enclave key to hold the keychain "Always Allow" prompt count to
//! one-per-binary-per-rebuild, and concurrent signing through the agent
//! serializes cleanly only under serial test execution.

#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{
    docker_skip_reason, generate_on_disk_ed25519, run, shared_enclave_pubkey, SshdContainer,
    SshencEnv,
};
use std::process::Command;

/// Print a skip message and return true if Docker is unavailable. Each test
/// calls this first and early-returns on true so CI without Docker doesn't
/// hard-fail the suite.
fn skip_if_no_docker(test_name: &str) -> bool {
    if let Some(reason) = docker_skip_reason() {
        eprintln!("skip {test_name}: {reason}");
        return true;
    }
    false
}

/// Invoke `sshenc ssh [--label L] -- <isolated-ssh-flags> sshtest@127.0.0.1 true`.
///
/// Always passes `-i <tempdir>/.ssh/id_ed25519` when the on-disk key exists:
/// without it, OpenSSH's default identity search resolves `~/.ssh/id_ed25519`
/// via `getpwuid`, which points at the real user's home rather than the
/// per-test tempdir, so the test would never offer the on-disk key it
/// just generated. Passing `-i` restores the "drop-in" semantics we're
/// trying to verify (the on-disk key from the sandbox is a candidate).
fn sshenc_ssh_to(env: &SshencEnv, container: &SshdContainer, label: Option<&str>) -> Command {
    let mut cmd = env.sshenc_cmd().expect("sshenc cmd");
    cmd.arg("ssh");
    if let Some(label) = label {
        cmd.arg("--label").arg(label);
    }
    cmd.arg("--");
    SshencEnv::apply_ssh_isolation(&mut cmd, container.host_port, &env.known_hosts());
    // Only add the on-disk IdentityFile when no label is forcing enclave-only
    // selection. The `--label` path's whole purpose is `IdentitiesOnly yes`
    // plus a single enclave IdentityFile — adding our on-disk `-i` would
    // defeat the restriction scenario 5 is verifying.
    if label.is_none() {
        let on_disk_path = env.ssh_dir().join("id_ed25519");
        if on_disk_path.exists() {
            cmd.arg("-i").arg(&on_disk_path);
        }
    }
    cmd.arg("sshtest@127.0.0.1").arg("true");
    cmd
}

/// Scenario 1: the `sshenc install` flow is drop-in for on-disk keys.
///
/// Simulates the user's actual install path:
///   - fresh sshenc install with no enclave keys yet,
///   - `sshenc install` writes the managed `Host *` block with
///     `IdentityAgent` into `~/.ssh/config` and starts the agent daemon,
///   - the user continues to run plain `ssh`, expecting their existing
///     on-disk key to keep working.
///
/// Proves `sshenc install` + plain `ssh` preserves drop-in semantics
/// without any additional flags or wrapper invocation.
#[test]
#[ignore = "requires docker"]
fn sshenc_install_preserves_plain_ssh_with_on_disk_keys() {
    if skip_if_no_docker("sshenc_install_preserves_plain_ssh_with_on_disk_keys") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    // No enclave keys — agent has nothing to offer, so success must come
    // from OpenSSH's fallback to the on-disk IdentityFile.
    env.use_ephemeral_keys_dir().expect("ephemeral keys dir");
    let on_disk = generate_on_disk_ed25519(&env, "on-disk@e2e").expect("on-disk keygen");

    // Run the real install flow. This writes ~/.ssh/config and daemonizes
    // the agent; the SshencEnv drop impl cleans up the pidfile-tracked
    // daemon at test teardown.
    let install =
        run(env.sshenc_cmd().expect("sshenc cmd").arg("install")).expect("sshenc install");
    assert!(
        install.succeeded(),
        "sshenc install failed; stderr:\n{}",
        install.stderr
    );

    // The install must have produced a ~/.ssh/config with the managed
    // block pointing at the isolated socket.
    let config_path = env.ssh_dir().join("config");
    let config_text = std::fs::read_to_string(&config_path).expect("read ssh config");
    assert!(
        config_text.contains("IdentityAgent"),
        "expected IdentityAgent directive in {}; got:\n{config_text}",
        config_path.display()
    );
    assert!(
        config_text.contains(&env.socket_path().display().to_string()),
        "IdentityAgent should reference the isolated socket; got:\n{config_text}",
    );

    let container = SshdContainer::start(&[&on_disk]).expect("sshd container");

    // Plain `ssh -F <written-config> …` — no sshenc wrapper, no manual
    // IdentityAgent. The only way this succeeds is if the managed config
    // + running agent + on-disk IdentityFile fallback all cooperate.
    let outcome = run(env
        .scrubbed_command("ssh")
        .arg("-F")
        .arg(&config_path)
        .arg("-o")
        .arg("StrictHostKeyChecking=accept-new")
        .arg("-o")
        .arg(format!(
            "UserKnownHostsFile={}",
            env.known_hosts().display()
        ))
        .arg("-o")
        .arg("ConnectTimeout=10")
        .arg("-o")
        .arg("NumberOfPasswordPrompts=0")
        .arg("-o")
        .arg("PreferredAuthentications=publickey")
        .arg("-p")
        .arg(container.host_port.to_string())
        .arg("-i")
        .arg(env.ssh_dir().join("id_ed25519"))
        .arg("sshtest@127.0.0.1")
        .arg("true"))
    .expect("ssh");
    assert!(
        outcome.succeeded(),
        "expected plain ssh via sshenc-installed config to succeed; stderr:\n{}",
        outcome.stderr
    );
}

/// Scenario 2: agent running but empty, on-disk still works.
///
/// Proves sshenc-agent doesn't break OpenSSH's default on-disk key fallback
/// when the agent has nothing to offer.
///
/// This test uses a per-run isolated keys dir so the agent genuinely has no
/// enclave keys — the other enclave tests share a persistent keys dir, but
/// this one needs "empty agent" semantics.
#[test]
#[ignore = "requires docker"]
fn agent_running_zero_enclave_keys_still_authenticates_on_disk() {
    if skip_if_no_docker("agent_running_zero_enclave_keys_still_authenticates_on_disk") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    env.use_ephemeral_keys_dir().expect("ephemeral keys dir");
    let on_disk = generate_on_disk_ed25519(&env, "on-disk@e2e").expect("on-disk keygen");
    env.start_agent().expect("agent start");
    let container = SshdContainer::start(&[&on_disk]).expect("sshd container");

    let outcome = run(&mut sshenc_ssh_to(&env, &container, None)).expect("sshenc ssh");
    assert!(
        outcome.succeeded(),
        "expected sshenc ssh to succeed via on-disk fallback; stderr:\n{}",
        outcome.stderr
    );
}

/// Scenario 3: both keys present, unlabeled, container accepts on-disk only.
///
/// Proves that when sshenc's agent is running with an enclave key the server
/// doesn't trust, OpenSSH still falls back to on-disk keys.
#[test]
#[ignore = "requires docker"]
fn both_present_unlabeled_falls_back_to_on_disk() {
    if skip_if_no_docker("both_present_unlabeled_falls_back_to_on_disk") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let on_disk = generate_on_disk_ed25519(&env, "on-disk@e2e").expect("on-disk keygen");
    let _enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("agent start");

    let container = SshdContainer::start(&[&on_disk]).expect("sshd container");

    let outcome = run(&mut sshenc_ssh_to(&env, &container, None)).expect("sshenc ssh");
    assert!(
        outcome.succeeded(),
        "expected fallback to on-disk key to succeed; stderr:\n{}",
        outcome.stderr
    );
}

/// Scenario 4: both keys present, unlabeled, container accepts enclave only.
///
/// Proves the agent actually serves enclave identities.
#[test]
#[ignore = "requires docker"]
fn both_present_unlabeled_uses_enclave_via_agent() {
    if skip_if_no_docker("both_present_unlabeled_uses_enclave_via_agent") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let _on_disk = generate_on_disk_ed25519(&env, "on-disk@e2e").expect("on-disk keygen");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("agent start");

    let container = SshdContainer::start(&[&enclave]).expect("sshd container");

    let outcome = run(&mut sshenc_ssh_to(&env, &container, None)).expect("sshenc ssh");
    assert!(
        outcome.succeeded(),
        "expected enclave auth via agent to succeed; stderr:\n{}",
        outcome.stderr
    );
}

/// Scenario 5: `--label` forces enclave key and must NOT fall back.
///
/// The `sshenc ssh --label X` wrapper sets `IdentitiesOnly yes` and a temp
/// `IdentityFile` pointing at the enclave pubkey, so OpenSSH should offer
/// only that one identity. Against a server that trusts only on-disk keys,
/// this must fail.
#[test]
#[ignore = "requires docker"]
fn label_forces_enclave_and_refuses_on_disk_fallback() {
    if skip_if_no_docker("label_forces_enclave_and_refuses_on_disk_fallback") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let on_disk = generate_on_disk_ed25519(&env, "on-disk@e2e").expect("on-disk keygen");
    let _enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("agent start");

    let container = SshdContainer::start(&[&on_disk]).expect("sshd container");

    let outcome = run(&mut sshenc_ssh_to(
        &env,
        &container,
        Some(sshenc_e2e::SHARED_ENCLAVE_LABEL),
    ))
    .expect("sshenc ssh");
    assert!(
        !outcome.succeeded(),
        "expected --label to refuse on-disk fallback; stdout:\n{}\nstderr:\n{}",
        outcome.stdout,
        outcome.stderr
    );
    assert!(
        outcome.stderr.contains("Permission denied") || outcome.stderr.contains("publickey"),
        "expected authentication failure, not a transport error; stderr:\n{}",
        outcome.stderr
    );
}

/// Scenario 6: plain `ssh` with `IdentityAgent=<sshenc-sock>`.
///
/// Proves the "install" path — where `~/.ssh/config` gets an IdentityAgent
/// directive and users continue to invoke plain `ssh` — preserves drop-in
/// semantics. Runs twice: once against a container trusting on-disk, once
/// against a container trusting enclave. Both must succeed.
#[test]
#[ignore = "requires docker"]
fn plain_ssh_with_identity_agent_accepts_both_key_paths() {
    if skip_if_no_docker("plain_ssh_with_identity_agent_accepts_both_key_paths") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let on_disk = generate_on_disk_ed25519(&env, "on-disk@e2e").expect("on-disk keygen");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("agent start");

    for (label, line) in [("on-disk", on_disk.as_str()), ("enclave", enclave.as_str())] {
        let container = SshdContainer::start(&[line]).expect("sshd container");
        let outcome = run(env
            .ssh_cmd(&container)
            .arg("-o")
            .arg(format!("IdentityAgent={}", env.socket_path().display()))
            .arg("-i")
            .arg(env.ssh_dir().join("id_ed25519"))
            .arg("sshtest@127.0.0.1")
            .arg("true"))
        .expect("ssh");
        assert!(
            outcome.succeeded(),
            "variant {label}: expected success; stderr:\n{}",
            outcome.stderr
        );
    }
}
