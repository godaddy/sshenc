// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Agent concurrency beyond RequestIdentities.
//!
//! `agent_protocol_edge.rs::concurrent_connections_each_get_clean_reply`
//! covers N concurrent **RequestIdentities**, but the agent's heavier
//! operation is **SignRequest** — that's what most clients spend their
//! time doing. These tests exercise:
//!
//! - N concurrent `sshenc -Y sign` invocations all produce valid
//!   sigs that real ssh-keygen verifies (no signature corruption, no
//!   deadlock, no cross-talk between connections).
//! - Mixed sign + identity-enumeration traffic: signing threads
//!   running alongside `ssh-add -L` threads — both code paths share
//!   the backend and must not interfere.
//!
//! Unix-only because the sign code path uses `sshenc -Y sign` which
//! we test through real OpenSSH `ssh-keygen -Y verify` (Windows
//! ssh-keygen has different exec semantics; the wire-protocol
//! invariant covered here applies on both platforms but the
//! end-to-end verify isn't portable).

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{docker_skip_reason, run, shared_enclave_pubkey, SshencEnv, SHARED_ENCLAVE_LABEL};
use std::io::Write;
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

const PRINCIPAL: &str = "signer@concurrency.test";

/// Set up env: shared enclave key, agent started, allowed_signers
/// seeded for ssh-keygen verify.
fn setup() -> (SshencEnv, std::path::PathBuf, std::path::PathBuf, String) {
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");

    let pub_path = env.ssh_dir().join(format!("{SHARED_ENCLAVE_LABEL}.pub"));
    std::fs::create_dir_all(pub_path.parent().unwrap()).expect("mkdir ssh dir");
    std::fs::write(&pub_path, format!("{enclave}\n")).expect("write pub");

    let allowed = env.ssh_dir().join("allowed_signers");
    std::fs::write(&allowed, format!("{PRINCIPAL} {enclave}\n")).expect("write allowed_signers");

    (env, pub_path, allowed, enclave)
}

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

fn ssh_keygen_verify(
    env: &SshencEnv,
    allowed: &Path,
    namespace: &str,
    sig: &Path,
    data: &Path,
) -> bool {
    let data_bytes = std::fs::read(data).expect("read data");
    let mut child = env
        .scrubbed_command("ssh-keygen")
        .arg("-Y")
        .arg("verify")
        .arg("-f")
        .arg(allowed)
        .arg("-I")
        .arg(PRINCIPAL)
        .arg("-n")
        .arg(namespace)
        .arg("-s")
        .arg(sig)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ssh-keygen verify");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        stdin.write_all(&data_bytes).expect("write data");
    }
    child.wait().expect("ssh-keygen wait").success()
}

/// N concurrent `sshenc -Y sign` invocations, each over a unique
/// data file. All must produce valid sigs that real ssh-keygen
/// verifies — proving the agent serves SignRequest concurrently
/// without cross-talk or signature corruption.
#[test]
#[ignore = "requires docker"]
fn agent_handles_concurrent_sign_requests() {
    if skip_if_no_docker("agent_handles_concurrent_sign_requests") {
        return;
    }
    let (env, pub_path, allowed, _enclave) = setup();
    let env = Arc::new(env);
    let pub_path = Arc::new(pub_path);
    let allowed = Arc::new(allowed);

    const N: usize = 8;
    let mut handles = Vec::with_capacity(N);
    for i in 0..N {
        let env = Arc::clone(&env);
        let pub_path = Arc::clone(&pub_path);
        let allowed = Arc::clone(&allowed);
        handles.push(std::thread::spawn(move || {
            // Each worker writes its own data file with unique
            // bytes so verify-after-sign actually checks per-thread
            // payload integrity (not just "some sig was produced").
            let data = env.home().join(format!("concurrent-sign-{i}.txt"));
            let payload = format!("worker-{i}-payload-{}\n", i.wrapping_mul(0x9E37_79B9));
            std::fs::write(&data, payload.as_bytes()).expect("write data");
            let outcome = ssh_sign(&env, "git", &pub_path, &data);
            assert!(
                outcome.succeeded(),
                "worker {i} sign failed; stderr:\n{}",
                outcome.stderr
            );
            let sig = data.with_extension("txt.sig");
            assert!(sig.exists(), "worker {i} sigfile missing");
            assert!(
                ssh_keygen_verify(&env, &allowed, "git", &sig, &data),
                "worker {i} signature failed to verify"
            );
        }));
    }
    for (i, h) in handles.into_iter().enumerate() {
        h.join()
            .unwrap_or_else(|e| panic!("worker {i} panicked: {e:?}"));
    }
}

/// Mixed concurrent traffic: half the threads sign, half enumerate
/// identities. Both must succeed under contention; the agent must
/// not deadlock or starve one path under load from the other.
#[test]
#[ignore = "requires docker"]
fn agent_handles_mixed_sign_and_list_concurrent() {
    if skip_if_no_docker("agent_handles_mixed_sign_and_list_concurrent") {
        return;
    }
    let (env, pub_path, allowed, enclave) = setup();
    let env = Arc::new(env);
    let pub_path = Arc::new(pub_path);
    let allowed = Arc::new(allowed);

    // Extract the base64 key body (second whitespace field) for the
    // ssh-add -L containment check. ssh-add -L emits a slightly
    // different comment than what we wrote, but the key body is
    // identical.
    let key_body = enclave
        .split_whitespace()
        .nth(1)
        .expect("enclave pubkey body")
        .to_string();
    let key_body = Arc::new(key_body);

    const SIGN_WORKERS: usize = 4;
    const LIST_WORKERS: usize = 4;
    let mut handles = Vec::with_capacity(SIGN_WORKERS + LIST_WORKERS);

    for i in 0..SIGN_WORKERS {
        let env = Arc::clone(&env);
        let pub_path = Arc::clone(&pub_path);
        let allowed = Arc::clone(&allowed);
        handles.push(std::thread::spawn(move || {
            let data = env.home().join(format!("mixed-sign-{i}.txt"));
            std::fs::write(&data, format!("mix sign {i}\n")).expect("write data");
            let outcome = ssh_sign(&env, "git", &pub_path, &data);
            assert!(
                outcome.succeeded(),
                "sign worker {i} failed; stderr:\n{}",
                outcome.stderr
            );
            let sig = data.with_extension("txt.sig");
            assert!(
                ssh_keygen_verify(&env, &allowed, "git", &sig, &data),
                "sign worker {i} sig failed to verify"
            );
        }));
    }

    for i in 0..LIST_WORKERS {
        let env = Arc::clone(&env);
        let key_body = Arc::clone(&key_body);
        handles.push(std::thread::spawn(move || {
            let listed = run(env
                .scrubbed_command("ssh-add")
                .env("SSH_AUTH_SOCK", env.socket_path())
                .arg("-L"))
            .expect("ssh-add -L");
            assert!(
                listed.succeeded(),
                "list worker {i} failed; stderr:\n{}",
                listed.stderr
            );
            assert!(
                listed.stdout.contains(key_body.as_str()),
                "list worker {i} did not see expected key body; got:\n{}",
                listed.stdout
            );
        }));
    }

    for (i, h) in handles.into_iter().enumerate() {
        h.join()
            .unwrap_or_else(|e| panic!("mixed worker {i} panicked: {e:?}"));
    }
}
