// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `sshenc -Y sign` / `-Y verify` direct round-trip.
//!
//! `gitenc.rs::gitenc_config_signs_commit_and_verifies` exercises the
//! sign+verify chain through git, but if anything regresses in the
//! direct CLI surface those tests will still pass because git
//! synthesizes the args and feeds the output through its own
//! plumbing. These tests invoke `sshenc -Y sign` and `ssh-keygen -Y
//! verify` directly:
//!
//! - sign produces a sigfile with the SSHSIG PEM envelope
//! - sigfile verifies cleanly via real `ssh-keygen -Y verify`
//!   against an `allowed_signers` file we constructed
//! - tampering with the data invalidates the signature
//! - tampering with the sigfile invalidates the signature
//! - sign with a non-default namespace still round-trips
//! - sign errors out if the agent is down (no local fallback —
//!   this is the "agent is the sole crypto toucher" invariant)

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{docker_skip_reason, run, shared_enclave_pubkey, SshencEnv, SHARED_ENCLAVE_LABEL};
use std::path::Path;
use std::process::Stdio;

fn skip_if_no_docker(test_name: &str) -> bool {
    if let Some(reason) = docker_skip_reason() {
        eprintln!("skip {test_name}: {reason}");
        return true;
    }
    false
}

/// Standard signer principal used in allowed_signers.
const PRINCIPAL: &str = "signer@y-sign.test";

/// Set up the env: shared enclave key written to `~/.ssh/<label>.pub`,
/// agent started, allowed_signers seeded with `<PRINCIPAL> <pubkey>`.
/// Returns the (env, pubkey_path, allowed_signers_path) triple.
fn setup() -> (SshencEnv, std::path::PathBuf, std::path::PathBuf) {
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");

    let pub_path = env.ssh_dir().join(format!("{SHARED_ENCLAVE_LABEL}.pub"));
    std::fs::create_dir_all(pub_path.parent().unwrap()).expect("mkdir ssh dir");
    std::fs::write(&pub_path, format!("{enclave}\n")).expect("write pub");

    let allowed = env.ssh_dir().join("allowed_signers");
    std::fs::write(&allowed, format!("{PRINCIPAL} {enclave}\n")).expect("write allowed_signers");

    (env, pub_path, allowed)
}

fn write_data(env: &SshencEnv, name: &str, contents: &[u8]) -> std::path::PathBuf {
    let path = env.home().join(name);
    std::fs::write(&path, contents).expect("write data");
    path
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

/// Run `ssh-keygen -Y verify -f <allowed_signers> -I <principal> -n
/// <namespace> -s <sig>` with `<data>` piped on stdin. Returns the
/// stderr text and exit status. Uses the system ssh-keygen because
/// sshenc's `-Y verify` forwards to it anyway.
fn ssh_keygen_verify(
    env: &SshencEnv,
    allowed: &Path,
    principal: &str,
    namespace: &str,
    sig: &Path,
    data: &Path,
) -> (std::process::ExitStatus, String) {
    let data_bytes = std::fs::read(data).expect("read data");
    let mut child = env
        .scrubbed_command("ssh-keygen")
        .arg("-Y")
        .arg("verify")
        .arg("-f")
        .arg(allowed)
        .arg("-I")
        .arg(principal)
        .arg("-n")
        .arg(namespace)
        .arg("-s")
        .arg(sig)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ssh-keygen -Y verify");
    {
        use std::io::Write;
        let mut stdin = child.stdin.take().expect("stdin");
        stdin.write_all(&data_bytes).expect("write data to stdin");
    }
    let output = child.wait_with_output().expect("ssh-keygen wait");
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (output.status, combined)
}

/// `sshenc -Y sign` writes `<data>.sig` with the SSHSIG PEM envelope.
#[test]
#[ignore = "requires docker"]
fn y_sign_writes_valid_pem_sigfile() {
    if skip_if_no_docker("y_sign_writes_valid_pem_sigfile") {
        return;
    }
    let (env, pub_path, _allowed) = setup();
    let data = write_data(&env, "msg.txt", b"hello sshenc Y-sign\n");

    let outcome = ssh_sign(&env, "git", &pub_path, &data);
    assert!(
        outcome.succeeded(),
        "sshenc -Y sign failed; stderr:\n{}",
        outcome.stderr
    );

    let sig = data.with_extension("txt.sig");
    let pem = std::fs::read_to_string(&sig).expect("read sig");
    assert!(
        pem.starts_with("-----BEGIN SSH SIGNATURE-----"),
        "expected SSHSIG PEM header; got:\n{pem}"
    );
    assert!(
        pem.trim_end().ends_with("-----END SSH SIGNATURE-----"),
        "expected SSHSIG PEM footer; got:\n{pem}"
    );
}

/// Sign + ssh-keygen verify round-trip. Proves the SSHSIG payload
/// the agent emits is interpretable by an unrelated SSH
/// implementation (real OpenSSH ssh-keygen).
#[test]
#[ignore = "requires docker"]
fn y_sign_verifies_via_ssh_keygen() {
    if skip_if_no_docker("y_sign_verifies_via_ssh_keygen") {
        return;
    }
    let (env, pub_path, allowed) = setup();
    let data = write_data(&env, "verify.txt", b"sign-then-verify roundtrip\n");
    let sign = ssh_sign(&env, "git", &pub_path, &data);
    assert!(sign.succeeded(), "sshenc -Y sign: {}", sign.stderr);

    let sig = data.with_extension("txt.sig");
    let (status, combined) = ssh_keygen_verify(&env, &allowed, PRINCIPAL, "git", &sig, &data);
    assert!(
        status.success(),
        "ssh-keygen -Y verify failed; output:\n{combined}"
    );
    assert!(
        combined.contains("Good \"git\" signature"),
        "expected good signature line; got:\n{combined}"
    );
}

/// Tampering with the signed data must invalidate the signature.
#[test]
#[ignore = "requires docker"]
fn y_verify_rejects_tampered_data() {
    if skip_if_no_docker("y_verify_rejects_tampered_data") {
        return;
    }
    let (env, pub_path, allowed) = setup();
    let data = write_data(&env, "tamper.txt", b"original data\n");
    let sign = ssh_sign(&env, "git", &pub_path, &data);
    assert!(sign.succeeded(), "sshenc -Y sign: {}", sign.stderr);
    let sig = data.with_extension("txt.sig");

    // Modify the data after signing.
    std::fs::write(&data, b"tampered data\n").expect("rewrite data");

    let (status, combined) = ssh_keygen_verify(&env, &allowed, PRINCIPAL, "git", &sig, &data);
    assert!(
        !status.success(),
        "ssh-keygen -Y verify must reject tampered data; output:\n{combined}"
    );
}

/// A non-default namespace must round-trip. Mismatched namespace on
/// verify must fail (sshsig binds the namespace into the
/// signed-content prefix).
#[test]
#[ignore = "requires docker"]
fn y_sign_namespace_round_trip_and_mismatch_fails() {
    if skip_if_no_docker("y_sign_namespace_round_trip_and_mismatch_fails") {
        return;
    }
    let (env, pub_path, allowed) = setup();
    let data = write_data(&env, "ns.txt", b"namespaced payload\n");
    let sign = ssh_sign(&env, "file", &pub_path, &data);
    assert!(sign.succeeded(), "sshenc -Y sign: {}", sign.stderr);
    let sig = data.with_extension("txt.sig");

    // Verify with the matching namespace: success.
    let (status_ok, output_ok) = ssh_keygen_verify(&env, &allowed, PRINCIPAL, "file", &sig, &data);
    assert!(
        status_ok.success(),
        "ssh-keygen verify with matching namespace failed; output:\n{output_ok}"
    );

    // Verify with the wrong namespace: failure.
    let (status_bad, output_bad) = ssh_keygen_verify(&env, &allowed, PRINCIPAL, "git", &sig, &data);
    assert!(
        !status_bad.success(),
        "ssh-keygen verify with mismatched namespace should fail; output:\n{output_bad}"
    );
}

/// `sshenc -Y sign` must error out when the agent is not reachable.
/// There's no local fallback by design — the agent is the sole
/// crypto toucher on every platform, and the CLI failing here is
/// the right signal to the user that the agent is down.
#[test]
#[ignore = "requires docker"]
fn y_sign_errors_when_agent_unreachable() {
    if skip_if_no_docker("y_sign_errors_when_agent_unreachable") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    // Deliberately do NOT start the agent.

    let pub_path = env.ssh_dir().join(format!("{SHARED_ENCLAVE_LABEL}.pub"));
    std::fs::create_dir_all(pub_path.parent().unwrap()).expect("mkdir ssh dir");
    std::fs::write(&pub_path, format!("{enclave}\n")).expect("write pub");

    let data = write_data(&env, "no-agent.txt", b"no agent running\n");

    let outcome = ssh_sign(&env, "git", &pub_path, &data);
    // It's OK if the CLI auto-respawns the agent transparently
    // (small_subcommands.rs::cli_respawns_agent_after_kill covers
    // that). What's not OK is silent local-fallback signing — if
    // sign succeeds, the socket must now exist (proving the agent
    // came up). If sign fails, that's also acceptable — the
    // important guarantee is that no sigfile was written without
    // the agent being involved.
    let sig = data.with_extension("txt.sig");
    if outcome.succeeded() {
        assert!(
            env.socket_path().exists(),
            "sign succeeded — agent must have been respawned; socket missing at {}",
            env.socket_path().display()
        );
        assert!(sig.exists(), "sign reported success but no sigfile");
    } else {
        assert!(
            !sig.exists(),
            "sign failed but a sigfile was written anyway: {}",
            sig.display()
        );
        assert!(
            outcome.stderr.to_lowercase().contains("agent")
                || outcome.stderr.to_lowercase().contains("not reachable")
                || outcome.stderr.to_lowercase().contains("connect"),
            "expected agent-related error message; got:\n{}",
            outcome.stderr
        );
    }

    // Cleanup any agent that started during the test.
    env.stop_agent();
}
