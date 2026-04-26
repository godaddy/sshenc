// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `sshenc -Y sign` followed by `ssh-keygen -Y verify` against an
//! `allowed_signers` file that **doesn't** authorize the signer.
//!
//! `y_sign_verify.rs` covers the positive round-trip and rejects on
//! tampered data / mismatched namespace. This file pins the third
//! axis of failure: the signer was authorized at sign time, but is
//! no longer authorized in `allowed_signers` at verify time. Real-
//! world scenario: key rotation where the old key's pubkey has been
//! removed from `allowed_signers` but a stale signature is presented.
//! ssh-keygen must reject — otherwise rotation provides no security
//! benefit.
//!
//! The cases:
//! 1. allowed_signers contains the right principal but a *different*
//!    pubkey
//! 2. allowed_signers contains the right pubkey but the verify call
//!    asks for a *different* principal
//! 3. allowed_signers is empty

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{
    docker_skip_reason, generate_on_disk_ed25519, shared_enclave_pubkey, SshencEnv,
    SHARED_ENCLAVE_LABEL,
};
use std::path::Path;
use std::process::Stdio;

fn skip_if_no_docker(test_name: &str) -> bool {
    if let Some(reason) = docker_skip_reason() {
        eprintln!("skip {test_name}: {reason}");
        return true;
    }
    false
}

const PRINCIPAL: &str = "signer@y-verify-neg.test";

fn setup_signed(name: &str, namespace: &str) -> (SshencEnv, std::path::PathBuf, String) {
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");

    let pub_path = env.ssh_dir().join(format!("{SHARED_ENCLAVE_LABEL}.pub"));
    std::fs::create_dir_all(pub_path.parent().unwrap()).expect("mkdir ssh dir");
    std::fs::write(&pub_path, format!("{enclave}\n")).expect("write pub");

    let data = env.home().join(name);
    std::fs::write(&data, format!("payload for {name}\n").as_bytes()).expect("write data");

    let mut cmd = env.sshenc_cmd().expect("sshenc cmd");
    cmd.arg("-Y")
        .arg("sign")
        .arg("-n")
        .arg(namespace)
        .arg("-f")
        .arg(&pub_path)
        .arg(&data);
    let outcome = sshenc_e2e::run(&mut cmd).expect("sshenc -Y sign");
    assert!(outcome.succeeded(), "sshenc -Y sign: {}", outcome.stderr);

    (env, data, enclave)
}

fn verify(
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
        .expect("spawn ssh-keygen verify");
    {
        use std::io::Write;
        let mut stdin = child.stdin.take().expect("stdin");
        stdin.write_all(&data_bytes).expect("write data");
    }
    let output = child.wait_with_output().expect("verify wait");
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (output.status, combined)
}

/// allowed_signers binds `<principal>` to a *different* pubkey than
/// the one that signed. Verify must reject. Models a key-rotation
/// regression where the principal's authorized pubkey has been
/// swapped in `allowed_signers` but a signature minted by the old
/// key is replayed.
#[test]
#[ignore = "requires docker"]
fn y_verify_rejects_when_allowed_signers_pubkey_does_not_match() {
    if skip_if_no_docker("y_verify_rejects_when_allowed_signers_pubkey_does_not_match") {
        return;
    }
    let (env, data, _enclave) = setup_signed("rotate.txt", "git");

    // Mint an unrelated ed25519 pubkey on disk and put *that* in
    // allowed_signers. The signature was produced by the enclave key,
    // so verify must reject.
    let other = generate_on_disk_ed25519(&env, "rotated@e2e").expect("generate ed25519");
    let allowed = env.ssh_dir().join("allowed_signers");
    std::fs::write(&allowed, format!("{PRINCIPAL} {other}\n")).expect("write allowed_signers");

    let sig = data.with_extension("txt.sig");
    let (status, combined) = verify(&env, &allowed, PRINCIPAL, "git", &sig, &data);
    assert!(
        !status.success(),
        "verify with rotated pubkey must fail; output:\n{combined}"
    );
}

/// allowed_signers contains the right pubkey but bound to a
/// *different* principal than the one we ask verify to check. Verify
/// must reject because principal is part of the trust binding.
#[test]
#[ignore = "requires docker"]
fn y_verify_rejects_when_principal_does_not_match() {
    if skip_if_no_docker("y_verify_rejects_when_principal_does_not_match") {
        return;
    }
    let (env, data, enclave) = setup_signed("principal.txt", "git");

    // allowed_signers binds enclave to "owner@host" — verify with a
    // different principal "stranger@host" must reject. ssh-keygen
    // looks up by principal first; a mismatched principal yields
    // "no principal matched" / "no signers".
    let allowed = env.ssh_dir().join("allowed_signers");
    std::fs::write(&allowed, format!("owner@host {enclave}\n")).expect("write allowed_signers");

    let sig = data.with_extension("txt.sig");
    let (status, combined) = verify(&env, &allowed, "stranger@host", "git", &sig, &data);
    assert!(
        !status.success(),
        "verify with non-matching principal must fail; output:\n{combined}"
    );
}

/// allowed_signers is empty. Verify must reject — nothing is
/// trusted, so no signature can be considered valid.
#[test]
#[ignore = "requires docker"]
fn y_verify_rejects_when_allowed_signers_is_empty() {
    if skip_if_no_docker("y_verify_rejects_when_allowed_signers_is_empty") {
        return;
    }
    let (env, data, _enclave) = setup_signed("empty.txt", "git");

    let allowed = env.ssh_dir().join("allowed_signers");
    std::fs::write(&allowed, b"").expect("write empty allowed_signers");

    let sig = data.with_extension("txt.sig");
    let (status, combined) = verify(&env, &allowed, PRINCIPAL, "git", &sig, &data);
    assert!(
        !status.success(),
        "verify against empty allowed_signers must fail; output:\n{combined}"
    );
}
