// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `sshenc -Y find-principals` and `sshenc -Y check-novalidate`
//! are not implemented in sshenc; the CLI forwards every `-Y`
//! subcommand other than `sign` to the system `ssh-keygen`. The
//! forwarding itself is the contract under test — if a future
//! refactor accidentally drops args, mangles arg ordering, or
//! changes what gets exec'd, these workflows silently break.
//!
//! Two scenarios:
//! - `find-principals`: after a `sshenc -Y sign`, asking sshenc
//!   to look up which principal in `allowed_signers` produced
//!   that signature returns the right name.
//! - `check-novalidate`: verifies a signature WITHOUT requiring
//!   a principal lookup (useful when trust is established by
//!   other means, e.g. signature attached to a known-good
//!   payload).

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

const PRINCIPAL: &str = "signer@y-variants.test";

fn setup_signed(ns: &str) -> (SshencEnv, std::path::PathBuf, std::path::PathBuf) {
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");

    let pub_path = env.ssh_dir().join(format!("{SHARED_ENCLAVE_LABEL}.pub"));
    std::fs::create_dir_all(env.ssh_dir()).expect("mkdir ssh dir");
    std::fs::write(&pub_path, format!("{enclave}\n")).expect("write pub");

    let allowed = env.ssh_dir().join("allowed_signers");
    std::fs::write(&allowed, format!("{PRINCIPAL} {enclave}\n")).expect("write allowed_signers");

    let data = env.home().join("y-variants-payload.txt");
    std::fs::write(&data, b"y-variants payload\n").expect("write data");

    let sign = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .arg("-Y")
        .arg("sign")
        .arg("-n")
        .arg(ns)
        .arg("-f")
        .arg(&pub_path)
        .arg(&data))
    .expect("sshenc -Y sign");
    assert!(sign.succeeded(), "sshenc -Y sign: {}", sign.stderr);

    (env, data, allowed)
}

/// `sshenc -Y find-principals` reads a sigfile and the
/// allowed_signers file and emits the principal(s) whose key
/// produced the signature. The CLI forwards directly to the
/// system `ssh-keygen` for this op; we just need to prove the
/// arg passthrough works end-to-end.
#[test]
#[ignore = "requires docker"]
fn y_find_principals_returns_signer_principal() {
    if skip_if_no_docker("y_find_principals_returns_signer_principal") {
        return;
    }
    let (env, data, allowed) = setup_signed("git");
    let sig = data.with_extension("txt.sig");

    let out = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .arg("-Y")
        .arg("find-principals")
        .arg("-f")
        .arg(&allowed)
        .arg("-s")
        .arg(&sig))
    .expect("sshenc -Y find-principals");
    assert!(
        out.succeeded(),
        "sshenc -Y find-principals failed; stdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    assert!(
        out.stdout.contains(PRINCIPAL),
        "expected principal '{PRINCIPAL}' in find-principals output; got:\n{}",
        out.stdout
    );
}

/// `sshenc -Y check-novalidate` verifies a signature is
/// well-formed and produced by the pubkey embedded in the
/// signature, but does NOT require the principal/pubkey to be
/// in any allowed_signers file. Used when caller has already
/// established trust through another channel.
#[test]
#[ignore = "requires docker"]
fn y_check_novalidate_verifies_well_formed_signature() {
    if skip_if_no_docker("y_check_novalidate_verifies_well_formed_signature") {
        return;
    }
    let (env, data, _allowed) = setup_signed("git");
    let sig = data.with_extension("txt.sig");

    let mut child = env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .arg("-Y")
        .arg("check-novalidate")
        .arg("-n")
        .arg("git")
        .arg("-s")
        .arg(&sig)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sshenc -Y check-novalidate");
    {
        use std::io::Write;
        let mut stdin = child.stdin.take().expect("stdin");
        let payload = std::fs::read(&data).expect("read data");
        stdin.write_all(&payload).expect("write payload");
    }
    let output = child.wait_with_output().expect("wait child");
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "sshenc -Y check-novalidate failed; output:\n{combined}"
    );

    // Tampered payload must fail check-novalidate too — otherwise
    // the test isn't actually exercising the verification path,
    // just printing OK regardless.
    let bad = env.home().join("tampered.txt");
    std::fs::write(&bad, b"different bytes\n").expect("write bad");
    let bad_status = check_novalidate_with_payload(&env, &sig, "git", &bad);
    assert!(
        !bad_status,
        "check-novalidate accepted tampered payload — verification didn't run"
    );
}

fn check_novalidate_with_payload(env: &SshencEnv, sig: &Path, ns: &str, payload: &Path) -> bool {
    let mut child = env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .arg("-Y")
        .arg("check-novalidate")
        .arg("-n")
        .arg(ns)
        .arg("-s")
        .arg(sig)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn check-novalidate");
    {
        use std::io::Write;
        let mut stdin = child.stdin.take().expect("stdin");
        let bytes = std::fs::read(payload).expect("read payload");
        let _ignored = stdin.write_all(&bytes);
    }
    child.wait().map(|s| s.success()).unwrap_or(false)
}
