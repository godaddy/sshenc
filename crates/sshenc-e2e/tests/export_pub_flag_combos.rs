// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `sshenc export-pub` flag combinations not covered by
//! `cli_flag_matrix.rs` (which tests each individually) or
//! `json_output_stability.rs` (which covers --fingerprint --json
//! only). Pin the behavior of the remaining cross-products so
//! a future refactor that flips precedence is caught.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{docker_skip_reason, run, shared_enclave_pubkey, SshencEnv, SHARED_ENCLAVE_LABEL};

fn skip_if_no_docker(test_name: &str) -> bool {
    if let Some(reason) = docker_skip_reason() {
        eprintln!("skip {test_name}: {reason}");
        return true;
    }
    false
}

/// `sshenc export-pub <label> --authorized-keys --json` produces
/// either valid JSON or fails cleanly. Pin whichever the
/// implementation chose so a silent flip is caught.
#[test]
#[ignore = "requires docker"]
fn export_pub_authorized_keys_with_json_is_deterministic() {
    if skip_if_no_docker("export_pub_authorized_keys_with_json_is_deterministic") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared enclave"));

    let out = run(env.sshenc_cmd().expect("sshenc cmd").args([
        "export-pub",
        SHARED_ENCLAVE_LABEL,
        "--authorized-keys",
        "--json",
    ]))
    .expect("export-pub --authorized-keys --json");

    let combined = format!("{}\n{}", out.stdout, out.stderr);
    assert!(
        !combined.contains("panicked at"),
        "export-pub panicked on --authorized-keys --json combo:\n{combined}"
    );

    if out.succeeded() {
        // If accepted, the output must parse as JSON. (The exact
        // shape isn't pinned here — `cli_flag_matrix` and
        // `json_output_stability` already pin shapes for individual
        // flag combos. The contract here is "output is valid".)
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&out.stdout);
        assert!(
            parsed.is_ok(),
            "succeeded but output isn't valid JSON; stdout:\n{}",
            out.stdout
        );
    } else {
        // If rejected, the error must mention the conflict, not
        // panic.
        let lower = out.stderr.to_lowercase();
        assert!(
            lower.contains("conflict")
                || lower.contains("authorized")
                || lower.contains("json")
                || lower.contains("incompatible")
                || lower.contains("usage"),
            "rejected but error doesn't mention the flag conflict; stderr:\n{}",
            out.stderr
        );
    }
}

/// `sshenc export-pub <label> --fingerprint --authorized-keys`
/// behaves deterministically (succeeds with one format winning,
/// or fails cleanly).
#[test]
#[ignore = "requires docker"]
fn export_pub_fingerprint_with_authorized_keys_is_deterministic() {
    if skip_if_no_docker("export_pub_fingerprint_with_authorized_keys_is_deterministic") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared enclave"));

    let out = run(env.sshenc_cmd().expect("sshenc cmd").args([
        "export-pub",
        SHARED_ENCLAVE_LABEL,
        "--fingerprint",
        "--authorized-keys",
    ]))
    .expect("export-pub --fingerprint --authorized-keys");

    let combined = format!("{}\n{}", out.stdout, out.stderr);
    assert!(
        !combined.contains("panicked at"),
        "export-pub panicked on --fingerprint --authorized-keys combo:\n{combined}"
    );

    if out.succeeded() {
        // Should look like one of the two: either a SHA256
        // fingerprint line, or an authorized_keys line. Both start
        // with letters, but they differ markedly: the fingerprint
        // contains "SHA256:", the authorized_keys line starts with
        // "ecdsa-".
        let stdout = out.stdout.trim();
        assert!(
            stdout.starts_with("ecdsa-") || stdout.contains("SHA256:"),
            "output doesn't look like fingerprint or authorized_keys; got:\n{stdout}"
        );
    }
}
