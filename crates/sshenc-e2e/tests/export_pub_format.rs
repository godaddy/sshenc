// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `sshenc export-pub` output must be consumable by real OpenSSH
//! tooling. The internal pubkey wire-format unit tests cover the
//! encoding round-trip in-process; these tests close the loop with
//! the actual `ssh-keygen` binary.
//!
//! Coverage:
//!
//! - `ssh-keygen -l -f <pub>` accepts the OpenSSH-format export
//!   and prints a fingerprint.
//! - The fingerprint that ssh-keygen prints matches the one
//!   `sshenc export-pub --fingerprint` prints.
//! - `ssh-keygen -e -f <pub>` exports to RFC4716, then
//!   `ssh-keygen -i -f <rfc>` imports back to OpenSSH form, and
//!   the resulting pubkey matches our original byte-for-byte
//!   (modulo trailing whitespace and the comment field).
//! - The `--authorized_keys` form parses as a valid
//!   authorized_keys line: ssh-keygen -l succeeds on it.

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

/// Extract the SHA256 fingerprint substring (`SHA256:abc...`) from
/// either `ssh-keygen -l` stdout or `sshenc export-pub --fingerprint`.
/// Returns the substring starting at "SHA256:" up to the next
/// whitespace, or None if no SHA256 fingerprint found.
fn extract_sha256(text: &str) -> Option<String> {
    let start = text.find("SHA256:")?;
    let rest = &text[start..];
    let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

fn ssh_keygen_l(env: &SshencEnv, pub_path: &std::path::Path) -> sshenc_e2e::RunOutcome {
    run(env
        .scrubbed_command("ssh-keygen")
        .arg("-l")
        .arg("-f")
        .arg(pub_path))
    .expect("ssh-keygen -l")
}

/// `ssh-keygen -l -f <pub>` accepts the export-pub output and
/// prints a SHA256 fingerprint that matches what
/// `sshenc export-pub --fingerprint` reports.
#[test]
#[ignore = "requires docker"]
fn export_pub_fingerprint_matches_ssh_keygen() {
    if skip_if_no_docker("export_pub_fingerprint_matches_ssh_keygen") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared key"));

    // Write the OpenSSH-format pub via export-pub -o.
    let pub_path = env.home().join("export_pub_match.pub");
    let exp = run(env.sshenc_cmd().expect("sshenc").args([
        "export-pub",
        SHARED_ENCLAVE_LABEL,
        "-o",
        &pub_path.display().to_string(),
    ]))
    .expect("export-pub");
    assert!(exp.succeeded(), "export-pub failed: {}", exp.stderr);

    // Verify ssh-keygen accepts it and prints a SHA256 fingerprint.
    let kg = ssh_keygen_l(&env, &pub_path);
    assert!(
        kg.succeeded(),
        "ssh-keygen -l rejected sshenc export-pub output; stdout:\n{}\nstderr:\n{}\nfile content:\n{}",
        kg.stdout,
        kg.stderr,
        std::fs::read_to_string(&pub_path).unwrap_or_default()
    );
    let kg_fp = extract_sha256(&kg.stdout).unwrap_or_else(|| {
        panic!(
            "ssh-keygen -l output should contain SHA256:; got:\n{}",
            kg.stdout
        )
    });

    // Now ask sshenc for the fingerprint directly.
    let our = run(env.sshenc_cmd().expect("sshenc").args([
        "export-pub",
        SHARED_ENCLAVE_LABEL,
        "--fingerprint",
    ]))
    .expect("export-pub --fingerprint");
    assert!(
        our.succeeded(),
        "export-pub --fingerprint failed: {}",
        our.stderr
    );
    let our_fp = extract_sha256(&our.stdout).unwrap_or_else(|| {
        panic!(
            "sshenc export-pub --fingerprint output should contain SHA256:; got:\n{}",
            our.stdout
        )
    });

    assert_eq!(
        kg_fp, our_fp,
        "SHA256 fingerprints disagree:\n  ssh-keygen: {kg_fp}\n  sshenc:     {our_fp}"
    );
}

/// `ssh-keygen -e -f <pub>` (export to RFC4716) succeeds on the
/// sshenc-emitted pub file, and the resulting RFC4716 form is
/// importable back via `ssh-keygen -i` to a pubkey whose key body
/// matches the original.
#[test]
#[ignore = "requires docker"]
fn export_pub_rfc4716_round_trip_via_ssh_keygen() {
    if skip_if_no_docker("export_pub_rfc4716_round_trip_via_ssh_keygen") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared key"));

    let pub_path = env.home().join("for_rfc.pub");
    let exp = run(env.sshenc_cmd().expect("sshenc").args([
        "export-pub",
        SHARED_ENCLAVE_LABEL,
        "-o",
        &pub_path.display().to_string(),
    ]))
    .expect("export-pub");
    assert!(exp.succeeded(), "export-pub failed: {}", exp.stderr);

    // Convert OpenSSH → RFC4716.
    let rfc = run(env
        .scrubbed_command("ssh-keygen")
        .arg("-e")
        .arg("-f")
        .arg(&pub_path)
        .arg("-m")
        .arg("RFC4716"))
    .expect("ssh-keygen -e RFC4716");
    assert!(
        rfc.succeeded(),
        "ssh-keygen -e -m RFC4716 failed; stderr:\n{}",
        rfc.stderr
    );
    assert!(
        rfc.stdout.contains("---- BEGIN SSH2 PUBLIC KEY ----"),
        "RFC4716 envelope missing; got:\n{}",
        rfc.stdout
    );
    assert!(
        rfc.stdout.contains("---- END SSH2 PUBLIC KEY ----"),
        "RFC4716 footer missing"
    );

    // Round-trip: write the RFC4716 form, convert back to OpenSSH
    // via ssh-keygen -i, and verify the key body matches.
    let rfc_path = env.home().join("rfc.pub");
    std::fs::write(&rfc_path, rfc.stdout.as_bytes()).expect("write rfc");
    let back = run(env
        .scrubbed_command("ssh-keygen")
        .arg("-i")
        .arg("-f")
        .arg(&rfc_path)
        .arg("-m")
        .arg("RFC4716"))
    .expect("ssh-keygen -i");
    assert!(
        back.succeeded(),
        "ssh-keygen -i RFC4716 → OpenSSH failed; stderr:\n{}",
        back.stderr
    );

    let original = std::fs::read_to_string(&pub_path).expect("read original");
    let original_body = original
        .split_whitespace()
        .nth(1)
        .expect("original pub has key body");
    let back_body = back
        .stdout
        .split_whitespace()
        .nth(1)
        .expect("back-converted pub has key body");
    assert_eq!(
        original_body, back_body,
        "key body should match across RFC4716 round-trip;\n  original: {original_body}\n  back:     {back_body}"
    );
}

/// The `--authorized_keys` flag emits a line that's a valid
/// `authorized_keys` entry: ssh-keygen accepts it via -l directly.
#[test]
#[ignore = "requires docker"]
fn export_pub_authorized_keys_format_accepted_by_ssh_keygen() {
    if skip_if_no_docker("export_pub_authorized_keys_format_accepted_by_ssh_keygen") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared key"));

    let exp = run(env.sshenc_cmd().expect("sshenc").args([
        "export-pub",
        SHARED_ENCLAVE_LABEL,
        "--authorized-keys",
    ]))
    .expect("export-pub --authorized_keys");
    assert!(
        exp.succeeded(),
        "export-pub --authorized_keys failed: {}",
        exp.stderr
    );

    // Persist to a file and feed to ssh-keygen -l.
    let auth_path = env.home().join("ak_line.txt");
    std::fs::write(&auth_path, exp.stdout.as_bytes()).expect("write auth line");
    let kg = ssh_keygen_l(&env, &auth_path);
    assert!(
        kg.succeeded(),
        "ssh-keygen -l rejected the authorized_keys line; stdout:\n{}\nstderr:\n{}\nline:\n{}",
        kg.stdout,
        kg.stderr,
        exp.stdout,
    );
}
