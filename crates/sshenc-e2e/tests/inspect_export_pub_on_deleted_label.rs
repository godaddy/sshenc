// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `sshenc inspect <label>` and `sshenc export-pub <label>` for
//! a label that was previously deleted. The contract: exit
//! non-zero with a clear "not found" diagnostic, no panic, no
//! partial output.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{docker_skip_reason, extended_enabled, run, software_mode, SshencEnv};

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

/// `sshenc inspect <label>` after deletion exits cleanly with a
/// "not found"-style error.
#[test]
#[ignore = "requires docker"]
fn inspect_after_delete_errors_cleanly() {
    if skip_if_no_docker("inspect_after_delete_errors_cleanly") {
        return;
    }
    if skip_unless_key_creation_cheap("inspect_after_delete_errors_cleanly") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    env.use_ephemeral_keys_dir().expect("ephemeral");
    env.start_agent().expect("start agent");

    let label = "post-delete-victim";
    let kg = run(env.sshenc_cmd().expect("sshenc cmd").args([
        "keygen",
        "--label",
        label,
        "--auth-policy",
        "none",
        "--no-pub-file",
    ]))
    .expect("keygen");
    assert!(kg.succeeded(), "keygen: {}", kg.stderr);

    let delete = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["delete", label, "-y"]))
    .expect("delete");
    assert!(delete.succeeded(), "delete: {}", delete.stderr);

    let inspect = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["inspect", label]))
    .expect("inspect post-delete");
    assert!(
        !inspect.succeeded(),
        "inspect on deleted label should fail; stdout:\n{}\nstderr:\n{}",
        inspect.stdout,
        inspect.stderr
    );
    let combined = format!("{}\n{}", inspect.stdout, inspect.stderr);
    assert!(
        !combined.contains("panicked at"),
        "inspect panicked on deleted label:\n{combined}"
    );
}

/// `sshenc export-pub <label>` after deletion exits cleanly with
/// a "not found"-style error.
#[test]
#[ignore = "requires docker"]
fn export_pub_after_delete_errors_cleanly() {
    if skip_if_no_docker("export_pub_after_delete_errors_cleanly") {
        return;
    }
    if skip_unless_key_creation_cheap("export_pub_after_delete_errors_cleanly") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    env.use_ephemeral_keys_dir().expect("ephemeral");
    env.start_agent().expect("start agent");

    let label = "export-victim";
    let kg = run(env.sshenc_cmd().expect("sshenc cmd").args([
        "keygen",
        "--label",
        label,
        "--auth-policy",
        "none",
        "--no-pub-file",
    ]))
    .expect("keygen");
    assert!(kg.succeeded(), "keygen: {}", kg.stderr);

    let delete = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["delete", label, "-y"]))
    .expect("delete");
    assert!(delete.succeeded(), "delete: {}", delete.stderr);

    let exp = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["export-pub", label]))
    .expect("export-pub post-delete");
    assert!(
        !exp.succeeded(),
        "export-pub on deleted label should fail; stdout:\n{}\nstderr:\n{}",
        exp.stdout,
        exp.stderr
    );
    let combined = format!("{}\n{}", exp.stdout, exp.stderr);
    assert!(
        !combined.contains("panicked at"),
        "export-pub panicked on deleted label:\n{combined}"
    );
}
