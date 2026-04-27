// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Label length boundary: a very long label (>200 ASCII chars)
//! is rejected by `validate_label` before any keystore state
//! is written. Catches a regression where the validator's
//! length cap silently shifts.

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

/// `sshenc keygen --label <256-char-label>` is rejected by
/// `validate_label` (no panic, no partial state).
#[test]
#[ignore = "requires docker"]
fn keygen_rejects_overlong_label() {
    if skip_if_no_docker("keygen_rejects_overlong_label") {
        return;
    }
    if skip_unless_key_creation_cheap("keygen_rejects_overlong_label") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    env.use_ephemeral_keys_dir().expect("ephemeral");

    // 256 ASCII chars — well past any reasonable cap.
    let bad = "a".repeat(256);
    let kg = run(env.sshenc_cmd().expect("sshenc cmd").args([
        "keygen",
        "--label",
        &bad,
        "--auth-policy",
        "none",
        "--no-pub-file",
    ]))
    .expect("keygen");

    assert!(
        !kg.succeeded(),
        "keygen with overlong (256-char) label should fail; stdout:\n{}\nstderr:\n{}",
        kg.stdout,
        kg.stderr
    );
    let combined = format!("{}\n{}", kg.stdout, kg.stderr);
    assert!(
        !combined.contains("panicked at"),
        "keygen panicked on overlong label:\n{combined}"
    );

    // No partial keystore state (label not visible in list).
    let listed = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["list", "--json"]))
    .expect("list");
    assert!(listed.succeeded(), "list: {}", listed.stderr);
    assert!(
        !listed.stdout.contains(&bad),
        "list shouldn't contain the rejected label; got:\n{}",
        listed.stdout
    );
}
