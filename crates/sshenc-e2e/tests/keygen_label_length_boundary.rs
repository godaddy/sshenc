// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Label length boundary tests.
//!
//! `validate_label` enforces a 64-character cap. These tests pin the
//! exact boundary:
//!   - 64-char label → accepted (key created)
//!   - 65-char label → rejected before any keystore state is written
//!   - 256-char label → rejected (well past the cap)
//!
//! Catches a regression where the validator's length cap silently shifts.

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

/// Exactly 64 ASCII characters is the maximum allowed label length.
/// The key must be created and appear in `sshenc list`.
#[test]
#[ignore = "requires docker"]
fn keygen_accepts_exactly_64_char_label() {
    if skip_if_no_docker("keygen_accepts_exactly_64_char_label") {
        return;
    }
    if skip_unless_key_creation_cheap("keygen_accepts_exactly_64_char_label") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    env.use_ephemeral_keys_dir().expect("ephemeral");
    env.start_agent().expect("start agent");

    let label = "a".repeat(64);
    let kg = run(env.sshenc_cmd().expect("sshenc cmd").args([
        "keygen",
        "--label",
        &label,
        "--auth-policy",
        "none",
        "--no-pub-file",
    ]))
    .expect("keygen");

    assert!(
        kg.succeeded(),
        "keygen with 64-char label should succeed; stderr:\n{}",
        kg.stderr
    );

    let listed = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["list", "--json"]))
    .expect("list");
    assert!(listed.succeeded(), "list: {}", listed.stderr);
    assert!(
        listed.stdout.contains(&label),
        "list should contain the 64-char label; got:\n{}",
        listed.stdout
    );
}

/// 65 ASCII characters exceeds the 64-character cap. `validate_label`
/// must reject it before writing any keystore state.
#[test]
#[ignore = "requires docker"]
fn keygen_rejects_65_char_label() {
    if skip_if_no_docker("keygen_rejects_65_char_label") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    env.use_ephemeral_keys_dir().expect("ephemeral");

    let bad = "a".repeat(65);
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
        "keygen with 65-char label should fail; stdout:\n{}\nstderr:\n{}",
        kg.stdout,
        kg.stderr
    );
    let combined = format!("{}\n{}", kg.stdout, kg.stderr);
    assert!(
        !combined.contains("panicked at"),
        "keygen panicked on 65-char label:\n{combined}"
    );

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
