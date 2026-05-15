// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Labels containing control characters or non-ASCII characters
//! (newline, tab, emoji) are rejected by `validate_label` before any
//! keystore state is written.
//!
//! `validate_label` accepts only ASCII alphanumeric, hyphens, and
//! underscores. Emoji encode as multi-byte UTF-8 sequences that
//! contain non-ASCII bytes and thus fail that check.

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

/// `sshenc keygen --label` with embedded control characters
/// (newline, tab) is rejected cleanly.
#[test]
#[ignore = "requires docker"]
fn keygen_rejects_label_with_control_chars() {
    if skip_if_no_docker("keygen_rejects_label_with_control_chars") {
        return;
    }
    if skip_unless_key_creation_cheap("keygen_rejects_label_with_control_chars") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    env.use_ephemeral_keys_dir().expect("ephemeral");

    for bad in ["with\nnewline", "with\ttab", "with\rcr", "with\x7fdel"] {
        let kg = run(env.sshenc_cmd().expect("sshenc cmd").args([
            "keygen",
            "--label",
            bad,
            "--auth-policy",
            "none",
            "--no-pub-file",
        ]))
        .expect("keygen");
        assert!(
            !kg.succeeded(),
            "keygen with control-char label {bad:?} should fail; stdout:\n{}\nstderr:\n{}",
            kg.stdout,
            kg.stderr
        );
        let combined = format!("{}\n{}", kg.stdout, kg.stderr);
        assert!(
            !combined.contains("panicked at"),
            "keygen panicked on control-char label {bad:?}:\n{combined}"
        );
    }

    // No partial keystore state.
    let listed = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["list", "--json"]))
    .expect("list");
    assert!(listed.succeeded(), "list: {}", listed.stderr);
    let parsed: serde_json::Value =
        serde_json::from_str(listed.stdout.trim()).expect("list --json invalid JSON");
    if let Some(arr) = parsed.as_array() {
        assert!(arr.is_empty(), "list should be empty; got: {parsed}");
    }
}

/// `sshenc keygen --label` with an emoji (non-ASCII, multi-byte UTF-8)
/// is rejected cleanly. `validate_label` requires ASCII alphanumeric
/// plus hyphens and underscores.
#[test]
#[ignore = "requires docker"]
fn keygen_rejects_label_with_emoji() {
    if skip_if_no_docker("keygen_rejects_label_with_emoji") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    env.use_ephemeral_keys_dir().expect("ephemeral");

    for bad in ["key-🔑", "🗝️-label", "mykey🙂"] {
        let kg = run(env.sshenc_cmd().expect("sshenc cmd").args([
            "keygen",
            "--label",
            bad,
            "--auth-policy",
            "none",
            "--no-pub-file",
        ]))
        .expect("keygen");
        assert!(
            !kg.succeeded(),
            "keygen with emoji label {bad:?} should fail; stdout:\n{}\nstderr:\n{}",
            kg.stdout,
            kg.stderr
        );
        let combined = format!("{}\n{}", kg.stdout, kg.stderr);
        assert!(
            !combined.contains("panicked at"),
            "keygen panicked on emoji label {bad:?}:\n{combined}"
        );
    }

    // No partial keystore state.
    let listed = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["list", "--json"]))
    .expect("list");
    assert!(listed.succeeded(), "list: {}", listed.stderr);
    let parsed: serde_json::Value =
        serde_json::from_str(listed.stdout.trim()).expect("list --json invalid JSON");
    if let Some(arr) = parsed.as_array() {
        assert!(arr.is_empty(), "list should be empty; got: {parsed}");
    }
}
