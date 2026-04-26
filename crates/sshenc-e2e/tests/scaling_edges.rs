// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Two scaling-shaped edges that didn't fit `multi_key_scaling.rs`
//! or `sign_edge_data.rs`:
//!
//! 1. **100 keys in keys_dir**: `multi_key_scaling.rs` exercises
//!    12; this stresses the realistic upper-end of a developer
//!    account (many machines / projects → many labels) and pins
//!    that list/inspect don't truncate, panic, or get
//!    quadratically slow.
//! 2. **1024-byte SSH key comment**: `cli_flag_matrix.rs` covers
//!    a typical comment with unicode and spaces; nothing pinned
//!    that the OpenSSH wire encoder accepts a maximally-long
//!    comment without overrun on the wire-format mpint encoder.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{docker_skip_reason, extended_enabled, run, software_mode, SshencEnv};
use std::time::Instant;

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
        "skip {test_name}: needs to mint many keys; \
         set SSHENC_E2E_SOFTWARE=1 or SSHENC_E2E_EXTENDED=1"
    );
    true
}

fn unique_label(prefix: &str, i: usize) -> String {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{prefix}-{pid}-{nanos}-{i}")
}

/// Mint 100 keys in an ephemeral keys_dir, then list them. All 100
/// must appear; list time stays bounded (<10s on dev hardware,
/// generous for CI).
#[test]
#[ignore = "requires docker"]
fn list_returns_all_100_keys_in_bounded_time() {
    if skip_if_no_docker("list_returns_all_100_keys_in_bounded_time") {
        return;
    }
    if skip_unless_key_creation_cheap("list_returns_all_100_keys_in_bounded_time") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    env.use_ephemeral_keys_dir().expect("ephemeral");
    env.start_agent().expect("start agent");

    const N: usize = 100;
    let labels: Vec<String> = (0..N).map(|i| unique_label("scale100", i)).collect();
    for label in &labels {
        let outcome = run(env.sshenc_cmd().expect("sshenc cmd").args([
            "keygen",
            "--label",
            label,
            "--auth-policy",
            "none",
            "--no-pub-file",
        ]))
        .expect("keygen");
        assert!(outcome.succeeded(), "keygen {label}: {}", outcome.stderr);
    }

    let start = Instant::now();
    let listed = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["list", "--json"]))
    .expect("list --json");
    let elapsed = start.elapsed();
    assert!(listed.succeeded(), "list: {}", listed.stderr);
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "list took {elapsed:?} for 100 keys; >10s smells quadratic"
    );
    let arr: serde_json::Value = serde_json::from_str(&listed.stdout).expect("list --json");
    let entries = arr.as_array().expect("array");
    for label in &labels {
        let seen = entries.iter().any(|e| {
            e.get("metadata")
                .and_then(|m| m.get("label"))
                .and_then(|v| v.as_str())
                == Some(&**label)
        });
        assert!(seen, "label '{label}' missing from 100-key list output");
    }
}

/// A 1024-byte SSH key comment round-trips through keygen and
/// `inspect --json` without truncation. Pins the comment field
/// boundary on the wire and JSON sides.
#[test]
#[ignore = "requires docker"]
fn keygen_with_1024_byte_comment_round_trips() {
    if skip_if_no_docker("keygen_with_1024_byte_comment_round_trips") {
        return;
    }
    if skip_unless_key_creation_cheap("keygen_with_1024_byte_comment_round_trips") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    env.use_ephemeral_keys_dir().expect("ephemeral");
    env.start_agent().expect("start agent");

    let label = unique_label("longcomment", 0);
    let comment: String = "X".repeat(1024);
    let kg = run(env.sshenc_cmd().expect("sshenc cmd").args([
        "keygen",
        "--label",
        &label,
        "--comment",
        &comment,
        "--auth-policy",
        "none",
        "--no-pub-file",
    ]))
    .expect("keygen");
    assert!(kg.succeeded(), "keygen with 1024B comment: {}", kg.stderr);

    let inspect = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["inspect", &label, "--json"]))
    .expect("inspect --json");
    assert!(inspect.succeeded(), "inspect: {}", inspect.stderr);
    let info: serde_json::Value = serde_json::from_str(&inspect.stdout).expect("inspect --json");
    let returned_comment = info
        .get("metadata")
        .and_then(|m| m.get("comment"))
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert_eq!(
        returned_comment.len(),
        comment.len(),
        "comment length round-trip mismatch: sent {}B, got {}B",
        comment.len(),
        returned_comment.len()
    );
    assert_eq!(returned_comment, comment, "comment bytes diverged");
}
