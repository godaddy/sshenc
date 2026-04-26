// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Edge cases that don't fit any of the topical files:
//!
//! 1. `~/.sshenc` pre-existing with a permissive (0o755) mode
//!    when the agent starts. The agent's `prepare_socket_path`
//!    sets parent dir to 0o700; this test pins that the chmod
//!    fires regardless of what the dir's mode was before.
//!
//! 2. `sshenc list` against a *truly empty* keys_dir prints the
//!    documented "No sshenc-managed keys found." line and exits
//!    successfully (not failure-on-empty).
//!
//! 3. A label of maximum reasonable length (the longest label
//!    the validator accepts) round-trips through keygen → list →
//!    inspect → delete. Catches off-by-one regressions in label
//!    validation or filename construction.
//!
//! 4. `sshenc inspect <missing-label> --json` errors cleanly with
//!    a non-zero exit, doesn't crash, doesn't emit malformed JSON.
//!    Covers a corner of the JSON contract that
//!    json_output_stability.rs assumes works for the success path.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{
    docker_skip_reason, extended_enabled, run, shared_enclave_pubkey, software_mode, SshencEnv,
};
use std::os::unix::fs::PermissionsExt;

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

/// `prepare_socket_path` should chmod `~/.sshenc` to 0o700 every
/// time the agent starts, even if it pre-exists with a permissive
/// mode. Pin this so a regression that only chmods *new* dirs
/// doesn't leave widely-readable parents in place.
#[test]
#[ignore = "requires docker"]
fn agent_chmods_preexisting_sshenc_parent_to_0700() {
    if skip_if_no_docker("agent_chmods_preexisting_sshenc_parent_to_0700") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");

    // Pre-create ~/.sshenc with a deliberately wrong mode.
    let parent = env.home().join(".sshenc");
    std::fs::create_dir_all(&parent).expect("mkdir .sshenc");
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).expect("chmod 0o755");

    env.start_agent().expect("start agent");

    let mode = std::fs::metadata(&parent)
        .expect("stat parent")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode, 0o700,
        "agent did not tighten ~/.sshenc to 0o700; got 0o{mode:o}"
    );
}

/// `sshenc list` on an empty keys_dir prints the documented
/// "No sshenc-managed keys found." line and exits 0. External
/// callers depend on this for "is sshenc set up at all" probing.
#[test]
#[ignore = "requires docker"]
fn list_on_empty_keys_dir_emits_canonical_message() {
    if skip_if_no_docker("list_on_empty_keys_dir_emits_canonical_message") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    env.use_ephemeral_keys_dir().expect("ephemeral");

    let listed = run(env.sshenc_cmd().expect("sshenc cmd").arg("list")).expect("sshenc list");
    assert!(
        listed.succeeded(),
        "sshenc list on empty dir should exit 0; stderr:\n{}",
        listed.stderr
    );
    assert!(
        listed.stdout.contains("No sshenc-managed keys found."),
        "expected canonical empty-list message; got:\n{}",
        listed.stdout
    );
}

/// `sshenc list --json` on an empty keys_dir emits `[]`, not an
/// error, and not a non-array. JSON consumers expect an array.
#[test]
#[ignore = "requires docker"]
fn list_json_on_empty_keys_dir_emits_empty_array() {
    if skip_if_no_docker("list_json_on_empty_keys_dir_emits_empty_array") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    env.use_ephemeral_keys_dir().expect("ephemeral");

    let listed = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["list", "--json"]))
    .expect("sshenc list --json");
    assert!(listed.succeeded(), "list --json: {}", listed.stderr);
    let parsed: serde_json::Value =
        serde_json::from_str(&listed.stdout).expect("output must be JSON");
    assert!(
        parsed.is_array(),
        "list --json must emit an array; got: {}",
        listed.stdout
    );
    assert!(
        parsed.as_array().unwrap().is_empty(),
        "list --json on empty dir must be []; got: {}",
        listed.stdout
    );
}

/// A 64-char label round-trips end-to-end. KeyLabel's documented
/// max length is 64; this test pins that the boundary is
/// honoured by every link in the chain (keygen → meta filename →
/// list → inspect → delete).
#[test]
#[ignore = "requires docker"]
fn maximum_length_label_round_trips() {
    if skip_if_no_docker("maximum_length_label_round_trips") {
        return;
    }
    if skip_unless_key_creation_cheap("maximum_length_label_round_trips") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("warm shared key"));

    // 64 chars — match KeyLabel's published max. Use lowercase
    // alpha + digits only; KeyLabel validates against a strict
    // charset.
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let prefix = format!("maxlen-{pid}-{nanos}");
    let label: String = prefix
        .chars()
        .chain(std::iter::repeat('a'))
        .take(64)
        .collect();
    assert_eq!(label.len(), 64);

    let kg = run(env.sshenc_cmd().expect("sshenc cmd").args([
        "keygen",
        "--label",
        &label,
        "--auth-policy",
        "none",
        "--no-pub-file",
    ]))
    .expect("keygen");
    assert!(kg.succeeded(), "keygen 64-char label: {}", kg.stderr);

    let listed = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["list", "--json"]))
    .expect("list");
    assert!(listed.succeeded(), "list: {}", listed.stderr);
    let arr: serde_json::Value = serde_json::from_str(&listed.stdout).expect("list --json");
    let seen = arr.as_array().expect("array").iter().any(|e| {
        e.get("metadata")
            .and_then(|m| m.get("label"))
            .and_then(|v| v.as_str())
            == Some(&*label)
    });
    assert!(seen, "64-char label not in list output");

    let inspect = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["inspect", &label, "--json"]))
    .expect("inspect");
    assert!(inspect.succeeded(), "inspect: {}", inspect.stderr);

    let del = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["delete", &label, "-y"]))
    .expect("delete");
    assert!(del.succeeded(), "delete: {}", del.stderr);
}

/// `sshenc inspect <missing-label> --json` errors cleanly. JSON
/// consumers should see a non-zero exit code and not have to
/// parse stdout — and stdout should remain empty rather than
/// containing partial / malformed JSON.
#[test]
#[ignore = "requires docker"]
fn inspect_missing_label_json_emits_no_partial_json() {
    if skip_if_no_docker("inspect_missing_label_json_emits_no_partial_json") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    env.use_ephemeral_keys_dir().expect("ephemeral");

    let out = run(env.sshenc_cmd().expect("sshenc cmd").args([
        "inspect",
        "definitely-not-a-real-label",
        "--json",
    ]))
    .expect("inspect missing");
    assert!(
        !out.succeeded(),
        "inspect of missing label should fail; stdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    // stdout must NOT contain a partial JSON object: either empty
    // or a clean diagnostic. We assert empty here; if the CLI
    // changes to print a JSON-shaped error, the test should be
    // updated to match — that's still a contract worth pinning.
    assert!(
        out.stdout.trim().is_empty(),
        "inspect of missing label should not emit anything to stdout in --json mode; got: {}",
        out.stdout
    );
}
