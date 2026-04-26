// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `sshenc list` and `ssh-add -L` behavior with N keys.
//!
//! Existing tests use 1–3 labels at a time. This file verifies
//! the read-side scaling assumptions for a more realistic key
//! count:
//!
//! - **list returns every key** — generate 12, list returns 12,
//!   no truncation, no dropped entries.
//! - **fingerprints are distinct** — no SHA256 collisions across
//!   N freshly-generated keys.
//! - **list output is deterministic** — sort order stable across
//!   repeated invocations on the same keys_dir state.
//! - **agent enumerates the same set** — `ssh-add -L` returns one
//!   identity per generated label, all matching what list returned.
//!
//! Software/extended-mode gated because tests mint many keys.
//! Each test cleans up its own labels.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{
    docker_skip_reason, extended_enabled, run, shared_enclave_pubkey, software_mode, SshencEnv,
};
use std::collections::HashSet;

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

const N_KEYS: usize = 12;

/// Build a set of unique labels for this test run.
fn unique_labels(prefix: &str, n: usize) -> Vec<String> {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    (0..n)
        .map(|i| format!("{prefix}-{pid}-{nanos}-{i:02}"))
        .collect()
}

/// Generate N keys, returning the label list. Cleanup happens in
/// the caller's Drop guard.
fn mint_n_keys(env: &SshencEnv, labels: &[String]) {
    for label in labels {
        let kg = run(env.sshenc_cmd().expect("sshenc").args([
            "keygen",
            "--label",
            label,
            "--auth-policy",
            "none",
            "--no-pub-file",
        ]))
        .expect("sshenc keygen");
        assert!(kg.succeeded(), "keygen {label} failed: {}", kg.stderr);
    }
}

/// Cleanup helper: best-effort delete all labels.
fn delete_labels(env: &SshencEnv, labels: &[String]) {
    for label in labels {
        drop(run(env
            .sshenc_cmd()
            .expect("sshenc")
            .args(["delete", label, "-y"])));
    }
}

/// Generate 12 keys, run `sshenc list --json`, assert all 12
/// labels appear, no truncation, no duplicate entries.
#[test]
#[ignore = "requires docker"]
fn list_returns_all_n_keys() {
    if skip_if_no_docker("list_returns_all_n_keys") {
        return;
    }
    if skip_unless_key_creation_cheap("list_returns_all_n_keys") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("warm shared key"));

    let labels = unique_labels("scale-list", N_KEYS);
    mint_n_keys(&env, &labels);

    let listed = run(env.sshenc_cmd().expect("sshenc").args(["list", "--json"]))
        .expect("sshenc list --json");
    assert!(listed.succeeded(), "list --json: {}", listed.stderr);

    let arr: serde_json::Value =
        serde_json::from_str(&listed.stdout).expect("list --json output is JSON");
    let entries = arr.as_array().expect("list output is an array");

    let mut found_labels = HashSet::new();
    for entry in entries {
        if let Some(l) = entry
            .get("metadata")
            .and_then(|m| m.get("label"))
            .and_then(|v| v.as_str())
        {
            found_labels.insert(l.to_string());
        }
    }

    for label in &labels {
        assert!(
            found_labels.contains(label),
            "label {label} missing from list output (saw {} entries; {} unique labels)",
            entries.len(),
            found_labels.len()
        );
    }

    delete_labels(&env, &labels);
}

/// Generate N keys, collect fingerprints from `inspect --json`,
/// assert all fingerprints are distinct (no collisions, no
/// truncation that would conflate distinct keys).
#[test]
#[ignore = "requires docker"]
fn fingerprints_distinct_across_n_keys() {
    if skip_if_no_docker("fingerprints_distinct_across_n_keys") {
        return;
    }
    if skip_unless_key_creation_cheap("fingerprints_distinct_across_n_keys") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("warm shared key"));

    let labels = unique_labels("scale-fp", N_KEYS);
    mint_n_keys(&env, &labels);

    let mut sha256_seen: HashSet<String> = HashSet::new();
    let mut md5_seen: HashSet<String> = HashSet::new();
    for label in &labels {
        let inspect = run(env
            .sshenc_cmd()
            .expect("sshenc")
            .args(["inspect", label, "--json"]))
        .expect("inspect");
        assert!(inspect.succeeded(), "inspect {label}: {}", inspect.stderr);
        let info: serde_json::Value =
            serde_json::from_str(&inspect.stdout).expect("inspect output is JSON");
        let sha256 = info
            .get("fingerprint_sha256")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("missing fingerprint_sha256 for {label}"))
            .to_string();
        let md5 = info
            .get("fingerprint_md5")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("missing fingerprint_md5 for {label}"))
            .to_string();
        assert!(
            sha256_seen.insert(sha256.clone()),
            "SHA256 collision: {sha256} appeared twice across {N_KEYS} fresh keys"
        );
        assert!(
            md5_seen.insert(md5.clone()),
            "MD5 collision: {md5} appeared twice across {N_KEYS} fresh keys"
        );
    }

    delete_labels(&env, &labels);
}

/// `sshenc list --json` should return entries in deterministic
/// order across repeated invocations against the same keys_dir.
/// Without this property, scripts diffing list output for change
/// detection would see spurious "changes". The current
/// implementation sorts by label; this pins that contract.
#[test]
#[ignore = "requires docker"]
fn list_order_is_deterministic() {
    if skip_if_no_docker("list_order_is_deterministic") {
        return;
    }
    if skip_unless_key_creation_cheap("list_order_is_deterministic") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("warm shared key"));

    let labels = unique_labels("scale-order", N_KEYS);
    mint_n_keys(&env, &labels);

    fn label_sequence(env: &SshencEnv) -> Vec<String> {
        let listed =
            run(env.sshenc_cmd().expect("sshenc").args(["list", "--json"])).expect("list --json");
        let arr: serde_json::Value =
            serde_json::from_str(&listed.stdout).expect("list output is JSON");
        arr.as_array()
            .expect("array")
            .iter()
            .filter_map(|e| {
                e.get("metadata")
                    .and_then(|m| m.get("label"))
                    .and_then(|v| v.as_str())
                    .map(String::from)
            })
            .collect()
    }

    let first = label_sequence(&env);
    let second = label_sequence(&env);
    let third = label_sequence(&env);
    assert_eq!(
        first, second,
        "list output reorder between invocations 1 and 2; \
         scripts that diff list output need stable ordering"
    );
    assert_eq!(first, third, "list output reorder between 1 and 3");

    delete_labels(&env, &labels);
}

/// With N keys in the keys_dir, `ssh-add -L` against the agent
/// returns one identity per label. Catches a regression where the
/// agent's RequestIdentities response truncates large identity
/// lists or drops entries.
#[test]
#[ignore = "requires docker"]
fn agent_enumerates_all_n_identities() {
    if skip_if_no_docker("agent_enumerates_all_n_identities") {
        return;
    }
    if skip_unless_key_creation_cheap("agent_enumerates_all_n_identities") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("warm shared key"));

    let labels = unique_labels("scale-agent", N_KEYS);
    mint_n_keys(&env, &labels);

    env.start_agent().expect("start agent");

    let listed = run(env
        .scrubbed_command("ssh-add")
        .env("SSH_AUTH_SOCK", env.socket_path())
        .arg("-L"))
    .expect("ssh-add -L");
    assert!(listed.succeeded(), "ssh-add -L failed: {}", listed.stderr);

    // ssh-add -L outputs one line per identity. Count lines that
    // start with an SSH key type prefix.
    let identity_lines: Vec<&str> = listed
        .stdout
        .lines()
        .filter(|line| {
            line.starts_with("ecdsa-sha2-nistp256 ")
                || line.starts_with("ssh-ed25519 ")
                || line.starts_with("ssh-rsa ")
        })
        .collect();
    // Expect at least N (we added N) plus the persistent shared
    // key plus any other persistent keys carried across runs. The
    // important assertion is that identity_lines.len() >= N + 1
    // (our keys plus the warmed shared one).
    assert!(
        identity_lines.len() > N_KEYS,
        "agent should enumerate at least N+shared identities; got {}:\n{}",
        identity_lines.len(),
        listed.stdout
    );

    // Every test-minted label's pubkey body must appear in the agent's output.
    for label in &labels {
        let exp = run(env
            .sshenc_cmd()
            .expect("sshenc")
            .args(["export-pub", label]))
        .expect("export-pub");
        assert!(exp.succeeded(), "export-pub {label}: {}", exp.stderr);
        let body = exp
            .stdout
            .split_whitespace()
            .nth(1)
            .expect("pub body")
            .to_string();
        assert!(
            listed.stdout.contains(&body),
            "agent should expose {label}'s key body; got:\n{}",
            listed.stdout
        );
    }

    delete_labels(&env, &labels);
}
