// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! sshenc CLI's `--json` outputs are an external contract: any
//! script or tool that pipes them through `jq` or parses them
//! with serde will break if a field is renamed or its type changes
//! silently. These tests parse each `--json` flavor and assert
//! the documented field names/types are present, catching
//! accidental schema drift.
//!
//! Covered:
//!
//! - `sshenc list --json` → array of KeyInfo
//! - `sshenc inspect --json` → single KeyInfo
//! - `sshenc export-pub --fingerprint --json` → `{"label": …,
//!   "sha256": …}`
//! - `sshenc export-pub --json` → object with at least
//!   `fingerprint_sha256` and `pubkey_line`
//!
//! We assert the *presence and types* of well-known fields, not
//! the absence of additional fields — additive changes (new
//! optional fields) are non-breaking; renames or type flips are
//! breaking, and those are what we catch here.

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

/// Assert a JSON object has a string field at `key`. Panics on a
/// missing key, wrong type, or empty value.
fn assert_string_field(value: &serde_json::Value, key: &str) -> String {
    let v = value
        .get(key)
        .unwrap_or_else(|| panic!("expected {key} field; got: {value}"));
    let s = v
        .as_str()
        .unwrap_or_else(|| panic!("{key} should be a string, got: {v}"));
    assert!(!s.is_empty(), "{key} should not be empty");
    s.to_string()
}

/// `sshenc list --json` returns a JSON array. Each entry has the
/// documented KeyInfo fields.
#[test]
#[ignore = "requires docker"]
fn list_json_has_documented_keyinfo_fields() {
    if skip_if_no_docker("list_json_has_documented_keyinfo_fields") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared key"));

    let out = run(env.sshenc_cmd().expect("sshenc").args(["list", "--json"]))
        .expect("sshenc list --json");
    assert!(out.succeeded(), "sshenc list --json failed: {}", out.stderr);

    let arr: serde_json::Value = serde_json::from_str(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "list --json output is not valid JSON: {e}\nstdout:\n{}",
            out.stdout
        )
    });
    let entries = arr
        .as_array()
        .unwrap_or_else(|| panic!("list --json should be a JSON array; got: {arr}"));
    assert!(!entries.is_empty(), "list --json should have ≥1 entry");

    // Find the shared enclave entry; assert its documented fields.
    let shared = entries
        .iter()
        .find(|e| {
            e.get("metadata")
                .and_then(|m| m.get("label"))
                .and_then(|l| l.as_str())
                == Some(SHARED_ENCLAVE_LABEL)
        })
        .unwrap_or_else(|| panic!("shared label not in list: {arr}"));

    let metadata = shared
        .get("metadata")
        .unwrap_or_else(|| panic!("entry missing `metadata`: {shared}"));
    assert_string_field(metadata, "label");
    assert_string_field(metadata, "algorithm");
    assert_string_field(shared, "fingerprint_sha256");
    assert_string_field(shared, "fingerprint_md5");
    // public_key_blob is base64 — assert presence + non-empty string.
    assert_string_field(shared, "public_key_bytes");
}

/// `sshenc inspect --json` returns a single KeyInfo with the same
/// shape as one entry of `list --json`.
#[test]
#[ignore = "requires docker"]
fn inspect_json_has_documented_keyinfo_fields() {
    if skip_if_no_docker("inspect_json_has_documented_keyinfo_fields") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared key"));

    let out =
        run(env
            .sshenc_cmd()
            .expect("sshenc")
            .args(["inspect", SHARED_ENCLAVE_LABEL, "--json"]))
        .expect("sshenc inspect --json");
    assert!(
        out.succeeded(),
        "sshenc inspect --json failed: {}",
        out.stderr
    );

    let info: serde_json::Value = serde_json::from_str(&out.stdout)
        .unwrap_or_else(|e| panic!("inspect --json invalid: {e}; stdout:\n{}", out.stdout));
    let metadata = info
        .get("metadata")
        .unwrap_or_else(|| panic!("inspect missing `metadata`: {info}"));
    assert_eq!(
        metadata.get("label").and_then(|v| v.as_str()),
        Some(SHARED_ENCLAVE_LABEL),
        "inspect label mismatch: {info}"
    );
    assert_string_field(metadata, "algorithm");
    assert_string_field(&info, "fingerprint_sha256");
    assert_string_field(&info, "fingerprint_md5");
    assert_string_field(&info, "public_key_bytes");
    let pub_file_path = info
        .get("pub_file_path")
        .unwrap_or_else(|| panic!("inspect --json missing `pub_file_path` key"));
    assert!(
        pub_file_path.is_null() || pub_file_path.is_string(),
        "pub_file_path should be null or string; got: {pub_file_path}"
    );
}

/// `sshenc export-pub --fingerprint --json` returns an object with
/// `label` and `sha256` string fields.
#[test]
#[ignore = "requires docker"]
fn export_pub_fingerprint_json_has_label_and_sha256() {
    if skip_if_no_docker("export_pub_fingerprint_json_has_label_and_sha256") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared key"));

    let out = run(env.sshenc_cmd().expect("sshenc").args([
        "export-pub",
        SHARED_ENCLAVE_LABEL,
        "--fingerprint",
        "--json",
    ]))
    .expect("export-pub --fingerprint --json");
    assert!(
        out.succeeded(),
        "export-pub --fingerprint --json failed: {}",
        out.stderr
    );

    let v: serde_json::Value = serde_json::from_str(&out.stdout)
        .unwrap_or_else(|e| panic!("fingerprint --json invalid: {e}; stdout:\n{}", out.stdout));
    assert_eq!(
        v.get("label").and_then(|v| v.as_str()),
        Some(SHARED_ENCLAVE_LABEL),
        "label field mismatch: {v}"
    );
    let sha = assert_string_field(&v, "sha256");
    assert!(
        sha.starts_with("SHA256:"),
        "sha256 should be SHA256:-prefixed; got {sha}"
    );
}

/// `sshenc export-pub --json` returns an object with at minimum
/// `fingerprint_sha256` and `pubkey_line`. Catches schema drift in
/// the consolidated export-pub JSON shape.
#[test]
#[ignore = "requires docker"]
fn export_pub_json_has_fingerprint_and_pubkey_line() {
    if skip_if_no_docker("export_pub_json_has_fingerprint_and_pubkey_line") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared key"));

    let out =
        run(env
            .sshenc_cmd()
            .expect("sshenc")
            .args(["export-pub", SHARED_ENCLAVE_LABEL, "--json"]))
        .expect("export-pub --json");
    assert!(out.succeeded(), "export-pub --json failed: {}", out.stderr);

    let v: serde_json::Value = serde_json::from_str(&out.stdout)
        .unwrap_or_else(|e| panic!("export-pub --json invalid: {e}; stdout:\n{}", out.stdout));
    assert_eq!(
        v.get("label").and_then(|v| v.as_str()),
        Some(SHARED_ENCLAVE_LABEL),
        "label field mismatch: {v}"
    );
    let fp = assert_string_field(&v, "fingerprint_sha256");
    assert!(
        fp.starts_with("SHA256:"),
        "fingerprint_sha256 should be SHA256:-prefixed; got {fp}"
    );
    assert_string_field(&v, "fingerprint_md5");
    let pubkey_line = assert_string_field(&v, "public_key");
    assert!(
        pubkey_line.starts_with("ecdsa-sha2-nistp256 ") || pubkey_line.starts_with("ssh-ed25519 "),
        "public_key should look like an OpenSSH pubkey line; got: {pubkey_line}"
    );
}
