// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! End-to-end coverage for CLI subcommand flag combinations and
//! error paths. Complements `lifecycle.rs` (which covers the
//! happy-path one-flag-per-subcommand cases) by sweeping the
//! cross-product of useful flags.
//!
//! Tests that don't create new enclave keys reuse the
//! `SHARED_ENCLAVE_LABEL` and run for free in every mode. Tests
//! that *do* create keys gate behind `SSHENC_E2E_EXTENDED=1` (SE
//! mode, accepts extra keychain prompts) or `SSHENC_E2E_SOFTWARE=1`
//! (software mode, prompt-free) — same gate as `lifecycle.rs`.

#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{
    docker_skip_reason, extended_enabled, run, shared_enclave_pubkey, software_mode, SshencEnv,
    SHARED_ENCLAVE_LABEL,
};

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
        "skip {test_name}: needs to create enclave keys; \
         set SSHENC_E2E_EXTENDED=1 or SSHENC_E2E_SOFTWARE=1"
    );
    true
}

// ───────────────────────────────────────────────────────────────
// keygen flag matrix
// ───────────────────────────────────────────────────────────────

/// `sshenc keygen --comment "<unicode + spaces>"` round-trips the
/// comment through metadata and exposes it in `inspect`.
#[test]
#[ignore = "requires docker"]
fn keygen_comment_round_trips_through_inspect() {
    if skip_if_no_docker("keygen_comment_round_trips_through_inspect") {
        return;
    }
    if skip_unless_key_creation_cheap("keygen_comment_round_trips_through_inspect") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let label = "e2e-comment";
    let comment = "jay@laptop ✨ unicode test";

    drop(run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["delete", label, "-y"])));

    let out = run(env.sshenc_cmd().expect("sshenc").args([
        "keygen",
        "--label",
        label,
        "--comment",
        comment,
        "--auth-policy",
        "none",
        "--no-pub-file",
    ]))
    .expect("keygen");
    assert!(out.succeeded(), "keygen failed: {}", out.stderr);

    let inspected = run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["inspect", label, "--show-pub"]))
    .expect("inspect");
    assert!(
        inspected.succeeded(),
        "inspect failed: {}",
        inspected.stderr
    );
    assert!(
        inspected.stdout.contains(comment),
        "comment should appear in --show-pub line:\n{}",
        inspected.stdout
    );

    drop(run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["delete", label, "-y"])));
}

/// `sshenc keygen --print-pub` emits the OpenSSH public-key line on
/// stdout in addition to the human-readable fingerprint summary.
#[test]
#[ignore = "requires docker"]
fn keygen_print_pub_emits_openssh_line() {
    if skip_if_no_docker("keygen_print_pub_emits_openssh_line") {
        return;
    }
    if skip_unless_key_creation_cheap("keygen_print_pub_emits_openssh_line") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let label = "e2e-print-pub";
    drop(run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["delete", label, "-y"])));

    let out = run(env.sshenc_cmd().expect("sshenc").args([
        "keygen",
        "--label",
        label,
        "--auth-policy",
        "none",
        "--no-pub-file",
        "--print-pub",
    ]))
    .expect("keygen --print-pub");
    assert!(out.succeeded(), "keygen --print-pub failed: {}", out.stderr);
    assert!(
        out.stdout.contains("ecdsa-sha2-nistp256 AAAA"),
        "expected OpenSSH key line in stdout:\n{}",
        out.stdout
    );

    drop(run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["delete", label, "-y"])));
}

/// `sshenc keygen --json` produces parseable JSON with the new
/// key's metadata, public-key bytes, and fingerprint fields.
#[test]
#[ignore = "requires docker"]
fn keygen_json_output_is_valid_keyinfo() {
    if skip_if_no_docker("keygen_json_output_is_valid_keyinfo") {
        return;
    }
    if skip_unless_key_creation_cheap("keygen_json_output_is_valid_keyinfo") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let label = "e2e-json-keygen";
    drop(run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["delete", label, "-y"])));

    let out = run(env.sshenc_cmd().expect("sshenc").args([
        "keygen",
        "--label",
        label,
        "--auth-policy",
        "none",
        "--no-pub-file",
        "--json",
    ]))
    .expect("keygen --json");
    assert!(out.succeeded(), "keygen --json failed: {}", out.stderr);

    let parsed: serde_json::Value =
        serde_json::from_str(&out.stdout).expect("keygen --json must emit valid JSON");
    assert_eq!(
        parsed
            .get("metadata")
            .and_then(|m| m.get("label"))
            .and_then(|l| l.as_str()),
        Some(label)
    );
    assert!(
        parsed
            .get("fingerprint_sha256")
            .and_then(|s| s.as_str())
            .is_some_and(|s| s.starts_with("SHA256:")),
        "fingerprint_sha256 missing or malformed: {}",
        out.stdout
    );

    drop(run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["delete", label, "-y"])));
}

/// `sshenc keygen --write-pub <custom path>` creates the `.pub`
/// file at the requested location.
#[test]
#[ignore = "requires docker"]
fn keygen_write_pub_custom_path() {
    if skip_if_no_docker("keygen_write_pub_custom_path") {
        return;
    }
    if skip_unless_key_creation_cheap("keygen_write_pub_custom_path") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let label = "e2e-custom-pub";
    let custom_dir = env.home().join("pubs");
    let custom_path = custom_dir.join("the-key.pub");
    drop(run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["delete", label, "-y"])));
    drop(std::fs::remove_file(&custom_path));

    let out = run(env.sshenc_cmd().expect("sshenc").args([
        "keygen",
        "--label",
        label,
        "--auth-policy",
        "none",
        "--write-pub",
        custom_path.to_str().expect("utf-8"),
    ]))
    .expect("keygen --write-pub");
    assert!(out.succeeded(), "keygen --write-pub failed: {}", out.stderr);
    assert!(
        custom_path.exists(),
        "custom .pub path should exist: {}",
        custom_path.display()
    );
    let pub_contents = std::fs::read_to_string(&custom_path).expect("read pub");
    assert!(
        pub_contents.starts_with("ecdsa-sha2-nistp256 "),
        "pub file should be OpenSSH format:\n{pub_contents}"
    );

    drop(run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["delete", label, "-y"])));
}

/// Duplicate-label keygen errors out — the existing key must not be
/// silently replaced.
#[test]
#[ignore = "requires docker"]
fn keygen_duplicate_label_errors() {
    if skip_if_no_docker("keygen_duplicate_label_errors") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared key"));

    let out = run(env.sshenc_cmd().expect("sshenc").args([
        "keygen",
        "--label",
        SHARED_ENCLAVE_LABEL,
        "--auth-policy",
        "none",
        "--no-pub-file",
    ]))
    .expect("duplicate keygen");
    assert!(
        !out.succeeded(),
        "keygen with existing label must fail; stdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    // The agent collapses the duplicate-label backend error into a
    // generic FAILURE on the wire, so the CLI surfaces "agent refused
    // generate". Either the original duplicate message or the proxy
    // refusal counts — but the exit must be non-zero and stderr must
    // mention either generate or the label.
    let err_lower = out.stderr.to_lowercase();
    assert!(
        err_lower.contains("exists")
            || err_lower.contains("duplicate")
            || err_lower.contains("already")
            || err_lower.contains("refused")
            || err_lower.contains("generate"),
        "expected duplicate or agent-refusal error; got:\n{}",
        out.stderr
    );
}

/// keygen rejects labels with characters that would corrupt the
/// keys-dir filesystem layout.
#[test]
#[ignore = "requires docker"]
fn keygen_rejects_invalid_label() {
    if skip_if_no_docker("keygen_rejects_invalid_label") {
        return;
    }
    let env = SshencEnv::new().expect("env");

    for bad in &["../escape", "with space", ".leading-dot", "ends-in-slash/"] {
        let out = run(env.sshenc_cmd().expect("sshenc").args([
            "keygen",
            "--label",
            bad,
            "--auth-policy",
            "none",
            "--no-pub-file",
        ]))
        .expect("keygen invalid label");
        assert!(
            !out.succeeded(),
            "keygen should reject invalid label '{bad}'; stdout:\n{}\nstderr:\n{}",
            out.stdout,
            out.stderr
        );
    }
}

// ───────────────────────────────────────────────────────────────
// inspect / list / export-pub flag matrix
// ───────────────────────────────────────────────────────────────

/// `sshenc inspect --json` returns a `KeyInfo`-shaped object with
/// the same fields keygen --json emits.
#[test]
#[ignore = "requires docker"]
fn inspect_json_emits_keyinfo() {
    if skip_if_no_docker("inspect_json_emits_keyinfo") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared key"));

    let out =
        run(env
            .sshenc_cmd()
            .expect("sshenc")
            .args(["inspect", SHARED_ENCLAVE_LABEL, "--json"]))
        .expect("inspect --json");
    assert!(out.succeeded(), "inspect --json failed: {}", out.stderr);
    let parsed: serde_json::Value =
        serde_json::from_str(&out.stdout).expect("inspect --json must be valid JSON");
    assert_eq!(
        parsed
            .get("metadata")
            .and_then(|m| m.get("label"))
            .and_then(|l| l.as_str()),
        Some(SHARED_ENCLAVE_LABEL),
    );
    assert!(parsed.get("public_key_bytes").is_some());
    assert!(parsed.get("fingerprint_sha256").is_some());
}

/// `sshenc inspect <missing>` errors out with a label-not-found
/// style message.
#[test]
#[ignore = "requires docker"]
fn inspect_missing_label_errors() {
    if skip_if_no_docker("inspect_missing_label_errors") {
        return;
    }
    let env = SshencEnv::new().expect("env");

    let out = run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["inspect", "definitely-not-a-label-xyz"]))
    .expect("inspect missing");
    assert!(
        !out.succeeded(),
        "inspect on missing label should fail:\n{}",
        out.stdout
    );
    let stderr_lower = out.stderr.to_lowercase();
    assert!(
        stderr_lower.contains("not found") || stderr_lower.contains("no such"),
        "expected not-found error; got:\n{}",
        out.stderr
    );
}

/// `sshenc export-pub --output <path>` writes the OpenSSH public
/// key to disk and exits cleanly.
#[test]
#[ignore = "requires docker"]
fn export_pub_output_writes_file() {
    if skip_if_no_docker("export_pub_output_writes_file") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared key"));
    let target = env.home().join("exported.pub");
    drop(std::fs::remove_file(&target));

    let out = run(env.sshenc_cmd().expect("sshenc").args([
        "export-pub",
        SHARED_ENCLAVE_LABEL,
        "--output",
        target.to_str().expect("utf-8"),
    ]))
    .expect("export-pub --output");
    assert!(
        out.succeeded(),
        "export-pub --output failed: {}",
        out.stderr
    );
    let exported = std::fs::read_to_string(&target).expect("read exported");
    assert!(
        exported.starts_with("ecdsa-sha2-nistp256 "),
        "exported file should be an OpenSSH key line:\n{exported}"
    );
}

/// `sshenc export-pub --fingerprint` emits the SHA256 fingerprint
/// string only — no full public key — for scripting.
#[test]
#[ignore = "requires docker"]
fn export_pub_fingerprint_only() {
    if skip_if_no_docker("export_pub_fingerprint_only") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared key"));

    let out = run(env.sshenc_cmd().expect("sshenc").args([
        "export-pub",
        SHARED_ENCLAVE_LABEL,
        "--fingerprint",
    ]))
    .expect("export-pub --fingerprint");
    assert!(
        out.succeeded(),
        "export-pub --fingerprint failed: {}",
        out.stderr
    );
    let line = out.stdout.trim();
    assert!(
        line.starts_with("SHA256:"),
        "expected SHA256: prefix; got '{line}'"
    );
    assert!(
        !line.contains("ecdsa-sha2-nistp256"),
        "fingerprint output should not contain the full key:\n{line}"
    );
}

/// `sshenc export-pub --authorized-keys` formats the output as the
/// authorized_keys-style line (no trailing comment options today,
/// just the standard `<algo> <base64>` form).
#[test]
#[ignore = "requires docker"]
fn export_pub_authorized_keys_format() {
    if skip_if_no_docker("export_pub_authorized_keys_format") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared key"));

    let out = run(env.sshenc_cmd().expect("sshenc").args([
        "export-pub",
        SHARED_ENCLAVE_LABEL,
        "--authorized-keys",
    ]))
    .expect("export-pub --authorized-keys");
    assert!(
        out.succeeded(),
        "export-pub --authorized-keys failed: {}",
        out.stderr
    );
    assert!(
        out.stdout.contains("ecdsa-sha2-nistp256 "),
        "expected OpenSSH algo prefix:\n{}",
        out.stdout
    );
}

/// `sshenc export-pub --json` returns the public-key info with the
/// fingerprint fields and the raw OpenSSH line.
#[test]
#[ignore = "requires docker"]
fn export_pub_json_format() {
    if skip_if_no_docker("export_pub_json_format") {
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
    let parsed: serde_json::Value =
        serde_json::from_str(&out.stdout).expect("export-pub --json must be valid JSON");
    assert_eq!(
        parsed.get("label").and_then(|l| l.as_str()),
        Some(SHARED_ENCLAVE_LABEL),
    );
    assert!(parsed.get("public_key").is_some() || parsed.get("fingerprint_sha256").is_some());
}

/// `sshenc export-pub <missing>` errors out cleanly.
#[test]
#[ignore = "requires docker"]
fn export_pub_missing_label_errors() {
    if skip_if_no_docker("export_pub_missing_label_errors") {
        return;
    }
    let env = SshencEnv::new().expect("env");

    let out = run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["export-pub", "no-such-label-here"]))
    .expect("export-pub missing");
    assert!(
        !out.succeeded(),
        "export-pub on missing label should fail:\n{}",
        out.stdout
    );
}

// ───────────────────────────────────────────────────────────────
// delete flag matrix
// ───────────────────────────────────────────────────────────────

/// `sshenc delete <missing> -y` errors out — the CLI must not
/// pretend a nonexistent key was deleted.
#[test]
#[ignore = "requires docker"]
fn delete_missing_label_errors() {
    if skip_if_no_docker("delete_missing_label_errors") {
        return;
    }
    let env = SshencEnv::new().expect("env");

    let out =
        run(env
            .sshenc_cmd()
            .expect("sshenc")
            .args(["delete", "no-such-label-anywhere", "-y"]))
        .expect("delete missing");
    assert!(
        !out.succeeded(),
        "delete on missing label should fail:\n{}",
        out.stdout
    );
}

/// `sshenc delete --delete-pub` removes the OpenSSH `.pub` file
/// alongside the key.
#[test]
#[ignore = "requires docker"]
fn delete_with_delete_pub_removes_pub_file() {
    if skip_if_no_docker("delete_with_delete_pub_removes_pub_file") {
        return;
    }
    if skip_unless_key_creation_cheap("delete_with_delete_pub_removes_pub_file") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let label = "e2e-delete-pub";
    let pub_path = env.ssh_dir().join(format!("{label}.pub"));

    drop(run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["delete", label, "-y"])));
    drop(std::fs::remove_file(&pub_path));

    let kg = run(env.sshenc_cmd().expect("sshenc").args([
        "keygen",
        "--label",
        label,
        "--auth-policy",
        "none",
        "--write-pub",
        pub_path.to_str().expect("utf-8"),
    ]))
    .expect("keygen");
    assert!(kg.succeeded(), "keygen failed: {}", kg.stderr);
    assert!(pub_path.exists(), ".pub should exist after keygen");

    let del = run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["delete", label, "-y", "--delete-pub"]))
    .expect("delete --delete-pub");
    assert!(
        del.succeeded(),
        "delete --delete-pub failed: {}",
        del.stderr
    );
    assert!(
        !pub_path.exists(),
        ".pub should be removed by --delete-pub: {}",
        pub_path.display()
    );
}

/// `sshenc delete a b -y` deletes multiple labels in a single
/// invocation.
#[test]
#[ignore = "requires docker"]
fn delete_multi_label_in_one_invocation() {
    if skip_if_no_docker("delete_multi_label_in_one_invocation") {
        return;
    }
    if skip_unless_key_creation_cheap("delete_multi_label_in_one_invocation") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let labels = ["e2e-multi-a", "e2e-multi-b"];

    for label in &labels {
        drop(run(env
            .sshenc_cmd()
            .expect("sshenc")
            .args(["delete", label, "-y"])));
        let kg = run(env.sshenc_cmd().expect("sshenc").args([
            "keygen",
            "--label",
            label,
            "--auth-policy",
            "none",
            "--no-pub-file",
        ]))
        .expect("keygen");
        assert!(kg.succeeded(), "keygen {label} failed: {}", kg.stderr);
    }

    let del = run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["delete", labels[0], labels[1], "-y"]))
    .expect("delete multi");
    assert!(del.succeeded(), "delete multi failed: {}", del.stderr);

    let listed = run(env.sshenc_cmd().expect("sshenc").arg("list")).expect("list");
    for label in &labels {
        assert!(
            !listed.stdout.contains(label),
            "label {label} should be gone:\n{}",
            listed.stdout
        );
    }
}
