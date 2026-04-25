// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! gitenc edge-case coverage.
//!
//! The main `gitenc.rs` suite covers the happy-path chain (push,
//! clone, `--config` basics, signed-commit verification). This file
//! covers edge behavior of `gitenc --config`:
//!
//! - no-label form uses the default `~/.ssh/id_ecdsa.pub` signing key
//! - alternate `--config --label X` form parses identically to
//!   `--config X`
//! - `allowed_signers` integration preserves unrelated principals
//! - re-running `gitenc --config` with the same identity leaves a
//!   single entry for that email (idempotent)
//! - invalid label format is rejected before any git config mutation
//! - recorded `pub_file_path` pointing to a missing file errors
//!   cleanly without partial-writing git config
//!
//! These tests don't need docker — they exercise `gitenc --config`,
//! which writes git config and `~/.ssh/allowed_signers` locally.
//! They're still `#[ignore]` so they only run with the rest of the
//! e2e suite under `--ignored`.
//!
//! Meta files are written directly into `$HOME/.sshenc/keys/` (the
//! path gitenc reads via `dirs::home_dir()`). This deliberately
//! bypasses the `sshenc identity` CLI so we don't mutate the shared
//! persistent identity that other tests depend on.

#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{run, shared_enclave_pubkey, SshencEnv, SHARED_ENCLAVE_LABEL};
use std::path::Path;

/// Write a `<label>.meta` file at the path gitenc reads from
/// (`$HOME/.sshenc/keys/`). Returns the written path.
fn write_gitenc_meta(env: &SshencEnv, label: &str, meta: &serde_json::Value) -> std::path::PathBuf {
    let dir = env.home().join(".sshenc").join("keys");
    std::fs::create_dir_all(&dir).expect("mkdir gitenc meta dir");
    let path = dir.join(format!("{label}.meta"));
    std::fs::write(
        &path,
        serde_json::to_string_pretty(meta).expect("serialize meta json"),
    )
    .expect("write meta");
    path
}

fn init_repo(env: &SshencEnv, name: &str) -> std::path::PathBuf {
    let repo = env.home().join(name);
    std::fs::create_dir_all(&repo).expect("mkdir repo");
    assert!(env
        .git_cmd()
        .current_dir(&repo)
        .args(["init", "-q"])
        .status()
        .unwrap()
        .success());
    repo
}

fn git_config_get(env: &SshencEnv, repo: &Path, key: &str) -> String {
    let output = env
        .git_cmd()
        .current_dir(repo)
        .args(["config", "--get", key])
        .output()
        .expect("git config --get");
    assert!(
        output.status.success(),
        "git config --get {key} failed; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// `gitenc --config` (no label) must set `user.signingkey` to the
/// default `$HOME/.ssh/id_ecdsa.pub` path and `core.sshCommand` to
/// `sshenc ssh --` (no label flag).
#[test]
#[ignore = "requires e2e suite"]
fn gitenc_config_no_label_uses_default_id_ecdsa_pub() {
    let env = SshencEnv::new().expect("env");

    // Provide a pub at the default location so the signing key path
    // references a real file (not strictly required, but closer to
    // what users experience).
    let default_pub = env.ssh_dir().join("id_ecdsa.pub");
    std::fs::create_dir_all(default_pub.parent().unwrap()).expect("mkdir ssh dir");
    std::fs::write(&default_pub, "ecdsa-sha2-nistp256 AAAA default@e2e\n")
        .expect("write default pub");

    let repo = init_repo(&env, "no_label_repo");
    let outcome = run(env
        .gitenc_cmd()
        .expect("gitenc cmd")
        .current_dir(&repo)
        .arg("--config"))
    .expect("gitenc --config (no label)");
    assert!(
        outcome.succeeded(),
        "gitenc --config (no label) failed; stderr:\n{}",
        outcome.stderr
    );

    assert_eq!(
        git_config_get(&env, &repo, "core.sshCommand"),
        "sshenc ssh --"
    );
    let signingkey = git_config_get(&env, &repo, "user.signingkey");
    assert!(
        signingkey.ends_with("id_ecdsa.pub"),
        "no-label mode should default to id_ecdsa.pub, got: {signingkey}"
    );
    assert_eq!(git_config_get(&env, &repo, "gpg.format"), "ssh");
    assert_eq!(git_config_get(&env, &repo, "commit.gpgsign"), "true");
}

/// `gitenc --config --label X` must parse identically to
/// `gitenc --config X`. This is the alternate form supported by the
/// arg parser in `gitenc/main.rs:parse_args`.
#[test]
#[ignore = "requires e2e suite"]
fn gitenc_config_alternate_label_form_parses_identically() {
    let env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");

    let pub_path = env.ssh_dir().join(format!("{SHARED_ENCLAVE_LABEL}.pub"));
    std::fs::create_dir_all(pub_path.parent().unwrap()).expect("mkdir ssh dir");
    std::fs::write(&pub_path, format!("{enclave}\n")).expect("write enclave pub");

    let repo = init_repo(&env, "alt_form_repo");
    let outcome = run(env
        .gitenc_cmd()
        .expect("gitenc cmd")
        .current_dir(&repo)
        .args(["--config", "--label", SHARED_ENCLAVE_LABEL]))
    .expect("gitenc --config --label");
    assert!(
        outcome.succeeded(),
        "gitenc --config --label X failed; stderr:\n{}",
        outcome.stderr
    );

    assert_eq!(
        git_config_get(&env, &repo, "core.sshCommand"),
        format!("sshenc ssh --label {SHARED_ENCLAVE_LABEL} --"),
        "alternate --config --label X form should set the same sshCommand"
    );
    let signingkey = git_config_get(&env, &repo, "user.signingkey");
    assert!(
        signingkey.ends_with(&format!("{SHARED_ENCLAVE_LABEL}.pub")),
        "signingkey should reference the labeled pub, got: {signingkey}"
    );
}

/// Running `gitenc --config <label>` when `~/.ssh/allowed_signers`
/// already has entries for unrelated emails must preserve them
/// verbatim. Only the line for the configured key email should be
/// added.
#[test]
#[ignore = "requires e2e suite"]
fn gitenc_config_allowed_signers_preserves_unrelated_entries() {
    let env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");

    // Pub at standard path so configure_repo_entries() picks it up.
    let pub_path = env.ssh_dir().join(format!("{SHARED_ENCLAVE_LABEL}.pub"));
    std::fs::create_dir_all(pub_path.parent().unwrap()).expect("mkdir ssh dir");
    std::fs::write(&pub_path, format!("{enclave}\n")).expect("write enclave pub");

    // Identity metadata at the exact path gitenc reads from.
    // Bypass `sshenc identity` because that CLI writes to
    // $SSHENC_KEYS_DIR (the persistent dir) while gitenc reads from
    // $HOME/.sshenc/keys via dirs::home_dir().
    let email = "signer@e2e-edge.test";
    write_gitenc_meta(
        &env,
        SHARED_ENCLAVE_LABEL,
        &serde_json::json!({
            "app_specific": {
                "git_name": "edge signer",
                "git_email": email,
            }
        }),
    );

    // Pre-populate allowed_signers with unrelated entries.
    let allowed = env.ssh_dir().join("allowed_signers");
    let preexisting = "alice@other.test ssh-ed25519 AAAAalice\n\
                       bob@other.test ssh-ed25519 AAAAbob\n\
                       # comment line explaining the file\n";
    std::fs::write(&allowed, preexisting).expect("seed allowed_signers");

    let repo = init_repo(&env, "allowed_preserve_repo");
    let outcome = run(env
        .gitenc_cmd()
        .expect("gitenc cmd")
        .current_dir(&repo)
        .args(["--config", SHARED_ENCLAVE_LABEL]))
    .expect("gitenc --config");
    assert!(
        outcome.succeeded(),
        "gitenc --config failed; stderr:\n{}",
        outcome.stderr
    );

    let result = std::fs::read_to_string(&allowed).expect("read allowed_signers");
    for (needle, description) in [
        ("alice@other.test", "unrelated alice entry"),
        ("AAAAalice", "alice key bytes verbatim"),
        ("bob@other.test", "unrelated bob entry"),
        ("AAAAbob", "bob key bytes verbatim"),
        ("# comment line explaining the file", "unrelated comment"),
        (email, "new entry for configured email"),
    ] {
        assert!(
            result.contains(needle),
            "{description} should be present; got:\n{result}"
        );
    }
}

/// Running `gitenc --config` twice with the same identity must leave
/// exactly one `allowed_signers` entry for that email — not a
/// duplicate per invocation. Guards against accidental append-only
/// behavior that would grow the file unboundedly across re-configs.
#[test]
#[ignore = "requires e2e suite"]
fn gitenc_config_twice_produces_single_allowed_signers_entry() {
    let env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");

    let pub_path = env.ssh_dir().join(format!("{SHARED_ENCLAVE_LABEL}.pub"));
    std::fs::create_dir_all(pub_path.parent().unwrap()).expect("mkdir ssh dir");
    std::fs::write(&pub_path, format!("{enclave}\n")).expect("write enclave pub");

    let email = "repeater@e2e-edge.test";
    write_gitenc_meta(
        &env,
        SHARED_ENCLAVE_LABEL,
        &serde_json::json!({
            "app_specific": {
                "git_name": "edge repeater",
                "git_email": email,
            }
        }),
    );

    let repo = init_repo(&env, "twice_repo");
    for round in 0..2 {
        let outcome = run(env
            .gitenc_cmd()
            .expect("gitenc cmd")
            .current_dir(&repo)
            .args(["--config", SHARED_ENCLAVE_LABEL]))
        .expect("gitenc --config");
        assert!(
            outcome.succeeded(),
            "gitenc --config round {round} failed; stderr:\n{}",
            outcome.stderr
        );
    }

    let allowed = env.ssh_dir().join("allowed_signers");
    let content = std::fs::read_to_string(&allowed).expect("read allowed_signers");
    let matches_for_email = content
        .lines()
        .filter(|line| line.split_whitespace().next() == Some(email))
        .count();
    assert_eq!(
        matches_for_email, 1,
        "exactly one allowed_signers line should exist for {email} after 2 configs; got:\n{content}"
    );
}

/// Invalid-format labels are rejected before any git state is
/// touched. `gitenc --config <bad>` must not mutate the repo's git
/// config even partially.
#[test]
#[ignore = "requires e2e suite"]
fn gitenc_config_rejects_invalid_label_without_mutating_repo() {
    let env = SshencEnv::new().expect("env");
    let repo = init_repo(&env, "invalid_label_repo");

    // A label with a path separator is invalid.
    let bad = "bad/label";
    let outcome = run(env
        .gitenc_cmd()
        .expect("gitenc cmd")
        .current_dir(&repo)
        .args(["--config", bad]))
    .expect("gitenc --config bad");
    assert!(
        !outcome.succeeded(),
        "gitenc --config {bad} should fail; stdout:\n{}\nstderr:\n{}",
        outcome.stdout,
        outcome.stderr
    );
    assert!(
        outcome.stderr.contains("invalid label") || outcome.stderr.contains("label"),
        "expected label-validation error on stderr; got:\n{}",
        outcome.stderr
    );

    // No core.sshCommand was written.
    let probe = env
        .git_cmd()
        .current_dir(&repo)
        .args(["config", "--get", "core.sshCommand"])
        .output()
        .expect("git config probe");
    assert!(
        !probe.status.success(),
        "core.sshCommand should not be set after rejected config; got: {}",
        String::from_utf8_lossy(&probe.stdout)
    );
}

/// When a key's metadata records a `pub_file_path` that no longer
/// exists on disk, `gitenc --config` must error cleanly without
/// mutating git config. Covers the stale-export path.
#[test]
#[ignore = "requires e2e suite"]
fn gitenc_config_errors_when_recorded_pub_path_missing() {
    let env = SshencEnv::new().expect("env");

    // Record a bogus pub_file_path for the shared label.
    let bogus_path = env.home().join(".ssh").join("nonexistent.pub");
    write_gitenc_meta(
        &env,
        SHARED_ENCLAVE_LABEL,
        &serde_json::json!({
            "app_specific": {
                "pub_file_path": bogus_path.display().to_string(),
            }
        }),
    );

    let repo = init_repo(&env, "recorded_missing_repo");
    let outcome = run(env
        .gitenc_cmd()
        .expect("gitenc cmd")
        .current_dir(&repo)
        .args(["--config", SHARED_ENCLAVE_LABEL]))
    .expect("gitenc --config");
    assert!(
        !outcome.succeeded(),
        "gitenc --config must fail when recorded pub_file_path is missing; stdout:\n{}",
        outcome.stdout
    );
    let msg = outcome.stderr.to_lowercase();
    assert!(
        msg.contains("public key") || msg.contains("does not exist") || msg.contains("recorded"),
        "expected missing-pub error on stderr; got:\n{}",
        outcome.stderr
    );

    // No core.sshCommand got written mid-failure.
    let probe = env
        .git_cmd()
        .current_dir(&repo)
        .args(["config", "--get", "core.sshCommand"])
        .output()
        .expect("git config probe");
    assert!(
        !probe.status.success(),
        "core.sshCommand must not be written when gitenc rejects the config; got: {}",
        String::from_utf8_lossy(&probe.stdout)
    );
}
