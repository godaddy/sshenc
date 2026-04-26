// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `gitenc --config` corners involving environment variables and
//! the implicit-default label, which the existing gitenc test
//! files don't cover:
//!
//! 1. **`gitenc --config` with no label argument** falls back to
//!    the "default" label. `gitenc.rs` always passes an explicit
//!    label; pin the implicit-default path.
//! 2. **`GIT_DIR` env var pointing at a non-standard location**:
//!    `gitenc --config` should still write to the right repo
//!    config file (the one `git config --local` would write to)
//!    when GIT_DIR is set.
//! 3. **User git aliases** in repo-local config survive
//!    `gitenc --config`. `gitenc_config_more.rs` tests global
//!    isolation; this is the per-repo equivalent.

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
        "skip {test_name}: needs to mint keys; \
         set SSHENC_E2E_SOFTWARE=1 or SSHENC_E2E_EXTENDED=1"
    );
    true
}

fn plant_meta(env: &SshencEnv, label: &str, name: &str, email: &str) {
    let dir = env.home().join(".sshenc").join("keys");
    std::fs::create_dir_all(&dir).expect("mkdir gitenc meta dir");
    std::fs::write(
        dir.join(format!("{label}.meta")),
        serde_json::to_string_pretty(&serde_json::json!({
            "app_specific": {
                "git_name": name,
                "git_email": email,
            }
        }))
        .unwrap(),
    )
    .expect("write meta");
}

/// `gitenc --config` with no label falls back to "default".
/// Mints a "default" key, plants its meta+pub, runs gitenc
/// --config (no positional arg), verifies user.email reflects
/// the default key's identity.
#[test]
#[ignore = "requires docker"]
fn gitenc_config_no_label_uses_default() {
    if skip_if_no_docker("gitenc_config_no_label_uses_default") {
        return;
    }
    if skip_unless_key_creation_cheap("gitenc_config_no_label_uses_default") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    env.use_ephemeral_keys_dir().expect("ephemeral");
    env.start_agent().expect("start agent");

    // Mint a "default" key with --write-pub so the meta records
    // pub_file_path (gitenc reads that field).
    let default_pub = env.ssh_dir().join("id_ecdsa.pub");
    std::fs::create_dir_all(env.ssh_dir()).expect("mkdir ssh dir");
    let kg = run(env.sshenc_cmd().expect("sshenc cmd").args([
        "keygen",
        "--label",
        "default",
        "--auth-policy",
        "none",
    ]))
    .expect("keygen default");
    assert!(kg.succeeded(), "keygen default: {}", kg.stderr);
    assert!(
        default_pub.exists(),
        "expected ~/.ssh/id_ecdsa.pub after keygen --label default"
    );

    plant_meta(&env, "default", "default signer", "default@e2e.test");
    // Replicate the meta from the keys_dir into gitenc's path with
    // a repaired pub_file_path (see git_verify_pull_show_sig.rs
    // for context — the agent-side meta records null because
    // write_pub_path doesn't travel in the GenerateKey RPC).
    let keys_dir = env.home().join(".sshenc-keys-ephemeral");
    let meta_src = keys_dir.join("default.meta");
    let mut meta_val: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&meta_src).expect("read meta"))
            .expect("parse meta");
    if let Some(app) = meta_val
        .get_mut("app_specific")
        .and_then(|v| v.as_object_mut())
    {
        app.insert(
            "pub_file_path".to_string(),
            serde_json::Value::String(default_pub.display().to_string()),
        );
        app.insert(
            "git_name".to_string(),
            serde_json::Value::String("default signer".to_string()),
        );
        app.insert(
            "git_email".to_string(),
            serde_json::Value::String("default@e2e.test".to_string()),
        );
    }
    std::fs::write(
        env.home().join(".sshenc").join("keys").join("default.meta"),
        serde_json::to_string_pretty(&meta_val).unwrap(),
    )
    .expect("plant repaired meta");

    let repo = env.home().join("default-label-repo");
    std::fs::create_dir_all(&repo).expect("mkdir");
    assert!(env
        .git_cmd()
        .current_dir(&repo)
        .args(["init", "-q", "-b", "main"])
        .status()
        .expect("git init")
        .success());

    // gitenc --config with NO positional label argument.
    let cfg = run(env
        .gitenc_cmd()
        .expect("gitenc cmd")
        .current_dir(&repo)
        .arg("--config"))
    .expect("gitenc --config (no label)");
    assert!(
        cfg.succeeded(),
        "gitenc --config (no label) failed; stdout:\n{}\nstderr:\n{}",
        cfg.stdout,
        cfg.stderr
    );

    let email =
        run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["config", "--local", "--get", "user.email"]))
        .expect("git config email");
    assert_eq!(
        email.stdout.trim(),
        "default@e2e.test",
        "default-label fallback didn't pick up the default key's email; got:\n{}",
        email.stdout
    );

    drop(run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["delete", "default", "-y"])));
}

/// `gitenc --config` preserves user-defined per-repo git
/// aliases. A regression that rewrites .git/config wholesale
/// would lose aliases the user added; the contract is "edit the
/// signing-related keys, leave everything else alone."
#[test]
#[ignore = "requires docker"]
fn gitenc_config_preserves_per_repo_git_aliases() {
    if skip_if_no_docker("gitenc_config_preserves_per_repo_git_aliases") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let _shared = shared_enclave_pubkey(&env).expect("shared enclave");
    plant_meta(&env, SHARED_ENCLAVE_LABEL, "alias signer", "alias@e2e.test");

    let repo = env.home().join("alias-repo");
    std::fs::create_dir_all(&repo).expect("mkdir");
    assert!(env
        .git_cmd()
        .current_dir(&repo)
        .args(["init", "-q", "-b", "main"])
        .status()
        .expect("git init")
        .success());

    // Add user-defined aliases to the repo-local config.
    for (k, v) in [
        ("alias.lg", "log --oneline --graph"),
        ("alias.st", "status -s"),
        ("alias.amend", "commit --amend --no-edit"),
    ] {
        let set = run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["config", "--local", k, v]))
        .expect("git config set");
        assert!(set.succeeded(), "git config {k}: {}", set.stderr);
    }

    let cfg = run(env
        .gitenc_cmd()
        .expect("gitenc cmd")
        .current_dir(&repo)
        .args(["--config", SHARED_ENCLAVE_LABEL]))
    .expect("gitenc --config");
    assert!(cfg.succeeded(), "gitenc --config: {}", cfg.stderr);

    // All three aliases must still be present after gitenc
    // wrote its signing-related keys.
    for (k, v) in [
        ("alias.lg", "log --oneline --graph"),
        ("alias.st", "status -s"),
        ("alias.amend", "commit --amend --no-edit"),
    ] {
        let got = run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["config", "--local", "--get", k]))
        .expect("git config get");
        assert!(got.succeeded(), "alias {k} disappeared: {}", got.stderr);
        assert_eq!(
            got.stdout.trim(),
            v,
            "alias {k} value changed: expected '{v}', got '{}'",
            got.stdout.trim()
        );
    }
}

/// `gitenc --config` with `GIT_DIR` set to the repo's actual
/// .git directory still writes to the right config file.
/// Some tooling sets GIT_DIR explicitly (e.g., post-receive
/// hooks, scripts that walk worktrees); pin the contract.
#[test]
#[ignore = "requires docker"]
fn gitenc_config_with_git_dir_env_writes_correct_config() {
    if skip_if_no_docker("gitenc_config_with_git_dir_env_writes_correct_config") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let _shared = shared_enclave_pubkey(&env).expect("shared enclave");
    plant_meta(
        &env,
        SHARED_ENCLAVE_LABEL,
        "git-dir signer",
        "git-dir@e2e.test",
    );

    let repo = env.home().join("git-dir-repo");
    std::fs::create_dir_all(&repo).expect("mkdir");
    assert!(env
        .git_cmd()
        .current_dir(&repo)
        .args(["init", "-q", "-b", "main"])
        .status()
        .expect("git init")
        .success());

    let git_dir = repo.join(".git");
    let cfg = run(env
        .gitenc_cmd()
        .expect("gitenc cmd")
        .current_dir(&repo)
        .env("GIT_DIR", &git_dir)
        .args(["--config", SHARED_ENCLAVE_LABEL]))
    .expect("gitenc --config");
    assert!(
        cfg.succeeded(),
        "gitenc --config with GIT_DIR set failed; stderr:\n{}",
        cfg.stderr
    );

    // The local repo config must reflect the planted identity.
    let email = run(env
        .git_cmd()
        .current_dir(&repo)
        .env("GIT_DIR", &git_dir)
        .args(["config", "--local", "--get", "user.email"]))
    .expect("git config");
    assert_eq!(
        email.stdout.trim(),
        "git-dir@e2e.test",
        "user.email not set with GIT_DIR env; got:\n{}",
        email.stdout
    );
}
