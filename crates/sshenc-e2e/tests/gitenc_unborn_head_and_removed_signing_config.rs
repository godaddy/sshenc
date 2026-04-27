// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Two gitenc-config edge cases that the existing
//! `gitenc.rs`, `gitenc_corners.rs`, and `gitenc_config_more.rs`
//! tests don't pin:
//!
//! - `gitenc --config <label>` on a freshly-initialized repo
//!   with no commits (HEAD is unborn) succeeds. A subsequent
//!   first commit is signed and verifies.
//! - After `gitenc --config <label>`, manually unsetting
//!   `commit.gpgsign` and `gpg.ssh.allowedSignersFile` produces
//!   the expected behavior: a fresh commit is no longer signed
//!   (signing config is read fresh from git config, not cached).

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

fn plant_meta_and_pub(env: &SshencEnv, label: &str, name: &str, email: &str, enclave: &str) {
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
    std::fs::create_dir_all(env.ssh_dir()).expect("mkdir ssh dir");
    std::fs::write(
        env.ssh_dir().join(format!("{label}.pub")),
        format!("{enclave}\n"),
    )
    .expect("write pub");
}

/// `gitenc --config <label>` succeeds on a freshly-initialized
/// repo with no commits (unborn HEAD). The subsequent first
/// commit is sshenc-signed.
#[test]
#[ignore = "requires docker"]
fn gitenc_config_succeeds_on_unborn_head() {
    if skip_if_no_docker("gitenc_config_succeeds_on_unborn_head") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");

    plant_meta_and_pub(
        &env,
        SHARED_ENCLAVE_LABEL,
        "unborn signer",
        "unborn@e2e.test",
        &enclave,
    );

    let repo = env.home().join("unborn-head-repo");
    std::fs::create_dir_all(&repo).expect("mkdir");
    assert!(env
        .git_cmd()
        .current_dir(&repo)
        .args(["init", "-q", "-b", "main"])
        .status()
        .expect("git init")
        .success());

    // Confirm HEAD is unborn.
    let rev = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["rev-parse", "--verify", "HEAD"]))
    .expect("rev-parse");
    assert!(
        !rev.succeeded(),
        "HEAD should be unborn before first commit; got:\n{}",
        rev.stdout
    );

    // gitenc --config must succeed despite unborn HEAD.
    let cfg = run(env
        .gitenc_cmd()
        .expect("gitenc cmd")
        .current_dir(&repo)
        .args(["--config", SHARED_ENCLAVE_LABEL]))
    .expect("gitenc --config");
    assert!(
        cfg.succeeded(),
        "gitenc --config on unborn head failed; stderr:\n{}",
        cfg.stderr
    );

    // First commit on the unborn branch must be signed and verify.
    std::fs::write(repo.join("first.txt"), b"first\n").expect("write");
    let add = run(env.git_cmd().current_dir(&repo).args(["add", "first.txt"])).expect("git add");
    assert!(add.succeeded(), "git add: {}", add.stderr);
    let commit = run(env.git_cmd().current_dir(&repo).args([
        "commit",
        "-q",
        "-m",
        "first commit on unborn head",
    ]))
    .expect("git commit");
    assert!(commit.succeeded(), "first commit: {}", commit.stderr);

    let verify = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(
        verify.succeeded(),
        "verify-commit on first-commit-after-unborn failed; stderr:\n{}",
        verify.stderr
    );
}

/// After `gitenc --config`, removing `commit.gpgsign` makes
/// subsequent commits unsigned. Pins that signing config is
/// read fresh from git config, not cached at gitenc-time.
#[test]
#[ignore = "requires docker"]
fn unsetting_signing_config_disables_signing_on_next_commit() {
    if skip_if_no_docker("unsetting_signing_config_disables_signing_on_next_commit") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");

    plant_meta_and_pub(
        &env,
        SHARED_ENCLAVE_LABEL,
        "config-mut signer",
        "configmut@e2e.test",
        &enclave,
    );

    let repo = env.home().join("config-removal-repo");
    std::fs::create_dir_all(&repo).expect("mkdir");
    assert!(env
        .git_cmd()
        .current_dir(&repo)
        .args(["init", "-q", "-b", "main"])
        .status()
        .expect("git init")
        .success());
    let cfg = run(env
        .gitenc_cmd()
        .expect("gitenc cmd")
        .current_dir(&repo)
        .args(["--config", SHARED_ENCLAVE_LABEL]))
    .expect("gitenc --config");
    assert!(cfg.succeeded(), "gitenc --config: {}", cfg.stderr);

    // First commit signs cleanly.
    std::fs::write(repo.join("a.txt"), b"first\n").expect("write");
    let add = run(env.git_cmd().current_dir(&repo).args(["add", "a.txt"])).expect("git add");
    assert!(add.succeeded(), "git add: {}", add.stderr);
    let commit1 =
        run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["commit", "-q", "-m", "signed first"]))
        .expect("first commit");
    assert!(commit1.succeeded(), "first commit: {}", commit1.stderr);
    let verify1 = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(
        verify1.succeeded(),
        "first commit didn't verify; stderr:\n{}",
        verify1.stderr
    );

    // Remove commit.gpgsign locally.
    let unset = run(env.git_cmd().current_dir(&repo).args([
        "config",
        "--local",
        "--unset",
        "commit.gpgsign",
    ]))
    .expect("git config --unset");
    assert!(unset.succeeded(), "git config --unset: {}", unset.stderr);

    // Second commit must not be signed: verify-commit should fail
    // with "no signature".
    std::fs::write(repo.join("b.txt"), b"second\n").expect("write");
    let add2 = run(env.git_cmd().current_dir(&repo).args(["add", "b.txt"])).expect("git add");
    assert!(add2.succeeded(), "git add b: {}", add2.stderr);
    let commit2 =
        run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["commit", "-q", "-m", "unsigned second"]))
        .expect("second commit");
    assert!(commit2.succeeded(), "second commit: {}", commit2.stderr);

    let verify2 = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit on unsigned");
    assert!(
        !verify2.succeeded(),
        "verify-commit should fail on unsigned commit; stdout:\n{}\nstderr:\n{}",
        verify2.stdout,
        verify2.stderr
    );
}
