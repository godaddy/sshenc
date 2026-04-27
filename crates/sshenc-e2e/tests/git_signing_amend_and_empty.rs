// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `git commit --allow-empty` and `git commit --amend` both
//! produce sshenc-signed commits that `git verify-commit HEAD`
//! accepts. Complements `gitenc.rs` and
//! `git_verify_pull_show_sig.rs`, which pin the standard
//! "make-a-commit-then-verify" flow but don't exercise these
//! two edge cases of the signing path.
//!
//! - `--allow-empty`: the commit has no diff body, so the
//!   signing path must not bail on "nothing to sign".
//! - `--amend`: the rewritten HEAD has a new sha; the new
//!   signature must verify (signing isn't skipped or copied
//!   from the prior commit).

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

fn make_signed_repo(env: &SshencEnv, name: &str, enclave: &str) -> std::path::PathBuf {
    plant_meta_and_pub(
        env,
        SHARED_ENCLAVE_LABEL,
        "amend signer",
        "amend@e2e.test",
        enclave,
    );
    let repo = env.home().join(name);
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
    repo
}

fn make_commit(env: &SshencEnv, repo: &std::path::Path, file: &str, content: &str, msg: &str) {
    std::fs::write(repo.join(file), content.as_bytes()).expect("write file");
    let add = run(env.git_cmd().current_dir(repo).args(["add", file])).expect("git add");
    assert!(add.succeeded(), "git add: {}", add.stderr);
    let commit = run(env
        .git_cmd()
        .current_dir(repo)
        .args(["commit", "-q", "-m", msg]))
    .expect("git commit");
    assert!(commit.succeeded(), "git commit: {}", commit.stderr);
}

/// `git commit --allow-empty` produces an sshenc-signed empty
/// commit and `git verify-commit HEAD` accepts it.
#[test]
#[ignore = "requires docker"]
fn commit_allow_empty_produces_signed_commit() {
    if skip_if_no_docker("commit_allow_empty_produces_signed_commit") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "allow-empty-repo", &enclave);

    make_commit(&env, &repo, "a.txt", "first\n", "first");

    let empty = run(env.git_cmd().current_dir(&repo).args([
        "commit",
        "--allow-empty",
        "-q",
        "-m",
        "empty signed",
    ]))
    .expect("commit --allow-empty");
    assert!(
        empty.succeeded(),
        "git commit --allow-empty failed: {}",
        empty.stderr
    );

    let verify = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(
        verify.succeeded(),
        "verify-commit on empty commit failed; stdout:\n{}\nstderr:\n{}",
        verify.stdout,
        verify.stderr
    );
}

/// `git commit --amend` produces a new HEAD sha whose signature
/// verifies cleanly.
#[test]
#[ignore = "requires docker"]
fn commit_amend_re_signs_commit() {
    if skip_if_no_docker("commit_amend_re_signs_commit") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "amend-repo", &enclave);

    make_commit(&env, &repo, "a.txt", "first\n", "first commit");
    let original_sha = run(env.git_cmd().current_dir(&repo).args(["rev-parse", "HEAD"]))
        .expect("rev-parse")
        .stdout
        .trim()
        .to_string();

    let amend = run(env.git_cmd().current_dir(&repo).args([
        "commit",
        "--amend",
        "-q",
        "-m",
        "first commit (amended)",
    ]))
    .expect("commit --amend");
    assert!(amend.succeeded(), "commit --amend: {}", amend.stderr);

    let new_sha = run(env.git_cmd().current_dir(&repo).args(["rev-parse", "HEAD"]))
        .expect("rev-parse new")
        .stdout
        .trim()
        .to_string();
    assert_ne!(
        original_sha, new_sha,
        "amend should produce a new commit sha"
    );

    let verify = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(
        verify.succeeded(),
        "verify-commit on amended HEAD failed; stdout:\n{}\nstderr:\n{}",
        verify.stdout,
        verify.stderr
    );
}
