// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Low-level git ref-manipulation operations on a
//! gitenc-configured repo:
//!
//! - `git checkout --orphan <branch>` creates a fresh branch
//!   with no parent. The first commit on that branch is signed
//!   and verifies, even though the orphan branch's HEAD started
//!   from an unborn ref state.
//! - `git update-ref refs/heads/<name> <sha>` directly creates
//!   a branch ref pointing at a signed commit. Verification on
//!   the new ref must work without re-signing.

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
        "ref-ops signer",
        "refops@e2e.test",
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

fn rev_parse(env: &SshencEnv, repo: &std::path::Path, rev: &str) -> String {
    let out = run(env.git_cmd().current_dir(repo).args(["rev-parse", rev])).expect("rev-parse");
    assert!(out.succeeded(), "rev-parse {rev}: {}", out.stderr);
    out.stdout.trim().to_string()
}

/// `git checkout --orphan <branch>` followed by a first commit
/// produces a signed commit on the new orphan branch.
#[test]
#[ignore = "requires docker"]
fn checkout_orphan_branch_first_commit_is_signed() {
    if skip_if_no_docker("checkout_orphan_branch_first_commit_is_signed") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "orphan-repo", &enclave);

    // Initial commit on main so the repo has a valid root.
    make_commit(&env, &repo, "main.txt", "main\n", "main");

    // Switch to a brand-new orphan branch with no parent.
    let orphan = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["checkout", "--orphan", "fresh"]))
    .expect("checkout --orphan");
    assert!(
        orphan.succeeded(),
        "git checkout --orphan: {}",
        orphan.stderr
    );

    // Clear the index (orphan starts with everything staged from
    // the previous tree).
    let rm = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["rm", "-rf", "--cached", "."]))
    .expect("git rm --cached");
    assert!(rm.succeeded(), "git rm --cached: {}", rm.stderr);

    // First (and only) commit on the orphan branch.
    std::fs::write(repo.join("o.txt"), b"orphan content\n").expect("write");
    let add = run(env.git_cmd().current_dir(&repo).args(["add", "o.txt"])).expect("git add");
    assert!(add.succeeded(), "git add: {}", add.stderr);
    let commit = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["commit", "-q", "-m", "orphan first"]))
    .expect("orphan commit");
    assert!(commit.succeeded(), "orphan commit: {}", commit.stderr);

    let verify = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(
        verify.succeeded(),
        "verify-commit on orphan first commit failed; stderr:\n{}",
        verify.stderr
    );
}

/// `git update-ref refs/heads/<name> <sha>` creates a branch ref
/// pointing at a signed commit; `git verify-commit <name>` works
/// against the new ref.
#[test]
#[ignore = "requires docker"]
fn update_ref_to_signed_commit_works_for_verify() {
    if skip_if_no_docker("update_ref_to_signed_commit_works_for_verify") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "update-ref-repo", &enclave);

    make_commit(&env, &repo, "a.txt", "first\n", "first");
    let sha = rev_parse(&env, &repo, "HEAD");

    let update =
        run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["update-ref", "refs/heads/manual-ref", &sha]))
        .expect("git update-ref");
    assert!(update.succeeded(), "git update-ref: {}", update.stderr);

    // The new ref resolves to the same commit.
    let resolved = rev_parse(&env, &repo, "manual-ref");
    assert_eq!(
        resolved, sha,
        "manual-ref should resolve to the signed commit's sha"
    );

    // verify-commit works through the new ref.
    let verify = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "manual-ref"]))
    .expect("verify-commit manual-ref");
    assert!(
        verify.succeeded(),
        "verify-commit on manual-ref failed; stderr:\n{}",
        verify.stderr
    );
}
