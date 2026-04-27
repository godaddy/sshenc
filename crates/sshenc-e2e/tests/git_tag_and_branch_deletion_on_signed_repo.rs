// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `git tag -d` (delete tag) and `git branch -D` (force-delete
//! branch) on a gitenc-configured repo. Existing tests cover
//! creating signed tags and force-overwriting them, but not
//! deleting them. The contract: deletion succeeds without
//! errors and the ref is gone from `git for-each-ref`. Adjacent
//! commits/objects remain intact (they're reachable via
//! reflog).

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
        "delete signer",
        "delete@e2e.test",
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

/// `git tag -d <signed-tag>` removes the tag ref cleanly.
#[test]
#[ignore = "requires docker"]
fn delete_signed_tag_removes_ref() {
    if skip_if_no_docker("delete_signed_tag_removes_ref") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "tag-delete-repo", &enclave);

    make_commit(&env, &repo, "a.txt", "first\n", "first");
    let tag = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["tag", "-s", "v1", "-m", "signed"]))
    .expect("git tag -s");
    assert!(tag.succeeded(), "git tag -s: {}", tag.stderr);

    // Tag is present.
    let listed_before =
        run(env.git_cmd().current_dir(&repo).args(["tag", "-l"])).expect("tag list before");
    assert!(
        listed_before.stdout.contains("v1"),
        "expected v1 in tag list before delete; got:\n{}",
        listed_before.stdout
    );

    // Delete it.
    let delete =
        run(env.git_cmd().current_dir(&repo).args(["tag", "-d", "v1"])).expect("git tag -d");
    assert!(delete.succeeded(), "git tag -d: {}", delete.stderr);

    // Tag is gone.
    let listed_after =
        run(env.git_cmd().current_dir(&repo).args(["tag", "-l"])).expect("tag list after");
    assert!(
        !listed_after.stdout.contains("v1"),
        "v1 should be absent after delete; got:\n{}",
        listed_after.stdout
    );

    // The underlying commit (HEAD) still verifies — only the tag ref was removed.
    let verify = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(
        verify.succeeded(),
        "verify-commit on HEAD after tag delete failed; stderr:\n{}",
        verify.stderr
    );
}

/// `git branch -D <branch>` force-deletes a branch containing
/// signed commits. The underlying commits remain reachable via
/// reflog; the branch ref is gone.
#[test]
#[ignore = "requires docker"]
fn force_delete_branch_with_signed_commits_removes_ref() {
    if skip_if_no_docker("force_delete_branch_with_signed_commits_removes_ref") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "branch-delete-repo", &enclave);

    make_commit(&env, &repo, "a.txt", "main\n", "main commit");

    // Create a feature branch with a signed commit.
    assert!(env
        .git_cmd()
        .current_dir(&repo)
        .args(["checkout", "-q", "-b", "feature"])
        .status()
        .expect("checkout -b feature")
        .success());
    make_commit(&env, &repo, "feat.txt", "feat\n", "feat commit");

    // Switch back to main so feature isn't HEAD.
    assert!(env
        .git_cmd()
        .current_dir(&repo)
        .args(["checkout", "-q", "main"])
        .status()
        .expect("checkout main")
        .success());

    // Force-delete the feature branch (which has commits not on main).
    let delete = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["branch", "-D", "feature"]))
    .expect("git branch -D");
    assert!(delete.succeeded(), "git branch -D: {}", delete.stderr);

    // The branch ref is gone.
    let branches = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["for-each-ref", "refs/heads/feature"]))
    .expect("for-each-ref");
    assert!(branches.succeeded(), "for-each-ref: {}", branches.stderr);
    assert!(
        branches.stdout.trim().is_empty(),
        "feature branch ref should be gone; got:\n{}",
        branches.stdout
    );

    // main HEAD still verifies.
    let verify = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(
        verify.succeeded(),
        "verify-commit on main HEAD after branch delete failed; stderr:\n{}",
        verify.stderr
    );
}
