// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `git revert --no-commit`, `git cherry-pick --no-commit`, and
//! `git merge --no-commit` stage their changes without making a
//! commit; the user then runs `git commit` separately. The
//! contract pinned: that follow-up `git commit` produces a
//! valid sshenc-signed commit (and for merge, a 2-parent merge
//! commit).

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
        "no-commit signer",
        "nocommit@e2e.test",
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

/// `git revert --no-commit <sha>` stages a revert; the
/// subsequent `git commit` signs the resulting commit.
#[test]
#[ignore = "requires docker"]
fn revert_no_commit_then_commit_is_signed() {
    if skip_if_no_docker("revert_no_commit_then_commit_is_signed") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "revert-no-commit-repo", &enclave);

    make_commit(&env, &repo, "a.txt", "first\n", "first");
    make_commit(&env, &repo, "b.txt", "second\n", "second");

    let revert = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["revert", "--no-commit", "HEAD"]))
    .expect("git revert --no-commit");
    assert!(
        revert.succeeded(),
        "git revert --no-commit: {}",
        revert.stderr
    );

    // The user separately commits the staged revert.
    let commit =
        run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["commit", "-q", "-m", "manual revert commit"]))
        .expect("git commit (after revert --no-commit)");
    assert!(
        commit.succeeded(),
        "manual commit after revert --no-commit failed: {}",
        commit.stderr
    );

    let verify = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(
        verify.succeeded(),
        "verify-commit on manual-revert HEAD failed; stderr:\n{}",
        verify.stderr
    );
}

/// `git cherry-pick --no-commit <sha>` stages a pick; the
/// subsequent `git commit` signs.
#[test]
#[ignore = "requires docker"]
fn cherry_pick_no_commit_then_commit_is_signed() {
    if skip_if_no_docker("cherry_pick_no_commit_then_commit_is_signed") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "cp-no-commit-repo", &enclave);

    make_commit(&env, &repo, "main.txt", "main\n", "main");
    assert!(env
        .git_cmd()
        .current_dir(&repo)
        .args(["checkout", "-q", "-b", "feature"])
        .status()
        .expect("checkout -b feature")
        .success());
    make_commit(&env, &repo, "feat.txt", "feat\n", "feat commit");
    let feat_sha = run(env.git_cmd().current_dir(&repo).args(["rev-parse", "HEAD"]))
        .expect("rev-parse")
        .stdout
        .trim()
        .to_string();

    assert!(env
        .git_cmd()
        .current_dir(&repo)
        .args(["checkout", "-q", "main"])
        .status()
        .expect("checkout main")
        .success());

    let cp = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["cherry-pick", "--no-commit", &feat_sha]))
    .expect("git cherry-pick --no-commit");
    assert!(cp.succeeded(), "cherry-pick --no-commit: {}", cp.stderr);

    let commit =
        run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["commit", "-q", "-m", "manual pick commit"]))
        .expect("git commit (after cherry-pick --no-commit)");
    assert!(
        commit.succeeded(),
        "manual commit after cherry-pick --no-commit failed: {}",
        commit.stderr
    );

    let verify = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(
        verify.succeeded(),
        "verify-commit on manual-pick HEAD failed; stderr:\n{}",
        verify.stderr
    );
}

/// `git merge --no-commit --no-ff <branch>` stages a
/// (conflict-free) merge; the subsequent `git commit` produces
/// a 2-parent signed merge commit.
#[test]
#[ignore = "requires docker"]
fn merge_no_commit_then_commit_is_signed_merge() {
    if skip_if_no_docker("merge_no_commit_then_commit_is_signed_merge") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "merge-no-commit-repo", &enclave);

    make_commit(&env, &repo, "main.txt", "main\n", "main");
    assert!(env
        .git_cmd()
        .current_dir(&repo)
        .args(["checkout", "-q", "-b", "feature"])
        .status()
        .expect("checkout -b feature")
        .success());
    make_commit(&env, &repo, "feat.txt", "feat\n", "feat");

    assert!(env
        .git_cmd()
        .current_dir(&repo)
        .args(["checkout", "-q", "main"])
        .status()
        .expect("checkout main")
        .success());

    let merge =
        run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["merge", "--no-ff", "--no-commit", "feature"]))
        .expect("git merge --no-commit");
    assert!(merge.succeeded(), "merge --no-commit: {}", merge.stderr);

    let commit =
        run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["commit", "-q", "-m", "manual merge commit"]))
        .expect("git commit (after merge --no-commit)");
    assert!(
        commit.succeeded(),
        "manual commit after merge --no-commit failed: {}",
        commit.stderr
    );

    // 2-parent merge commit and verifies.
    let parents =
        run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["rev-list", "--parents", "-n", "1", "HEAD"]))
        .expect("rev-list parents");
    let parent_count = parents.stdout.split_whitespace().count() - 1;
    assert_eq!(
        parent_count, 2,
        "expected 2-parent merge commit; got {parent_count}:\n{}",
        parents.stdout
    );
    let verify = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(
        verify.succeeded(),
        "verify-commit on manual merge HEAD failed; stderr:\n{}",
        verify.stderr
    );
}
