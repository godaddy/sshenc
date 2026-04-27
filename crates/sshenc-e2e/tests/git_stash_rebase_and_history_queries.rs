// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Local git operations on a gitenc-configured repo:
//!
//! - `git stash push` and `git stash pop` complete cleanly when
//!   the repo has `commit.gpgsign=true` set by `gitenc --config`.
//!   Stash creates internal commits for the index/worktree;
//!   pin that this doesn't crash or wedge the agent.
//! - `git rebase` produces fresh sshenc-signed commits for every
//!   rewritten commit in the rebased range. Each rebased commit
//!   must verify with `git verify-commit`.
//! - History-query commands (`log --graph`, `describe`, `reflog`)
//!   work against a chain of sshenc-signed commits — signature
//!   metadata in commit headers doesn't break topology walking.

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
        "stash signer",
        "stash@e2e.test",
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

/// `git stash push` followed by `git stash pop` complete cleanly
/// on a gitenc-configured repo (where `commit.gpgsign=true`).
#[test]
#[ignore = "requires docker"]
fn stash_push_and_pop_round_trip() {
    if skip_if_no_docker("stash_push_and_pop_round_trip") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "stash-repo", &enclave);

    make_commit(&env, &repo, "a.txt", "first\n", "first");

    // Modify and stash.
    std::fs::write(repo.join("a.txt"), b"modified\n").expect("write");
    let stash = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["stash", "push", "-m", "wip"]))
    .expect("git stash push");
    assert!(stash.succeeded(), "git stash push: {}", stash.stderr);

    // Working tree should be back to "first\n".
    let body = std::fs::read_to_string(repo.join("a.txt")).expect("read");
    assert_eq!(body, "first\n", "stash should reset worktree");

    // Pop and verify the modification returns.
    let pop = run(env.git_cmd().current_dir(&repo).args(["stash", "pop"])).expect("git stash pop");
    assert!(pop.succeeded(), "git stash pop: {}", pop.stderr);
    let body_after = std::fs::read_to_string(repo.join("a.txt")).expect("read");
    assert_eq!(
        body_after, "modified\n",
        "stash pop should restore modification"
    );
}

/// `git rebase` rewrites commits and signs each one. Every
/// rebased commit must verify with `git verify-commit`.
#[test]
#[ignore = "requires docker"]
fn rebase_re_signs_each_rewritten_commit() {
    if skip_if_no_docker("rebase_re_signs_each_rewritten_commit") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "rebase-repo", &enclave);

    // Initial commit on main.
    make_commit(&env, &repo, "main.txt", "main\n", "main");

    // Branch with two commits to rebase.
    assert!(env
        .git_cmd()
        .current_dir(&repo)
        .args(["checkout", "-q", "-b", "feature"])
        .status()
        .expect("checkout")
        .success());
    make_commit(&env, &repo, "f1.txt", "feat-1\n", "feat-1");
    make_commit(&env, &repo, "f2.txt", "feat-2\n", "feat-2");

    // Move main forward so rebase has work to do.
    assert!(env
        .git_cmd()
        .current_dir(&repo)
        .args(["checkout", "-q", "main"])
        .status()
        .expect("checkout main")
        .success());
    make_commit(&env, &repo, "main2.txt", "main-2\n", "main-2");

    // Rebase feature onto main.
    assert!(env
        .git_cmd()
        .current_dir(&repo)
        .args(["checkout", "-q", "feature"])
        .status()
        .expect("checkout feature")
        .success());
    let rebase =
        run(env.git_cmd().current_dir(&repo).args(["rebase", "main"])).expect("git rebase");
    assert!(rebase.succeeded(), "git rebase: {}", rebase.stderr);

    // Verify HEAD and HEAD~1 — the two rewritten commits.
    for rev in ["HEAD", "HEAD~1"] {
        let verify = run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["verify-commit", rev]))
        .expect("verify-commit");
        assert!(
            verify.succeeded(),
            "verify-commit on rebased {rev} failed; stderr:\n{}",
            verify.stderr
        );
    }
}

/// `git log --graph`, `git describe`, and `git reflog` work
/// cleanly against a chain of sshenc-signed commits. Smoke test
/// to catch any regression where signature metadata in commit
/// headers breaks history walking.
#[test]
#[ignore = "requires docker"]
fn history_queries_work_on_signed_chain() {
    if skip_if_no_docker("history_queries_work_on_signed_chain") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "history-repo", &enclave);

    for i in 0..3 {
        make_commit(
            &env,
            &repo,
            &format!("f{i}.txt"),
            &format!("content-{i}\n"),
            &format!("commit-{i}"),
        );
    }
    // Tag the second commit so `git describe` has something to find.
    assert!(env
        .git_cmd()
        .current_dir(&repo)
        .args(["tag", "v0.1", "HEAD~1"])
        .status()
        .expect("git tag")
        .success());

    let log_graph = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["log", "--graph", "--oneline"]))
    .expect("git log --graph");
    assert!(
        log_graph.succeeded(),
        "git log --graph: {}",
        log_graph.stderr
    );
    assert!(
        log_graph.stdout.lines().count() >= 3,
        "expected at least 3 commits in graph; got:\n{}",
        log_graph.stdout
    );

    let describe = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["describe", "--tags", "HEAD"]))
    .expect("git describe");
    assert!(describe.succeeded(), "git describe: {}", describe.stderr);
    assert!(
        describe.stdout.starts_with("v0.1"),
        "describe output should start with v0.1; got:\n{}",
        describe.stdout
    );

    let reflog = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["reflog", "show", "HEAD"]))
    .expect("git reflog");
    assert!(reflog.succeeded(), "git reflog: {}", reflog.stderr);
    assert!(
        reflog.stdout.lines().count() >= 3,
        "expected at least 3 reflog entries; got:\n{}",
        reflog.stdout
    );
}
