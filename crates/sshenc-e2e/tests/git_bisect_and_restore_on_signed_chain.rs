// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Local git history-traversal commands on a chain of
//! sshenc-signed commits:
//!
//! - `git bisect start` + good/bad marking traverses signed
//!   commits cleanly. Bisect doesn't create commits, but it
//!   walks the signed DAG; signature metadata in commit headers
//!   mustn't break the traversal or hang verification.
//! - `git restore --staged <path>` and
//!   `git restore --source=<commit> <path>` work cleanly on a
//!   gitenc-configured repo. Restore is local-only (no signing
//!   happens) but mustn't error out just because
//!   `commit.gpgsign=true` is set.

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
        "history walker",
        "walker@e2e.test",
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

/// `git bisect start` over a chain of sshenc-signed commits
/// walks the DAG cleanly.
#[test]
#[ignore = "requires docker"]
fn git_bisect_traverses_signed_chain_cleanly() {
    if skip_if_no_docker("git_bisect_traverses_signed_chain_cleanly") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "bisect-repo", &enclave);

    // Five signed commits: c0 .. c4.
    for i in 0..5 {
        make_commit(
            &env,
            &repo,
            &format!("f{i}.txt"),
            &format!("v{i}\n"),
            &format!("c{i}"),
        );
    }
    let good = rev_parse(&env, &repo, "HEAD~4");
    let bad = rev_parse(&env, &repo, "HEAD");

    let start = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["bisect", "start", &bad, &good]))
    .expect("git bisect start");
    assert!(start.succeeded(), "bisect start: {}", start.stderr);

    // After `start <bad> <good>`, git checks out a midpoint commit.
    // We just need to confirm bisect is in a consistent state and
    // we can read the next commit it picked.
    let head_after_start = rev_parse(&env, &repo, "HEAD");
    assert_ne!(
        head_after_start, bad,
        "bisect should have moved HEAD off bad"
    );
    assert_ne!(
        head_after_start, good,
        "bisect should have moved HEAD off good"
    );

    // The midpoint commit must verify (it's part of the signed chain).
    let verify = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(
        verify.succeeded(),
        "verify-commit on bisect midpoint failed; stderr:\n{}",
        verify.stderr
    );

    // Mark current as good and let bisect narrow further.
    let mark_good =
        run(env.git_cmd().current_dir(&repo).args(["bisect", "good"])).expect("git bisect good");
    assert!(mark_good.succeeded(), "bisect good: {}", mark_good.stderr);

    // Reset bisect state.
    let reset =
        run(env.git_cmd().current_dir(&repo).args(["bisect", "reset"])).expect("git bisect reset");
    assert!(reset.succeeded(), "bisect reset: {}", reset.stderr);
}

/// `git restore --staged <path>` and
/// `git restore --source=<commit> <path>` work cleanly on a
/// gitenc-configured repo.
#[test]
#[ignore = "requires docker"]
fn git_restore_staged_and_source_work_in_signed_repo() {
    if skip_if_no_docker("git_restore_staged_and_source_work_in_signed_repo") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "restore-repo", &enclave);

    make_commit(&env, &repo, "a.txt", "v1\n", "first");
    make_commit(&env, &repo, "a.txt", "v2\n", "second");

    // Stage a third version, then unstage with `restore --staged`.
    std::fs::write(repo.join("a.txt"), b"v3-staged\n").expect("write v3");
    let add = run(env.git_cmd().current_dir(&repo).args(["add", "a.txt"])).expect("git add");
    assert!(add.succeeded(), "git add: {}", add.stderr);

    let restore_staged = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["restore", "--staged", "a.txt"]))
    .expect("git restore --staged");
    assert!(
        restore_staged.succeeded(),
        "git restore --staged: {}",
        restore_staged.stderr
    );

    // The worktree still has v3-staged content (unstaged but not reverted).
    let body = std::fs::read_to_string(repo.join("a.txt")).expect("read");
    assert_eq!(
        body, "v3-staged\n",
        "worktree shouldn't be changed by --staged"
    );

    // Now restore from a previous commit's version of a.txt.
    let restore_source =
        run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["restore", "--source=HEAD~1", "a.txt"]))
        .expect("git restore --source");
    assert!(
        restore_source.succeeded(),
        "git restore --source=HEAD~1: {}",
        restore_source.stderr
    );

    let body_after = std::fs::read_to_string(repo.join("a.txt")).expect("read after");
    assert_eq!(
        body_after, "v1\n",
        "restore --source=HEAD~1 should bring back v1 content"
    );
}
