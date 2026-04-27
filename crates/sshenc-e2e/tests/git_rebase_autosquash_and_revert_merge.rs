// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Two rebase/revert variants on a gitenc-configured repo:
//!
//! - `git rebase --autosquash` collapses `fixup!`-prefixed
//!   commits into their target; the resulting squashed commit
//!   is signed.
//! - `git revert -m <N> <merge-sha>` reverts a merge commit
//!   selecting parent N as mainline; the resulting revert
//!   commit is signed.

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
        "rebase-revert signer",
        "rebaserevert@e2e.test",
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

/// `git rebase --autosquash` collapses `fixup!` commits and
/// the resulting squashed commit is signed.
#[test]
#[ignore = "requires docker"]
fn rebase_autosquash_signs_squashed_commit() {
    if skip_if_no_docker("rebase_autosquash_signs_squashed_commit") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "autosquash-repo", &enclave);

    make_commit(&env, &repo, "base.txt", "base\n", "base");
    make_commit(&env, &repo, "a.txt", "first edition\n", "feat: a");
    let target = rev_parse(&env, &repo, "HEAD");

    // Stage a fix and create a fixup! commit targeting the previous one.
    std::fs::write(repo.join("a.txt"), b"fixed edition\n").expect("write");
    drop(run(env.git_cmd().current_dir(&repo).args(["add", "a.txt"])));
    let fixup = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["commit", "-q", "--fixup", &target]))
    .expect("commit --fixup");
    assert!(fixup.succeeded(), "commit --fixup: {}", fixup.stderr);

    // Non-interactive autosquash: GIT_SEQUENCE_EDITOR=true accepts
    // the rebase plan unchanged (fixup commands collapse). The
    // upstream is HEAD~2 (covering "feat: a" and the fixup commit).
    let rebase = run(env
        .git_cmd()
        .env("GIT_SEQUENCE_EDITOR", "true")
        .current_dir(&repo)
        .args(["rebase", "-i", "--autosquash", "HEAD~2"]))
    .expect("git rebase -i --autosquash");
    assert!(
        rebase.succeeded(),
        "rebase --autosquash failed; stdout:\n{}\nstderr:\n{}",
        rebase.stdout,
        rebase.stderr
    );

    // The fixup commit should be gone (subject "fixup! …" should
    // not appear in the log) and HEAD's content reflects the fix.
    let log = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["log", "--format=%s"]))
    .expect("git log");
    assert!(log.succeeded(), "git log: {}", log.stderr);
    assert!(
        !log.stdout.contains("fixup!"),
        "fixup! subject should be squashed away; got:\n{}",
        log.stdout
    );
    let body = std::fs::read_to_string(repo.join("a.txt")).expect("read");
    assert_eq!(body, "fixed edition\n", "fixup contents should land");

    let verify = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(
        verify.succeeded(),
        "verify-commit on autosquashed HEAD failed; stderr:\n{}",
        verify.stderr
    );
}

/// `git revert -m 1 <merge-sha>` reverts a merge commit; the
/// resulting revert commit is signed and verifies.
#[test]
#[ignore = "requires docker"]
fn revert_dash_m_on_merge_commit_is_signed() {
    if skip_if_no_docker("revert_dash_m_on_merge_commit_is_signed") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "revert-merge-repo", &enclave);

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

    let merge = run(env.git_cmd().current_dir(&repo).args([
        "merge",
        "--no-ff",
        "--no-edit",
        "-m",
        "merge feature",
        "feature",
    ]))
    .expect("git merge");
    assert!(merge.succeeded(), "git merge: {}", merge.stderr);
    let merge_sha = rev_parse(&env, &repo, "HEAD");

    // Revert the merge with -m 1 (mainline = first parent).
    let revert =
        run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["revert", "--no-edit", "-m", "1", &merge_sha]))
        .expect("git revert -m 1");
    assert!(
        revert.succeeded(),
        "git revert -m 1 failed; stderr:\n{}",
        revert.stderr
    );

    let verify = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(
        verify.succeeded(),
        "verify-commit on merge-revert HEAD failed; stderr:\n{}",
        verify.stderr
    );
}
