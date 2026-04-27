// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Three contracts at the gitenc / git-signing boundary that
//! aren't covered by the existing commit/rebase/cherry-pick
//! tests:
//!
//! - `git commit --signoff` on a gitenc-configured repo produces
//!   a commit that both verifies (sshenc signing) AND has a
//!   `Signed-off-by:` trailer in the message body. Both
//!   features must work together — the signoff path mustn't
//!   suppress signing, and signing mustn't strip the trailer.
//! - `git reset --hard <signed-commit>` moves HEAD to a
//!   previously-signed commit. The signature must remain
//!   verifiable after the reset (no corruption of the existing
//!   commit object).
//! - `gitenc --label <key> <local-only-git-op>` (e.g., `status`,
//!   `log`) succeeds without invoking SSH and without rejecting
//!   the label, even though the underlying git command never
//!   uses the agent. gitenc's job is to set GIT_SSH_COMMAND for
//!   eventual remote ops; local ops shouldn't error out.

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
        "boundary signer",
        "boundary@e2e.test",
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

/// `git commit --signoff` on a gitenc-configured repo produces
/// a commit that verifies AND has a `Signed-off-by:` trailer.
#[test]
#[ignore = "requires docker"]
fn commit_signoff_produces_signed_commit_with_trailer() {
    if skip_if_no_docker("commit_signoff_produces_signed_commit_with_trailer") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "signoff-repo", &enclave);

    std::fs::write(repo.join("a.txt"), b"signoff content\n").expect("write");
    let add = run(env.git_cmd().current_dir(&repo).args(["add", "a.txt"])).expect("git add");
    assert!(add.succeeded(), "git add: {}", add.stderr);

    let commit = run(env.git_cmd().current_dir(&repo).args([
        "commit",
        "-q",
        "--signoff",
        "-m",
        "with signoff",
    ]))
    .expect("git commit --signoff");
    assert!(commit.succeeded(), "commit --signoff: {}", commit.stderr);

    // Verify the signature.
    let verify = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(
        verify.succeeded(),
        "verify-commit on --signoff HEAD failed; stderr:\n{}",
        verify.stderr
    );

    // The commit message body must contain `Signed-off-by:`.
    let body = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["log", "-1", "--format=%B"]))
    .expect("git log -1 --format=%B");
    assert!(body.succeeded(), "git log: {}", body.stderr);
    assert!(
        body.stdout.contains("Signed-off-by:"),
        "expected Signed-off-by: trailer in commit body; got:\n{}",
        body.stdout
    );
}

/// `git reset --hard <signed-commit>` moves HEAD without
/// corrupting the existing signature on the target commit.
#[test]
#[ignore = "requires docker"]
fn reset_hard_to_signed_commit_preserves_signature() {
    if skip_if_no_docker("reset_hard_to_signed_commit_preserves_signature") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "reset-hard-repo", &enclave);

    make_commit(&env, &repo, "a.txt", "first\n", "first");
    let first_sha = rev_parse(&env, &repo, "HEAD");

    make_commit(&env, &repo, "b.txt", "second\n", "second");
    let second_sha = rev_parse(&env, &repo, "HEAD");
    assert_ne!(first_sha, second_sha, "second commit should differ");

    // Reset HEAD back to the first signed commit.
    let reset = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["reset", "--hard", &first_sha]))
    .expect("git reset --hard");
    assert!(reset.succeeded(), "reset --hard: {}", reset.stderr);

    let after = rev_parse(&env, &repo, "HEAD");
    assert_eq!(after, first_sha, "HEAD didn't move to first_sha");

    let verify = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(
        verify.succeeded(),
        "verify-commit on reset HEAD failed; stderr:\n{}",
        verify.stderr
    );
}

/// `gitenc --label <key> <local-git-op>` succeeds for git
/// commands that don't invoke SSH (status, log, diff). The
/// label is a hint for SSH operations only; passing it with
/// purely-local commands must not error.
#[test]
#[ignore = "requires docker"]
fn gitenc_label_passes_through_for_local_only_git_ops() {
    if skip_if_no_docker("gitenc_label_passes_through_for_local_only_git_ops") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "local-ops-repo", &enclave);

    make_commit(&env, &repo, "a.txt", "first\n", "first");
    make_commit(&env, &repo, "b.txt", "second\n", "second");

    // `gitenc --label SHARED status` — no SSH, must succeed.
    let status = run(env
        .gitenc_cmd()
        .expect("gitenc cmd")
        .current_dir(&repo)
        .args(["--label", SHARED_ENCLAVE_LABEL, "status", "--short"]))
    .expect("gitenc status");
    assert!(
        status.succeeded(),
        "gitenc --label X status failed; stderr:\n{}",
        status.stderr
    );

    // `gitenc --label SHARED log --oneline` — no SSH, must succeed and list both commits.
    let log = run(env
        .gitenc_cmd()
        .expect("gitenc cmd")
        .current_dir(&repo)
        .args(["--label", SHARED_ENCLAVE_LABEL, "log", "--oneline"]))
    .expect("gitenc log");
    assert!(
        log.succeeded(),
        "gitenc --label X log failed; stderr:\n{}",
        log.stderr
    );
    assert!(
        log.stdout.lines().count() >= 2,
        "expected at least 2 log entries; got:\n{}",
        log.stdout
    );
}
