// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Index-mutating git plumbing (`git mv`, `git rm`) followed by
//! a commit produces a signed, verifiable commit. The signing
//! path doesn't depend on whether the staged change came from a
//! bare `git add` or from a higher-level index command.

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
        "index signer",
        "index@e2e.test",
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

/// `git mv old new` followed by `git commit` produces a signed,
/// verifiable commit. The rename status flag in git's internal
/// commit serialization mustn't disturb the signing path.
#[test]
#[ignore = "requires docker"]
fn git_mv_followed_by_commit_is_signed() {
    if skip_if_no_docker("git_mv_followed_by_commit_is_signed") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "mv-repo", &enclave);

    make_commit(&env, &repo, "old.txt", "rename me\n", "initial");

    let mv = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["mv", "old.txt", "new.txt"]))
    .expect("git mv");
    assert!(mv.succeeded(), "git mv: {}", mv.stderr);

    let commit = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["commit", "-q", "-m", "rename"]))
    .expect("commit after mv");
    assert!(commit.succeeded(), "commit after mv: {}", commit.stderr);

    let verify = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(
        verify.succeeded(),
        "verify-commit on `git mv` HEAD failed; stderr:\n{}",
        verify.stderr
    );

    // Confirm the rename actually landed.
    assert!(
        repo.join("new.txt").exists(),
        "new.txt should exist after mv"
    );
    assert!(
        !repo.join("old.txt").exists(),
        "old.txt should be gone after mv"
    );
}

/// `git rm <tracked>` followed by `git commit` produces a
/// signed, verifiable commit recording the deletion.
#[test]
#[ignore = "requires docker"]
fn git_rm_followed_by_commit_is_signed() {
    if skip_if_no_docker("git_rm_followed_by_commit_is_signed") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "rm-repo", &enclave);

    make_commit(&env, &repo, "doomed.txt", "byebye\n", "initial");

    let rm = run(env.git_cmd().current_dir(&repo).args(["rm", "doomed.txt"])).expect("git rm");
    assert!(rm.succeeded(), "git rm: {}", rm.stderr);

    let commit =
        run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["commit", "-q", "-m", "remove doomed.txt"]))
        .expect("commit after rm");
    assert!(commit.succeeded(), "commit after rm: {}", commit.stderr);

    let verify = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(
        verify.succeeded(),
        "verify-commit on `git rm` HEAD failed; stderr:\n{}",
        verify.stderr
    );

    assert!(
        !repo.join("doomed.txt").exists(),
        "doomed.txt should be gone after rm + commit"
    );
}
