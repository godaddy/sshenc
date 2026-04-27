// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Committing on a detached HEAD (`git checkout <commit-sha>`)
//! produces a signed commit. HEAD isn't pointing at a branch
//! ref; the signing path must not require a branch context.

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
        "detached signer",
        "detached@e2e.test",
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

/// `git checkout <commit-sha>` lands on a detached HEAD; a
/// commit there signs and verifies.
#[test]
#[ignore = "requires docker"]
fn commit_on_detached_head_is_signed() {
    if skip_if_no_docker("commit_on_detached_head_is_signed") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "detached-head-repo", &enclave);

    make_commit(&env, &repo, "a.txt", "first\n", "first");
    make_commit(&env, &repo, "b.txt", "second\n", "second");

    let first_sha = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["rev-parse", "HEAD~1"]))
    .expect("rev-parse")
    .stdout
    .trim()
    .to_string();

    // Detach HEAD onto first_sha.
    let detach = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["checkout", "-q", "--detach", &first_sha]))
    .expect("git checkout --detach");
    assert!(
        detach.succeeded(),
        "git checkout --detach: {}",
        detach.stderr
    );

    // Confirm HEAD is detached (symbolic-ref --short fails on a
    // detached HEAD).
    let symref = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["symbolic-ref", "--short", "HEAD"]))
    .expect("symbolic-ref --short");
    assert!(
        !symref.succeeded(),
        "HEAD should be detached (symbolic-ref should fail); stdout:\n{}",
        symref.stdout
    );

    // Commit on the detached HEAD.
    make_commit(&env, &repo, "detached.txt", "detached\n", "on detached");

    let verify = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(
        verify.succeeded(),
        "verify-commit on detached HEAD commit failed; stderr:\n{}",
        verify.stderr
    );
}
