// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `git filter-branch` rewrites every commit in a range. Git
//! uses `commit-tree` internally for the rewrites, which does
//! NOT honor `commit.gpgsign` — so the rewritten commits are
//! unsigned. The contract pinned here:
//!
//! - filter-branch completes successfully without breaking the
//!   gitenc-configured repo state.
//! - The original signed commits remain reachable via
//!   `refs/original/refs/heads/<branch>` (filter-branch's
//!   automatic backup ref) and still verify.
//! - A new commit on top of the filtered HEAD signs and
//!   verifies — the agent and signing config aren't disturbed.

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
        "filter-branch signer",
        "filter@e2e.test",
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

/// `git filter-branch` completes cleanly; the original signed
/// commits remain reachable via the auto-backup ref and still
/// verify; a fresh commit on top of the filtered branch signs
/// and verifies.
#[test]
#[ignore = "requires docker"]
fn filter_branch_completes_and_subsequent_commit_signs() {
    if skip_if_no_docker("filter_branch_completes_and_subsequent_commit_signs") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "filter-branch-repo", &enclave);

    // Three signed commits to filter.
    for i in 0..3 {
        make_commit(
            &env,
            &repo,
            &format!("f{i}.txt"),
            &format!("v{i}\n"),
            &format!("c{i}"),
        );
    }

    // FILTER_BRANCH_SQUELCH_WARNING silences git's deprecation
    // notice so it doesn't fail under `set -e`-style harnesses.
    let filter = run(env
        .git_cmd()
        .env("FILTER_BRANCH_SQUELCH_WARNING", "1")
        .current_dir(&repo)
        .args([
            "filter-branch",
            "-f",
            "--msg-filter",
            "sed 's/^/[filtered] /'",
            "HEAD",
        ]))
    .expect("git filter-branch");
    assert!(
        filter.succeeded(),
        "git filter-branch failed; stdout:\n{}\nstderr:\n{}",
        filter.stdout,
        filter.stderr
    );

    // The rewritten HEAD's subject has the marker.
    let subject = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["log", "-1", "--format=%s"]))
    .expect("log subject");
    assert!(subject.succeeded(), "git log: {}", subject.stderr);
    assert!(
        subject.stdout.starts_with("[filtered]"),
        "filter-branch should have rewritten the subject; got:\n{}",
        subject.stdout
    );

    // The auto-backup ref preserves the original signed commits.
    let original_head = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "refs/original/refs/heads/main"]))
    .expect("verify-commit refs/original");
    assert!(
        original_head.succeeded(),
        "verify-commit on the pre-filter backup ref failed; stderr:\n{}",
        original_head.stderr
    );

    // A fresh commit on top of the filtered HEAD signs cleanly —
    // the agent and signing config weren't disturbed.
    make_commit(&env, &repo, "after.txt", "after-filter\n", "after");
    let verify_after = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(
        verify_after.succeeded(),
        "verify-commit on post-filter commit failed; stderr:\n{}",
        verify_after.stderr
    );
}
