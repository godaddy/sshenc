// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Three local-only git operations on a gitenc-configured repo:
//!
//! - `git switch -` (the reflog "previous branch" shorthand)
//!   moves HEAD back to the prior branch without disturbing the
//!   signing config.
//! - `git branch --move <old> <new>` renames a branch; refs and
//!   reflog stay consistent and a fresh signed commit on the
//!   renamed branch verifies.
//! - `git diff --raw HEAD~1..HEAD` produces the colon-prefixed
//!   raw diff output (mode + sha + status + path) on a chain of
//!   sshenc-signed commits.

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
        "branch-nav signer",
        "branchnav@e2e.test",
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

/// `git switch -` moves HEAD to the previously checked-out branch.
#[test]
#[ignore = "requires docker"]
fn git_switch_dash_returns_to_previous_branch() {
    if skip_if_no_docker("git_switch_dash_returns_to_previous_branch") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "switch-dash-repo", &enclave);

    make_commit(&env, &repo, "main.txt", "main\n", "main");
    assert!(env
        .git_cmd()
        .current_dir(&repo)
        .args(["switch", "-c", "feature"])
        .status()
        .expect("switch -c feature")
        .success());

    // Switch back to main.
    assert!(env
        .git_cmd()
        .current_dir(&repo)
        .args(["switch", "main"])
        .status()
        .expect("switch main")
        .success());

    // Now `git switch -` should return to feature.
    let dash = run(env.git_cmd().current_dir(&repo).args(["switch", "-"])).expect("git switch -");
    assert!(dash.succeeded(), "git switch -: {}", dash.stderr);

    let head = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["symbolic-ref", "--short", "HEAD"]))
    .expect("symbolic-ref --short");
    assert!(head.succeeded(), "symbolic-ref: {}", head.stderr);
    assert_eq!(
        head.stdout.trim(),
        "feature",
        "expected HEAD on feature; got:\n{}",
        head.stdout
    );
}

/// `git branch --move <old> <new>` renames a branch; subsequent
/// signed commits on the renamed branch verify.
#[test]
#[ignore = "requires docker"]
fn git_branch_move_renames_and_signing_continues() {
    if skip_if_no_docker("git_branch_move_renames_and_signing_continues") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "branch-move-repo", &enclave);

    make_commit(&env, &repo, "main.txt", "main\n", "main");
    assert!(env
        .git_cmd()
        .current_dir(&repo)
        .args(["switch", "-c", "old-name"])
        .status()
        .expect("switch -c old-name")
        .success());
    make_commit(&env, &repo, "f.txt", "feat\n", "feat");

    let mv = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["branch", "--move", "old-name", "new-name"]))
    .expect("git branch --move");
    assert!(mv.succeeded(), "git branch --move: {}", mv.stderr);

    // refs/heads/new-name resolves; refs/heads/old-name is gone.
    let new_ref = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["for-each-ref", "refs/heads/new-name"]))
    .expect("for-each-ref new-name");
    assert!(
        !new_ref.stdout.trim().is_empty(),
        "new-name ref should exist; got:\n{}",
        new_ref.stdout
    );
    let old_ref = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["for-each-ref", "refs/heads/old-name"]))
    .expect("for-each-ref old-name");
    assert!(
        old_ref.stdout.trim().is_empty(),
        "old-name ref should be gone; got:\n{}",
        old_ref.stdout
    );

    // Signing on the renamed branch still works.
    make_commit(&env, &repo, "f2.txt", "after rename\n", "post-rename");
    let verify = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(
        verify.succeeded(),
        "verify-commit after branch --move failed; stderr:\n{}",
        verify.stderr
    );
}

/// `git diff --raw HEAD~1..HEAD` produces colon-prefixed raw
/// diff output on a chain of sshenc-signed commits.
#[test]
#[ignore = "requires docker"]
fn git_diff_raw_works_on_signed_chain() {
    if skip_if_no_docker("git_diff_raw_works_on_signed_chain") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "diff-raw-repo", &enclave);

    make_commit(&env, &repo, "a.txt", "first\n", "first");
    make_commit(&env, &repo, "b.txt", "added\n", "second adds b");

    let raw = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["diff", "--raw", "HEAD~1..HEAD"]))
    .expect("git diff --raw");
    assert!(raw.succeeded(), "git diff --raw: {}", raw.stderr);

    // Raw format: `:<old_mode> <new_mode> <old_sha> <new_sha> <status>\t<path>`
    // For the second commit (which adds b.txt), there's an "A" status entry.
    assert!(
        raw.stdout.starts_with(':'),
        "diff --raw output should start with ':'; got:\n{}",
        raw.stdout
    );
    assert!(
        raw.stdout.contains("\tb.txt"),
        "expected b.txt path in raw diff; got:\n{}",
        raw.stdout
    );
    // The "A" (added) status should appear in the line for b.txt.
    assert!(
        raw.stdout.contains(" A\t"),
        "expected 'A' (added) status entry; got:\n{}",
        raw.stdout
    );
}
