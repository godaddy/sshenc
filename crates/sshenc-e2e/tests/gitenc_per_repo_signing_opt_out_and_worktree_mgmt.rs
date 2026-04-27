// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Two contracts:
//!
//! - Setting `commit.gpgsign=false` in the per-repo config
//!   after `gitenc --config` is an explicit per-repo opt-out;
//!   subsequent commits are unsigned. Distinct from
//!   `gitenc_unborn_head_and_removed_signing_config.rs`, which
//!   tests `--unset` (removing the key entirely): here we set
//!   it to the literal string `false`.
//! - `git worktree list/remove` work cleanly on a
//!   gitenc-configured repo. `gitenc_advanced_ops.rs` covers
//!   `worktree add` + signing in the worktree; this pins the
//!   read/destruction half of worktree management.

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
        "opt-out signer",
        "optout@e2e.test",
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

/// `git config --local commit.gpgsign false` after gitenc
/// --config produces unsigned commits; resetting to true
/// re-enables signing.
#[test]
#[ignore = "requires docker"]
fn explicit_commit_gpgsign_false_disables_signing_per_repo() {
    if skip_if_no_docker("explicit_commit_gpgsign_false_disables_signing_per_repo") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "opt-out-repo", &enclave);

    // Baseline: a commit signs.
    make_commit(&env, &repo, "a.txt", "first\n", "first");
    let v1 = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(v1.succeeded(), "first commit didn't verify: {}", v1.stderr);

    // Per-repo opt-out.
    let off = run(env.git_cmd().current_dir(&repo).args([
        "config",
        "--local",
        "commit.gpgsign",
        "false",
    ]))
    .expect("git config --local commit.gpgsign false");
    assert!(off.succeeded(), "git config: {}", off.stderr);

    // Subsequent commit must be unsigned.
    make_commit(&env, &repo, "b.txt", "off\n", "off");
    let v2 = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit off");
    assert!(
        !v2.succeeded(),
        "verify-commit should fail on unsigned commit; stdout:\n{}\nstderr:\n{}",
        v2.stdout,
        v2.stderr
    );

    // Re-enable: subsequent commit signs again.
    let on =
        run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["config", "--local", "commit.gpgsign", "true"]))
        .expect("git config --local commit.gpgsign true");
    assert!(on.succeeded(), "git config: {}", on.stderr);
    make_commit(&env, &repo, "c.txt", "on\n", "on again");
    let v3 = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit on");
    assert!(
        v3.succeeded(),
        "verify-commit failed after re-enabling; stderr:\n{}",
        v3.stderr
    );
}

/// `git worktree list` and `git worktree remove` work cleanly
/// on a gitenc-configured repo.
#[test]
#[ignore = "requires docker"]
fn git_worktree_list_and_remove_work() {
    if skip_if_no_docker("git_worktree_list_and_remove_work") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "worktree-mgmt-repo", &enclave);

    make_commit(&env, &repo, "main.txt", "main\n", "main");

    // Add a worktree at sibling path.
    let wt_path = env.home().join("worktree-mgmt-secondary");
    let add = run(env.git_cmd().current_dir(&repo).args([
        "worktree",
        "add",
        wt_path.to_str().expect("utf-8"),
        "-b",
        "secondary",
    ]))
    .expect("git worktree add");
    assert!(add.succeeded(), "git worktree add: {}", add.stderr);

    // `worktree list` shows both the primary and the secondary.
    let listed = run(env.git_cmd().current_dir(&repo).args(["worktree", "list"]))
        .expect("git worktree list");
    assert!(listed.succeeded(), "git worktree list: {}", listed.stderr);
    assert!(
        listed.stdout.contains(repo.to_str().expect("utf-8"))
            && listed.stdout.contains(wt_path.to_str().expect("utf-8")),
        "expected both worktrees in list; got:\n{}",
        listed.stdout
    );
    assert!(
        listed.stdout.contains("secondary"),
        "expected 'secondary' branch label in worktree list; got:\n{}",
        listed.stdout
    );

    // Remove the secondary worktree.
    let remove = run(env.git_cmd().current_dir(&repo).args([
        "worktree",
        "remove",
        wt_path.to_str().expect("utf-8"),
    ]))
    .expect("git worktree remove");
    assert!(remove.succeeded(), "git worktree remove: {}", remove.stderr);

    // After removal, list shows only the primary; the secondary
    // path is gone from disk.
    let listed_after = run(env.git_cmd().current_dir(&repo).args(["worktree", "list"]))
        .expect("git worktree list after");
    assert!(
        listed_after.succeeded(),
        "git worktree list after: {}",
        listed_after.stderr
    );
    assert!(
        !listed_after
            .stdout
            .contains(wt_path.to_str().expect("utf-8")),
        "secondary worktree should be gone from list; got:\n{}",
        listed_after.stdout
    );
    assert!(
        !wt_path.exists(),
        "worktree directory should be gone from disk: {}",
        wt_path.display()
    );
}
