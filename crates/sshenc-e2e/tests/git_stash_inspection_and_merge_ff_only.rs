// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Read-only git ops on a gitenc-configured repo:
//!
//! - `git stash list` and `git stash show` work cleanly when
//!   the repo has signing enabled and there's a stashed state.
//! - `git merge --ff-only <branch>` (direct, not via `git pull`)
//!   fast-forwards on a signed history without producing a new
//!   commit; HEAD's signature still verifies.

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
        "stash-merge signer",
        "stashmerge@e2e.test",
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

/// `git stash list` and `git stash show` work cleanly on a
/// gitenc-configured repo with a stashed state.
#[test]
#[ignore = "requires docker"]
fn stash_list_and_show_work_on_signed_repo() {
    if skip_if_no_docker("stash_list_and_show_work_on_signed_repo") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "stash-inspect-repo", &enclave);

    make_commit(&env, &repo, "a.txt", "first\n", "first");

    // Stash a wip change.
    std::fs::write(repo.join("a.txt"), b"wip-content\n").expect("modify");
    let stash =
        run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["stash", "push", "-m", "inspection-wip"]))
        .expect("git stash push");
    assert!(stash.succeeded(), "git stash push: {}", stash.stderr);

    let list =
        run(env.git_cmd().current_dir(&repo).args(["stash", "list"])).expect("git stash list");
    assert!(list.succeeded(), "git stash list: {}", list.stderr);
    assert!(
        list.stdout.contains("inspection-wip"),
        "expected stash entry; got:\n{}",
        list.stdout
    );

    let show = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["stash", "show", "stash@{0}"]))
    .expect("git stash show");
    assert!(show.succeeded(), "git stash show: {}", show.stderr);
    assert!(
        show.stdout.contains("a.txt"),
        "expected file in stash diff; got:\n{}",
        show.stdout
    );
}

/// `git merge --ff-only <branch>` fast-forwards on a signed
/// history; no new commit is produced, HEAD moves to the tip
/// of the named branch, and verify-commit still works.
#[test]
#[ignore = "requires docker"]
fn merge_ff_only_advances_head_on_signed_history() {
    if skip_if_no_docker("merge_ff_only_advances_head_on_signed_history") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "merge-ff-repo", &enclave);

    make_commit(&env, &repo, "main.txt", "main\n", "main");
    let main_sha_before = run(env.git_cmd().current_dir(&repo).args(["rev-parse", "HEAD"]))
        .expect("rev-parse main")
        .stdout
        .trim()
        .to_string();

    // Linear feature branch (one commit ahead) — ff-only is valid.
    assert!(env
        .git_cmd()
        .current_dir(&repo)
        .args(["checkout", "-q", "-b", "feature"])
        .status()
        .expect("checkout -b feature")
        .success());
    make_commit(&env, &repo, "feat.txt", "feat\n", "feat");
    let feature_sha = run(env.git_cmd().current_dir(&repo).args(["rev-parse", "HEAD"]))
        .expect("rev-parse feature")
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

    let merge = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["merge", "--ff-only", "feature"]))
    .expect("git merge --ff-only");
    assert!(merge.succeeded(), "git merge --ff-only: {}", merge.stderr);

    // HEAD advanced to feature's commit (no merge commit).
    let main_sha_after = run(env.git_cmd().current_dir(&repo).args(["rev-parse", "HEAD"]))
        .expect("rev-parse main after")
        .stdout
        .trim()
        .to_string();
    assert_ne!(
        main_sha_after, main_sha_before,
        "HEAD should have moved after ff-only merge"
    );
    assert_eq!(
        main_sha_after, feature_sha,
        "ff-only should advance to feature's tip; HEAD={main_sha_after}, feature={feature_sha}"
    );

    // HEAD's commit is the original signed feature commit; verifies.
    let verify = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(
        verify.succeeded(),
        "verify-commit on ff-only HEAD failed; stderr:\n{}",
        verify.stderr
    );
}
