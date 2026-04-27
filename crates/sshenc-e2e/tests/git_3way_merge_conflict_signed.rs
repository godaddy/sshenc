// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! A `git merge` that conflicts and is then resolved manually
//! produces a signed merge commit. Distinct from the
//! conflict-free `merge --no-ff` case in
//! `git_history_ops_and_validation_corners.rs`: here the user
//! edits the conflict markers, stages the resolution, then
//! commits.

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
        "merge-conflict signer",
        "mc@e2e.test",
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

/// 3-way merge with manual conflict resolution produces a signed
/// merge commit that verifies.
#[test]
#[ignore = "requires docker"]
fn merge_with_manual_conflict_resolution_is_signed() {
    if skip_if_no_docker("merge_with_manual_conflict_resolution_is_signed") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "merge-conflict-repo", &enclave);

    // Initial commit on main.
    make_commit(&env, &repo, "shared.txt", "base\n", "base");

    // Feature branch edits shared.txt one way.
    assert!(env
        .git_cmd()
        .current_dir(&repo)
        .args(["checkout", "-q", "-b", "feature"])
        .status()
        .expect("checkout -b feature")
        .success());
    std::fs::write(repo.join("shared.txt"), b"feature edit\n").expect("write");
    drop(run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["add", "shared.txt"])));
    let commit_feat =
        run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["commit", "-q", "-m", "feat edit"]))
        .expect("commit feat");
    assert!(
        commit_feat.succeeded(),
        "commit feat: {}",
        commit_feat.stderr
    );

    // Main edits shared.txt differently → conflict on merge.
    assert!(env
        .git_cmd()
        .current_dir(&repo)
        .args(["checkout", "-q", "main"])
        .status()
        .expect("checkout main")
        .success());
    std::fs::write(repo.join("shared.txt"), b"main edit\n").expect("write");
    drop(run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["add", "shared.txt"])));
    let commit_main =
        run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["commit", "-q", "-m", "main edit"]))
        .expect("commit main");
    assert!(
        commit_main.succeeded(),
        "commit main: {}",
        commit_main.stderr
    );

    // Merge feature into main — must conflict.
    let merge =
        run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["merge", "--no-ff", "--no-commit", "feature"]))
        .expect("git merge (expected conflict)");
    assert!(
        !merge.succeeded(),
        "merge should conflict; stdout:\n{}\nstderr:\n{}",
        merge.stdout,
        merge.stderr
    );

    // Resolve the conflict manually.
    std::fs::write(repo.join("shared.txt"), b"resolved content\n").expect("resolve");
    let add = run(env.git_cmd().current_dir(&repo).args(["add", "shared.txt"])).expect("git add");
    assert!(add.succeeded(), "git add: {}", add.stderr);

    // Complete the merge with a commit; signing fires.
    let commit_merge = run(env.git_cmd().current_dir(&repo).args([
        "commit",
        "-q",
        "-m",
        "resolve merge conflict",
    ]))
    .expect("merge commit");
    assert!(
        commit_merge.succeeded(),
        "merge resolution commit failed; stderr:\n{}",
        commit_merge.stderr
    );

    // HEAD is a merge commit (2 parents) and verifies.
    let parents =
        run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["rev-list", "--parents", "-n", "1", "HEAD"]))
        .expect("rev-list parents");
    let parent_count = parents.stdout.split_whitespace().count() - 1;
    assert_eq!(
        parent_count, 2,
        "expected 2-parent merge commit; got {parent_count}:\n{}",
        parents.stdout
    );
    let verify = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(
        verify.succeeded(),
        "verify-commit on resolved-merge HEAD failed; stderr:\n{}",
        verify.stderr
    );
}
