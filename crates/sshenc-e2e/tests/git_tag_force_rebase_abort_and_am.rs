// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Git history-edit workflows that touch the signing path in
//! ways the existing rebase/cherry-pick/revert/merge tests
//! don't:
//!
//! - `git tag --force -s v1 <new-commit>` overwrites an existing
//!   signed annotated tag. The new tag must verify with
//!   `git verify-tag` against the rewritten target.
//! - `git rebase --abort` after a conflicting rebase restores
//!   HEAD to the pre-rebase commit. That commit must still
//!   verify with `git verify-commit` (no signature corruption,
//!   no orphaned objects breaking verification).
//! - `git format-patch HEAD~1..HEAD` + `git am <patch>` applies
//!   a patch in a sibling tree and produces a fresh
//!   sshenc-signed commit (because the receiving tree has
//!   `commit.gpgsign=true` from `gitenc --config`).

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
        "history signer",
        "history@e2e.test",
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

/// `git tag --force -s` overwrites an existing signed tag.
/// `git verify-tag` against the rewritten tag must accept the
/// new signature on the new target sha.
#[test]
#[ignore = "requires docker"]
fn tag_force_overwrites_signed_tag_and_new_target_verifies() {
    if skip_if_no_docker("tag_force_overwrites_signed_tag_and_new_target_verifies") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "tag-force-repo", &enclave);

    make_commit(&env, &repo, "a.txt", "first\n", "first");
    let first_sha = rev_parse(&env, &repo, "HEAD");

    // Initial signed tag on the first commit.
    let tag1 = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["tag", "-s", "v1", "-m", "initial"]))
    .expect("git tag -s");
    assert!(tag1.succeeded(), "initial git tag -s: {}", tag1.stderr);

    // Second commit, then force-overwrite the tag onto it.
    make_commit(&env, &repo, "b.txt", "second\n", "second");
    let second_sha = rev_parse(&env, &repo, "HEAD");
    assert_ne!(first_sha, second_sha, "second commit should differ");

    let tag_force =
        run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["tag", "-s", "-f", "v1", "-m", "rewritten"]))
        .expect("git tag -s -f");
    assert!(
        tag_force.succeeded(),
        "git tag --force failed: {}",
        tag_force.stderr
    );

    // Verify-tag must accept the rewritten tag.
    let verify =
        run(env.git_cmd().current_dir(&repo).args(["verify-tag", "v1"])).expect("git verify-tag");
    assert!(
        verify.succeeded(),
        "verify-tag on force-rewritten tag failed; stderr:\n{}",
        verify.stderr
    );

    // The tag must point at the second commit, not the first.
    let tag_target = rev_parse(&env, &repo, "v1^{commit}");
    assert_eq!(
        tag_target, second_sha,
        "v1 should now point to the second commit; got {tag_target}, want {second_sha}"
    );
}

/// `git rebase --abort` after a conflict restores HEAD to the
/// pre-rebase commit, and that commit's signature still verifies.
#[test]
#[ignore = "requires docker"]
fn rebase_abort_after_conflict_restores_verifiable_head() {
    if skip_if_no_docker("rebase_abort_after_conflict_restores_verifiable_head") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "rebase-abort-repo", &enclave);

    // Initial commit on main.
    make_commit(&env, &repo, "shared.txt", "main-content\n", "main");

    // Feature branch modifies shared.txt one way.
    assert!(env
        .git_cmd()
        .current_dir(&repo)
        .args(["checkout", "-q", "-b", "feature"])
        .status()
        .expect("checkout -b feature")
        .success());
    std::fs::write(repo.join("shared.txt"), b"feature-content\n").expect("write");
    drop(run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["add", "shared.txt"])));
    let feat_commit =
        run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["commit", "-q", "-m", "feat-edit"]))
        .expect("commit feat");
    assert!(
        feat_commit.succeeded(),
        "commit feat: {}",
        feat_commit.stderr
    );
    let feature_sha = rev_parse(&env, &repo, "HEAD");

    // Main edits the same file differently → guaranteed conflict on rebase.
    assert!(env
        .git_cmd()
        .current_dir(&repo)
        .args(["checkout", "-q", "main"])
        .status()
        .expect("checkout main")
        .success());
    std::fs::write(repo.join("shared.txt"), b"main-edited\n").expect("write");
    drop(run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["add", "shared.txt"])));
    drop(run(env.git_cmd().current_dir(&repo).args([
        "commit",
        "-q",
        "-m",
        "main-edit",
    ])));

    // Rebase feature onto main — must conflict.
    assert!(env
        .git_cmd()
        .current_dir(&repo)
        .args(["checkout", "-q", "feature"])
        .status()
        .expect("checkout feature")
        .success());
    let rebase = run(env.git_cmd().current_dir(&repo).args(["rebase", "main"]))
        .expect("git rebase (expected to conflict)");
    assert!(
        !rebase.succeeded(),
        "rebase should have conflicted; stdout:\n{}\nstderr:\n{}",
        rebase.stdout,
        rebase.stderr
    );

    // Abort the rebase.
    let abort = run(env.git_cmd().current_dir(&repo).args(["rebase", "--abort"]))
        .expect("git rebase --abort");
    assert!(abort.succeeded(), "rebase --abort: {}", abort.stderr);

    // HEAD should be back on the pre-rebase feature commit.
    let head_after = rev_parse(&env, &repo, "HEAD");
    assert_eq!(
        head_after, feature_sha,
        "HEAD should be restored to the pre-rebase feature commit"
    );

    // And it must still verify cleanly.
    let verify = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(
        verify.succeeded(),
        "verify-commit on restored HEAD failed; stderr:\n{}",
        verify.stderr
    );
}

/// `git format-patch` + `git am` round-trip: a patch produced
/// from one repo and applied in a sibling repo with sshenc
/// signing configured produces a freshly-signed commit on the
/// receiving side. Verifies that `am`'s commit-creation path
/// honors `commit.gpgsign=true`.
#[test]
#[ignore = "requires docker"]
fn format_patch_and_am_produces_signed_commit_on_receiver() {
    if skip_if_no_docker("format_patch_and_am_produces_signed_commit_on_receiver") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");

    // Sender repo: produce a commit and format-patch it.
    let sender = make_signed_repo(&env, "patch-sender", &enclave);
    make_commit(&env, &sender, "a.txt", "shared\n", "shared base");
    make_commit(&env, &sender, "b.txt", "patch body\n", "patchable change");

    let patch_dir = env.home().join("patches");
    std::fs::create_dir_all(&patch_dir).expect("mkdir patches");
    let format = run(env.git_cmd().current_dir(&sender).args([
        "format-patch",
        "-1",
        "-o",
        patch_dir.to_str().expect("utf-8"),
        "HEAD",
    ]))
    .expect("git format-patch");
    assert!(format.succeeded(), "format-patch: {}", format.stderr);

    let patch_path = std::fs::read_dir(&patch_dir)
        .expect("read patches dir")
        .filter_map(Result::ok)
        .find(|e| e.file_name().to_string_lossy().ends_with(".patch"))
        .expect("at least one .patch file produced")
        .path();

    // Receiver repo: same shared base content, no patchable change yet.
    let receiver = make_signed_repo(&env, "patch-receiver", &enclave);
    make_commit(&env, &receiver, "a.txt", "shared\n", "shared base");

    let am = run(env
        .git_cmd()
        .current_dir(&receiver)
        .arg("am")
        .arg(&patch_path))
    .expect("git am");
    assert!(am.succeeded(), "git am: {}", am.stderr);

    // The newly applied commit on the receiver must be sshenc-signed.
    let verify = run(env
        .git_cmd()
        .current_dir(&receiver)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(
        verify.succeeded(),
        "verify-commit on `git am` HEAD failed; stderr:\n{}",
        verify.stderr
    );

    // Receiver's HEAD content must match the sender's patched file.
    let body = std::fs::read_to_string(receiver.join("b.txt")).expect("read b.txt");
    assert_eq!(body, "patch body\n", "patch body didn't apply correctly");
}
