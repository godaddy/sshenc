// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Four signing/message/tag-display contracts on a
//! gitenc-configured repo:
//!
//! - `git cherry-pick -x` re-signs the cherry-picked commit and
//!   embeds a `(cherry picked from ...)` footer in its message;
//!   the new HEAD verifies and the body contains the footer.
//! - `git commit --allow-empty-message --no-edit` produces a
//!   signed commit with an empty subject; verify-commit accepts.
//! - A lightweight (unsigned) `git tag <name>` on a signed
//!   commit makes `git verify-tag` fail (no signature attached
//!   to the tag itself, even though the underlying commit is
//!   signed).
//! - `git show --pretty=fuller HEAD` includes both the standard
//!   committer/author block and the gpgsig metadata for a
//!   signed commit.

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
        "msg-tag signer",
        "msgtag@e2e.test",
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

/// `git cherry-pick -x` re-signs and embeds the
/// `(cherry picked from ...)` footer.
#[test]
#[ignore = "requires docker"]
fn cherry_pick_dash_x_re_signs_and_records_origin() {
    if skip_if_no_docker("cherry_pick_dash_x_re_signs_and_records_origin") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "cp-x-repo", &enclave);

    make_commit(&env, &repo, "main.txt", "main\n", "main commit");

    assert!(env
        .git_cmd()
        .current_dir(&repo)
        .args(["checkout", "-q", "-b", "feature"])
        .status()
        .expect("checkout -b feature")
        .success());
    make_commit(&env, &repo, "feat.txt", "feat\n", "feat commit");
    let feat_sha = rev_parse(&env, &repo, "HEAD");

    assert!(env
        .git_cmd()
        .current_dir(&repo)
        .args(["checkout", "-q", "main"])
        .status()
        .expect("checkout main")
        .success());

    let cp = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["cherry-pick", "-x", &feat_sha]))
    .expect("git cherry-pick -x");
    assert!(cp.succeeded(), "cherry-pick -x: {}", cp.stderr);

    // verify-commit on new HEAD passes.
    let verify = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(
        verify.succeeded(),
        "verify-commit on cherry-pick -x HEAD failed; stderr:\n{}",
        verify.stderr
    );

    // Body contains the cherry-picked-from footer with the original sha.
    let body = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["log", "-1", "--format=%B"]))
    .expect("git log %B");
    assert!(body.succeeded(), "git log: {}", body.stderr);
    assert!(
        body.stdout.contains("(cherry picked from commit ") && body.stdout.contains(&feat_sha[..8]),
        "expected cherry-picked-from footer with original sha; got:\n{}",
        body.stdout
    );
}

/// `git commit --allow-empty-message --no-edit` on a staged
/// change produces a signed commit with an empty subject.
#[test]
#[ignore = "requires docker"]
fn commit_with_empty_message_is_signed() {
    if skip_if_no_docker("commit_with_empty_message_is_signed") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "empty-msg-repo", &enclave);

    std::fs::write(repo.join("a.txt"), b"empty msg\n").expect("write");
    let add = run(env.git_cmd().current_dir(&repo).args(["add", "a.txt"])).expect("git add");
    assert!(add.succeeded(), "git add: {}", add.stderr);

    let commit = run(env.git_cmd().current_dir(&repo).args([
        "commit",
        "--allow-empty-message",
        "-q",
        "-m",
        "",
    ]))
    .expect("git commit --allow-empty-message");
    assert!(
        commit.succeeded(),
        "git commit --allow-empty-message: {}",
        commit.stderr
    );

    let verify = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(
        verify.succeeded(),
        "verify-commit on empty-message HEAD failed; stderr:\n{}",
        verify.stderr
    );

    let subject = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["log", "-1", "--format=%s"]))
    .expect("log subject");
    assert!(subject.succeeded(), "git log: {}", subject.stderr);
    assert!(
        subject.stdout.trim().is_empty(),
        "subject should be empty; got: {:?}",
        subject.stdout
    );
}

/// A lightweight (unsigned) `git tag <name>` on a signed commit
/// fails `git verify-tag` (no tag-level signature attached).
#[test]
#[ignore = "requires docker"]
fn lightweight_tag_on_signed_commit_fails_verify_tag() {
    if skip_if_no_docker("lightweight_tag_on_signed_commit_fails_verify_tag") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "lightweight-tag-repo", &enclave);

    make_commit(&env, &repo, "a.txt", "first\n", "first");

    // Lightweight tag (no -s, no -a, no -m).
    let tag = run(env.git_cmd().current_dir(&repo).args(["tag", "lite-tag"])).expect("git tag");
    assert!(tag.succeeded(), "git tag: {}", tag.stderr);

    // verify-tag must fail (no signature on the tag itself).
    let verify = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-tag", "lite-tag"]))
    .expect("git verify-tag");
    assert!(
        !verify.succeeded(),
        "verify-tag on lightweight tag should fail; stdout:\n{}\nstderr:\n{}",
        verify.stdout,
        verify.stderr
    );

    // The underlying commit is still signed and verifies.
    let verify_commit = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(
        verify_commit.succeeded(),
        "underlying commit should still verify; stderr:\n{}",
        verify_commit.stderr
    );
}

/// `git show --pretty=fuller HEAD` on a signed commit emits both
/// the extended committer/author info and the gpgsig metadata.
#[test]
#[ignore = "requires docker"]
fn git_show_pretty_fuller_includes_signing_metadata() {
    if skip_if_no_docker("git_show_pretty_fuller_includes_signing_metadata") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "fuller-repo", &enclave);

    make_commit(&env, &repo, "a.txt", "fuller\n", "fuller body");

    let show = run(env.git_cmd().current_dir(&repo).args([
        "show",
        "--show-signature",
        "--pretty=fuller",
        "HEAD",
    ]))
    .expect("git show --pretty=fuller --show-signature");
    assert!(show.succeeded(), "git show: {}", show.stderr);
    let combined = format!("{}\n{}", show.stdout, show.stderr);
    assert!(
        combined.contains("Author:") && combined.contains("AuthorDate:"),
        "expected --pretty=fuller author block; got:\n{combined}"
    );
    assert!(
        combined.contains("Commit:") && combined.contains("CommitDate:"),
        "expected --pretty=fuller committer block; got:\n{combined}"
    );
    assert!(
        combined.contains("Good \"git\" signature") || combined.contains("Good signature"),
        "expected signature display; got:\n{combined}"
    );
}
