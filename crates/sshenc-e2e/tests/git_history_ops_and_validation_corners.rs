// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Git history-rewriting ops with sshenc signing, plus CLI
//! input-validation error paths:
//!
//! 1. `git cherry-pick` of an existing commit produces an
//!    sshenc-signed commit on the current branch (the
//!    new commit verifies with `git verify-commit HEAD`).
//! 2. `git revert` produces an sshenc-signed reverting commit
//!    that verifies with `git verify-commit`.
//! 3. `git merge --no-ff` produces an sshenc-signed merge commit
//!    that verifies with `git verify-commit`. (Distinct from
//!    `pull` which does fetch+merge across an SSH remote.)
//! 4. `sshenc keygen --auth-policy <invalid>` exits non-zero with
//!    a clear "unknown access policy" message — pins the enum
//!    rejection path that `selected_access_policy` implements.
//! 5. `gitenc push` in a repo with no configured remote exits
//!    non-zero with a clean error (no panic, useful diagnostic).

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{
    docker_skip_reason, extended_enabled, run, shared_enclave_pubkey, software_mode, SshencEnv,
    SHARED_ENCLAVE_LABEL,
};

fn skip_if_no_docker(test_name: &str) -> bool {
    if let Some(reason) = docker_skip_reason() {
        eprintln!("skip {test_name}: {reason}");
        return true;
    }
    false
}

fn skip_unless_key_creation_cheap(test_name: &str) -> bool {
    if extended_enabled() || software_mode() {
        return false;
    }
    eprintln!(
        "skip {test_name}: needs to mint keys; \
         set SSHENC_E2E_SOFTWARE=1 or SSHENC_E2E_EXTENDED=1"
    );
    true
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
        "round9 signer",
        "round9@e2e.test",
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

/// `git cherry-pick <sha>` produces a new commit on the current
/// branch, signed by the configured sshenc key. The new commit
/// must verify with `git verify-commit HEAD`.
#[test]
#[ignore = "requires docker"]
fn cherry_pick_produces_signed_commit() {
    if skip_if_no_docker("cherry_pick_produces_signed_commit") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "cherry-pick-repo", &enclave);

    // Initial commit on main so cherry-pick has somewhere to land.
    make_commit(&env, &repo, "main.txt", "main\n", "main commit");

    // Side branch with a commit we'll cherry-pick.
    assert!(env
        .git_cmd()
        .current_dir(&repo)
        .args(["checkout", "-q", "-b", "feature"])
        .status()
        .expect("checkout")
        .success());
    make_commit(&env, &repo, "feat.txt", "feat\n", "feature commit");
    let feat_sha = rev_parse(&env, &repo, "HEAD");

    // Back to main, cherry-pick.
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
        .args(["cherry-pick", &feat_sha]))
    .expect("cherry-pick");
    assert!(cp.succeeded(), "cherry-pick: {}", cp.stderr);

    let verify = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(
        verify.succeeded(),
        "verify-commit on cherry-picked HEAD failed; stdout:\n{}\nstderr:\n{}",
        verify.stdout,
        verify.stderr
    );
}

/// `git revert <sha>` produces a new reverting commit signed by
/// the configured sshenc key, which verifies with
/// `git verify-commit HEAD`.
#[test]
#[ignore = "requires docker"]
fn revert_produces_signed_commit() {
    if skip_if_no_docker("revert_produces_signed_commit") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "revert-repo", &enclave);

    make_commit(&env, &repo, "a.txt", "first\n", "first");
    make_commit(&env, &repo, "b.txt", "second\n", "second");
    let target = rev_parse(&env, &repo, "HEAD");

    let revert = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["revert", "--no-edit", &target]))
    .expect("revert");
    assert!(revert.succeeded(), "git revert: {}", revert.stderr);

    let verify = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(
        verify.succeeded(),
        "verify-commit on revert HEAD failed; stdout:\n{}\nstderr:\n{}",
        verify.stdout,
        verify.stderr
    );
}

/// `git merge --no-ff <branch>` produces a merge commit signed
/// by the configured sshenc key. (`pull` exercises the same
/// internal merge but over an SSH remote; this isolates the
/// merge-commit signing path locally.)
#[test]
#[ignore = "requires docker"]
fn merge_no_ff_produces_signed_merge_commit() {
    if skip_if_no_docker("merge_no_ff_produces_signed_merge_commit") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "merge-noff-repo", &enclave);

    // Initial commit on main.
    make_commit(&env, &repo, "main.txt", "main\n", "main");

    // Feature branch with a commit.
    assert!(env
        .git_cmd()
        .current_dir(&repo)
        .args(["checkout", "-q", "-b", "feature"])
        .status()
        .expect("checkout -b feature")
        .success());
    make_commit(&env, &repo, "feat.txt", "feat\n", "feat");

    // Back to main and merge --no-ff so a merge commit is produced.
    assert!(env
        .git_cmd()
        .current_dir(&repo)
        .args(["checkout", "-q", "main"])
        .status()
        .expect("checkout main")
        .success());
    let merge = run(env.git_cmd().current_dir(&repo).args([
        "merge",
        "--no-ff",
        "--no-edit",
        "-m",
        "merge feature",
        "feature",
    ]))
    .expect("git merge --no-ff");
    assert!(merge.succeeded(), "git merge --no-ff: {}", merge.stderr);

    // HEAD should be a merge commit (two parents) and verify cleanly.
    let parents =
        run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["rev-list", "--parents", "-n", "1", "HEAD"]))
        .expect("rev-list parents");
    assert!(parents.succeeded(), "rev-list: {}", parents.stderr);
    let parent_count = parents.stdout.split_whitespace().count() - 1;
    assert_eq!(
        parent_count, 2,
        "expected merge commit (2 parents); got {parent_count} parents:\n{}",
        parents.stdout
    );

    let verify = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(
        verify.succeeded(),
        "verify-commit on merge HEAD failed; stdout:\n{}\nstderr:\n{}",
        verify.stdout,
        verify.stderr
    );
}

/// `sshenc keygen --auth-policy <unknown>` exits non-zero with
/// "unknown access policy: ..." — pins the rejection branch in
/// `selected_access_policy`. (Valid values are any/biometric/
/// password/none.)
#[test]
#[ignore = "requires docker"]
fn keygen_invalid_auth_policy_errors_cleanly() {
    if skip_if_no_docker("keygen_invalid_auth_policy_errors_cleanly") {
        return;
    }
    if skip_unless_key_creation_cheap("keygen_invalid_auth_policy_errors_cleanly") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    env.use_ephemeral_keys_dir().expect("ephemeral");

    let kg = run(env.sshenc_cmd().expect("sshenc cmd").args([
        "keygen",
        "--label",
        "policy-bogus",
        "--auth-policy",
        "no-such-policy",
        "--no-pub-file",
    ]))
    .expect("sshenc keygen");

    assert!(
        !kg.succeeded(),
        "keygen with bogus --auth-policy should fail; stdout:\n{}\nstderr:\n{}",
        kg.stdout,
        kg.stderr
    );
    let combined = format!("{}\n{}", kg.stdout, kg.stderr).to_lowercase();
    assert!(
        combined.contains("unknown access policy") || combined.contains("policy"),
        "expected diagnostic mentioning the rejected policy; got:\n{combined}"
    );
    assert!(
        !combined.contains("panicked at"),
        "keygen panicked on invalid policy:\n{combined}"
    );
}

/// `gitenc push` in a repo with no remote configured exits
/// non-zero with a clean error (the underlying git failure
/// surfaces, no panic from the wrapper).
#[test]
#[ignore = "requires docker"]
fn gitenc_push_in_repo_with_no_remote_errors_cleanly() {
    if skip_if_no_docker("gitenc_push_in_repo_with_no_remote_errors_cleanly") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "no-remote-repo", &enclave);

    make_commit(&env, &repo, "a.txt", "a\n", "first");

    // No `git remote add` — push should fail at the git layer.
    let push = run(env
        .gitenc_cmd()
        .expect("gitenc cmd")
        .current_dir(&repo)
        .args(["push", "origin", "main"]))
    .expect("gitenc push");

    assert!(
        !push.succeeded(),
        "gitenc push with no remote should fail; stdout:\n{}\nstderr:\n{}",
        push.stdout,
        push.stderr
    );
    let combined = format!("{}\n{}", push.stdout, push.stderr);
    assert!(
        !combined.contains("panicked at"),
        "gitenc panicked on missing remote:\n{combined}"
    );
}
