// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Two contracts on a gitenc-configured repo:
//!
//! - Pure plumbing inspection commands (`git ls-files`,
//!   `git ls-tree`, `git cat-file -p`) work cleanly on a repo
//!   of sshenc-signed commits — they don't invoke the agent
//!   and don't trip on signature metadata in commit objects.
//! - Committing a large (>10 MB) binary blob signs and
//!   verifies. Existing `sign_edge_data.rs` covers ~5 MiB
//!   payloads; this pushes past that to catch streaming or
//!   buffer-size regressions in the signing path.

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
        "plumbing signer",
        "plumbing@e2e.test",
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

/// `git ls-files`, `git ls-tree HEAD`, `git cat-file -p HEAD`
/// all run cleanly on a signed-commit history.
#[test]
#[ignore = "requires docker"]
fn git_plumbing_inspection_works_on_signed_repo() {
    if skip_if_no_docker("git_plumbing_inspection_works_on_signed_repo") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "plumbing-repo", &enclave);

    make_commit(&env, &repo, "a.txt", "alpha\n", "first");
    make_commit(&env, &repo, "b.txt", "beta\n", "second");

    let ls_files = run(env.git_cmd().current_dir(&repo).args(["ls-files"])).expect("git ls-files");
    assert!(ls_files.succeeded(), "git ls-files: {}", ls_files.stderr);
    assert!(
        ls_files.stdout.contains("a.txt") && ls_files.stdout.contains("b.txt"),
        "expected both files; got:\n{}",
        ls_files.stdout
    );

    let ls_tree =
        run(env.git_cmd().current_dir(&repo).args(["ls-tree", "HEAD"])).expect("git ls-tree");
    assert!(ls_tree.succeeded(), "git ls-tree: {}", ls_tree.stderr);
    assert!(
        ls_tree.stdout.contains("a.txt") && ls_tree.stdout.contains("b.txt"),
        "expected both files in tree; got:\n{}",
        ls_tree.stdout
    );

    let cat = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["cat-file", "-p", "HEAD"]))
    .expect("git cat-file -p HEAD");
    assert!(cat.succeeded(), "git cat-file: {}", cat.stderr);
    // Signed commits have a `gpgsig` header in their object body —
    // pin that the inspection actually surfaces it (proves the
    // signing path put it there and cat-file doesn't strip it).
    assert!(
        cat.stdout.contains("gpgsig"),
        "expected gpgsig header in cat-file output; got:\n{}",
        cat.stdout
    );
}

/// A 12 MiB binary blob committed via gitenc signs and
/// `git verify-commit HEAD` accepts the signature.
#[test]
#[ignore = "requires docker"]
fn large_binary_commit_signs_and_verifies() {
    if skip_if_no_docker("large_binary_commit_signs_and_verifies") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "large-blob-repo", &enclave);

    // 12 MiB pseudo-random-ish bytes (deterministic so the test is
    // reproducible).
    let mut blob = Vec::with_capacity(12 * 1024 * 1024);
    let mut state: u64 = 0xC0FFEE_DEADBEEF;
    while blob.len() < 12 * 1024 * 1024 {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        blob.extend_from_slice(&state.to_le_bytes());
    }
    blob.truncate(12 * 1024 * 1024);
    std::fs::write(repo.join("big.bin"), &blob).expect("write big blob");

    let add = run(env.git_cmd().current_dir(&repo).args(["add", "big.bin"])).expect("git add");
    assert!(add.succeeded(), "git add: {}", add.stderr);

    let commit = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["commit", "-q", "-m", "12 MiB blob"]))
    .expect("git commit");
    assert!(
        commit.succeeded(),
        "git commit on large blob failed: {}",
        commit.stderr
    );

    let verify = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(
        verify.succeeded(),
        "verify-commit on large-blob commit failed; stderr:\n{}",
        verify.stderr
    );
}
