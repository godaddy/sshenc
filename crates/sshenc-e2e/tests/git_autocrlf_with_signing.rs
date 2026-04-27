// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Git config flags that change how content is hashed/stored
//! must not break sshenc signing or verification:
//!
//! - `core.autocrlf=true` rewrites line endings on checkin (CRLF
//!   → LF in the index). Pin that signing produces a verifiable
//!   commit even when the worktree has CRLF endings.
//! - `core.fileMode=false` ignores executable-bit changes. Pin
//!   that signing/verification works under this config.

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
        "config-toggle signer",
        "configtoggle@e2e.test",
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

/// `git commit` under `core.autocrlf=true` produces a verifiable
/// signed commit even though git's index normalization rewrites
/// CRLF → LF.
#[test]
#[ignore = "requires docker"]
fn signing_works_with_core_autocrlf_true() {
    if skip_if_no_docker("signing_works_with_core_autocrlf_true") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "autocrlf-repo", &enclave);

    let set_autocrlf =
        run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["config", "--local", "core.autocrlf", "true"]))
        .expect("git config core.autocrlf");
    assert!(
        set_autocrlf.succeeded(),
        "git config core.autocrlf: {}",
        set_autocrlf.stderr
    );

    // Write a file with CRLF endings.
    std::fs::write(repo.join("crlf.txt"), b"line1\r\nline2\r\n").expect("write CRLF");
    let add = run(env.git_cmd().current_dir(&repo).args(["add", "crlf.txt"])).expect("git add");
    assert!(add.succeeded(), "git add: {}", add.stderr);

    let commit = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["commit", "-q", "-m", "crlf content"]))
    .expect("git commit");
    assert!(commit.succeeded(), "git commit: {}", commit.stderr);

    let verify = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(
        verify.succeeded(),
        "verify-commit on CRLF-normalized commit failed; stderr:\n{}",
        verify.stderr
    );
}

/// `git commit` under `core.fileMode=false` (mode-bit changes
/// ignored) produces a verifiable signed commit.
#[test]
#[ignore = "requires docker"]
fn signing_works_with_core_filemode_false() {
    if skip_if_no_docker("signing_works_with_core_filemode_false") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "filemode-repo", &enclave);

    let set_fm =
        run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["config", "--local", "core.fileMode", "false"]))
        .expect("git config core.fileMode");
    assert!(
        set_fm.succeeded(),
        "git config core.fileMode: {}",
        set_fm.stderr
    );

    std::fs::write(repo.join("a.txt"), b"content\n").expect("write");
    let add = run(env.git_cmd().current_dir(&repo).args(["add", "a.txt"])).expect("git add");
    assert!(add.succeeded(), "git add: {}", add.stderr);

    let commit = run(env.git_cmd().current_dir(&repo).args([
        "commit",
        "-q",
        "-m",
        "filemode-false content",
    ]))
    .expect("git commit");
    assert!(commit.succeeded(), "git commit: {}", commit.stderr);

    let verify = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(
        verify.succeeded(),
        "verify-commit under core.fileMode=false failed; stderr:\n{}",
        verify.stderr
    );
}
