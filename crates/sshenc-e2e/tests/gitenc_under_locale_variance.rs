// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! gitenc and signing-related operations work under non-default
//! locale environments. Catches regressions where sshenc parses
//! git's output (e.g., for label/identity discovery) under an
//! assumed `en_US.UTF-8` and breaks when the user's shell uses
//! a different locale.

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
        "locale signer",
        "locale@e2e.test",
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

/// `git commit` under `LC_ALL=C` produces a verifiable signed
/// commit. The C locale is the most-restrictive POSIX locale —
/// no UTF-8, no localized strings — and is a common sentinel
/// for parser portability.
#[test]
#[ignore = "requires docker"]
fn signed_commit_works_under_lc_all_c() {
    if skip_if_no_docker("signed_commit_works_under_lc_all_c") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "lc-all-c-repo", &enclave);

    std::fs::write(repo.join("a.txt"), b"content\n").expect("write");
    let add = run(env
        .git_cmd()
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .current_dir(&repo)
        .args(["add", "a.txt"]))
    .expect("git add");
    assert!(add.succeeded(), "git add: {}", add.stderr);

    let commit = run(env
        .git_cmd()
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .current_dir(&repo)
        .args(["commit", "-q", "-m", "lc-c content"]))
    .expect("git commit");
    assert!(
        commit.succeeded(),
        "git commit under LC_ALL=C: {}",
        commit.stderr
    );

    let verify = run(env
        .git_cmd()
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(
        verify.succeeded(),
        "verify-commit under LC_ALL=C failed; stderr:\n{}",
        verify.stderr
    );
}

/// `gitenc --config` and a subsequent commit under
/// `LC_ALL=en_US.UTF-8` (default-flavored UTF-8 locale) work
/// cleanly. Pin that gitenc doesn't trip on UTF-8 git output.
#[test]
#[ignore = "requires docker"]
fn signed_commit_works_under_utf8_locale() {
    if skip_if_no_docker("signed_commit_works_under_utf8_locale") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "lc-utf8-repo", &enclave);

    std::fs::write(repo.join("u.txt"), b"unicode-friendly\n").expect("write");
    let add = run(env
        .git_cmd()
        .env("LC_ALL", "en_US.UTF-8")
        .current_dir(&repo)
        .args(["add", "u.txt"]))
    .expect("git add");
    assert!(add.succeeded(), "git add: {}", add.stderr);

    let commit = run(env
        .git_cmd()
        .env("LC_ALL", "en_US.UTF-8")
        .current_dir(&repo)
        .args(["commit", "-q", "-m", "utf8 content"]))
    .expect("git commit");
    assert!(
        commit.succeeded(),
        "git commit under LC_ALL=en_US.UTF-8: {}",
        commit.stderr
    );

    let verify = run(env
        .git_cmd()
        .env("LC_ALL", "en_US.UTF-8")
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(
        verify.succeeded(),
        "verify-commit under LC_ALL=en_US.UTF-8 failed; stderr:\n{}",
        verify.stderr
    );
}
