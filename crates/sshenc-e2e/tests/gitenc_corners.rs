// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Four `gitenc` corner cases the existing four gitenc test files
//! don't cover:
//!
//! 1. `gitenc --config` from a directory that isn't a git repo
//!    must fail cleanly (don't write to ~/.gitconfig, don't crash).
//! 2. `gitenc --config` on a bare repository (`git init --bare`)
//!    succeeds and writes the config to the bare repo's
//!    `config` file (not a `.git/config` because there isn't one).
//! 3. `gitenc --config --label <invalid>` fails *before* writing
//!    any git config — atomic failure on validation, no partial
//!    state.
//! 4. `gitenc --config` on a repo whose path contains spaces still
//!    correctly resolves and writes per-repo config.

#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{docker_skip_reason, run, shared_enclave_pubkey, SshencEnv, SHARED_ENCLAVE_LABEL};

fn skip_if_no_docker(test_name: &str) -> bool {
    if let Some(reason) = docker_skip_reason() {
        eprintln!("skip {test_name}: {reason}");
        return true;
    }
    false
}

fn plant_meta(env: &SshencEnv, label: &str, name: &str, email: &str) {
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
}

/// `gitenc --config <label>` invoked from a directory that isn't a
/// git repo must error out without modifying anything outside the
/// directory.
#[test]
#[ignore = "requires docker"]
fn gitenc_config_in_non_git_dir_fails_cleanly() {
    if skip_if_no_docker("gitenc_config_in_non_git_dir_fails_cleanly") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("warm shared key"));
    plant_meta(&env, SHARED_ENCLAVE_LABEL, "x", "x@y.test");

    // Seed a global ~/.gitconfig with a known marker so we can
    // verify gitenc didn't touch it on the failure path.
    let global = env.home().join(".gitconfig");
    let marker = "[user]\n\tname = preserved\n";
    std::fs::write(&global, marker).expect("write global");

    // Make a directory that's NOT a git repo.
    let non_repo = env.home().join("not-a-repo");
    std::fs::create_dir_all(&non_repo).expect("mkdir non-repo");

    let outcome = run(env
        .gitenc_cmd()
        .expect("gitenc cmd")
        .current_dir(&non_repo)
        .args(["--config", SHARED_ENCLAVE_LABEL]))
    .expect("gitenc --config in non-repo");

    assert!(
        !outcome.succeeded(),
        "gitenc --config in non-repo dir should fail; stdout:\n{}\nstderr:\n{}",
        outcome.stdout,
        outcome.stderr
    );

    // Global gitconfig must still be intact.
    let after = std::fs::read_to_string(&global).expect("read global");
    assert_eq!(
        after, marker,
        "gitenc --config touched ~/.gitconfig on failure path; after:\n{after}"
    );
}

/// `gitenc --config <label>` inside a bare repository writes per-
/// repo config to the bare repo's `config` file. Bare repos don't
/// have a `.git/` subdirectory; the config lives in `<repo>/config`.
#[test]
#[ignore = "requires docker"]
fn gitenc_config_on_bare_repo_writes_repo_config() {
    if skip_if_no_docker("gitenc_config_on_bare_repo_writes_repo_config") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("warm shared key"));
    plant_meta(&env, SHARED_ENCLAVE_LABEL, "bare signer", "bare@e2e.test");

    let bare = env.home().join("bare-repo.git");
    let init = run(env
        .git_cmd()
        .args(["init", "--bare", "-b", "main", "-q"])
        .arg(&bare))
    .expect("git init --bare");
    assert!(init.succeeded(), "git init --bare: {}", init.stderr);

    let outcome = run(env
        .gitenc_cmd()
        .expect("gitenc cmd")
        .current_dir(&bare)
        .args(["--config", SHARED_ENCLAVE_LABEL]))
    .expect("gitenc --config on bare");
    assert!(
        outcome.succeeded(),
        "gitenc --config on bare repo failed; stderr:\n{}",
        outcome.stderr
    );

    let email =
        run(env
            .git_cmd()
            .current_dir(&bare)
            .args(["config", "--local", "--get", "user.email"]))
        .expect("git config bare");
    assert_eq!(
        email.stdout.trim(),
        "bare@e2e.test",
        "bare repo's user.email not set by gitenc --config; got:\n{}",
        email.stdout
    );
}

/// `gitenc --config --label <invalid>` rejects the label before
/// touching any git config. Atomic validation: the repo's
/// .git/config must be byte-identical before and after the failed
/// invocation.
#[test]
#[ignore = "requires docker"]
fn gitenc_config_invalid_label_does_not_partial_write() {
    if skip_if_no_docker("gitenc_config_invalid_label_does_not_partial_write") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("warm shared key"));

    let repo = env.home().join("invalid-label-repo");
    std::fs::create_dir_all(&repo).expect("mkdir");
    assert!(env
        .git_cmd()
        .current_dir(&repo)
        .args(["init", "-q", "-b", "main"])
        .status()
        .expect("git init")
        .success());

    let config_path = repo.join(".git").join("config");
    let before = std::fs::read_to_string(&config_path).expect("read .git/config");

    // Invalid labels per KeyLabel validation: contains slash.
    let outcome = run(env
        .gitenc_cmd()
        .expect("gitenc cmd")
        .current_dir(&repo)
        .args(["--config", "bad/label/with/slashes"]))
    .expect("gitenc --config invalid");
    assert!(
        !outcome.succeeded(),
        "gitenc --config with invalid label should fail; stdout:\n{}\nstderr:\n{}",
        outcome.stdout,
        outcome.stderr
    );

    let after = std::fs::read_to_string(&config_path).expect("read .git/config after");
    assert_eq!(
        before, after,
        ".git/config was modified despite invalid label; before:\n{before}\nafter:\n{after}"
    );
}

/// Repo paths with spaces don't break gitenc's path handling.
#[test]
#[ignore = "requires docker"]
fn gitenc_config_handles_repo_path_with_spaces() {
    if skip_if_no_docker("gitenc_config_handles_repo_path_with_spaces") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("warm shared key"));
    plant_meta(
        &env,
        SHARED_ENCLAVE_LABEL,
        "spacey signer",
        "spacey@e2e.test",
    );

    let repo = env.home().join("repo with spaces");
    std::fs::create_dir_all(&repo).expect("mkdir spaced repo");
    assert!(env
        .git_cmd()
        .current_dir(&repo)
        .args(["init", "-q", "-b", "main"])
        .status()
        .expect("git init")
        .success());

    let outcome = run(env
        .gitenc_cmd()
        .expect("gitenc cmd")
        .current_dir(&repo)
        .args(["--config", SHARED_ENCLAVE_LABEL]))
    .expect("gitenc --config spaced");
    assert!(
        outcome.succeeded(),
        "gitenc --config in path with spaces failed; stderr:\n{}",
        outcome.stderr
    );

    let email =
        run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["config", "--local", "--get", "user.email"]))
        .expect("git config spaced");
    assert_eq!(
        email.stdout.trim(),
        "spacey@e2e.test",
        "user.email not set in spaced-path repo; got:\n{}",
        email.stdout
    );
}
