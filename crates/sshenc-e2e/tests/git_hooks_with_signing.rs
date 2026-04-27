// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Custom git hooks (pre-commit, post-commit) coexist cleanly
//! with sshenc-mediated signing. The hooks must fire, the
//! resulting commit must verify, and the hook environment
//! must not leak agent socket paths or credentials in a way
//! that's visible to the user (the contract here is "hook
//! ran" + "commit verifies", not specific env-var hygiene
//! beyond no-panic).

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{docker_skip_reason, run, shared_enclave_pubkey, SshencEnv, SHARED_ENCLAVE_LABEL};
use std::os::unix::fs::PermissionsExt;

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
        "hook signer",
        "hook@e2e.test",
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

fn write_executable_hook(repo: &std::path::Path, name: &str, body: &str) {
    let hook = repo.join(".git").join("hooks").join(name);
    std::fs::create_dir_all(hook.parent().unwrap()).expect("mkdir hooks dir");
    std::fs::write(&hook, body).expect("write hook");
    let mut perms = std::fs::metadata(&hook).expect("stat hook").permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&hook, perms).expect("chmod hook");
}

/// Both pre-commit and post-commit hooks fire on a signed
/// commit, and the resulting commit verifies.
#[test]
#[ignore = "requires docker"]
fn pre_and_post_commit_hooks_fire_alongside_signing() {
    if skip_if_no_docker("pre_and_post_commit_hooks_fire_alongside_signing") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "hooks-repo", &enclave);

    let pre_marker = repo.join("pre-commit-fired");
    let post_marker = repo.join("post-commit-fired");

    write_executable_hook(
        &repo,
        "pre-commit",
        &format!(
            "#!/bin/sh\ntouch {marker}\nexit 0\n",
            marker = pre_marker.display()
        ),
    );
    write_executable_hook(
        &repo,
        "post-commit",
        &format!(
            "#!/bin/sh\ntouch {marker}\nexit 0\n",
            marker = post_marker.display()
        ),
    );

    std::fs::write(repo.join("a.txt"), b"hookable\n").expect("write");
    let add = run(env.git_cmd().current_dir(&repo).args(["add", "a.txt"])).expect("git add");
    assert!(add.succeeded(), "git add: {}", add.stderr);

    let commit =
        run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["commit", "-q", "-m", "hooked + signed"]))
        .expect("git commit");
    assert!(commit.succeeded(), "git commit: {}", commit.stderr);

    assert!(pre_marker.exists(), "pre-commit hook didn't fire");
    assert!(post_marker.exists(), "post-commit hook didn't fire");

    let verify = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(
        verify.succeeded(),
        "verify-commit on hook-affected HEAD failed; stderr:\n{}",
        verify.stderr
    );
}
