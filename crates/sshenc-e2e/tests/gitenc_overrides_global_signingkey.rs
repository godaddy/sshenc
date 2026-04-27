// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! When the user already has a `user.signingkey` set in their
//! global git config, `gitenc --config <label>` in a repo writes
//! a per-repo `user.signingkey` whose value takes precedence
//! locally — and does NOT touch the global config. Existing
//! `gitenc_config_more.rs` covers "global isn't disturbed";
//! this pins the orthogonal "local overrides global precedence"
//! contract by checking that signing actually uses the local
//! key (not the bogus global one).

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

/// Pre-existing global `user.signingkey` is overridden by
/// gitenc's per-repo config; signing uses the local label's
/// pub, not the global bogus path; the global value is
/// untouched.
#[test]
#[ignore = "requires docker"]
fn local_signingkey_takes_precedence_over_pre_set_global() {
    if skip_if_no_docker("local_signingkey_takes_precedence_over_pre_set_global") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");

    plant_meta_and_pub(
        &env,
        SHARED_ENCLAVE_LABEL,
        "global-vs-local",
        "globallocal@e2e.test",
        &enclave,
    );

    // Pre-seed a global `~/.gitconfig` with a bogus
    // user.signingkey value.
    let bogus_global = env.home().join("not-the-real-key.pub");
    std::fs::write(&bogus_global, "ssh-bogus FAKE not-real\n").expect("write bogus global pub");
    let global_gitconfig = env.home().join(".gitconfig");
    std::fs::write(
        &global_gitconfig,
        format!(
            "[user]\n\tname = global user\n\temail = global@e2e.test\n\tsigningkey = {}\n",
            bogus_global.display()
        ),
    )
    .expect("write global gitconfig");

    // Set up a repo and run gitenc --config.
    let repo = env.home().join("global-vs-local-repo");
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

    // The global config still references the bogus value.
    let global_after = std::fs::read_to_string(&global_gitconfig).expect("read global");
    assert!(
        global_after.contains("not-the-real-key.pub"),
        "global config should not be touched; got:\n{global_after}"
    );

    // The local config has its own user.signingkey.
    let local_key = run(env.git_cmd().current_dir(&repo).args([
        "config",
        "--local",
        "--get",
        "user.signingkey",
    ]))
    .expect("git config --local --get user.signingkey");
    assert!(
        local_key.succeeded(),
        "expected local user.signingkey; stderr:\n{}",
        local_key.stderr
    );
    let local_path = local_key.stdout.trim();
    assert!(
        !local_path.contains("not-the-real-key"),
        "local user.signingkey should NOT be the bogus global value; got: {local_path}"
    );

    // A signed commit must use the local key (verifies cleanly).
    std::fs::write(repo.join("a.txt"), b"signed\n").expect("write");
    let add = run(env.git_cmd().current_dir(&repo).args(["add", "a.txt"])).expect("git add");
    assert!(add.succeeded(), "git add: {}", add.stderr);
    let commit = run(env.git_cmd().current_dir(&repo).args([
        "commit",
        "-q",
        "-m",
        "signed via local override",
    ]))
    .expect("git commit");
    assert!(
        commit.succeeded(),
        "git commit failed; stderr:\n{}",
        commit.stderr
    );
    let verify = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(
        verify.succeeded(),
        "verify-commit failed under global+local config; stderr:\n{}",
        verify.stderr
    );
}
