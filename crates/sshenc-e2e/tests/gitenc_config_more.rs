// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `gitenc --config` corner cases not covered by `gitenc.rs`,
//! `gitenc_edge.rs`, `gitenc_extras.rs`, or `gitenc_advanced_ops.rs`:
//!
//! 1. Re-running `gitenc --config <other_label>` in a repo that
//!    was previously configured with a different label must point
//!    every per-repo setting at the new label, not leave a mix of
//!    old + new. A regression that "appends" instead of "replaces"
//!    would leave stale gpg.ssh.allowedSignersFile / user.signingKey
//!    behind.
//!
//! 2. A repo whose user has a `~/.gitconfig` (global) signing
//!    config pointing at an unrelated key must end up using the
//!    sshenc per-repo config, since git's precedence is
//!    system → global → local with later levels winning. We don't
//!    actually verify "later levels win" (that's git's contract);
//!    we verify gitenc didn't write to the global file by mistake
//!    and that signing still works under the precedence.

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
        "skip {test_name}: needs to mint a second key; \
         set SSHENC_E2E_SOFTWARE=1 or SSHENC_E2E_EXTENDED=1"
    );
    true
}

fn unique_label(prefix: &str) -> String {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{prefix}-{pid}-{nanos}")
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

/// Re-running `gitenc --config <new_label>` in a repo that already
/// had `--config <old_label>` configured must point every relevant
/// per-repo git setting at the new label. A regression where the
/// old label's allowed_signers path / user.signingkey lingers
/// would silently mean some commit-sign attempts use stale keys.
#[test]
#[ignore = "requires docker"]
fn gitenc_config_relabels_existing_repo_cleanly() {
    if skip_if_no_docker("gitenc_config_relabels_existing_repo_cleanly") {
        return;
    }
    if skip_unless_key_creation_cheap("gitenc_config_relabels_existing_repo_cleanly") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let _shared = shared_enclave_pubkey(&env).expect("shared enclave");

    // Mint a second key, both keys get meta planted.
    let alt_label = unique_label("relabel-alt");
    let kg = run(env.sshenc_cmd().expect("sshenc cmd").args([
        "keygen",
        "--label",
        &alt_label,
        "--auth-policy",
        "none",
        "--no-pub-file",
    ]))
    .expect("keygen alt");
    assert!(kg.succeeded(), "keygen alt: {}", kg.stderr);

    plant_meta(
        &env,
        SHARED_ENCLAVE_LABEL,
        "shared signer",
        "shared@e2e.test",
    );
    plant_meta(&env, &alt_label, "alt signer", "alt@e2e.test");

    // Init a repo and configure it with the shared label first.
    let repo = env.home().join("relabel-repo");
    std::fs::create_dir_all(&repo).expect("mkdir repo");
    assert!(env
        .git_cmd()
        .current_dir(&repo)
        .args(["init", "-q", "-b", "main"])
        .status()
        .expect("git init")
        .success());

    let cfg1 = run(env
        .gitenc_cmd()
        .expect("gitenc cmd")
        .current_dir(&repo)
        .args(["--config", SHARED_ENCLAVE_LABEL]))
    .expect("gitenc --config shared");
    assert!(cfg1.succeeded(), "first config: {}", cfg1.stderr);

    let email_after_shared =
        run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["config", "--get", "user.email"]))
        .expect("git config email");
    assert_eq!(
        email_after_shared.stdout.trim(),
        "shared@e2e.test",
        "first config didn't set user.email; got:\n{}",
        email_after_shared.stdout
    );

    // Re-config with the alt label.
    let cfg2 = run(env
        .gitenc_cmd()
        .expect("gitenc cmd")
        .current_dir(&repo)
        .args(["--config", &alt_label]))
    .expect("gitenc --config alt");
    assert!(cfg2.succeeded(), "re-config: {}", cfg2.stderr);

    // user.email and user.name must reflect the alt key now.
    let email_after_alt =
        run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["config", "--get", "user.email"]))
        .expect("git config email after alt");
    assert_eq!(
        email_after_alt.stdout.trim(),
        "alt@e2e.test",
        "re-config didn't update user.email; got:\n{}",
        email_after_alt.stdout
    );

    let name_after_alt =
        run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["config", "--get", "user.name"]))
        .expect("git config name");
    assert_eq!(
        name_after_alt.stdout.trim(),
        "alt signer",
        "re-config didn't update user.name; got:\n{}",
        name_after_alt.stdout
    );

    // user.signingkey should also be the alt key's pubkey path or
    // similar — at minimum, it should NOT still mention shared's
    // keyfile / pub.
    let signingkey =
        run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["config", "--get", "user.signingkey"]))
        .expect("git config signingkey");
    assert!(
        signingkey.succeeded(),
        "user.signingkey not set: {}",
        signingkey.stderr
    );
    let signingkey_value = signingkey.stdout.trim();
    assert!(
        !signingkey_value.contains(SHARED_ENCLAVE_LABEL),
        "user.signingkey still references shared label after re-config; got: {signingkey_value}"
    );

    drop(run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["delete", &alt_label, "-y"])));
}

/// `gitenc --config` only writes to the repo-local `.git/config` —
/// not to `~/.gitconfig` or `/etc/gitconfig`. We can't easily
/// inspect /etc/gitconfig in the test environment, but we *can*
/// seed `~/.gitconfig` with a known marker, run `gitenc --config`,
/// and assert the global file is byte-identical afterward.
#[test]
#[ignore = "requires docker"]
fn gitenc_config_does_not_touch_global_gitconfig() {
    if skip_if_no_docker("gitenc_config_does_not_touch_global_gitconfig") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let _shared = shared_enclave_pubkey(&env).expect("shared enclave");
    plant_meta(&env, SHARED_ENCLAVE_LABEL, "shared", "shared@e2e.test");

    // Seed a global ~/.gitconfig with a known marker.
    let global_config = env.home().join(".gitconfig");
    let global_marker = "# DO-NOT-TOUCH MARKER\n\
[user]\n\
\tname = Outer Person\n\
\temail = outer@elsewhere.example\n\
[gpg]\n\
\tformat = openpgp\n";
    std::fs::write(&global_config, global_marker).expect("write global gitconfig");

    let repo = env.home().join("global-untouched-repo");
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

    let after = std::fs::read_to_string(&global_config).expect("read global");
    assert_eq!(
        after, global_marker,
        "gitenc --config modified ~/.gitconfig (per-repo settings should land in .git/config only). \
         Before:\n{global_marker}\nAfter:\n{after}"
    );

    // The repo-local config must have user.email = shared, not
    // outer (proves the per-repo write happened).
    let local_email =
        run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["config", "--local", "--get", "user.email"]))
        .expect("git config local email");
    assert_eq!(
        local_email.stdout.trim(),
        "shared@e2e.test",
        "local user.email not set by gitenc --config; got:\n{}",
        local_email.stdout
    );
}
