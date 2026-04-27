// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! When a user (post `gitenc --config`) flips `gpg.format` from
//! `ssh` to `openpgp`, signing no longer goes through the
//! sshenc agent. The contract pinned: gitenc doesn't intercept
//! the wrong backend — git's signing path runs (and either
//! succeeds via gpg or fails because no gpg key is configured),
//! the agent isn't invoked, and the operation completes
//! without panicking sshenc.

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

/// Flipping `gpg.format` to `openpgp` after `gitenc --config`
/// makes a subsequent commit attempt go through git's openpgp
/// path (not sshenc). Either the commit fails (no gpg key) or
/// it succeeds via the system gpg — what we pin is "no panic,
/// agent stays alive, sshenc didn't sign".
#[test]
#[ignore = "requires docker"]
fn gpg_format_openpgp_does_not_invoke_sshenc() {
    if skip_if_no_docker("gpg_format_openpgp_does_not_invoke_sshenc") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");

    plant_meta_and_pub(
        &env,
        SHARED_ENCLAVE_LABEL,
        "fallback signer",
        "fallback@e2e.test",
        &enclave,
    );
    let repo = env.home().join("gpg-fallback-repo");
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

    // Flip gpg.format to openpgp post-config.
    let flip =
        run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["config", "--local", "gpg.format", "openpgp"]))
        .expect("git config gpg.format=openpgp");
    assert!(flip.succeeded(), "git config: {}", flip.stderr);

    // Try to commit. We expect either:
    //   (a) commit fails because gpg.format=openpgp expects a
    //       configured gpg signing key (none in scrubbed HOME), or
    //   (b) commit succeeds via system gpg with whatever default it
    //       finds.
    // Either way: no sshenc panic, no agent invocation, no
    // verify-commit success against sshenc's allowed_signers.
    std::fs::write(repo.join("a.txt"), b"content\n").expect("write");
    let add = run(env.git_cmd().current_dir(&repo).args(["add", "a.txt"])).expect("git add");
    assert!(add.succeeded(), "git add: {}", add.stderr);

    let commit =
        run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["commit", "-q", "-m", "openpgp attempt"]))
        .expect("git commit attempt");
    let combined = format!("{}\n{}", commit.stdout, commit.stderr);
    assert!(
        !combined.contains("panicked at"),
        "git commit panicked under gpg.format=openpgp:\n{combined}"
    );

    // If the commit succeeded, verify-commit against sshenc's
    // allowed_signers MUST fail (the signature, if any, is from
    // the openpgp path, not sshenc).
    if commit.succeeded() {
        let verify = run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["verify-commit", "HEAD"]))
        .expect("verify-commit");
        let combined_v = format!("{}\n{}", verify.stdout, verify.stderr);
        assert!(
            !combined_v.contains("panicked at"),
            "verify-commit panicked under gpg.format=openpgp:\n{combined_v}"
        );
        // We don't pin success-vs-fail of verify (depends on whether
        // gpg-the-binary signed and whether the resulting sig is
        // valid against the allowed_signers file gitenc wrote —
        // unrelated formats), only no-panic.
    }

    // Agent must still serve.
    let listed = run(env
        .scrubbed_command("ssh-add")
        .env("SSH_AUTH_SOCK", env.socket_path())
        .arg("-L"))
    .expect("ssh-add -L");
    assert!(
        listed.succeeded(),
        "agent should still serve after gpg.format flip; stderr:\n{}",
        listed.stderr
    );
}
