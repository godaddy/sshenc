// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Git signature-verification surfaces and SSH IdentityAgent
//! corners:
//!
//! 1. `git verify-tag <tag>` accepts an sshenc-signed annotated
//!    tag. Distinct surface from `verify-commit`.
//! 2. `gpg.ssh.allowedSignersFile` written by gitenc with a
//!    tilde-expanded path is interpreted by `git verify-commit`
//!    against the same file gitenc points at.
//! 3. `git verify-commit` against a missing
//!    `gpg.ssh.allowedSignersFile` errors cleanly without
//!    crashing.
//! 4. `ssh -o IdentityAgent=none` explicitly suppresses agent
//!    delegation; ssh tries on-disk identities only.
//! 5. `git diff --no-index a.txt b.txt` (file compare outside
//!    a repo) doesn't trigger any gitenc/agent machinery.

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
        "tag signer",
        "tag@e2e.test",
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

/// `git tag -s` produces a signed annotated tag; `git verify-tag`
/// accepts it using the `gpg.ssh.allowedSignersFile` gitenc
/// wrote. Pins tag verification specifically (commit verification
/// is in `git_verify_pull_show_sig.rs`).
#[test]
#[ignore = "requires docker"]
fn git_verify_tag_accepts_sshenc_signed_tag() {
    if skip_if_no_docker("git_verify_tag_accepts_sshenc_signed_tag") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "verify-tag-repo", &enclave);

    std::fs::write(repo.join("a.txt"), b"tag-target\n").expect("write");
    drop(run(env.git_cmd().current_dir(&repo).args(["add", "."])));
    drop(run(env.git_cmd().current_dir(&repo).args([
        "commit",
        "-q",
        "-m",
        "tag-target-commit",
    ])));
    let tag =
        run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["tag", "-s", "v1.0", "-m", "first signed tag"]))
        .expect("git tag -s");
    assert!(tag.succeeded(), "git tag -s: {}", tag.stderr);

    let verify = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-tag", "v1.0"]))
    .expect("git verify-tag");
    assert!(
        verify.succeeded(),
        "git verify-tag failed; stdout:\n{}\nstderr:\n{}",
        verify.stdout,
        verify.stderr
    );

    // `git tag -v` is the alias.
    let verify_alias =
        run(env.git_cmd().current_dir(&repo).args(["tag", "-v", "v1.0"])).expect("git tag -v");
    assert!(
        verify_alias.succeeded(),
        "git tag -v alias failed; stderr:\n{}",
        verify_alias.stderr
    );
}

/// `gpg.ssh.allowedSignersFile` written by gitenc resolves
/// against the same path `git verify-commit` reads. Pins that
/// path-resolution doesn't diverge between the writer and the
/// verifier.
#[test]
#[ignore = "requires docker"]
fn allowed_signers_path_round_trips_writer_to_verifier() {
    if skip_if_no_docker("allowed_signers_path_round_trips_writer_to_verifier") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "path-roundtrip-repo", &enclave);

    let recorded = run(env.git_cmd().current_dir(&repo).args([
        "config",
        "--local",
        "--get",
        "gpg.ssh.allowedSignersFile",
    ]))
    .expect("git config");
    assert!(
        recorded.succeeded(),
        "gitenc --config didn't set allowedSignersFile: {}",
        recorded.stderr
    );
    let recorded_path = recorded.stdout.trim();
    assert!(
        !recorded_path.is_empty(),
        "allowedSignersFile is empty after gitenc --config"
    );

    // Make a signed commit and verify — exercises the path
    // resolution end-to-end.
    std::fs::write(repo.join("a.txt"), b"signed\n").expect("write");
    drop(run(env.git_cmd().current_dir(&repo).args(["add", "."])));
    drop(run(env.git_cmd().current_dir(&repo).args([
        "commit",
        "-q",
        "-m",
        "signed-commit",
    ])));
    let verify = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("git verify-commit");
    assert!(
        verify.succeeded(),
        "verify-commit didn't accept the signature; \
         allowed-signers path: {recorded_path}\nstderr:\n{}",
        verify.stderr
    );
}

/// `git verify-commit` against a configured but missing
/// allowed_signers file errors cleanly without panicking.
#[test]
#[ignore = "requires docker"]
fn verify_commit_with_missing_allowed_signers_errors_cleanly() {
    if skip_if_no_docker("verify_commit_with_missing_allowed_signers_errors_cleanly") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "missing-signers-repo", &enclave);

    std::fs::write(repo.join("a.txt"), b"signed\n").expect("write");
    drop(run(env.git_cmd().current_dir(&repo).args(["add", "."])));
    drop(run(env.git_cmd().current_dir(&repo).args([
        "commit",
        "-q",
        "-m",
        "to-verify",
    ])));

    // Repoint allowedSignersFile at a path that doesn't exist.
    let bogus = env.home().join("does-not-exist-allowed-signers");
    drop(run(env.git_cmd().current_dir(&repo).args([
        "config",
        "--local",
        "gpg.ssh.allowedSignersFile",
        bogus.to_str().expect("utf-8"),
    ])));

    let verify = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(
        !verify.succeeded(),
        "verify-commit with missing signers file should fail; stdout:\n{}\nstderr:\n{}",
        verify.stdout,
        verify.stderr
    );
    let combined = format!("{}\n{}", verify.stdout, verify.stderr);
    assert!(
        !combined.contains("panicked at"),
        "verify-commit panicked on missing signers file:\n{combined}"
    );
}

/// `ssh -o IdentityAgent=none` should suppress agent delegation
/// entirely. Without on-disk identities and without the agent,
/// pubkey auth has no key to offer — the connection fails with
/// "Permission denied (publickey)". Pin that the wrapper honors
/// `IdentityAgent=none` (doesn't override it back to the sshenc
/// socket).
#[test]
#[ignore = "requires docker"]
fn ssh_identity_agent_none_suppresses_sshenc_agent() {
    if skip_if_no_docker("ssh_identity_agent_none_suppresses_sshenc_agent") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let container = sshenc_e2e::SshdContainer::start(&[&enclave]).expect("sshd");

    let outcome = run(env
        .scrubbed_command("ssh")
        .arg("-p")
        .arg(container.host_port.to_string())
        .arg("-F")
        .arg("/dev/null")
        .arg("-o")
        .arg("StrictHostKeyChecking=accept-new")
        .arg("-o")
        .arg(format!(
            "UserKnownHostsFile={}",
            env.known_hosts().display()
        ))
        .arg("-o")
        .arg("IdentityAgent=none")
        .arg("-o")
        .arg("IdentitiesOnly=yes")
        .arg("-o")
        .arg("ConnectTimeout=10")
        .arg("-o")
        .arg("PreferredAuthentications=publickey")
        .arg("-o")
        .arg("NumberOfPasswordPrompts=0")
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("sshtest@127.0.0.1")
        .arg("--")
        .arg("echo should-not-reach"))
    .expect("ssh -o IdentityAgent=none");

    // No agent + IdentitiesOnly + no IdentityFile → publickey
    // can't offer anything → connection rejected.
    assert!(
        !outcome.succeeded(),
        "ssh with IdentityAgent=none and no on-disk key shouldn't auth; stdout:\n{}\nstderr:\n{}",
        outcome.stdout,
        outcome.stderr
    );
    assert!(
        !outcome.stdout.contains("should-not-reach"),
        "remote command shouldn't have run; got:\n{}",
        outcome.stdout
    );
}

/// `git diff --no-index <a> <b>` is a "compare-two-files" mode
/// that doesn't require a git repo. gitenc's gpg.ssh.* settings
/// only activate inside a repo; pin that diff --no-index
/// outside any repo doesn't trip into the gitenc machinery.
#[test]
#[ignore = "requires docker"]
fn git_diff_no_index_outside_repo_does_not_invoke_gitenc() {
    if skip_if_no_docker("git_diff_no_index_outside_repo_does_not_invoke_gitenc") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let _shared = shared_enclave_pubkey(&env).expect("shared enclave");

    // Create two files in HOME (not a git repo).
    let a = env.home().join("a.txt");
    let b = env.home().join("b.txt");
    std::fs::write(&a, b"line one\n").expect("write a");
    std::fs::write(&b, b"line two\n").expect("write b");

    let outcome = run(env
        .git_cmd()
        .current_dir(env.home())
        .args(["diff", "--no-index", "--exit-code"])
        .arg("a.txt")
        .arg("b.txt"))
    .expect("git diff --no-index");

    // Files differ → exit code 1 (per --exit-code semantics).
    // What matters: stderr doesn't surface a gitenc/agent error,
    // and the diff content shows both files.
    let stderr_lower = outcome.stderr.to_lowercase();
    assert!(
        !stderr_lower.contains("agent")
            && !stderr_lower.contains("gitenc:")
            && !stderr_lower.contains("sshenc:")
            && !stderr_lower.contains("panicked"),
        "git diff --no-index surfaced gitenc/agent error; stdout:\n{}\nstderr:\n{}",
        outcome.stdout,
        outcome.stderr
    );
    assert!(
        outcome.stdout.contains("line one") || outcome.stdout.contains("line two"),
        "expected diff content; got:\n{}",
        outcome.stdout
    );
}
