// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Two contracts that complement the existing
//! `git verify-commit` coverage:
//!
//! - `git show --show-signature HEAD` on an sshenc-signed
//!   commit emits a "Good signature" line in human-readable
//!   form. Distinct from the verify-commit exit code: this is
//!   the user-visible UI surface.
//! - `git gc --aggressive` followed by `git verify-commit
//!   HEAD` still verifies the commit. Repacking must not
//!   corrupt the embedded signature blob in the commit object.

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
        "show-sig signer",
        "showsig@e2e.test",
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

/// `git show --show-signature HEAD` displays a "Good signature"
/// line in its human-readable output for an sshenc-signed commit.
#[test]
#[ignore = "requires docker"]
fn git_show_signature_emits_good_signature_line() {
    if skip_if_no_docker("git_show_signature_emits_good_signature_line") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "show-sig-repo", &enclave);
    make_commit(&env, &repo, "a.txt", "first\n", "first");

    let show = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["show", "--show-signature", "HEAD"]))
    .expect("git show --show-signature");
    assert!(show.succeeded(), "git show: {}", show.stderr);
    let combined = format!("{}\n{}", show.stdout, show.stderr);
    assert!(
        combined.contains("Good \"git\" signature") || combined.contains("Good signature"),
        "expected 'Good signature' in show --show-signature output; got:\n{combined}"
    );
}

/// `git gc --aggressive` (object repacking) followed by
/// `git verify-commit HEAD` still validates the signature on
/// repacked objects.
#[test]
#[ignore = "requires docker"]
fn git_gc_aggressive_preserves_signature_validity() {
    if skip_if_no_docker("git_gc_aggressive_preserves_signature_validity") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "gc-repo", &enclave);

    // Multiple commits to give gc something to repack.
    for i in 0..3 {
        make_commit(
            &env,
            &repo,
            &format!("f{i}.txt"),
            &format!("v{i}\n"),
            &format!("c{i}"),
        );
    }

    let gc = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["gc", "--aggressive", "--quiet"]))
    .expect("git gc");
    assert!(gc.succeeded(), "git gc --aggressive: {}", gc.stderr);

    // After repack, all three commits must still verify.
    for rev in ["HEAD", "HEAD~1", "HEAD~2"] {
        let verify = run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["verify-commit", rev]))
        .expect("verify-commit");
        assert!(
            verify.succeeded(),
            "verify-commit on {rev} after gc failed; stderr:\n{}",
            verify.stderr
        );
    }
}
