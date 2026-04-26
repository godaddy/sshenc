// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Two git protocol-shape variants the gitenc test files don't
//! cover:
//!
//! 1. `git clone --depth N` (shallow clone) over an sshenc-mediated
//!    SSH remote. Shallow clone uses a different ref-negotiation
//!    sequence (server advertises "shallow" capability, client
//!    sends "shallow"/"deepen" in want lines). The auth path is the
//!    same as a full clone, but a regression that changes how
//!    sshenc passes args to ssh would surface here even if full
//!    clones still work.
//! 2. `git fsck` after a series of agent-backed signed commits is
//!    clean. Pins that the pack format and ref structure remain
//!    valid — a corrupt object would surface as an fsck error.

#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{
    docker_skip_reason, run, shared_enclave_pubkey, SshdContainer, SshencEnv, SHARED_ENCLAVE_LABEL,
};

fn skip_if_no_docker(test_name: &str) -> bool {
    if let Some(reason) = docker_skip_reason() {
        eprintln!("skip {test_name}: {reason}");
        return true;
    }
    false
}

fn ssh_extra_args(env: &SshencEnv) -> String {
    format!(
        "-F /dev/null -o StrictHostKeyChecking=accept-new \
         -o UserKnownHostsFile={known} -o ConnectTimeout=10 \
         -o NumberOfPasswordPrompts=0 -o PreferredAuthentications=publickey",
        known = env.known_hosts().display(),
    )
}

fn init_bare_repo(env: &SshencEnv, container: &SshdContainer, repo_name: &str) -> String {
    let cmd = format!(
        "mkdir -p /home/sshtest/{repo_name} && \
         git init --bare -b main /home/sshtest/{repo_name} >/dev/null"
    );
    let outcome = run(env
        .ssh_cmd(container)
        .arg("-o")
        .arg(format!("IdentityAgent={}", env.socket_path().display()))
        .arg("sshtest@127.0.0.1")
        .arg(cmd))
    .expect("ssh init bare");
    assert!(
        outcome.succeeded(),
        "remote git init failed; stderr:\n{}",
        outcome.stderr
    );
    format!(
        "ssh://sshtest@127.0.0.1:{port}/home/sshtest/{repo_name}",
        port = container.host_port
    )
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

/// `git clone --depth 1` over an sshenc-mediated SSH remote
/// produces a working shallow clone of a populated bare repo.
#[test]
#[ignore = "requires docker"]
fn git_shallow_clone_via_sshenc_succeeds() {
    if skip_if_no_docker("git_shallow_clone_via_sshenc_succeeds") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    plant_meta(
        &env,
        SHARED_ENCLAVE_LABEL,
        "shallow signer",
        "shallow@e2e.test",
    );

    // gitenc --config writes user.signingkey to ~/.ssh/<label>.pub
    // — git's commit signing reads that path and fails ENOENT if
    // we don't actually plant the file. (The other gitenc test
    // helpers do this; the bare init helper here doesn't.)
    let pub_path = env.ssh_dir().join(format!("{SHARED_ENCLAVE_LABEL}.pub"));
    std::fs::create_dir_all(env.ssh_dir()).expect("mkdir ssh dir");
    std::fs::write(&pub_path, format!("{enclave}\n")).expect("write pub");

    let container = SshdContainer::start(&[&enclave]).expect("sshd");
    let remote_url = init_bare_repo(&env, &container, "shallow-target.git");

    // Seed the bare repo with several commits via a temporary local repo.
    let seeder = env.home().join("seeder");
    std::fs::create_dir_all(&seeder).expect("mkdir seeder");
    assert!(env
        .git_cmd()
        .current_dir(&seeder)
        .args(["init", "-q", "-b", "main"])
        .status()
        .expect("git init")
        .success());
    let cfg = run(env
        .gitenc_cmd()
        .expect("gitenc cmd")
        .current_dir(&seeder)
        .args(["--config", SHARED_ENCLAVE_LABEL]))
    .expect("gitenc --config");
    assert!(cfg.succeeded(), "gitenc --config: {}", cfg.stderr);
    let extra = ssh_extra_args(&env);
    let setup =
        run(env
            .git_cmd()
            .current_dir(&seeder)
            .args(["remote", "add", "origin", &remote_url]))
        .expect("remote add");
    assert!(setup.succeeded(), "remote add: {}", setup.stderr);
    for i in 0..5 {
        std::fs::write(
            seeder.join(format!("file{i}.txt")),
            format!("content {i}\n"),
        )
        .expect("write file");
        let add = run(env.git_cmd().current_dir(&seeder).args(["add", "."])).expect("git add");
        assert!(add.succeeded(), "git add: {}", add.stderr);
        let commit = run(env.git_cmd().current_dir(&seeder).args([
            "commit",
            "-q",
            "-m",
            &format!("commit {i}"),
        ]))
        .expect("git commit");
        assert!(commit.succeeded(), "git commit {i}: {}", commit.stderr);
    }
    let push = run(env
        .git_cmd()
        .env("SSHENC_SSH_EXTRA_ARGS", &extra)
        .current_dir(&seeder)
        .args(["push", "-q", "-u", "origin", "main"]))
    .expect("seed push");
    assert!(push.succeeded(), "seed push: {}", push.stderr);

    // Now do a shallow clone of the populated bare repo. The
    // clone target has no .git/config yet, so we have to drive
    // ssh through sshenc explicitly via GIT_SSH_COMMAND with the
    // host-key + identity-agent isolation flags inline.
    let git_ssh = format!(
        "sshenc ssh -F /dev/null \
         -o StrictHostKeyChecking=accept-new \
         -o UserKnownHostsFile={known} \
         -o ConnectTimeout=10 \
         -o NumberOfPasswordPrompts=0 \
         -o PreferredAuthentications=publickey",
        known = env.known_hosts().display()
    );
    let target = env.home().join("shallow-clone");
    let clone = run(env
        .git_cmd()
        .env("SSHENC_SSH_EXTRA_ARGS", &extra)
        .env("GIT_SSH_COMMAND", &git_ssh)
        .args(["clone", "--depth", "1", "-q", &remote_url])
        .arg(&target))
    .expect("git clone --depth 1");
    assert!(
        clone.succeeded(),
        "git clone --depth 1 failed; stderr:\n{}",
        clone.stderr
    );

    // Verify shallow: there should be exactly 1 commit reachable
    // and the .git/shallow file should exist.
    let log = run(env
        .git_cmd()
        .current_dir(&target)
        .args(["rev-list", "--count", "HEAD"]))
    .expect("git rev-list");
    assert!(log.succeeded(), "git rev-list: {}", log.stderr);
    assert_eq!(
        log.stdout.trim(),
        "1",
        "expected 1 commit in shallow clone, got {}",
        log.stdout.trim()
    );
    assert!(
        target.join(".git").join("shallow").exists(),
        "shallow clone should have .git/shallow marker"
    );
}

/// `git fsck --strict` is clean after a sequence of agent-backed
/// signed commits. Pins that signing doesn't corrupt the object
/// store or refs.
#[test]
#[ignore = "requires docker"]
fn git_fsck_clean_after_signed_commits() {
    if skip_if_no_docker("git_fsck_clean_after_signed_commits") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    plant_meta(&env, SHARED_ENCLAVE_LABEL, "fsck signer", "fsck@e2e.test");

    let pub_path = env.ssh_dir().join(format!("{SHARED_ENCLAVE_LABEL}.pub"));
    std::fs::create_dir_all(env.ssh_dir()).expect("mkdir ssh dir");
    std::fs::write(&pub_path, format!("{enclave}\n")).expect("write pub");

    let repo = env.home().join("fsck-repo");
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

    for i in 0..3 {
        std::fs::write(repo.join(format!("f{i}.txt")), format!("body {i}\n")).expect("write");
        let add = run(env.git_cmd().current_dir(&repo).args(["add", "."])).expect("git add");
        assert!(add.succeeded(), "git add: {}", add.stderr);
        let commit = run(env.git_cmd().current_dir(&repo).args([
            "commit",
            "-q",
            "-m",
            &format!("signed-{i}"),
        ]))
        .expect("git commit");
        assert!(commit.succeeded(), "git commit {i}: {}", commit.stderr);
    }

    let fsck = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["fsck", "--strict", "--no-progress"]))
    .expect("git fsck");
    assert!(
        fsck.succeeded(),
        "git fsck --strict failed after signed commits; stdout:\n{}\nstderr:\n{}",
        fsck.stdout,
        fsck.stderr
    );
    // fsck output to stderr should be empty (no warnings) on a
    // clean repo. Be lenient about info-level messages but fail
    // on "error", "missing", or "corrupt".
    let lower = fsck.stderr.to_lowercase();
    for bad in ["error", "missing", "corrupt", "broken"] {
        assert!(
            !lower.contains(bad),
            "git fsck stderr contains '{bad}':\n{}",
            fsck.stderr
        );
    }
}
