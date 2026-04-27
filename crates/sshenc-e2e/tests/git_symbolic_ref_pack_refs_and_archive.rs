// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Three more git plumbing operations on a gitenc-configured
//! repo:
//!
//! - `git symbolic-ref HEAD refs/heads/<new>` rewires HEAD; a
//!   subsequent commit on the rewired branch is signed and
//!   verifies.
//! - `git pack-refs --all` collapses loose refs into a packed
//!   file; signature verification on a packed-ref'd commit
//!   still works.
//! - `git archive --remote <sshenc-url>` enumerates files from
//!   the remote without cloning, exercising the archive
//!   protocol over the agent-mediated SSH channel.

#![cfg(unix)]
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
    assert!(outcome.succeeded(), "remote git init: {}", outcome.stderr);
    format!(
        "ssh://sshtest@127.0.0.1:{port}/home/sshtest/{repo_name}",
        port = container.host_port
    )
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
        "plumbing signer",
        "plumbing@e2e.test",
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

/// `git symbolic-ref HEAD refs/heads/<new>` rewires HEAD; a
/// subsequent commit on the rewired branch is signed and
/// verifies.
#[test]
#[ignore = "requires docker"]
fn symbolic_ref_rewires_head_and_subsequent_commit_signs() {
    if skip_if_no_docker("symbolic_ref_rewires_head_and_subsequent_commit_signs") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "symbolic-ref-repo", &enclave);

    make_commit(&env, &repo, "a.txt", "first\n", "first");

    // Create the target ref before pointing HEAD at it (otherwise
    // git treats the new branch as unborn — which is fine, but
    // pin a specific path here: HEAD points at an existing branch).
    let branch_at = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["branch", "alternate"]))
    .expect("git branch alternate");
    assert!(branch_at.succeeded(), "git branch: {}", branch_at.stderr);

    let symref = run(env.git_cmd().current_dir(&repo).args([
        "symbolic-ref",
        "HEAD",
        "refs/heads/alternate",
    ]))
    .expect("git symbolic-ref");
    assert!(symref.succeeded(), "git symbolic-ref: {}", symref.stderr);

    // A new commit lands on the alternate branch and verifies.
    make_commit(&env, &repo, "b.txt", "second\n", "second on alternate");
    let verify = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(
        verify.succeeded(),
        "verify-commit on alternate HEAD failed; stderr:\n{}",
        verify.stderr
    );

    // HEAD should resolve via refs/heads/alternate.
    let resolved = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["symbolic-ref", "--short", "HEAD"]))
    .expect("symbolic-ref --short");
    assert!(
        resolved.succeeded(),
        "symbolic-ref --short: {}",
        resolved.stderr
    );
    assert_eq!(
        resolved.stdout.trim(),
        "alternate",
        "HEAD should point at alternate; got:\n{}",
        resolved.stdout
    );
}

/// `git pack-refs --all` collapses loose refs into a packed file;
/// `git verify-commit` on a now-packed-ref'd commit still works.
#[test]
#[ignore = "requires docker"]
fn pack_refs_preserves_signature_verification() {
    if skip_if_no_docker("pack_refs_preserves_signature_verification") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "pack-refs-repo", &enclave);

    make_commit(&env, &repo, "a.txt", "first\n", "first");
    // Create some named refs so pack-refs has work to do.
    for branch in ["release", "experimental"] {
        let out =
            run(env.git_cmd().current_dir(&repo).args(["branch", branch])).expect("git branch");
        assert!(out.succeeded(), "git branch {branch}: {}", out.stderr);
    }
    let tag = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["tag", "-s", "v1", "-m", "tag"]))
    .expect("git tag -s");
    assert!(tag.succeeded(), "git tag -s: {}", tag.stderr);

    let pack = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["pack-refs", "--all"]))
    .expect("git pack-refs --all");
    assert!(pack.succeeded(), "git pack-refs: {}", pack.stderr);

    // packed-refs file should now exist and contain our refs.
    let packed_path = repo.join(".git").join("packed-refs");
    assert!(
        packed_path.exists(),
        "packed-refs file not created at {}",
        packed_path.display()
    );
    let packed = std::fs::read_to_string(&packed_path).expect("read packed-refs");
    assert!(
        packed.contains("refs/heads/release") || packed.contains("refs/tags/v1"),
        "packed-refs missing expected entries; got:\n{packed}"
    );

    // Verify the commit and tag through the packed refs.
    let vc = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(
        vc.succeeded(),
        "verify-commit after pack-refs failed; stderr:\n{}",
        vc.stderr
    );
    let vt = run(env.git_cmd().current_dir(&repo).args(["verify-tag", "v1"])).expect("verify-tag");
    assert!(
        vt.succeeded(),
        "verify-tag after pack-refs failed; stderr:\n{}",
        vt.stderr
    );
}

/// `git archive --remote <sshenc-url>` over a sshenc-mediated
/// SSH channel produces a tar stream; the file list matches the
/// remote tree.
#[test]
#[ignore = "requires docker"]
fn git_archive_remote_via_sshenc() {
    if skip_if_no_docker("git_archive_remote_via_sshenc") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let container = SshdContainer::start(&[&enclave]).expect("sshd");
    let remote_url = init_bare_repo(&env, &container, "archive-target.git");

    // Push a tree of files so archive has something interesting.
    let seeder = make_signed_repo(&env, "archive-seeder", &enclave);
    make_commit(&env, &seeder, "f1.txt", "one\n", "one");
    make_commit(&env, &seeder, "f2.txt", "two\n", "two");
    let extra = ssh_extra_args(&env);
    assert!(run(env
        .git_cmd()
        .current_dir(&seeder)
        .args(["remote", "add", "origin", &remote_url]))
    .expect("remote add")
    .succeeded());
    assert!(run(env
        .git_cmd()
        .env("SSHENC_SSH_EXTRA_ARGS", &extra)
        .current_dir(&seeder)
        .args(["push", "-q", "-u", "origin", "main"]))
    .expect("seed push")
    .succeeded());

    // The remote bare repo needs uploadArchive enabled to serve
    // git-archive over the SSH side-channel.
    drop(run(env
        .ssh_cmd(&container)
        .arg("-o")
        .arg(format!("IdentityAgent={}", env.socket_path().display()))
        .arg("sshtest@127.0.0.1")
        .arg(
            "git -C /home/sshtest/archive-target.git config \
             daemon.uploadArchive true",
        )));

    // Stream the archive locally via sshenc ssh.
    let git_ssh = format!(
        "sshenc ssh -F /dev/null \
         -o StrictHostKeyChecking=accept-new \
         -o UserKnownHostsFile={known} \
         -o ConnectTimeout=10 \
         -o NumberOfPasswordPrompts=0 \
         -o PreferredAuthentications=publickey",
        known = env.known_hosts().display()
    );
    let tar_path = env.home().join("archive.tar");
    let archive = run(env
        .git_cmd()
        .env("GIT_SSH_COMMAND", &git_ssh)
        .args(["archive", "--remote", &remote_url, "--format=tar", "HEAD"])
        .arg("-o")
        .arg(&tar_path))
    .expect("git archive --remote");
    assert!(
        archive.succeeded(),
        "git archive --remote failed; stderr:\n{}",
        archive.stderr
    );

    // Inspect the tar to confirm files are present.
    let tar = std::fs::read(&tar_path).expect("read tar");
    assert!(
        tar.len() > 1024,
        "tar suspiciously small: {} bytes",
        tar.len()
    );
    let listing = run(env.scrubbed_command("tar").arg("-tf").arg(&tar_path)).expect("tar -tf");
    assert!(
        listing.succeeded(),
        "tar -tf failed; stderr:\n{}",
        listing.stderr
    );
    assert!(
        listing.stdout.contains("f1.txt") && listing.stdout.contains("f2.txt"),
        "expected f1.txt and f2.txt in archive; got:\n{}",
        listing.stdout
    );
}
