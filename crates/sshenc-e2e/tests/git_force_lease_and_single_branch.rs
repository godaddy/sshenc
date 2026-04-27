// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Git remote-protocol contracts over the gitenc-mediated SSH
//! path that aren't covered by the standard push/pull/fetch
//! happy-paths in `gitenc.rs`, `git_verify_pull_show_sig.rs`,
//! `git_protocol_variants.rs`, or `git_fetch_and_partial_clone.rs`:
//!
//! - `git push --force-with-lease` succeeds when the lease
//!   matches the actual upstream sha. Exercises the multi-phase
//!   ref-query+push flow under sshenc agent auth (distinct from
//!   plain `push` because the lease check requires reading the
//!   remote's current ref before the push frame).
//! - `git clone --single-branch -b <branch>` tracks only the
//!   requested branch — distinct from `--depth 1` (shallow) and
//!   `--filter=blob:none` (partial), which are pinned elsewhere.

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
        "remote signer",
        "remote@e2e.test",
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

/// `git push --force-with-lease` over the gitenc SSH path
/// completes when the lease matches actual upstream.
#[test]
#[ignore = "requires docker"]
fn push_force_with_lease_matching_succeeds() {
    if skip_if_no_docker("push_force_with_lease_matching_succeeds") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let container = SshdContainer::start(&[&enclave]).expect("sshd");
    let remote_url = init_bare_repo(&env, &container, "fwl-target.git");

    let repo = make_signed_repo(&env, "fwl-repo", &enclave);
    make_commit(&env, &repo, "f.txt", "first\n", "first");
    let extra = ssh_extra_args(&env);
    assert!(run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["remote", "add", "origin", &remote_url]))
    .expect("remote add")
    .succeeded());
    let push = run(env
        .git_cmd()
        .env("SSHENC_SSH_EXTRA_ARGS", &extra)
        .current_dir(&repo)
        .args(["push", "-q", "-u", "origin", "main"]))
    .expect("push");
    assert!(push.succeeded(), "initial push: {}", push.stderr);

    make_commit(&env, &repo, "f.txt", "second\n", "second");
    let fwl = run(env
        .git_cmd()
        .env("SSHENC_SSH_EXTRA_ARGS", &extra)
        .current_dir(&repo)
        .args(["push", "-q", "--force-with-lease", "origin", "main"]))
    .expect("push --force-with-lease");
    assert!(
        fwl.succeeded(),
        "force-with-lease push (matching lease) should succeed; stdout:\n{}\nstderr:\n{}",
        fwl.stdout,
        fwl.stderr
    );
}

/// `git clone --single-branch -b main` over the gitenc SSH path
/// tracks only the requested branch.
#[test]
#[ignore = "requires docker"]
fn clone_single_branch_tracks_only_one() {
    if skip_if_no_docker("clone_single_branch_tracks_only_one") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let container = SshdContainer::start(&[&enclave]).expect("sshd");
    let remote_url = init_bare_repo(&env, &container, "single-branch-target.git");

    let seeder = make_signed_repo(&env, "single-branch-seeder", &enclave);
    make_commit(&env, &seeder, "f.txt", "main\n", "main commit");
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
    .expect("seed push main")
    .succeeded());
    for branch in ["branch-a", "branch-b"] {
        assert!(env
            .git_cmd()
            .current_dir(&seeder)
            .args(["checkout", "-q", "-b", branch])
            .status()
            .expect("checkout")
            .success());
        make_commit(&env, &seeder, "f.txt", &format!("{branch}\n"), branch);
        assert!(run(env
            .git_cmd()
            .env("SSHENC_SSH_EXTRA_ARGS", &extra)
            .current_dir(&seeder)
            .args(["push", "-q", "-u", "origin", branch]))
        .expect("seed push branch")
        .succeeded());
    }

    let git_ssh = format!(
        "sshenc ssh -F /dev/null \
         -o StrictHostKeyChecking=accept-new \
         -o UserKnownHostsFile={known} \
         -o ConnectTimeout=10 \
         -o NumberOfPasswordPrompts=0 \
         -o PreferredAuthentications=publickey",
        known = env.known_hosts().display()
    );
    let consumer = env.home().join("single-branch-consumer");
    let clone = run(env
        .git_cmd()
        .env("GIT_SSH_COMMAND", &git_ssh)
        .args(["clone", "-q", "--single-branch", "-b", "main", &remote_url])
        .arg(&consumer))
    .expect("clone --single-branch");
    assert!(clone.succeeded(), "clone: {}", clone.stderr);

    let branches =
        run(env.git_cmd().current_dir(&consumer).args(["branch", "-r"])).expect("git branch -r");
    assert!(branches.succeeded(), "branch -r: {}", branches.stderr);
    let remote_branches: Vec<&str> = branches
        .stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.contains("HEAD"))
        .collect();
    assert_eq!(
        remote_branches.len(),
        1,
        "single-branch clone should track only 1 remote branch; got: {remote_branches:?}"
    );
    assert!(
        remote_branches[0].ends_with("/main"),
        "expected origin/main; got: {remote_branches:?}"
    );
}
