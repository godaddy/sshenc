// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Three git fetch/clone variants that exchange different wire
//! sequences than plain fetch/clone — pinning the agent-mediated
//! SSH path doesn't regress for any of them:
//!
//! 1. `git fetch --prune` deletes local tracking refs whose
//!    upstream is gone. The wire dialog includes the server's
//!    full ref list; the client computes the prune set locally.
//! 2. `git fetch --tags` discovers and pulls remote tags
//!    (including unreachable ones), exchanging tag refs in the
//!    advertise.
//! 3. `git clone --filter=blob:none` (partial clone) sets up a
//!    promisor-remote relationship and skips fetching blobs
//!    until needed; uses the protocol-v2 capability negotiation.

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

fn git_ssh_command(env: &SshencEnv) -> String {
    format!(
        "sshenc ssh -F /dev/null \
         -o StrictHostKeyChecking=accept-new \
         -o UserKnownHostsFile={known} \
         -o ConnectTimeout=10 \
         -o NumberOfPasswordPrompts=0 \
         -o PreferredAuthentications=publickey",
        known = env.known_hosts().display()
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

fn make_repo_pushed_with_branch(
    env: &SshencEnv,
    enclave: &str,
    name: &str,
    branches: &[(&str, &str, &str)],
    remote_url: &str,
) -> std::path::PathBuf {
    plant_meta_and_pub(
        env,
        SHARED_ENCLAVE_LABEL,
        "fetch signer",
        "fetch@e2e.test",
        enclave,
    );
    let repo = env.home().join(name);
    std::fs::create_dir_all(&repo).expect("mkdir repo");
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
    let extra = ssh_extra_args(env);
    assert!(run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["remote", "add", "origin", remote_url]))
    .expect("remote add")
    .succeeded());

    // Initial main commit.
    std::fs::write(repo.join("README"), b"main\n").expect("write");
    let add = run(env.git_cmd().current_dir(&repo).args(["add", "."])).expect("git add");
    assert!(add.succeeded());
    let commit = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["commit", "-q", "-m", "initial"]))
    .expect("git commit");
    assert!(commit.succeeded());
    assert!(run(env
        .git_cmd()
        .env("SSHENC_SSH_EXTRA_ARGS", &extra)
        .current_dir(&repo)
        .args(["push", "-q", "-u", "origin", "main"]))
    .expect("push main")
    .succeeded());

    // Side branches each get a single commit + push.
    for (branch, file, body) in branches {
        let co = run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["checkout", "-q", "-b", branch, "main"]))
        .expect("checkout");
        assert!(co.succeeded(), "checkout {branch}: {}", co.stderr);
        std::fs::write(repo.join(file), body.as_bytes()).expect("write");
        let add = run(env.git_cmd().current_dir(&repo).args(["add", file])).expect("git add");
        assert!(add.succeeded());
        let commit = run(env.git_cmd().current_dir(&repo).args([
            "commit",
            "-q",
            "-m",
            &format!("on-{branch}"),
        ]))
        .expect("git commit");
        assert!(commit.succeeded());
        assert!(run(env
            .git_cmd()
            .env("SSHENC_SSH_EXTRA_ARGS", &extra)
            .current_dir(&repo)
            .args(["push", "-q", "-u", "origin", branch]))
        .expect("push branch")
        .succeeded());
    }
    repo
}

/// `git fetch --prune` after a remote branch is deleted on the
/// server cleans up the local tracking ref.
#[test]
#[ignore = "requires docker"]
fn git_fetch_prune_drops_deleted_remote_branch() {
    if skip_if_no_docker("git_fetch_prune_drops_deleted_remote_branch") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let container = SshdContainer::start(&[&enclave]).expect("sshd");
    let remote_url = init_bare_repo(&env, &container, "prune-target.git");

    let seeder = make_repo_pushed_with_branch(
        &env,
        &enclave,
        "prune-seeder",
        &[("doomed", "f.txt", "doomed body\n")],
        &remote_url,
    );

    // Consumer clones, sees the doomed branch.
    let git_ssh = git_ssh_command(&env);
    let consumer = env.home().join("prune-consumer");
    let clone = run(env
        .git_cmd()
        .env("GIT_SSH_COMMAND", &git_ssh)
        .args(["clone", "-q", &remote_url])
        .arg(&consumer))
    .expect("clone");
    assert!(clone.succeeded(), "clone: {}", clone.stderr);

    let pre =
        run(env.git_cmd().current_dir(&consumer).args(["branch", "-r"])).expect("branch -r pre");
    assert!(
        pre.stdout.contains("origin/doomed"),
        "consumer should see origin/doomed before prune; got:\n{}",
        pre.stdout
    );

    // Seeder deletes the doomed branch on the remote.
    let extra = ssh_extra_args(&env);
    let del = run(env
        .git_cmd()
        .env("SSHENC_SSH_EXTRA_ARGS", &extra)
        .current_dir(&seeder)
        .args(["push", "-q", "origin", ":doomed"]))
    .expect("push :doomed");
    assert!(del.succeeded(), "delete remote branch: {}", del.stderr);

    // Consumer fetches with --prune. Local tracking ref must go.
    let fetch = run(env
        .git_cmd()
        .env("GIT_SSH_COMMAND", &git_ssh)
        .current_dir(&consumer)
        .args(["fetch", "-q", "--prune", "origin"]))
    .expect("fetch --prune");
    assert!(fetch.succeeded(), "fetch --prune: {}", fetch.stderr);

    let post =
        run(env.git_cmd().current_dir(&consumer).args(["branch", "-r"])).expect("branch -r post");
    assert!(
        !post.stdout.contains("origin/doomed"),
        "origin/doomed should be pruned; got:\n{}",
        post.stdout
    );
}

/// `git fetch --tags` pulls all remote tags, including ones not
/// reachable from any local branch.
#[test]
#[ignore = "requires docker"]
fn git_fetch_tags_pulls_remote_tags() {
    if skip_if_no_docker("git_fetch_tags_pulls_remote_tags") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let container = SshdContainer::start(&[&enclave]).expect("sshd");
    let remote_url = init_bare_repo(&env, &container, "tags-target.git");

    let seeder = make_repo_pushed_with_branch(&env, &enclave, "tags-seeder", &[], &remote_url);

    // Seeder creates a tag and pushes it.
    let extra = ssh_extra_args(&env);
    let tag = run(env
        .git_cmd()
        .current_dir(&seeder)
        .args(["tag", "v1.0.0", "-m", "first tag"]))
    .expect("git tag");
    assert!(tag.succeeded(), "tag: {}", tag.stderr);
    let push_tag = run(env
        .git_cmd()
        .env("SSHENC_SSH_EXTRA_ARGS", &extra)
        .current_dir(&seeder)
        .args(["push", "-q", "origin", "v1.0.0"]))
    .expect("push tag");
    assert!(push_tag.succeeded(), "push tag: {}", push_tag.stderr);

    // Consumer fetches with --tags.
    let git_ssh = git_ssh_command(&env);
    let consumer = env.home().join("tags-consumer");
    let clone = run(env
        .git_cmd()
        .env("GIT_SSH_COMMAND", &git_ssh)
        .args(["clone", "-q", "--no-tags", &remote_url])
        .arg(&consumer))
    .expect("clone");
    assert!(clone.succeeded(), "clone: {}", clone.stderr);
    let fetch = run(env
        .git_cmd()
        .env("GIT_SSH_COMMAND", &git_ssh)
        .current_dir(&consumer)
        .args(["fetch", "-q", "--tags", "origin"]))
    .expect("fetch --tags");
    assert!(fetch.succeeded(), "fetch --tags: {}", fetch.stderr);

    let tags = run(env.git_cmd().current_dir(&consumer).arg("tag")).expect("git tag list");
    assert!(
        tags.stdout.contains("v1.0.0"),
        "consumer should have v1.0.0 after --tags; got:\n{}",
        tags.stdout
    );
}

/// `git clone --filter=blob:none` (partial clone) over the
/// agent-mediated SSH path. Sets up a promisor remote and lazy-
/// fetches blobs on demand. Pin that the protocol-v2 capability
/// negotiation works through sshenc-ssh.
#[test]
#[ignore = "requires docker"]
fn git_clone_partial_blob_filter_succeeds() {
    if skip_if_no_docker("git_clone_partial_blob_filter_succeeds") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let container = SshdContainer::start(&[&enclave]).expect("sshd");
    let remote_url = init_bare_repo(&env, &container, "partial-target.git");

    let _seeder = make_repo_pushed_with_branch(&env, &enclave, "partial-seeder", &[], &remote_url);

    let git_ssh = git_ssh_command(&env);
    let consumer = env.home().join("partial-consumer");
    let clone = run(env
        .git_cmd()
        .env("GIT_SSH_COMMAND", &git_ssh)
        .args(["clone", "-q", "--filter=blob:none", &remote_url])
        .arg(&consumer))
    .expect("partial clone");
    assert!(
        clone.succeeded(),
        "partial clone failed; stderr:\n{}",
        clone.stderr
    );

    // Verify the promisor was set up.
    let cfg = run(env.git_cmd().current_dir(&consumer).args([
        "config",
        "--local",
        "--get-all",
        "remote.origin.promisor",
    ]))
    .expect("config promisor");
    assert!(cfg.succeeded(), "config promisor: {}", cfg.stderr);
    assert_eq!(
        cfg.stdout.trim(),
        "true",
        "remote.origin.promisor should be 'true' after --filter=blob:none; got:\n{}",
        cfg.stdout
    );
}
