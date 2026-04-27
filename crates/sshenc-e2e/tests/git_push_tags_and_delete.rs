// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Distinct push variants over the gitenc-mediated SSH path:
//!
//! - `git push --tags` (push all tags) exercises the
//!   "tag refspec advertisement" code path. Plain `push` only
//!   sends branch refs by default; `--tags` adds every
//!   `refs/tags/*` ref to the push frame.
//! - `git push --delete origin <branch>` (delete a remote
//!   branch) sends a zero-sha update for the named ref. Distinct
//!   protocol shape from a normal push (which sends a non-zero
//!   target sha).

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
        "tag-pusher",
        "tag-pusher@e2e.test",
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

/// `git push --tags` over the gitenc SSH path uploads every
/// local `refs/tags/*` ref to the remote.
#[test]
#[ignore = "requires docker"]
fn push_tags_uploads_all_tags() {
    if skip_if_no_docker("push_tags_uploads_all_tags") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let container = SshdContainer::start(&[&enclave]).expect("sshd");
    let remote_url = init_bare_repo(&env, &container, "tags-target.git");

    let repo = make_signed_repo(&env, "tags-repo", &enclave);
    make_commit(&env, &repo, "f.txt", "first\n", "first");

    // Two lightweight tags on HEAD.
    for tag in ["v0.1", "v0.2"] {
        assert!(env
            .git_cmd()
            .current_dir(&repo)
            .args(["tag", tag])
            .status()
            .expect("git tag")
            .success());
    }

    let extra = ssh_extra_args(&env);
    assert!(run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["remote", "add", "origin", &remote_url]))
    .expect("remote add")
    .succeeded());

    // Push the branch first, then push all tags.
    assert!(run(env
        .git_cmd()
        .env("SSHENC_SSH_EXTRA_ARGS", &extra)
        .current_dir(&repo)
        .args(["push", "-q", "-u", "origin", "main"]))
    .expect("push main")
    .succeeded());

    let push_tags = run(env
        .git_cmd()
        .env("SSHENC_SSH_EXTRA_ARGS", &extra)
        .current_dir(&repo)
        .args(["push", "-q", "--tags", "origin"]))
    .expect("push --tags");
    assert!(
        push_tags.succeeded(),
        "git push --tags failed: {}",
        push_tags.stderr
    );

    // Verify both tags landed on the remote via ls-remote.
    let git_ssh = format!(
        "sshenc ssh -F /dev/null \
         -o StrictHostKeyChecking=accept-new \
         -o UserKnownHostsFile={known} \
         -o ConnectTimeout=10 \
         -o NumberOfPasswordPrompts=0 \
         -o PreferredAuthentications=publickey",
        known = env.known_hosts().display()
    );
    let ls_remote = run(env.git_cmd().env("GIT_SSH_COMMAND", &git_ssh).args([
        "ls-remote",
        "--tags",
        &remote_url,
    ]))
    .expect("ls-remote");
    assert!(ls_remote.succeeded(), "ls-remote: {}", ls_remote.stderr);
    for tag in ["refs/tags/v0.1", "refs/tags/v0.2"] {
        assert!(
            ls_remote.stdout.contains(tag),
            "expected {tag} in ls-remote output; got:\n{}",
            ls_remote.stdout
        );
    }
}

/// `git push --delete origin <branch>` removes the remote branch.
/// Sends a zero-sha update for the named ref — distinct protocol
/// shape from a normal push (non-zero target sha).
#[test]
#[ignore = "requires docker"]
fn push_delete_removes_remote_branch() {
    if skip_if_no_docker("push_delete_removes_remote_branch") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let container = SshdContainer::start(&[&enclave]).expect("sshd");
    let remote_url = init_bare_repo(&env, &container, "delete-target.git");

    let repo = make_signed_repo(&env, "delete-repo", &enclave);
    make_commit(&env, &repo, "f.txt", "first\n", "first");

    let extra = ssh_extra_args(&env);
    assert!(run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["remote", "add", "origin", &remote_url]))
    .expect("remote add")
    .succeeded());

    // Push main and a feature branch.
    assert!(run(env
        .git_cmd()
        .env("SSHENC_SSH_EXTRA_ARGS", &extra)
        .current_dir(&repo)
        .args(["push", "-q", "-u", "origin", "main"]))
    .expect("push main")
    .succeeded());
    assert!(env
        .git_cmd()
        .current_dir(&repo)
        .args(["checkout", "-q", "-b", "doomed"])
        .status()
        .expect("checkout doomed")
        .success());
    make_commit(&env, &repo, "doomed.txt", "doomed\n", "doomed");
    assert!(run(env
        .git_cmd()
        .env("SSHENC_SSH_EXTRA_ARGS", &extra)
        .current_dir(&repo)
        .args(["push", "-q", "-u", "origin", "doomed"]))
    .expect("push doomed")
    .succeeded());

    // Delete it.
    let delete = run(env
        .git_cmd()
        .env("SSHENC_SSH_EXTRA_ARGS", &extra)
        .current_dir(&repo)
        .args(["push", "-q", "--delete", "origin", "doomed"]))
    .expect("push --delete");
    assert!(
        delete.succeeded(),
        "git push --delete failed: {}",
        delete.stderr
    );

    // Verify the branch is gone via ls-remote.
    let git_ssh = format!(
        "sshenc ssh -F /dev/null \
         -o StrictHostKeyChecking=accept-new \
         -o UserKnownHostsFile={known} \
         -o ConnectTimeout=10 \
         -o NumberOfPasswordPrompts=0 \
         -o PreferredAuthentications=publickey",
        known = env.known_hosts().display()
    );
    let ls_remote = run(env.git_cmd().env("GIT_SSH_COMMAND", &git_ssh).args([
        "ls-remote",
        "--heads",
        &remote_url,
    ]))
    .expect("ls-remote heads");
    assert!(ls_remote.succeeded(), "ls-remote: {}", ls_remote.stderr);
    assert!(
        !ls_remote.stdout.contains("refs/heads/doomed"),
        "doomed branch should be gone after push --delete; ls-remote output:\n{}",
        ls_remote.stdout
    );
    assert!(
        ls_remote.stdout.contains("refs/heads/main"),
        "main should remain after deleting doomed; got:\n{}",
        ls_remote.stdout
    );
}
