// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `gitenc.rs` covers plain `git push` / `git clone`. `gitenc_extras.rs`
//! covers tag signing, fetch, ls-remote, submodule. The other
//! workflows users hit — force-push, ref-delete, push-tags,
//! `git worktree` — share the same SSH path but exchange different
//! ref-update sequences with the server, and a regression where
//! sshenc's identity-binding doesn't follow into a worktree (or
//! where forced/delete refspec parsing breaks something) wouldn't
//! surface in any current test.
//!
//! Three new scenarios:
//! - `git push --force` after a non-fast-forward local rewrite
//!   succeeds against the same agent-mediated remote.
//! - `git push origin :branch` (delete-by-empty-source) drops the
//!   remote branch through the same SSH channel.
//! - `git worktree add` produces a tree where `gitenc --config`
//!   continues to apply (commit signing + ssh remote both work
//!   from the new tree directory).

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

fn make_signed_repo(env: &SshencEnv, name: &str, enclave_pub: &str) -> std::path::PathBuf {
    let pub_path = env.ssh_dir().join(format!("{SHARED_ENCLAVE_LABEL}.pub"));
    std::fs::create_dir_all(env.ssh_dir()).expect("mkdir ssh dir");
    std::fs::write(&pub_path, format!("{enclave_pub}\n")).expect("write pub");

    // gitenc reads meta from $HOME/.sshenc/keys (dirs::home_dir
    // path), not SSHENC_KEYS_DIR. Plant the meta file there so
    // gitenc --config picks up the git identity.
    let gitenc_meta_dir = env.home().join(".sshenc").join("keys");
    std::fs::create_dir_all(&gitenc_meta_dir).expect("mkdir gitenc meta dir");
    std::fs::write(
        gitenc_meta_dir.join(format!("{SHARED_ENCLAVE_LABEL}.meta")),
        serde_json::to_string_pretty(&serde_json::json!({
            "app_specific": {
                "git_name": "advanced-ops signer",
                "git_email": "signer@gitenc-advanced.test",
            }
        }))
        .unwrap(),
    )
    .expect("write meta");

    let repo = env.home().join(name);
    std::fs::create_dir_all(&repo).expect("mkdir local repo");
    let status = env
        .git_cmd()
        .current_dir(&repo)
        .args(["init", "-q", "-b", "main"])
        .status()
        .expect("git init");
    assert!(status.success());

    let cfg = run(env
        .gitenc_cmd()
        .expect("gitenc cmd")
        .current_dir(&repo)
        .args(["--config", SHARED_ENCLAVE_LABEL]))
    .expect("gitenc --config");
    assert!(
        cfg.succeeded(),
        "gitenc --config failed; stderr:\n{}",
        cfg.stderr
    );
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

/// `git push --force` after a local rewrite (e.g. amend, reset)
/// must succeed against the agent-mediated remote. Tests the
/// non-fast-forward push path which exchanges different protocol
/// frames than a normal fast-forward push.
#[test]
#[ignore = "requires docker"]
fn gitenc_push_force_after_local_rewrite() {
    if skip_if_no_docker("gitenc_push_force_after_local_rewrite") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    let mut env_owned = env;
    env_owned.start_agent().expect("start agent");
    let env = env_owned;

    let container = SshdContainer::start(&[&enclave]).expect("sshd");
    let remote_url = init_bare_repo(&env, &container, "force-push-target.git");

    let repo = make_signed_repo(&env, "force-push-local", &enclave);

    // Initial commit + push to seed the remote.
    make_commit(&env, &repo, "README.md", "initial\n", "initial");
    let extra = ssh_extra_args(&env);
    let setup =
        run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["remote", "add", "origin", &remote_url]))
        .expect("git remote add");
    assert!(setup.succeeded(), "remote add: {}", setup.stderr);
    let push_first = run(env
        .git_cmd()
        .env("SSHENC_SSH_EXTRA_ARGS", &extra)
        .current_dir(&repo)
        .args(["push", "-q", "-u", "origin", "main"]))
    .expect("first push");
    assert!(push_first.succeeded(), "first push: {}", push_first.stderr);

    // Add a second commit, push it. Remote is now: initial → second.
    make_commit(&env, &repo, "README.md", "second\n", "second");
    let push_second = run(env
        .git_cmd()
        .env("SSHENC_SSH_EXTRA_ARGS", &extra)
        .current_dir(&repo)
        .args(["push", "-q", "origin", "main"]))
    .expect("second push");
    assert!(
        push_second.succeeded(),
        "second push: {}",
        push_second.stderr
    );

    // Rewrite history: drop the second commit locally and replace
    // it with a different one. Now local main diverges from remote
    // — both have an "initial → X" line, but X is a different SHA
    // on each side. Plain push is non-fast-forward; --force wins.
    let reset = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["reset", "--hard", "HEAD~1"]))
    .expect("git reset");
    assert!(reset.succeeded(), "reset: {}", reset.stderr);
    make_commit(&env, &repo, "README.md", "diverged\n", "diverged");

    let plain_push = run(env
        .git_cmd()
        .env("SSHENC_SSH_EXTRA_ARGS", &extra)
        .current_dir(&repo)
        .args(["push", "-q", "origin", "main"]))
    .expect("git push (no force)");
    assert!(
        !plain_push.succeeded(),
        "plain push of diverged ref unexpectedly succeeded; setup is wrong:\nstdout:\n{}\nstderr:\n{}",
        plain_push.stdout,
        plain_push.stderr,
    );
    let force_push = run(env
        .git_cmd()
        .env("SSHENC_SSH_EXTRA_ARGS", &extra)
        .current_dir(&repo)
        .args(["push", "-q", "--force", "origin", "main"]))
    .expect("git push --force");
    assert!(
        force_push.succeeded(),
        "git push --force failed; stderr:\n{}",
        force_push.stderr
    );
}

/// `git push origin :branch` (delete-refspec) drops a remote
/// branch through the same SSH path. The receiving side does
/// different ref-update bookkeeping for deletes vs creates;
/// pin that the agent-mediated channel handles it cleanly.
#[test]
#[ignore = "requires docker"]
fn gitenc_push_delete_remote_branch() {
    if skip_if_no_docker("gitenc_push_delete_remote_branch") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");

    let container = SshdContainer::start(&[&enclave]).expect("sshd");
    let remote_url = init_bare_repo(&env, &container, "delete-branch-target.git");

    let repo = make_signed_repo(&env, "delete-branch-local", &enclave);
    make_commit(&env, &repo, "README.md", "main content\n", "main commit");

    let extra = ssh_extra_args(&env);
    let setup =
        run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["remote", "add", "origin", &remote_url]))
        .expect("remote add");
    assert!(setup.succeeded(), "remote add: {}", setup.stderr);
    let push_main = run(env
        .git_cmd()
        .env("SSHENC_SSH_EXTRA_ARGS", &extra)
        .current_dir(&repo)
        .args(["push", "-q", "-u", "origin", "main"]))
    .expect("push main");
    assert!(push_main.succeeded(), "push main: {}", push_main.stderr);

    // Make a side branch, push it, then delete it remotely via :branch refspec.
    let side = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["checkout", "-q", "-b", "throwaway"]))
    .expect("checkout side");
    assert!(side.succeeded(), "checkout: {}", side.stderr);
    make_commit(&env, &repo, "extra.txt", "side\n", "on side");
    let push_side = run(env
        .git_cmd()
        .env("SSHENC_SSH_EXTRA_ARGS", &extra)
        .current_dir(&repo)
        .args(["push", "-q", "-u", "origin", "throwaway"]))
    .expect("push side");
    assert!(push_side.succeeded(), "push side: {}", push_side.stderr);

    let delete = run(env
        .git_cmd()
        .env("SSHENC_SSH_EXTRA_ARGS", &extra)
        .current_dir(&repo)
        .args(["push", "-q", "origin", ":throwaway"]))
    .expect("push :throwaway");
    assert!(
        delete.succeeded(),
        "push :throwaway (delete) failed; stderr:\n{}",
        delete.stderr
    );

    // ls-remote must no longer list refs/heads/throwaway.
    let lsr = run(env
        .git_cmd()
        .env("SSHENC_SSH_EXTRA_ARGS", &extra)
        .current_dir(&repo)
        .args(["ls-remote", "origin"]))
    .expect("ls-remote");
    assert!(lsr.succeeded(), "ls-remote: {}", lsr.stderr);
    assert!(
        !lsr.stdout.contains("refs/heads/throwaway"),
        "deleted branch still in ls-remote:\n{}",
        lsr.stdout
    );
}

/// `git worktree add <path> -b feature` creates a new working tree
/// in a separate directory. The original repo's `gitenc --config`
/// settings (signing key, ssh command) live in the parent's
/// .git/config, which is shared across all worktrees — so a commit
/// from inside the worktree should still be signed by the same
/// enclave key, and a push from inside the worktree should use the
/// same SSH command. Pin both contracts.
#[test]
#[ignore = "requires docker"]
fn gitenc_worktree_inherits_signing_and_ssh_config() {
    if skip_if_no_docker("gitenc_worktree_inherits_signing_and_ssh_config") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");

    let container = SshdContainer::start(&[&enclave]).expect("sshd");
    let remote_url = init_bare_repo(&env, &container, "worktree-target.git");

    let repo = make_signed_repo(&env, "worktree-local", &enclave);
    make_commit(&env, &repo, "README.md", "main\n", "initial");
    let extra = ssh_extra_args(&env);
    let setup =
        run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["remote", "add", "origin", &remote_url]))
        .expect("remote add");
    assert!(setup.succeeded(), "remote add: {}", setup.stderr);
    let push_main = run(env
        .git_cmd()
        .env("SSHENC_SSH_EXTRA_ARGS", &extra)
        .current_dir(&repo)
        .args(["push", "-q", "-u", "origin", "main"]))
    .expect("push main");
    assert!(push_main.succeeded(), "push main: {}", push_main.stderr);

    // Add a worktree.
    let wt = env.home().join("worktree-feature");
    let wt_add = run(env.git_cmd().current_dir(&repo).args([
        "worktree",
        "add",
        wt.to_str().expect("utf-8"),
        "-b",
        "feature",
    ]))
    .expect("git worktree add");
    assert!(
        wt_add.succeeded(),
        "git worktree add failed; stderr:\n{}",
        wt_add.stderr
    );

    // Commit from inside the worktree — must succeed; if signing
    // config didn't follow, this fails because gpg.format=ssh and
    // gpg.ssh.program=sshenc were set on the parent .git/config
    // (shared with the worktree's HEAD ref but per-worktree config
    // could in theory shadow it).
    make_commit(&env, &wt, "feature.txt", "feature work\n", "feature commit");

    // Push the new branch from inside the worktree — must use the
    // same SSH path, so this proves the SSH command + agent socket
    // resolution still works from the worktree's cwd.
    let push_feat = run(env
        .git_cmd()
        .env("SSHENC_SSH_EXTRA_ARGS", &extra)
        .current_dir(&wt)
        .args(["push", "-q", "-u", "origin", "feature"]))
    .expect("push feature from worktree");
    assert!(
        push_feat.succeeded(),
        "push feature from worktree failed; stderr:\n{}",
        push_feat.stderr
    );

    // Verify signed-commit metadata via git log --show-signature
    // from the worktree (the signature must have been produced by
    // the enclave key, and the -G/--show-signature read should not
    // surface "no signature").
    let log =
        run(env
            .git_cmd()
            .current_dir(&wt)
            .args(["log", "--show-signature", "-1", "--format=%H"]))
        .expect("git log");
    assert!(log.succeeded(), "git log --show-signature: {}", log.stderr);
    // Match the commit-sign success line. If signing didn't run,
    // this line is absent and we'd see "No signature".
    let combined = format!("{}\n{}", log.stdout, log.stderr);
    assert!(
        combined.contains("Good \"git\" signature")
            || combined.contains("Good signature")
            || combined.contains("ssh-keygen verify"),
        "expected a positive signature-validation line in log output; got:\nstdout:\n{}\nstderr:\n{}",
        log.stdout,
        log.stderr
    );
}
