// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `git pull --rebase` over the sshenc-mediated SSH path.
//! Distinct from the `--ff-only` case in
//! `git_verify_pull_show_sig.rs`: with `--rebase`, the consumer
//! has its own local commit that gets rewritten on top of the
//! upstream's new commits. Each rewritten local commit is
//! re-signed via the agent.

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
        "rebase-pull signer",
        "rebase-pull@e2e.test",
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

/// `git pull --rebase` rewrites a local commit on top of new
/// upstream commits; each rewritten local commit must verify.
#[test]
#[ignore = "requires docker"]
fn git_pull_rebase_re_signs_local_commits() {
    if skip_if_no_docker("git_pull_rebase_re_signs_local_commits") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let container = SshdContainer::start(&[&enclave]).expect("sshd");
    let remote_url = init_bare_repo(&env, &container, "pull-rebase-target.git");

    // Seeder publishes the initial commit.
    let seeder = make_signed_repo(&env, "pull-rebase-seeder", &enclave);
    make_commit(&env, &seeder, "shared.txt", "base\n", "base");
    let extra = ssh_extra_args(&env);
    assert!(run(env
        .git_cmd()
        .current_dir(&seeder)
        .args(["remote", "add", "origin", &remote_url]))
    .expect("seeder remote add")
    .succeeded());
    assert!(run(env
        .git_cmd()
        .env("SSHENC_SSH_EXTRA_ARGS", &extra)
        .current_dir(&seeder)
        .args(["push", "-q", "-u", "origin", "main"]))
    .expect("seed push")
    .succeeded());

    // Consumer clones, makes a local commit, then waits for upstream
    // to advance.
    let git_ssh = format!(
        "sshenc ssh -F /dev/null \
         -o StrictHostKeyChecking=accept-new \
         -o UserKnownHostsFile={known} \
         -o ConnectTimeout=10 \
         -o NumberOfPasswordPrompts=0 \
         -o PreferredAuthentications=publickey",
        known = env.known_hosts().display()
    );
    let consumer = env.home().join("pull-rebase-consumer");
    let clone = run(env
        .git_cmd()
        .env("GIT_SSH_COMMAND", &git_ssh)
        .args(["clone", "-q", &remote_url])
        .arg(&consumer))
    .expect("git clone");
    assert!(clone.succeeded(), "clone: {}", clone.stderr);
    let cfg_consumer = run(env
        .gitenc_cmd()
        .expect("gitenc cmd")
        .current_dir(&consumer)
        .args(["--config", SHARED_ENCLAVE_LABEL]))
    .expect("gitenc --config consumer");
    assert!(
        cfg_consumer.succeeded(),
        "gitenc --config consumer: {}",
        cfg_consumer.stderr
    );

    make_commit(&env, &consumer, "consumer.txt", "local\n", "local commit");

    // Seeder pushes a second commit on top.
    make_commit(&env, &seeder, "shared.txt", "seed-2\n", "seed-2");
    assert!(run(env
        .git_cmd()
        .env("SSHENC_SSH_EXTRA_ARGS", &extra)
        .current_dir(&seeder)
        .args(["push", "-q", "origin", "main"]))
    .expect("seed push 2")
    .succeeded());

    // Consumer pulls with --rebase. Their local commit must end up
    // on top of seeder's new commit, and it must re-verify (signing
    // re-fires for the rewritten commit).
    let pull = run(env
        .git_cmd()
        .env("SSHENC_SSH_EXTRA_ARGS", &extra)
        .env("GIT_SSH_COMMAND", &git_ssh)
        .current_dir(&consumer)
        .args(["pull", "-q", "--rebase", "origin", "main"]))
    .expect("git pull --rebase");
    assert!(
        pull.succeeded(),
        "git pull --rebase failed; stderr:\n{}",
        pull.stderr
    );

    // HEAD's parent should be seeder's second commit (consumer's
    // local commit was rebased on top of it).
    let log = run(env
        .git_cmd()
        .current_dir(&consumer)
        .args(["log", "--format=%s", "-2"]))
    .expect("git log");
    assert!(log.succeeded(), "git log: {}", log.stderr);
    let lines: Vec<&str> = log.stdout.lines().collect();
    assert_eq!(
        lines,
        ["local commit", "seed-2"],
        "expected rebased order; got:\n{}",
        log.stdout
    );

    // The rebased local commit (HEAD) must verify.
    let verify = run(env
        .git_cmd()
        .current_dir(&consumer)
        .args(["verify-commit", "HEAD"]))
    .expect("verify-commit");
    assert!(
        verify.succeeded(),
        "verify-commit on rebased HEAD failed; stderr:\n{}",
        verify.stderr
    );
}
