// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Three git workflow corners not previously pinned:
//!
//! 1. `git verify-commit <sha>` accepts an sshenc-signed commit
//!    when `gpg.ssh.allowedSignersFile` is set. `gitenc.rs` covers
//!    "commit succeeds with -S"; this pins that the *verification*
//!    side also works against the same allowed_signers file
//!    gitenc wrote.
//! 2. `git pull` (vs `git fetch`+`git merge`) over the agent-
//!    mediated SSH path. `gitenc_extras.rs` covers fetch;
//!    `gitenc.rs` covers push. Pull has its own option set
//!    (`--rebase`, `--ff-only`) and is the more common day-to-day
//!    operation; pin that it works.
//! 3. `git log --show-signature` walking a multi-commit branch
//!    surfaces a signature line for *every* commit. Catches a
//!    regression where signing fires on the first commit but
//!    silently no-ops on later ones in the same session.

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
        "verify signer",
        "verify@e2e.test",
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

/// `git verify-commit HEAD` accepts the signature gitenc wrote.
/// Verifies the trust chain: gitenc --config writes
/// gpg.ssh.allowedSignersFile, commit signs against the agent,
/// verify reads the same allowed_signers file and accepts.
#[test]
#[ignore = "requires docker"]
fn git_verify_commit_accepts_sshenc_signature() {
    if skip_if_no_docker("git_verify_commit_accepts_sshenc_signature") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");

    let repo = make_signed_repo(&env, "verify-commit-repo", &enclave);
    make_commit(&env, &repo, "f.txt", "verify body\n", "first signed");

    let verify = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["verify-commit", "HEAD"]))
    .expect("git verify-commit");
    assert!(
        verify.succeeded(),
        "git verify-commit failed; stdout:\n{}\nstderr:\n{}",
        verify.stdout,
        verify.stderr
    );
}

/// `git pull` over the sshenc-mediated SSH path picks up commits
/// pushed by another working tree. Mirrors the standard
/// developer fetch+merge workflow.
#[test]
#[ignore = "requires docker"]
fn git_pull_over_sshenc_remote() {
    if skip_if_no_docker("git_pull_over_sshenc_remote") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let container = SshdContainer::start(&[&enclave]).expect("sshd");
    let remote_url = init_bare_repo(&env, &container, "pull-target.git");

    // Seeder repo populates the remote.
    let seeder = make_signed_repo(&env, "pull-seeder", &enclave);
    make_commit(&env, &seeder, "f.txt", "seed body\n", "seed");
    let extra = ssh_extra_args(&env);
    assert!(run(env
        .git_cmd()
        .current_dir(&seeder)
        .args(["remote", "add", "origin", &remote_url]))
    .expect("seeder remote add")
    .succeeded());
    let push = run(env
        .git_cmd()
        .env("SSHENC_SSH_EXTRA_ARGS", &extra)
        .current_dir(&seeder)
        .args(["push", "-q", "-u", "origin", "main"]))
    .expect("seed push");
    assert!(push.succeeded(), "seed push: {}", push.stderr);

    // Consumer repo: clone via GIT_SSH_COMMAND, then pull a new
    // commit the seeder pushes.
    let git_ssh = format!(
        "sshenc ssh -F /dev/null \
         -o StrictHostKeyChecking=accept-new \
         -o UserKnownHostsFile={known} \
         -o ConnectTimeout=10 \
         -o NumberOfPasswordPrompts=0 \
         -o PreferredAuthentications=publickey",
        known = env.known_hosts().display()
    );
    let consumer = env.home().join("pull-consumer");
    let clone = run(env
        .git_cmd()
        .env("GIT_SSH_COMMAND", &git_ssh)
        .args(["clone", "-q", &remote_url])
        .arg(&consumer))
    .expect("git clone");
    assert!(clone.succeeded(), "clone: {}", clone.stderr);

    // Seeder pushes a second commit.
    make_commit(&env, &seeder, "f.txt", "seed body 2\n", "seed-2");
    let push2 = run(env
        .git_cmd()
        .env("SSHENC_SSH_EXTRA_ARGS", &extra)
        .current_dir(&seeder)
        .args(["push", "-q", "origin", "main"]))
    .expect("seed push 2");
    assert!(push2.succeeded(), "seed push 2: {}", push2.stderr);

    // Consumer pulls — must get the new commit.
    let pull = run(env
        .git_cmd()
        .env("SSHENC_SSH_EXTRA_ARGS", &extra)
        .env("GIT_SSH_COMMAND", &git_ssh)
        .current_dir(&consumer)
        .args(["pull", "-q", "--ff-only", "origin", "main"]))
    .expect("git pull");
    assert!(
        pull.succeeded(),
        "git pull --ff-only failed; stderr:\n{}",
        pull.stderr
    );
    let body = std::fs::read_to_string(consumer.join("f.txt")).expect("read");
    assert_eq!(
        body.trim(),
        "seed body 2",
        "consumer didn't pick up seeder's commit; got:\n{body}"
    );
}

/// `git log --show-signature` walks a multi-commit branch and
/// surfaces a signature-validation line for every commit, not
/// just HEAD. Catches a regression where signing fires on the
/// first commit but silently no-ops on later ones in the same
/// session.
#[test]
#[ignore = "requires docker"]
fn git_log_show_signature_validates_every_commit() {
    if skip_if_no_docker("git_log_show_signature_validates_every_commit") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "multi-sig-repo", &enclave);

    for i in 0..5 {
        make_commit(
            &env,
            &repo,
            "f.txt",
            &format!("body {i}\n"),
            &format!("commit-{i}"),
        );
    }

    let log =
        run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["log", "--show-signature", "--format=%H"]))
        .expect("git log");
    assert!(log.succeeded(), "git log: {}", log.stderr);

    // git log --show-signature emits a "Good \"git\" signature"
    // line per commit (or similar accept message). With 5 commits
    // we expect at least 5 such lines. Be lenient about exact
    // wording but strict about count: missing a line means a
    // commit went unsigned.
    let combined = format!("{}\n{}", log.stdout, log.stderr);
    let positive_lines = combined
        .lines()
        .filter(|l| {
            l.contains("Good \"git\" signature")
                || l.contains("Good signature")
                || l.contains("ssh-keygen verify")
        })
        .count();
    assert!(
        positive_lines >= 5,
        "expected ≥5 positive signature lines (one per commit); got {positive_lines}\nfull output:\n{combined}"
    );
}

/// `sshenc identity --name --email <label>` writes the metadata
/// values that `gitenc --config <label>` then applies to a repo's
/// per-repo user.name and user.email. Pins the cross-binary
/// metadata round-trip.
#[test]
#[ignore = "requires docker"]
fn sshenc_identity_propagates_to_gitenc_config() {
    if skip_if_no_docker("sshenc_identity_propagates_to_gitenc_config") {
        return;
    }
    if !sshenc_e2e::extended_enabled() && !sshenc_e2e::software_mode() {
        eprintln!("skip: needs to mint a key");
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("warm shared key"));
    env.start_agent().expect("start agent");

    let label = format!(
        "id-roundtrip-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    // Skip --no-pub-file: gitenc --config requires the meta to
    // record a pub_file_path, which only happens when keygen
    // wrote one. The default --write-pub destination is
    // ~/.ssh/<label>.pub.
    let kg = run(env.sshenc_cmd().expect("sshenc cmd").args([
        "keygen",
        "--label",
        &label,
        "--auth-policy",
        "none",
    ]))
    .expect("keygen");
    assert!(kg.succeeded(), "keygen: {}", kg.stderr);

    let id = run(env.sshenc_cmd().expect("sshenc cmd").args([
        "identity",
        &label,
        "--name",
        "Roundtrip Person",
        "--email",
        "roundtrip@e2e.test",
    ]))
    .expect("sshenc identity");
    assert!(id.succeeded(), "sshenc identity: {}", id.stderr);

    // gitenc --config reads from $HOME/.sshenc/keys/<label>.meta;
    // sshenc identity writes via SSHENC_KEYS_DIR (= persistent
    // path). The meta the agent writes records pub_file_path =
    // null because that field travels with write_pub_path, which
    // isn't part of the GenerateKey RPC payload — the CLI writes
    // the .pub on its own side. For gitenc to find a recorded
    // pub_file_path we have to repair the meta after-the-fact.
    let persistent = sshenc_e2e::persistent_keys_dir();
    let pub_path = env.ssh_dir().join(format!("{label}.pub"));
    std::fs::create_dir_all(env.ssh_dir()).expect("mkdir ssh dir");
    let exp = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["export-pub", &label]))
    .expect("export-pub");
    assert!(exp.succeeded(), "export-pub: {}", exp.stderr);
    std::fs::write(&pub_path, exp.stdout.as_bytes()).expect("write pub");

    let meta_src = persistent.join(format!("{label}.meta"));
    let mut meta_val: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&meta_src).expect("read meta"))
            .expect("parse meta");
    if let Some(app) = meta_val
        .get_mut("app_specific")
        .and_then(|v| v.as_object_mut())
    {
        app.insert(
            "pub_file_path".to_string(),
            serde_json::Value::String(pub_path.display().to_string()),
        );
    }
    let gitenc_dir = env.home().join(".sshenc").join("keys");
    std::fs::create_dir_all(&gitenc_dir).expect("mkdir");
    std::fs::write(
        gitenc_dir.join(format!("{label}.meta")),
        serde_json::to_string_pretty(&meta_val).unwrap(),
    )
    .expect("write repaired meta");

    // gitenc --config in a fresh repo, then verify per-repo
    // user.name / user.email reflect what sshenc identity wrote.
    let repo = env.home().join("identity-roundtrip-repo");
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
        .args(["--config", &label]))
    .expect("gitenc --config");
    assert!(cfg.succeeded(), "gitenc --config: {}", cfg.stderr);

    let email =
        run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["config", "--local", "--get", "user.email"]))
        .expect("git config email");
    assert_eq!(
        email.stdout.trim(),
        "roundtrip@e2e.test",
        "user.email from sshenc identity didn't reach gitenc; got: {}",
        email.stdout
    );
    let name =
        run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["config", "--local", "--get", "user.name"]))
        .expect("git config name");
    assert_eq!(
        name.stdout.trim(),
        "Roundtrip Person",
        "user.name from sshenc identity didn't reach gitenc; got: {}",
        name.stdout
    );

    drop(run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["delete", &label, "-y"])));
}
