// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! gitenc e2e coverage.
//!
//! gitenc is a thin wrapper that runs `git` with
//! `GIT_SSH_COMMAND = sshenc ssh [--label X] --`, and (via `--config`)
//! writes per-repo git config that routes auth through the sshenc agent
//! and commit signing through the sshenc `-Y sign` code path.
//!
//! These scenarios verify the full chain against a real git server
//! running over ssh in the test container.
//!
//! All tests are `#[ignore]` by default:
//!
//! ```text
//! cargo test -p sshenc-e2e -- --ignored --test-threads=1
//! ```

#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{
    docker_skip_reason, generate_on_disk_ed25519, run, shared_enclave_pubkey, SshdContainer,
    SshencEnv, SHARED_ENCLAVE_LABEL,
};
use std::path::Path;
use std::process::Stdio;

/// Build `SSHENC_SSH_EXTRA_ARGS` so indirect invocations (gitenc →
/// `GIT_SSH_COMMAND=sshenc ssh --` → ssh) inherit the tempdir-scoped
/// known_hosts and skip the user's real ssh_config (OpenSSH resolves
/// `~/.ssh/config` via `getpwuid`, so setting `HOME` is not enough).
///
/// We do NOT inject `Port=` here — git provides the port via the
/// `ssh://…:<port>/…` URL form, which becomes `-p <port>` after our args.
fn ssh_extra_args(env: &SshencEnv) -> String {
    format!(
        "-F /dev/null -o StrictHostKeyChecking=accept-new \
         -o UserKnownHostsFile={known} -o ConnectTimeout=10 \
         -o NumberOfPasswordPrompts=0 -o PreferredAuthentications=publickey",
        known = env.known_hosts().display(),
    )
}

fn skip_if_no_docker(test_name: &str) -> bool {
    if let Some(reason) = docker_skip_reason() {
        eprintln!("skip {test_name}: {reason}");
        return true;
    }
    false
}

/// Initialize a bare repo inside the container via an ssh exec, then
/// return its remote URL suitable for `git clone` / `git push`.
fn init_bare_repo(env: &SshencEnv, container: &SshdContainer, repo_name: &str) -> String {
    // `git init --bare -b main` sets HEAD to refs/heads/main so a clone
    // after the first push checks out cleanly.
    let cmd = format!(
        "mkdir -p /home/sshtest/{repo_name} && \
         git init --bare -b main /home/sshtest/{repo_name} >/dev/null",
    );
    let outcome = run(env
        .ssh_cmd(container)
        .arg("-o")
        .arg(format!("IdentityAgent={}", env.socket_path().display()))
        .arg("-i")
        .arg(env.ssh_dir().join("id_ed25519"))
        .arg("sshtest@127.0.0.1")
        .arg(cmd))
    .expect("ssh init bare repo");
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

/// Common setup: env with on-disk + shared enclave keys, agent running,
/// container trusting the enclave key, and a bare repo created on it.
fn env_with_bare_repo(repo_name: &str) -> (SshencEnv, String, String, SshdContainer, String) {
    let mut env = SshencEnv::new().expect("env");
    let on_disk = generate_on_disk_ed25519(&env, "on-disk@e2e").expect("on-disk keygen");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("agent start");
    let container = SshdContainer::start(&[&enclave, &on_disk]).expect("sshd container");
    let remote = init_bare_repo(&env, &container, repo_name);
    (env, on_disk, enclave, container, remote)
}

/// A local working repo with a single committed file. Returns the repo
/// path and the remote-tracked URL alias we'll push to.
fn make_local_repo(env: &SshencEnv, dir_name: &str, remote_url: &str) -> std::path::PathBuf {
    let repo = env.home().join(dir_name);
    std::fs::create_dir_all(&repo).expect("mkdir local repo");
    let status = env
        .git_cmd()
        .current_dir(&repo)
        .args(["init", "-q", "-b", "main"])
        .status()
        .expect("git init");
    assert!(status.success(), "git init failed");
    let status = env
        .git_cmd()
        .current_dir(&repo)
        .args(["remote", "add", "origin", remote_url])
        .status()
        .expect("git remote add");
    assert!(status.success(), "git remote add failed");
    std::fs::write(repo.join("README.md"), b"hello from e2e\n").expect("write README");
    let status = env
        .git_cmd()
        .current_dir(&repo)
        .args(["add", "README.md"])
        .status()
        .expect("git add");
    assert!(status.success(), "git add failed");
    let status = env
        .git_cmd()
        .current_dir(&repo)
        .args(["commit", "-q", "-m", "initial"])
        .status()
        .expect("git commit");
    assert!(status.success(), "git commit failed");
    repo
}

/// 1. gitenc push + re-clone roundtrip via the enclave agent (unlabeled).
///
/// Proves the full git-over-ssh pipeline works under gitenc: client
/// authenticates via agent, pushes refs, server accepts them, a fresh
/// clone reads them back with the same content.
#[test]
#[ignore = "requires docker"]
fn gitenc_push_and_clone_roundtrip_via_enclave_agent() {
    if skip_if_no_docker("gitenc_push_and_clone_roundtrip_via_enclave_agent") {
        return;
    }
    let (env, _on_disk, _enclave, _container, remote) = env_with_bare_repo("roundtrip.git");

    let repo = make_local_repo(&env, "source", &remote);
    let extras = ssh_extra_args(&env);

    // Push via gitenc (unlabeled → uses the agent).
    let push = run(env
        .gitenc_cmd()
        .expect("gitenc cmd")
        .env("SSHENC_SSH_EXTRA_ARGS", &extras)
        .current_dir(&repo)
        .args(["push", "-u", "origin", "main"]))
    .expect("gitenc push");
    assert!(
        push.succeeded(),
        "gitenc push failed; stdout:\n{}\nstderr:\n{}",
        push.stdout,
        push.stderr
    );

    // Clone into a new dir and verify the file content matches.
    let clone_dir = env.home().join("clone");
    let clone = run(env
        .gitenc_cmd()
        .expect("gitenc cmd")
        .env("SSHENC_SSH_EXTRA_ARGS", &extras)
        .arg("clone")
        .arg(&remote)
        .arg(&clone_dir))
    .expect("gitenc clone");
    assert!(
        clone.succeeded(),
        "gitenc clone failed; stdout:\n{}\nstderr:\n{}",
        clone.stdout,
        clone.stderr
    );
    let readme_path = clone_dir.join("README.md");
    let readme = std::fs::read_to_string(&readme_path).unwrap_or_else(|e| {
        let entries: Vec<String> = std::fs::read_dir(&clone_dir)
            .map(|rd| {
                rd.filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
                    .collect()
            })
            .unwrap_or_default();
        panic!(
            "read {}: {e}\nclone_dir entries: {entries:?}\nclone stdout:\n{}\nclone stderr:\n{}",
            readme_path.display(),
            clone.stdout,
            clone.stderr,
        )
    });
    assert_eq!(readme, "hello from e2e\n");
}

/// 2. `gitenc --label X` routes auth through the named enclave key.
///
/// Proves label selection carries through the env-var handoff to ssh.
/// Server trusts only the shared enclave key; `--label e2e-shared`
/// succeeds. A mismatched label must fail auth.
#[test]
#[ignore = "requires docker"]
fn gitenc_label_forces_named_enclave_key() {
    if skip_if_no_docker("gitenc_label_forces_named_enclave_key") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    // Also generate an on-disk key so ssh won't just fall through.
    let _on_disk = generate_on_disk_ed25519(&env, "on-disk@e2e").expect("on-disk keygen");
    env.start_agent().expect("agent start");
    let container = SshdContainer::start(&[&enclave]).expect("container");
    let remote = init_bare_repo(&env, &container, "labeled.git");
    let repo = make_local_repo(&env, "labeled_source", &remote);
    let extras = ssh_extra_args(&env);

    // --label e2e-shared: should succeed.
    let ok = run(env
        .gitenc_cmd()
        .expect("gitenc cmd")
        .env("SSHENC_SSH_EXTRA_ARGS", &extras)
        .current_dir(&repo)
        .arg("--label")
        .arg(SHARED_ENCLAVE_LABEL)
        .args(["push", "-u", "origin", "main"]))
    .expect("gitenc push labeled");
    assert!(
        ok.succeeded(),
        "gitenc --label {SHARED_ENCLAVE_LABEL} push should succeed; stderr:\n{}",
        ok.stderr
    );

    // --label does-not-exist: must fail (invalid label rejected by gitenc
    // before reaching ssh, or by the backend when the label is bogus).
    let bad = run(env
        .gitenc_cmd()
        .expect("gitenc cmd")
        .env("SSHENC_SSH_EXTRA_ARGS", &extras)
        .current_dir(&repo)
        .arg("--label")
        .arg("nonexistent-label")
        .args(["fetch", "origin"]))
    .expect("gitenc fetch unlabeled");
    assert!(
        !bad.succeeded(),
        "gitenc --label nonexistent should fail; stdout:\n{}\nstderr:\n{}",
        bad.stdout,
        bad.stderr
    );
}

/// 3. `gitenc --config` writes the expected git config for a repo.
///
/// Doesn't exercise ssh — just verifies the configuration side of the
/// product: after running `gitenc --config [label]`, `git config --get`
/// returns the known directives (`core.sshCommand`, `gpg.format`,
/// `gpg.ssh.program`, `user.signingkey`, `commit.gpgsign`).
#[test]
#[ignore = "requires docker"]
fn gitenc_config_writes_expected_git_config() {
    if skip_if_no_docker("gitenc_config_writes_expected_git_config") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");

    // We need a pub file at $HOME/.ssh/<label>.pub because `gitenc
    // --config <label>` references it as `user.signingkey`.
    let pub_path = env.ssh_dir().join(format!("{SHARED_ENCLAVE_LABEL}.pub"));
    std::fs::write(&pub_path, format!("{enclave}\n")).expect("write enclave pub");

    // Local repo to configure.
    let repo = env.home().join("configured");
    std::fs::create_dir_all(&repo).expect("mkdir");
    let status = env
        .git_cmd()
        .current_dir(&repo)
        .args(["init", "-q"])
        .status()
        .expect("git init");
    assert!(status.success(), "git init failed");

    let outcome = run(env
        .gitenc_cmd()
        .expect("gitenc cmd")
        .current_dir(&repo)
        .arg("--config")
        .arg(SHARED_ENCLAVE_LABEL))
    .expect("gitenc --config");
    assert!(
        outcome.succeeded(),
        "gitenc --config failed; stdout:\n{}\nstderr:\n{}",
        outcome.stdout,
        outcome.stderr
    );

    let get = |key: &str| -> String {
        let output = env
            .git_cmd()
            .current_dir(&repo)
            .args(["config", "--get", key])
            .output()
            .expect("git config --get");
        assert!(
            output.status.success(),
            "git config --get {key} failed; stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    };

    assert_eq!(
        get("core.sshCommand"),
        format!("sshenc ssh --label {SHARED_ENCLAVE_LABEL} --")
    );
    assert_eq!(get("gpg.format"), "ssh");
    let signingkey = get("user.signingkey");
    assert!(
        signingkey.ends_with(&format!("{SHARED_ENCLAVE_LABEL}.pub"))
            || signingkey == pub_path.display().to_string(),
        "unexpected signingkey: {signingkey}"
    );
    assert_eq!(get("commit.gpgsign"), "true");
    // gpg.ssh.program is an absolute path to the sshenc binary. Verify
    // the path exists and its basename is sshenc.
    let sshenc_bin = get("gpg.ssh.program");
    assert!(
        Path::new(&sshenc_bin).file_name().and_then(|s| s.to_str()) == Some("sshenc")
            || Path::new(&sshenc_bin).file_name().and_then(|s| s.to_str()) == Some("sshenc.exe"),
        "gpg.ssh.program basename should be sshenc, got: {sshenc_bin}"
    );
}

/// 4. `gitenc --config` + `git commit -S` produces a signature that
///    `git log --show-signature` accepts.
///
/// The full chain:
///   sshenc identity … → write git identity metadata
///   gitenc --config → set gpg.format=ssh, gpg.ssh.program=sshenc,
///                     user.signingkey=<pubfile>,
///                     commit.gpgsign=true,
///                     gpg.ssh.allowedSignersFile=<path>,
///                     user.name / user.email from the metadata
///   git commit → calls sshenc -Y sign → signs with enclave
///   git log --show-signature → verifies via allowed_signers
#[test]
#[ignore = "requires docker"]
fn gitenc_config_signs_commit_and_verifies() {
    if skip_if_no_docker("gitenc_config_signs_commit_and_verifies") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");

    // Write the pub file so gitenc --config can reference it.
    let pub_path = env.ssh_dir().join(format!("{SHARED_ENCLAVE_LABEL}.pub"));
    std::fs::write(&pub_path, format!("{enclave}\n")).expect("write enclave pub");

    // Set git identity on the sshenc key metadata. gitenc --config
    // copies user.name / user.email from there into the git config.
    let id = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .arg("identity")
        .arg(SHARED_ENCLAVE_LABEL)
        .arg("--name")
        .arg("e2e signer")
        .arg("--email")
        .arg("signer@e2e.test"))
    .expect("sshenc identity");
    assert!(
        id.succeeded(),
        "sshenc identity failed; stderr:\n{}",
        id.stderr
    );

    // Fresh local repo.
    let repo = env.home().join("signed");
    std::fs::create_dir_all(&repo).expect("mkdir");
    let status = env
        .git_cmd()
        .current_dir(&repo)
        .args(["init", "-q", "-b", "main"])
        .status()
        .expect("git init");
    assert!(status.success(), "git init failed");

    // Configure the repo via gitenc.
    let cfg = run(env
        .gitenc_cmd()
        .expect("gitenc cmd")
        .current_dir(&repo)
        .arg("--config")
        .arg(SHARED_ENCLAVE_LABEL))
    .expect("gitenc --config");
    assert!(
        cfg.succeeded(),
        "gitenc --config failed; stdout:\n{}\nstderr:\n{}",
        cfg.stdout,
        cfg.stderr
    );

    // Make a signed commit. The env we pass over GIT_AUTHOR_* will be
    // overridden by user.name/user.email from the repo config (git uses
    // the repo config first for commit identity).
    std::fs::write(repo.join("hello.txt"), b"hi\n").expect("write file");
    let add = run(env.git_cmd().current_dir(&repo).args(["add", "hello.txt"])).expect("git add");
    assert!(add.succeeded(), "git add failed; stderr:\n{}", add.stderr);
    let commit = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["commit", "-S", "-m", "signed"]))
    .expect("git commit -S");
    assert!(
        commit.succeeded(),
        "git commit -S failed; stdout:\n{}\nstderr:\n{}",
        commit.stdout,
        commit.stderr
    );

    // Verify the signature via git log.
    let verify = env
        .git_cmd()
        .current_dir(&repo)
        .args(["log", "--show-signature", "-1"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("git log --show-signature");
    let stdout = String::from_utf8_lossy(&verify.stdout);
    let stderr = String::from_utf8_lossy(&verify.stderr);
    let combined = format!("{stdout}\n{stderr}");
    assert!(
        verify.status.success(),
        "git log --show-signature failed; output:\n{combined}"
    );
    assert!(
        combined.contains("Good \"git\" signature") || combined.contains("Good ssh signature"),
        "expected a good ssh signature in output; got:\n{combined}"
    );
}

/// 5. gitenc falls back to on-disk keys when the agent has none.
///
/// Proves gitenc inherits the ssh-level drop-in compatibility: a user
/// with an on-disk key and no enclave keys can still use gitenc as a
/// direct git replacement.
#[test]
#[ignore = "requires docker"]
fn gitenc_falls_back_to_on_disk_when_agent_is_empty() {
    if skip_if_no_docker("gitenc_falls_back_to_on_disk_when_agent_is_empty") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    env.use_ephemeral_keys_dir().expect("ephemeral keys dir");
    let on_disk = generate_on_disk_ed25519(&env, "on-disk@e2e").expect("on-disk keygen");
    env.start_agent().expect("agent start");
    let container = SshdContainer::start(&[&on_disk]).expect("container");
    let remote = init_bare_repo(&env, &container, "fallback.git");
    let repo = make_local_repo(&env, "fallback_source", &remote);

    // No label, no enclave keys. gitenc sets GIT_SSH_COMMAND to
    // `sshenc ssh --`, which doesn't pass IdentitiesOnly, so ssh must
    // fall through to the on-disk IdentityFile. We have to point ssh at
    // the tempdir's id_ed25519 explicitly — same reason as the drop-in
    // tests (ssh resolves the default via getpwuid, not $HOME).
    let mut cmd = env.gitenc_cmd().expect("gitenc cmd");
    cmd.current_dir(&repo);
    cmd.env(
        "SSHENC_SSH_EXTRA_ARGS",
        format!(
            "-F /dev/null -o StrictHostKeyChecking=accept-new \
             -o UserKnownHostsFile={} -o NumberOfPasswordPrompts=0 \
             -o PreferredAuthentications=publickey \
             -i {}",
            env.known_hosts().display(),
            env.ssh_dir().join("id_ed25519").display(),
        ),
    );
    cmd.args(["push", "-u", "origin", "main"]);
    let outcome = run(&mut cmd).expect("gitenc push fallback");
    assert!(
        outcome.succeeded(),
        "gitenc on-disk fallback push failed; stderr:\n{}",
        outcome.stderr
    );
}
