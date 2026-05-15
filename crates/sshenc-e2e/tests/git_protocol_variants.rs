// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Git protocol-shape variants the gitenc test files don't cover:
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
//! 3. `git clone --depth 1` followed by a signed commit in the
//!    shallow clone. Pins that gitenc signing works in a shallow
//!    repo where the full history is absent.
//! 4. `git sparse-checkout set` followed by a signed commit. Pins
//!    that the sparse working-directory state doesn't confuse the
//!    signing path (git signs the index, not the working tree, but
//!    a regression in sshenc's agent forwarding could surface here).

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

/// After a `git clone --depth 1`, make a signed commit in the shallow
/// clone and verify it with `git verify-commit`. Pins that gitenc
/// signing works inside a shallow repo where the full history is absent.
#[test]
#[ignore = "requires docker"]
fn git_shallow_clone_then_signed_commit_is_verifiable() {
    if skip_if_no_docker("git_shallow_clone_then_signed_commit_is_verifiable") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("enclave");
    env.start_agent().expect("start agent");
    plant_meta(
        &env,
        SHARED_ENCLAVE_LABEL,
        "shallow signer",
        "shallow-sign@e2e.test",
    );
    let pub_path = env.ssh_dir().join(format!("{SHARED_ENCLAVE_LABEL}.pub"));
    std::fs::create_dir_all(env.ssh_dir()).expect("mkdir ssh dir");
    std::fs::write(&pub_path, format!("{enclave}\n")).expect("write pub");

    let container = SshdContainer::start(&[&enclave]).expect("sshd");
    let remote_url = init_bare_repo(&env, &container, "shallow-sign-target.git");
    let extra = ssh_extra_args(&env);

    // Seed the bare repo with an initial commit via a temporary local repo.
    let seeder = env.home().join("shallow-sign-seeder");
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
    .expect("gitenc --config seeder");
    assert!(cfg.succeeded(), "gitenc --config seeder: {}", cfg.stderr);
    let add_remote =
        run(env
            .git_cmd()
            .current_dir(&seeder)
            .args(["remote", "add", "origin", &remote_url]))
        .expect("remote add");
    assert!(add_remote.succeeded(), "remote add: {}", add_remote.stderr);
    std::fs::write(seeder.join("seed.txt"), b"seed commit\n").expect("write seed");
    let add =
        run(env.git_cmd().current_dir(&seeder).args(["add", "seed.txt"])).expect("git add seed");
    assert!(add.succeeded(), "git add: {}", add.stderr);
    let commit =
        run(env
            .git_cmd()
            .current_dir(&seeder)
            .args(["commit", "-q", "-m", "initial seed"]))
        .expect("git commit seed");
    assert!(commit.succeeded(), "git commit seed: {}", commit.stderr);
    let push = run(env
        .git_cmd()
        .env("SSHENC_SSH_EXTRA_ARGS", &extra)
        .current_dir(&seeder)
        .args(["push", "-q", "-u", "origin", "main"]))
    .expect("seed push");
    assert!(push.succeeded(), "seed push: {}", push.stderr);

    // Shallow-clone the seeded bare repo.
    let git_ssh = format!(
        "sshenc ssh -F /dev/null \
         -o StrictHostKeyChecking=accept-new \
         -o UserKnownHostsFile={known} \
         -o ConnectTimeout=10 \
         -o NumberOfPasswordPrompts=0 \
         -o PreferredAuthentications=publickey",
        known = env.known_hosts().display()
    );
    let cloned = env.home().join("shallow-sign-clone");
    let clone = run(env
        .git_cmd()
        .env("SSHENC_SSH_EXTRA_ARGS", &extra)
        .env("GIT_SSH_COMMAND", &git_ssh)
        .args(["clone", "--depth", "1", "-q", &remote_url])
        .arg(&cloned))
    .expect("git clone --depth 1");
    assert!(
        clone.succeeded(),
        "git clone --depth 1 failed; stderr:\n{}",
        clone.stderr
    );

    // Configure gitenc in the shallow clone for signing.
    let cfg2 = run(env
        .gitenc_cmd()
        .expect("gitenc cmd")
        .current_dir(&cloned)
        .args(["--config", SHARED_ENCLAVE_LABEL]))
    .expect("gitenc --config clone");
    assert!(cfg2.succeeded(), "gitenc --config clone: {}", cfg2.stderr);

    // Make a new signed commit in the shallow clone.
    std::fs::write(cloned.join("shallow-new.txt"), b"added in shallow clone\n").expect("write");
    let add2 = run(env
        .git_cmd()
        .current_dir(&cloned)
        .args(["add", "shallow-new.txt"]))
    .expect("git add");
    assert!(add2.succeeded(), "git add: {}", add2.stderr);
    let commit2 = run(env.git_cmd().current_dir(&cloned).args([
        "commit",
        "-q",
        "-m",
        "signed in shallow clone",
    ]))
    .expect("git commit in shallow clone");
    assert!(
        commit2.succeeded(),
        "git commit in shallow clone failed; stderr:\n{}",
        commit2.stderr
    );

    // Verify the new commit's signature.
    let verify = run(env
        .git_cmd()
        .current_dir(&cloned)
        .args(["verify-commit", "HEAD"]))
    .expect("git verify-commit");
    assert!(
        verify.succeeded(),
        "git verify-commit failed in shallow clone; stdout:\n{}\nstderr:\n{}",
        verify.stdout,
        verify.stderr
    );
    let combined = format!("{}\n{}", verify.stdout, verify.stderr);
    assert!(
        combined.contains("Good") || combined.contains("good"),
        "git verify-commit should report Good signature; got:\n{combined}"
    );
}

/// `git sparse-checkout set` followed by a signed commit.
/// Pins that the sparse working-directory state (some files absent
/// from the working tree) doesn't interfere with commit signing.
#[test]
#[ignore = "requires docker"]
fn git_sparse_checkout_then_signed_commit_is_verifiable() {
    if skip_if_no_docker("git_sparse_checkout_then_signed_commit_is_verifiable") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("enclave");
    env.start_agent().expect("start agent");
    plant_meta(
        &env,
        SHARED_ENCLAVE_LABEL,
        "sparse signer",
        "sparse@e2e.test",
    );
    let pub_path = env.ssh_dir().join(format!("{SHARED_ENCLAVE_LABEL}.pub"));
    std::fs::create_dir_all(env.ssh_dir()).expect("mkdir ssh dir");
    std::fs::write(&pub_path, format!("{enclave}\n")).expect("write pub");

    let container = SshdContainer::start(&[&enclave]).expect("sshd");
    let remote_url = init_bare_repo(&env, &container, "sparse-sign-target.git");
    let extra = ssh_extra_args(&env);

    // Seed the bare repo with a two-directory tree.
    let seeder = env.home().join("sparse-sign-seeder");
    std::fs::create_dir_all(seeder.join("dirA")).expect("mkdir dirA");
    std::fs::create_dir_all(seeder.join("dirB")).expect("mkdir dirB");
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
    .expect("gitenc --config seeder");
    assert!(cfg.succeeded(), "gitenc --config: {}", cfg.stderr);
    let add_remote =
        run(env
            .git_cmd()
            .current_dir(&seeder)
            .args(["remote", "add", "origin", &remote_url]))
        .expect("remote add");
    assert!(add_remote.succeeded());
    std::fs::write(seeder.join("dirA").join("a.txt"), b"file in A\n").expect("write a.txt");
    std::fs::write(seeder.join("dirB").join("b.txt"), b"file in B\n").expect("write b.txt");
    let add = run(env.git_cmd().current_dir(&seeder).args(["add", "."])).expect("git add");
    assert!(add.succeeded(), "git add: {}", add.stderr);
    let commit = run(env.git_cmd().current_dir(&seeder).args([
        "commit",
        "-q",
        "-m",
        "seed with dirA and dirB",
    ]))
    .expect("git commit seed");
    assert!(commit.succeeded(), "seed commit: {}", commit.stderr);
    let push = run(env
        .git_cmd()
        .env("SSHENC_SSH_EXTRA_ARGS", &extra)
        .current_dir(&seeder)
        .args(["push", "-q", "-u", "origin", "main"]))
    .expect("seed push");
    assert!(push.succeeded(), "seed push: {}", push.stderr);

    // Clone the repo.
    let git_ssh = format!(
        "sshenc ssh -F /dev/null \
         -o StrictHostKeyChecking=accept-new \
         -o UserKnownHostsFile={known} \
         -o ConnectTimeout=10 \
         -o NumberOfPasswordPrompts=0 \
         -o PreferredAuthentications=publickey",
        known = env.known_hosts().display()
    );
    let cloned = env.home().join("sparse-sign-clone");
    let clone = run(env
        .git_cmd()
        .env("SSHENC_SSH_EXTRA_ARGS", &extra)
        .env("GIT_SSH_COMMAND", &git_ssh)
        .args(["clone", "-q", &remote_url])
        .arg(&cloned))
    .expect("git clone");
    assert!(clone.succeeded(), "git clone: {}", clone.stderr);

    // Set up sparse checkout: only check out dirA, leave dirB absent.
    let sparse_init =
        run(env
            .git_cmd()
            .current_dir(&cloned)
            .args(["sparse-checkout", "init", "--cone"]))
        .expect("sparse-checkout init");
    assert!(
        sparse_init.succeeded(),
        "sparse-checkout init: {}",
        sparse_init.stderr
    );
    let sparse_set =
        run(env
            .git_cmd()
            .current_dir(&cloned)
            .args(["sparse-checkout", "set", "dirA"]))
        .expect("sparse-checkout set");
    assert!(
        sparse_set.succeeded(),
        "sparse-checkout set: {}",
        sparse_set.stderr
    );
    // dirB should be absent from the working tree.
    assert!(
        !cloned.join("dirB").exists(),
        "dirB should be absent from sparse checkout"
    );

    // Configure gitenc for signing in the sparse clone.
    let cfg2 = run(env
        .gitenc_cmd()
        .expect("gitenc cmd")
        .current_dir(&cloned)
        .args(["--config", SHARED_ENCLAVE_LABEL]))
    .expect("gitenc --config");
    assert!(cfg2.succeeded(), "gitenc --config: {}", cfg2.stderr);

    // Add a file and make a signed commit.
    std::fs::write(
        cloned.join("dirA").join("new.txt"),
        b"added in sparse clone\n",
    )
    .expect("write new.txt");
    let add2 = run(env
        .git_cmd()
        .current_dir(&cloned)
        .args(["add", "dirA/new.txt"]))
    .expect("git add");
    assert!(add2.succeeded(), "git add: {}", add2.stderr);
    let commit2 = run(env.git_cmd().current_dir(&cloned).args([
        "commit",
        "-q",
        "-m",
        "signed in sparse checkout",
    ]))
    .expect("git commit sparse");
    assert!(
        commit2.succeeded(),
        "git commit in sparse checkout failed; stderr:\n{}",
        commit2.stderr
    );

    // Verify the signed commit.
    let verify = run(env
        .git_cmd()
        .current_dir(&cloned)
        .args(["verify-commit", "HEAD"]))
    .expect("git verify-commit");
    assert!(
        verify.succeeded(),
        "git verify-commit failed in sparse checkout; stdout:\n{}\nstderr:\n{}",
        verify.stdout,
        verify.stderr
    );
    let combined = format!("{}\n{}", verify.stdout, verify.stderr);
    assert!(
        combined.contains("Good") || combined.contains("good"),
        "git verify-commit should report Good signature; got:\n{combined}"
    );
    // Make sure there's no "error" in the verify output.
    assert!(
        !combined.to_lowercase().contains("error"),
        "git verify-commit contained 'error'; got:\n{combined}"
    );
}
