// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Gitenc env-var, signing-opt-out, label-validation, and
//! key-store corners:
//!
//! 1. `GIT_TRACE=1` on a gitenc operation doesn't expose private
//!    key material in the trace output.
//! 2. `SSH_ASKPASS` set to a script that screams "called!" never
//!    actually fires when sshenc-agent is providing the
//!    identity — agent auth means no passphrase prompt.
//! 3. `git commit --no-gpg-sign` overrides gitenc's enforced
//!    signing — the user's per-commit opt-out works.
//! 4. `sshenc keygen --label ''` (empty label) is rejected by
//!    label validation, not silently accepted.
//! 5. `git remote set-url` to a different sshenc-mediated URL
//!    after gitenc --config — push still works against the new
//!    URL.
//! 6. `<label>.tmp` file left in keys_dir (atomic_write crashed
//!    mid-rename) doesn't break `sshenc list`.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{
    docker_skip_reason, extended_enabled, run, shared_enclave_pubkey, software_mode, SshdContainer,
    SshencEnv, SHARED_ENCLAVE_LABEL,
};

fn skip_if_no_docker(test_name: &str) -> bool {
    if let Some(reason) = docker_skip_reason() {
        eprintln!("skip {test_name}: {reason}");
        return true;
    }
    false
}

fn skip_unless_key_creation_cheap(test_name: &str) -> bool {
    if extended_enabled() || software_mode() {
        return false;
    }
    eprintln!("skip {test_name}: needs to mint keys");
    true
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

/// `GIT_TRACE=1 GIT_TRACE_PACKET=1` on a gitenc-mediated push
/// doesn't surface any byte sequence resembling private key
/// material in the trace output. The agent does signing in-
/// process; trace output observed by git is post-signature.
#[test]
#[ignore = "requires docker"]
fn git_trace_does_not_leak_private_material_during_gitenc_push() {
    if skip_if_no_docker("git_trace_does_not_leak_private_material_during_gitenc_push") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let container = SshdContainer::start(&[&enclave]).expect("sshd");

    let init = run(env
        .ssh_cmd(&container)
        .arg("-o")
        .arg(format!("IdentityAgent={}", env.socket_path().display()))
        .arg("sshtest@127.0.0.1")
        .arg(
            "mkdir -p /home/sshtest/trace.git && \
              git init --bare -b main /home/sshtest/trace.git >/dev/null",
        ))
    .expect("ssh init bare");
    assert!(init.succeeded(), "remote init: {}", init.stderr);

    let remote_url = format!(
        "ssh://sshtest@127.0.0.1:{}/home/sshtest/trace.git",
        container.host_port
    );
    plant_meta_and_pub(
        &env,
        SHARED_ENCLAVE_LABEL,
        "trace signer",
        "trace@e2e.test",
        &enclave,
    );

    let repo = env.home().join("trace-repo");
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
    std::fs::write(repo.join("README"), b"trace probe\n").expect("write");
    drop(run(env.git_cmd().current_dir(&repo).args(["add", "."])));
    drop(run(env.git_cmd().current_dir(&repo).args([
        "commit",
        "-q",
        "-m",
        "trace-init",
    ])));
    drop(run(env.git_cmd().current_dir(&repo).args([
        "remote",
        "add",
        "origin",
        &remote_url,
    ])));

    let extra = format!(
        "-F /dev/null -o StrictHostKeyChecking=accept-new \
         -o UserKnownHostsFile={known} -o ConnectTimeout=10 \
         -o NumberOfPasswordPrompts=0 -o PreferredAuthentications=publickey",
        known = env.known_hosts().display()
    );
    let push = run(env
        .git_cmd()
        .env("SSHENC_SSH_EXTRA_ARGS", &extra)
        .env("GIT_TRACE", "1")
        .env("GIT_TRACE_PACKET", "1")
        .current_dir(&repo)
        .args(["push", "-q", "-u", "origin", "main"]))
    .expect("traced push");
    assert!(push.succeeded(), "traced push: {}", push.stderr);

    // The trace output should not contain telltale private-key
    // markers. We look for OpenSSH private key boundaries and
    // PKCS#8 / SEC1 markers — none of which should ever appear
    // because the private key never leaves the enclave.
    let combined = format!("{}\n{}", push.stdout, push.stderr);
    for marker in [
        "BEGIN OPENSSH PRIVATE KEY",
        "BEGIN EC PRIVATE KEY",
        "BEGIN PRIVATE KEY",
        "BEGIN ENCRYPTED PRIVATE KEY",
        "BEGIN RSA PRIVATE KEY",
    ] {
        assert!(
            !combined.contains(marker),
            "trace output contains private-key marker '{marker}'; head:\n{}",
            &combined.chars().take(2000).collect::<String>()
        );
    }
}

/// Setting `SSH_ASKPASS` and `SSH_ASKPASS_REQUIRE=force` doesn't
/// trigger a passphrase prompt when sshenc-agent is providing
/// the identity. The agent answers the auth challenge before
/// ssh ever needs to consult the askpass helper.
#[test]
#[ignore = "requires docker"]
fn ssh_askpass_does_not_fire_with_sshenc_agent_present() {
    if skip_if_no_docker("ssh_askpass_does_not_fire_with_sshenc_agent_present") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let container = SshdContainer::start(&[&enclave]).expect("sshd");

    // Plant an askpass that writes a marker file when invoked,
    // so we can detect any spurious call.
    let askpass = env.home().join("askpass.sh");
    let marker = env.home().join("askpass-was-called.marker");
    std::fs::write(
        &askpass,
        format!(
            "#!/bin/sh\ntouch {}\necho fake-passphrase\n",
            marker.display()
        ),
    )
    .expect("write askpass");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&askpass, std::fs::Permissions::from_mode(0o755))
        .expect("chmod askpass");

    let outcome = run(env
        .scrubbed_command("ssh")
        .env("SSH_ASKPASS", &askpass)
        .env("SSH_ASKPASS_REQUIRE", "force")
        .arg("-p")
        .arg(container.host_port.to_string())
        .arg("-F")
        .arg("/dev/null")
        .arg("-o")
        .arg("StrictHostKeyChecking=accept-new")
        .arg("-o")
        .arg(format!(
            "UserKnownHostsFile={}",
            env.known_hosts().display()
        ))
        .arg("-o")
        .arg(format!("IdentityAgent={}", env.socket_path().display()))
        .arg("-o")
        .arg("ConnectTimeout=10")
        .arg("-o")
        .arg("PreferredAuthentications=publickey")
        .arg("-o")
        .arg("BatchMode=no")
        .arg("sshtest@127.0.0.1")
        .arg("--")
        .arg("echo agent-auth-ok"))
    .expect("ssh");
    assert!(
        outcome.succeeded(),
        "ssh failed; stderr:\n{}",
        outcome.stderr
    );
    assert!(
        outcome.stdout.contains("agent-auth-ok"),
        "remote command didn't run; got:\n{}",
        outcome.stdout
    );
    assert!(
        !marker.exists(),
        "SSH_ASKPASS was called even though agent provided the identity"
    );
}

/// `git commit --no-gpg-sign` overrides gitenc's enforced
/// signing. Pin that the user's per-commit opt-out works.
#[test]
#[ignore = "requires docker"]
fn git_commit_no_gpg_sign_overrides_gitenc_signing() {
    if skip_if_no_docker("git_commit_no_gpg_sign_overrides_gitenc_signing") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    plant_meta_and_pub(
        &env,
        SHARED_ENCLAVE_LABEL,
        "override signer",
        "override@e2e.test",
        &enclave,
    );

    let repo = env.home().join("override-repo");
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

    std::fs::write(repo.join("a.txt"), b"unsigned\n").expect("write");
    drop(run(env.git_cmd().current_dir(&repo).args(["add", "."])));
    let commit = run(env.git_cmd().current_dir(&repo).args([
        "commit",
        "-q",
        "--no-gpg-sign",
        "-m",
        "explicitly unsigned",
    ]))
    .expect("git commit --no-gpg-sign");
    assert!(
        commit.succeeded(),
        "git commit --no-gpg-sign failed; stderr:\n{}",
        commit.stderr
    );

    let log = run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["log", "--show-signature", "-1"]))
    .expect("git log");
    let combined = format!("{}\n{}", log.stdout, log.stderr);
    // The commit must not have a "Good signature" line — it
    // should be unsigned.
    assert!(
        !combined.contains("Good \"git\" signature") && !combined.contains("Good signature"),
        "--no-gpg-sign commit unexpectedly carries a signature; output:\n{combined}"
    );
}

/// `sshenc keygen --label ''` (empty label) is rejected by
/// label validation. Pin the diagnostic so a future
/// validator-loosening regression is caught.
#[test]
#[ignore = "requires docker"]
fn keygen_empty_label_is_rejected() {
    if skip_if_no_docker("keygen_empty_label_is_rejected") {
        return;
    }
    let env = SshencEnv::new().expect("env");

    let outcome = run(env.sshenc_cmd().expect("sshenc cmd").args([
        "keygen",
        "--label",
        "",
        "--auth-policy",
        "none",
        "--no-pub-file",
    ]))
    .expect("keygen empty label");
    assert!(
        !outcome.succeeded(),
        "keygen with empty label should fail; stdout:\n{}\nstderr:\n{}",
        outcome.stdout,
        outcome.stderr
    );
    let combined = format!("{}\n{}", outcome.stdout, outcome.stderr);
    assert!(
        !combined.contains("panicked at"),
        "panicked on empty label:\n{combined}"
    );
    assert!(
        combined.to_lowercase().contains("label")
            || combined.to_lowercase().contains("empty")
            || combined.to_lowercase().contains("invalid"),
        "rejection should mention label/empty/invalid; got:\n{combined}"
    );
}

/// `git remote set-url` after `gitenc --config` switches the
/// remote URL; subsequent push to the new URL still works
/// because the SSH command and signing config are URL-
/// independent.
#[test]
#[ignore = "requires docker"]
fn gitenc_set_url_after_config_still_pushes() {
    if skip_if_no_docker("gitenc_set_url_after_config_still_pushes") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let container = SshdContainer::start(&[&enclave]).expect("sshd");

    // Two bare repos on the same container.
    for n in ["url-a.git", "url-b.git"] {
        let init = run(env
            .ssh_cmd(&container)
            .arg("-o")
            .arg(format!("IdentityAgent={}", env.socket_path().display()))
            .arg("sshtest@127.0.0.1")
            .arg(format!(
                "mkdir -p /home/sshtest/{n} && \
                 git init --bare -b main /home/sshtest/{n} >/dev/null"
            )))
        .expect("ssh init");
        assert!(init.succeeded(), "remote init {n}: {}", init.stderr);
    }
    let url_a = format!(
        "ssh://sshtest@127.0.0.1:{}/home/sshtest/url-a.git",
        container.host_port
    );
    let url_b = format!(
        "ssh://sshtest@127.0.0.1:{}/home/sshtest/url-b.git",
        container.host_port
    );

    plant_meta_and_pub(
        &env,
        SHARED_ENCLAVE_LABEL,
        "set-url signer",
        "set-url@e2e.test",
        &enclave,
    );

    let repo = env.home().join("set-url-repo");
    std::fs::create_dir_all(&repo).expect("mkdir");
    assert!(env
        .git_cmd()
        .current_dir(&repo)
        .args(["init", "-q", "-b", "main"])
        .status()
        .expect("git init")
        .success());
    drop(run(env
        .gitenc_cmd()
        .expect("gitenc cmd")
        .current_dir(&repo)
        .args(["--config", SHARED_ENCLAVE_LABEL])));
    drop(run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["remote", "add", "origin", &url_a])));
    std::fs::write(repo.join("a"), b"x\n").expect("write");
    drop(run(env.git_cmd().current_dir(&repo).args(["add", "."])));
    drop(run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["commit", "-q", "-m", "first"])));
    let extra = format!(
        "-F /dev/null -o StrictHostKeyChecking=accept-new \
         -o UserKnownHostsFile={known} -o ConnectTimeout=10 \
         -o NumberOfPasswordPrompts=0 -o PreferredAuthentications=publickey",
        known = env.known_hosts().display()
    );
    let push_a = run(env
        .git_cmd()
        .env("SSHENC_SSH_EXTRA_ARGS", &extra)
        .current_dir(&repo)
        .args(["push", "-q", "-u", "origin", "main"]))
    .expect("push a");
    assert!(push_a.succeeded(), "push a: {}", push_a.stderr);

    // Switch URL.
    drop(run(env
        .git_cmd()
        .current_dir(&repo)
        .args(["remote", "set-url", "origin", &url_b])));

    // Push to the new URL.
    let push_b = run(env
        .git_cmd()
        .env("SSHENC_SSH_EXTRA_ARGS", &extra)
        .current_dir(&repo)
        .args(["push", "-q", "-u", "origin", "main"]))
    .expect("push b");
    assert!(
        push_b.succeeded(),
        "push to new URL after set-url failed; stderr:\n{}",
        push_b.stderr
    );
}

/// A `<label>.tmp` file in keys_dir (atomic_write crashed
/// mid-rename) doesn't break `sshenc list`. The list path
/// scans for `.meta` extensions specifically, so `.tmp` should
/// be ignored.
#[test]
#[ignore = "requires docker"]
fn list_ignores_tmp_files_in_keys_dir() {
    if skip_if_no_docker("list_ignores_tmp_files_in_keys_dir") {
        return;
    }
    if skip_unless_key_creation_cheap("list_ignores_tmp_files_in_keys_dir") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    env.use_ephemeral_keys_dir().expect("ephemeral");
    env.start_agent().expect("start agent");

    // Mint a real key so list has something legitimate to find.
    let real = "tmp-test-real";
    let kg = run(env.sshenc_cmd().expect("sshenc cmd").args([
        "keygen",
        "--label",
        real,
        "--auth-policy",
        "none",
        "--no-pub-file",
    ]))
    .expect("keygen");
    assert!(kg.succeeded(), "keygen: {}", kg.stderr);

    // Plant a stale .tmp from a hypothetical crashed atomic_write.
    let keys_dir = env.home().join(".sshenc-keys-ephemeral");
    let tmp = keys_dir.join("orphan.meta.tmp");
    std::fs::write(&tmp, b"{}").expect("plant tmp");

    let listed = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["list", "--json"]))
    .expect("list --json");
    assert!(
        listed.succeeded(),
        "list failed in presence of .tmp:\n{}",
        listed.stderr
    );
    let combined = format!("{}\n{}", listed.stdout, listed.stderr);
    assert!(
        !combined.contains("panicked at"),
        "list panicked on .tmp:\n{combined}"
    );
    let arr: serde_json::Value = serde_json::from_str(&listed.stdout).expect("list --json output");
    let entries = arr.as_array().expect("array");
    let real_seen = entries.iter().any(|e| {
        e.get("metadata")
            .and_then(|m| m.get("label"))
            .and_then(|v| v.as_str())
            == Some(real)
    });
    assert!(real_seen, "real key missing from list");
    let orphan_seen = entries.iter().any(|e| {
        e.get("metadata")
            .and_then(|m| m.get("label"))
            .and_then(|v| v.as_str())
            == Some("orphan.meta")
    });
    assert!(!orphan_seen, ".tmp file should not appear as a label");
}
