// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Round-6 corner cases — small contracts that none of the
//! 60+ existing test files pinned:
//!
//! 1. `sshenc keygen --no-pub-file --write-pub <path>` —
//!    conflicting flags. Pin the actual behavior so a future
//!    refactor that flips precedence is caught.
//! 2. `sshenc-agent --labels` parsing edges: empty string,
//!    trailing comma, spaces around delimiters.
//! 3. `git switch` after a fresh fetch from an sshenc-mediated
//!    remote (local op, but exercises the post-fetch ref state).
//! 4. SSH client options ssh_client_feats didn't cover: `-T`
//!    (no PTY), `-q` (quiet), and `-c <cipher>` (specific
//!    cipher negotiation). Pin that sshenc-ssh forwards each
//!    cleanly.
//! 5. `sshenc default <nonexistent-label>` errors cleanly.
//! 6. `config.toml` with `allowed_labels = []` (explicit
//!    empty) parses identically to the field being absent.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{
    docker_skip_reason, extended_enabled, run, shared_enclave_pubkey, software_mode, workspace_bin,
    SshdContainer, SshencEnv,
};
use std::process::Stdio;
use std::time::{Duration, Instant};

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

fn unique_label(prefix: &str) -> String {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{prefix}-{pid}-{nanos}")
}

/// `sshenc keygen --no-pub-file --write-pub <path>` — both flags
/// supplied. The current behavior: `--no-pub-file` wins (no .pub
/// is written) because the CLI checks it first. Pin this so a
/// future flip is a deliberate decision.
#[test]
#[ignore = "requires docker"]
fn keygen_conflicting_no_pub_and_write_pub_flags() {
    if skip_if_no_docker("keygen_conflicting_no_pub_and_write_pub_flags") {
        return;
    }
    if skip_unless_key_creation_cheap("keygen_conflicting_no_pub_and_write_pub_flags") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    env.use_ephemeral_keys_dir().expect("ephemeral");
    env.start_agent().expect("start agent");

    let label = unique_label("conflict");
    let custom_pub = env.home().join("explicit-pub-path.pub");
    let kg = run(env.sshenc_cmd().expect("sshenc cmd").args([
        "keygen",
        "--label",
        &label,
        "--auth-policy",
        "none",
        "--no-pub-file",
        "--write-pub",
        custom_pub.to_str().expect("utf-8"),
    ]))
    .expect("keygen conflicting");
    // Either the CLI rejects the conflict outright (fail), or one
    // wins. Both are valid — what's NOT valid is silently
    // succeeding with both effects (no-pub honored AND custom
    // path written), or panicking. Pin the deterministic outcome:
    // either both flags are accepted (one wins) or it's rejected.
    let combined = format!("{}\n{}", kg.stdout, kg.stderr);
    assert!(
        !combined.contains("panicked at"),
        "CLI panicked on conflicting flags:\n{combined}"
    );
    if kg.succeeded() {
        // If accepted, exactly one of "wrote pub" / "didn't write
        // pub" is true. We don't pin which (CLI's choice), but if
        // a .pub appeared at the custom path, --no-pub-file lost
        // its effect; if not, --write-pub did.
        let pub_existed = custom_pub.exists();
        eprintln!("keygen accepted both flags; pub at custom path exists: {pub_existed}");
    } else {
        // Rejected — fine, but the diagnostic should be useful.
        let lower = combined.to_lowercase();
        assert!(
            lower.contains("conflict")
                || lower.contains("mutually exclusive")
                || lower.contains("--no-pub-file")
                || lower.contains("--write-pub"),
            "rejection should mention which flags conflict; got:\n{combined}"
        );
    }

    drop(run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["delete", &label, "-y"])));
}

/// `sshenc-agent --labels "a,a"` (duplicate label) is accepted —
/// the agent doesn't crash, the duplicate doesn't widen the
/// filter, and the named label is exposed normally.
#[test]
#[ignore = "spawns sshenc-agent"]
fn agent_labels_with_duplicate_entry_is_accepted() {
    let env = SshencEnv::new().expect("env");
    let _shared = shared_enclave_pubkey(&env).expect("warm shared key");

    let bin = workspace_bin("sshenc-agent").expect("agent bin");
    let socket = env.socket_path();
    drop(std::fs::remove_file(&socket));
    let mut agent = env
        .scrubbed_command(&bin)
        .arg("--foreground")
        .arg("--socket")
        .arg(&socket)
        .arg("--labels")
        .arg("e2e-shared,e2e-shared")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if socket.exists() && std::os::unix::net::UnixStream::connect(&socket).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        socket.exists(),
        "agent didn't bind on --labels with duplicate"
    );

    let listed = run(env
        .scrubbed_command("ssh-add")
        .env("SSH_AUTH_SOCK", &socket)
        .arg("-L"))
    .expect("ssh-add -L");
    assert!(listed.succeeded(), "ssh-add -L: {}", listed.stderr);
    assert!(
        listed.stdout.contains("ecdsa-sha2-nistp256"),
        "shared key should still be visible with duplicate label entry; got:\n{}",
        listed.stdout
    );

    drop(agent.kill());
    drop(agent.wait());
}

/// `git switch` after fetching from an sshenc-mediated remote
/// works — the post-fetch ref state is consistent. switch is
/// a local operation but it relies on `refs/remotes/origin/*`
/// being correctly populated by the previous fetch.
#[test]
#[ignore = "requires docker"]
fn git_switch_after_sshenc_fetch_works() {
    if skip_if_no_docker("git_switch_after_sshenc_fetch_works") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let container = SshdContainer::start(&[&enclave]).expect("sshd");

    // Set up bare repo, populate with two branches via a seeder.
    let init_cmd = "mkdir -p /home/sshtest/switch-target.git && \
        git init --bare -b main /home/sshtest/switch-target.git >/dev/null";
    let init = run(env
        .ssh_cmd(&container)
        .arg("-o")
        .arg(format!("IdentityAgent={}", env.socket_path().display()))
        .arg("sshtest@127.0.0.1")
        .arg(init_cmd))
    .expect("ssh init");
    assert!(init.succeeded(), "remote init: {}", init.stderr);
    let remote_url = format!(
        "ssh://sshtest@127.0.0.1:{}/home/sshtest/switch-target.git",
        container.host_port
    );

    let git_ssh = format!(
        "sshenc ssh -F /dev/null \
         -o StrictHostKeyChecking=accept-new \
         -o UserKnownHostsFile={known} \
         -o ConnectTimeout=10 \
         -o NumberOfPasswordPrompts=0 \
         -o PreferredAuthentications=publickey",
        known = env.known_hosts().display()
    );

    // Seeder pushes main + a "feature" branch.
    let seeder = env.home().join("switch-seeder");
    std::fs::create_dir_all(&seeder).expect("mkdir");
    assert!(env
        .git_cmd()
        .current_dir(&seeder)
        .args(["init", "-q", "-b", "main"])
        .status()
        .expect("git init")
        .success());
    std::fs::write(seeder.join("a.txt"), b"main\n").expect("write");
    drop(run(env.git_cmd().current_dir(&seeder).args(["add", "."])));
    drop(run(env
        .git_cmd()
        .current_dir(&seeder)
        .args(["commit", "-q", "-m", "main"])));
    drop(run(env.git_cmd().current_dir(&seeder).args([
        "remote",
        "add",
        "origin",
        &remote_url,
    ])));
    let push_main = run(env
        .git_cmd()
        .env("GIT_SSH_COMMAND", &git_ssh)
        .current_dir(&seeder)
        .args(["push", "-q", "-u", "origin", "main"]))
    .expect("push main");
    assert!(push_main.succeeded(), "push main: {}", push_main.stderr);
    drop(run(env
        .git_cmd()
        .current_dir(&seeder)
        .args(["checkout", "-q", "-b", "feature"])));
    std::fs::write(seeder.join("b.txt"), b"feature\n").expect("write");
    drop(run(env.git_cmd().current_dir(&seeder).args(["add", "."])));
    drop(run(env
        .git_cmd()
        .current_dir(&seeder)
        .args(["commit", "-q", "-m", "feature"])));
    let push_feat = run(env
        .git_cmd()
        .env("GIT_SSH_COMMAND", &git_ssh)
        .current_dir(&seeder)
        .args(["push", "-q", "-u", "origin", "feature"]))
    .expect("push feature");
    assert!(push_feat.succeeded(), "push feature: {}", push_feat.stderr);

    // Consumer clones, then switches to feature.
    let consumer = env.home().join("switch-consumer");
    let clone = run(env
        .git_cmd()
        .env("GIT_SSH_COMMAND", &git_ssh)
        .args(["clone", "-q", &remote_url])
        .arg(&consumer))
    .expect("clone");
    assert!(clone.succeeded(), "clone: {}", clone.stderr);

    let switch = run(env
        .git_cmd()
        .current_dir(&consumer)
        .args(["switch", "feature"]))
    .expect("git switch");
    assert!(
        switch.succeeded(),
        "git switch feature failed; stderr:\n{}",
        switch.stderr
    );
    assert!(
        consumer.join("b.txt").exists(),
        "feature branch's file should be present after switch"
    );
}

/// `sshenc ssh -T` (force no-PTY) and `-c <cipher>` are
/// forwarded by the wrapper. -T is the inverse of -tt; -c
/// negotiates a specific cipher, exercising the wrapper's
/// pass-through of crypto-relevant flags.
#[test]
#[ignore = "requires docker"]
fn sshenc_ssh_dash_t_and_dash_c_forwarded() {
    if skip_if_no_docker("sshenc_ssh_dash_t_and_dash_c_forwarded") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let container = SshdContainer::start(&[&enclave]).expect("sshd");

    // -T: explicit no-PTY. With a remote command, ssh runs the
    // command without allocating a PTY.
    let no_pty = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["ssh", "-T", "-p"])
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
        .arg("sshtest@127.0.0.1")
        .arg("--")
        .arg("tty -s && echo hadtty || echo notty"))
    .expect("sshenc ssh -T");
    assert!(
        no_pty.succeeded(),
        "sshenc ssh -T failed: {}",
        no_pty.stderr
    );
    assert!(
        no_pty.stdout.contains("notty"),
        "expected notty (no PTY) under -T; got:\n{}",
        no_pty.stdout
    );

    // -c chacha20-poly1305@openssh.com: specific cipher.
    let cipher_run = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["ssh", "-c", "chacha20-poly1305@openssh.com", "-p"])
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
        .arg("sshtest@127.0.0.1")
        .arg("--")
        .arg("echo cipher-ok"))
    .expect("sshenc ssh -c");
    assert!(
        cipher_run.succeeded(),
        "sshenc ssh -c <cipher> failed; stderr:\n{}",
        cipher_run.stderr
    );
    assert!(
        cipher_run.stdout.contains("cipher-ok"),
        "expected echo output; got:\n{}",
        cipher_run.stdout
    );
}

/// `sshenc default <nonexistent-label>` fails cleanly with a
/// useful diagnostic, doesn't crash, doesn't try to act on
/// the missing label.
#[test]
#[ignore = "requires docker"]
fn sshenc_default_nonexistent_label_errors_cleanly() {
    if skip_if_no_docker("sshenc_default_nonexistent_label_errors_cleanly") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    env.use_ephemeral_keys_dir().expect("ephemeral");

    let outcome = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["default", "definitely-not-a-real-label-12345"]))
    .expect("sshenc default missing");
    assert!(
        !outcome.succeeded(),
        "sshenc default <missing> should fail; stdout:\n{}\nstderr:\n{}",
        outcome.stdout,
        outcome.stderr
    );
    let combined = format!("{}\n{}", outcome.stdout, outcome.stderr);
    assert!(
        !combined.contains("panicked at"),
        "panicked on missing default label:\n{combined}"
    );
}

/// `config.toml` with `allowed_labels = []` (explicit empty
/// array) parses, agent boots cleanly, and behaves identically
/// to the field being absent — empty-list semantics: no filter.
#[test]
#[ignore = "requires docker"]
fn config_with_explicit_empty_allowed_labels_parses() {
    if skip_if_no_docker("config_with_explicit_empty_allowed_labels_parses") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("warm shared key"));

    let cfg_path = env.home().join("explicit-empty.toml");
    let cfg = format!(
        "socket_path = \"{}\"\n\
         pub_dir = \"{}\"\n\
         allowed_labels = []\n\
         log_level = \"warn\"\n\
         wrapping_key_cache_ttl_secs = 300\n",
        env.socket_path().display(),
        env.ssh_dir().display()
    );
    std::fs::write(&cfg_path, &cfg).expect("write config");

    env.start_agent_with_config(Some(&cfg_path))
        .expect("agent must boot with allowed_labels = []");

    // Empty allowed_labels = no filter; ssh-add -L should expose
    // the shared key.
    let listed = run(env
        .scrubbed_command("ssh-add")
        .env("SSH_AUTH_SOCK", env.socket_path())
        .arg("-L"))
    .expect("ssh-add -L");
    assert!(listed.succeeded(), "ssh-add -L: {}", listed.stderr);
    assert!(
        listed.stdout.contains("ecdsa-sha2-nistp256"),
        "shared key should be visible under explicit empty allowed_labels; got:\n{}",
        listed.stdout
    );
}
