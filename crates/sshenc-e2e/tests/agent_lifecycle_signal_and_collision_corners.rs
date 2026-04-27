// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Agent signal handling, socket-collision, install/uninstall
//! interaction, and on-disk-state corners. Complements
//! `signal_handling.rs` (SIGTERM graceful shutdown) and
//! `corrupted_state.rs` (garbage JSON in meta files).
//!
//! 1. **SIGHUP doesn't crash the agent**: SIGHUP isn't a
//!    documented sshenc-agent reload signal — it should either
//!    be ignored or cause graceful shutdown, but never
//!    abort()/SIGSEGV the process. Pin "agent stays alive (or
//!    exits cleanly) across SIGHUP".
//! 2. **A second sshenc-agent on the same socket path bails
//!    cleanly**: prepare_socket_path's "socket already in use"
//!    branch. Rather than silently overwriting the listener, the
//!    second agent must exit non-zero with a clear message.
//! 3. **`sshenc uninstall` while an agent is running**: the
//!    install/uninstall paths edit ~/.ssh/config; uninstall
//!    shouldn't crash if a live agent is holding the socket. Test
//!    that uninstall succeeds even with the agent up.
//! 4. **Truncated meta file (0 bytes) on disk**: a different
//!    failure mode from garbage JSON (e.g. crash mid-fsync) — the
//!    agent must skip the entry rather than panic when listing.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{
    docker_skip_reason, extended_enabled, run, shared_enclave_pubkey, software_mode, workspace_bin,
    SshencEnv,
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
    eprintln!(
        "skip {test_name}: needs to mint keys; \
         set SSHENC_E2E_SOFTWARE=1 or SSHENC_E2E_EXTENDED=1"
    );
    true
}

/// SIGHUP currently terminates the agent (the default disposition;
/// the agent doesn't install a SIGHUP handler). The contract
/// under test: SIGHUP doesn't core-dump or hang — termination
/// is fine, and a fresh `env.start_agent()` immediately after
/// brings up a healthy replacement on the same socket. This
/// pins the *current* behavior; if the agent is later updated
/// to ignore-or-reload on SIGHUP, this test should be updated
/// to match the new contract.
#[test]
#[ignore = "requires docker"]
fn agent_terminates_cleanly_on_sighup_and_can_be_restarted() {
    if skip_if_no_docker("agent_terminates_cleanly_on_sighup_and_can_be_restarted") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("warm shared key"));
    env.start_agent().expect("start agent");

    let socket = env.socket_path();
    let pgrep = run(std::process::Command::new("pgrep")
        .arg("-f")
        .arg(socket.display().to_string()))
    .expect("pgrep");
    let pid_line = pgrep.stdout.lines().next().unwrap_or("").trim().to_string();
    if pid_line.is_empty() {
        eprintln!("skip: couldn't locate agent pid via pgrep");
        return;
    }

    let kill = std::process::Command::new("kill")
        .arg("-HUP")
        .arg(&pid_line)
        .status()
        .expect("kill");
    assert!(kill.success(), "kill -HUP exit: {kill}");

    // Give the agent's process a moment to exit.
    std::thread::sleep(Duration::from_millis(300));

    // Check the agent process is gone.
    let pgrep_after = run(std::process::Command::new("pgrep")
        .arg("-f")
        .arg(socket.display().to_string()))
    .expect("pgrep after");
    assert!(
        !pgrep_after.stdout.lines().any(|l| l.trim() == pid_line),
        "agent pid {pid_line} should have exited after SIGHUP; pgrep stdout:\n{}",
        pgrep_after.stdout
    );

    // Restart the agent — must come up cleanly on the same socket.
    // env.start_agent() is a no-op if env.agent is Some (it tracks
    // the now-dead child); call stop_agent first to clear the
    // tracked handle so start_agent really spawns again.
    env.stop_agent();
    drop(std::fs::remove_file(&socket));
    env.start_agent().expect("restart agent after SIGHUP");
    let listed = run(env
        .scrubbed_command("ssh-add")
        .env("SSH_AUTH_SOCK", &socket)
        .arg("-L"))
    .expect("ssh-add -L post-restart");
    assert!(
        listed.succeeded(),
        "post-SIGHUP-and-restart agent should answer; stderr:\n{}",
        listed.stderr
    );
}

/// A second `sshenc-agent` started against the same socket path
/// must bail cleanly with a useful diagnostic, not silently
/// hijack the listener or crash.
#[test]
#[ignore = "requires docker"]
fn second_agent_on_same_socket_path_bails() {
    if skip_if_no_docker("second_agent_on_same_socket_path_bails") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("warm shared key"));
    env.start_agent().expect("start first agent");

    // Try to bring up a second agent against the same socket path.
    // prepare_socket_path's UnixStream::connect succeeds (first
    // agent is listening), so the second agent should bail with
    // "agent socket already in use" before binding.
    let bin = workspace_bin("sshenc-agent").expect("agent binary");
    let mut second = env
        .scrubbed_command(&bin)
        .arg("--foreground")
        .arg("--socket")
        .arg(env.socket_path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn second agent");

    let deadline = Instant::now() + Duration::from_secs(5);
    let exit_status = loop {
        if let Some(status) = second.try_wait().expect("try_wait") {
            break status;
        }
        if Instant::now() >= deadline {
            drop(second.kill());
            panic!("second agent didn't exit; expected it to bail");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(
        !exit_status.success(),
        "second agent should exit non-zero on already-bound socket"
    );
    let out = second.wait_with_output().expect("wait second");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.to_lowercase().contains("already in use")
            || stderr.to_lowercase().contains("address already")
            || stderr.to_lowercase().contains("socket"),
        "expected diagnostic about socket already in use; got:\n{stderr}"
    );

    // First agent must still be alive and serving.
    let listed = run(env
        .scrubbed_command("ssh-add")
        .env("SSH_AUTH_SOCK", env.socket_path())
        .arg("-L"))
    .expect("ssh-add -L");
    assert!(
        listed.succeeded(),
        "first agent should still serve; stderr:\n{}",
        listed.stderr
    );
}

/// `sshenc uninstall` while a live agent holds the socket
/// completes successfully and removes the managed block.
/// install/uninstall edit ~/.ssh/config; the live socket
/// shouldn't interfere.
#[test]
#[ignore = "requires docker"]
fn sshenc_uninstall_while_agent_running() {
    if skip_if_no_docker("sshenc_uninstall_while_agent_running") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("warm shared key"));
    env.start_agent().expect("start agent");

    std::fs::create_dir_all(env.ssh_dir()).expect("mkdir ssh dir");
    let install =
        run(env.sshenc_cmd().expect("sshenc cmd").arg("install")).expect("sshenc install");
    assert!(install.succeeded(), "install: {}", install.stderr);

    // Confirm the live agent's socket is still bound.
    assert!(env.socket_path().exists(), "agent socket should exist");

    // Uninstall — must succeed despite the agent holding the socket.
    let uninstall =
        run(env.sshenc_cmd().expect("sshenc cmd").arg("uninstall")).expect("sshenc uninstall");
    assert!(
        uninstall.succeeded(),
        "uninstall while agent running failed; stderr:\n{}",
        uninstall.stderr
    );

    let config = std::fs::read_to_string(env.ssh_dir().join("config")).expect("read config");
    assert!(
        !config.contains("BEGIN sshenc managed block"),
        "managed block should be gone after uninstall; config:\n{config}"
    );

    drop(std::fs::remove_file(env.socket_path()));
}

/// A meta file truncated to 0 bytes on disk doesn't crash
/// `sshenc list`; the entry is skipped (or surfaced cleanly)
/// rather than panicking the listing.
#[test]
#[ignore = "requires docker"]
fn list_skips_or_surfaces_truncated_zero_byte_meta() {
    if skip_if_no_docker("list_skips_or_surfaces_truncated_zero_byte_meta") {
        return;
    }
    if skip_unless_key_creation_cheap("list_skips_or_surfaces_truncated_zero_byte_meta") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    env.use_ephemeral_keys_dir().expect("ephemeral");
    env.start_agent().expect("start agent");

    let keys_dir = env.home().join(".sshenc-keys-ephemeral");
    let label = "trunc-victim";
    let kg = run(env.sshenc_cmd().expect("sshenc cmd").args([
        "keygen",
        "--label",
        label,
        "--auth-policy",
        "none",
        "--no-pub-file",
    ]))
    .expect("keygen");
    assert!(kg.succeeded(), "keygen: {}", kg.stderr);

    // Truncate the .meta to 0 bytes — simulates a crash mid-fsync.
    let meta = keys_dir.join(format!("{label}.meta"));
    std::fs::write(&meta, b"").expect("truncate meta");
    assert_eq!(
        std::fs::metadata(&meta).expect("stat").len(),
        0,
        "meta should be zero bytes"
    );

    let listed = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["list", "--json"]))
    .expect("sshenc list --json");
    // The list command must not panic. Whether it succeeds (entry
    // skipped, valid JSON output) or fails cleanly is the agent's
    // contract; what matters is "no `panicked at` in output".
    let combined = format!("{}\n{}", listed.stdout, listed.stderr);
    assert!(
        !combined.contains("panicked at"),
        "list panicked on zero-byte meta:\n{combined}"
    );
}
