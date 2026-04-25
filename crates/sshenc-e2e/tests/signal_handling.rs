// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! sshenc-agent signal-handling and socket-lifecycle behavior.
//!
//! The agent is a long-running daemon. These invariants matter:
//!
//! - SIGINT (Ctrl-C) → clean shutdown, exit 0, socket file removed.
//!   Without this, repeated dev-loop runs would leak socket files in
//!   `~/.sshenc/`.
//! - On restart after an ungraceful kill (the agent didn't get a
//!   chance to clean up), the new agent must replace the stale
//!   socket file rather than fail to bind. `cli_respawns_agent_after_kill`
//!   in `small_subcommands.rs` covers respawn end-to-end; this file
//!   covers the agent-side socket-replacement invariant directly.
//! - The agent must refuse to bind to a path that exists but is not
//!   a socket (regular file). Without this check, a stray file at
//!   the agent path could be silently truncated or replaced.
//!
//! Unix-only: signals and Unix sockets. The Windows agent uses named
//! pipes which have entirely different lifecycle semantics. Signal
//! delivery uses the system `kill` binary so we don't pull libc into
//! sshenc-e2e just for these tests.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{docker_skip_reason, workspace_bin, SshencEnv};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn skip_if_no_docker(test_name: &str) -> bool {
    if let Some(reason) = docker_skip_reason() {
        eprintln!("skip {test_name}: {reason}");
        return true;
    }
    false
}

/// Spawn the agent in foreground mode with stderr captured. Caller
/// is responsible for terminating + waiting on the child.
fn spawn_agent_foreground(env: &SshencEnv) -> Child {
    let bin = workspace_bin("sshenc-agent").expect("agent binary");
    env.scrubbed_command(&bin)
        .arg("--foreground")
        .arg("--socket")
        .arg(env.socket_path())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sshenc-agent")
}

/// Wait until the agent's socket appears (it's listening) or the
/// deadline passes. Panics on timeout — the failure mode for
/// signal/lifecycle tests is "the daemon didn't come up".
fn wait_for_socket(socket: &Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if UnixStream::connect(socket).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("socket never became available at {}", socket.display());
}

/// Wait for the child to exit, returning its status. Panics on
/// timeout (kills child first).
fn wait_for_exit(mut child: Child, timeout: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status,
            Ok(None) if Instant::now() >= deadline => {
                drop(child.kill());
                drop(child.wait());
                panic!("agent did not exit within {timeout:?}");
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(25)),
            Err(e) => panic!("try_wait: {e}"),
        }
    }
}

/// Send a signal to the child via the system `kill` binary
/// (`kill -<sig> <pid>`). Avoids pulling libc into sshenc-e2e.
fn send_signal(child: &Child, sig: &str) {
    let pid = child.id().to_string();
    let status = Command::new("kill")
        .arg(format!("-{sig}"))
        .arg(&pid)
        .status()
        .expect("spawn kill");
    assert!(status.success(), "kill -{sig} {pid} failed: {status:?}");
}

/// SIGINT must trigger a clean shutdown: agent exits 0 and the
/// socket file is removed. Verifies the `signal::ctrl_c` branch in
/// the accept loop fires the cleanup.
#[test]
#[ignore = "requires docker"]
fn agent_shuts_down_cleanly_on_sigint() {
    if skip_if_no_docker("agent_shuts_down_cleanly_on_sigint") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let child = spawn_agent_foreground(&env);
    wait_for_socket(&env.socket_path(), Duration::from_secs(5));
    assert!(env.socket_path().exists(), "socket should be present");

    send_signal(&child, "INT");
    let status = wait_for_exit(child, Duration::from_secs(5));
    assert!(
        status.success(),
        "agent should exit 0 after SIGINT; got status: {status:?}"
    );
    assert!(
        !env.socket_path().exists(),
        "socket file should have been removed on clean shutdown; still at {}",
        env.socket_path().display()
    );
}

/// On restart after an ungraceful kill (SIGKILL — the agent didn't
/// get a chance to clean up), the new agent must replace the stale
/// socket file rather than fail to bind. This is the agent-side
/// invariant that makes the CLI auto-respawn path work.
#[test]
#[ignore = "requires docker"]
fn agent_replaces_stale_socket_on_restart() {
    if skip_if_no_docker("agent_replaces_stale_socket_on_restart") {
        return;
    }
    let env = SshencEnv::new().expect("env");

    // First instance: start, then SIGKILL (no cleanup).
    let first = spawn_agent_foreground(&env);
    wait_for_socket(&env.socket_path(), Duration::from_secs(5));
    send_signal(&first, "KILL");
    let _ = wait_for_exit(first, Duration::from_secs(5));
    // Stale socket file must remain after SIGKILL — that's the
    // whole point of the test. Sanity check it.
    assert!(
        env.socket_path().exists(),
        "SIGKILL should leave a stale socket; got: socket missing already"
    );
    // But the listening process is gone, so connect should now fail.
    assert!(
        UnixStream::connect(env.socket_path()).is_err(),
        "stale socket should no longer accept connections after SIGKILL"
    );

    // Second instance: should bind to the same path, replacing the stale file.
    let second = spawn_agent_foreground(&env);
    wait_for_socket(&env.socket_path(), Duration::from_secs(5));
    assert!(
        UnixStream::connect(env.socket_path()).is_ok(),
        "second agent should accept connections at the same socket path"
    );

    // Clean up the second instance so the test exits clean.
    send_signal(&second, "INT");
    let _ = wait_for_exit(second, Duration::from_secs(5));
}

/// The agent must refuse to bind to a socket path where a
/// non-socket file already exists. Without this check a stray
/// regular file at `~/.sshenc/agent.sock` could be silently
/// replaced; a blunt refusal forces the user to intervene.
#[test]
#[ignore = "requires docker"]
fn agent_refuses_to_bind_over_non_socket_path() {
    if skip_if_no_docker("agent_refuses_to_bind_over_non_socket_path") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let socket = env.socket_path();
    std::fs::create_dir_all(socket.parent().unwrap()).expect("mkdir socket parent");

    // Plant a regular file (NOT a socket) at the agent socket path.
    std::fs::write(&socket, b"not a socket\n").expect("plant regular file");

    let child = spawn_agent_foreground(&env);
    let status = wait_for_exit(child, Duration::from_secs(5));
    assert!(
        !status.success(),
        "agent should refuse to start when socket path is a regular file; got status: {status:?}"
    );

    // The regular file we planted must be untouched.
    let after = std::fs::read(&socket).expect("read socket-path file");
    assert_eq!(
        after, b"not a socket\n",
        "agent must not modify a non-socket file it refused to bind to"
    );
}
