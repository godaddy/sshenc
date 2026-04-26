// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `sshenc-agent` Unix socket file mode and parent-directory mode.
//!
//! The agent serves SSH-signing RPCs over a Unix domain socket. If
//! the socket file is world- or group-readable, any user on the
//! system that can `connect()` to it can request signatures from
//! the agent (whose `verify_peer_uid` check is the only remaining
//! gate, and that check should not be the *only* line of defense).
//! `server.rs` sets the socket file to 0o600 explicitly after
//! binding; `prepare_socket_path` sets the parent directory to
//! 0o700. Both are security-relevant invariants and worth pinning
//! in e2e — a regression here would silently widen the attack
//! surface to every other local user.
//!
//! These tests boot a real `sshenc-agent --foreground`, then
//! `stat()` the socket and its parent. They don't try to connect
//! from another uid because CI containers run as a single user;
//! the *mode* is the cheap, deterministic check.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{docker_skip_reason, SshencEnv};
use std::os::unix::fs::PermissionsExt;

fn skip_if_no_docker(test_name: &str) -> bool {
    if let Some(reason) = docker_skip_reason() {
        eprintln!("skip {test_name}: {reason}");
        return true;
    }
    false
}

/// The agent socket file is `0o600` (rw owner only) once the agent
/// is listening. `server.rs` does this explicitly via
/// `set_permissions(socket, 0o600)` right after `UnixListener::bind`,
/// so this test pins that invariant on disk.
#[test]
#[ignore = "requires docker"]
fn agent_socket_file_is_owner_rw_only() {
    if skip_if_no_docker("agent_socket_file_is_owner_rw_only") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    env.start_agent().expect("start agent");

    let sock = env.socket_path();
    assert!(sock.exists(), "agent socket missing at {}", sock.display());

    let mode = std::fs::metadata(&sock)
        .expect("stat socket")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode,
        0o600,
        "agent socket {} mode is {:o}; expected 0o600",
        sock.display(),
        mode
    );
}

/// The directory holding the agent socket is `0o700` (owner-only
/// access). Even if a future change accidentally relaxed the socket
/// file mode, the dir mode would still block other users from
/// `stat`/`connect` to anything inside.
#[test]
#[ignore = "requires docker"]
fn agent_socket_parent_dir_is_owner_only() {
    if skip_if_no_docker("agent_socket_parent_dir_is_owner_only") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    env.start_agent().expect("start agent");

    let parent = env
        .socket_path()
        .parent()
        .expect("socket has parent")
        .to_path_buf();
    let mode = std::fs::metadata(&parent)
        .expect("stat socket parent")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode,
        0o700,
        "agent socket parent {} mode is {:o}; expected 0o700",
        parent.display(),
        mode
    );
}

/// Re-binding the socket on a fresh agent restart re-applies 0o600.
/// `prepare_socket_path` removes a stale socket file before
/// `bind`, which means the *new* inode goes through the
/// `set_permissions` path again. This guards against a regression
/// where someone moves the chmod under a conditional that doesn't
/// fire on respawn.
#[test]
#[ignore = "requires docker"]
fn agent_restart_keeps_socket_at_0600() {
    if skip_if_no_docker("agent_restart_keeps_socket_at_0600") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    env.start_agent().expect("start agent #1");
    let sock = env.socket_path();
    let mode_first = std::fs::metadata(&sock)
        .expect("stat 1")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode_first, 0o600, "first-boot mode {:o}", mode_first);

    env.stop_agent();
    env.start_agent().expect("start agent #2");
    let mode_second = std::fs::metadata(&sock)
        .expect("stat 2")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode_second, 0o600,
        "post-restart mode is {:o}; expected 0o600",
        mode_second
    );
}
