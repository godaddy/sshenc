// Copyright 2026 Jay Gowdy
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

use sshenc_e2e::{
    docker_skip_reason, run, shared_enclave_pubkey, workspace_bin, SshencEnv, SHARED_ENCLAVE_LABEL,
};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
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

/// SIGTERM while many `sshenc -Y sign` processes are active must not
/// cause any client to hang indefinitely. Each in-flight or pending
/// sign either completes (if the agent served it before shutdown) or
/// gets a connection error — never a blocked wait with no progress.
///
/// This pins the graceful-shutdown contract: the tokio runtime must
/// finish draining active connections within a bounded window after
/// the SIGTERM handler fires.
#[test]
#[ignore = "requires docker"]
fn agent_sigterm_while_sign_traffic_active_no_hang() {
    if skip_if_no_docker("agent_sigterm_while_sign_traffic_active_no_hang") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("enclave");

    // Spawn agent directly so we can hold the Child for signal delivery.
    let agent_child = spawn_agent_foreground(&env);
    wait_for_socket(&env.socket_path(), Duration::from_secs(10));

    let pub_path = env.ssh_dir().join(format!("{SHARED_ENCLAVE_LABEL}.pub"));
    std::fs::create_dir_all(env.ssh_dir()).expect("mkdir ssh dir");
    std::fs::write(&pub_path, format!("{enclave}\n")).expect("write pub");

    let env = Arc::new(env);
    let pub_path = Arc::new(pub_path);

    // Spawn N threads; each fires multiple sign requests in a tight
    // loop so the agent is busy when SIGTERM arrives.
    const N: usize = 8;
    let (tx, rx) = std::sync::mpsc::channel::<usize>();
    for i in 0..N {
        let env = Arc::clone(&env);
        let pub_path = Arc::clone(&pub_path);
        let tx = tx.clone();
        std::thread::spawn(move || {
            for j in 0..20 {
                let data = env.home().join(format!("sigterm-sign-{i}-{j}.txt"));
                std::fs::write(&data, format!("payload-{i}-{j}\n")).ok();
                let mut cmd = env.sshenc_cmd().expect("sshenc cmd");
                cmd.arg("-Y")
                    .arg("sign")
                    .arg("-n")
                    .arg("git")
                    .arg("-f")
                    .arg(&*pub_path)
                    .arg(&data);
                drop(run(&mut cmd));
            }
            tx.send(i).ok();
        });
    }
    drop(tx);

    // Let threads get several requests in flight, then SIGTERM.
    std::thread::sleep(Duration::from_millis(100));
    send_signal(&agent_child, "TERM");
    let _ = wait_for_exit(agent_child, Duration::from_secs(5));

    // All threads must complete within 10 s of the agent exiting.
    // Once the socket is gone, pending sshenc -Y sign processes will
    // get connection errors and exit, unblocking the threads.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut finished = 0;
    while finished < N {
        match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(_) => finished += 1,
            Err(_) => {
                panic!("worker thread hung after agent SIGTERM (only {finished}/{N} finished)")
            }
        }
    }
}

/// SIGTERM while `sshenc keygen` operations are in progress must
/// leave the keystore in a consistent state: each key is either
/// fully created (key + pub file both present, key visible in list)
/// or fully absent (no pub file, not in list). No torn state.
#[test]
#[ignore = "requires docker"]
fn agent_sigterm_during_keygen_leaves_consistent_keystore() {
    if skip_if_no_docker("agent_sigterm_during_keygen_leaves_consistent_keystore") {
        return;
    }
    use sshenc_e2e::extended_enabled;
    use sshenc_e2e::software_mode;
    if !extended_enabled() && !software_mode() {
        eprintln!(
            "skip agent_sigterm_during_keygen_leaves_consistent_keystore: \
             needs to mint keys; set SSHENC_E2E_SOFTWARE=1 or SSHENC_E2E_EXTENDED=1"
        );
        return;
    }

    let mut env = SshencEnv::new().expect("env");
    env.use_ephemeral_keys_dir().expect("ephemeral");
    let agent_child = spawn_agent_foreground(&env);
    wait_for_socket(&env.socket_path(), Duration::from_secs(10));

    let env = Arc::new(env);

    // Fire several keygen operations concurrently. Each targets a
    // unique label so they don't interfere with each other.
    const N: usize = 6;
    let labels: Vec<String> = (0..N).map(|i| format!("sigterm-gen-{i}")).collect();
    let (tx, rx) = std::sync::mpsc::channel::<String>();

    for label in &labels {
        let env = Arc::clone(&env);
        let label = label.clone();
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut cmd = env.sshenc_cmd().expect("sshenc cmd");
            cmd.args(["keygen", "--label", &label, "--auth-policy", "none"]);
            drop(run(&mut cmd));
            tx.send(label).ok();
        });
    }
    drop(tx);

    // Give threads a moment to start, then SIGTERM the agent.
    std::thread::sleep(Duration::from_millis(50));
    send_signal(&agent_child, "TERM");
    let _ = wait_for_exit(agent_child, Duration::from_secs(5));

    // All keygen threads must complete (they'll get errors once agent exits).
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut finished = 0;
    while finished < N {
        match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(_) => finished += 1,
            Err(_) => panic!("keygen thread hung after agent SIGTERM ({finished}/{N} finished)"),
        }
    }

    // Start a fresh agent to check keystore consistency.
    let env = Arc::try_unwrap(env).expect("arc unwrap");
    let mut env = env;
    env.start_agent().expect("restart agent");

    let listed = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["list", "--json"]))
    .expect("list");
    assert!(listed.succeeded(), "list: {}", listed.stderr);

    let keys_dir = env.home().join(".sshenc").join("keys");
    for label in &labels {
        let key_in_list = listed.stdout.contains(label.as_str());
        let pub_file = keys_dir.join(format!("{label}.pub"));
        let pub_exists = pub_file.exists();
        assert_eq!(
            key_in_list,
            pub_exists,
            "key {label}: list says present={key_in_list} but pub file present={pub_exists} — torn state"
        );
    }
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
