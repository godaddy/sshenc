// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `log_level` config field actually filters agent log output.
//!
//! `config_variations.rs` verifies that each `log_level` value
//! parses cleanly and the agent boots with it. That doesn't catch
//! a regression where the parsed level fails to flow into the
//! tracing subscriber's EnvFilter — leaving the agent at an
//! unintended verbosity.
//!
//! These tests:
//!
//! - Set `log_level = "debug"` in config, drive a few RPCs, and
//!   verify the agent's stderr contains DEBUG-level lines that
//!   only appear when debug filtering is active (e.g. the
//!   per-connection `new agent connection` debug line in
//!   `server.rs`).
//! - Set `log_level = "warn"`, drive the same RPCs, and verify
//!   the agent's stderr does NOT contain DEBUG/INFO lines.
//! - The `info` baseline shouldn't see `DEBUG` lines either.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{docker_skip_reason, run, shared_enclave_pubkey, workspace_bin, SshencEnv};
use std::io::Read;
use std::path::Path;
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

fn skip_if_no_docker(test_name: &str) -> bool {
    if let Some(reason) = docker_skip_reason() {
        eprintln!("skip {test_name}: {reason}");
        return true;
    }
    false
}

fn write_config(env: &SshencEnv, log_level: &str) -> std::path::PathBuf {
    let path = env.home().join("sshenc-config.toml");
    std::fs::write(
        &path,
        format!(
            "socket_path = \"{sock}\"\n\
             pub_dir = \"{pub_dir}\"\n\
             log_level = \"{log_level}\"\n",
            sock = env.socket_path().display(),
            pub_dir = env.ssh_dir().display(),
        ),
    )
    .expect("write config");
    path
}

/// Spawn the agent with the given config, wait for the socket,
/// drive a few RPCs (RequestIdentities) to populate the log,
/// then kill and collect the agent's log output. The agent uses
/// `tracing_subscriber::fmt()` whose default writer is **stdout**,
/// not stderr — so we pipe stdout and treat that as the log
/// stream.
fn agent_log_after_workload(env: &SshencEnv, log_level: &str) -> String {
    let config = write_config(env, log_level);
    drop(std::fs::remove_file(env.socket_path()));

    let bin = workspace_bin("sshenc-agent").expect("agent");
    let mut cmd = env.scrubbed_command(&bin);
    cmd.arg("--foreground")
        .arg("--socket")
        .arg(env.socket_path())
        .arg("--config")
        .arg(&config)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn agent");

    wait_for_socket(&env.socket_path(), Duration::from_secs(10));

    // Drive a few RPCs through ssh-add -L to give the agent
    // something to log at each level.
    for _ in 0..3 {
        drop(run(env
            .scrubbed_command("ssh-add")
            .env("SSH_AUTH_SOCK", env.socket_path())
            .arg("-L")));
    }

    // Give the agent a moment to flush log output before we kill
    // it. tracing-subscriber writes synchronously, but the
    // kernel may buffer.
    std::thread::sleep(Duration::from_millis(200));

    drop(child.kill());
    let output = child.wait_with_output().expect("wait_with_output");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    // Concatenate both — tracing-subscriber output lives on
    // stdout in current sshenc-agent, but if a future change
    // moves it (or adds a stderr layer), we want both.
    format!("{stdout}\n{stderr}")
}

fn wait_for_socket(path: &Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if std::os::unix::net::UnixStream::connect(path).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("socket never became available at {}", path.display());
}

// Drain and discard a child's stderr — used in cleanup paths
// where we don't care about the content.
fn drain_stderr(child: &mut Child) {
    if let Some(mut s) = child.stderr.take() {
        let mut buf = Vec::new();
        drop(s.read_to_end(&mut buf));
    }
}

/// `log_level = "debug"` produces DEBUG-level lines in agent
/// stderr. The per-connection log message in `server.rs::handle_connection`
/// is at DEBUG level — three RPCs guarantee we hit it.
#[test]
#[ignore = "requires docker"]
fn log_level_debug_emits_debug_lines() {
    if skip_if_no_docker("log_level_debug_emits_debug_lines") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("warm shared key"));

    let stderr = agent_log_after_workload(&env, "debug");
    assert!(
        stderr.contains("DEBUG"),
        "log_level=debug should produce DEBUG lines; agent stderr:\n{stderr}"
    );
    let _ = &mut env;
}

/// `log_level = "warn"` filters out INFO and DEBUG lines. The
/// agent's startup `INFO sshenc_agent: starting sshenc-agent`
/// line should not appear.
#[test]
#[ignore = "requires docker"]
fn log_level_warn_filters_out_info_and_debug() {
    if skip_if_no_docker("log_level_warn_filters_out_info_and_debug") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("warm shared key"));

    let stderr = agent_log_after_workload(&env, "warn");
    assert!(
        !stderr.contains("DEBUG"),
        "log_level=warn must not emit DEBUG lines; got:\n{stderr}"
    );
    assert!(
        !stderr.contains(" INFO ") && !stderr.contains(" INFO\u{1b}"),
        "log_level=warn must not emit INFO lines; got:\n{stderr}"
    );
    let _ = &mut env;
}

/// `log_level = "info"` (the default) emits INFO but not DEBUG.
/// Pins the default contract so a regression that flipped the
/// default to debug (verbose by default) would surface here.
#[test]
#[ignore = "requires docker"]
fn log_level_info_emits_info_but_not_debug() {
    if skip_if_no_docker("log_level_info_emits_info_but_not_debug") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("warm shared key"));

    let stderr = agent_log_after_workload(&env, "info");
    assert!(
        !stderr.contains("DEBUG"),
        "log_level=info must not emit DEBUG lines; got:\n{stderr}"
    );
    assert!(
        stderr.contains("INFO"),
        "log_level=info should emit at least one INFO line (e.g. startup); got:\n{stderr}"
    );
    let _ = &mut env;
}

/// Compile guard: keep `drain_stderr` in scope for future
/// regressions that need finer-grained child stderr handling.
#[allow(dead_code)]
fn _unused_drain(child: &mut Child) {
    drain_stderr(child);
}
