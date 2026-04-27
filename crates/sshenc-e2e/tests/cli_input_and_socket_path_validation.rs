// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Input-validation contracts at the CLI/agent boundary:
//!
//! - `sshenc delete <good> <missing>` is atomic — when one of the
//!   labels in the batch doesn't exist, *no* keys are deleted.
//!   `commands::delete` verifies all keys exist before issuing
//!   any backend.delete() calls; this pins that contract from
//!   the user's perspective.
//! - `sshenc-agent --foreground --socket <path-with-missing-parent>`
//!   exits non-zero with a clean error rather than panicking or
//!   silently bricking the agent. The "create_dir_all" semantics
//!   in `prepare_socket_path` only create the socket's immediate
//!   parent; deeply-missing parents must surface a useful error.
//! - `sshenc keygen --label "../traversal"` is rejected by the
//!   shared `validate_label` validator before any state is
//!   written, so a hostile label can't escape the keys_dir.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{
    docker_skip_reason, extended_enabled, run, software_mode, workspace_bin, SshencEnv,
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

/// `sshenc delete a missing-label` (mixed batch with one missing)
/// must be atomic: neither `a` nor `missing-label` is deleted.
/// `a` must still be present afterward.
#[test]
#[ignore = "requires docker"]
fn delete_with_mixed_valid_and_missing_label_is_atomic() {
    if skip_if_no_docker("delete_with_mixed_valid_and_missing_label_is_atomic") {
        return;
    }
    if skip_unless_key_creation_cheap("delete_with_mixed_valid_and_missing_label_is_atomic") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    env.use_ephemeral_keys_dir().expect("ephemeral");
    env.start_agent().expect("start agent");

    let good = "atomic-keep-me";
    let kg = run(env.sshenc_cmd().expect("sshenc cmd").args([
        "keygen",
        "--label",
        good,
        "--auth-policy",
        "none",
        "--no-pub-file",
    ]))
    .expect("keygen");
    assert!(kg.succeeded(), "keygen: {}", kg.stderr);

    // Try to delete the good label and a nonexistent one in one call.
    let delete =
        run(env
            .sshenc_cmd()
            .expect("sshenc cmd")
            .args(["delete", good, "no-such-label", "-y"]))
        .expect("sshenc delete");
    assert!(
        !delete.succeeded(),
        "delete with a missing label should fail; stdout:\n{}\nstderr:\n{}",
        delete.stdout,
        delete.stderr
    );

    // The good label must still exist.
    let listed = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["list", "--json"]))
    .expect("sshenc list --json");
    assert!(listed.succeeded(), "list: {}", listed.stderr);
    assert!(
        listed.stdout.contains(good),
        "atomic delete should leave '{good}' intact when the batch contained a missing label; \
         list output:\n{}",
        listed.stdout
    );
}

/// `sshenc-agent --foreground --socket <path-with-missing-parent>`
/// either exits cleanly with a useful diagnostic OR creates the
/// parent tree and serves on the requested path. Neither path is
/// allowed to panic, hang silently, or leave a dangling socket.
#[test]
#[ignore = "requires docker"]
fn agent_socket_with_missing_parent_does_not_panic() {
    if skip_if_no_docker("agent_socket_with_missing_parent_does_not_panic") {
        return;
    }
    let env = SshencEnv::new().expect("env");

    // A path several levels under a directory that doesn't exist.
    let bogus = env
        .home()
        .join("not-yet-created")
        .join("nested")
        .join("missing")
        .join("agent.sock");
    assert!(
        !bogus.parent().unwrap().exists(),
        "test setup: socket parent should not exist"
    );

    let bin = workspace_bin("sshenc-agent").expect("agent binary");
    let mut child = env
        .scrubbed_command(&bin)
        .arg("--foreground")
        .arg("--socket")
        .arg(&bogus)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn agent");

    // Give the agent up to 3 seconds to either exit (preferred for
    // a hostile path) or come up and bind.
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut exit_status = None;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("try_wait") {
            exit_status = Some(status);
            break;
        }
        if bogus.exists() {
            // Agent created the parent tree and bound the socket.
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let still_running = exit_status.is_none();
    if still_running {
        drop(child.kill());
    }
    let out = child.wait_with_output().expect("wait");
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    assert!(
        !combined.contains("panicked at"),
        "agent panicked on missing-parent socket path:\n{combined}"
    );
    assert!(
        exit_status.is_some() || bogus.exists(),
        "agent neither exited nor bound the socket within 3s; output:\n{combined}"
    );
}

/// `sshenc keygen --label "../traversal"` is rejected by label
/// validation before any keystore state is written.
#[test]
#[ignore = "requires docker"]
fn keygen_rejects_label_with_path_traversal() {
    if skip_if_no_docker("keygen_rejects_label_with_path_traversal") {
        return;
    }
    if skip_unless_key_creation_cheap("keygen_rejects_label_with_path_traversal") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    env.use_ephemeral_keys_dir().expect("ephemeral");

    for bad in ["../escape", "foo/bar", "/abs/path"] {
        let kg = run(env.sshenc_cmd().expect("sshenc cmd").args([
            "keygen",
            "--label",
            bad,
            "--auth-policy",
            "none",
            "--no-pub-file",
        ]))
        .expect("keygen");

        assert!(
            !kg.succeeded(),
            "keygen with hostile label {bad:?} should fail; stdout:\n{}\nstderr:\n{}",
            kg.stdout,
            kg.stderr
        );
        let combined = format!("{}\n{}", kg.stdout, kg.stderr);
        assert!(
            !combined.contains("panicked at"),
            "keygen panicked on hostile label {bad:?}:\n{combined}"
        );
    }
}
