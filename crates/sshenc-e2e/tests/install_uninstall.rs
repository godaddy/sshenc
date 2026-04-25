// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `sshenc install` / `sshenc uninstall` edge cases.
//!
//! `lifecycle.rs` already covers:
//! - install is idempotent (run twice → single managed block)
//! - install + uninstall preserves unrelated config content
//!
//! This file covers the surfaces those tests don't reach:
//!
//! - install on a stale managed block (different socket path baked in)
//!   triggers the **Repair** path. PR #47 added this self-heal so users
//!   whose dylib or socket path moved aren't stuck with broken SSH;
//!   `lifecycle.rs::sshenc_install_idempotent` doesn't reach Repair
//!   because the second invocation sees current values and short-circuits
//!   to AlreadyPresent.
//! - uninstall on a virgin (no managed block) config is a clean no-op
//!   that prints `NotPresent` and does not touch the file.
//! - install when `~/.ssh` doesn't exist creates it (and the config file)
//!   with the right Unix permissions.
//! - install preserves user content **both above and below** the managed
//!   block (the existing roundtrip test only seeds content above).
//! - uninstall on a malformed managed block (BEGIN marker present, END
//!   missing) errors out without modifying the file.
//!
//! `#[ignore]` matches the rest of the e2e suite. The tests do not
//! actually require docker but they call `sshenc install`, which spawns
//! the agent — same convention as the existing install tests in
//! `lifecycle.rs`.

#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{docker_skip_reason, run, SshencEnv};

fn skip_if_no_docker(test_name: &str) -> bool {
    if let Some(reason) = docker_skip_reason() {
        eprintln!("skip {test_name}: {reason}");
        return true;
    }
    false
}

/// Stop any agent the install path may have spawned, so the tempdir
/// teardown doesn't leak a child process. The agent listens on
/// `$HOME/.sshenc/agent.sock`; after the socket file disappears the
/// agent's accept loop exits, but explicit cleanup via the socket
/// keeps tests well-behaved.
fn stop_install_spawned_agent(env: &SshencEnv) {
    let sock = env.socket_path();
    if !sock.exists() {
        return;
    }
    // Best-effort: connect and let the agent close on socket-file
    // removal. We can't kill the spawned PID directly because
    // install() doesn't return it. Tempdir cleanup handles the rest.
    drop(std::fs::remove_file(&sock));
}

const BEGIN: &str = "# BEGIN sshenc managed block -- do not edit";
const END: &str = "# END sshenc managed block";

/// `sshenc install` on a managed block that names a stale socket
/// path must rewrite the block (Repair) and print the
/// "Updated sshenc block" message. This is the regression test for
/// PR #47: previously the second install short-circuited on the
/// BEGIN marker alone and left users stuck with a broken dylib /
/// socket reference.
#[test]
#[ignore = "requires docker"]
fn sshenc_install_repairs_stale_socket_path() {
    if skip_if_no_docker("sshenc_install_repairs_stale_socket_path") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let ssh_config = env.ssh_dir().join("config");
    std::fs::create_dir_all(env.ssh_dir()).expect("mkdir ssh dir");

    // Seed a managed block that names a deliberately stale socket
    // path. Same markers, different IdentityAgent value than what
    // `sshenc install` would synthesize.
    let stale = format!(
        "{BEGIN}\nHost *\n    IdentityAgent /tmp/old-stale-socket-path-from-prior-install\n{END}\n"
    );
    std::fs::write(&ssh_config, &stale).expect("seed stale config");

    let install = run(env.sshenc_cmd().expect("sshenc").arg("install")).expect("sshenc install");
    assert!(
        install.succeeded(),
        "sshenc install failed; stdout:\n{}\nstderr:\n{}",
        install.stdout,
        install.stderr
    );
    assert!(
        install.stdout.contains("Updated sshenc block"),
        "expected Repaired-path message; got:\n{}",
        install.stdout
    );

    let after = std::fs::read_to_string(&ssh_config).expect("read config after install");
    assert!(
        !after.contains("/tmp/old-stale-socket-path-from-prior-install"),
        "stale socket path should have been rewritten; got:\n{after}"
    );
    let expected_socket = env.socket_path().display().to_string();
    assert!(
        after.contains(&expected_socket),
        "current socket path {expected_socket} should be in repaired block; got:\n{after}"
    );
    assert_eq!(
        after.matches(BEGIN).count(),
        1,
        "should be exactly one BEGIN after repair; got:\n{after}"
    );

    stop_install_spawned_agent(&env);
}

/// `sshenc uninstall` against an `~/.ssh/config` that has no managed
/// block must succeed, print the NotPresent message, and leave the
/// file content byte-for-byte unchanged.
#[test]
#[ignore = "requires docker"]
fn sshenc_uninstall_when_not_present_is_clean_noop() {
    if skip_if_no_docker("sshenc_uninstall_when_not_present_is_clean_noop") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let ssh_config = env.ssh_dir().join("config");
    std::fs::create_dir_all(env.ssh_dir()).expect("mkdir ssh dir");

    let original = "Host preexisting\n    User me\n    Port 2222\n";
    std::fs::write(&ssh_config, original).expect("seed config");
    let mtime_before = std::fs::metadata(&ssh_config)
        .expect("stat config")
        .modified()
        .expect("mtime");

    let outcome =
        run(env.sshenc_cmd().expect("sshenc").arg("uninstall")).expect("sshenc uninstall");
    assert!(
        outcome.succeeded(),
        "uninstall on virgin config failed; stderr:\n{}",
        outcome.stderr
    );
    assert!(
        outcome.stdout.contains("No sshenc configuration found"),
        "expected NotPresent message; got:\n{}",
        outcome.stdout
    );

    let after = std::fs::read_to_string(&ssh_config).expect("read config");
    assert_eq!(
        after, original,
        "uninstall should not modify a config it didn't touch"
    );
    let mtime_after = std::fs::metadata(&ssh_config)
        .expect("stat config")
        .modified()
        .expect("mtime");
    assert_eq!(
        mtime_before, mtime_after,
        "mtime should be unchanged after no-op uninstall"
    );
}

/// `sshenc install` must create `~/.ssh/` if it doesn't exist and
/// write the managed block into a fresh config file. On Unix the
/// directory mode must be 0700 (SSH's strict-mode requirement;
/// otherwise OpenSSH refuses to read the config).
#[test]
#[ignore = "requires docker"]
fn sshenc_install_creates_ssh_dir_when_missing() {
    if skip_if_no_docker("sshenc_install_creates_ssh_dir_when_missing") {
        return;
    }
    let env = SshencEnv::new().expect("env");

    // Sanity: ~/.ssh must not pre-exist for this test to mean anything.
    let ssh_dir = env.ssh_dir();
    if ssh_dir.exists() {
        std::fs::remove_dir_all(&ssh_dir).expect("remove preexisting ssh dir");
    }

    let outcome = run(env.sshenc_cmd().expect("sshenc").arg("install")).expect("sshenc install");
    assert!(
        outcome.succeeded(),
        "sshenc install failed on missing ssh dir; stderr:\n{}",
        outcome.stderr
    );

    assert!(ssh_dir.exists(), "install should create ~/.ssh");
    let ssh_config = ssh_dir.join("config");
    assert!(ssh_config.exists(), "install should create ~/.ssh/config");
    let content = std::fs::read_to_string(&ssh_config).expect("read config");
    assert!(
        content.contains(BEGIN) && content.contains(END),
        "config should contain managed block markers; got:\n{content}"
    );
    assert!(
        content.contains("IdentityAgent"),
        "config should contain IdentityAgent directive; got:\n{content}"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&ssh_dir)
            .expect("stat ssh dir")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o700,
            "newly-created ~/.ssh should have mode 0700, got {mode:o}"
        );
    }

    stop_install_spawned_agent(&env);
}

/// `sshenc install` must preserve user content **both above and
/// below** the managed block. The existing roundtrip test only
/// seeds content above; this verifies the upsert keeps surrounding
/// content intact in both directions.
#[test]
#[ignore = "requires docker"]
fn sshenc_install_preserves_content_above_and_below_managed_block() {
    if skip_if_no_docker("sshenc_install_preserves_content_above_and_below_managed_block") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let ssh_config = env.ssh_dir().join("config");
    std::fs::create_dir_all(env.ssh_dir()).expect("mkdir ssh dir");

    // First install with a fresh config to seed the managed block.
    let first = run(env.sshenc_cmd().expect("sshenc").arg("install")).expect("first install");
    assert!(first.succeeded(), "first install failed: {}", first.stderr);

    // Now sandwich the managed block between user content above and below.
    let after_first = std::fs::read_to_string(&ssh_config).expect("read config");
    let above = "Host above-block\n    User alice\n    Port 2200\n\n";
    let below = "\nHost below-block\n    User bob\n    Port 2201\n";
    let sandwich = format!("{above}{after_first}{below}");
    std::fs::write(&ssh_config, &sandwich).expect("rewrite sandwiched config");

    // Second install — exercises the upsert path with content on
    // both sides of the managed block.
    let second = run(env.sshenc_cmd().expect("sshenc").arg("install")).expect("second install");
    assert!(
        second.succeeded(),
        "second install failed; stderr:\n{}",
        second.stderr
    );

    let after = std::fs::read_to_string(&ssh_config).expect("read config");
    assert!(
        after.contains("Host above-block") && after.contains("User alice"),
        "above-block content should survive; got:\n{after}"
    );
    assert!(
        after.contains("Host below-block") && after.contains("User bob"),
        "below-block content should survive; got:\n{after}"
    );
    assert_eq!(
        after.matches(BEGIN).count(),
        1,
        "should be exactly one BEGIN; got:\n{after}"
    );
    assert_eq!(
        after.matches(END).count(),
        1,
        "should be exactly one END; got:\n{after}"
    );

    // Uninstall should remove the block but leave both wrappers.
    let un = run(env.sshenc_cmd().expect("sshenc").arg("uninstall")).expect("uninstall");
    assert!(un.succeeded(), "uninstall failed: {}", un.stderr);
    let final_content = std::fs::read_to_string(&ssh_config).expect("read final");
    assert!(
        !final_content.contains(BEGIN),
        "managed block should be gone; got:\n{final_content}"
    );
    assert!(
        final_content.contains("Host above-block") && final_content.contains("Host below-block"),
        "both wrappers should still be present after uninstall; got:\n{final_content}"
    );

    stop_install_spawned_agent(&env);
}

/// A malformed managed block (BEGIN without END) must cause
/// `sshenc uninstall` to error out without modifying the file.
/// This guards against the agent eating user content if a half-
/// written config ever ends up on disk.
#[test]
#[ignore = "requires docker"]
fn sshenc_uninstall_rejects_malformed_block_without_modifying_file() {
    if skip_if_no_docker("sshenc_uninstall_rejects_malformed_block_without_modifying_file") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let ssh_config = env.ssh_dir().join("config");
    std::fs::create_dir_all(env.ssh_dir()).expect("mkdir ssh dir");

    // BEGIN marker present, END never written. Plus some unrelated
    // content above so we can verify nothing is touched.
    let malformed = format!(
        "Host keep-me\n    User alice\n\n\
         {BEGIN}\nHost *\n    IdentityAgent /tmp/never-completed\n"
    );
    std::fs::write(&ssh_config, &malformed).expect("write malformed");

    let outcome =
        run(env.sshenc_cmd().expect("sshenc").arg("uninstall")).expect("sshenc uninstall");
    assert!(
        !outcome.succeeded(),
        "uninstall should fail on malformed block; stdout:\n{}\nstderr:\n{}",
        outcome.stdout,
        outcome.stderr
    );
    assert!(
        outcome.stderr.to_lowercase().contains("malformed")
            || outcome.stderr.to_lowercase().contains("end")
            || outcome.stderr.to_lowercase().contains("refusing"),
        "expected malformed-block error message; got:\n{}",
        outcome.stderr
    );

    let after = std::fs::read_to_string(&ssh_config).expect("read config");
    assert_eq!(
        after, malformed,
        "uninstall must not touch a malformed config file"
    );
}
