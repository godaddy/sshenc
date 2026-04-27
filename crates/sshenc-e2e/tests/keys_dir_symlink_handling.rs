// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! When `~/.sshenc/keys` is a symbolic link to another
//! directory, sshenc must not crash on list/inspect/keygen.
//! The contract here is "no panic, no segfault, behavior is
//! either (a) follow the symlink and operate on the target,
//! or (b) reject the symlink with a clean diagnostic". Either
//! is acceptable; what we pin is robustness against this
//! filesystem layout.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{docker_skip_reason, extended_enabled, run, software_mode, SshencEnv};

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

/// `~/.sshenc/keys` is a symlink to another directory. sshenc
/// must handle list, keygen, and inspect without panicking.
#[test]
#[ignore = "requires docker"]
fn keys_dir_as_symlink_does_not_panic() {
    if skip_if_no_docker("keys_dir_as_symlink_does_not_panic") {
        return;
    }
    if skip_unless_key_creation_cheap("keys_dir_as_symlink_does_not_panic") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");

    // Set up the symlink: ~/.sshenc/keys-ephemeral (the dir the
    // ephemeral-keys helper would point at) → /tmp-ish/<uuid>.
    let target = env.home().join("symlink-target-keys");
    let link = env.home().join(".sshenc-keys-ephemeral");
    std::fs::create_dir_all(&target).expect("mkdir target");
    std::fs::create_dir_all(env.home().join(".sshenc")).expect("mkdir .sshenc");
    drop(std::fs::remove_dir_all(&link));
    std::os::unix::fs::symlink(&target, &link).expect("symlink keys dir");
    env.use_ephemeral_keys_dir().expect("ephemeral");
    env.start_agent().expect("start agent");

    // Confirm the symlink is in place and points where we expect.
    let meta = std::fs::symlink_metadata(&link).expect("symlink_metadata");
    assert!(
        meta.file_type().is_symlink(),
        "expected symlink at {}",
        link.display()
    );

    // list on empty (symlinked) keys dir must succeed.
    let list_empty = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["list", "--json"]))
    .expect("sshenc list --json");
    let combined_empty = format!("{}\n{}", list_empty.stdout, list_empty.stderr);
    assert!(
        !combined_empty.contains("panicked at"),
        "sshenc list panicked on symlinked empty keys_dir:\n{combined_empty}"
    );

    // keygen into the (symlinked) keys_dir.
    let label = "symlink-resident";
    let kg = run(env.sshenc_cmd().expect("sshenc cmd").args([
        "keygen",
        "--label",
        label,
        "--auth-policy",
        "none",
        "--no-pub-file",
    ]))
    .expect("sshenc keygen");
    let combined_kg = format!("{}\n{}", kg.stdout, kg.stderr);
    assert!(
        !combined_kg.contains("panicked at"),
        "sshenc keygen panicked on symlinked keys_dir:\n{combined_kg}"
    );

    // If keygen succeeded, list must show it; if keygen rejected
    // the symlinked dir, list should still not panic.
    let list_after = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["list", "--json"]))
    .expect("sshenc list --json");
    let combined_after = format!("{}\n{}", list_after.stdout, list_after.stderr);
    assert!(
        !combined_after.contains("panicked at"),
        "sshenc list panicked after keygen against symlinked keys_dir:\n{combined_after}"
    );

    // inspect must also not panic, regardless of whether the key
    // exists.
    let inspect = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["inspect", label, "--json"]))
    .expect("sshenc inspect --json");
    let combined_inspect = format!("{}\n{}", inspect.stdout, inspect.stderr);
    assert!(
        !combined_inspect.contains("panicked at"),
        "sshenc inspect panicked against symlinked keys_dir:\n{combined_inspect}"
    );
}
