// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! CLI first-run and keys_dir filesystem robustness:
//!
//! - `sshenc --help` and `sshenc <subcommand> --help` succeed
//!   on a vanilla HOME with no config file, no agent, no keys.
//!   Pin that the CLI doesn't eagerly require config to render
//!   help.
//! - `gitenc --help` likewise works without setup.
//! - `sshenc list` ignores stray subdirectories inside keys_dir
//!   instead of treating them as keys or panicking.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{docker_skip_reason, run, SshencEnv};

fn skip_if_no_docker(test_name: &str) -> bool {
    if let Some(reason) = docker_skip_reason() {
        eprintln!("skip {test_name}: {reason}");
        return true;
    }
    false
}

/// `sshenc --help` and `sshenc keygen --help` succeed without
/// any config file or agent running.
#[test]
#[ignore = "requires docker"]
fn sshenc_help_works_without_config() {
    if skip_if_no_docker("sshenc_help_works_without_config") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    // Don't start an agent, don't init a config — vanilla HOME.

    let top = run(env.sshenc_cmd().expect("sshenc cmd").arg("--help")).expect("sshenc --help");
    assert!(top.succeeded(), "sshenc --help: {}", top.stderr);
    assert!(
        top.stdout.contains("keygen") && top.stdout.contains("list"),
        "sshenc --help output missing subcommand listing; got:\n{}",
        top.stdout
    );

    let keygen_help = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["keygen", "--help"]))
    .expect("sshenc keygen --help");
    assert!(
        keygen_help.succeeded(),
        "sshenc keygen --help: {}",
        keygen_help.stderr
    );
    assert!(
        keygen_help.stdout.contains("--label"),
        "keygen --help missing --label; got:\n{}",
        keygen_help.stdout
    );
}

/// `gitenc --help` succeeds without any config or agent.
#[test]
#[ignore = "requires docker"]
fn gitenc_help_works_without_config() {
    if skip_if_no_docker("gitenc_help_works_without_config") {
        return;
    }
    let env = SshencEnv::new().expect("env");

    let help = run(env.gitenc_cmd().expect("gitenc cmd").arg("--help")).expect("gitenc --help");
    let combined = format!("{}\n{}", help.stdout, help.stderr);
    // gitenc passes --help through to git when invoked without a
    // recognized gitenc subcommand, so accept either gitenc-specific
    // help or git's help text. Either way, no panic and exit 0.
    assert!(help.succeeded(), "gitenc --help: {combined}");
    assert!(
        !combined.contains("panicked at"),
        "gitenc --help panicked: {combined}"
    );
}

/// `sshenc list` ignores stray subdirectories planted in
/// keys_dir without erroring.
#[test]
#[ignore = "requires docker"]
fn list_ignores_stray_subdirectory_in_keys_dir() {
    if skip_if_no_docker("list_ignores_stray_subdirectory_in_keys_dir") {
        return;
    }
    let env = SshencEnv::new().expect("env");

    let keys_dir = env.home().join(".sshenc").join("keys");
    std::fs::create_dir_all(&keys_dir).expect("mkdir keys_dir");

    // Plant a stray subdirectory.
    let stray = keys_dir.join("stray-subdir");
    std::fs::create_dir_all(&stray).expect("mkdir stray");
    std::fs::write(stray.join("not-a-meta.txt"), b"junk").expect("write junk");

    let listed = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["list", "--json"]))
    .expect("sshenc list --json");
    let combined = format!("{}\n{}", listed.stdout, listed.stderr);
    assert!(
        !combined.contains("panicked at"),
        "sshenc list panicked on stray subdirectory in keys_dir:\n{combined}"
    );
    assert!(
        listed.succeeded(),
        "sshenc list with stray subdir should succeed; stderr:\n{}",
        listed.stderr
    );
    // JSON output should be parseable (probably an empty array).
    let parsed: serde_json::Value =
        serde_json::from_str(listed.stdout.trim()).expect("list --json invalid JSON");
    assert!(
        parsed.is_array(),
        "list --json should be a JSON array; got: {parsed}"
    );
}
