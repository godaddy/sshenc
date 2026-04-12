// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Integration tests for the sshenc CLI binary.
//!
//! These tests run the compiled `sshenc` binary and verify its output.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::process::Command;

fn sshenc_binary() -> String {
    let mut path = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    path.push("sshenc");
    path.to_string_lossy().to_string()
}

#[test]
fn version_exits_0_and_contains_sshenc() {
    let output = Command::new(sshenc_binary())
        .arg("--version")
        .output()
        .unwrap();
    assert!(output.status.success(), "sshenc --version failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("sshenc"),
        "expected 'sshenc' in version output, got: {stdout}"
    );
}

#[test]
fn help_exits_0_and_contains_manage() {
    let output = Command::new(sshenc_binary())
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success(), "sshenc --help failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("manages") || stdout.contains("Manage"),
        "expected 'manages' or 'Manage' in help output, got: {stdout}"
    );
}

#[test]
fn list_json_exits_0() {
    let output = Command::new(sshenc_binary())
        .args(["list", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "sshenc list --json failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn completions_bash_exits_0_and_contains_complete() {
    let output = Command::new(sshenc_binary())
        .args(["completions", "bash"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "sshenc completions bash failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("complete"),
        "expected 'complete' in bash completions, got: {stdout}"
    );
}

#[test]
fn completions_zsh_exits_0_and_contains_compdef() {
    let output = Command::new(sshenc_binary())
        .args(["completions", "zsh"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "sshenc completions zsh failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("compdef") || stdout.contains("_sshenc"),
        "expected zsh completion content, got: {stdout}"
    );
}

#[test]
fn completions_fish_exits_0() {
    let output = Command::new(sshenc_binary())
        .args(["completions", "fish"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "sshenc completions fish failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("complete") || stdout.contains("sshenc"),
        "expected fish completion content, got: {stdout}"
    );
}

#[test]
fn config_path_exits_0_and_contains_config_toml() {
    let output = Command::new(sshenc_binary())
        .args(["config", "path"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "sshenc config path failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("config.toml"),
        "expected 'config.toml' in config path output, got: {stdout}"
    );
}

#[test]
fn no_args_shows_help() {
    let output = Command::new(sshenc_binary()).output().unwrap();
    // clap should show help or error when no subcommand is given
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("Usage") || combined.contains("sshenc"),
        "expected usage info, got: {combined}"
    );
}

#[test]
fn invalid_subcommand_fails() {
    let output = Command::new(sshenc_binary())
        .arg("nonexistent-subcommand")
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "sshenc with invalid subcommand should fail"
    );
}

#[test]
fn version_contains_semver() {
    let output = Command::new(sshenc_binary())
        .arg("--version")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Version should match semver pattern: digits.digits.digits
    let has_version = stdout.split_whitespace().any(|word| {
        let parts: Vec<&str> = word.split('.').collect();
        parts.len() == 3 && parts.iter().all(|p| p.chars().all(|c| c.is_ascii_digit()))
    });
    assert!(
        has_version,
        "expected semver version in output, got: {stdout}"
    );
}
