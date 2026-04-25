// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Shell completion script integration.
//!
//! `small_subcommands.rs::completions_emits_scripts_for_each_shell`
//! verifies the CLI **emits** a non-empty completion script for each
//! shell, but it doesn't check that those scripts are actually
//! parseable by the shell they target. A malformed script that the
//! CLI happily prints would still break a user's shell on next
//! source.
//!
//! These tests pipe each generated script back through the target
//! shell with a syntax-check flag (`bash -n`, `zsh -n`,
//! `fish --no-execute`). Exit 0 means the shell parsed the script
//! without complaint. Failures surface as a non-zero exit and a
//! parser error on stderr.
//!
//! Tests skip gracefully when the target shell isn't installed —
//! the CI matrix doesn't guarantee fish on every runner, and we
//! shouldn't fail when a tool just isn't available.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{docker_skip_reason, run, SshencEnv};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

fn skip_if_no_docker(test_name: &str) -> bool {
    if let Some(reason) = docker_skip_reason() {
        eprintln!("skip {test_name}: {reason}");
        return true;
    }
    false
}

/// Returns true if the named program can be found on PATH. Used to
/// skip tests gracefully when the target shell isn't installed.
fn binary_on_path(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Generate `sshenc completions <shell>` and return the script
/// text. Panics on failure since every test in this file relies on
/// this working.
fn generate_completion(env: &SshencEnv, shell: &str) -> String {
    let outcome = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["completions", shell]))
    .expect("sshenc completions");
    assert!(
        outcome.succeeded(),
        "sshenc completions {shell} failed; stderr:\n{}",
        outcome.stderr
    );
    assert!(
        !outcome.stdout.is_empty(),
        "sshenc completions {shell} emitted empty output"
    );
    outcome.stdout
}

/// Run `<shell-cmd>` with the given args and feed `script` on
/// stdin. Returns the exit status and stderr text.
fn shell_check(shell_cmd: &str, args: &[&str], script: &str) -> (std::process::ExitStatus, String) {
    let mut child = Command::new(shell_cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn shell");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        stdin.write_all(script.as_bytes()).expect("write script");
    }
    let output = child.wait_with_output().expect("wait shell");
    (
        output.status,
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// Same as `shell_check`, but the shell reads the script from a
/// file path (some shells, notably fish, can't take `--no-execute`
/// from stdin). Writes the script to a temp path and passes the
/// path as a positional argument.
fn shell_check_via_file(
    shell_cmd: &str,
    args_with_path_placeholder: &[&str],
    script: &str,
    workspace: &Path,
) -> (std::process::ExitStatus, String) {
    let path = workspace.join(format!("completion-{shell_cmd}.script"));
    std::fs::write(&path, script).expect("write completion script");
    let mut full_args: Vec<String> = args_with_path_placeholder
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    full_args.push(path.display().to_string());
    let output = Command::new(shell_cmd)
        .args(&full_args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("run shell");
    (
        output.status,
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// `bash -n` reads stdin (or a file) and reports syntax errors
/// without executing anything. The generated bash completion script
/// must parse cleanly.
#[test]
#[ignore = "requires docker"]
fn bash_completion_script_parses_cleanly() {
    if skip_if_no_docker("bash_completion_script_parses_cleanly") {
        return;
    }
    if !binary_on_path("bash") {
        eprintln!("skip: bash not on PATH");
        return;
    }
    let env = SshencEnv::new().expect("env");
    let script = generate_completion(&env, "bash");

    let (status, stderr) = shell_check("bash", &["-n"], &script);
    assert!(
        status.success(),
        "bash -n rejected the generated completion script; stderr:\n{stderr}\n\
         (first 30 lines of script for context):\n{}",
        script.lines().take(30).collect::<Vec<_>>().join("\n")
    );
}

/// `zsh -n` does the same syntax-only parse for zsh. The generated
/// zsh script is also wrapped with a `compdef` guard in the CLI;
/// this test verifies the wrapper itself parses cleanly.
#[test]
#[ignore = "requires docker"]
fn zsh_completion_script_parses_cleanly() {
    if skip_if_no_docker("zsh_completion_script_parses_cleanly") {
        return;
    }
    if !binary_on_path("zsh") {
        eprintln!("skip: zsh not on PATH");
        return;
    }
    let env = SshencEnv::new().expect("env");
    let script = generate_completion(&env, "zsh");

    let (status, stderr) = shell_check("zsh", &["-n"], &script);
    assert!(
        status.success(),
        "zsh -n rejected the generated completion script; stderr:\n{stderr}\n\
         (first 30 lines of script):\n{}",
        script.lines().take(30).collect::<Vec<_>>().join("\n")
    );
}

/// `fish --no-execute <file>` parses the script without running it.
/// Fish requires a file path (not stdin), so we write the script
/// to the env's tempdir and pass the path.
#[test]
#[ignore = "requires docker"]
fn fish_completion_script_parses_cleanly() {
    if skip_if_no_docker("fish_completion_script_parses_cleanly") {
        return;
    }
    if !binary_on_path("fish") {
        eprintln!("skip: fish not on PATH");
        return;
    }
    let env = SshencEnv::new().expect("env");
    let script = generate_completion(&env, "fish");

    let (status, stderr) = shell_check_via_file("fish", &["--no-execute"], &script, env.home());
    assert!(
        status.success(),
        "fish --no-execute rejected the generated completion script; stderr:\n{stderr}\n\
         (first 30 lines of script):\n{}",
        script.lines().take(30).collect::<Vec<_>>().join("\n")
    );
}

/// Sanity check: each completion script is more than just a
/// shebang or a comment block — it should reference `sshenc`
/// subcommands. We pick a representative subcommand (`keygen`)
/// that should appear in any reasonable completion file.
#[test]
#[ignore = "requires docker"]
fn completion_scripts_reference_sshenc_subcommands() {
    if skip_if_no_docker("completion_scripts_reference_sshenc_subcommands") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    for shell in &["bash", "zsh", "fish"] {
        let script = generate_completion(&env, shell);
        assert!(
            script.contains("keygen"),
            "{shell} completion script should reference at least one subcommand (e.g. keygen); \
             head:\n{}",
            script.lines().take(5).collect::<Vec<_>>().join("\n")
        );
    }
}
