// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `--version` and per-subcommand `--help` exit-0 contract.
//!
//! `exit_codes.rs` covers behavioral exit codes (success / failure
//! shapes for keygen, sign, etc.) and `small_subcommands.rs` covers
//! the `--help` *content* on the umbrella CLI. Two thin slices
//! weren't pinned:
//!
//! 1. `sshenc --version` exits 0 and emits a non-empty version
//!    string. Same for `sshenc-agent --version`, `sshenc-keygen
//!    --version`, `gitenc --version` (clap's `version` derive
//!    covers all four). A regression in the clap setup that
//!    accidentally made any binary not honor `--version` would
//!    slip past every other test.
//! 2. Every umbrella `sshenc <subcommand> --help` exits 0 and
//!    emits help text. Per-subcommand help is what users actually
//!    invoke when stuck; if any subcommand stops accepting it
//!    (e.g. a clap migration goes wrong), we want the signal.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{run, workspace_bin, SshencEnv};

const SUBCOMMANDS: &[&str] = &[
    "keygen",
    "list",
    "inspect",
    "delete",
    "export-pub",
    "agent",
    "config",
    "openssh",
    "install",
    "uninstall",
    "default",
    "identity",
    "ssh",
    "completions",
];

/// Each binary built by the workspace honors `--version` and emits
/// a non-empty string on stdout with exit code 0.
#[test]
#[ignore = "exercises built binaries"]
fn binaries_emit_version_and_exit_zero() {
    let env = SshencEnv::new().expect("env");
    for name in ["sshenc", "sshenc-agent", "sshenc-keygen", "gitenc"] {
        let bin = workspace_bin(name).expect(name);
        let out = run(env.scrubbed_command(&bin).arg("--version"))
            .unwrap_or_else(|e| panic!("spawn {name} --version: {e}"));
        assert!(
            out.succeeded(),
            "{name} --version should exit 0; stderr:\n{}",
            out.stderr
        );
        assert!(
            !out.stdout.trim().is_empty(),
            "{name} --version emitted empty stdout"
        );
    }
}

/// Every documented `sshenc` subcommand accepts `--help` with exit
/// 0 and emits help text. clap's automatic `--help` propagation
/// only applies if the subcommand is actually wired up — this is
/// the regression test for "we forgot to register a subcommand
/// in the right place."
#[test]
#[ignore = "exercises built binaries"]
fn each_sshenc_subcommand_accepts_dash_help() {
    let env = SshencEnv::new().expect("env");
    for sub in SUBCOMMANDS {
        let out = run(env.sshenc_cmd().expect("sshenc cmd").args([sub, "--help"]))
            .unwrap_or_else(|e| panic!("sshenc {sub} --help: {e}"));
        assert!(
            out.succeeded(),
            "sshenc {sub} --help should exit 0; stderr:\n{}",
            out.stderr
        );
        // Help output goes to stdout per clap's defaults.
        assert!(
            !out.stdout.trim().is_empty(),
            "sshenc {sub} --help emitted empty stdout"
        );
    }
}

/// `sshenc <unknown-subcommand>` exits non-zero and surfaces a
/// usage hint. Pins the standard clap "did you mean / see
/// --help" diagnostic.
#[test]
#[ignore = "exercises built binaries"]
fn unknown_subcommand_exits_nonzero_with_usage_hint() {
    let env = SshencEnv::new().expect("env");
    let out = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .arg("definitely-not-a-real-subcommand"))
    .expect("sshenc unknown");
    assert!(
        !out.succeeded(),
        "unknown subcommand should exit non-zero; stdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    let combined = format!("{}\n{}", out.stdout, out.stderr).to_lowercase();
    assert!(
        combined.contains("usage")
            || combined.contains("help")
            || combined.contains("unrecognized")
            || combined.contains("subcommand"),
        "expected usage / help hint in error output; got:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
}
