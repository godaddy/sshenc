// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! CLI exit-code contract.
//!
//! Scripts wrapping `sshenc` (CI pipelines, shell aliases, makefiles)
//! decide what to do based on the exit code. Today many error
//! paths just exit 1, but a few are well-defined:
//!
//! - clap argument-parse errors exit **2** (clap convention)
//! - operation success exits 0
//! - operational failure (missing key, agent unreachable, etc.) is
//!   non-zero — currently 1
//!
//! This file pins the contract so a future refactor that
//! accidentally changes "label-not-found" to exit 0 (silently
//! eating the error) or "missing required arg" to exit 1 (mixing
//! it with operational errors) is caught.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{docker_skip_reason, run, SshencEnv, SHARED_ENCLAVE_LABEL};

fn skip_if_no_docker(test_name: &str) -> bool {
    if let Some(reason) = docker_skip_reason() {
        eprintln!("skip {test_name}: {reason}");
        return true;
    }
    false
}

/// Helper: run a sshenc invocation and return its raw exit code,
/// stdout, and stderr.
fn run_sshenc(env: &SshencEnv, args: &[&str]) -> (Option<i32>, String, String) {
    let outcome = run(env.sshenc_cmd().expect("sshenc cmd").args(args)).expect("run sshenc");
    (outcome.status.code(), outcome.stdout, outcome.stderr)
}

/// `sshenc` invoked with no subcommand prints help and exits with
/// a clap-style usage error code (2).
#[test]
#[ignore = "requires docker"]
fn no_subcommand_exits_with_clap_usage_error_code() {
    if skip_if_no_docker("no_subcommand_exits_with_clap_usage_error_code") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let (code, _stdout, stderr) = run_sshenc(&env, &[]);
    assert_eq!(
        code,
        Some(2),
        "no-subcommand should exit 2 (clap usage error); got {code:?}\nstderr:\n{stderr}"
    );
}

/// `sshenc <unknown-subcommand>` is a clap error → exit 2.
#[test]
#[ignore = "requires docker"]
fn unknown_subcommand_exits_with_clap_usage_error_code() {
    if skip_if_no_docker("unknown_subcommand_exits_with_clap_usage_error_code") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let (code, _stdout, stderr) = run_sshenc(&env, &["does-not-exist"]);
    assert_eq!(
        code,
        Some(2),
        "unknown subcommand should exit 2; got {code:?}\nstderr:\n{stderr}"
    );
}

/// `sshenc default` (missing required positional label) exits 2.
/// This is a clap-level usage error, not an operational one.
#[test]
#[ignore = "requires docker"]
fn default_missing_required_label_exits_2() {
    if skip_if_no_docker("default_missing_required_label_exits_2") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let (code, _stdout, stderr) = run_sshenc(&env, &["default"]);
    assert_eq!(
        code,
        Some(2),
        "missing default label should exit 2; got {code:?}\nstderr:\n{stderr}"
    );
}

/// `sshenc identity` (missing required `--name` and `--email`)
/// exits 2.
#[test]
#[ignore = "requires docker"]
fn identity_missing_required_flags_exits_2() {
    if skip_if_no_docker("identity_missing_required_flags_exits_2") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let (code, _stdout, stderr) = run_sshenc(&env, &["identity"]);
    assert_eq!(
        code,
        Some(2),
        "missing identity --name/--email should exit 2; got {code:?}\nstderr:\n{stderr}"
    );
}

/// `sshenc inspect <label>` for a missing key exits non-zero. We
/// don't pin to a specific code beyond "not 0" — different error
/// classes share exit 1 today and that's a known limitation.
#[test]
#[ignore = "requires docker"]
fn inspect_missing_key_exits_nonzero() {
    if skip_if_no_docker("inspect_missing_key_exits_nonzero") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    env.use_ephemeral_keys_dir().expect("ephemeral keys dir");
    let (code, _stdout, stderr) = run_sshenc(&env, &["inspect", "ghost-label"]);
    assert!(
        matches!(code, Some(c) if c != 0),
        "inspect of missing key should exit non-zero; got {code:?}\nstderr:\n{stderr}"
    );
    // Also: the exit must NOT be 2 — that's reserved for usage
    // errors. An operational failure shouldn't masquerade as a
    // syntax error.
    assert_ne!(
        code,
        Some(2),
        "missing-key error should NOT exit 2 (usage error code); got {code:?}\nstderr:\n{stderr}"
    );
}

/// `sshenc inspect ../escape` (invalid label format) exits
/// non-zero. The validator catches this before any filesystem
/// access.
#[test]
#[ignore = "requires docker"]
fn invalid_label_exits_nonzero() {
    if skip_if_no_docker("invalid_label_exits_nonzero") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let (code, _stdout, stderr) = run_sshenc(&env, &["inspect", "../escape"]);
    assert!(
        matches!(code, Some(c) if c != 0),
        "invalid label should exit non-zero; got {code:?}\nstderr:\n{stderr}"
    );
}

/// `sshenc keygen` with a bogus `--auth-policy` value is a clap
/// value-validation error → exit 2.
#[test]
#[ignore = "requires docker"]
fn keygen_invalid_auth_policy_value_exits_2() {
    if skip_if_no_docker("keygen_invalid_auth_policy_value_exits_2") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let (code, _stdout, stderr) = run_sshenc(
        &env,
        &[
            "keygen",
            "--label",
            "irrelevant",
            "--auth-policy",
            "bogus-policy-value",
        ],
    );
    assert_eq!(
        code,
        Some(2),
        "invalid --auth-policy value should exit 2; got {code:?}\nstderr:\n{stderr}"
    );
}

/// Successful operation exits 0. Sanity baseline so we know an
/// exit-0 detection isn't flagged as a problem.
#[test]
#[ignore = "requires docker"]
fn successful_list_exits_0() {
    if skip_if_no_docker("successful_list_exits_0") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    drop(sshenc_e2e::shared_enclave_pubkey(&env).expect("shared key"));
    let (code, _stdout, _stderr) = run_sshenc(&env, &["list"]);
    assert_eq!(code, Some(0), "list should exit 0; got {code:?}");
}

/// `sshenc inspect <SHARED_ENCLAVE_LABEL>` for the existing key
/// exits 0. Pairs with the missing-key case above.
#[test]
#[ignore = "requires docker"]
fn inspect_existing_key_exits_0() {
    if skip_if_no_docker("inspect_existing_key_exits_0") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    drop(sshenc_e2e::shared_enclave_pubkey(&env).expect("shared key"));
    let (code, _stdout, _stderr) = run_sshenc(&env, &["inspect", SHARED_ENCLAVE_LABEL]);
    assert_eq!(code, Some(0), "inspect of existing key should exit 0");
}
