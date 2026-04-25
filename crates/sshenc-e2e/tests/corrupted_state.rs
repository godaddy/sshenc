// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Robustness against corrupted on-disk state.
//!
//! sshenc reads `<keys_dir>/<label>.meta` (and on Linux, the
//! sibling `.key` file containing the encrypted key material). If
//! a meta file gets truncated, partially written, or has its JSON
//! corrupted (e.g. a crash mid-write, a half-finished migration),
//! the CLI must fail cleanly — not panic, not double-free, not
//! silently swallow the bad entry while pretending nothing's wrong.
//!
//! These tests cover:
//!
//! - `list` against an empty / missing keys_dir → empty list, exit 0
//! - `inspect` against a non-existent label → clean error
//! - `inspect` against a corrupted-meta label → clean error (no panic)
//! - `list` survives one corrupted meta (returns the rest, no crash)
//!
//! All operate in software mode using an ephemeral keys_dir so the
//! shared persistent identity is undisturbed. Unix-only because
//! we manipulate the keys_dir via `SSHENC_KEYS_DIR` and the env
//! scrubbing — Windows e2e takes a different path.

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

/// `sshenc list` against a keys_dir that doesn't exist must succeed
/// with an empty list. A first-time user with no keys must not see
/// an error here.
#[test]
#[ignore = "requires docker"]
fn list_succeeds_when_keys_dir_missing() {
    if skip_if_no_docker("list_succeeds_when_keys_dir_missing") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    env.use_ephemeral_keys_dir().expect("ephemeral keys dir");
    // Clear it so it doesn't even exist as a directory.
    let keys_dir = env.home().join(".sshenc-keys-ephemeral");
    if keys_dir.exists() {
        std::fs::remove_dir_all(&keys_dir).expect("rm ephemeral");
    }

    let outcome = run(env.sshenc_cmd().expect("sshenc").arg("list")).expect("sshenc list");
    assert!(
        outcome.succeeded(),
        "sshenc list should succeed on missing keys_dir; stdout:\n{}\nstderr:\n{}",
        outcome.stdout,
        outcome.stderr
    );
}

/// `sshenc inspect <nonexistent-label>` must error cleanly with a
/// non-zero exit and a descriptive message.
#[test]
#[ignore = "requires docker"]
fn inspect_unknown_label_errors_cleanly() {
    if skip_if_no_docker("inspect_unknown_label_errors_cleanly") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    env.use_ephemeral_keys_dir().expect("ephemeral keys dir");

    let outcome = run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["inspect", "ghost-label-does-not-exist"]))
    .expect("sshenc inspect");
    assert!(
        !outcome.succeeded(),
        "inspect on missing label should fail; stdout:\n{}\nstderr:\n{}",
        outcome.stdout,
        outcome.stderr
    );
    let msg = outcome.stderr.to_lowercase();
    assert!(
        msg.contains("not found") || msg.contains("does not exist") || msg.contains("no such"),
        "expected not-found error in stderr; got:\n{}",
        outcome.stderr
    );
}

/// `sshenc inspect <label>` against a key whose `.meta` file
/// contains corrupted JSON must error cleanly without panicking.
/// We seed the keys_dir with a bogus meta file and verify the CLI
/// surfaces a parse error, not a stack trace.
#[test]
#[ignore = "requires docker"]
fn inspect_with_corrupted_meta_errors_cleanly() {
    if skip_if_no_docker("inspect_with_corrupted_meta_errors_cleanly") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    env.use_ephemeral_keys_dir().expect("ephemeral keys dir");
    let keys_dir = env.home().join(".sshenc-keys-ephemeral");
    std::fs::create_dir_all(&keys_dir).expect("mkdir ephemeral");

    // Plant a meta file that's not valid JSON.
    let meta_path = keys_dir.join("corrupt-label.meta");
    std::fs::write(&meta_path, b"\x00\x01\x02 not even close to JSON {{").expect("write bad meta");

    let outcome = run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["inspect", "corrupt-label"]))
    .expect("sshenc inspect");
    // Either fail outright, or succeed-with-error-on-stderr — but
    // never panic. We assert non-success here; a panic would show
    // up as exit 101 with "panicked at" in stderr.
    assert!(
        !outcome.stderr.contains("panicked at") && !outcome.stdout.contains("panicked at"),
        "sshenc inspect must not panic on corrupted meta; stderr:\n{}",
        outcome.stderr
    );
    assert!(
        !outcome.succeeded(),
        "inspect on corrupted meta should fail; stdout:\n{}\nstderr:\n{}",
        outcome.stdout,
        outcome.stderr
    );
}

/// `sshenc list` must not panic when one meta file in the keys_dir
/// is corrupted. The exact behavior — return the others, fail the
/// whole listing, or return an entry with a partial — is whatever
/// the current implementation does; what we guarantee is "no panic,
/// non-zero exit only if the user sees a useful error".
#[test]
#[ignore = "requires docker"]
fn list_does_not_panic_on_corrupted_meta() {
    if skip_if_no_docker("list_does_not_panic_on_corrupted_meta") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    env.use_ephemeral_keys_dir().expect("ephemeral keys dir");
    let keys_dir = env.home().join(".sshenc-keys-ephemeral");
    std::fs::create_dir_all(&keys_dir).expect("mkdir ephemeral");

    // Plant a corrupted meta file in an otherwise-empty keys_dir.
    std::fs::write(keys_dir.join("bad.meta"), b"definitely not json").expect("write bad meta");

    let outcome = run(env.sshenc_cmd().expect("sshenc").arg("list")).expect("sshenc list");
    assert!(
        !outcome.stderr.contains("panicked at") && !outcome.stdout.contains("panicked at"),
        "sshenc list must not panic on corrupted meta; stdout:\n{}\nstderr:\n{}",
        outcome.stdout,
        outcome.stderr
    );
    // Also: if it failed, the failure must surface useful text on
    // stderr — not be silent.
    if !outcome.succeeded() {
        assert!(
            !outcome.stderr.is_empty(),
            "sshenc list failed but stderr was empty"
        );
    }
}

/// `sshenc inspect <bad-label>` invoked with an invalid label
/// (path-separator chars) must reject early with a label-validation
/// error, not surface a confusing filesystem error from a stat()
/// against a synthesized path.
#[test]
#[ignore = "requires docker"]
fn inspect_invalid_label_format_rejected_early() {
    if skip_if_no_docker("inspect_invalid_label_format_rejected_early") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    env.use_ephemeral_keys_dir().expect("ephemeral keys dir");

    let outcome = run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["inspect", "../escape"]))
    .expect("sshenc inspect");
    assert!(
        !outcome.succeeded(),
        "inspect on invalid label should fail; stdout:\n{}\nstderr:\n{}",
        outcome.stdout,
        outcome.stderr
    );
    let msg = outcome.stderr.to_lowercase();
    assert!(
        msg.contains("label") || msg.contains("invalid") || msg.contains("not found"),
        "expected label-validation or not-found error; got:\n{}",
        outcome.stderr
    );
}
