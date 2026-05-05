// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `sshenc keygen --label default` against an existing
//! `~/.ssh/id_ecdsa` + `~/.ssh/id_ecdsa.pub` pair routes through
//! `backup::run_with_backup`. The unit tests for `backup.rs` cover
//! the rename-into-backup, the on-success cleanup, and the on-failure
//! restore at the API level. What's pinned here is end-to-end proof
//! that the CLI wires keygen through the backup helper AND that
//! rotation (keygen against an existing label) preserves the right
//! adjacent files.
//!
//! Contracts pinned:
//! - first-keygen success: the planted paired-private + paired-public
//!   are moved aside, the new key's pubkey lands at
//!   `~/.ssh/id_ecdsa.pub`, the planted private is removed (the new
//!   key is hardware-backed), and no `.bak` files remain.
//! - rotation (second keygen with same label): completes successfully
//!   with the rotation banner; the pub file gets the NEW pubkey; an
//!   id_ecdsa private the user planted is left untouched (rotation
//!   doesn't synthesize or mutate paired private material); no `.bak`
//!   files leak.
//! - rotation of a non-default label: the user's id_ecdsa pair is
//!   completely untouched -- a named-label rotation has nothing to
//!   do with `id_ecdsa`.
//!
//! The earlier "failure restores paired files" contract was pinned
//! against `DuplicateLabel` as the failure trigger. That trigger was
//! retired when sshenc PR #187 turned same-label keygen into an
//! in-place rotation; the backup-restore path is still exercised at
//! the unit level via `crates/sshenc-core/src/backup.rs` tests.

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

fn list_bak_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|ext| ext == "bak"))
                .collect()
        })
        .unwrap_or_default()
}

/// Successful `sshenc keygen --label default` against an existing
/// `id_ecdsa` + `id_ecdsa.pub` pair: backup happens, keygen
/// succeeds, the new pubkey ends up at `id_ecdsa.pub`, and the
/// backup files are cleaned up.
#[test]
#[ignore = "requires docker"]
fn keygen_default_success_cleans_up_backed_up_files() {
    if skip_if_no_docker("keygen_default_success_cleans_up_backed_up_files") {
        return;
    }
    if skip_unless_key_creation_cheap("keygen_default_success_cleans_up_backed_up_files") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    env.use_ephemeral_keys_dir().expect("ephemeral");
    env.start_agent().expect("start agent");

    let priv_path = env.ssh_dir().join("id_ecdsa");
    let pub_path = env.ssh_dir().join("id_ecdsa.pub");

    // Plant a paired private+pub the user might have on disk before
    // installing sshenc — content doesn't have to be a real ECDSA
    // key, only the file presence matters for the CLI's "back this
    // up before generating" branch.
    std::fs::write(&priv_path, b"PREEXISTING PRIVATE KEY MARKER\n").expect("write priv");
    std::fs::write(&pub_path, b"ssh-ecdsa AAAA-old-pubkey-content user@old\n").expect("write pub");

    let kg = run(env.sshenc_cmd().expect("sshenc cmd").args([
        "keygen",
        "--label",
        "default",
        "--auth-policy",
        "none",
    ]))
    .expect("spawn sshenc keygen");
    assert!(
        kg.succeeded(),
        "keygen --label default should succeed; stderr:\n{}",
        kg.stderr
    );

    // The .pub file now holds the freshly-generated key — different
    // content than what we planted.
    let new_pub = std::fs::read_to_string(&pub_path).expect("read pub after");
    assert_ne!(
        new_pub, "ssh-ecdsa AAAA-old-pubkey-content user@old\n",
        "id_ecdsa.pub still has the planted content; backup didn't take"
    );

    // The original `id_ecdsa` private file was a paired backup
    // candidate; on success it must be cleaned up rather than
    // restored. (The new key is hardware-backed, so no new
    // id_ecdsa private file is written.)
    assert!(
        !priv_path.exists(),
        "id_ecdsa private should be cleaned up after success, still at {}",
        priv_path.display()
    );

    let leftover = list_bak_files(&env.ssh_dir());
    assert!(
        leftover.is_empty(),
        "no .bak files should remain after success; got: {leftover:?}"
    );

    // Cleanup so the next test's keys_dir is fresh — the ephemeral
    // dir is wiped by SshencEnv drop, so we just need to ensure
    // we don't leak the agent.
    drop(run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["delete", "default", "-y"])));
}

/// `sshenc keygen --label default` invoked a second time rotates
/// the existing `default` key in place (sshenc PR #187). The
/// pre-existing pubkey at `~/.ssh/id_ecdsa.pub` becomes the rotation
/// target -- the rotation flow rewrites it with the NEW pubkey. A
/// paired private that the user planted at `~/.ssh/id_ecdsa` is left
/// untouched: rotation has no business synthesizing or mutating an
/// external private file. No `.bak` files leak.
#[test]
#[ignore = "requires docker"]
fn keygen_default_second_invocation_rotates_in_place() {
    if skip_if_no_docker("keygen_default_second_invocation_rotates_in_place") {
        return;
    }
    if skip_unless_key_creation_cheap("keygen_default_second_invocation_rotates_in_place") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    env.use_ephemeral_keys_dir().expect("ephemeral");
    env.start_agent().expect("start agent");

    let priv_path = env.ssh_dir().join("id_ecdsa");
    let pub_path = env.ssh_dir().join("id_ecdsa.pub");

    // Mint `default` once with the default pub-file path; that
    // populates id_ecdsa.pub so we have something for the rotation
    // to rewrite. Drop `--no-pub-file` here vs the smoke variants
    // because we need the file to exist for the bytes-changed
    // assertion below.
    let pre = run(env.sshenc_cmd().expect("sshenc cmd").args([
        "keygen",
        "--label",
        "default",
        "--auth-policy",
        "none",
    ]))
    .expect("first keygen");
    assert!(
        pre.succeeded(),
        "first keygen failed unexpectedly: {}",
        pre.stderr
    );

    // Capture the freshly-written pubkey so we can confirm the
    // rotation rewrote it with new bytes.
    let pre_rotation_pub = std::fs::read(&pub_path).expect("read pub after first keygen");

    // Plant a paired private the user might still have on disk. The
    // rotation flow has no reason to touch it -- the key material
    // lives in the SE, not in this file -- but we pin that here.
    let original_priv: &[u8] = b"-- USER PLANTED PRIVATE FILE --\n";
    std::fs::write(&priv_path, original_priv).expect("write priv");

    // Second keygen rotates in place.
    let kg2 = run(env.sshenc_cmd().expect("sshenc cmd").args([
        "keygen",
        "--label",
        "default",
        "--auth-policy",
        "none",
    ]))
    .expect("second keygen");
    assert!(
        kg2.succeeded(),
        "second keygen should succeed via rotation; stdout:\n{}\nstderr:\n{}",
        kg2.stdout,
        kg2.stderr
    );
    assert!(
        kg2.stdout.contains("Rotated") && kg2.stdout.contains("Old fingerprint"),
        "expected rotation banner with old/new fingerprints; got:\n{}",
        kg2.stdout
    );

    // The .pub file holds the rotated pubkey -- different bytes
    // than the first-keygen output.
    let post_rotation_pub = std::fs::read(&pub_path).expect("read pub after rotation");
    assert_ne!(
        post_rotation_pub, pre_rotation_pub,
        "id_ecdsa.pub still has the pre-rotation content; rotation did not rewrite the .pub file"
    );

    // The planted private file is untouched by the rotation flow.
    let priv_after = std::fs::read(&priv_path).expect("read priv after");
    assert_eq!(
        priv_after, original_priv,
        "id_ecdsa private was disturbed by the rotation; rotation must not synthesize or mutate paired private material",
    );

    let leftover = list_bak_files(&env.ssh_dir());
    assert!(
        leftover.is_empty(),
        "no .bak files should remain after a successful rotation; got: {leftover:?}"
    );

    // Cleanup the rotated key so we don't leak agent-side state.
    drop(run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["delete", "default", "-y"])));
}

/// A non-`default` label uses `~/.ssh/<label>.pub` and has no
/// paired-private semantics — the user's `id_ecdsa` pair is out of
/// scope for a named-label keygen. Pins that contract for both the
/// first-mint AND the rotation (second invocation) paths.
#[test]
#[ignore = "requires docker"]
fn keygen_named_label_does_not_touch_id_ecdsa() {
    if skip_if_no_docker("keygen_named_label_does_not_touch_id_ecdsa") {
        return;
    }
    if skip_unless_key_creation_cheap("keygen_named_label_does_not_touch_id_ecdsa") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    env.use_ephemeral_keys_dir().expect("ephemeral");
    env.start_agent().expect("start agent");

    let priv_path = env.ssh_dir().join("id_ecdsa");
    let pub_path = env.ssh_dir().join("id_ecdsa.pub");
    std::fs::write(&priv_path, b"DO NOT TOUCH\n").expect("write priv");
    std::fs::write(&pub_path, b"DO NOT TOUCH PUB\n").expect("write pub");

    // Mint, then re-mint the same named label. First call generates;
    // second call rotates in place. Either way, `id_ecdsa{,.pub}` is
    // not in scope and must remain byte-for-byte untouched.
    let label = "other-backup-probe";
    let pre = run(env.sshenc_cmd().expect("sshenc cmd").args([
        "keygen",
        "--label",
        label,
        "--auth-policy",
        "none",
        "--no-pub-file",
    ]))
    .expect("pre keygen");
    assert!(pre.succeeded(), "pre keygen: {}", pre.stderr);

    let kg2 = run(env.sshenc_cmd().expect("sshenc cmd").args([
        "keygen",
        "--label",
        label,
        "--auth-policy",
        "none",
        "--no-pub-file",
    ]))
    .expect("second keygen (rotation)");
    assert!(
        kg2.succeeded(),
        "second keygen for {label} should rotate in place; stderr:\n{}",
        kg2.stderr
    );
    assert!(
        kg2.stdout.contains("Rotated"),
        "expected rotation banner; stdout:\n{}",
        kg2.stdout
    );

    // id_ecdsa pair must be untouched -- a named-label rotation has
    // nothing to do with the `default`-label paired-private path.
    assert_eq!(
        std::fs::read(&priv_path).expect("read priv"),
        b"DO NOT TOUCH\n"
    );
    assert_eq!(
        std::fs::read(&pub_path).expect("read pub"),
        b"DO NOT TOUCH PUB\n"
    );

    drop(run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["delete", label, "-y"])));
}
