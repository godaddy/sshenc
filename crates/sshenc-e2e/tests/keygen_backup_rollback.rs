// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `sshenc keygen --label default` against an existing
//! `~/.ssh/id_ecdsa` + `~/.ssh/id_ecdsa.pub` pair routes through
//! `backup::run_with_backup`. The unit tests for `backup.rs` cover
//! the rename-into-backup, the on-success cleanup, and the on-failure
//! restore at the API level. What was missing was end-to-end proof
//! that the CLI actually wires keygen through that backup helper.
//!
//! Two contracts to pin:
//! - on success: the original files were moved aside (so the new
//!   key's pubkey now lives at `~/.ssh/id_ecdsa.pub`), and no `.bak`
//!   files remain behind.
//! - on failure: both `~/.ssh/id_ecdsa` and `~/.ssh/id_ecdsa.pub`
//!   are restored *byte-for-byte*, and again no `.bak` files leak.
//!
//! For the failure case we use the agent's `DuplicateLabel`
//! rejection: a successful first keygen leaves `default` in
//! keys_dir, then a second keygen with the same label fails with
//! the agent rejecting the duplicate. The CLI's backup-rollback
//! path is what catches that, so this test guards the
//! "wired-through-the-helper" property.

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

/// `sshenc keygen --label default` failing AFTER the backup has been
/// taken must restore both files byte-for-byte, with no `.bak`
/// stragglers. We trigger the failure by minting `default` once,
/// then asking the agent to mint it again — `SshencBackend.generate`
/// rejects with `DuplicateLabel`, which propagates up through the
/// CLI's `run_with_backup` call site.
#[test]
#[ignore = "requires docker"]
fn keygen_default_failure_restores_paired_files() {
    if skip_if_no_docker("keygen_default_failure_restores_paired_files") {
        return;
    }
    if skip_unless_key_creation_cheap("keygen_default_failure_restores_paired_files") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    env.use_ephemeral_keys_dir().expect("ephemeral");

    // Mint `default` once so a second attempt is guaranteed to
    // fail with DuplicateLabel.
    let pre = run(env.sshenc_cmd().expect("sshenc cmd").args([
        "keygen",
        "--label",
        "default",
        "--auth-policy",
        "none",
        "--no-pub-file",
    ]))
    .expect("first keygen");
    assert!(
        pre.succeeded(),
        "first keygen failed unexpectedly: {}",
        pre.stderr
    );

    let priv_path = env.ssh_dir().join("id_ecdsa");
    let pub_path = env.ssh_dir().join("id_ecdsa.pub");

    // Plant the paired files we want preserved across a failed
    // second keygen. Use distinguishable content so the assertion
    // can verify byte-for-byte restoration.
    let original_priv: &[u8] = b"-- BACKUP PROBE PRIVATE FILE --\n";
    let original_pub: &[u8] = b"ssh-ecdsa AAAA-backup-probe-pubkey owner@host\n";
    std::fs::write(&priv_path, original_priv).expect("write priv");
    std::fs::write(&pub_path, original_pub).expect("write pub");

    // Second keygen — must fail; backup-then-restore is the
    // contract under test.
    let kg2 = run(env.sshenc_cmd().expect("sshenc cmd").args([
        "keygen",
        "--label",
        "default",
        "--auth-policy",
        "none",
    ]))
    .expect("second keygen");
    assert!(
        !kg2.succeeded(),
        "second keygen should fail (DuplicateLabel); stdout:\n{}\nstderr:\n{}",
        kg2.stdout,
        kg2.stderr
    );

    // Both planted files must come back, byte-identical.
    let restored_priv = std::fs::read(&priv_path).expect("read priv after");
    let restored_pub = std::fs::read(&pub_path).expect("read pub after");
    assert_eq!(
        restored_priv,
        original_priv,
        "id_ecdsa private was not byte-for-byte restored; got {} bytes",
        restored_priv.len()
    );
    assert_eq!(
        restored_pub,
        original_pub,
        "id_ecdsa.pub was not byte-for-byte restored; got {} bytes",
        restored_pub.len()
    );

    let leftover = list_bak_files(&env.ssh_dir());
    assert!(
        leftover.is_empty(),
        "no .bak files should remain after rollback; got: {leftover:?}"
    );

    // Cleanup the pre-minted key so we don't leak agent-side state.
    drop(run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["delete", "default", "-y"])));
}

/// A non-`default` label uses an explicit `--write-pub` *or* falls
/// back to `~/.ssh/<label>.pub` with no paired-private semantics —
/// pre-existing `id_ecdsa` is *not* in scope, so a failure on a
/// named-label keygen must not back up or touch the user's
/// `id_ecdsa` files at all. Pins the "paired-private only for
/// default label" boundary.
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

    let priv_path = env.ssh_dir().join("id_ecdsa");
    let pub_path = env.ssh_dir().join("id_ecdsa.pub");
    std::fs::write(&priv_path, b"DO NOT TOUCH\n").expect("write priv");
    std::fs::write(&pub_path, b"DO NOT TOUCH PUB\n").expect("write pub");

    // Mint and re-mint a named label to drive the failure path,
    // exactly as the default-label test does — but for label "other"
    // the CLI's backup target is `~/.ssh/other.pub`, not `id_ecdsa`.
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
    .expect("second keygen");
    assert!(
        !kg2.succeeded(),
        "second keygen for {label} should fail; stderr:\n{}",
        kg2.stderr
    );

    // id_ecdsa pair must be untouched.
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
