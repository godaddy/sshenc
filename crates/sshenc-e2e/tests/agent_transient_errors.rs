// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Agent recovery from torn on-disk state.
//!
//! `corrupted_state.rs` covers garbage *contents* of a meta file.
//! This file covers a different real-world condition: a previous
//! op crashed mid-write, leaving only one of `.meta` / `.key`
//! behind. The agent must:
//!
//! - never panic on the partial state;
//! - ideally skip the orphan during list (it's not a usable key);
//! - allow operations on the orphan label (delete, or keygen with
//!   the same label) without leaving more torn state behind.
//!
//! Why these conditions are realistic: a crash between
//! `atomic_write(meta)` and `atomic_write(key)` produces an
//! orphan .meta. A crash between two halves of `delete` (which
//! removes both files) can leave either orphan. Power loss,
//! `kill -9`, ENOSPC mid-op all produce the same shape.
//!
//! The chmod-based transient-error injection that an earlier
//! draft of this file used didn't work — `metadata::ensure_dir`
//! unconditionally chmods the keys_dir back to 0o700 on every op
//! (deliberately, to enforce restrictive perms), which the owner
//! can always do regardless of the current mode. So denial-of-
//! write requires either root, FUSE, or LD_PRELOAD injection —
//! all out of scope. Torn-state injection is just file deletion.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{
    docker_skip_reason, extended_enabled, run, shared_enclave_pubkey, software_mode, SshencEnv,
};

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

fn unique_label(prefix: &str) -> String {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{prefix}-{pid}-{nanos}")
}

/// `sshenc list` on a keys_dir containing an orphaned .meta (no
/// matching .key) must not panic. The orphan should be skipped
/// or surfaced cleanly — never crash the listing.
#[test]
#[ignore = "requires docker"]
fn list_with_orphaned_meta_does_not_panic() {
    if skip_if_no_docker("list_with_orphaned_meta_does_not_panic") {
        return;
    }
    if skip_unless_key_creation_cheap("list_with_orphaned_meta_does_not_panic") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    env.use_ephemeral_keys_dir().expect("ephemeral");
    let keys_dir = env.home().join(".sshenc-keys-ephemeral");

    // Create one valid key plus one orphan-meta to simulate a
    // crash between meta-write and key-write.
    let valid = unique_label("torn-valid");
    let orphan = unique_label("torn-orphan-meta");
    let kg = run(env.sshenc_cmd().expect("sshenc").args([
        "keygen",
        "--label",
        &valid,
        "--auth-policy",
        "none",
        "--no-pub-file",
    ]))
    .expect("keygen valid");
    assert!(kg.succeeded(), "keygen valid: {}", kg.stderr);

    // Plant orphan .meta directly. Steal the schema from the
    // valid key's meta so the JSON parses.
    let valid_meta =
        std::fs::read_to_string(keys_dir.join(format!("{valid}.meta"))).expect("read valid meta");
    let orphan_meta_path = keys_dir.join(format!("{orphan}.meta"));
    let mut orphan_meta_value: serde_json::Value =
        serde_json::from_str(&valid_meta).expect("parse meta");
    if let Some(t) = orphan_meta_value.as_object_mut() {
        t.insert("label".into(), serde_json::json!(orphan));
    }
    std::fs::write(
        &orphan_meta_path,
        serde_json::to_string_pretty(&orphan_meta_value).unwrap(),
    )
    .expect("write orphan meta");

    let listed =
        run(env.sshenc_cmd().expect("sshenc").args(["list", "--json"])).expect("list --json");
    assert!(
        !listed.stdout.contains("panicked at") && !listed.stderr.contains("panicked at"),
        "sshenc list must not panic on orphan .meta; stderr:\n{}",
        listed.stderr
    );
    // List should succeed (exit 0) — the contract for "skip
    // unrecoverable entry" is that listing still works for the
    // recoverable ones.
    assert!(
        listed.succeeded(),
        "list should succeed despite orphan; stderr:\n{}",
        listed.stderr
    );

    drop(run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["delete", &valid, "-y"])));
    // Cleanup orphan manually (delete may or may not handle it).
    drop(std::fs::remove_file(&orphan_meta_path));
}

/// `sshenc list` on a keys_dir containing an orphaned .key (no
/// matching .meta) must not panic. .meta is the source of truth
/// for "this is a sshenc-managed key" — an orphan .key should be
/// invisible to list (no metadata = no entry).
#[test]
#[ignore = "requires docker"]
fn list_with_orphaned_key_file_skips_entry() {
    if skip_if_no_docker("list_with_orphaned_key_file_skips_entry") {
        return;
    }
    if skip_unless_key_creation_cheap("list_with_orphaned_key_file_skips_entry") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    env.use_ephemeral_keys_dir().expect("ephemeral");
    let keys_dir = env.home().join(".sshenc-keys-ephemeral");

    let valid = unique_label("torn-valid2");
    let orphan = unique_label("torn-orphan-key");
    assert!(run(env.sshenc_cmd().expect("sshenc").args([
        "keygen",
        "--label",
        &valid,
        "--auth-policy",
        "none",
        "--no-pub-file",
    ]))
    .expect("keygen valid")
    .succeeded());

    // Plant a fake .key with no matching .meta.
    let orphan_key_path = keys_dir.join(format!("{orphan}.key"));
    std::fs::write(&orphan_key_path, b"\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE")
        .expect("write orphan key");

    let listed =
        run(env.sshenc_cmd().expect("sshenc").args(["list", "--json"])).expect("list --json");
    assert!(
        !listed.stdout.contains("panicked at") && !listed.stderr.contains("panicked at"),
        "list must not panic on orphan .key"
    );
    assert!(listed.succeeded(), "list failed: {}", listed.stderr);

    // The orphan label must NOT appear in the list output —
    // without metadata it's not a real key.
    let arr: serde_json::Value =
        serde_json::from_str(&listed.stdout).expect("list --json output is JSON");
    let orphan_seen = arr.as_array().expect("array").iter().any(|e| {
        e.get("metadata")
            .and_then(|m| m.get("label"))
            .and_then(|v| v.as_str())
            == Some(&*orphan)
    });
    assert!(
        !orphan_seen,
        "orphan .key without .meta should not appear in list output"
    );
    // Valid one should appear.
    let valid_seen = arr.as_array().expect("array").iter().any(|e| {
        e.get("metadata")
            .and_then(|m| m.get("label"))
            .and_then(|v| v.as_str())
            == Some(&*valid)
    });
    assert!(valid_seen, "valid key should appear alongside the orphan");

    drop(run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["delete", &valid, "-y"])));
    drop(std::fs::remove_file(&orphan_key_path));
}

/// After a torn state is observed, agent ops continue working —
/// list, keygen, delete, and signed-RPC traffic should all keep
/// flowing past the orphan files without the agent's accept loop
/// dying.
#[test]
#[ignore = "requires docker"]
fn agent_keeps_serving_with_orphan_files_present() {
    if skip_if_no_docker("agent_keeps_serving_with_orphan_files_present") {
        return;
    }
    if skip_unless_key_creation_cheap("agent_keeps_serving_with_orphan_files_present") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    env.use_ephemeral_keys_dir().expect("ephemeral");
    let keys_dir = env.home().join(".sshenc-keys-ephemeral");
    drop(shared_enclave_pubkey(&env).expect("warm shared key"));
    env.start_agent().expect("start agent");

    // Mint a real key.
    let real = unique_label("orph-svc-real");
    assert!(run(env.sshenc_cmd().expect("sshenc").args([
        "keygen",
        "--label",
        &real,
        "--auth-policy",
        "none",
        "--no-pub-file",
    ]))
    .expect("keygen")
    .succeeded());

    // Plant both kinds of orphan to maximize the surface area.
    let orphan_meta = unique_label("orph-svc-meta-only");
    let orphan_key = unique_label("orph-svc-key-only");
    let real_meta =
        std::fs::read_to_string(keys_dir.join(format!("{real}.meta"))).expect("real meta");
    let mut meta_val: serde_json::Value = serde_json::from_str(&real_meta).expect("parse");
    if let Some(t) = meta_val.as_object_mut() {
        t.insert("label".into(), serde_json::json!(orphan_meta));
    }
    std::fs::write(
        keys_dir.join(format!("{orphan_meta}.meta")),
        serde_json::to_string_pretty(&meta_val).unwrap(),
    )
    .expect("plant orphan meta");
    std::fs::write(
        keys_dir.join(format!("{orphan_key}.key")),
        b"\x00\x01\x02\x03",
    )
    .expect("plant orphan key");

    env.start_agent().expect("start agent");

    // Agent must answer ssh-add -L despite the orphans.
    let listed = run(env
        .scrubbed_command("ssh-add")
        .env("SSH_AUTH_SOCK", env.socket_path())
        .arg("-L"))
    .expect("ssh-add -L");
    assert!(
        listed.succeeded(),
        "ssh-add -L with orphans present failed; stderr:\n{}",
        listed.stderr
    );

    // The real key should be visible.
    let exp = run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["export-pub", &real]))
    .expect("export-pub");
    assert!(exp.succeeded(), "export-pub: {}", exp.stderr);
    let real_body = exp
        .stdout
        .split_whitespace()
        .nth(1)
        .expect("body")
        .to_string();
    assert!(
        listed.stdout.contains(&real_body),
        "real key should be visible despite orphans; got:\n{}",
        listed.stdout
    );

    // A fresh keygen still works — agent's accept loop wasn't
    // killed by the orphans.
    let post = unique_label("orph-svc-post");
    let kg2 = run(env.sshenc_cmd().expect("sshenc").args([
        "keygen",
        "--label",
        &post,
        "--auth-policy",
        "none",
        "--no-pub-file",
    ]))
    .expect("post-orphan keygen");
    assert!(
        kg2.succeeded(),
        "post-orphan keygen failed; stderr:\n{}",
        kg2.stderr
    );

    // Cleanup.
    drop(run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["delete", &real, "-y"])));
    drop(run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["delete", &post, "-y"])));
    drop(std::fs::remove_file(
        keys_dir.join(format!("{orphan_meta}.meta")),
    ));
    drop(std::fs::remove_file(
        keys_dir.join(format!("{orphan_key}.key")),
    ));
}
