// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! CLI-level concurrency: two `sshenc` processes racing on the
//! same agent must serialize through the agent without crashing,
//! corrupting metadata, or producing unexplained partial state.
//!
//! `agent_concurrency.rs` exercises N concurrent SignRequests over
//! one CLI process; this file goes further and races independent
//! CLI invocations:
//!
//! - Two `sshenc keygen --label X` for the same X — exactly one
//!   should succeed; the other gets a duplicate-label error.
//! - Two `sshenc delete --label X -y` for the same X — exactly
//!   one succeeds; the other reports the key already gone.
//! - keygen + list racing — list never sees a half-created key
//!   (label appears either fully or not at all, no torn metadata).
//!
//! Software/extended gated because tests mint extra keys.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{
    docker_skip_reason, extended_enabled, run, software_mode, SshencEnv, SHARED_ENCLAVE_LABEL,
};
use std::process::Command;
use std::sync::Arc;

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
        "skip {test_name}: needs to mint extra keys; \
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

/// Spawn `cmd` and return whether it succeeded plus combined
/// stdout+stderr text (for diagnostics on failure).
fn spawn_and_collect(mut cmd: Command) -> (bool, String) {
    let output = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("spawn child");
    let combined = format!(
        "exit={}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    (output.status.success(), combined)
}

/// Two `sshenc keygen --label <same>` racing — exactly one
/// succeeds; the other surfaces a duplicate-label / agent-refused
/// error rather than corrupting state.
#[test]
#[ignore = "requires docker"]
fn concurrent_keygen_same_label_one_winner() {
    if skip_if_no_docker("concurrent_keygen_same_label_one_winner") {
        return;
    }
    if skip_unless_key_creation_cheap("concurrent_keygen_same_label_one_winner") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(sshenc_e2e::shared_enclave_pubkey(&env).expect("warm shared key"));
    env.start_agent().expect("start agent");

    let label = unique_label("concur-keygen");
    let env_arc = Arc::new(env);

    let h1 = {
        let env = Arc::clone(&env_arc);
        let label = label.clone();
        std::thread::spawn(move || {
            let mut cmd = env.sshenc_cmd().expect("sshenc cmd");
            cmd.args([
                "keygen",
                "--label",
                &label,
                "--auth-policy",
                "none",
                "--no-pub-file",
            ]);
            spawn_and_collect(cmd)
        })
    };
    let h2 = {
        let env = Arc::clone(&env_arc);
        let label = label.clone();
        std::thread::spawn(move || {
            let mut cmd = env.sshenc_cmd().expect("sshenc cmd");
            cmd.args([
                "keygen",
                "--label",
                &label,
                "--auth-policy",
                "none",
                "--no-pub-file",
            ]);
            spawn_and_collect(cmd)
        })
    };
    let r1 = h1.join().expect("thread 1");
    let r2 = h2.join().expect("thread 2");

    let winners = [&r1, &r2].iter().filter(|(ok, _)| *ok).count();
    assert_eq!(
        winners, 1,
        "exactly one keygen should win for same label; r1={r1:?}\nr2={r2:?}"
    );

    // The label should appear in `sshenc list`.
    let listed = run(env_arc.sshenc_cmd().expect("sshenc").arg("list")).expect("sshenc list");
    assert!(
        listed.stdout.contains(&label),
        "winner-created label {label} should be listable; got:\n{}",
        listed.stdout
    );

    // Cleanup.
    drop(run(env_arc
        .sshenc_cmd()
        .expect("sshenc")
        .args(["delete", &label, "-y"])));
}

/// Two `sshenc delete --label <same> -y` racing — both must
/// terminate cleanly and the key must be gone after. The current
/// design is `rm -f`-style: the second delete sees the key
/// already absent and returns success silently rather than
/// erroring. This test guards that contract: don't crash, don't
/// leave torn state, end up with the key gone.
#[test]
#[ignore = "requires docker"]
fn concurrent_delete_same_label_ends_with_key_gone() {
    if skip_if_no_docker("concurrent_delete_same_label_ends_with_key_gone") {
        return;
    }
    if skip_unless_key_creation_cheap("concurrent_delete_same_label_ends_with_key_gone") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(sshenc_e2e::shared_enclave_pubkey(&env).expect("warm shared key"));
    env.start_agent().expect("start agent");

    let label = unique_label("concur-delete");
    // Pre-create the key.
    let kg = run(env.sshenc_cmd().expect("sshenc").args([
        "keygen",
        "--label",
        &label,
        "--auth-policy",
        "none",
        "--no-pub-file",
    ]))
    .expect("keygen");
    assert!(kg.succeeded(), "pre-keygen failed: {}", kg.stderr);

    let env_arc = Arc::new(env);
    let h1 = {
        let env = Arc::clone(&env_arc);
        let label = label.clone();
        std::thread::spawn(move || {
            let mut cmd = env.sshenc_cmd().expect("sshenc cmd");
            cmd.args(["delete", &label, "-y"]);
            spawn_and_collect(cmd)
        })
    };
    let h2 = {
        let env = Arc::clone(&env_arc);
        let label = label.clone();
        std::thread::spawn(move || {
            let mut cmd = env.sshenc_cmd().expect("sshenc cmd");
            cmd.args(["delete", &label, "-y"]);
            spawn_and_collect(cmd)
        })
    };
    let r1 = h1.join().expect("thread 1");
    let r2 = h2.join().expect("thread 2");

    // Both must terminate without panic/crash output.
    for (n, (_, combined)) in [&r1, &r2].iter().enumerate() {
        assert!(
            !combined.contains("panicked at"),
            "delete worker {n} panicked; got:\n{combined}"
        );
    }
    // At least one must succeed (the first one to land); the
    // second is allowed to succeed (idempotent design) or fail
    // cleanly. What's NOT allowed is both failing — that would
    // mean the key was never deleted.
    assert!(
        r1.0 || r2.0,
        "at least one delete must succeed; r1={r1:?}\nr2={r2:?}"
    );

    // End state: the label is gone.
    let listed = run(env_arc.sshenc_cmd().expect("sshenc").arg("list")).expect("sshenc list");
    assert!(
        !listed.stdout.contains(&label),
        "label should be gone after concurrent deletes; got:\n{}",
        listed.stdout
    );

    // Agent still serves requests after the race.
    let listed_again =
        run(env_arc.sshenc_cmd().expect("sshenc").arg("list")).expect("post-race list");
    assert!(
        listed_again.succeeded(),
        "agent should still serve after delete race; stderr:\n{}",
        listed_again.stderr
    );
}

/// keygen + list racing — list must never observe a half-created
/// key. Either the new label is absent (list raced first) or
/// fully present (keygen completed first); never partial.
#[test]
#[ignore = "requires docker"]
fn concurrent_keygen_and_list_no_torn_state() {
    if skip_if_no_docker("concurrent_keygen_and_list_no_torn_state") {
        return;
    }
    if skip_unless_key_creation_cheap("concurrent_keygen_and_list_no_torn_state") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(sshenc_e2e::shared_enclave_pubkey(&env).expect("warm shared key"));
    env.start_agent().expect("start agent");

    let label = unique_label("concur-kg-list");
    let env_arc = Arc::new(env);

    let kg_thread = {
        let env = Arc::clone(&env_arc);
        let label = label.clone();
        std::thread::spawn(move || {
            let mut cmd = env.sshenc_cmd().expect("sshenc cmd");
            cmd.args([
                "keygen",
                "--label",
                &label,
                "--auth-policy",
                "none",
                "--no-pub-file",
            ]);
            spawn_and_collect(cmd)
        })
    };
    // Spam list while keygen runs. If at any point list output is
    // malformed (parsing fails) or contains the label as a partial
    // entry (line truncated mid-bytes), this test catches that.
    let list_thread = {
        let env = Arc::clone(&env_arc);
        std::thread::spawn(move || -> Vec<String> {
            let mut snapshots = Vec::new();
            for _ in 0..20 {
                let out = run(env.sshenc_cmd().expect("sshenc").args(["list", "--json"]))
                    .expect("sshenc list --json");
                if !out.succeeded() {
                    panic!("racing list failed: {}", out.stderr);
                }
                // Parse each snapshot — invalid JSON would mean the
                // list saw torn on-disk state.
                let parsed: serde_json::Value = serde_json::from_str(&out.stdout)
                    .unwrap_or_else(|e| panic!("torn list output: {e}\nstdout:\n{}", out.stdout));
                drop(parsed);
                snapshots.push(out.stdout);
                std::thread::sleep(std::time::Duration::from_millis(15));
            }
            snapshots
        })
    };

    let kg_result = kg_thread.join().expect("keygen thread");
    let snapshots = list_thread.join().expect("list thread");
    assert!(
        kg_result.0,
        "keygen failed under concurrent list pressure: {:?}",
        kg_result.1
    );
    // Final list (post-keygen) must contain the label.
    let final_listed = run(env_arc.sshenc_cmd().expect("sshenc").arg("list")).expect("sshenc list");
    assert!(
        final_listed.stdout.contains(&label),
        "label should appear in post-race list; got:\n{}",
        final_listed.stdout
    );
    // The shared enclave label should appear in every snapshot
    // (it's present from the start) — proves we weren't getting
    // empty lists from a contended read.
    for (i, snap) in snapshots.iter().enumerate() {
        assert!(
            snap.contains(SHARED_ENCLAVE_LABEL),
            "snapshot {i} missing shared label, suggests contended read returned empty: {snap}"
        );
    }

    // Cleanup.
    drop(run(env_arc
        .sshenc_cmd()
        .expect("sshenc")
        .args(["delete", &label, "-y"])));
}
