// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Concurrent `sshenc keygen` and `sshenc -Y sign` against the
//! same agent: keygen takes a directory write-lock for the
//! new key's `.meta`/.key`, while sign reads existing key
//! state. Both must complete cleanly without deadlock or
//! corruption. Existing tests cover concurrent keygen+keygen
//! and concurrent sign+list; this orthogonal mix isn't pinned.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{
    docker_skip_reason, extended_enabled, run, shared_enclave_pubkey, software_mode, SshencEnv,
    SHARED_ENCLAVE_LABEL,
};
use std::sync::Arc;
use std::time::{Duration, Instant};

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

/// Concurrent keygen + sign against the same agent: both
/// complete; no deadlock, no panic, no torn state.
#[test]
#[ignore = "requires docker"]
fn concurrent_keygen_and_sign_on_same_agent() {
    if skip_if_no_docker("concurrent_keygen_and_sign_on_same_agent") {
        return;
    }
    if skip_unless_key_creation_cheap("concurrent_keygen_and_sign_on_same_agent") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");

    // Pre-write the shared key's pubfile so -Y sign can find it.
    let pub_path = env.ssh_dir().join(format!("{SHARED_ENCLAVE_LABEL}.pub"));
    std::fs::create_dir_all(env.ssh_dir()).expect("mkdir ssh dir");
    std::fs::write(&pub_path, format!("{enclave}\n")).expect("write pub");

    let env_arc = Arc::new(env);

    // Sign thread: runs `sshenc -Y sign` repeatedly for ~3s.
    let sign_env = env_arc.clone();
    let sign_pub = pub_path.clone();
    let sign_thread = std::thread::spawn(move || {
        let payload = sign_env.home().join("concurrent-sign-payload.txt");
        std::fs::write(&payload, b"concurrent payload\n").expect("write payload");
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut succeeded = 0_usize;
        let mut total = 0_usize;
        while Instant::now() < deadline {
            total += 1;
            let out = run(sign_env
                .sshenc_cmd()
                .expect("sshenc cmd")
                .arg("-Y")
                .arg("sign")
                .arg("-n")
                .arg("git")
                .arg("-f")
                .arg(&sign_pub)
                .arg(&payload))
            .expect("sshenc -Y sign");
            if out.succeeded() {
                succeeded += 1;
                drop(std::fs::remove_file(payload.with_extension("txt.sig")));
            }
            std::thread::sleep(Duration::from_millis(30));
        }
        (total, succeeded)
    });

    // Keygen thread: mint 3 distinct labels while sign loop is hot.
    let keygen_env = env_arc.clone();
    let keygen_thread = std::thread::spawn(move || {
        let mut minted = Vec::new();
        for i in 0..3 {
            let label = format!("concurrent-{}-{i}", std::process::id());
            let kg = run(keygen_env.sshenc_cmd().expect("sshenc cmd").args([
                "keygen",
                "--label",
                &label,
                "--auth-policy",
                "none",
                "--no-pub-file",
            ]))
            .expect("sshenc keygen");
            if kg.succeeded() {
                minted.push(label);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        minted
    });

    let minted = keygen_thread.join().expect("keygen thread");
    let (sign_total, sign_ok) = sign_thread.join().expect("sign thread");

    // Both threads completed; no panic propagated. Pin minimal
    // success criteria: at least one sign and one keygen actually
    // succeeded. The agent's rate limiter may reject some — that's
    // fine; what we forbid is deadlock or zero-progress.
    assert!(
        !minted.is_empty(),
        "no keygens succeeded under concurrent sign load"
    );
    assert!(
        sign_ok > 0,
        "no signs succeeded ({sign_ok}/{sign_total}); concurrent keygen blocked sign"
    );

    // Listing the agent must show all minted keys.
    let listed = run(env_arc
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["list", "--json"]))
    .expect("sshenc list --json");
    assert!(listed.succeeded(), "list: {}", listed.stderr);
    for label in &minted {
        assert!(
            listed.stdout.contains(label),
            "minted label {label} not in list output:\n{}",
            listed.stdout
        );
    }
}
