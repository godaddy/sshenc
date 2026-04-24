// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Extended sshenc e2e scenarios that require additional Secure Enclave
//! keys beyond the single shared key used by the baseline tests.
//!
//! Gated behind `SSHENC_E2E_EXTENDED=1` because each extra SE key on
//! macOS has its own keychain ACL, and each ACL re-prompts after a
//! binary rebuild. Baseline e2e runs stay at two prompts per rebuild;
//! extended mode accepts the higher cost in exchange for broader
//! coverage (multiple labeled keys, default-label promotion).
//!
//! In CI (Linux or any environment without macOS keychain ACLs), always
//! enable: `SSHENC_E2E_EXTENDED=1 cargo test -p sshenc-e2e -- --ignored`.

#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{
    docker_skip_reason, ensure_persistent_enclave_key, extended_enabled, run,
    shared_enclave_pubkey, SshdContainer, SshencEnv, SHARED_ENCLAVE_LABEL,
};

fn skip_preamble(test: &str) -> bool {
    if !extended_enabled() {
        eprintln!("skip {test}: SSHENC_E2E_EXTENDED not set");
        return true;
    }
    if let Some(reason) = docker_skip_reason() {
        eprintln!("skip {test}: {reason}");
        return true;
    }
    false
}

/// A second persistent enclave key label used by the multi-key scenarios.
const SECOND_LABEL: &str = "e2e-shared-b";

/// Label created fresh by the default-promotion test, which promotes it
/// to `default`. Persisted so the promotion only happens once ever.
const PROMOTE_SOURCE_LABEL: &str = "e2e-promote";

/// `sshenc ssh --label X` selects among multiple enclave keys correctly.
///
/// Two enclave keys both exist in the backend. Test:
///   - server trusts only key A → `--label A` succeeds, `--label B` fails,
///   - server trusts only key B → `--label B` succeeds, `--label A` fails.
///
/// Proves the label-based selection inside the wrapper and the agent
/// actually picks the right identity and doesn't just offer whichever
/// key happens to be first.
#[test]
#[ignore = "requires docker + SSHENC_E2E_EXTENDED"]
fn sshenc_ssh_selects_among_multiple_enclave_keys_by_label() {
    if skip_preamble("sshenc_ssh_selects_among_multiple_enclave_keys_by_label") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let key_a = shared_enclave_pubkey(&env).expect("shared enclave");
    let key_b = ensure_persistent_enclave_key(&env, SECOND_LABEL).expect("second enclave");
    assert_ne!(
        key_a, key_b,
        "expected distinct pubkeys for distinct labels"
    );
    env.start_agent().expect("agent start");

    // --- Server trusts A only ---
    let container_a = SshdContainer::start(&[&key_a]).expect("container A");
    let ok = run(&mut build_labeled_ssh(
        &env,
        &container_a,
        SHARED_ENCLAVE_LABEL,
    ))
    .expect("ssh A/A");
    assert!(
        ok.succeeded(),
        "--label {SHARED_ENCLAVE_LABEL} against server trusting {SHARED_ENCLAVE_LABEL} \
         should succeed; stderr:\n{}",
        ok.stderr
    );
    let bad = run(&mut build_labeled_ssh(&env, &container_a, SECOND_LABEL)).expect("ssh A/B");
    assert!(
        !bad.succeeded(),
        "--label {SECOND_LABEL} against server trusting {SHARED_ENCLAVE_LABEL} \
         should fail; stderr:\n{}",
        bad.stderr
    );
    drop(container_a);

    // --- Server trusts B only ---
    let container_b = SshdContainer::start(&[&key_b]).expect("container B");
    let ok = run(&mut build_labeled_ssh(&env, &container_b, SECOND_LABEL)).expect("ssh B/B");
    assert!(
        ok.succeeded(),
        "--label {SECOND_LABEL} against server trusting {SECOND_LABEL} should succeed; \
         stderr:\n{}",
        ok.stderr
    );
    let bad = run(&mut build_labeled_ssh(
        &env,
        &container_b,
        SHARED_ENCLAVE_LABEL,
    ))
    .expect("ssh B/A");
    assert!(
        !bad.succeeded(),
        "--label {SHARED_ENCLAVE_LABEL} against server trusting {SECOND_LABEL} should fail; \
         stderr:\n{}",
        bad.stderr
    );
}

/// `sshenc default <label>` renames the key and writes `~/.ssh/id_ecdsa.pub`,
/// and the promoted key can authenticate through the agent as the default.
///
/// Idempotent: if `default` already exists from a prior run, just verify
/// its presence and usability.
#[test]
#[ignore = "requires docker + SSHENC_E2E_EXTENDED"]
fn sshenc_default_promotion_writes_id_ecdsa_pub_and_authenticates() {
    if skip_preamble("sshenc_default_promotion_writes_id_ecdsa_pub_and_authenticates") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");

    // List current keys and see whether "default" already exists from a
    // previous run. If yes, skip the promote step.
    let list = run(env.sshenc_cmd().expect("sshenc cmd").arg("list")).expect("sshenc list");
    assert!(
        list.succeeded(),
        "sshenc list failed; stderr:\n{}",
        list.stderr
    );
    let default_exists = list
        .stdout
        .lines()
        .any(|line| line.trim_start().starts_with("default ") || line.trim() == "default");

    let id_ecdsa_pub = env.ssh_dir().join("id_ecdsa.pub");

    if !default_exists {
        // Create the source key, then promote it. `sshenc default` writes
        // id_ecdsa.pub in $HOME/.ssh as part of its promotion work.
        drop(
            ensure_persistent_enclave_key(&env, PROMOTE_SOURCE_LABEL).expect("promote source key"),
        );
        let promote = run(env
            .sshenc_cmd()
            .expect("sshenc cmd")
            .arg("default")
            .arg(PROMOTE_SOURCE_LABEL))
        .expect("sshenc default");
        assert!(
            promote.succeeded(),
            "sshenc default {PROMOTE_SOURCE_LABEL} failed; stderr:\n{}",
            promote.stderr
        );
    } else if !id_ecdsa_pub.exists() {
        // "default" persists across runs in the shared keys_dir, but
        // id_ecdsa.pub lives in the per-test tempdir HOME and is gone
        // after each run. Rehydrate it from the enclave so the
        // assertions below can verify the content.
        let exported = run(env
            .sshenc_cmd()
            .expect("sshenc cmd")
            .arg("export-pub")
            .arg("default"))
        .expect("sshenc export-pub default");
        assert!(
            exported.succeeded(),
            "sshenc export-pub default failed; stderr:\n{}",
            exported.stderr
        );
        std::fs::create_dir_all(env.ssh_dir()).expect("mkdir ssh");
        std::fs::write(&id_ecdsa_pub, exported.stdout.trim().as_bytes())
            .expect("write id_ecdsa.pub");
    }

    // After promotion `id_ecdsa.pub` must exist and list a single key line.
    let pub_text = std::fs::read_to_string(&id_ecdsa_pub)
        .unwrap_or_else(|e| panic!("read {}: {e}", id_ecdsa_pub.display()));
    let default_line = pub_text.trim().to_string();
    assert!(
        default_line.starts_with("ecdsa-sha2-nistp256 "),
        "id_ecdsa.pub doesn't look like an ECDSA P-256 key: {pub_text}"
    );

    // Confirm export-pub default matches what's in the file.
    let exported = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .arg("export-pub")
        .arg("default"))
    .expect("sshenc export-pub default");
    assert!(
        exported.succeeded(),
        "sshenc export-pub default failed; stderr:\n{}",
        exported.stderr
    );
    assert_eq!(
        exported.stdout.trim(),
        default_line,
        "id_ecdsa.pub content doesn't match sshenc export-pub default"
    );

    // Authenticate through the agent using the default-labeled key.
    env.start_agent().expect("agent start");
    let container = SshdContainer::start(&[&default_line]).expect("container");
    let outcome = run(&mut build_labeled_ssh(&env, &container, "default")).expect("ssh default");
    assert!(
        outcome.succeeded(),
        "ssh --label default should succeed after promotion; stderr:\n{}",
        outcome.stderr
    );
}

fn build_labeled_ssh(
    env: &SshencEnv,
    container: &SshdContainer,
    label: &str,
) -> std::process::Command {
    let mut cmd = env.sshenc_cmd().expect("sshenc cmd");
    cmd.arg("ssh").arg("--label").arg(label).arg("--");
    SshencEnv::apply_ssh_isolation(&mut cmd, container.host_port, &env.known_hosts());
    cmd.arg("sshtest@127.0.0.1").arg("true");
    cmd
}
