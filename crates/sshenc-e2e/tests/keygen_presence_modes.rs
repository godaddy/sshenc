// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Pin the keygen `presence_mode` matrix introduced when sshenc
//! switched its default to user-presence-required-cached.
//!
//! Three modes, three flag combinations, three `.meta` shapes:
//!
//! | Flags                    | `access_policy` | `app_specific.presence_mode` |
//! |--------------------------|-----------------|------------------------------|
//! | (none — default)         | `"any"`         | `"cached"`                   |
//! | `--strict`               | `"any"`         | `"strict"`                   |
//! | `--no-user-presence`     | `"none"`        | `"none"`                     |
//!
//! The legacy `--require-user-presence` flag is preserved as a
//! deprecated alias for `--strict`; the deprecation warning goes to
//! stderr and the resulting `.meta` is identical to `--strict`'s.
//!
//! These tests cover *only* the on-disk `.meta` shape. Verifying the
//! prompt cadence (one prompt per cache-TTL window vs. one per sign)
//! requires real Secure Enclave hardware and is exercised manually
//! against macOS — see `docs/macos-unsigned-ux.md`.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{
    docker_skip_reason, extended_enabled, persistent_keys_dir, run, shared_enclave_pubkey,
    software_mode, SshencEnv,
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

fn read_meta(label: &str) -> serde_json::Value {
    let meta_path = persistent_keys_dir().join(format!("{label}.meta"));
    let raw = std::fs::read_to_string(&meta_path).expect("read meta");
    serde_json::from_str(&raw).expect("meta is JSON")
}

fn presence_mode_field(meta: &serde_json::Value) -> Option<&str> {
    meta.get("app_specific")
        .and_then(|a| a.get("presence_mode"))
        .and_then(|v| v.as_str())
}

fn delete(env: &SshencEnv, label: &str) {
    drop(run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["delete", label, "-y"])));
}

/// `sshenc keygen --label X` (no presence flag) is the new default
/// and writes `access_policy=any` + `presence_mode=cached`. Captures
/// the breaking change away from the historical "no presence by
/// default" behaviour.
#[test]
#[ignore = "requires docker"]
fn keygen_default_writes_cached_user_presence() {
    let test_name = "keygen_default_writes_cached_user_presence";
    if skip_if_no_docker(test_name) {
        return;
    }
    if skip_unless_key_creation_cheap(test_name) {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("warm shared key"));
    env.start_agent().expect("start agent");

    let label = unique_label("presence-default");
    let kg =
        run(env
            .sshenc_cmd()
            .expect("sshenc")
            .args(["keygen", "--label", &label, "--no-pub-file"]))
        .expect("sshenc keygen");
    assert!(kg.succeeded(), "keygen failed: {}", kg.stderr);

    let meta = read_meta(&label);
    assert_eq!(
        meta.get("access_policy").and_then(|v| v.as_str()),
        Some("any"),
        "default keygen should record access_policy=any; got: {meta}"
    );
    assert_eq!(
        presence_mode_field(&meta),
        Some("cached"),
        "default keygen should record presence_mode=cached; got: {meta}"
    );

    delete(&env, &label);
}

/// `--strict` writes `access_policy=any` + `presence_mode=strict`,
/// signalling the agent that every signature must trigger a fresh
/// SEP user-presence check (no LAContext reuse).
#[test]
#[ignore = "requires docker"]
fn keygen_strict_writes_strict_presence_mode() {
    let test_name = "keygen_strict_writes_strict_presence_mode";
    if skip_if_no_docker(test_name) {
        return;
    }
    if skip_unless_key_creation_cheap(test_name) {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("warm shared key"));
    env.start_agent().expect("start agent");

    let label = unique_label("presence-strict");
    let kg = run(env.sshenc_cmd().expect("sshenc").args([
        "keygen",
        "--label",
        &label,
        "--strict",
        "--no-pub-file",
    ]))
    .expect("sshenc keygen");
    assert!(kg.succeeded(), "keygen --strict failed: {}", kg.stderr);

    let meta = read_meta(&label);
    assert_eq!(
        meta.get("access_policy").and_then(|v| v.as_str()),
        Some("any"),
        "--strict should record access_policy=any; got: {meta}"
    );
    assert_eq!(
        presence_mode_field(&meta),
        Some("strict"),
        "--strict should record presence_mode=strict; got: {meta}"
    );

    delete(&env, &label);
}

/// `--no-user-presence` opts out entirely: `access_policy=none` +
/// `presence_mode=none`. The key signs silently with no prompt.
#[test]
#[ignore = "requires docker"]
fn keygen_no_user_presence_writes_none() {
    let test_name = "keygen_no_user_presence_writes_none";
    if skip_if_no_docker(test_name) {
        return;
    }
    if skip_unless_key_creation_cheap(test_name) {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("warm shared key"));
    env.start_agent().expect("start agent");

    let label = unique_label("presence-none");
    let kg = run(env.sshenc_cmd().expect("sshenc").args([
        "keygen",
        "--label",
        &label,
        "--no-user-presence",
        "--no-pub-file",
    ]))
    .expect("sshenc keygen");
    assert!(
        kg.succeeded(),
        "keygen --no-user-presence failed: {}",
        kg.stderr
    );

    let meta = read_meta(&label);
    assert_eq!(
        meta.get("access_policy").and_then(|v| v.as_str()),
        Some("none"),
        "--no-user-presence should record access_policy=none; got: {meta}"
    );
    assert_eq!(
        presence_mode_field(&meta),
        Some("none"),
        "--no-user-presence should record presence_mode=none; got: {meta}"
    );

    delete(&env, &label);
}

/// The legacy `--require-user-presence` flag remains a deprecated
/// alias for `--strict`: the resulting `.meta` matches `--strict`'s
/// (`access_policy=any`, `presence_mode=strict`) and the deprecation
/// warning surfaces on stderr so script authors notice they should
/// migrate.
#[test]
#[ignore = "requires docker"]
fn keygen_require_user_presence_aliases_strict_with_deprecation_warning() {
    let test_name = "keygen_require_user_presence_aliases_strict_with_deprecation_warning";
    if skip_if_no_docker(test_name) {
        return;
    }
    if skip_unless_key_creation_cheap(test_name) {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("warm shared key"));
    env.start_agent().expect("start agent");

    let label = unique_label("presence-legacy");
    let kg = run(env.sshenc_cmd().expect("sshenc").args([
        "keygen",
        "--label",
        &label,
        "--require-user-presence",
        "--no-pub-file",
    ]))
    .expect("sshenc keygen");
    assert!(
        kg.succeeded(),
        "keygen --require-user-presence failed: {}",
        kg.stderr
    );
    assert!(
        kg.stderr.contains("--require-user-presence is deprecated"),
        "expected deprecation warning on stderr; got: {}",
        kg.stderr
    );

    let meta = read_meta(&label);
    assert_eq!(
        meta.get("access_policy").and_then(|v| v.as_str()),
        Some("any"),
        "--require-user-presence should record access_policy=any; got: {meta}"
    );
    assert_eq!(
        presence_mode_field(&meta),
        Some("strict"),
        "--require-user-presence should alias to presence_mode=strict; got: {meta}"
    );

    delete(&env, &label);
}
