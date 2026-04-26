// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Three more contracts:
//!
//! 1. Agent rejects an oversized request frame (> 256 KB) without
//!    crashing. The frame-length cap exists in `server.rs` and
//!    `wire.rs`; ssh_add_unsupported_ops covers unknown opcodes
//!    on a normally-sized frame, but not "frame length itself out
//!    of bounds." The agent must close the connection and keep
//!    serving.
//!
//! 2. Agent rejects a zero-length frame the same way.
//!
//! 3. `sshenc-keygen --require-user-presence` (the standalone
//!    binary) persists `access_policy: "any"` in the meta file,
//!    matching `sshenc keygen --require-user-presence` (covered
//!    by keygen_up_and_agent_labels.rs). Verifies the same flag
//!    behaves identically across both keygen entry points.
//!
//! 4. `sshenc-agent --config <malformed-toml>` exits non-zero with
//!    a useful error message rather than panicking. Pins the user-
//!    facing diagnostic for "your config file is broken".

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{
    docker_skip_reason, extended_enabled, persistent_keys_dir, run, shared_enclave_pubkey,
    software_mode, workspace_bin, SshencEnv,
};
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::process::Stdio;
use std::time::Duration;

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

fn assert_alive(env: &SshencEnv, after: &str) {
    let listed = run(env
        .scrubbed_command("ssh-add")
        .env("SSH_AUTH_SOCK", env.socket_path())
        .arg("-L"))
    .expect("ssh-add -L");
    assert!(
        listed.succeeded(),
        "agent should still answer after {after}; stderr:\n{}",
        listed.stderr
    );
}

/// A request frame whose declared length exceeds the agent's
/// 256 KB cap must be rejected without crashing. We send a
/// length prefix of 256 KB + 1 byte; the agent should close the
/// connection. Subsequent ssh-add -L must still succeed.
#[test]
#[ignore = "requires docker"]
fn agent_rejects_oversized_frame_length() {
    if skip_if_no_docker("agent_rejects_oversized_frame_length") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("warm shared key"));
    env.start_agent().expect("start agent");

    // 4-byte BE length prefix for 256*1024 + 1.
    let oversized = (256_u32 * 1024 + 1).to_be_bytes();
    let mut stream = UnixStream::connect(env.socket_path()).expect("connect agent");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set timeout");
    let _ignored = stream.write_all(&oversized);
    drop(stream);

    assert_alive(&env, "oversized frame");
}

/// A zero-length frame is malformed (the opcode byte is missing).
/// Agent must reject and stay up.
#[test]
#[ignore = "requires docker"]
fn agent_rejects_zero_length_frame() {
    if skip_if_no_docker("agent_rejects_zero_length_frame") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("warm shared key"));
    env.start_agent().expect("start agent");

    let mut stream = UnixStream::connect(env.socket_path()).expect("connect agent");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set timeout");
    let _ignored = stream.write_all(&[0_u8; 4]);
    drop(stream);

    assert_alive(&env, "zero-length frame");
}

/// `sshenc-keygen --require-user-presence` (standalone binary)
/// must persist `access_policy: "any"` in the meta file, matching
/// the umbrella CLI's behavior covered by
/// keygen_up_and_agent_labels.rs. The two binaries should agree
/// on policy semantics.
#[test]
#[ignore = "requires docker"]
fn sshenc_keygen_bin_require_user_presence_persists_access_policy_any() {
    if skip_if_no_docker("sshenc_keygen_bin_require_user_presence_persists_access_policy_any") {
        return;
    }
    if skip_unless_key_creation_cheap(
        "sshenc_keygen_bin_require_user_presence_persists_access_policy_any",
    ) {
        return;
    }
    let env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("warm shared key"));

    let label = format!(
        "kgbin-up-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
    );
    let kg_bin = workspace_bin("sshenc-keygen").expect("sshenc-keygen binary");
    let kg = run(env
        .scrubbed_command(&kg_bin)
        .arg("--label")
        .arg(&label)
        .arg("--no-pub-file")
        .arg("--require-user-presence")
        .arg("--quiet"))
    .expect("sshenc-keygen --require-user-presence");
    assert!(
        kg.succeeded(),
        "sshenc-keygen --require-user-presence failed; stdout:\n{}\nstderr:\n{}",
        kg.stdout,
        kg.stderr
    );

    let meta_path = persistent_keys_dir().join(format!("{label}.meta"));
    let meta = std::fs::read_to_string(&meta_path).expect("read meta");
    let parsed: serde_json::Value = serde_json::from_str(&meta).expect("meta is JSON");
    assert_eq!(
        parsed.get("access_policy").and_then(|v| v.as_str()),
        Some("any"),
        "expected access_policy=any from --require-user-presence; got: {meta}"
    );

    drop(run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["delete", &label, "-y"])));
}

/// `sshenc-agent --foreground --config <malformed.toml>` exits
/// non-zero with a useful error rather than panicking. The user
/// experience contract: bad config = clear diagnostic, not a
/// stack trace.
#[test]
#[ignore = "requires docker"]
fn agent_with_malformed_config_emits_useful_error() {
    if skip_if_no_docker("agent_with_malformed_config_emits_useful_error") {
        return;
    }
    let env = SshencEnv::new().expect("env");

    let bad_config = env.home().join("malformed-config.toml");
    std::fs::write(
        &bad_config,
        b"this is not [valid TOML] = and = also = wrong\n",
    )
    .expect("write malformed");

    let bin = workspace_bin("sshenc-agent").expect("agent binary");
    let child = env
        .scrubbed_command(&bin)
        .arg("--foreground")
        .arg("--socket")
        .arg(env.socket_path())
        .arg("--config")
        .arg(&bad_config)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn agent with malformed config");

    let outcome = child.wait_with_output().expect("agent wait");
    assert!(
        !outcome.status.success(),
        "agent with malformed config should exit non-zero; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&outcome.stdout),
        String::from_utf8_lossy(&outcome.stderr)
    );
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&outcome.stdout),
        String::from_utf8_lossy(&outcome.stderr)
    );
    let lower = combined.to_lowercase();
    // The error should mention TOML / parse / config in some form
    // so a user knows where to look. We don't pin the exact
    // wording — that's a doc-level concern — but absence of all
    // three indicates a regression from "useful diagnostic".
    let useful = lower.contains("toml")
        || lower.contains("parse")
        || lower.contains("config")
        || lower.contains("invalid");
    assert!(
        useful,
        "agent error message should mention toml/parse/config/invalid; got:\n{combined}"
    );
}
