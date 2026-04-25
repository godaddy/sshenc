// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! sshenc agent config file variations.
//!
//! The existing suite (`lifecycle.rs::agent_allowed_labels_filters_identities`)
//! already exercises one full config.toml path — socket_path, pub_dir,
//! `allowed_labels`, `prompt_policy = "never"`. This file covers the
//! remaining surfaces of `crates/sshenc-core/src/config.rs`:
//!
//! - `prompt_policy = "always"` and `"keydefault"` load cleanly and
//!   the agent serves identities (companion to `"never"` above)
//! - `wrapping_key_cache_ttl_secs = 0` (cache disabled) and a large
//!   value (long cache) load cleanly and the agent serves identities
//! - unknown fields in config.toml are silently ignored (serde(default)
//!   forward-compat — a new sshenc adds a field; older agents on the
//!   same config must still start)
//! - invalid `prompt_policy` values cause the agent to exit non-zero
//!   before opening the socket
//! - malformed TOML syntax causes the agent to exit non-zero
//!
//! All tests are `#[ignore]` and run only under `--ignored`. They
//! operate on the shared enclave key and a per-test socket so they
//! can run in parallel with the rest of the suite.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{docker_skip_reason, shared_enclave_pubkey, SshencEnv};
use std::io::Read;
use std::path::Path;
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

fn skip_if_no_docker(test_name: &str) -> bool {
    if let Some(reason) = docker_skip_reason() {
        eprintln!("skip {test_name}: {reason}");
        return true;
    }
    false
}

/// Write a minimal config.toml with the given body appended to a
/// standard header pinning socket_path and pub_dir to the tempdir.
fn write_config(env: &SshencEnv, body: &str) -> std::path::PathBuf {
    let path = env.home().join("sshenc-config.toml");
    let header = format!(
        "socket_path = \"{sock}\"\n\
         pub_dir = \"{pub_dir}\"\n",
        sock = env.socket_path().display(),
        pub_dir = env.ssh_dir().display(),
    );
    std::fs::write(&path, format!("{header}{body}")).expect("write config");
    path
}

/// Start the agent with the given config, verify identities are
/// enumerable via ssh-add -L (checks the whole load → open socket →
/// handle request chain works). Used for positive-path tests.
fn assert_agent_serves_with_config(env: &mut SshencEnv, config_body: &str) {
    let config = write_config(env, config_body);
    env.start_agent_with_config(Some(&config))
        .expect("agent start with config");

    let listed = sshenc_e2e::run(
        env.scrubbed_command("ssh-add")
            .env("SSH_AUTH_SOCK", env.socket_path())
            .arg("-L"),
    )
    .expect("ssh-add -L");
    assert!(
        listed.succeeded(),
        "ssh-add -L against agent failed; stderr:\n{}",
        listed.stderr
    );
    // ssh-add -L prints nothing (but still exits 0 here) if there
    // are zero identities; our config doesn't filter, so the shared
    // key should be visible.
    assert!(
        listed.stdout.contains("ecdsa-sha2-nistp256"),
        "expected shared enclave key in ssh-add -L output; got:\n{}",
        listed.stdout
    );
}

/// Spawn the agent directly without waiting for socket readiness,
/// for negative-path tests that expect early exit. Returns the child
/// so the caller can poll and verify exit status + stderr.
fn spawn_agent_expected_to_fail(env: &SshencEnv, config_path: &Path) -> Child {
    env.scrubbed_command("sshenc-agent")
        .arg("--foreground")
        .arg("--socket")
        .arg(env.socket_path())
        .arg("--config")
        .arg(config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sshenc-agent")
}

/// Poll `child.try_wait()` until it reports an exit, or bail after
/// `timeout`. Returns the exit status plus the stderr captured so
/// far. Kills the child on timeout.
fn wait_for_exit(mut child: Child, timeout: Duration) -> (std::process::ExitStatus, String) {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stderr = String::new();
                if let Some(mut err) = child.stderr.take() {
                    drop(err.read_to_string(&mut stderr));
                }
                return (status, stderr);
            }
            Ok(None) if Instant::now() >= deadline => {
                drop(child.kill());
                drop(child.wait());
                panic!(
                    "sshenc-agent did not exit within {:?}; expected early exit on bad config",
                    timeout
                );
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(25)),
            Err(e) => panic!("try_wait: {e}"),
        }
    }
}

/// `prompt_policy = "always"` loads and agent serves. Software mode
/// doesn't exercise the actual UP prompt path, but we guarantee the
/// config parses and the agent starts — a regression in the
/// lowercase-serde tag for `Always` would fail here.
#[test]
#[ignore = "requires docker"]
fn agent_loads_config_with_prompt_policy_always() {
    if skip_if_no_docker("agent_loads_config_with_prompt_policy_always") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared enclave"));
    assert_agent_serves_with_config(&mut env, "prompt_policy = \"always\"\n");
}

/// `prompt_policy = "keydefault"` loads and agent serves. This is
/// the default variant; a regression where the default isn't parseable
/// back from its own serialized form would fail here.
#[test]
#[ignore = "requires docker"]
fn agent_loads_config_with_prompt_policy_keydefault() {
    if skip_if_no_docker("agent_loads_config_with_prompt_policy_keydefault") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared enclave"));
    assert_agent_serves_with_config(&mut env, "prompt_policy = \"keydefault\"\n");
}

/// `wrapping_key_cache_ttl_secs = 0` — cache disabled. In software
/// mode there's no wrapping-key prompt, so TTL has no observable
/// runtime effect, but the field must parse and flow through.
#[test]
#[ignore = "requires docker"]
fn agent_loads_config_with_wrapping_key_cache_ttl_zero() {
    if skip_if_no_docker("agent_loads_config_with_wrapping_key_cache_ttl_zero") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared enclave"));
    assert_agent_serves_with_config(&mut env, "wrapping_key_cache_ttl_secs = 0\n");
}

/// `wrapping_key_cache_ttl_secs = 3600` — 1-hour cache. Sanity-checks
/// that larger-than-default values are accepted and don't hit any
/// unintended clamp / overflow in the passthrough.
#[test]
#[ignore = "requires docker"]
fn agent_loads_config_with_wrapping_key_cache_ttl_large() {
    if skip_if_no_docker("agent_loads_config_with_wrapping_key_cache_ttl_large") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared enclave"));
    assert_agent_serves_with_config(&mut env, "wrapping_key_cache_ttl_secs = 3600\n");
}

/// Unknown TOML fields (both top-level and nested tables) are
/// silently ignored. Exercises the `#[serde(default)]` on `Config`
/// — future sshenc versions may add fields, and older agents
/// running on a newer config must still start.
#[test]
#[ignore = "requires docker"]
fn agent_tolerates_unknown_config_fields() {
    if skip_if_no_docker("agent_tolerates_unknown_config_fields") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared enclave"));
    assert_agent_serves_with_config(
        &mut env,
        "some_future_field = \"hello\"\n\
         another_unknown = 42\n\
         \n\
         [some_future_table]\n\
         key = \"value\"\n",
    );
}

/// An invalid `prompt_policy` value (e.g. `"bogus"`) must cause the
/// agent to exit non-zero before opening the socket. Guards against
/// the lowercase-serde tag silently falling back to a default on
/// typos.
#[test]
#[ignore = "requires docker"]
fn agent_rejects_invalid_prompt_policy_value() {
    if skip_if_no_docker("agent_rejects_invalid_prompt_policy_value") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let config = write_config(&env, "prompt_policy = \"bogus\"\n");

    let child = spawn_agent_expected_to_fail(&env, &config);
    let (status, stderr) = wait_for_exit(child, Duration::from_secs(5));
    assert!(
        !status.success(),
        "agent should exit non-zero on bad prompt_policy; stderr:\n{stderr}"
    );
    let msg = stderr.to_lowercase();
    assert!(
        msg.contains("prompt_policy") || msg.contains("bogus") || msg.contains("unknown variant"),
        "expected parse-error context in stderr; got:\n{stderr}"
    );
    // Socket must NOT have been created.
    assert!(
        !env.socket_path().exists(),
        "agent should not create socket when config is invalid; socket exists at {}",
        env.socket_path().display()
    );
}

/// Malformed TOML syntax (unterminated string) must cause the agent
/// to exit non-zero with a syntax error. Same invariant as the
/// invalid-value test but at the tokenizer level.
#[test]
#[ignore = "requires docker"]
fn agent_rejects_malformed_toml_syntax() {
    if skip_if_no_docker("agent_rejects_malformed_toml_syntax") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    // Bare value with a leading equals — not valid TOML.
    let config = write_config(&env, "= not valid toml\n");

    let child = spawn_agent_expected_to_fail(&env, &config);
    let (status, stderr) = wait_for_exit(child, Duration::from_secs(5));
    assert!(
        !status.success(),
        "agent should exit non-zero on malformed TOML; stderr:\n{stderr}"
    );
    assert!(
        !env.socket_path().exists(),
        "agent should not create socket when config is invalid; socket exists at {}",
        env.socket_path().display()
    );
}
