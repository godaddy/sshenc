// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Wrapping-key cache TTL runtime behavior.
//!
//! `config_variations.rs` already verifies that
//! `wrapping_key_cache_ttl_secs` *parses* and the agent loads with
//! various values. These tests verify the **runtime** consequences:
//!
//! - With TTL = 0 (cache disabled), repeated signs all succeed —
//!   the disable-cache path doesn't break anything.
//! - With TTL = 1 (very short), a sign followed by a 2-second
//!   sleep + another sign both succeed — the cache eviction +
//!   re-acquire path doesn't break anything.
//! - The env-var override (`SSHENC_WRAPPING_KEY_CACHE_TTL_SECS`)
//!   takes precedence over `config.toml`. The agent's main.rs
//!   documents this precedence; without a runtime test, a
//!   regression in the precedence ordering would silently swap
//!   "fast cached" for "slow uncached" or vice versa.
//!
//! Tests run in software mode too (the cache is a no-op
//! optimization there since there's no keychain wrapping key) —
//! they still exercise the eviction code path.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{docker_skip_reason, run, shared_enclave_pubkey, SshencEnv, SHARED_ENCLAVE_LABEL};
use std::io::Write;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

fn skip_if_no_docker(test_name: &str) -> bool {
    if let Some(reason) = docker_skip_reason() {
        eprintln!("skip {test_name}: {reason}");
        return true;
    }
    false
}

const PRINCIPAL: &str = "signer@cache-ttl.test";

fn write_pub(env: &SshencEnv, enclave_pub: &str) -> std::path::PathBuf {
    let pub_path = env.ssh_dir().join(format!("{SHARED_ENCLAVE_LABEL}.pub"));
    std::fs::create_dir_all(env.ssh_dir()).expect("mkdir ssh dir");
    std::fs::write(&pub_path, format!("{enclave_pub}\n")).expect("write pub");
    pub_path
}

fn write_allowed_signers(env: &SshencEnv, enclave_pub: &str) -> std::path::PathBuf {
    let allowed = env.ssh_dir().join("allowed_signers");
    std::fs::write(&allowed, format!("{PRINCIPAL} {enclave_pub}\n"))
        .expect("write allowed_signers");
    allowed
}

fn write_config(env: &SshencEnv, body: &str) -> std::path::PathBuf {
    let path = env.home().join("sshenc-config.toml");
    let header = format!(
        "socket_path = \"{sock}\"\npub_dir = \"{pub_dir}\"\n",
        sock = env.socket_path().display(),
        pub_dir = env.ssh_dir().display(),
    );
    std::fs::write(&path, format!("{header}{body}")).expect("write config");
    path
}

fn ssh_sign(env: &SshencEnv, pub_path: &Path, data: &Path) -> sshenc_e2e::RunOutcome {
    run(env
        .sshenc_cmd()
        .expect("sshenc")
        .arg("-Y")
        .arg("sign")
        .arg("-n")
        .arg("git")
        .arg("-f")
        .arg(pub_path)
        .arg(data))
    .expect("sshenc -Y sign")
}

fn ssh_keygen_verify(env: &SshencEnv, allowed: &Path, sig: &Path, data: &Path) -> bool {
    let data_bytes = std::fs::read(data).expect("read data");
    let mut child = env
        .scrubbed_command("ssh-keygen")
        .arg("-Y")
        .arg("verify")
        .arg("-f")
        .arg(allowed)
        .arg("-I")
        .arg(PRINCIPAL)
        .arg("-n")
        .arg("git")
        .arg("-s")
        .arg(sig)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ssh-keygen");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        stdin.write_all(&data_bytes).expect("write data");
    }
    child.wait().expect("ssh-keygen wait").success()
}

/// Sign + verify, returning whether the round-trip succeeded.
/// Each call uses a unique data filename so pre-existing sigs
/// don't poison the test.
fn sign_and_verify_round(env: &SshencEnv, pub_path: &Path, allowed: &Path, name: &str) -> bool {
    let data = env.home().join(format!("{name}.txt"));
    std::fs::write(&data, format!("payload {name}\n").as_bytes()).expect("write data");
    let sign = ssh_sign(env, pub_path, &data);
    if !sign.succeeded() {
        eprintln!("sign failed: {}", sign.stderr);
        return false;
    }
    let sig = data.with_extension("txt.sig");
    if !sig.exists() {
        eprintln!("sigfile missing");
        return false;
    }
    ssh_keygen_verify(env, allowed, &sig, &data)
}

/// TTL=0 disables the wrapping-key cache (every sign re-acquires).
/// Repeated signs must all succeed — the no-cache path is the
/// extreme case of "every operation evicts before it runs".
#[test]
#[ignore = "requires docker"]
fn agent_with_zero_ttl_signs_repeatedly() {
    if skip_if_no_docker("agent_with_zero_ttl_signs_repeatedly") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");

    let config = write_config(&env, "wrapping_key_cache_ttl_secs = 0\n");
    env.start_agent_with_config(Some(&config))
        .expect("start agent (ttl=0)");

    let pub_path = write_pub(&env, &enclave);
    let allowed = write_allowed_signers(&env, &enclave);

    // Three back-to-back signs. With TTL=0 every one re-acquires
    // the wrapping key (in software mode this is a no-op; in
    // hardware mode this would re-prompt unless the keychain ACL
    // grants Always Allow).
    for round in 0..3 {
        assert!(
            sign_and_verify_round(&env, &pub_path, &allowed, &format!("ttl0-{round}")),
            "round {round} failed under ttl=0"
        );
    }
}

/// TTL=1 (1 second) — sign, sleep past TTL, sign again. Both must
/// succeed. Exercises the cache-evict-then-re-acquire path under
/// realistic timing instead of just "TTL value flowed to the
/// agent".
#[test]
#[ignore = "requires docker"]
fn agent_signs_after_cache_ttl_eviction_window() {
    if skip_if_no_docker("agent_signs_after_cache_ttl_eviction_window") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");

    let config = write_config(&env, "wrapping_key_cache_ttl_secs = 1\n");
    env.start_agent_with_config(Some(&config))
        .expect("start agent (ttl=1)");

    let pub_path = write_pub(&env, &enclave);
    let allowed = write_allowed_signers(&env, &enclave);

    assert!(
        sign_and_verify_round(&env, &pub_path, &allowed, "before-eviction"),
        "first sign (cache populated) failed"
    );
    // Sleep past the 1-second TTL so the cached wrapping key is
    // evicted on the next access.
    std::thread::sleep(Duration::from_millis(1500));
    assert!(
        sign_and_verify_round(&env, &pub_path, &allowed, "after-eviction"),
        "second sign (after cache eviction) failed"
    );
}

/// `SSHENC_WRAPPING_KEY_CACHE_TTL_SECS` env-var must take
/// precedence over `config.toml`. We can't directly observe which
/// TTL the agent is using (it's an internal cache parameter with
/// no on-the-wire signal), so this test verifies the precedence
/// path indirectly: spawn an agent with config saying 600s AND env
/// saying 0s — the agent must boot cleanly and continue serving.
/// A regression that, say, dereferenced None or panicked on the
/// override path would surface as a failed start or a hung sign.
#[test]
#[ignore = "requires docker"]
fn env_override_for_cache_ttl_does_not_break_agent() {
    if skip_if_no_docker("env_override_for_cache_ttl_does_not_break_agent") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");

    // Config says 600s; env will say 0s. Spawn the agent
    // ourselves (bypassing SshencEnv::start_agent_with_config) so
    // we can inject the env var into the child without touching
    // the parent process's environment.
    let config = write_config(&env, "wrapping_key_cache_ttl_secs = 600\n");
    let bin = sshenc_e2e::workspace_bin("sshenc-agent").expect("agent binary");
    let socket = env.socket_path();
    let mut cmd = env.scrubbed_command(&bin);
    cmd.env("SSHENC_WRAPPING_KEY_CACHE_TTL_SECS", "0")
        .arg("--foreground")
        .arg("--socket")
        .arg(&socket)
        .arg("--config")
        .arg(&config)
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn sshenc-agent");

    // Wait for the socket; if the override path is broken, the
    // agent never gets here.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        if std::os::unix::net::UnixStream::connect(&socket).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        std::os::unix::net::UnixStream::connect(&socket).is_ok(),
        "agent did not come up with env-override TTL"
    );

    let pub_path = write_pub(&env, &enclave);
    let allowed = write_allowed_signers(&env, &enclave);
    let signed = sign_and_verify_round(&env, &pub_path, &allowed, "env-override");

    // Always tear the agent down even if the assertion below fails.
    drop(child.kill());
    drop(child.wait());
    drop(enclave); // Suppress unused-binding lint after the SE handle outlives the agent.

    assert!(signed, "sign failed with env-override TTL");
}
