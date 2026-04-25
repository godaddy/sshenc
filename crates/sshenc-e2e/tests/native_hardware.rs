// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Native-hardware-backed e2e scenarios.
//!
//! All other e2e tests are designed to pass in software mode
//! (`SSHENC_E2E_SOFTWARE=1`) so CI can run them on cloud runners
//! without keychain prompts. This file is the opposite: tests that
//! **only** run when real hardware is available (Secure Enclave on
//! macOS, TPM 2.0 on Windows). On Linux, in software mode, or when
//! the platform's hardware isn't usable, every test in this file
//! skips gracefully with a logged reason.
//!
//! What the tests verify, beyond the software-mode invariants:
//!
//! - The keys_dir actually contains hardware-backed key handles
//!   (`.handle` files), not software keys (`.key` files). This is
//!   the on-disk fingerprint of "the agent really used hardware".
//! - Sign produces a signature that real `ssh-keygen -Y verify`
//!   accepts — same chain we exercise in software mode, but
//!   driven by the hardware signer this time.
//! - The hardware-backed key persists across an agent restart:
//!   handle files survive on disk, the new agent picks them up,
//!   and signing still works without re-creating the key.
//! - Reuses the persistent `e2e-shared` label and persistent keys
//!   dir so this file does NOT add fresh macOS keychain prompts —
//!   it shares the same one-key budget as the rest of the suite.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{
    docker_skip_reason, persistent_keys_dir, run, shared_enclave_pubkey, software_mode, SshencEnv,
    SHARED_ENCLAVE_LABEL,
};
use std::io::Write;
use std::path::Path;
use std::process::Stdio;

/// Reasons we'd skip a hardware test, in priority order.
fn hardware_skip_reason() -> Option<&'static str> {
    if software_mode() {
        return Some("SSHENC_E2E_SOFTWARE=1 forces software mode; native hardware tests skipped");
    }
    if !cfg!(any(target_os = "macos", target_os = "windows")) {
        return Some("Linux has no hardware backend; native hardware tests skipped");
    }
    None
}

fn skip_if_no_docker(test_name: &str) -> bool {
    if let Some(reason) = docker_skip_reason() {
        eprintln!("skip {test_name}: {reason}");
        return true;
    }
    false
}

fn skip_unless_native_hardware(test_name: &str) -> bool {
    if let Some(reason) = hardware_skip_reason() {
        eprintln!("skip {test_name}: {reason}");
        return true;
    }
    false
}

const PRINCIPAL: &str = "signer@native-hw.test";

/// Seed allowed_signers with the shared enclave key so
/// `ssh-keygen -Y verify` accepts our sigs.
fn write_allowed_signers(env: &SshencEnv, enclave_pub: &str) -> std::path::PathBuf {
    let allowed = env.ssh_dir().join("allowed_signers");
    std::fs::create_dir_all(env.ssh_dir()).expect("mkdir ssh dir");
    std::fs::write(&allowed, format!("{PRINCIPAL} {enclave_pub}\n"))
        .expect("write allowed_signers");
    allowed
}

fn write_pub(env: &SshencEnv, enclave_pub: &str) -> std::path::PathBuf {
    let pub_path = env.ssh_dir().join(format!("{SHARED_ENCLAVE_LABEL}.pub"));
    std::fs::create_dir_all(env.ssh_dir()).expect("mkdir ssh dir");
    std::fs::write(&pub_path, format!("{enclave_pub}\n")).expect("write pub");
    pub_path
}

fn ssh_sign_via_cli(
    env: &SshencEnv,
    pub_path: &Path,
    data: &Path,
    namespace: &str,
) -> sshenc_e2e::RunOutcome {
    run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .arg("-Y")
        .arg("sign")
        .arg("-n")
        .arg(namespace)
        .arg("-f")
        .arg(pub_path)
        .arg(data))
    .expect("sshenc -Y sign")
}

fn ssh_keygen_verify(
    env: &SshencEnv,
    allowed: &Path,
    namespace: &str,
    sig: &Path,
    data: &Path,
) -> bool {
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
        .arg(namespace)
        .arg("-s")
        .arg(sig)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ssh-keygen verify");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        stdin.write_all(&data_bytes).expect("write data");
    }
    child.wait().expect("ssh-keygen wait").success()
}

/// Native-hardware mode produces `.handle` files in the keys_dir
/// (not `.key`). The persistent keys_dir leaf is `keys`, not
/// `keys-sw`. Together these two on-disk fingerprints prove the
/// hardware backend was actually used to create the shared key.
#[test]
#[ignore = "requires native hardware (skipped in software mode and on Linux)"]
fn native_hardware_persistent_dir_uses_handle_files() {
    if skip_if_no_docker("native_hardware_persistent_dir_uses_handle_files") {
        return;
    }
    if skip_unless_native_hardware("native_hardware_persistent_dir_uses_handle_files") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared enclave (creates handle on first use)"));

    let keys_dir = persistent_keys_dir();
    assert!(
        keys_dir.ends_with("keys"),
        "hardware-mode persistent dir should be `.sshenc-e2e/keys`, got: {}",
        keys_dir.display()
    );

    let entries: Vec<std::path::PathBuf> = std::fs::read_dir(&keys_dir)
        .expect("read keys_dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    let has_handle = entries
        .iter()
        .any(|p| p.extension().is_some_and(|e| e == "handle"));
    let has_key = entries
        .iter()
        .any(|p| p.extension().is_some_and(|e| e == "key"));
    assert!(
        has_handle,
        "hardware mode should emit a .handle file; entries: {entries:?}"
    );
    assert!(
        !has_key,
        "hardware mode keys_dir must NOT contain .key files (those are software-only); entries: {entries:?}"
    );
}

/// Hardware-backed sign + ssh-keygen verify round-trip. Uses the
/// shared persistent key, so this is "the macOS Secure Enclave (or
/// Windows TPM 2.0) actually produced a signature that real
/// ssh-keygen accepts" — the strongest end-to-end proof of the
/// hardware path.
#[test]
#[ignore = "requires native hardware"]
fn native_hardware_sign_and_ssh_keygen_verify() {
    if skip_if_no_docker("native_hardware_sign_and_ssh_keygen_verify") {
        return;
    }
    if skip_unless_native_hardware("native_hardware_sign_and_ssh_keygen_verify") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");

    let pub_path = write_pub(&env, &enclave);
    let allowed = write_allowed_signers(&env, &enclave);
    let data = env.home().join("hw-sign.txt");
    std::fs::write(&data, b"hardware-signed payload\n").expect("write data");

    let sign = ssh_sign_via_cli(&env, &pub_path, &data, "git");
    assert!(
        sign.succeeded(),
        "hardware sign failed; stderr:\n{}",
        sign.stderr
    );
    let sig = data.with_extension("txt.sig");
    assert!(sig.exists(), "sigfile missing after hardware sign");
    assert!(
        ssh_keygen_verify(&env, &allowed, "git", &sig, &data),
        "ssh-keygen verify failed on hardware-produced sig"
    );
}

/// The hardware-backed key handle persists across an agent restart:
/// after stopping the agent, the next agent re-discovers the same
/// key from disk and exposes it via the SSH agent protocol again.
/// Without this, the agent auto-respawn path elsewhere wouldn't be
/// useful in practice — the user would lose their key on every
/// restart.
///
/// Scope note: only enumeration is checked across the restart, not
/// signing. A post-restart sign on macOS may need to re-unlock the
/// keychain wrapping key, which is a hardware-prompt-driven path
/// outside the scope of this on-disk persistence invariant. The
/// `native_hardware_sign_and_ssh_keygen_verify` test covers signing
/// directly against the persisted key with a freshly-warmed agent.
#[test]
#[ignore = "requires native hardware"]
fn native_hardware_key_persists_across_agent_restart() {
    if skip_if_no_docker("native_hardware_key_persists_across_agent_restart") {
        return;
    }
    if skip_unless_native_hardware("native_hardware_key_persists_across_agent_restart") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    let key_body = enclave
        .split_whitespace()
        .nth(1)
        .expect("enclave key body")
        .to_string();

    // First agent: ensure the shared key is visible.
    env.start_agent().expect("start agent (first)");
    let listed = run(env
        .scrubbed_command("ssh-add")
        .env("SSH_AUTH_SOCK", env.socket_path())
        .arg("-L"))
    .expect("ssh-add -L (first)");
    assert!(listed.succeeded(), "first ssh-add -L: {}", listed.stderr);
    assert!(
        listed.stdout.contains(&key_body),
        "shared enclave key not visible to first agent; got:\n{}",
        listed.stdout
    );

    // Stop and restart.
    env.stop_agent();
    // Allow the OS a moment to release the socket file before the
    // second agent claims the same path.
    std::thread::sleep(std::time::Duration::from_millis(100));
    env.start_agent().expect("start agent (second)");

    let listed_again = run(env
        .scrubbed_command("ssh-add")
        .env("SSH_AUTH_SOCK", env.socket_path())
        .arg("-L"))
    .expect("ssh-add -L (second)");
    assert!(
        listed_again.succeeded(),
        "second ssh-add -L: {}",
        listed_again.stderr
    );
    assert!(
        listed_again.stdout.contains(&key_body),
        "key disappeared across agent restart in hardware mode; got:\n{}",
        listed_again.stdout
    );
}

/// `sshenc list --json` against a hardware-backed key returns at
/// least one entry whose label matches the shared enclave label.
/// This catches regressions where the read-side `AgentProxyBackend`
/// fails to enumerate the persisted hardware key without the
/// agent's help.
#[test]
#[ignore = "requires native hardware"]
fn native_hardware_list_finds_persisted_key() {
    if skip_if_no_docker("native_hardware_list_finds_persisted_key") {
        return;
    }
    if skip_unless_native_hardware("native_hardware_list_finds_persisted_key") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared enclave"));

    let listed = run(env.sshenc_cmd().expect("sshenc").args(["list", "--json"]))
        .expect("sshenc list --json");
    assert!(
        listed.succeeded(),
        "sshenc list --json failed; stderr:\n{}",
        listed.stderr
    );
    assert!(
        listed.stdout.contains(SHARED_ENCLAVE_LABEL),
        "list should include shared enclave label {SHARED_ENCLAVE_LABEL}; got:\n{}",
        listed.stdout
    );
}
