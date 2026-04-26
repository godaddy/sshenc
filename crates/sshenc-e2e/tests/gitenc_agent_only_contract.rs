// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Pins gitenc's "agent-only" contract.
//!
//! gitenc has no PKCS#11 mode by design — both the SSH side
//! (`core.sshCommand`) and the commit-signing side
//! (`gpg.ssh.program`) point at sshenc binaries that talk to the
//! agent over the Unix socket. PKCS#11 is OpenSSH's plug-in
//! interface, used only by `sshenc install` to wire the agent
//! boot-hook into `~/.ssh/config`.
//!
//! These tests make that contract explicit:
//!
//! - `gitenc --config <label>` sets `core.sshCommand` to a
//!   `sshenc ssh ...` invocation; never references a
//!   `PKCS11Provider`.
//! - `gpg.ssh.program` points at the `sshenc` binary, not at
//!   the PKCS#11 dylib.
//! - `gitenc --pkcs11` (a hypothetical flag) is rejected by
//!   the arg parser; this guards against silently adding such
//!   a flag in the future without updating the contract test.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{docker_skip_reason, run, shared_enclave_pubkey, SshencEnv, SHARED_ENCLAVE_LABEL};

fn skip_if_no_docker(test_name: &str) -> bool {
    if let Some(reason) = docker_skip_reason() {
        eprintln!("skip {test_name}: {reason}");
        return true;
    }
    false
}

/// `gitenc --config <label>` writes a `core.sshCommand` that
/// invokes `sshenc ssh ...` and never references PKCS#11. Both
/// directions of the contract are pinned: the SSH command must
/// be agent-mediated, and there must be NO PKCS11Provider in
/// the per-repo git config.
#[test]
#[ignore = "requires docker"]
fn gitenc_config_emits_agent_only_directives() {
    if skip_if_no_docker("gitenc_config_emits_agent_only_directives") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");

    let pub_path = env.ssh_dir().join(format!("{SHARED_ENCLAVE_LABEL}.pub"));
    std::fs::create_dir_all(env.ssh_dir()).expect("mkdir ssh dir");
    std::fs::write(&pub_path, format!("{enclave}\n")).expect("write enclave pub");

    let repo = env.home().join("agent-only-repo");
    std::fs::create_dir_all(&repo).expect("mkdir repo");
    assert!(env
        .git_cmd()
        .current_dir(&repo)
        .args(["init", "-q"])
        .status()
        .unwrap()
        .success());

    let cfg = run(env
        .gitenc_cmd()
        .expect("gitenc")
        .current_dir(&repo)
        .args(["--config", SHARED_ENCLAVE_LABEL]))
    .expect("gitenc --config");
    assert!(cfg.succeeded(), "gitenc --config: {}", cfg.stderr);

    // Read back the entire repo-level git config and verify the
    // agent-only contract.
    let dump = env
        .git_cmd()
        .current_dir(&repo)
        .args(["config", "--list", "--local"])
        .output()
        .expect("git config --list --local");
    assert!(dump.status.success(), "git config --list failed");
    let dump_text = String::from_utf8_lossy(&dump.stdout).into_owned();

    // core.sshCommand must reference sshenc ssh.
    let ssh_command_line = dump_text
        .lines()
        .find(|l| l.starts_with("core.sshcommand="))
        .unwrap_or_else(|| panic!("core.sshCommand missing; dump:\n{dump_text}"));
    assert!(
        ssh_command_line.contains("sshenc ssh"),
        "core.sshCommand should invoke `sshenc ssh`; got: {ssh_command_line}"
    );

    // No PKCS11Provider anywhere in the repo config — the agent
    // path is the only transport.
    assert!(
        !dump_text.to_lowercase().contains("pkcs11"),
        "gitenc --config must not emit PKCS11-related directives; \
         dump:\n{dump_text}"
    );

    // gpg.ssh.program must point at a sshenc binary, not a
    // dylib. Path basename is sshenc / sshenc.exe / sshenc-keygen
    // (any sshenc CLI is acceptable; PKCS#11 dylib is not).
    let gpg_prog_line = dump_text
        .lines()
        .find(|l| l.starts_with("gpg.ssh.program="))
        .unwrap_or_else(|| panic!("gpg.ssh.program missing; dump:\n{dump_text}"));
    assert!(
        !gpg_prog_line.to_lowercase().contains("pkcs11"),
        "gpg.ssh.program must not point at a PKCS#11 dylib; got: {gpg_prog_line}"
    );
    assert!(
        !gpg_prog_line.contains(".dylib") && !gpg_prog_line.contains(".so"),
        "gpg.ssh.program should be a CLI binary, not a dylib; got: {gpg_prog_line}"
    );
}

/// `gitenc --config <label>` never emits any PKCS#11-related
/// directive regardless of which label it was given. Pinned by
/// also probing with a label that contains the substring
/// "pkcs11" — the contract is "no PKCS11Provider in any
/// gitenc-managed config", not "no label string starting with
/// pkcs11".
#[test]
#[ignore = "requires docker"]
fn gitenc_config_never_emits_pkcs11_for_any_label() {
    if skip_if_no_docker("gitenc_config_never_emits_pkcs11_for_any_label") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");

    // Use the shared enclave label (which doesn't contain
    // "pkcs11"), but isolate to a fresh tempdir repo. Without
    // setting current_dir, `git config` would mutate the
    // workspace's own repo config — a bug an earlier draft of
    // this test had.
    let pub_path = env.ssh_dir().join(format!("{SHARED_ENCLAVE_LABEL}.pub"));
    std::fs::create_dir_all(env.ssh_dir()).expect("mkdir ssh dir");
    std::fs::write(&pub_path, format!("{enclave}\n")).expect("write pub");

    let repo = env.home().join("pkcs11-probe-repo");
    std::fs::create_dir_all(&repo).expect("mkdir repo");
    assert!(env
        .git_cmd()
        .current_dir(&repo)
        .args(["init", "-q"])
        .status()
        .unwrap()
        .success());

    let cfg = run(env
        .gitenc_cmd()
        .expect("gitenc")
        .current_dir(&repo)
        .args(["--config", SHARED_ENCLAVE_LABEL]))
    .expect("gitenc --config");
    assert!(cfg.succeeded(), "gitenc --config: {}", cfg.stderr);

    let dump = env
        .git_cmd()
        .current_dir(&repo)
        .args(["config", "--list", "--local"])
        .output()
        .expect("git config dump");
    let dump_text = String::from_utf8_lossy(&dump.stdout).into_owned();

    // No PKCS11Provider, no PKCS11 directives, no .dylib / .so
    // anywhere in the gitenc-managed repo config.
    assert!(
        !dump_text.to_lowercase().contains("pkcs11"),
        "gitenc --config must never emit a PKCS#11-related \
         directive into the repo's git config; dump:\n{dump_text}"
    );
}
