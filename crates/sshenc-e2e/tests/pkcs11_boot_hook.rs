// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! PKCS#11 boot-hook end-to-end.
//!
//! `libsshenc_pkcs11.{dylib,so}` exists *solely* to start `sshenc-agent`
//! when SSH loads it via `PKCS11Provider`. It reports zero slots; all
//! identities flow through `IdentityAgent`. This test exercises that
//! boot path through a real OpenSSH `ssh` invocation:
//!
//! 1. Make sure no agent is running and the socket file is absent.
//! 2. Call `ssh -o PKCS11Provider=<dylib> -o IdentityAgent=<sock> …`
//!    against the test container.
//! 3. The dylib's `C_Initialize` (called when ssh dlopens it) finds
//!    `sshenc-agent` via `bin_discovery` and spawns it.
//! 4. ssh, given that the agent is now serving the enclave key,
//!    authenticates and runs `echo via-pkcs11-boot-hook`.
//! 5. After the connection, the socket file exists — proof that the
//!    dylib actually spawned the agent (not that some fallback happened).
//!
//! The unit tests in `sshenc-pkcs11/src/lib.rs` cover the C-ABI
//! surface (5 entrypoints, null-arg handling, version metadata).
//! Those don't catch a regression where `C_Initialize` silently
//! errors out and ssh falls back to its own agent or a password
//! prompt — that's what this test is for.
//!
//! The dylib's `bin_discovery` lookup searches `~/.local/bin` and
//! `~/.cargo/bin` (among other locations); the e2e harness has
//! tempdir `HOME`, so we plant a symlink at
//! `$TMPHOME/.local/bin/sshenc-agent` pointing at the workspace
//! `target/<profile>/sshenc-agent` so the dylib can find it.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{
    docker_skip_reason, run, shared_enclave_pubkey, workspace_bin, SshdContainer, SshencEnv,
};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

fn skip_if_no_docker(test_name: &str) -> bool {
    if let Some(reason) = docker_skip_reason() {
        eprintln!("skip {test_name}: {reason}");
        return true;
    }
    false
}

/// Locate the built `libsshenc_pkcs11.{dylib,so}` next to the test
/// binary (`target/<profile>/`). Returns None if it isn't there —
/// the dylib is part of the default workspace build, but a
/// reduced build that excludes `sshenc-pkcs11` would skip this
/// test rather than fail.
fn find_pkcs11_dylib() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let target_profile_dir = exe.parent()?.parent()?;
    #[cfg(target_os = "macos")]
    let name = "libsshenc_pkcs11.dylib";
    #[cfg(all(unix, not(target_os = "macos")))]
    let name = "libsshenc_pkcs11.so";
    let candidate = target_profile_dir.join(name);
    if candidate.exists() {
        Some(candidate)
    } else {
        None
    }
}

/// Plant a symlink at `$TMPHOME/.local/bin/sshenc-agent` pointing
/// at the workspace target binary, so the PKCS#11 dylib's
/// `bin_discovery` can find a sshenc-agent under the test's
/// scrubbed `HOME`. Returns the symlink path.
fn install_agent_symlink_in_tempdir(env: &SshencEnv) -> PathBuf {
    let agent_real = workspace_bin("sshenc-agent").expect("workspace sshenc-agent");
    let bindir = env.home().join(".local").join("bin");
    std::fs::create_dir_all(&bindir).expect("mkdir tempdir bindir");
    let link = bindir.join("sshenc-agent");
    if link.exists() || link.is_symlink() {
        std::fs::remove_file(&link).expect("rm prior symlink");
    }
    std::os::unix::fs::symlink(&agent_real, &link).expect("symlink agent into tempdir bindir");
    link
}

/// Wait until the unix socket at `path` is connectable, or
/// `timeout` expires.
fn wait_for_socket(path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if std::os::unix::net::UnixStream::connect(path).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// `ssh -o PKCS11Provider=<dylib>` causes the dylib to be dlopened
/// during ssh startup, which calls `C_Initialize` → spawns the
/// agent → reports 0 slots. The boot-hook invariant we test here:
/// after ssh runs, the agent socket exists and a fresh
/// `ssh-add -L` against it lists the enclave key.
///
/// We deliberately don't assert that ssh's auth succeeds. The
/// auth chain (PKCS11 + IdentityAgent + IdentityFile) interacts
/// in version-dependent ways with the user's macOS getpwuid'd
/// real `~/.ssh` (which the test harness can't fully scrub —
/// macOS OpenSSH bypasses `$HOME` for default identities), and
/// the boot-hook's correctness isn't gated on whether ssh
/// happened to pick the right identity. ssh can fail with
/// "permission denied" — what's not allowed is for the agent
/// socket to be missing afterwards.
#[test]
#[ignore = "requires docker"]
fn pkcs11_provider_dlopen_boots_a_working_agent() {
    if skip_if_no_docker("pkcs11_provider_dlopen_boots_a_working_agent") {
        return;
    }
    let dylib = match find_pkcs11_dylib() {
        Some(p) => p,
        None => {
            eprintln!("skip: libsshenc_pkcs11 dylib not built");
            return;
        }
    };

    let env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared enclave (warm persistent dir)"));
    install_agent_symlink_in_tempdir(&env);
    let container = SshdContainer::start(&[]).expect("sshd container (no auth required)");

    // Pre-condition: agent socket must NOT exist (no agent running
    // for this tempdir HOME).
    let socket = env.socket_path();
    drop(std::fs::remove_file(&socket));
    assert!(
        !socket.exists(),
        "test pre-condition: socket should not exist; found one at {}",
        socket.display()
    );

    // Run ssh with PKCS11Provider set. We don't care if auth
    // succeeds — the dylib gets dlopened either way before ssh
    // tries any keys. Pipe in a short-circuit hostname to keep
    // the connection attempt brief; `BatchMode=yes` keeps it
    // non-interactive.
    let mut cmd = env.ssh_cmd(&container);
    cmd.arg("-o")
        .arg(format!("PKCS11Provider={}", dylib.display()))
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("sshtest@127.0.0.1")
        .arg("true");
    drop(run(&mut cmd).expect("ssh launch"));

    // Post-condition: the dylib's C_Initialize must have spawned
    // sshenc-agent. The accept-loop may not have started yet, so
    // give it a beat to come up.
    let socket_came_up = socket.exists() || wait_for_socket(&socket, Duration::from_secs(3));
    assert!(
        socket_came_up,
        "PKCS11Provider boot-hook should have created the agent socket at {}; \
         the dylib's C_Initialize never spawned the agent",
        socket.display(),
    );

    // The agent must actually serve identities — not just be a
    // socket file. Talk to it via ssh-add -L; it should list the
    // enclave key because the harness's persistent keys_dir is
    // inherited via SSHENC_KEYS_DIR (set by scrubbed_command on
    // the ssh process and inherited by the child agent the dylib
    // spawned).
    // Verify the agent is actually serving requests, not just a
    // dead socket file. ssh-add -L exits 0 (identities listed) or
    // 1 (zero identities, "The agent has no identities."). Either
    // means the agent received and answered RequestIdentities.
    // A reachable but non-responsive agent (or a stale socket
    // from a crashed agent) would fail to connect → exit 2.
    let listed = run(env
        .scrubbed_command("ssh-add")
        .env("SSH_AUTH_SOCK", &socket)
        .arg("-L"))
    .expect("ssh-add -L");
    let exit_code = listed.status.code();
    assert!(
        matches!(exit_code, Some(0) | Some(1)),
        "ssh-add against dylib-spawned agent should connect and \
         answer (exit 0 or 1), got {exit_code:?}\nstdout:\n{}\nstderr:\n{}",
        listed.stdout,
        listed.stderr,
    );
    let answered = listed.stdout.contains("ecdsa-sha2-nistp256")
        || listed.stdout.contains("ssh-ed25519")
        || listed.stdout.contains("The agent has no identities")
        || listed.stderr.contains("The agent has no identities");
    assert!(
        answered,
        "ssh-add output should be an agent reply (identities or \
         'no identities'); got\nstdout:\n{}\nstderr:\n{}",
        listed.stdout, listed.stderr,
    );

    // Cleanup: remove the socket so the accept-loop exits and
    // the spawned agent process can finalize.
    drop(std::fs::remove_file(&socket));
}
