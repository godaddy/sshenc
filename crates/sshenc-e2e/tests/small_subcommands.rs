// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! End-to-end coverage for sshenc subcommands that previously had
//! no e2e tests at all: `default` (key promotion), `identity`
//! (set git identity for a key), `completions` (shell completion
//! script generation), and `openssh print-config --pkcs11` (the
//! PKCS#11-flavored Host block).
//!
//! Also exercises the **agent-respawn invariant**: killing the
//! `sshenc-agent` process underneath the CLI must NOT cause the
//! next CLI op to fail or fall back to a local backend. The CLI's
//! `ensure_agent_ready` call should detect the dead socket and
//! transparently re-spawn the agent before proceeding.

#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

#[cfg(not(windows))]
use std::time::{Duration, Instant};

use sshenc_e2e::{
    docker_skip_reason, extended_enabled, persistent_keys_dir, run, shared_enclave_pubkey,
    software_mode, SshencEnv, SHARED_ENCLAVE_LABEL,
};

fn skip_if_no_docker(test_name: &str) -> bool {
    if let Some(reason) = docker_skip_reason() {
        eprintln!("skip {test_name}: {reason}");
        return true;
    }
    false
}

#[cfg_attr(windows, allow(dead_code))] // Used only by Unix-gated tests below.
fn skip_unless_key_creation_cheap(test_name: &str) -> bool {
    if extended_enabled() || software_mode() {
        return false;
    }
    eprintln!(
        "skip {test_name}: needs to create enclave keys; \
         set SSHENC_E2E_EXTENDED=1 or SSHENC_E2E_SOFTWARE=1"
    );
    true
}

// ───────────────────────────────────────────────────────────────
// completions
// ───────────────────────────────────────────────────────────────

/// `sshenc completions <shell>` emits a non-empty completion
/// script for each supported shell, and the script mentions the
/// `sshenc` binary name so it's wired up to the right command.
#[test]
#[ignore = "requires docker"]
fn completions_emits_scripts_for_each_shell() {
    if skip_if_no_docker("completions_emits_scripts_for_each_shell") {
        return;
    }
    let env = SshencEnv::new().expect("env");

    for shell in &["bash", "zsh", "fish"] {
        let out = run(env
            .sshenc_cmd()
            .expect("sshenc")
            .args(["completions", shell]))
        .expect("completions");
        assert!(
            out.succeeded(),
            "completions {shell} failed: {}",
            out.stderr
        );
        assert!(
            out.stdout.contains("sshenc"),
            "{shell} completion script should mention `sshenc`:\n{}",
            out.stdout.lines().take(3).collect::<Vec<_>>().join("\n")
        );
        assert!(
            out.stdout.len() > 200,
            "{shell} completion script suspiciously short ({} bytes)",
            out.stdout.len()
        );
    }
}

// ───────────────────────────────────────────────────────────────
// identity (set git identity on a key)
// ───────────────────────────────────────────────────────────────

/// `sshenc identity --name --email` writes the git identity into
/// the key's metadata; subsequent `inspect --json` exposes it.
#[test]
#[ignore = "requires docker"]
fn identity_persists_through_metadata() {
    if skip_if_no_docker("identity_persists_through_metadata") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared key"));

    let name = "Jay E2e Tester";
    let email = "jay-e2e@example.invalid";
    let set = run(env.sshenc_cmd().expect("sshenc").args([
        "identity",
        SHARED_ENCLAVE_LABEL,
        "--name",
        name,
        "--email",
        email,
    ]))
    .expect("identity");
    assert!(set.succeeded(), "identity failed: {}", set.stderr);

    // The identity is stored in the key's metadata. The most
    // robust place to read it back is the `.meta` file directly —
    // CLI inspection paths surface only the comment, not the git
    // fields. The e2e harness uses `persistent_keys_dir()` (under
    // the developer's real `$HOME`, not the test's tempdir HOME)
    // so the shared key survives across tests.
    let meta_path = persistent_keys_dir().join(format!("{SHARED_ENCLAVE_LABEL}.meta"));
    let meta_text = std::fs::read_to_string(&meta_path).expect("read meta");
    assert!(
        meta_text.contains(name),
        "name should appear in {}:\n{meta_text}",
        meta_path.display()
    );
    assert!(
        meta_text.contains(email),
        "email should appear in {}:\n{meta_text}",
        meta_path.display()
    );
}

// ───────────────────────────────────────────────────────────────
// default promotion
// ───────────────────────────────────────────────────────────────

/// Promoting a non-default key to `default` succeeds, makes the
/// new label `default`, and writes `~/.ssh/id_ecdsa.pub`. Linux/
/// macOS only — the sshenc-cli command bails on Windows because
/// CNG key names are immutable.
#[test]
#[ignore = "requires docker"]
#[cfg(not(windows))]
fn default_promotion_relabels_and_writes_id_ecdsa_pub() {
    if skip_if_no_docker("default_promotion_relabels_and_writes_id_ecdsa_pub") {
        return;
    }
    if skip_unless_key_creation_cheap("default_promotion_relabels_and_writes_id_ecdsa_pub") {
        return;
    }
    let env = SshencEnv::new().expect("env");

    // Build a fresh non-default label, then promote it. Pre-clean
    // any prior leftover and any existing `default` so the
    // promotion picks a deterministic state.
    drop(run(env.sshenc_cmd().expect("sshenc").args([
        "delete",
        "promote-source",
        "-y",
    ])));

    let kg = run(env.sshenc_cmd().expect("sshenc").args([
        "keygen",
        "--label",
        "promote-source",
        "--auth-policy",
        "none",
        "--no-pub-file",
    ]))
    .expect("keygen");
    assert!(kg.succeeded(), "keygen failed: {}", kg.stderr);

    let id_ecdsa_pub = env.ssh_dir().join("id_ecdsa.pub");
    drop(std::fs::remove_file(&id_ecdsa_pub));

    let promote = run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["default", "promote-source"]))
    .expect("default");
    assert!(promote.succeeded(), "default failed: {}", promote.stderr);

    // The promoted label should now be `default` (rename was
    // proxied through the agent, including the keychain wrapping
    // entry).
    let listed = run(env.sshenc_cmd().expect("sshenc").arg("list")).expect("list");
    assert!(
        listed.stdout.contains("default"),
        "expected `default` in list:\n{}",
        listed.stdout
    );
    assert!(
        !listed.stdout.contains("promote-source"),
        "old label should be gone:\n{}",
        listed.stdout
    );
    assert!(
        id_ecdsa_pub.exists(),
        "id_ecdsa.pub should be written by default promotion: {}",
        id_ecdsa_pub.display()
    );

    drop(run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["delete", "default", "-y"])));
}

/// Promoting a label that's already `default` errors out cleanly
/// rather than rename-to-self looping.
#[test]
#[ignore = "requires docker"]
#[cfg(not(windows))]
fn default_promotion_already_default_errors() {
    if skip_if_no_docker("default_promotion_already_default_errors") {
        return;
    }
    let env = SshencEnv::new().expect("env");

    let out = run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["default", "default"]))
    .expect("default default");
    assert!(
        !out.succeeded(),
        "promoting default→default should fail:\n{}",
        out.stdout
    );
    assert!(
        out.stderr.to_lowercase().contains("already"),
        "expected 'already' in error; got:\n{}",
        out.stderr
    );
}

// ───────────────────────────────────────────────────────────────
// openssh print-config --pkcs11
// ───────────────────────────────────────────────────────────────

/// `sshenc openssh print-config --pkcs11 …` emits a Host block
/// using the PKCS#11 provider directive instead of `IdentityAgent`.
#[test]
#[ignore = "requires docker"]
fn openssh_print_config_pkcs11_mode() {
    if skip_if_no_docker("openssh_print_config_pkcs11_mode") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared key"));

    let out = run(env.sshenc_cmd().expect("sshenc").args([
        "openssh",
        "print-config",
        "--label",
        SHARED_ENCLAVE_LABEL,
        "--host",
        "github.com",
        "--pkcs11",
    ]))
    .expect("openssh print-config --pkcs11");
    assert!(
        out.succeeded(),
        "openssh print-config --pkcs11 failed: {}",
        out.stderr
    );
    assert!(
        out.stdout.contains("PKCS11Provider"),
        "expected PKCS11Provider directive:\n{}",
        out.stdout
    );
    assert!(
        out.stdout.contains("Host github.com"),
        "expected Host github.com block:\n{}",
        out.stdout
    );
}

/// Write a minimal sshenc config at the platform-default path so
/// `Config::load_default()` (which the CLI calls) finds it. Returns
/// the written path so the caller can read it back if needed.
#[cfg(not(windows))]
fn write_default_config(env: &SshencEnv, body: &str) -> std::path::PathBuf {
    // dirs::config_dir() resolves via HOME (or platform-specific
    // wrappers around it) — both macOS (~/Library/Application Support)
    // and Linux ($XDG_CONFIG_HOME or ~/.config) honor the test's
    // HOME tempdir scrub.
    #[cfg(target_os = "macos")]
    let cfg_dir = env
        .home()
        .join("Library")
        .join("Application Support")
        .join("sshenc");
    #[cfg(target_os = "linux")]
    let cfg_dir = env.home().join(".config").join("sshenc");
    std::fs::create_dir_all(&cfg_dir).expect("mkdir config dir");
    let path = cfg_dir.join("config.toml");
    std::fs::write(&path, body).expect("write config.toml");
    path
}

/// `sshenc openssh print-config` (no args) iterates
/// `host_identities` from the config file and emits one snippet
/// per entry. This is the wired-up form of what was previously a
/// dead config field — see PR that introduced
/// `openssh_print_config_dispatch`.
#[test]
#[ignore = "requires docker"]
#[cfg(not(windows))]
fn openssh_print_config_iterates_host_identities() {
    if skip_if_no_docker("openssh_print_config_iterates_host_identities") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared key"));

    write_default_config(
        &env,
        &format!(
            "[[host_identities]]\nhost = \"github.com\"\nlabel = \"{SHARED_ENCLAVE_LABEL}\"\n\n\
             [[host_identities]]\nhost = \"gitlab.com\"\nlabel = \"{SHARED_ENCLAVE_LABEL}\"\n",
        ),
    );

    let out = run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["openssh", "print-config"]))
    .expect("openssh print-config (no args)");
    assert!(
        out.succeeded(),
        "openssh print-config (host_identities mode) failed; stderr:\n{}",
        out.stderr
    );
    assert!(
        out.stdout.contains("Host github.com"),
        "expected Host github.com snippet; got:\n{}",
        out.stdout
    );
    assert!(
        out.stdout.contains("Host gitlab.com"),
        "expected Host gitlab.com snippet; got:\n{}",
        out.stdout
    );
    // Both snippets should reference the same agent socket and
    // include IdentitiesOnly.
    let identity_agent_count = out.stdout.matches("IdentityAgent").count();
    assert!(
        identity_agent_count >= 2,
        "expected at least 2 IdentityAgent directives (one per host); got {identity_agent_count}:\n{}",
        out.stdout
    );
}

/// Passing only `--label` (without `--host`) — or vice versa — must
/// error out with a message pointing at the right fix. We reject
/// the half-form to keep the user from being surprised by which
/// path the CLI silently chose.
#[test]
#[ignore = "requires docker"]
fn openssh_print_config_rejects_half_args() {
    if skip_if_no_docker("openssh_print_config_rejects_half_args") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared key"));

    let only_label = run(env.sshenc_cmd().expect("sshenc").args([
        "openssh",
        "print-config",
        "--label",
        SHARED_ENCLAVE_LABEL,
    ]))
    .expect("openssh print-config --label");
    assert!(
        !only_label.succeeded(),
        "should fail without --host; stdout:\n{}\nstderr:\n{}",
        only_label.stdout,
        only_label.stderr
    );
    assert!(
        only_label.stderr.contains("--host") || only_label.stderr.contains("host_identities"),
        "expected error pointing at --host; got:\n{}",
        only_label.stderr
    );

    let only_host = run(env.sshenc_cmd().expect("sshenc").args([
        "openssh",
        "print-config",
        "--host",
        "github.com",
    ]))
    .expect("openssh print-config --host");
    assert!(
        !only_host.succeeded(),
        "should fail without --label; stdout:\n{}\nstderr:\n{}",
        only_host.stdout,
        only_host.stderr
    );
}

/// With no `host_identities` configured, calling
/// `openssh print-config` with no args must error cleanly rather
/// than silently emit nothing.
#[test]
#[ignore = "requires docker"]
#[cfg(not(windows))]
fn openssh_print_config_errors_when_host_identities_empty() {
    if skip_if_no_docker("openssh_print_config_errors_when_host_identities_empty") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared key"));

    // Default config has no host_identities. Don't write any.
    write_default_config(&env, "# empty config\n");

    let out = run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["openssh", "print-config"]))
    .expect("openssh print-config");
    assert!(
        !out.succeeded(),
        "should fail when host_identities is empty; stdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    assert!(
        out.stderr.contains("host_identities") || out.stderr.contains("no"),
        "expected error referencing host_identities; got:\n{}",
        out.stderr
    );
}

// ───────────────────────────────────────────────────────────────
// agent-respawn invariant
// ───────────────────────────────────────────────────────────────

/// **Invariant**: if `sshenc-agent` dies between two CLI ops, the
/// next op detects the dead socket via `ensure_agent_ready` and
/// transparently re-spawns the agent. The CLI must NOT error out
/// (that would surprise users running interactive workflows after
/// a stale agent gets killed) and must NOT fall back to local
/// crypto (the centralization invariant — agent is the sole
/// toucher).
///
/// Unix only: the test removes the socket file to force the
/// readiness probe down the spawn path. Windows uses a named pipe
/// that's owned by the running process (not a filesystem entry we
/// can remove) and the auto-spawn path on Windows is intentionally
/// not implemented — agent lifecycle there is a Service.
#[test]
#[ignore = "requires docker"]
#[cfg(not(windows))]
fn cli_respawns_agent_after_kill() {
    if skip_if_no_docker("cli_respawns_agent_after_kill") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared key"));

    // Bring the agent up explicitly so we have a known PID to kill.
    env.start_agent().expect("start agent");
    let socket = env.socket_path();
    assert!(socket.exists(), "agent socket should exist after start");

    // Kill it. `stop_agent` SIGKILLs the spawned child and waits.
    env.stop_agent();
    // Drain any remaining socket file so the next CLI op sees the
    // "agent isn't listening" state cleanly. Linux leaves the
    // file; macOS too. Removing it forces ensure_agent_ready down
    // the spawn path.
    drop(std::fs::remove_file(&socket));

    // Now run a CLI op that requires the agent (`delete` would
    // make a fresh key + cleanup, which costs prompts on SE; use
    // a non-mutating sign-via-agent path instead). Easiest: run
    // `sshenc inspect <label>` — it doesn't talk to the agent at
    // all, so it'll succeed but won't prove the respawn.
    //
    // The cheap way to prove respawn is to delete a freshly-made
    // throwaway key — that round-trips through the agent. We gate
    // it the same way as other key-creating tests.
    if !extended_enabled() && !software_mode() {
        eprintln!(
            "skip cli_respawns_agent_after_kill: needs key creation; \
             set SSHENC_E2E_EXTENDED=1 or SSHENC_E2E_SOFTWARE=1 to run"
        );
        return;
    }
    let label = "e2e-respawn";
    drop(run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["delete", label, "-y"])));
    drop(std::fs::remove_file(&socket));

    // Keygen routes through the agent. If the CLI didn't respawn,
    // this would error with "sshenc-agent not reachable".
    let kg_start = Instant::now();
    let kg = run(env.sshenc_cmd().expect("sshenc").args([
        "keygen",
        "--label",
        label,
        "--auth-policy",
        "none",
        "--no-pub-file",
    ]))
    .expect("keygen after respawn");
    let kg_elapsed = kg_start.elapsed();
    assert!(
        kg.succeeded(),
        "keygen after agent kill should succeed (CLI must respawn agent); stderr:\n{}",
        kg.stderr
    );
    // Re-spawn + readiness wait is bounded at ~3.1 s by
    // `enclaveapp_core::daemon::ensure_daemon_ready` — generous
    // budget here in case CI is slow.
    assert!(
        kg_elapsed < Duration::from_secs(15),
        "respawn + keygen took {:?} which is way over the 3.1s readiness budget",
        kg_elapsed
    );

    // The respawned agent should have created a fresh socket on
    // its own — confirms the CLI didn't quietly fall back to a
    // local backend that bypassed the agent entirely.
    assert!(
        socket.exists(),
        "agent should have re-created its socket at {}",
        socket.display()
    );

    drop(run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["delete", label, "-y"])));
}
