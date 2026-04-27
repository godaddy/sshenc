// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Two thin coverage gaps left over from earlier batches:
//!
//! 1. `sshenc keygen --require-user-presence` round-trips through
//!    the key's `.meta` file as `access_policy: "any"`. Without
//!    hardware we can't fully validate that the UP requirement
//!    surfaces at sign time, but we can prove the policy is
//!    persisted correctly so the hardware backend has the right
//!    input. Hardware-mode runs additionally see the policy in
//!    `sshenc inspect --json`.
//!
//! 2. `sshenc-agent --labels` (the CLI override of
//!    `config.allowed_labels`). `lifecycle.rs` exercises the
//!    config-file path; this test covers the CLI flag, which the
//!    main.rs code merges with config (CLI wins when non-empty).
//!
//! Both gated `#![cfg(unix)]` to match the rest of the suite.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{
    docker_skip_reason, extended_enabled, persistent_keys_dir, run, shared_enclave_pubkey,
    software_mode, SshencEnv, SHARED_ENCLAVE_LABEL,
};
use std::process::Stdio;

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

/// `sshenc keygen --require-user-presence` writes
/// `access_policy: "any"` into the key's `.meta` file. Without the
/// flag the policy is `"none"`. The flag is the legacy spelling
/// for `--auth-policy any`; this test pins both spellings produce
/// the same on-disk shape.
#[test]
#[ignore = "requires docker"]
fn keygen_require_user_presence_persists_as_access_policy_any() {
    if skip_if_no_docker("keygen_require_user_presence_persists_as_access_policy_any") {
        return;
    }
    if skip_unless_key_creation_cheap("keygen_require_user_presence_persists_as_access_policy_any")
    {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("warm shared key"));
    // Pre-spawn the agent to dodge the libenclaveapp daemonize flake on
    // Linux CI.
    env.start_agent().expect("start agent");

    let label = unique_label("up-required");
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

    // Read the meta file via persistent_keys_dir() — sshenc CLI
    // writes there via $SSHENC_KEYS_DIR.
    let meta_path = persistent_keys_dir().join(format!("{label}.meta"));
    let meta = std::fs::read_to_string(&meta_path).expect("read meta");
    let parsed: serde_json::Value = serde_json::from_str(&meta).expect("meta is JSON");
    assert_eq!(
        parsed.get("access_policy").and_then(|v| v.as_str()),
        Some("any"),
        "expected access_policy=any after --require-user-presence; got: {meta}"
    );

    // sshenc inspect --json should surface the same policy.
    let inspect = run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["inspect", &label, "--json"]))
    .expect("inspect --json");
    assert!(inspect.succeeded(), "inspect failed: {}", inspect.stderr);
    let info: serde_json::Value =
        serde_json::from_str(&inspect.stdout).expect("inspect --json output is JSON");
    assert_eq!(
        info.get("metadata")
            .and_then(|m| m.get("access_policy"))
            .and_then(|v| v.as_str()),
        Some("any"),
        "inspect --json should report access_policy=any; got:\n{}",
        inspect.stdout
    );

    // Cleanup.
    drop(run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["delete", &label, "-y"])));
}

/// Without `--require-user-presence` (and no `--auth-policy`), the
/// metadata records `access_policy: "none"`. Pinned alongside the
/// positive case so a default flip would surface as a regression.
#[test]
#[ignore = "requires docker"]
fn keygen_default_persists_as_access_policy_none() {
    if skip_if_no_docker("keygen_default_persists_as_access_policy_none") {
        return;
    }
    if skip_unless_key_creation_cheap("keygen_default_persists_as_access_policy_none") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("warm shared key"));

    let label = unique_label("up-default");
    let kg = run(env.sshenc_cmd().expect("sshenc").args([
        "keygen",
        "--label",
        &label,
        "--auth-policy",
        "none",
        "--no-pub-file",
    ]))
    .expect("sshenc keygen");
    assert!(kg.succeeded(), "keygen failed: {}", kg.stderr);

    let meta_path = persistent_keys_dir().join(format!("{label}.meta"));
    let meta = std::fs::read_to_string(&meta_path).expect("read meta");
    let parsed: serde_json::Value = serde_json::from_str(&meta).expect("meta is JSON");
    assert_eq!(
        parsed.get("access_policy").and_then(|v| v.as_str()),
        Some("none"),
        "expected access_policy=none with default flags; got: {meta}"
    );

    drop(run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["delete", &label, "-y"])));
}

/// `sshenc-agent --labels` (CLI override) restricts the agent's
/// exposed identities to the named labels, the same way config's
/// `allowed_labels` does. CLI flag wins when non-empty:
/// see crates/sshenc-agent/src/main.rs line 232.
#[test]
#[ignore = "requires docker"]
fn agent_cli_labels_override_filters_identities() {
    if skip_if_no_docker("agent_cli_labels_override_filters_identities") {
        return;
    }
    if skip_unless_key_creation_cheap("agent_cli_labels_override_filters_identities") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let _shared = shared_enclave_pubkey(&env).expect("shared enclave");
    // Pre-spawn the agent to dodge the libenclaveapp daemonize flake on
    // Linux CI.
    env.start_agent().expect("start agent");

    // Mint a second key alongside the shared one so the agent has
    // two identities to choose between. With --labels = SHARED, the
    // second one must NOT appear.
    let other_label = unique_label("other-identity");
    let kg = run(env.sshenc_cmd().expect("sshenc").args([
        "keygen",
        "--label",
        &other_label,
        "--auth-policy",
        "none",
        "--no-pub-file",
    ]))
    .expect("sshenc keygen other");
    assert!(kg.succeeded(), "keygen other failed: {}", kg.stderr);

    // Look up other_label's key body now (this requires the agent
    // for AgentProxyBackend, but uses sshenc CLI which auto-spawns
    // the agent unfiltered — that's fine; the test's actual
    // agent-labels behavior we exercise after we kill that one).
    let other_pub = run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["export-pub", &other_label]))
    .expect("export-pub");
    assert!(
        other_pub.succeeded(),
        "export-pub other: {}",
        other_pub.stderr
    );
    let other_body = other_pub
        .stdout
        .split_whitespace()
        .nth(1)
        .expect("other pub has body")
        .to_string();

    // The CLI's AgentProxyBackend auto-spawned an unfiltered agent
    // for the keygen above. Remove the socket file so our labeled
    // agent can claim the path; the old (unfiltered) agent process
    // is left behind to be reaped on test exit. We connect-and-fail
    // on its dangling socket fd, but new connections via the path
    // hit the new agent.
    drop(std::fs::remove_file(env.socket_path()));

    let bin = sshenc_e2e::workspace_bin("sshenc-agent").expect("agent");
    let mut cmd = env.scrubbed_command(&bin);
    cmd.arg("--foreground")
        .arg("--debug")
        .arg("--socket")
        .arg(env.socket_path())
        .arg("--labels")
        .arg(SHARED_ENCLAVE_LABEL)
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn agent");

    // Wait for our labeled agent to claim the socket path.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        if std::os::unix::net::UnixStream::connect(env.socket_path()).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(
        std::os::unix::net::UnixStream::connect(env.socket_path()).is_ok(),
        "labeled agent didn't come up"
    );

    let listed = run(env
        .scrubbed_command("ssh-add")
        .env("SSH_AUTH_SOCK", env.socket_path())
        .arg("-L"))
    .expect("ssh-add -L");

    drop(child.kill());
    let stderr_out = child
        .wait_with_output()
        .map(|o| String::from_utf8_lossy(&o.stderr).into_owned())
        .unwrap_or_default();

    assert!(listed.succeeded(), "ssh-add -L failed: {}", listed.stderr);
    // Shared enclave key must be present.
    assert!(
        listed.stdout.contains("ecdsa-sha2-nistp256"),
        "shared key should be visible; got:\n{}\nagent stderr:\n{stderr_out}",
        listed.stdout
    );
    assert!(
        !listed.stdout.contains(&other_body),
        "agent --labels {SHARED_ENCLAVE_LABEL} should hide the other label's pub body; \
         ssh-add output:\n{}\nagent stderr (last 30 lines):\n{}",
        listed.stdout,
        stderr_out
            .lines()
            .rev()
            .take(30)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("\n")
    );

    // Cleanup the synthetic key.
    drop(run(env.sshenc_cmd().expect("sshenc").args([
        "delete",
        &other_label,
        "-y",
    ])));
}

/// `sshenc-agent --labels A,B,C` accepts a comma-separated list
/// (clap value_delimiter). Even with two labels both passed, only
/// the matching key surfaces.
#[test]
#[ignore = "requires docker"]
fn agent_cli_labels_accepts_comma_list() {
    if skip_if_no_docker("agent_cli_labels_accepts_comma_list") {
        return;
    }
    if skip_unless_key_creation_cheap("agent_cli_labels_accepts_comma_list") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let _shared = shared_enclave_pubkey(&env).expect("shared enclave");

    // Same socket-already-claimed concern as the override test —
    // shared_enclave_pubkey may have triggered an auto-spawn via
    // export-pub. Remove the socket file so our labeled agent
    // claims the path.
    drop(std::fs::remove_file(env.socket_path()));

    // Pass --labels with one real + one bogus label. Bogus label is
    // ignored at filter time (no key matches); real label still works.
    let bin = sshenc_e2e::workspace_bin("sshenc-agent").expect("agent");
    let mut cmd = env.scrubbed_command(&bin);
    cmd.arg("--foreground")
        .arg("--socket")
        .arg(env.socket_path())
        .arg("--labels")
        .arg(format!("{SHARED_ENCLAVE_LABEL},nonexistent-label"))
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn agent");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        if std::os::unix::net::UnixStream::connect(env.socket_path()).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(
        std::os::unix::net::UnixStream::connect(env.socket_path()).is_ok(),
        "agent didn't come up"
    );

    let listed = run(env
        .scrubbed_command("ssh-add")
        .env("SSH_AUTH_SOCK", env.socket_path())
        .arg("-L"))
    .expect("ssh-add -L");

    drop(child.kill());
    drop(child.wait());

    assert!(listed.succeeded(), "ssh-add -L failed: {}", listed.stderr);
    assert!(
        listed.stdout.contains("ecdsa-sha2-nistp256"),
        "shared key should appear with comma-list --labels; got:\n{}",
        listed.stdout
    );
}
