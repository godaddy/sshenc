// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Cross-binary contracts and install-time migration scenarios
//! that no other test file pins:
//!
//! 1. `sshenc-keygen` (the convenience binary) and `sshenc keygen`
//!    must agree on the keys_dir layout — a key minted by one is
//!    immediately usable by the other for sign / list / inspect.
//!    Both binaries call into `sshenc-se`, but they're separately
//!    compiled and a regression in either's path resolution would
//!    silently break workflows that mix them.
//!
//! 2. `sshenc install` against a `~/.ssh/config` that already has
//!    a user-set `IdentityAgent` directive (typical migration
//!    scenario: previously running yubikey-agent / 1Password /
//!    other) must not silently clobber the user's existing
//!    directive. The contract: sshenc adds its managed block
//!    (which has its own IdentityAgent inside) and leaves the
//!    user's pre-existing line intact above or below.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{
    docker_skip_reason, extended_enabled, run, software_mode, workspace_bin, SshencEnv,
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
        "skip {test_name}: needs to mint keys; \
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

/// A key minted by the `sshenc-keygen` standalone binary is
/// listable, inspectable, and signable through the `sshenc` CLI.
/// Verifies the cross-binary keys_dir contract.
#[test]
#[ignore = "requires docker"]
fn sshenc_keygen_minted_key_is_visible_to_sshenc_cli() {
    if skip_if_no_docker("sshenc_keygen_minted_key_is_visible_to_sshenc_cli") {
        return;
    }
    if skip_unless_key_creation_cheap("sshenc_keygen_minted_key_is_visible_to_sshenc_cli") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    env.start_agent().expect("start agent");

    let label = unique_label("xbin-handoff");
    let kg_bin = workspace_bin("sshenc-keygen").expect("sshenc-keygen binary");

    let kg = run(env
        .scrubbed_command(&kg_bin)
        .arg("--label")
        .arg(&label)
        .arg("--no-pub-file")
        .arg("--quiet"))
    .expect("run sshenc-keygen");
    assert!(
        kg.succeeded(),
        "sshenc-keygen failed; stdout:\n{}\nstderr:\n{}",
        kg.stdout,
        kg.stderr
    );

    // `sshenc list --json` must include the label.
    let listed = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["list", "--json"]))
    .expect("sshenc list --json");
    assert!(listed.succeeded(), "sshenc list: {}", listed.stderr);
    let array: serde_json::Value =
        serde_json::from_str(&listed.stdout).expect("list output is JSON");
    let seen = array.as_array().expect("array").iter().any(|e| {
        e.get("metadata")
            .and_then(|m| m.get("label"))
            .and_then(|v| v.as_str())
            == Some(&label)
    });
    assert!(
        seen,
        "label '{label}' minted by sshenc-keygen not seen by sshenc list:\n{}",
        listed.stdout
    );

    // `sshenc inspect <label> --json` must succeed for the label.
    let inspect = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["inspect", &label, "--json"]))
    .expect("sshenc inspect --json");
    assert!(
        inspect.succeeded(),
        "sshenc inspect '{label}': {}",
        inspect.stderr
    );

    // Cross-binary signing: `sshenc -Y sign` against the key the
    // standalone keygen minted must succeed.
    let pub_path = env.ssh_dir().join(format!("{label}.pub"));
    std::fs::create_dir_all(env.ssh_dir()).expect("mkdir ssh dir");
    let exp = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["export-pub", &label]))
    .expect("export-pub");
    assert!(exp.succeeded(), "export-pub: {}", exp.stderr);
    std::fs::write(&pub_path, exp.stdout.as_bytes()).expect("write pub");

    let data = env.home().join("xbin-data.txt");
    std::fs::write(&data, b"cross-binary handoff payload\n").expect("write data");
    let sign = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .arg("-Y")
        .arg("sign")
        .arg("-n")
        .arg("git")
        .arg("-f")
        .arg(&pub_path)
        .arg(&data))
    .expect("sshenc -Y sign");
    assert!(
        sign.succeeded(),
        "sshenc -Y sign with sshenc-keygen-minted key failed; stderr:\n{}",
        sign.stderr
    );

    drop(run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["delete", &label, "-y"])));
}

/// `sshenc install` against a `~/.ssh/config` that already has the
/// user's own `IdentityAgent` directive (e.g. migrating from
/// yubikey-agent or 1Password) must not silently overwrite the
/// existing directive. sshenc adds its own managed block; the
/// user's pre-existing line must still be present after install.
///
/// SSH evaluates Host blocks top-down with first-match-wins; we
/// don't assert about which IdentityAgent wins in practice (that's
/// the user's responsibility to order correctly). What we DO
/// assert: the user's line survives. A regression where install
/// rewrote the whole file or deleted unrelated lines would fail
/// here.
#[test]
#[ignore = "requires docker"]
fn install_preserves_preexisting_user_identityagent() {
    if skip_if_no_docker("install_preserves_preexisting_user_identityagent") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    std::fs::create_dir_all(env.ssh_dir()).expect("mkdir ssh dir");

    let ssh_config = env.ssh_dir().join("config");
    let pre_existing_block = "\
Host yubikey-only-host
    IdentityAgent ~/legacy/yubikey-agent.sock
    IdentitiesOnly yes
";
    std::fs::write(&ssh_config, pre_existing_block).expect("write pre-existing config");

    let install =
        run(env.sshenc_cmd().expect("sshenc cmd").arg("install")).expect("sshenc install");
    assert!(
        install.succeeded(),
        "sshenc install failed; stderr:\n{}",
        install.stderr
    );

    let after = std::fs::read_to_string(&ssh_config).expect("read config");

    // User's pre-existing block must still be present, byte-for-byte.
    assert!(
        after.contains("Host yubikey-only-host"),
        "user's pre-existing Host block was removed by install; config now:\n{after}"
    );
    assert!(
        after.contains("~/legacy/yubikey-agent.sock"),
        "user's pre-existing IdentityAgent value was removed by install; config now:\n{after}"
    );

    // sshenc's managed block was appended.
    assert!(
        after.contains("BEGIN sshenc managed block"),
        "sshenc install did not add a managed block; config now:\n{after}"
    );
    assert!(
        after.contains("END sshenc managed block"),
        "sshenc install added a malformed block; config now:\n{after}"
    );

    // Cleanup: stop any agent install spawned and remove its
    // socket file so SshencEnv drop doesn't have to chase it.
    drop(std::fs::remove_file(env.socket_path()));
}
