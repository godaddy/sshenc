// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Three SSH-config interaction edges:
//!
//! 1. After `sshenc install`, an `ssh -G <host>` (print effective
//!    config) reports `identityagent` set to the sshenc socket
//!    path. This is the user-visible signal that "sshenc owns
//!    auth for this host"; if the install block fails to take
//!    effect at parse time, `ssh -G` is the fastest way to find
//!    out.
//! 2. The sshenc-managed block coexists with a user `Match`
//!    directive — install on a config that already has Match
//!    blocks must produce a parseable file (`ssh -G` succeeds).
//! 3. `ssh-keyscan` against the e2e container works; pins the
//!    "ssh-keyscan doesn't go through sshenc-agent at all"
//!    invariant — keyscan only does kex, no auth, so it should
//!    succeed regardless of agent state.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{docker_skip_reason, run, shared_enclave_pubkey, SshdContainer, SshencEnv};

fn skip_if_no_docker(test_name: &str) -> bool {
    if let Some(reason) = docker_skip_reason() {
        eprintln!("skip {test_name}: {reason}");
        return true;
    }
    false
}

/// `ssh -G <hostname>` after `sshenc install` reports `identityagent`
/// pointing at the sshenc socket. The exact directive name is
/// lower-cased in `-G` output.
#[test]
#[ignore = "requires docker"]
fn ssh_dash_g_reports_sshenc_identityagent_after_install() {
    if skip_if_no_docker("ssh_dash_g_reports_sshenc_identityagent_after_install") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    std::fs::create_dir_all(env.ssh_dir()).expect("mkdir ssh dir");

    let install =
        run(env.sshenc_cmd().expect("sshenc cmd").arg("install")).expect("sshenc install");
    assert!(install.succeeded(), "install: {}", install.stderr);

    // Use ssh -G against an arbitrary hostname — the wildcard
    // sshenc Host * block should set IdentityAgent regardless.
    // Pin -F to our just-installed config so ssh ignores the
    // developer's real ~/.ssh/config and the system-wide
    // /etc/ssh/ssh_config defaults.
    let user_config = env.ssh_dir().join("config");
    let probe = run(env
        .scrubbed_command("ssh")
        .arg("-F")
        .arg(&user_config)
        .arg("-G")
        .arg("any-host.example.invalid"))
    .expect("ssh -G");
    assert!(
        probe.succeeded(),
        "ssh -G failed; stderr:\n{}",
        probe.stderr
    );
    let lower = probe.stdout.to_lowercase();
    assert!(
        lower.contains("identityagent"),
        "ssh -G should mention identityagent after install; got:\n{}",
        probe.stdout
    );
    let socket_str = env.socket_path().display().to_string().to_lowercase();
    assert!(
        lower.contains(&socket_str)
            || lower.contains(&socket_str.replace(".sshenc/agent.sock", ".sshenc")),
        "identityagent value doesn't reference sshenc socket; ssh -G:\n{}",
        probe.stdout
    );

    drop(std::fs::remove_file(env.socket_path()));
}

/// `sshenc install` against a config that already contains a user
/// `Match` directive must produce a parseable result. ssh -G does
/// the parsing; if our managed block trips up the Match parser,
/// ssh -G fails with a syntax error.
#[test]
#[ignore = "requires docker"]
fn install_coexists_with_user_match_block() {
    if skip_if_no_docker("install_coexists_with_user_match_block") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    std::fs::create_dir_all(env.ssh_dir()).expect("mkdir ssh dir");

    // Seed a config with a Match block so install has to weave
    // its block around it without breaking the parser.
    let pre = "\
Host github.com
    User git
    IdentitiesOnly yes

Match host *.internal exec \"true\"
    ServerAliveInterval 30
    Compression yes
";
    let config = env.ssh_dir().join("config");
    std::fs::write(&config, pre).expect("write config");

    let install =
        run(env.sshenc_cmd().expect("sshenc cmd").arg("install")).expect("sshenc install");
    assert!(install.succeeded(), "install: {}", install.stderr);

    // ssh -G must successfully parse the resulting config. Pin
    // -F so it reads only the file we just installed into,
    // bypassing the developer's real ~/.ssh/config. The Match
    // block uses `exec "true"` which always evaluates to true,
    // so `internal-host.internal` should match it; we care that
    // ssh -G parses without erroring.
    let probe = run(env
        .scrubbed_command("ssh")
        .arg("-F")
        .arg(&config)
        .arg("-G")
        .arg("internal-host.internal"))
    .expect("ssh -G");
    assert!(
        probe.succeeded(),
        "ssh -G failed against post-install config with Match; stderr:\n{}",
        probe.stderr
    );

    // Pre-existing user content survives.
    let after = std::fs::read_to_string(&config).expect("read after");
    assert!(
        after.contains("ServerAliveInterval 30"),
        "user Match block content was disturbed; config now:\n{after}"
    );
    assert!(
        after.contains("Host github.com"),
        "user Host block was disturbed; config now:\n{after}"
    );
    assert!(
        after.contains("BEGIN sshenc managed block"),
        "sshenc block missing after install; config now:\n{after}"
    );

    drop(std::fs::remove_file(env.socket_path()));
}

/// `ssh-keyscan` works against the e2e container without going
/// through sshenc-agent at all. Pins that ssh-keyscan continues
/// to function in the presence of an installed sshenc setup —
/// keyscan does kex but no user auth, so the agent shouldn't
/// matter.
#[test]
#[ignore = "requires docker"]
fn ssh_keyscan_works_against_test_container() {
    if skip_if_no_docker("ssh_keyscan_works_against_test_container") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    let container = SshdContainer::start(&[&enclave]).expect("sshd");

    let keyscan = run(env
        .scrubbed_command("ssh-keyscan")
        .arg("-T")
        .arg("10")
        .arg("-p")
        .arg(container.host_port.to_string())
        .arg("127.0.0.1"))
    .expect("ssh-keyscan");
    assert!(
        keyscan.succeeded(),
        "ssh-keyscan failed; stderr:\n{}",
        keyscan.stderr
    );
    // Output should contain at least one host-key line in the
    // form `<host> <keytype> <base64>`.
    let line = keyscan
        .stdout
        .lines()
        .find(|l| !l.starts_with('#') && !l.trim().is_empty())
        .unwrap_or("");
    let fields: Vec<&str> = line.split_whitespace().collect();
    assert!(
        fields.len() >= 3,
        "ssh-keyscan output missing host-key line; got:\n{}",
        keyscan.stdout
    );
    assert!(
        fields[1].starts_with("ssh-")
            || fields[1].starts_with("ecdsa-")
            || fields[1].starts_with("rsa-"),
        "second field should be a key type; got: '{}' in '{line}'",
        fields[1]
    );
}
