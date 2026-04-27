// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `Host [::1]` (IPv6 literal in brackets) coexists with the
//! sshenc install block. `ssh -G [::1]` parses cleanly and
//! reports the sshenc IdentityAgent. We don't try to actually
//! connect over IPv6 (the test sshd is IPv4-only); the contract
//! pinned here is purely "config parser + install block emit
//! valid output for IPv6 host literals".

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{docker_skip_reason, run, SshencEnv};

fn skip_if_no_docker(test_name: &str) -> bool {
    if let Some(reason) = docker_skip_reason() {
        eprintln!("skip {test_name}: {reason}");
        return true;
    }
    false
}

/// `Host ::1` (IPv6 literal) block alongside sshenc install:
/// the config parser accepts the resulting file and `ssh -G
/// ::1` resolves both the user-defined User and the sshenc
/// IdentityAgent.
#[test]
#[ignore = "requires docker"]
fn install_coexists_with_ipv6_literal_host() {
    if skip_if_no_docker("install_coexists_with_ipv6_literal_host") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    std::fs::create_dir_all(env.ssh_dir()).expect("mkdir ssh dir");

    let pre = "\
Host ::1
    User ipv6-user
    Port 2222
";
    let config = env.ssh_dir().join("config");
    std::fs::write(&config, pre).expect("write config");

    let install =
        run(env.sshenc_cmd().expect("sshenc cmd").arg("install")).expect("sshenc install");
    assert!(install.succeeded(), "sshenc install: {}", install.stderr);

    let probe = run(env
        .scrubbed_command("ssh")
        .arg("-F")
        .arg(&config)
        .arg("-G")
        .arg("::1"))
    .expect("ssh -G ::1");
    assert!(
        probe.succeeded(),
        "ssh -G ::1 failed; stderr:\n{}",
        probe.stderr
    );
    let lower = probe.stdout.to_lowercase();
    assert!(
        lower.contains("identityagent"),
        "expected identityagent for ::1; got:\n{}",
        probe.stdout
    );
    assert!(
        lower.contains("user ipv6-user"),
        "expected User ipv6-user from the IPv6 Host block; got:\n{}",
        probe.stdout
    );

    let after = std::fs::read_to_string(&config).expect("read after");
    assert!(
        after.contains("BEGIN sshenc managed block"),
        "sshenc managed block missing; config:\n{after}"
    );
    assert!(
        after.contains("Host ::1"),
        "user IPv6 Host block was disturbed; config:\n{after}"
    );

    drop(std::fs::remove_file(env.socket_path()));
}
