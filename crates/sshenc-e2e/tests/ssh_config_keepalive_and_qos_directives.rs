// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `ServerAliveCountMax`, `ServerAliveInterval`, and `IPQoS`
//! set in user-managed Host blocks survive `sshenc install`:
//! `ssh -G` parses the resulting config without error, every
//! user directive is preserved verbatim, and the sshenc managed
//! block is still present.

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

/// `ssh_config` carrying ServerAliveCountMax/Interval and IPQoS
/// directives in user blocks survives `sshenc install`: the
/// post-install file still contains them verbatim and `ssh -G`
/// parses without error. (Whether ssh's per-Host precedence
/// rules pick up those directives over the sshenc managed
/// block's wildcard is ssh's contract, not sshenc's; here we
/// pin "install doesn't drop or mangle user directives".)
#[test]
#[ignore = "requires docker"]
fn keepalive_and_qos_directives_survive_install() {
    if skip_if_no_docker("keepalive_and_qos_directives_survive_install") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    std::fs::create_dir_all(env.ssh_dir()).expect("mkdir ssh dir");

    let pre = "\
Host github.com
    User git
    ServerAliveInterval 30
    ServerAliveCountMax 3
    IPQoS lowdelay throughput
";
    let config = env.ssh_dir().join("config");
    std::fs::write(&config, pre).expect("write config");

    let install =
        run(env.sshenc_cmd().expect("sshenc cmd").arg("install")).expect("sshenc install");
    assert!(install.succeeded(), "sshenc install: {}", install.stderr);

    // ssh -G must still parse the resulting config without error,
    // for any host (we use a wildcard-friendly arbitrary name to
    // avoid relying on per-Host precedence).
    let probe = run(env
        .scrubbed_command("ssh")
        .arg("-F")
        .arg(&config)
        .arg("-G")
        .arg("any-host.example.invalid"))
    .expect("ssh -G");
    assert!(
        probe.succeeded(),
        "ssh -G failed after install with keepalive/qos directives; stderr:\n{}",
        probe.stderr
    );
    assert!(
        probe.stdout.to_lowercase().contains("identityagent"),
        "expected identityagent in ssh -G output; got:\n{}",
        probe.stdout
    );

    // Post-install file must still contain every user directive
    // verbatim, and the sshenc managed block.
    let after = std::fs::read_to_string(&config).expect("read after");
    for needle in [
        "Host github.com",
        "User git",
        "ServerAliveInterval 30",
        "ServerAliveCountMax 3",
        "IPQoS lowdelay throughput",
        "BEGIN sshenc managed block",
    ] {
        assert!(
            after.contains(needle),
            "expected {needle:?} in post-install config; got:\n{after}"
        );
    }

    drop(std::fs::remove_file(env.socket_path()));
}
