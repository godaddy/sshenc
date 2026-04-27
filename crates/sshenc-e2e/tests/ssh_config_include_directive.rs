// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `Include` directives in `~/.ssh/config` coexist with the
//! sshenc install block:
//!
//! - Absolute path: `Include /full/path/sshenc-extras.conf`.
//! - Glob pattern: `Include /full/path/sshenc-extras-*.conf`.
//! - Relative path (relative to ~/.ssh/): `Include hosts.d/*.conf`.
//!
//! In each form `sshenc install` runs cleanly and `ssh -G`
//! parses the resulting config without errors.

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

fn run_install_and_probe(env: &SshencEnv, pre_config: &str, host: &str) {
    let config = env.ssh_dir().join("config");
    std::fs::create_dir_all(env.ssh_dir()).expect("mkdir ssh dir");
    std::fs::write(&config, pre_config).expect("write config");

    let install =
        run(env.sshenc_cmd().expect("sshenc cmd").arg("install")).expect("sshenc install");
    assert!(install.succeeded(), "sshenc install: {}", install.stderr);

    let probe = run(env
        .scrubbed_command("ssh")
        .arg("-F")
        .arg(&config)
        .arg("-G")
        .arg(host))
    .expect("ssh -G");
    assert!(
        probe.succeeded(),
        "ssh -G on {host} failed after install with Include directive; stderr:\n{}",
        probe.stderr
    );
    let lower = probe.stdout.to_lowercase();
    assert!(
        lower.contains("identityagent"),
        "expected identityagent for {host}; got:\n{}",
        probe.stdout
    );

    // Sshenc block survived.
    let after = std::fs::read_to_string(&config).expect("read config after");
    assert!(
        after.contains("BEGIN sshenc managed block"),
        "sshenc managed block missing after install; config:\n{after}"
    );

    drop(std::fs::remove_file(env.socket_path()));
}

/// `Include /absolute/path` directive coexists with the
/// install block.
#[test]
#[ignore = "requires docker"]
fn install_coexists_with_include_absolute_path() {
    if skip_if_no_docker("install_coexists_with_include_absolute_path") {
        return;
    }
    let env = SshencEnv::new().expect("env");

    let extras_dir = env.home().join("extras-confd");
    std::fs::create_dir_all(&extras_dir).expect("mkdir extras dir");
    let extras = extras_dir.join("sshenc-extras.conf");
    std::fs::write(&extras, "Host included.example\n    User extra\n").expect("write extras");

    let pre = format!(
        "Include {}\n\nHost github.com\n    User git\n",
        extras.display()
    );
    run_install_and_probe(&env, &pre, "github.com");

    // The included Host block also resolves.
    let config = env.ssh_dir().join("config");
    let probe = run(env
        .scrubbed_command("ssh")
        .arg("-F")
        .arg(&config)
        .arg("-G")
        .arg("included.example"))
    .expect("ssh -G included");
    assert!(
        probe.succeeded(),
        "ssh -G included.example: {}",
        probe.stderr
    );
    assert!(
        probe.stdout.to_lowercase().contains("user extra"),
        "Include should have brought in 'User extra' for included.example; got:\n{}",
        probe.stdout
    );
}

/// `Include /absolute/path/pattern-*` (glob) coexists with the
/// install block.
#[test]
#[ignore = "requires docker"]
fn install_coexists_with_include_glob() {
    if skip_if_no_docker("install_coexists_with_include_glob") {
        return;
    }
    let env = SshencEnv::new().expect("env");

    let extras_dir = env.home().join("extras-glob-confd");
    std::fs::create_dir_all(&extras_dir).expect("mkdir extras dir");
    std::fs::write(
        extras_dir.join("a-extras.conf"),
        "Host glob-a.example\n    User a-user\n",
    )
    .expect("write a");
    std::fs::write(
        extras_dir.join("b-extras.conf"),
        "Host glob-b.example\n    User b-user\n",
    )
    .expect("write b");

    let pre = format!(
        "Include {}/*-extras.conf\n\nHost github.com\n    User git\n",
        extras_dir.display()
    );
    run_install_and_probe(&env, &pre, "github.com");

    let config = env.ssh_dir().join("config");
    for (host, expected_user) in [("glob-a.example", "a-user"), ("glob-b.example", "b-user")] {
        let probe = run(env
            .scrubbed_command("ssh")
            .arg("-F")
            .arg(&config)
            .arg("-G")
            .arg(host))
        .expect("ssh -G");
        assert!(probe.succeeded(), "ssh -G {host}: {}", probe.stderr);
        assert!(
            probe.stdout.to_lowercase().contains(expected_user),
            "Include glob should have brought in {expected_user} for {host}; got:\n{}",
            probe.stdout
        );
    }
}

/// `Include hosts.d/*.conf` (relative to ~/.ssh/) coexists with
/// the install block.
#[test]
#[ignore = "requires docker"]
fn install_coexists_with_include_relative_path() {
    if skip_if_no_docker("install_coexists_with_include_relative_path") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    std::fs::create_dir_all(env.ssh_dir().join("hosts.d")).expect("mkdir hosts.d");
    std::fs::write(
        env.ssh_dir().join("hosts.d").join("rel.conf"),
        "Host rel-host.example\n    User rel-user\n",
    )
    .expect("write rel");

    let pre = "Include hosts.d/*.conf\n\nHost github.com\n    User git\n";
    run_install_and_probe(&env, pre, "github.com");

    let config = env.ssh_dir().join("config");
    let probe = run(env
        .scrubbed_command("ssh")
        .arg("-F")
        .arg(&config)
        .arg("-G")
        .arg("rel-host.example"))
    .expect("ssh -G");
    assert!(probe.succeeded(), "ssh -G rel-host: {}", probe.stderr);
    assert!(
        probe.stdout.to_lowercase().contains("user rel-user"),
        "relative Include should have brought in rel-user; got:\n{}",
        probe.stdout
    );
}
