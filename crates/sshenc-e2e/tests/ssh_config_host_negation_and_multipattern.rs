// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Two SSH-config Host-line variants that the existing
//! `ssh_config_interactions.rs` (Match coexistence) doesn't
//! pin:
//!
//! - `Host !pattern` (negation) coexists with the sshenc
//!   install block — ssh's config parser accepts negated
//!   patterns, and `ssh -G` against a non-negated host should
//!   still resolve sshenc's IdentityAgent.
//! - `Host pat1 pat2 pat3` (multi-pattern Host line) coexists
//!   with the install block; user host blocks with multiple
//!   space-separated patterns survive intact and `ssh -G`
//!   parses cleanly.

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

/// `sshenc install` on a config that contains a `Host !pattern`
/// negation directive produces a parseable result.
#[test]
#[ignore = "requires docker"]
fn install_coexists_with_host_negation_pattern() {
    if skip_if_no_docker("install_coexists_with_host_negation_pattern") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    std::fs::create_dir_all(env.ssh_dir()).expect("mkdir ssh dir");

    let pre = "\
Host !ignored.example.com *
    ServerAliveInterval 60

Host github.com
    User git
";
    let config = env.ssh_dir().join("config");
    std::fs::write(&config, pre).expect("write config");

    let install =
        run(env.sshenc_cmd().expect("sshenc cmd").arg("install")).expect("sshenc install");
    assert!(install.succeeded(), "install: {}", install.stderr);

    let probe = run(env
        .scrubbed_command("ssh")
        .arg("-F")
        .arg(&config)
        .arg("-G")
        .arg("github.com"))
    .expect("ssh -G");
    assert!(
        probe.succeeded(),
        "ssh -G failed against post-install config with Host negation; stderr:\n{}",
        probe.stderr
    );
    let lower = probe.stdout.to_lowercase();
    assert!(
        lower.contains("identityagent"),
        "ssh -G should mention identityagent for non-negated host; got:\n{}",
        probe.stdout
    );

    let after = std::fs::read_to_string(&config).expect("read after");
    assert!(
        after.contains("Host !ignored.example.com *"),
        "user Host negation line was disturbed; config now:\n{after}"
    );
    assert!(
        after.contains("BEGIN sshenc managed block"),
        "sshenc block missing after install; config now:\n{after}"
    );

    drop(std::fs::remove_file(env.socket_path()));
}

/// `sshenc install` on a config containing a `Host pat1 pat2`
/// multi-pattern line preserves the line and produces a
/// parseable result.
#[test]
#[ignore = "requires docker"]
fn install_coexists_with_multipattern_host_line() {
    if skip_if_no_docker("install_coexists_with_multipattern_host_line") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    std::fs::create_dir_all(env.ssh_dir()).expect("mkdir ssh dir");

    let pre = "\
Host github.com gitlab.com bitbucket.org
    User git
    IdentitiesOnly yes
";
    let config = env.ssh_dir().join("config");
    std::fs::write(&config, pre).expect("write config");

    let install =
        run(env.sshenc_cmd().expect("sshenc cmd").arg("install")).expect("sshenc install");
    assert!(install.succeeded(), "install: {}", install.stderr);

    // Verify each pattern still resolves after install.
    for host in ["github.com", "gitlab.com", "bitbucket.org"] {
        let probe = run(env
            .scrubbed_command("ssh")
            .arg("-F")
            .arg(&config)
            .arg("-G")
            .arg(host))
        .expect("ssh -G");
        assert!(
            probe.succeeded(),
            "ssh -G failed for {host} after install; stderr:\n{}",
            probe.stderr
        );
        let lower = probe.stdout.to_lowercase();
        assert!(
            lower.contains("user git"),
            "expected user-git from multi-pattern Host block for {host}; got:\n{}",
            probe.stdout
        );
        assert!(
            lower.contains("identityagent"),
            "ssh -G should mention identityagent for {host}; got:\n{}",
            probe.stdout
        );
    }

    let after = std::fs::read_to_string(&config).expect("read after");
    assert!(
        after.contains("Host github.com gitlab.com bitbucket.org"),
        "multi-pattern Host line was disturbed; config now:\n{after}"
    );

    drop(std::fs::remove_file(env.socket_path()));
}
