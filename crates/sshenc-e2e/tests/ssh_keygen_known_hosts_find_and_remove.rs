// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `ssh-keygen -F <host>` (find host in known_hosts) and
//! `ssh-keygen -R <host>` (remove host) interact correctly with
//! a known_hosts file populated by `ssh-keyscan` against the
//! sshenc test container. Pin that the standard known_hosts
//! management tooling works alongside the rest of the harness.

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

fn populate_known_hosts(env: &SshencEnv, container: &SshdContainer, kh: &std::path::Path) {
    let scan = run(env
        .scrubbed_command("ssh-keyscan")
        .arg("-p")
        .arg(container.host_port.to_string())
        .arg("127.0.0.1"))
    .expect("ssh-keyscan");
    assert!(scan.succeeded(), "ssh-keyscan: {}", scan.stderr);
    std::fs::write(kh, &scan.stdout).expect("write known_hosts");
}

/// `ssh-keygen -F [127.0.0.1]:<port>` finds the entry that
/// `ssh-keyscan` populated.
#[test]
#[ignore = "requires docker"]
fn ssh_keygen_dash_f_finds_host_in_known_hosts() {
    if skip_if_no_docker("ssh_keygen_dash_f_finds_host_in_known_hosts") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let container = SshdContainer::start(&[&enclave]).expect("sshd");

    let kh = env.home().join("kh-find");
    populate_known_hosts(&env, &container, &kh);

    let host_form = format!("[127.0.0.1]:{}", container.host_port);
    let find = run(env
        .scrubbed_command("ssh-keygen")
        .arg("-F")
        .arg(&host_form)
        .arg("-f")
        .arg(&kh))
    .expect("ssh-keygen -F");
    assert!(
        find.succeeded(),
        "ssh-keygen -F should succeed when host is present; stdout:\n{}\nstderr:\n{}",
        find.stdout,
        find.stderr
    );
    assert!(
        find.stdout.contains(&host_form) || find.stdout.contains("127.0.0.1"),
        "expected the searched host in -F output; got:\n{}",
        find.stdout
    );
}

/// `ssh-keygen -R <host>` removes an entry; subsequent -F
/// against the same host fails (no match).
#[test]
#[ignore = "requires docker"]
fn ssh_keygen_dash_r_removes_host_from_known_hosts() {
    if skip_if_no_docker("ssh_keygen_dash_r_removes_host_from_known_hosts") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let container = SshdContainer::start(&[&enclave]).expect("sshd");

    let kh = env.home().join("kh-remove");
    populate_known_hosts(&env, &container, &kh);

    let host_form = format!("[127.0.0.1]:{}", container.host_port);
    let remove = run(env
        .scrubbed_command("ssh-keygen")
        .arg("-R")
        .arg(&host_form)
        .arg("-f")
        .arg(&kh))
    .expect("ssh-keygen -R");
    assert!(
        remove.succeeded(),
        "ssh-keygen -R failed: stdout:\n{}\nstderr:\n{}",
        remove.stdout,
        remove.stderr
    );

    let find_after = run(env
        .scrubbed_command("ssh-keygen")
        .arg("-F")
        .arg(&host_form)
        .arg("-f")
        .arg(&kh))
    .expect("ssh-keygen -F post-remove");
    assert!(
        !find_after.succeeded(),
        "ssh-keygen -F should fail (exit !=0) after -R; stdout:\n{}\nstderr:\n{}",
        find_after.stdout,
        find_after.stderr
    );
}
