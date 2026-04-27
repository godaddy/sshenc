// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `scp` flag combinations that the existing
//! `output_stability_and_shell_tools.rs` happy-path doesn't
//! cover:
//!
//! - `scp -p` preserves the source file's permission bits
//!   when uploading through the sshenc-managed SSH path.
//! - `scp -r` recursively copies a local directory tree into
//!   the remote, all files arriving intact.
//!
//! Both pin that flag forwarding through `sshenc ssh` doesn't
//! drop options before scp's argument parser sees them.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{docker_skip_reason, run, shared_enclave_pubkey, SshdContainer, SshencEnv};
use std::os::unix::fs::PermissionsExt;

fn skip_if_no_docker(test_name: &str) -> bool {
    if let Some(reason) = docker_skip_reason() {
        eprintln!("skip {test_name}: {reason}");
        return true;
    }
    false
}

/// `scp -p` preserves source permission bits across the upload.
#[test]
#[ignore = "requires docker"]
fn scp_preserve_keeps_source_mode() {
    if skip_if_no_docker("scp_preserve_keeps_source_mode") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let container = SshdContainer::start(&[&enclave]).expect("sshd");

    // Source file with a distinctive mode (0o640).
    let src = env.home().join("preserve-mode.txt");
    std::fs::write(&src, b"preserve me\n").expect("write src");
    std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o640)).expect("chmod 640 src");

    let scp = run(env
        .scrubbed_command("scp")
        .arg("-p")
        .arg("-P")
        .arg(container.host_port.to_string())
        .arg("-o")
        .arg("StrictHostKeyChecking=accept-new")
        .arg("-o")
        .arg(format!(
            "UserKnownHostsFile={}",
            env.known_hosts().display()
        ))
        .arg("-o")
        .arg(format!("IdentityAgent={}", env.socket_path().display()))
        .arg("-o")
        .arg("ConnectTimeout=10")
        .arg(&src)
        .arg("sshtest@127.0.0.1:/home/sshtest/preserve-mode.txt"))
    .expect("scp -p");
    assert!(scp.succeeded(), "scp -p failed: {}", scp.stderr);

    // Read back the remote file's mode via SSH stat.
    let stat = run(env
        .ssh_cmd(&container)
        .arg("-o")
        .arg(format!("IdentityAgent={}", env.socket_path().display()))
        .arg("sshtest@127.0.0.1")
        .arg("stat -c '%a' /home/sshtest/preserve-mode.txt"))
    .expect("stat remote");
    assert!(stat.succeeded(), "ssh stat: {}", stat.stderr);
    assert_eq!(
        stat.stdout.trim(),
        "640",
        "remote mode should be 640 with -p; got:\n{}",
        stat.stdout
    );
}

/// `scp -r` recursively copies a directory tree.
#[test]
#[ignore = "requires docker"]
fn scp_recursive_copies_tree() {
    if skip_if_no_docker("scp_recursive_copies_tree") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let container = SshdContainer::start(&[&enclave]).expect("sshd");

    // Build a small local tree.
    let tree = env.home().join("scp-tree");
    let nested = tree.join("nested");
    std::fs::create_dir_all(&nested).expect("mkdir tree");
    std::fs::write(tree.join("a.txt"), b"a\n").expect("write a");
    std::fs::write(nested.join("b.txt"), b"b\n").expect("write b");
    std::fs::write(nested.join("c.txt"), b"c\n").expect("write c");

    let scp = run(env
        .scrubbed_command("scp")
        .arg("-r")
        .arg("-P")
        .arg(container.host_port.to_string())
        .arg("-o")
        .arg("StrictHostKeyChecking=accept-new")
        .arg("-o")
        .arg(format!(
            "UserKnownHostsFile={}",
            env.known_hosts().display()
        ))
        .arg("-o")
        .arg(format!("IdentityAgent={}", env.socket_path().display()))
        .arg("-o")
        .arg("ConnectTimeout=10")
        .arg(&tree)
        .arg("sshtest@127.0.0.1:/home/sshtest/"))
    .expect("scp -r");
    assert!(scp.succeeded(), "scp -r failed: {}", scp.stderr);

    // Verify the tree landed on the remote.
    let listing = run(env
        .ssh_cmd(&container)
        .arg("-o")
        .arg(format!("IdentityAgent={}", env.socket_path().display()))
        .arg("sshtest@127.0.0.1")
        .arg("find /home/sshtest/scp-tree -type f | sort"))
    .expect("ssh find");
    assert!(listing.succeeded(), "ssh find: {}", listing.stderr);
    let lines: Vec<&str> = listing.stdout.lines().collect();
    assert_eq!(
        lines,
        [
            "/home/sshtest/scp-tree/a.txt",
            "/home/sshtest/scp-tree/nested/b.txt",
            "/home/sshtest/scp-tree/nested/c.txt",
        ],
        "remote tree mismatch; got:\n{}",
        listing.stdout
    );
}
