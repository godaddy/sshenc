// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `rsync -av --delete -e "sshenc ssh ..."` synchronizes a
//! local source tree to a remote target, deleting any extra
//! files on the remote side. The basic rsync-over-sshenc case
//! is covered in `ssh_functions.rs`; this pins the metadata-
//! preserving (`-a`) and delete-extra (`--delete`) variants.

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

/// `rsync -av --delete` over sshenc syncs a local tree and
/// prunes extras on the remote.
#[test]
#[ignore = "requires docker"]
fn rsync_archive_with_delete_syncs_and_prunes() {
    if skip_if_no_docker("rsync_archive_with_delete_syncs_and_prunes") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let container = SshdContainer::start(&[&enclave]).expect("sshd");

    // Source tree on local side.
    let src = env.home().join("rsync-src");
    std::fs::create_dir_all(src.join("nested")).expect("mkdir src/nested");
    std::fs::write(src.join("a.txt"), b"alpha\n").expect("write a");
    std::fs::write(src.join("nested/b.txt"), b"beta\n").expect("write b");

    // Pre-populate the remote target with an EXTRA file that should
    // be deleted by --delete.
    drop(run(env
        .ssh_cmd(&container)
        .arg("-o")
        .arg(format!("IdentityAgent={}", env.socket_path().display()))
        .arg("sshtest@127.0.0.1")
        .arg(
            "mkdir -p /home/sshtest/rsync-dst && \
              echo extra > /home/sshtest/rsync-dst/zz-extra.txt",
        )));

    // sshenc ssh wrapper string for rsync's -e.
    let known = env.known_hosts().display().to_string();
    let socket = env.socket_path().display().to_string();
    let port = container.host_port;
    let rsh = format!(
        "sshenc ssh -F /dev/null \
         -o StrictHostKeyChecking=accept-new \
         -o UserKnownHostsFile={known} \
         -o IdentityAgent={socket} \
         -o ConnectTimeout=10 \
         -o PreferredAuthentications=publickey \
         -p {port}"
    );

    let outcome = run(env
        .scrubbed_command("rsync")
        .arg("-av")
        .arg("--delete")
        .arg("-e")
        .arg(&rsh)
        .arg(format!("{}/", src.display()))
        .arg("sshtest@127.0.0.1:/home/sshtest/rsync-dst/"))
    .expect("rsync");
    assert!(
        outcome.succeeded(),
        "rsync -av --delete failed; stdout:\n{}\nstderr:\n{}",
        outcome.stdout,
        outcome.stderr
    );

    // Remote tree should now mirror the source: a.txt and nested/b.txt
    // present, zz-extra.txt gone.
    let listing = run(env
        .ssh_cmd(&container)
        .arg("-o")
        .arg(format!("IdentityAgent={}", env.socket_path().display()))
        .arg("sshtest@127.0.0.1")
        .arg("find /home/sshtest/rsync-dst -type f | sort"))
    .expect("ssh find");
    assert!(listing.succeeded(), "ssh find: {}", listing.stderr);
    let lines: Vec<&str> = listing.stdout.lines().collect();
    assert_eq!(
        lines,
        [
            "/home/sshtest/rsync-dst/a.txt",
            "/home/sshtest/rsync-dst/nested/b.txt",
        ],
        "remote tree mismatch after --delete; got:\n{}",
        listing.stdout
    );
}
