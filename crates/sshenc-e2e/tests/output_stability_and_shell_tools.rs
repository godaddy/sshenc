// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Three coverage gaps grouped because they all probe the
//! "external script / standard tool can drive sshenc" surface:
//!
//! 1. **Human-readable list/inspect/export-pub output stability**.
//!    `json_output_stability.rs` pins the JSON contract; nothing
//!    pinned the human-readable labels (`Algorithm:`, `SHA256:`,
//!    etc.) that some users grep/awk against. Renaming a label
//!    silently breaks those scripts.
//!
//! 2. **scp / sftp / rsync over an sshenc-managed agent**.
//!    `lib.rs` exposes `scp_cmd` / `sftp_cmd` helpers, but no test
//!    actually exercises them. These tools all spawn ssh under the
//!    hood; if sshenc's IdentityAgent injection regresses for any
//!    of them, file copy stops working and we wouldn't notice.
//!
//! 3. **ssh-copy-id with `-i <path>` pointing at a sshenc pubkey**.
//!    The standard install flow for a fresh key. The `.pub` lives
//!    under `~/.ssh/<label>.pub`; ssh-copy-id reads it, sshes to
//!    the target with our agent, appends to authorized_keys.

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

// ----- Output-stability tests -----

/// `sshenc list` (no --json) emits the documented labels in the
/// human-readable output. Pin the labels so a renaming PR has to
/// either bump the test or update the docs.
#[test]
#[ignore = "requires docker"]
fn list_human_readable_labels_are_stable() {
    if skip_if_no_docker("list_human_readable_labels_are_stable") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("warm shared key"));

    let listed = run(env.sshenc_cmd().expect("sshenc cmd").arg("list")).expect("sshenc list");
    assert!(listed.succeeded(), "sshenc list: {}", listed.stderr);

    // Documented labels (per `commands::list`). These are the
    // strings external scripts grep for.
    for needle in [
        "Algorithm:",
        "Key size:",
        "User presence:",
        "App tag:",
        "SHA256:",
        "MD5:",
    ] {
        assert!(
            listed.stdout.contains(needle),
            "list output missing documented label '{needle}'; got:\n{}",
            listed.stdout
        );
    }
    // Trailing summary line.
    assert!(
        listed.stdout.contains("key(s) found."),
        "list output missing summary line; got:\n{}",
        listed.stdout
    );
}

/// `sshenc inspect <label>` (no --json) emits the documented
/// labels. Inspect's set is a superset of list's plus per-key
/// detail.
#[test]
#[ignore = "requires docker"]
fn inspect_human_readable_labels_are_stable() {
    if skip_if_no_docker("inspect_human_readable_labels_are_stable") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("warm shared key"));

    let out = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["inspect", "e2e-shared"]))
    .expect("sshenc inspect");
    assert!(out.succeeded(), "sshenc inspect: {}", out.stderr);

    for needle in [
        "Key:",
        "Algorithm:",
        "Key size:",
        "Curve:",
        "SSH key type:",
        "User presence:",
        "Application tag:",
        "SHA256:",
        "MD5:",
    ] {
        assert!(
            out.stdout.contains(needle),
            "inspect output missing documented label '{needle}'; got:\n{}",
            out.stdout
        );
    }
}

/// `sshenc export-pub <label>` (no --json, no --fingerprint) emits
/// the OpenSSH single-line format (algo + base64 + comment) — the
/// shape ssh-copy-id, GitHub, GitLab, and friends parse. Pin the
/// algorithm prefix and the line shape.
#[test]
#[ignore = "requires docker"]
fn export_pub_emits_openssh_single_line() {
    if skip_if_no_docker("export_pub_emits_openssh_single_line") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("warm shared key"));

    let out = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["export-pub", "e2e-shared"]))
    .expect("sshenc export-pub");
    assert!(out.succeeded(), "export-pub: {}", out.stderr);

    let line = out.stdout.trim();
    let fields: Vec<&str> = line.split_whitespace().collect();
    assert!(
        fields.len() >= 2,
        "export-pub output not in 'algo base64 [comment]' shape: {line}"
    );
    assert_eq!(
        fields[0], "ecdsa-sha2-nistp256",
        "export-pub algo prefix changed; got: {line}"
    );
    // The base64 body should be syntactically plausible (ASCII,
    // long enough to encode a P-256 pubkey).
    assert!(
        fields[1].len() > 80,
        "export-pub body suspiciously short: '{}' in {line}",
        fields[1]
    );
}

// ----- scp / sftp / ssh-copy-id tests -----

/// scp through an sshenc-managed agent succeeds. If the harness's
/// `scp_cmd` helper or the underlying IdentityAgent injection
/// breaks, scp fails publickey auth and we'd silently lose the
/// "copy a file via sshenc" workflow.
#[test]
#[ignore = "requires docker"]
fn scp_uploads_file_via_sshenc_agent() {
    if skip_if_no_docker("scp_uploads_file_via_sshenc_agent") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");

    let container = SshdContainer::start(&[&enclave]).expect("sshd");

    let local_file = env.home().join("scp-payload.txt");
    std::fs::write(&local_file, b"scp payload\n").expect("write local file");

    let mut cmd = env.scp_cmd(&container);
    cmd.arg("-o")
        .arg(format!("IdentityAgent={}", env.socket_path().display()))
        .arg(&local_file)
        .arg("sshtest@127.0.0.1:/tmp/scp-payload.txt");
    let outcome = run(&mut cmd).expect("scp");
    assert!(
        outcome.succeeded(),
        "scp via sshenc agent failed; stderr:\n{}",
        outcome.stderr
    );

    // Verify the file landed on the remote.
    let read_back = run(env
        .ssh_cmd(&container)
        .arg("-o")
        .arg(format!("IdentityAgent={}", env.socket_path().display()))
        .arg("sshtest@127.0.0.1")
        .arg("cat /tmp/scp-payload.txt"))
    .expect("ssh cat");
    assert!(read_back.succeeded(), "remote cat: {}", read_back.stderr);
    assert!(
        read_back.stdout.contains("scp payload"),
        "remote file content mismatch; got:\n{}",
        read_back.stdout
    );
}

/// sftp batch mode (`-b -`) through the sshenc agent uploads a
/// file. sftp uses the same SSH-2 subsystem channel as scp's
/// `-O`-disabled mode, but the auth path is shared; if it
/// regresses we want the signal here.
#[test]
#[ignore = "requires docker"]
fn sftp_batch_upload_via_sshenc_agent() {
    if skip_if_no_docker("sftp_batch_upload_via_sshenc_agent") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");

    let container = SshdContainer::start(&[&enclave]).expect("sshd");

    let local = env.home().join("sftp-upload.bin");
    std::fs::write(&local, b"sftp batch payload\n").expect("write local");

    let batch = env.home().join("sftp-batch.txt");
    std::fs::write(
        &batch,
        format!(
            "put {local} /tmp/sftp-upload.bin\nquit\n",
            local = local.display()
        ),
    )
    .expect("write batch");

    let mut cmd = env.sftp_cmd(&container);
    cmd.arg("-o")
        .arg(format!("IdentityAgent={}", env.socket_path().display()))
        .arg("-b")
        .arg(&batch)
        .arg("sshtest@127.0.0.1");
    let outcome = run(&mut cmd).expect("sftp");
    assert!(
        outcome.succeeded(),
        "sftp via sshenc agent failed; stderr:\n{}",
        outcome.stderr
    );

    let read_back = run(env
        .ssh_cmd(&container)
        .arg("-o")
        .arg(format!("IdentityAgent={}", env.socket_path().display()))
        .arg("sshtest@127.0.0.1")
        .arg("cat /tmp/sftp-upload.bin"))
    .expect("ssh cat");
    assert!(read_back.succeeded(), "remote cat: {}", read_back.stderr);
    assert!(
        read_back.stdout.contains("sftp batch payload"),
        "remote file content mismatch; got:\n{}",
        read_back.stdout
    );
}

/// `ssh-copy-id -i <path>/<label>.pub` reads our exported pubkey
/// and appends it to a remote `~/.ssh/authorized_keys` over an
/// sshenc-mediated SSH connection. Standard fresh-key install
/// flow. We seed the remote with the shared key already so the
/// initial ssh authenticates; the test verifies a SECOND key gets
/// appended via ssh-copy-id (i.e., the "I want to add this new
/// pubkey to my existing authorized hosts" workflow).
#[test]
#[ignore = "requires docker"]
fn ssh_copy_id_appends_sshenc_pubkey_to_authorized_keys() {
    if skip_if_no_docker("ssh_copy_id_appends_sshenc_pubkey_to_authorized_keys") {
        return;
    }
    if !sshenc_e2e::extended_enabled() && !sshenc_e2e::software_mode() {
        eprintln!("skip: needs to mint a second key");
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");

    // Container's authorized_keys starts with ONLY the shared key.
    let container = SshdContainer::start(&[&enclave]).expect("sshd");

    // Mint a SECOND key whose pubkey we'll have ssh-copy-id append.
    let label = format!(
        "copy-id-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
    );
    let kg = run(env.sshenc_cmd().expect("sshenc cmd").args([
        "keygen",
        "--label",
        &label,
        "--auth-policy",
        "none",
        "--no-pub-file",
    ]))
    .expect("keygen second");
    assert!(kg.succeeded(), "keygen: {}", kg.stderr);
    let second_pub_path = env.ssh_dir().join(format!("{label}.pub"));
    let exported = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["export-pub", &label]))
    .expect("export-pub");
    assert!(exported.succeeded(), "export-pub: {}", exported.stderr);
    std::fs::create_dir_all(env.ssh_dir()).expect("mkdir ssh dir");
    std::fs::write(&second_pub_path, &exported.stdout).expect("write second pub");

    // Run ssh-copy-id. ssh-copy-id is a shell script that wraps
    // ssh; it picks up SSH_AUTH_SOCK / IdentityAgent indirectly
    // when it spawns ssh. We have to pass standard ssh isolation
    // flags via `-o` (ssh-copy-id forwards `-o` to ssh).
    // ssh-copy-id by default expects both <path> and <path>.pub
    // (the private+public pair). Hardware-backed keys have no
    // private file, so -f tells ssh-copy-id to install the .pub
    // anyway. Documented escape hatch and the only sensible flag
    // for sshenc-style setups.
    let mut cmd = env.scrubbed_command("ssh-copy-id");
    cmd.arg("-f")
        .arg("-i")
        .arg(&second_pub_path)
        .arg("-p")
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
        .arg("PreferredAuthentications=publickey")
        .arg("-o")
        .arg("ConnectTimeout=10")
        .arg("sshtest@127.0.0.1");
    let outcome = run(&mut cmd).expect("ssh-copy-id");
    assert!(
        outcome.succeeded(),
        "ssh-copy-id failed; stdout:\n{}\nstderr:\n{}",
        outcome.stdout,
        outcome.stderr
    );

    // Verify the authorized_keys on the remote now contains the
    // second pubkey (in addition to the original shared one).
    let read_back = run(env
        .ssh_cmd(&container)
        .arg("-o")
        .arg(format!("IdentityAgent={}", env.socket_path().display()))
        .arg("sshtest@127.0.0.1")
        .arg("cat /home/sshtest/.ssh/authorized_keys"))
    .expect("ssh cat authorized_keys");
    assert!(read_back.succeeded(), "remote cat: {}", read_back.stderr);

    let new_body = exported
        .stdout
        .split_whitespace()
        .nth(1)
        .expect("exported body")
        .to_string();
    assert!(
        read_back.stdout.contains(&new_body),
        "second pubkey body not in remote authorized_keys; got:\n{}",
        read_back.stdout
    );

    // Cleanup the second key.
    drop(run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["delete", &label, "-y"])));
}

/// `ssh-copy-id -n -i <path>/<label>.pub` (dry-run mode) prints
/// what it *would* install but doesn't actually mutate the
/// remote's authorized_keys.
#[test]
#[ignore = "requires docker"]
fn ssh_copy_id_dry_run_does_not_mutate_remote() {
    if skip_if_no_docker("ssh_copy_id_dry_run_does_not_mutate_remote") {
        return;
    }
    if !sshenc_e2e::extended_enabled() && !sshenc_e2e::software_mode() {
        eprintln!("skip: needs to mint a second key");
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");

    let container = SshdContainer::start(&[&enclave]).expect("sshd");

    // Mint a second key for dry-run.
    let label = format!(
        "copy-id-dryrun-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
    );
    let kg = run(env.sshenc_cmd().expect("sshenc cmd").args([
        "keygen",
        "--label",
        &label,
        "--auth-policy",
        "none",
        "--no-pub-file",
    ]))
    .expect("keygen second");
    assert!(kg.succeeded(), "keygen: {}", kg.stderr);
    let second_pub_path = env.ssh_dir().join(format!("{label}.pub"));
    let exported = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["export-pub", &label]))
    .expect("export-pub");
    assert!(exported.succeeded(), "export-pub: {}", exported.stderr);
    std::fs::create_dir_all(env.ssh_dir()).expect("mkdir ssh dir");
    std::fs::write(&second_pub_path, &exported.stdout).expect("write second pub");

    // Snapshot remote authorized_keys before the dry-run.
    let before = run(env
        .ssh_cmd(&container)
        .arg("-o")
        .arg(format!("IdentityAgent={}", env.socket_path().display()))
        .arg("sshtest@127.0.0.1")
        .arg("cat /home/sshtest/.ssh/authorized_keys"))
    .expect("cat before");
    assert!(before.succeeded(), "cat before: {}", before.stderr);

    // Run ssh-copy-id with -n (dry-run).
    let mut cmd = env.scrubbed_command("ssh-copy-id");
    cmd.arg("-n")
        .arg("-f")
        .arg("-i")
        .arg(&second_pub_path)
        .arg("-p")
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
        .arg("PreferredAuthentications=publickey")
        .arg("-o")
        .arg("ConnectTimeout=10")
        .arg("sshtest@127.0.0.1");
    let outcome = run(&mut cmd).expect("ssh-copy-id -n");
    assert!(
        outcome.succeeded(),
        "ssh-copy-id -n failed; stdout:\n{}\nstderr:\n{}",
        outcome.stdout,
        outcome.stderr
    );

    // The remote authorized_keys must be unchanged.
    let after = run(env
        .ssh_cmd(&container)
        .arg("-o")
        .arg(format!("IdentityAgent={}", env.socket_path().display()))
        .arg("sshtest@127.0.0.1")
        .arg("cat /home/sshtest/.ssh/authorized_keys"))
    .expect("cat after");
    assert!(after.succeeded(), "cat after: {}", after.stderr);
    assert_eq!(
        before.stdout, after.stdout,
        "remote authorized_keys was modified despite ssh-copy-id -n (dry-run); \
         before:\n{}\nafter:\n{}",
        before.stdout, after.stdout
    );

    // Cleanup.
    drop(run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .args(["delete", &label, "-y"])));
}
