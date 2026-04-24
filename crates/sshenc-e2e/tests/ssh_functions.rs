// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Extended sshenc e2e coverage beyond the drop-in authentication claim.
//!
//! These scenarios exercise the rest of the sshenc surface against a
//! containerized OpenSSH server: scp/sftp data transfers, ssh port and
//! agent forwarding, `sshenc -Y sign` signature production and
//! verification, the ssh-agent protocol (`ssh-add -l`), and concurrent
//! signing.
//!
//! All tests are `#[ignore]` by default:
//!
//! ```text
//! cargo test -p sshenc-e2e -- --ignored --test-threads=1
//! ```
//!
//! None of these scenarios generate additional enclave keys on macOS:
//! they all reuse the shared `e2e-shared` key. Extended scenarios that
//! need fresh keys live in `tests/extended.rs` and are opt-in.

#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{
    docker_skip_reason, generate_on_disk_ed25519, generate_on_disk_key, pick_free_port, run,
    shared_enclave_pubkey, OnDiskKeyKind, SshdContainer, SshencEnv,
};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

fn skip_if_no_docker(test_name: &str) -> bool {
    if let Some(reason) = docker_skip_reason() {
        eprintln!("skip {test_name}: {reason}");
        return true;
    }
    false
}

/// Common setup used by most scenarios: an env with the shared enclave
/// key, an on-disk key, the agent running, and a container trusting the
/// enclave pubkey. Returns both keys' pubkey lines plus the container.
fn env_with_enclave_trusted_container() -> (SshencEnv, String, String, SshdContainer) {
    let mut env = SshencEnv::new().expect("env");
    let on_disk = generate_on_disk_ed25519(&env, "on-disk@e2e").expect("on-disk keygen");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("agent start");
    let container = SshdContainer::start(&[&enclave]).expect("sshd container");
    (env, on_disk, enclave, container)
}

/// scp roundtrips a file to/from the container, authenticated via the
/// sshenc agent. Proves that non-interactive channels with data transfer
/// work — signing happens once per connection, the channel stays open
/// long enough to copy bytes, and we can verify byte-for-byte integrity.
#[test]
#[ignore = "requires docker"]
fn scp_roundtrips_file_via_enclave_agent() {
    if skip_if_no_docker("scp_roundtrips_file_via_enclave_agent") {
        return;
    }
    let (env, _on_disk, _enclave, container) = env_with_enclave_trusted_container();

    // Create a local source file with known content.
    let src = env.ssh_dir().join("scp_src.bin");
    let payload: Vec<u8> = (0_u8..=255).cycle().take(4096).collect();
    std::fs::write(&src, &payload).expect("write src");

    // Upload to container home.
    let upload = run(env
        .scp_cmd(&container)
        .arg("-o")
        .arg(format!("IdentityAgent={}", env.socket_path().display()))
        .arg(&src)
        .arg("sshtest@127.0.0.1:/home/sshtest/scp_copy.bin"))
    .expect("scp upload");
    assert!(
        upload.succeeded(),
        "scp upload failed; stderr:\n{}",
        upload.stderr
    );

    // Download to a different local path.
    let dst = env.ssh_dir().join("scp_dst.bin");
    let download = run(env
        .scp_cmd(&container)
        .arg("-o")
        .arg(format!("IdentityAgent={}", env.socket_path().display()))
        .arg("sshtest@127.0.0.1:/home/sshtest/scp_copy.bin")
        .arg(&dst))
    .expect("scp download");
    assert!(
        download.succeeded(),
        "scp download failed; stderr:\n{}",
        download.stderr
    );

    let returned = std::fs::read(&dst).expect("read dst");
    assert_eq!(returned, payload, "scp roundtrip corrupted payload");
}

/// sftp can list the remote home directory. Exercises the SFTP subsystem
/// channel, which is a different code path inside sshd from a plain exec
/// channel.
#[test]
#[ignore = "requires docker"]
fn sftp_lists_remote_directory_via_enclave_agent() {
    if skip_if_no_docker("sftp_lists_remote_directory_via_enclave_agent") {
        return;
    }
    let (env, _on_disk, _enclave, container) = env_with_enclave_trusted_container();

    // Plant a file we can expect to see in the listing.
    let src = env.ssh_dir().join("sftp_probe.txt");
    std::fs::write(&src, b"sftp probe").expect("write probe");
    let upload = run(env
        .scp_cmd(&container)
        .arg("-o")
        .arg(format!("IdentityAgent={}", env.socket_path().display()))
        .arg(&src)
        .arg("sshtest@127.0.0.1:/home/sshtest/sftp_probe.txt"))
    .expect("scp upload");
    assert!(upload.succeeded(), "probe upload failed: {}", upload.stderr);

    // Use sftp batch mode driven by a piped stdin (`-b -` reads commands
    // from stdin). Feed it an `ls` and `exit`, then inspect the output.
    let mut child = env
        .sftp_cmd(&container)
        .arg("-o")
        .arg(format!("IdentityAgent={}", env.socket_path().display()))
        .arg("-b")
        .arg("-")
        .arg("sshtest@127.0.0.1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sftp");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(b"ls /home/sshtest\nexit\n")
        .expect("write sftp commands");
    let output = child.wait_with_output().expect("wait sftp");
    assert!(
        output.status.success(),
        "sftp failed; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("sftp_probe.txt"),
        "expected sftp_probe.txt in listing; got:\n{stdout}"
    );
}

/// `ssh -L` local port forwarding works through the sshenc agent. The
/// tunnel target is the container's own sshd (127.0.0.1:22 inside the
/// container), so connecting to the local listen port and reading the
/// SSH-2.0 banner proves the forward channel is wired end-to-end.
#[test]
#[ignore = "requires docker"]
fn ssh_local_port_forward_through_enclave_agent() {
    if skip_if_no_docker("ssh_local_port_forward_through_enclave_agent") {
        return;
    }
    let (env, _on_disk, _enclave, container) = env_with_enclave_trusted_container();

    let local_port = pick_free_port().expect("pick port");

    // Spawn ssh with -N (no remote command), -L (port forward), and
    // ControlMaster-style daemonized behavior via -f. Use ExitOnForwardFailure
    // so we fail fast if the forward can't be set up.
    let mut cmd = env.ssh_cmd(&container);
    cmd.arg("-N")
        .arg("-f")
        .arg("-o")
        .arg("ExitOnForwardFailure=yes")
        .arg("-o")
        .arg(format!("IdentityAgent={}", env.socket_path().display()))
        .arg("-L")
        .arg(format!("127.0.0.1:{local_port}:127.0.0.1:22"))
        .arg("sshtest@127.0.0.1");
    let outcome = run(&mut cmd).expect("ssh -L");
    assert!(
        outcome.succeeded(),
        "ssh -L failed to establish; stderr:\n{}",
        outcome.stderr
    );

    // Connect to the local end and read the server banner.
    let mut stream = TcpStream::connect(("127.0.0.1", local_port)).expect("connect local");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set timeout");
    let mut buf = [0_u8; 7];
    stream.read_exact(&mut buf).expect("read banner");
    assert_eq!(
        &buf, b"SSH-2.0",
        "expected SSH banner through forward, got {buf:?}"
    );

    // Tear down the backgrounded ssh by killing the control process.
    // `pkill -f` is good enough for a per-test unique forward spec.
    drop(
        Command::new("pkill")
            .arg("-f")
            .arg(format!("127.0.0.1:{local_port}:127.0.0.1:22"))
            .status(),
    );
}

/// `ssh -A` agent forwarding: the forwarded agent inside the container is
/// the host's sshenc-agent. Running `ssh-add -l` on the container should
/// list the enclave key by fingerprint.
#[test]
#[ignore = "requires docker"]
fn ssh_a_forwards_sshenc_agent_to_remote() {
    if skip_if_no_docker("ssh_a_forwards_sshenc_agent_to_remote") {
        return;
    }
    let (env, _on_disk, enclave, container) = env_with_enclave_trusted_container();

    // Run `ssh-add -l` inside the container with the forwarded agent.
    let outcome = run(env
        .ssh_cmd(&container)
        .arg("-A")
        .arg("-o")
        .arg(format!("IdentityAgent={}", env.socket_path().display()))
        .arg("sshtest@127.0.0.1")
        .arg("ssh-add -l"))
    .expect("ssh -A");
    assert!(
        outcome.succeeded(),
        "ssh -A ssh-add -l failed; stderr:\n{}",
        outcome.stderr
    );

    // `ssh-add -l` prints lines like: "256 SHA256:ABC... comment (ECDSA)"
    // We verify by extracting the enclave key's type token ("ECDSA") and
    // checking that it appears in the output. The sshenc agent uses the
    // label as the comment when no explicit comment is set, so the label
    // or its fingerprint will appear too — but looking for "ECDSA" is
    // enough evidence that the forwarded agent served our enclave key.
    assert!(
        outcome.stdout.contains("ECDSA") || outcome.stdout.contains("nistp256"),
        "expected an ECDSA key in forwarded ssh-add -l output; enclave line was:\n{enclave}\n\
         ssh-add -l stdout:\n{}\nstderr:\n{}",
        outcome.stdout,
        outcome.stderr
    );
}

/// `ssh-add -l` directly against the sshenc agent socket enumerates the
/// enclave identities. Proves the sshenc-agent speaks standard OpenSSH
/// agent protocol well enough for `ssh-add` to use it.
#[test]
#[ignore = "requires docker"]
fn ssh_add_l_enumerates_sshenc_agent() {
    if skip_if_no_docker("ssh_add_l_enumerates_sshenc_agent") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared enclave"));
    env.start_agent().expect("agent start");

    let mut cmd = env.scrubbed_command("ssh-add");
    cmd.env("SSH_AUTH_SOCK", env.socket_path());
    cmd.arg("-l");
    let outcome = run(&mut cmd).expect("ssh-add");
    assert!(
        outcome.succeeded(),
        "ssh-add -l failed; stderr:\n{}",
        outcome.stderr
    );
    assert!(
        outcome.stdout.contains("ECDSA") || outcome.stdout.contains("nistp256"),
        "expected enclave identity in ssh-add -l; stdout:\n{}\nstderr:\n{}",
        outcome.stdout,
        outcome.stderr
    );
}

/// `sshenc -Y sign` produces a signature that `ssh-keygen -Y verify`
/// accepts when the signing pubkey is listed in an allowed_signers file.
/// Exercises the commit-signing codepath (same one git drives via
/// `gpg.ssh.program = sshenc`).
#[test]
#[ignore = "requires docker"]
fn sshenc_y_sign_produces_valid_signature() {
    if skip_if_no_docker("sshenc_y_sign_produces_valid_signature") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");

    // ssh-keygen -Y verify needs:
    //   - the pubkey file we signed with (passed to -f during sign)
    //   - an allowed_signers file listing that pubkey under a principal
    //   - the namespace we used at sign time
    //   - the data and the signature (the .sig file written by sign)
    let pubkey_path = env.ssh_dir().join("e2e-shared.pub");
    std::fs::write(&pubkey_path, format!("{enclave}\n")).expect("write pubkey");

    let data_path = env.ssh_dir().join("payload.txt");
    let payload = b"the quick brown fox jumps over the lazy dog\n";
    std::fs::write(&data_path, payload).expect("write payload");

    // sshenc -Y sign -n <namespace> -f <pubkey> <data>
    // writes <data>.sig next to the data file.
    let namespace = "e2e-sign";
    let sign = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .arg("-Y")
        .arg("sign")
        .arg("-n")
        .arg(namespace)
        .arg("-f")
        .arg(&pubkey_path)
        .arg(&data_path))
    .expect("sshenc -Y sign");
    assert!(
        sign.succeeded(),
        "sshenc -Y sign failed; stderr:\n{}",
        sign.stderr
    );

    let sig_path = data_path.with_extension("txt.sig");
    assert!(
        sig_path.exists(),
        "expected {} to exist",
        sig_path.display()
    );

    // Build allowed_signers: "<principal> <pubkey>"
    let allowed = env.ssh_dir().join("allowed_signers");
    std::fs::write(&allowed, format!("e2e@test {enclave}\n")).expect("write allowed_signers");

    // ssh-keygen -Y verify -f <allowed> -I <principal> -n <ns> -s <sig> < <data>
    let mut verify = env.scrubbed_command("ssh-keygen");
    verify
        .arg("-Y")
        .arg("verify")
        .arg("-f")
        .arg(&allowed)
        .arg("-I")
        .arg("e2e@test")
        .arg("-n")
        .arg(namespace)
        .arg("-s")
        .arg(&sig_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = verify.spawn().expect("spawn ssh-keygen");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(payload)
        .expect("write payload");
    let output = child.wait_with_output().expect("wait ssh-keygen");
    assert!(
        output.status.success(),
        "ssh-keygen -Y verify failed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Several ssh invocations in quick succession through the same
/// sshenc-agent must all succeed. Proves the agent serializes signing
/// requests correctly without deadlock, corruption, or dropped
/// connections.
#[test]
#[ignore = "requires docker"]
fn concurrent_ssh_invocations_via_enclave_agent() {
    if skip_if_no_docker("concurrent_ssh_invocations_via_enclave_agent") {
        return;
    }
    let (env, _on_disk, _enclave, container) = env_with_enclave_trusted_container();

    use std::sync::Arc;
    use std::sync::Mutex;
    use std::thread;

    let errors: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let mut handles = Vec::new();
    for i in 0..4 {
        let errors = Arc::clone(&errors);
        let mut cmd = env.ssh_cmd(&container);
        cmd.arg("-o")
            .arg(format!("IdentityAgent={}", env.socket_path().display()))
            .arg("sshtest@127.0.0.1")
            .arg(format!("echo OK_{i}"));
        handles.push(thread::spawn(move || {
            let outcome = cmd.output().expect("spawn ssh");
            if !outcome.status.success() {
                errors.lock().unwrap().push(format!(
                    "worker {i} failed: {}\n{}",
                    outcome.status,
                    String::from_utf8_lossy(&outcome.stderr)
                ));
            } else {
                let stdout = String::from_utf8_lossy(&outcome.stdout);
                if !stdout.contains(&format!("OK_{i}")) {
                    errors
                        .lock()
                        .unwrap()
                        .push(format!("worker {i} stdout mismatch: {stdout}"));
                }
            }
        }));
    }
    for h in handles {
        h.join().expect("worker thread");
    }
    let errors = errors.lock().unwrap();
    assert!(
        errors.is_empty(),
        "concurrent ssh failures:\n{}",
        errors.join("\n")
    );
}

/// `rsync -e ssh` through the sshenc agent.
///
/// Real-world workflow: `rsync -av -e 'ssh …' src/ user@host:dst/`. Proves
/// that rsync's double-ssh invocation (local rsync → ssh child → remote
/// rsync --server) authenticates through the sshenc agent and the ssh
/// client's environment is preserved across the fork.
#[test]
#[ignore = "requires docker"]
fn rsync_over_ssh_via_enclave_agent() {
    if skip_if_no_docker("rsync_over_ssh_via_enclave_agent") {
        return;
    }
    let (env, _on_disk, _enclave, container) = env_with_enclave_trusted_container();

    // Source tree with a couple of files.
    let src = env.home().join("rsync_src");
    std::fs::create_dir_all(&src).expect("mkdir src");
    std::fs::write(src.join("a.txt"), b"alpha\n").expect("write a");
    std::fs::write(src.join("b.bin"), (0_u8..=200).collect::<Vec<u8>>()).expect("write b");
    std::fs::create_dir_all(src.join("nested")).expect("mkdir nested");
    std::fs::write(src.join("nested/c.txt"), b"gamma\n").expect("write c");

    let ssh_cmd = format!(
        "ssh -F /dev/null -o Port={port} -o StrictHostKeyChecking=accept-new \
         -o UserKnownHostsFile={known} -o ConnectTimeout=10 \
         -o NumberOfPasswordPrompts=0 -o PreferredAuthentications=publickey \
         -o IdentityAgent={sock}",
        port = container.host_port,
        known = env.known_hosts().display(),
        sock = env.socket_path().display(),
    );

    // Upload.
    let up = run(env
        .scrubbed_command("rsync")
        .arg("-av")
        .arg("-e")
        .arg(&ssh_cmd)
        .arg(format!("{}/", src.display()))
        .arg("sshtest@127.0.0.1:/home/sshtest/rsync_dst/"))
    .expect("rsync upload");
    assert!(
        up.succeeded(),
        "rsync upload failed; stdout:\n{}\nstderr:\n{}",
        up.stdout,
        up.stderr
    );

    // Download to a new local path and compare.
    let back = env.home().join("rsync_back");
    std::fs::create_dir_all(&back).expect("mkdir back");
    let down = run(env
        .scrubbed_command("rsync")
        .arg("-av")
        .arg("-e")
        .arg(&ssh_cmd)
        .arg("sshtest@127.0.0.1:/home/sshtest/rsync_dst/")
        .arg(format!("{}/", back.display())))
    .expect("rsync download");
    assert!(
        down.succeeded(),
        "rsync download failed; stderr:\n{}",
        down.stderr
    );

    assert_eq!(
        std::fs::read(back.join("a.txt")).expect("read a"),
        b"alpha\n"
    );
    assert_eq!(
        std::fs::read(back.join("b.bin")).expect("read b"),
        (0_u8..=200).collect::<Vec<u8>>()
    );
    assert_eq!(
        std::fs::read(back.join("nested/c.txt")).expect("read c"),
        b"gamma\n"
    );
}

/// Existing on-disk RSA keys continue to authenticate when sshenc-agent
/// is in the picture. Proves drop-in compatibility for the most common
/// legacy enterprise key type.
#[test]
#[ignore = "requires docker"]
fn on_disk_rsa_key_still_works_with_sshenc_agent() {
    on_disk_legacy_key_works(OnDiskKeyKind::Rsa, "on-disk-rsa@e2e");
}

/// Existing on-disk ECDSA keys continue to authenticate when sshenc-agent
/// is in the picture. Separate from the RSA case because ECDSA and RSA
/// traverse different client-side negotiation paths.
#[test]
#[ignore = "requires docker"]
fn on_disk_ecdsa_key_still_works_with_sshenc_agent() {
    on_disk_legacy_key_works(OnDiskKeyKind::Ecdsa, "on-disk-ecdsa@e2e");
}

fn on_disk_legacy_key_works(kind: OnDiskKeyKind, comment: &str) {
    let tag = kind.default_filename();
    if skip_if_no_docker(tag) {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    env.use_ephemeral_keys_dir().expect("ephemeral keys dir");
    let pubkey = generate_on_disk_key(&env, kind, comment).expect("on-disk keygen");
    env.start_agent().expect("agent start");
    let container = SshdContainer::start(&[&pubkey]).expect("sshd container");

    let outcome = run(env
        .ssh_cmd(&container)
        .arg("-o")
        .arg(format!("IdentityAgent={}", env.socket_path().display()))
        .arg("-i")
        .arg(env.ssh_dir().join(kind.default_filename()))
        .arg("sshtest@127.0.0.1")
        .arg("true"))
    .expect("ssh");
    assert!(
        outcome.succeeded(),
        "{tag}: expected ssh to succeed; stderr:\n{}",
        outcome.stderr
    );
}

/// Exit codes from the remote command must reach the local caller.
///
/// `sshenc ssh host 'exit 42'` must exit 42. Critical for CI/build
/// scripts that rely on SSH exit codes for flow control.
#[test]
#[ignore = "requires docker"]
fn exit_code_propagates_through_sshenc_ssh() {
    if skip_if_no_docker("exit_code_propagates_through_sshenc_ssh") {
        return;
    }
    let (env, _on_disk, _enclave, container) = env_with_enclave_trusted_container();

    for expected in [0, 1, 17, 42, 127] {
        let mut cmd = env.sshenc_cmd().expect("sshenc cmd");
        cmd.arg("ssh").arg("--");
        SshencEnv::apply_ssh_isolation(&mut cmd, container.host_port, &env.known_hosts());
        cmd.arg("-o")
            .arg(format!("IdentityAgent={}", env.socket_path().display()))
            .arg("sshtest@127.0.0.1")
            .arg(format!("exit {expected}"));
        let outcome = run(&mut cmd).expect("sshenc ssh");
        assert_eq!(
            outcome.status.code(),
            Some(expected),
            "exit {expected}: expected code {expected}, got {:?}; stderr:\n{}",
            outcome.status.code(),
            outcome.stderr
        );
    }
}

/// Binary-safe stdin/stdout piping through `sshenc ssh host 'cat'`.
///
/// Many admin workflows pipe binary data through ssh (tar, dd, compression
/// streams). This verifies the channel does not mangle bytes — no CR/LF
/// translation, no truncation on null bytes, no local buffering quirks.
#[test]
#[ignore = "requires docker"]
fn stdin_stdout_binary_roundtrip_via_sshenc_ssh() {
    if skip_if_no_docker("stdin_stdout_binary_roundtrip_via_sshenc_ssh") {
        return;
    }
    let (env, _on_disk, _enclave, container) = env_with_enclave_trusted_container();

    // Build a 16 KiB payload that spans the full byte range and includes
    // NUL, CR, LF specifically so we catch the common breakage modes.
    let mut payload = Vec::with_capacity(16 * 1024);
    for i in 0..16 * 1024_usize {
        payload.push((i % 256) as u8);
    }

    let mut cmd = env.sshenc_cmd().expect("sshenc cmd");
    cmd.arg("ssh").arg("--");
    SshencEnv::apply_ssh_isolation(&mut cmd, container.host_port, &env.known_hosts());
    cmd.arg("-o")
        .arg(format!("IdentityAgent={}", env.socket_path().display()))
        .arg("sshtest@127.0.0.1")
        .arg("cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn ssh");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(&payload)
        .expect("write payload");
    // Close stdin so `cat` sees EOF and exits.
    drop(child.stdin.take());
    let output = child.wait_with_output().expect("wait ssh");
    assert!(
        output.status.success(),
        "ssh cat failed; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.stdout,
        payload,
        "binary roundtrip mismatch: got {} bytes back, expected {}",
        output.stdout.len(),
        payload.len()
    );
}

/// `ssh -t` forces pty allocation so remote interactive commands work
/// (sudo-over-ssh, curses, anything checking `isatty`).
#[test]
#[ignore = "requires docker"]
fn ssh_tt_allocates_pty_through_sshenc_agent() {
    if skip_if_no_docker("ssh_tt_allocates_pty_through_sshenc_agent") {
        return;
    }
    let (env, _on_disk, _enclave, container) = env_with_enclave_trusted_container();

    // `-tt` (double) forces pty allocation even when stdin is not a tty
    // in the local parent (which is true under cargo test).
    let mut cmd = env.sshenc_cmd().expect("sshenc cmd");
    cmd.arg("ssh").arg("--");
    SshencEnv::apply_ssh_isolation(&mut cmd, container.host_port, &env.known_hosts());
    cmd.arg("-tt")
        .arg("-o")
        .arg(format!("IdentityAgent={}", env.socket_path().display()))
        .arg("sshtest@127.0.0.1")
        .arg("tty < /dev/tty");
    let outcome = run(&mut cmd).expect("sshenc ssh -tt");
    assert!(
        outcome.succeeded(),
        "sshenc ssh -tt failed; stderr:\n{}",
        outcome.stderr
    );
    // `tty` prints the pty device name when connected to a tty.
    assert!(
        outcome.stdout.contains("/dev/pts/") || outcome.stdout.contains("/dev/tty"),
        "expected pty path in output; stdout:\n{}",
        outcome.stdout
    );
}

/// `ssh-copy-id` deposits a pubkey into the remote authorized_keys using
/// existing credentials. Critical end-user workflow: user has a working
/// key (on-disk), wants to also authorize their enclave key.
#[test]
#[ignore = "requires docker"]
fn ssh_copy_id_authorizes_new_key_via_existing_credentials() {
    if skip_if_no_docker("ssh_copy_id_authorizes_new_key_via_existing_credentials") {
        return;
    }
    // Skip if ssh-copy-id isn't on PATH (it ships with OpenSSH but some
    // minimal Linux installs strip it).
    if !is_in_path("ssh-copy-id") {
        eprintln!("skip ssh_copy_id: ssh-copy-id not found in PATH");
        return;
    }

    let mut env = SshencEnv::new().expect("env");
    let on_disk = generate_on_disk_ed25519(&env, "on-disk@e2e").expect("on-disk keygen");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("agent start");

    // Container initially trusts only the on-disk key.
    let container = SshdContainer::start(&[&on_disk]).expect("sshd container");

    // Sanity: enclave key should NOT be trusted yet.
    let mut fail_cmd = env.sshenc_cmd().expect("sshenc cmd");
    fail_cmd
        .arg("ssh")
        .arg("--label")
        .arg("e2e-shared")
        .arg("--");
    SshencEnv::apply_ssh_isolation(&mut fail_cmd, container.host_port, &env.known_hosts());
    fail_cmd.arg("sshtest@127.0.0.1").arg("true");
    let before = run(&mut fail_cmd).expect("pre-copy ssh");
    assert!(
        !before.succeeded(),
        "pre-condition failed: enclave key was already trusted"
    );

    // Write the enclave pubkey to a file and feed it to ssh-copy-id.
    let enclave_pub = env.ssh_dir().join("enclave_to_copy.pub");
    std::fs::write(&enclave_pub, format!("{enclave}\n")).expect("write enclave pub");

    // ssh-copy-id uses the current credentials (our on-disk key) to
    // authenticate, then appends the supplied pubkey to
    // ~/.ssh/authorized_keys on the remote.
    let mut copy = env.scrubbed_command("ssh-copy-id");
    copy.arg("-f") // skip the pre-check ssh probe
        .arg("-i")
        .arg(&enclave_pub)
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
        .arg("ConnectTimeout=10")
        .arg("-o")
        .arg("NumberOfPasswordPrompts=0")
        .arg("-o")
        .arg("PreferredAuthentications=publickey")
        .arg("-o")
        .arg(format!(
            "IdentityFile={}",
            env.ssh_dir().join("id_ed25519").display()
        ))
        .arg("sshtest@127.0.0.1");
    let outcome = run(&mut copy).expect("ssh-copy-id");
    assert!(
        outcome.succeeded(),
        "ssh-copy-id failed; stdout:\n{}\nstderr:\n{}",
        outcome.stdout,
        outcome.stderr
    );

    // Now the enclave key should authenticate.
    let mut ok_cmd = env.sshenc_cmd().expect("sshenc cmd");
    ok_cmd.arg("ssh").arg("--label").arg("e2e-shared").arg("--");
    SshencEnv::apply_ssh_isolation(&mut ok_cmd, container.host_port, &env.known_hosts());
    ok_cmd.arg("sshtest@127.0.0.1").arg("true");
    let after = run(&mut ok_cmd).expect("post-copy ssh");
    assert!(
        after.succeeded(),
        "enclave key should work after ssh-copy-id; stderr:\n{}",
        after.stderr
    );
}

fn is_in_path(binary: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths).any(|dir| {
                let candidate = Path::new(&dir).join(binary);
                candidate.exists()
            })
        })
        .unwrap_or(false)
}
