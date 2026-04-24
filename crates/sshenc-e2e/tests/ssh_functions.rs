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
    docker_skip_reason, generate_on_disk_ed25519, pick_free_port, run, shared_enclave_pubkey,
    SshdContainer, SshencEnv,
};
use std::io::{Read, Write};
use std::net::TcpStream;
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
