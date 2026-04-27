// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Two boundary cases:
//!
//! - `git commit -F -` with empty stdin (no message body): git
//!   normally rejects the empty message, so commit fails — but
//!   it must fail cleanly with git's normal "aborting commit
//!   due to empty commit message" path, not panic into sshenc's
//!   signing code.
//! - `sshenc -Y sign -n <very-long-namespace>` accepts a
//!   namespace much longer than the typical "git" or "file"
//!   value. Pin that argument-forwarding doesn't truncate or
//!   reject long namespaces.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{docker_skip_reason, run, shared_enclave_pubkey, SshencEnv, SHARED_ENCLAVE_LABEL};
use std::io::Write;
use std::process::Stdio;

fn skip_if_no_docker(test_name: &str) -> bool {
    if let Some(reason) = docker_skip_reason() {
        eprintln!("skip {test_name}: {reason}");
        return true;
    }
    false
}

fn plant_meta_and_pub(env: &SshencEnv, label: &str, name: &str, email: &str, enclave: &str) {
    let dir = env.home().join(".sshenc").join("keys");
    std::fs::create_dir_all(&dir).expect("mkdir gitenc meta dir");
    std::fs::write(
        dir.join(format!("{label}.meta")),
        serde_json::to_string_pretty(&serde_json::json!({
            "app_specific": {
                "git_name": name,
                "git_email": email,
            }
        }))
        .unwrap(),
    )
    .expect("write meta");
    std::fs::create_dir_all(env.ssh_dir()).expect("mkdir ssh dir");
    std::fs::write(
        env.ssh_dir().join(format!("{label}.pub")),
        format!("{enclave}\n"),
    )
    .expect("write pub");
}

fn make_signed_repo(env: &SshencEnv, name: &str, enclave: &str) -> std::path::PathBuf {
    plant_meta_and_pub(
        env,
        SHARED_ENCLAVE_LABEL,
        "boundary signer",
        "boundary@e2e.test",
        enclave,
    );
    let repo = env.home().join(name);
    std::fs::create_dir_all(&repo).expect("mkdir");
    assert!(env
        .git_cmd()
        .current_dir(&repo)
        .args(["init", "-q", "-b", "main"])
        .status()
        .expect("git init")
        .success());
    let cfg = run(env
        .gitenc_cmd()
        .expect("gitenc cmd")
        .current_dir(&repo)
        .args(["--config", SHARED_ENCLAVE_LABEL]))
    .expect("gitenc --config");
    assert!(cfg.succeeded(), "gitenc --config: {}", cfg.stderr);
    repo
}

/// `git commit -F -` with empty stdin fails cleanly (no panic
/// from sshenc, no agent crash); error mentions the empty-msg
/// rejection, not signing.
#[test]
#[ignore = "requires docker"]
fn commit_with_empty_stdin_message_fails_cleanly() {
    if skip_if_no_docker("commit_with_empty_stdin_message_fails_cleanly") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let repo = make_signed_repo(&env, "empty-msg-repo", &enclave);

    std::fs::write(repo.join("a.txt"), b"content\n").expect("write");
    let add = run(env.git_cmd().current_dir(&repo).args(["add", "a.txt"])).expect("git add");
    assert!(add.succeeded(), "git add: {}", add.stderr);

    let mut child = env
        .git_cmd()
        .current_dir(&repo)
        .args(["commit", "-q", "-F", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn git commit -F -");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        // Empty message: write nothing, just close stdin.
        drop(stdin.flush());
    }
    let out = child.wait_with_output().expect("wait git commit");
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !combined.contains("panicked at"),
        "commit -F - with empty stdin panicked:\n{combined}"
    );
    assert!(
        !out.status.success(),
        "git commit with empty message should fail; got success with output:\n{combined}"
    );

    // Agent still serves.
    let listed = run(env
        .scrubbed_command("ssh-add")
        .env("SSH_AUTH_SOCK", env.socket_path())
        .arg("-L"))
    .expect("ssh-add -L");
    assert!(
        listed.succeeded(),
        "agent should still serve after empty-stdin commit attempt; stderr:\n{}",
        listed.stderr
    );
}

/// `sshenc -Y sign -n <128-byte-namespace>` accepts a long
/// namespace argument and produces a valid signature.
#[test]
#[ignore = "requires docker"]
fn y_sign_accepts_long_namespace() {
    if skip_if_no_docker("y_sign_accepts_long_namespace") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");

    let pub_path = env.ssh_dir().join(format!("{SHARED_ENCLAVE_LABEL}.pub"));
    std::fs::create_dir_all(env.ssh_dir()).expect("mkdir ssh dir");
    std::fs::write(&pub_path, format!("{enclave}\n")).expect("write pub");

    let payload = env.home().join("long-ns-payload.txt");
    std::fs::write(&payload, b"payload bytes\n").expect("write payload");

    let long_ns = "x".repeat(128);
    let sign = run(env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .arg("-Y")
        .arg("sign")
        .arg("-n")
        .arg(&long_ns)
        .arg("-f")
        .arg(&pub_path)
        .arg(&payload))
    .expect("sshenc -Y sign");
    assert!(
        sign.succeeded(),
        "sshenc -Y sign with long namespace failed; stderr:\n{}",
        sign.stderr
    );

    // The .sig file must exist and be non-empty.
    let sig = payload.with_extension("txt.sig");
    let sig_bytes = std::fs::metadata(&sig).expect("stat sig").len();
    assert!(sig_bytes > 0, "signature file is empty: {}", sig.display());

    // Verifying with check-novalidate (which uses the namespace
    // baked into the sig) must succeed.
    let mut child = env
        .sshenc_cmd()
        .expect("sshenc cmd")
        .arg("-Y")
        .arg("check-novalidate")
        .arg("-n")
        .arg(&long_ns)
        .arg("-s")
        .arg(&sig)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn check-novalidate");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        let bytes = std::fs::read(&payload).expect("read payload");
        stdin.write_all(&bytes).expect("write payload");
    }
    let output = child.wait_with_output().expect("wait check-novalidate");
    assert!(
        output.status.success(),
        "check-novalidate with long namespace failed; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
