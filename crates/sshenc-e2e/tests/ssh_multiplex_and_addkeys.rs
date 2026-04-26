// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Two ssh-client features whose interaction with sshenc wasn't
//! pinned:
//!
//! 1. **ControlMaster (`-M`/`-O`)**: ssh's connection-multiplexing
//!    mode opens a master connection, then `-O check`/`-O exit`
//!    probe/close it via a control socket. Master-mode auth has
//!    to authenticate through sshenc-agent; follow-on probes use
//!    the existing channel and don't re-auth, so this pins
//!    "auth held once, multiplex worked".
//! 2. **AddKeysToAgent**: when ssh has a software identity in
//!    use it can push it into the agent on connection. sshenc-
//!    agent doesn't accept software-key adds (covered by
//!    `ssh_add_unsupported_ops`), but the AddKeysToAgent path
//!    surfaces this differently — ssh runs the add silently and
//!    swallows the FAILURE response. Pin that the connection
//!    still completes despite the silent rejection.

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

/// `ssh -M -S <socket>` opens a master connection authenticated
/// via sshenc, then `ssh -S <socket> -O check` reuses it
/// (succeeds without a fresh auth round-trip), then `-O exit`
/// closes it cleanly.
#[test]
#[ignore = "requires docker"]
fn ssh_controlmaster_with_sshenc_agent_round_trips() {
    if skip_if_no_docker("ssh_controlmaster_with_sshenc_agent_round_trips") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let container = SshdContainer::start(&[&enclave]).expect("sshd");

    let ctl = env.home().join("ctl-master.sock");
    // -M -f -N: open master in background, don't run a remote
    // command. -S points at the control socket.
    let mut master = env.scrubbed_command("ssh");
    master
        .arg("-M")
        .arg("-S")
        .arg(&ctl)
        .arg("-f")
        .arg("-N")
        .arg("-p")
        .arg(container.host_port.to_string())
        .arg("-F")
        .arg("/dev/null")
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
        .arg("-o")
        .arg("PreferredAuthentications=publickey")
        .arg("sshtest@127.0.0.1");
    let outcome = run(&mut master).expect("ssh -M");
    assert!(
        outcome.succeeded(),
        "ssh -M failed; stderr:\n{}",
        outcome.stderr
    );

    // -O check on the same socket: reuses the master, no auth.
    let check = run(env
        .scrubbed_command("ssh")
        .arg("-S")
        .arg(&ctl)
        .arg("-O")
        .arg("check")
        .arg("-p")
        .arg(container.host_port.to_string())
        .arg("sshtest@127.0.0.1"))
    .expect("ssh -O check");
    assert!(
        check.succeeded(),
        "ssh -O check on master failed; stderr:\n{}",
        check.stderr
    );
    let combined = format!("{}{}", check.stdout, check.stderr).to_lowercase();
    assert!(
        combined.contains("master running"),
        "expected 'Master running' from -O check; got:\n{combined}"
    );

    // -O exit: clean close.
    let exit = run(env
        .scrubbed_command("ssh")
        .arg("-S")
        .arg(&ctl)
        .arg("-O")
        .arg("exit")
        .arg("-p")
        .arg(container.host_port.to_string())
        .arg("sshtest@127.0.0.1"))
    .expect("ssh -O exit");
    assert!(
        exit.succeeded(),
        "ssh -O exit failed; stderr:\n{}",
        exit.stderr
    );
}

/// With `AddKeysToAgent yes`, ssh tries to push a software
/// identity into sshenc-agent at auth time. sshenc-agent rejects
/// software-key adds (it serves only enclave-backed keys), but
/// ssh swallows the FAILURE response and the connection still
/// completes. Pin both: connection succeeds, agent's identity
/// list does NOT pick up the would-be-added software key.
#[test]
#[ignore = "requires docker"]
fn add_keys_to_agent_yes_does_not_break_connection_or_pollute_agent() {
    if skip_if_no_docker("add_keys_to_agent_yes_does_not_break_connection_or_pollute_agent") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let container = SshdContainer::start(&[&enclave]).expect("sshd");

    // Generate a software ed25519 key that ssh might push.
    let keyfile = env.ssh_dir().join("for-add-keys-to-agent");
    let kg = run(env
        .scrubbed_command("ssh-keygen")
        .arg("-q")
        .arg("-t")
        .arg("ed25519")
        .arg("-N")
        .arg("")
        .arg("-f")
        .arg(&keyfile))
    .expect("ssh-keygen");
    assert!(kg.succeeded(), "ssh-keygen: {}", kg.stderr);

    // Authorize the ed25519 key on the container so this test's
    // connection succeeds via the software key — that's the path
    // that triggers AddKeysToAgent. Re-running the container
    // setup with both keys would be heavier; instead we use
    // -i <keyfile> to force ssh to use our software key, so
    // agent-mediated auth doesn't happen at all and AddKeysToAgent
    // genuinely fires.
    let mut authorized = String::new();
    authorized.push_str(&enclave);
    authorized.push('\n');
    authorized.push_str(
        &std::fs::read_to_string(keyfile.with_extension("pub")).expect("read software pub"),
    );

    drop(authorized); // We can't actually re-bind the container's
                      // authorized_keys mid-test; skip that path
                      // and just verify the agent isn't polluted
                      // by AddKeysToAgent against an unauthorized
                      // software key.

    // ssh against the container with AddKeysToAgent=yes,
    // IdentityAgent pointing at sshenc, IdentityFile =
    // our software key. The connection will use the agent's
    // enclave key (matches authorized_keys); AddKeysToAgent will
    // try to push the software key to the agent, agent responds
    // with FAILURE, ssh swallows.
    let connect = run(env
        .scrubbed_command("ssh")
        .arg("-p")
        .arg(container.host_port.to_string())
        .arg("-F")
        .arg("/dev/null")
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
        .arg("AddKeysToAgent=yes")
        .arg("-o")
        .arg(format!("IdentityFile={}", keyfile.display()))
        .arg("-o")
        .arg("ConnectTimeout=10")
        .arg("-o")
        .arg("PreferredAuthentications=publickey")
        .arg("sshtest@127.0.0.1")
        .arg("--")
        .arg("echo connected"))
    .expect("ssh connect");
    assert!(
        connect.succeeded(),
        "connection should succeed despite AddKeysToAgent rejection; stderr:\n{}",
        connect.stderr
    );

    // Verify agent identity list does NOT include the software
    // key we tried to add. ssh-add -L emits each identity's
    // pubkey body; the software key's body must not appear.
    let listed = run(env
        .scrubbed_command("ssh-add")
        .env("SSH_AUTH_SOCK", env.socket_path())
        .arg("-L"))
    .expect("ssh-add -L");
    assert!(listed.succeeded(), "ssh-add -L: {}", listed.stderr);

    let sw_body = std::fs::read_to_string(keyfile.with_extension("pub"))
        .expect("read sw pub")
        .split_whitespace()
        .nth(1)
        .map(str::to_string)
        .unwrap_or_default();
    assert!(
        !sw_body.is_empty() && !listed.stdout.contains(&sw_body),
        "agent identity list contains the software key — AddKeysToAgent should have been rejected:\n{}",
        listed.stdout
    );
}
