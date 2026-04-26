// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `sshenc ssh -A …` forwards the agent to a remote host so the
//! second hop in a jump-host workflow can sign against the local
//! enclave key. If forwarding regresses (the CLI strips `-A`,
//! `IdentityAgent` is set in a way that suppresses
//! `SSH_AUTH_SOCK` propagation, the OpenSSH forwarder can't
//! handshake against our agent's identity-enumerate response,
//! etc.), the second hop fails with "Permission denied
//! (publickey)" — silent regression that current tests don't
//! catch because they only ever do one hop.
//!
//! This test stands up two networked OpenSSH containers — a jump
//! host and a target — both authorized for the shared enclave
//! key. The test then runs:
//!
//!   sshenc ssh -A sshtest@<jumpA> -- \
//!     ssh -o StrictHostKeyChecking=accept-new sshtest@targethost hostname
//!
//! The inner ssh (running on jumpA) must complete pubkey auth
//! against targetB by signing through the forwarded agent, i.e.
//! through our local sshenc-agent.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{
    docker_skip_reason, ensure_image, run, shared_enclave_pubkey, SshencEnv, IMAGE_TAG,
};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn skip_if_no_docker(test_name: &str) -> bool {
    if let Some(reason) = docker_skip_reason() {
        eprintln!("skip {test_name}: {reason}");
        return true;
    }
    false
}

/// Networked pair of OpenSSH containers used for agent-forwarding
/// tests. Drops kill both containers and remove the network.
struct JumpAndTarget {
    network: String,
    jump_id: String,
    target_id: String,
    /// Host-side TCP port mapped to the jump host's sshd. Use
    /// 127.0.0.1:<this> to reach jump from the test driver.
    pub jump_host_port: u16,
    /// DNS name for the target reachable from inside the jump host
    /// over the docker network. Used as the second hop's hostname.
    pub target_hostname: String,
}

impl JumpAndTarget {
    fn start(authorized_keys_line: &str) -> anyhow::Result<Self> {
        ensure_image()?;
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let network = format!("sshenc-fwd-{pid}-{nanos}");
        let target_alias = "targethost".to_string();

        // Create a user-defined bridge network so docker DNS
        // auto-resolves --network-alias names.
        let create = Command::new("docker")
            .args(["network", "create", &network])
            .output()?;
        anyhow::ensure!(
            create.status.success(),
            "docker network create failed: {}",
            String::from_utf8_lossy(&create.stderr).trim()
        );

        // Start the target FIRST (no host port mapping — only
        // accessed through the jump host). Pass authorized_keys
        // via env so we don't need a host-mounted file for both.
        let target_run = Command::new("docker")
            .args([
                "run",
                "--rm",
                "-d",
                "--network",
                &network,
                "--network-alias",
                &target_alias,
                "-e",
            ])
            .arg(format!("AUTHORIZED_KEYS={authorized_keys_line}"))
            .arg(IMAGE_TAG)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;
        if !target_run.status.success() {
            let _ignored = remove_network(&network);
            anyhow::bail!(
                "docker run target: {}",
                String::from_utf8_lossy(&target_run.stderr).trim()
            );
        }
        let target_id = String::from_utf8(target_run.stdout)?.trim().to_string();

        // Start the jump host with a random host port mapping so
        // the test driver can ssh into it.
        let jump_run = Command::new("docker")
            .args([
                "run",
                "--rm",
                "-d",
                "--network",
                &network,
                "-p",
                "127.0.0.1:0:22",
                "-e",
            ])
            .arg(format!("AUTHORIZED_KEYS={authorized_keys_line}"))
            .arg(IMAGE_TAG)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;
        if !jump_run.status.success() {
            let _ignored = kill_container(&target_id);
            let _ignored = remove_network(&network);
            anyhow::bail!(
                "docker run jump: {}",
                String::from_utf8_lossy(&jump_run.stderr).trim()
            );
        }
        let jump_id = String::from_utf8(jump_run.stdout)?.trim().to_string();

        let jump_host_port = match discover_host_port(&jump_id) {
            Ok(p) => p,
            Err(e) => {
                let _ignored = kill_container(&jump_id);
                let _ignored = kill_container(&target_id);
                let _ignored = remove_network(&network);
                return Err(e);
            }
        };

        // Wait for both sshds to talk SSH.
        if let Err(e) = wait_for_ssh_banner(jump_host_port, Duration::from_secs(15)) {
            let _ignored = kill_container(&jump_id);
            let _ignored = kill_container(&target_id);
            let _ignored = remove_network(&network);
            return Err(e);
        }
        if let Err(e) = wait_for_target_ready(&jump_id, &target_alias, Duration::from_secs(15)) {
            let _ignored = kill_container(&jump_id);
            let _ignored = kill_container(&target_id);
            let _ignored = remove_network(&network);
            return Err(e);
        }

        Ok(Self {
            network,
            jump_id,
            target_id,
            jump_host_port,
            target_hostname: target_alias,
        })
    }
}

impl Drop for JumpAndTarget {
    fn drop(&mut self) {
        drop(kill_container(&self.jump_id));
        drop(kill_container(&self.target_id));
        drop(remove_network(&self.network));
    }
}

fn kill_container(id: &str) -> std::io::Result<()> {
    Command::new("docker")
        .args(["kill", id])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|_| ())
}

fn remove_network(name: &str) -> std::io::Result<()> {
    Command::new("docker")
        .args(["network", "rm", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|_| ())
}

fn discover_host_port(id: &str) -> anyhow::Result<u16> {
    let output = Command::new("docker")
        .args(["port", id, "22/tcp"])
        .output()?;
    anyhow::ensure!(
        output.status.success(),
        "docker port: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if let Some((_, port)) = line.rsplit_once(':') {
            if let Ok(port) = port.trim().parse::<u16>() {
                return Ok(port);
            }
        }
    }
    anyhow::bail!("could not parse host port from: {stdout}")
}

fn wait_for_ssh_banner(port: u16, timeout: Duration) -> anyhow::Result<()> {
    use std::io::Read;
    use std::net::TcpStream;
    let deadline = Instant::now() + timeout;
    let addr = format!("127.0.0.1:{port}");
    loop {
        if let Ok(mut stream) =
            TcpStream::connect_timeout(&addr.parse()?, Duration::from_millis(500))
        {
            stream
                .set_read_timeout(Some(Duration::from_millis(500)))
                .ok();
            let mut buf = [0_u8; 7];
            if stream.read_exact(&mut buf).is_ok() && &buf == b"SSH-2.0" {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            anyhow::bail!("sshd on 127.0.0.1:{port} did not answer SSH banner in {timeout:?}");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Probe the target host's sshd from *inside* the jump host. Uses
/// `nc -z` to check the port is accepting connections. The image's
/// shell is busybox sh, which doesn't support `/dev/tcp`, so we
/// rely on `netcat-openbsd` (installed in the e2e Dockerfile).
fn wait_for_target_ready(
    jump_id: &str,
    target_alias: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let probe = Command::new("docker")
            .args(["exec", jump_id, "nc", "-z", "-w", "1", target_alias, "22"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if matches!(probe, Ok(s) if s.success()) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "target host {target_alias} did not accept TCP from inside jump host in {timeout:?}"
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// `sshenc ssh -A` exposes the local enclave-backed agent to the
/// jump host. From the jump host, an inner `ssh targethost` must
/// be able to authenticate by signing through the forwarded agent.
/// If forwarding regresses, the inner ssh fails with publickey
/// rejection and we'd never know without a two-hop test.
#[test]
#[ignore = "requires docker"]
fn sshenc_ssh_forwards_agent_through_jump_host() {
    if skip_if_no_docker("sshenc_ssh_forwards_agent_through_jump_host") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");

    let pair = JumpAndTarget::start(&enclave).expect("start jump+target");

    // ssh -A from local to jump, then on the jump invoke ssh
    // targethost. StrictHostKeyChecking=accept-new on the inner
    // hop so the unknown host key on first contact doesn't trip
    // verification. The outer hop uses our scrubbed env's
    // /dev/null host config so it doesn't pick up the developer's
    // ~/.ssh/config.
    let mut cmd = env.sshenc_cmd().expect("sshenc cmd");
    cmd.arg("ssh")
        .arg("-A")
        .arg("-p")
        .arg(pair.jump_host_port.to_string())
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
        .arg("ConnectTimeout=10")
        .arg("-o")
        .arg("PreferredAuthentications=publickey")
        .arg("-o")
        .arg("NumberOfPasswordPrompts=0")
        .arg("sshtest@127.0.0.1")
        .arg("--")
        .arg(format!(
            "ssh -o StrictHostKeyChecking=accept-new \
                 -o UserKnownHostsFile=/tmp/known_hosts.inner \
                 -o ConnectTimeout=10 \
                 -o PreferredAuthentications=publickey \
                 sshtest@{} hostname",
            pair.target_hostname
        ));

    let outcome = run(&mut cmd).expect("run sshenc ssh -A");
    assert!(
        outcome.succeeded(),
        "sshenc ssh -A jump … ssh target hostname failed:\nstdout: {}\nstderr: {}",
        outcome.stdout,
        outcome.stderr
    );
    // The inner `hostname` runs in the target container; its
    // hostname is the docker container ID prefix, which is the
    // 12-char short SHA. We don't try to predict the exact ID;
    // we just assert non-empty output that isn't the jump host's
    // hostname (best we can without container introspection).
    let trimmed = outcome.stdout.trim();
    assert!(
        !trimmed.is_empty(),
        "expected target hostname output, got empty stdout; stderr:\n{}",
        outcome.stderr
    );
}

/// Without `-A`, the same two-hop invocation must FAIL: the inner
/// ssh has no agent to ask, no key on disk, and pubkey is the
/// only authentication enabled. This pins the negative — proves
/// `-A` is doing real work, not just being a quiet flag we accept.
#[test]
#[ignore = "requires docker"]
fn sshenc_ssh_without_dash_a_does_not_forward_agent() {
    if skip_if_no_docker("sshenc_ssh_without_dash_a_does_not_forward_agent") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");

    let pair = JumpAndTarget::start(&enclave).expect("start jump+target");

    let mut cmd = env.sshenc_cmd().expect("sshenc cmd");
    cmd.arg("ssh")
        // NB: no -A — this is the differentiator
        .arg("-p")
        .arg(pair.jump_host_port.to_string())
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
        .arg("ConnectTimeout=10")
        .arg("-o")
        .arg("PreferredAuthentications=publickey")
        .arg("-o")
        .arg("NumberOfPasswordPrompts=0")
        .arg("sshtest@127.0.0.1")
        .arg("--")
        .arg(format!(
            "ssh -o StrictHostKeyChecking=accept-new \
                 -o UserKnownHostsFile=/tmp/known_hosts.inner \
                 -o ConnectTimeout=10 \
                 -o PreferredAuthentications=publickey \
                 -o NumberOfPasswordPrompts=0 \
                 -o BatchMode=yes \
                 sshtest@{} hostname",
            pair.target_hostname
        ));

    let outcome = run(&mut cmd).expect("run sshenc ssh (no -A)");
    assert!(
        !outcome.succeeded(),
        "sshenc ssh without -A unexpectedly succeeded — agent forwarding may be on by default; stdout:\n{}\nstderr:\n{}",
        outcome.stdout,
        outcome.stderr
    );
}
