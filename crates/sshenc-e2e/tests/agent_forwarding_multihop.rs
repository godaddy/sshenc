// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Three-hop agent forwarding: client → A → B → C, where each
//! hop forwards the agent socket through to the next. The
//! signature for the C-target authentication is produced by the
//! original sshenc-agent on the client side.
//!
//! `agent_forwarding.rs` covers two-hop (`-A` from client to
//! one jump host then ssh from there). Three-hop tests a
//! different state machine: each forwarding ssh has to set up
//! its own AF_UNIX listener inside the previous hop's session,
//! and the "follow the SSH_AUTH_SOCK chain" delegation goes
//! one level deeper. Real-world bastion-of-bastions setups hit
//! this; it's worth pinning that the chain doesn't drop the
//! original agent reference partway through.

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

struct Fleet {
    network: String,
    hop_a_id: String,
    hop_b_id: String,
    hop_c_id: String,
    /// Host-side TCP port mapped to A's sshd. The test driver
    /// connects here; A reaches B, B reaches C, both via the
    /// in-network DNS aliases.
    pub hop_a_host_port: u16,
}

impl Fleet {
    fn start(authorized_keys_line: &str) -> anyhow::Result<Self> {
        ensure_image()?;
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let network = format!("sshenc-mh-{pid}-{nanos}");

        let create = Command::new("docker")
            .args(["network", "create", &network])
            .output()?;
        anyhow::ensure!(
            create.status.success(),
            "docker network create: {}",
            String::from_utf8_lossy(&create.stderr).trim()
        );

        // Start C and B without host port mappings; they're only
        // reachable via the docker network.
        let hop_c_id = run_container(&network, Some("hopc"), None, authorized_keys_line)?;
        let hop_b_id =
            run_container(&network, Some("hopb"), None, authorized_keys_line).map_err(|e| {
                let _ignored = kill_container(&hop_c_id);
                let _ignored = remove_network(&network);
                e
            })?;
        let hop_a_id =
            run_container(&network, None, Some(0), authorized_keys_line).map_err(|e| {
                let _ignored = kill_container(&hop_b_id);
                let _ignored = kill_container(&hop_c_id);
                let _ignored = remove_network(&network);
                e
            })?;

        let hop_a_host_port = match discover_host_port(&hop_a_id) {
            Ok(p) => p,
            Err(e) => {
                let _ignored = kill_container(&hop_a_id);
                let _ignored = kill_container(&hop_b_id);
                let _ignored = kill_container(&hop_c_id);
                let _ignored = remove_network(&network);
                return Err(e);
            }
        };

        if let Err(e) = wait_for_ssh_banner(hop_a_host_port, Duration::from_secs(15)) {
            let _ignored = kill_container(&hop_a_id);
            let _ignored = kill_container(&hop_b_id);
            let _ignored = kill_container(&hop_c_id);
            let _ignored = remove_network(&network);
            return Err(e);
        }
        for (jump, target) in [(&hop_a_id, "hopb"), (&hop_b_id, "hopc")] {
            if let Err(e) = wait_for_target_via_jump(jump, target, Duration::from_secs(15)) {
                let _ignored = kill_container(&hop_a_id);
                let _ignored = kill_container(&hop_b_id);
                let _ignored = kill_container(&hop_c_id);
                let _ignored = remove_network(&network);
                return Err(e);
            }
        }

        Ok(Self {
            network,
            hop_a_id,
            hop_b_id,
            hop_c_id,
            hop_a_host_port,
        })
    }
}

impl Drop for Fleet {
    fn drop(&mut self) {
        drop(kill_container(&self.hop_a_id));
        drop(kill_container(&self.hop_b_id));
        drop(kill_container(&self.hop_c_id));
        drop(remove_network(&self.network));
    }
}

fn run_container(
    network: &str,
    network_alias: Option<&str>,
    host_port_request: Option<u16>,
    authorized_keys_line: &str,
) -> anyhow::Result<String> {
    let mut cmd = Command::new("docker");
    cmd.args(["run", "--rm", "-d", "--network", network]);
    if let Some(alias) = network_alias {
        cmd.args(["--network-alias", alias]);
    }
    if let Some(host_port) = host_port_request {
        cmd.arg("-p").arg(format!("127.0.0.1:{host_port}:22"));
    }
    cmd.arg("-e")
        .arg(format!("AUTHORIZED_KEYS={authorized_keys_line}"))
        .arg(IMAGE_TAG)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = cmd.output()?;
    anyhow::ensure!(
        out.status.success(),
        "docker run: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    );
    Ok(String::from_utf8(out.stdout)?.trim().to_string())
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
            anyhow::bail!("sshd at 127.0.0.1:{port} did not answer banner");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn wait_for_target_via_jump(
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
            anyhow::bail!("target {target_alias} unreachable from jump in {timeout:?}");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Three-hop agent forwarding: client → A → B → C. The
/// authentication for C must be produced by the *original*
/// sshenc-agent on the client side; if any hop drops the
/// forwarded socket reference, the inner-most ssh fails publickey.
#[test]
#[ignore = "requires docker"]
fn three_hop_agent_forwarding_chain_authenticates_to_innermost() {
    if skip_if_no_docker("three_hop_agent_forwarding_chain_authenticates_to_innermost") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");

    let fleet = Fleet::start(&enclave).expect("fleet up");

    // Outer command: ssh -A from client to A. Mid: ssh -A from
    // A to B. Inner: ssh from B to C, runs `hostname`. Each
    // intermediate hop opens a new agent socket inside its
    // session that's hooked to the previous hop's forwarded one.
    let ssh_isolation = "-F /dev/null \
        -o StrictHostKeyChecking=accept-new \
        -o ConnectTimeout=10 \
        -o PreferredAuthentications=publickey \
        -o NumberOfPasswordPrompts=0";

    let inner = format!(
        "ssh {iso} -o UserKnownHostsFile=/tmp/ih sshtest@hopc hostname",
        iso = ssh_isolation
    );
    let mid = format!(
        "ssh -A {iso} -o UserKnownHostsFile=/tmp/mh sshtest@hopb -- {inner}",
        iso = ssh_isolation
    );

    let mut cmd = env.sshenc_cmd().expect("sshenc cmd");
    cmd.arg("ssh")
        .arg("-A")
        .arg("-p")
        .arg(fleet.hop_a_host_port.to_string())
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
        .arg(mid);

    let outcome = run(&mut cmd).expect("run three-hop ssh -A");
    assert!(
        outcome.succeeded(),
        "three-hop -A chain failed; stdout:\n{}\nstderr:\n{}",
        outcome.stdout,
        outcome.stderr
    );
    let trimmed = outcome.stdout.trim();
    assert!(
        !trimmed.is_empty(),
        "expected hostname output from innermost hop; got empty stdout. stderr:\n{}",
        outcome.stderr
    );
}
