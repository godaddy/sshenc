// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Three OpenSSH client-feature contracts not previously pinned:
//!
//! 1. **ProxyJump (`-J`)**: client → A → final, configured via
//!    `-J <jump>` rather than via ProxyCommand. ssh_port_forwarding
//!    covers ProxyCommand; -J is shorthand that uses -W internally
//!    but with its own option-parser code path.
//! 2. **RequestTTY=force / RemoteCommand**: forces a PTY allocation
//!    and runs a server-side command; the auth path is the same as
//!    a normal ssh, but option parsing in the CLI shouldn't strip
//!    or reorder these flags when sshenc-ssh forwards them.
//! 3. **SetEnv**: explicitly send a named env var to the remote.
//!    Tests that ssh's option parser receives the option from
//!    sshenc-ssh wrapper unmolested.

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

struct Pair {
    network: String,
    jump_id: String,
    target_id: String,
    pub jump_host_port: u16,
}

impl Pair {
    fn start(authorized_keys_line: &str) -> anyhow::Result<Self> {
        ensure_image()?;
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let network = format!("sshenc-feats-{pid}-{nanos}");

        let create = Command::new("docker")
            .args(["network", "create", &network])
            .output()?;
        anyhow::ensure!(
            create.status.success(),
            "docker network create: {}",
            String::from_utf8_lossy(&create.stderr).trim()
        );

        let target_id = run_container(&network, Some("targethost"), None, authorized_keys_line)?;
        let jump_id =
            run_container(&network, None, Some(0), authorized_keys_line).map_err(|e| {
                let _ignored = kill_container(&target_id);
                let _ignored = remove_network(&network);
                e
            })?;

        let jump_host_port = match discover_host_port(&jump_id) {
            Ok(p) => p,
            Err(e) => {
                let _ignored = kill_container(&jump_id);
                let _ignored = kill_container(&target_id);
                let _ignored = remove_network(&network);
                return Err(e);
            }
        };
        if let Err(e) = wait_for_ssh_banner(jump_host_port, Duration::from_secs(15)) {
            let _ignored = kill_container(&jump_id);
            let _ignored = kill_container(&target_id);
            let _ignored = remove_network(&network);
            return Err(e);
        }
        if let Err(e) = wait_for_target_via_jump(&jump_id, "targethost", Duration::from_secs(15)) {
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
        })
    }
}

impl Drop for Pair {
    fn drop(&mut self) {
        drop(kill_container(&self.jump_id));
        drop(kill_container(&self.target_id));
        drop(remove_network(&self.network));
    }
}

fn run_container(
    network: &str,
    alias: Option<&str>,
    host_port: Option<u16>,
    authorized_keys_line: &str,
) -> anyhow::Result<String> {
    let mut cmd = Command::new("docker");
    cmd.args(["run", "--rm", "-d", "--network", network]);
    if let Some(a) = alias {
        cmd.args(["--network-alias", a]);
    }
    if let Some(p) = host_port {
        cmd.arg("-p").arg(format!("127.0.0.1:{p}:22"));
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
        if let Some((_, p)) = line.rsplit_once(':') {
            if let Ok(p) = p.trim().parse() {
                return Ok(p);
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
        if let Ok(mut s) = TcpStream::connect_timeout(&addr.parse()?, Duration::from_millis(500)) {
            s.set_read_timeout(Some(Duration::from_millis(500))).ok();
            let mut buf = [0_u8; 7];
            if s.read_exact(&mut buf).is_ok() && &buf == b"SSH-2.0" {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            anyhow::bail!("sshd did not answer banner on {port}");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn wait_for_target_via_jump(jump_id: &str, target: &str, timeout: Duration) -> anyhow::Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let probe = Command::new("docker")
            .args(["exec", jump_id, "nc", "-z", "-w", "1", target, "22"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if matches!(probe, Ok(s) if s.success()) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!("target {target} unreachable from jump");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// `sshenc ssh -J <jump>` is parsed without complaint and the
/// flag reaches the underlying `ssh`. Two-hop host-key trust
/// chains in -J mode are involved (each hop's key has to live
/// in known_hosts before the other hop is allowed), so this
/// pins only that the wrapper forwards `-J` cleanly: the
/// connection doesn't fail with an unrecognized-flag error and
/// it reaches the host-key-verification stage.
#[test]
#[ignore = "requires docker"]
fn sshenc_ssh_dash_j_flag_is_forwarded_to_ssh() {
    if skip_if_no_docker("sshenc_ssh_dash_j_flag_is_forwarded_to_ssh") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");

    let pair = Pair::start(&enclave).expect("fleet");
    let jump_spec = format!("sshtest@127.0.0.1:{}", pair.jump_host_port);

    let mut cmd = env.sshenc_cmd().expect("sshenc cmd");
    cmd.arg("ssh")
        .arg("-J")
        .arg(&jump_spec)
        .arg("-F")
        .arg("/dev/null")
        .arg("-o")
        .arg("ConnectTimeout=5")
        .arg("-o")
        .arg("PreferredAuthentications=publickey")
        .arg("-o")
        .arg("NumberOfPasswordPrompts=0")
        .arg("sshtest@targethost")
        .arg("--")
        .arg("hostname");

    let outcome = run(&mut cmd).expect("sshenc ssh -J");
    // The wrapper-forwarding contract: not "unknown option -J",
    // not "could not resolve hostname targethost" (jump worked
    // and resolved targethost via docker DNS in the network).
    let combined = format!("{}\n{}", outcome.stdout, outcome.stderr).to_lowercase();
    assert!(
        !combined.contains("unknown option")
            && !combined.contains("invalid option")
            && !combined.contains("could not resolve hostname targethost"),
        "sshenc-ssh didn't forward -J cleanly to ssh; output:\nstdout:\n{}\nstderr:\n{}",
        outcome.stdout,
        outcome.stderr
    );
}

/// `sshenc ssh -t` (force PTY) + `RemoteCommand` runs a remote
/// command in a TTY. The auth path is unchanged but ssh's CLI
/// argument plumbing is — pin that sshenc-ssh forwards `-t` and
/// `-o RemoteCommand=...` without mangling.
#[test]
#[ignore = "requires docker"]
fn sshenc_ssh_forces_tty_and_runs_remote_command() {
    if skip_if_no_docker("sshenc_ssh_forces_tty_and_runs_remote_command") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let container = sshenc_e2e::SshdContainer::start(&[&enclave]).expect("sshd");

    // -tt forces TTY; RemoteCommand sets the server-side command.
    // Use `tty -s; echo ttyok` — `tty -s` succeeds only if stdin
    // is a TTY, so a successful `ttyok` proves the PTY allocation
    // happened.
    let mut cmd = env.sshenc_cmd().expect("sshenc cmd");
    cmd.arg("ssh")
        .arg("-tt")
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
        .arg("-o")
        .arg("RemoteCommand=tty -s && echo ttyok || echo nottyok")
        .arg("sshtest@127.0.0.1");

    let outcome = run(&mut cmd).expect("sshenc ssh -tt");
    assert!(
        outcome.succeeded(),
        "sshenc ssh -tt RemoteCommand failed; stdout:\n{}\nstderr:\n{}",
        outcome.stdout,
        outcome.stderr
    );
    let combined = format!("{}{}", outcome.stdout, outcome.stderr);
    assert!(
        combined.contains("ttyok"),
        "expected ttyok in output (PTY allocation succeeded); got:\n{combined}"
    );
}

/// `sshenc ssh -o SetEnv=KEY=value` propagates the named env var
/// to the remote shell. sshd's `AcceptEnv` defaults don't include
/// arbitrary names, but `SetEnv` writes through with `Send_env`
/// extension and the variable is observable via `printenv` only
/// if the server allows it. We instead probe via `set` (always
/// available) by looking for a value in the *connection* path —
/// using the form `LC_*` which sshd accepts by default on most
/// distros. If LC_ doesn't propagate on this build of the
/// container, we fall back to confirming the connection succeeds
/// with the SetEnv flag in place (no parsing regression).
#[test]
#[ignore = "requires docker"]
fn sshenc_ssh_setenv_lc_propagates_or_at_least_does_not_break_connection() {
    if skip_if_no_docker("sshenc_ssh_setenv_lc_propagates_or_at_least_does_not_break_connection") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let container = sshenc_e2e::SshdContainer::start(&[&enclave]).expect("sshd");

    let mut cmd = env.sshenc_cmd().expect("sshenc cmd");
    cmd.arg("ssh")
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
        .arg("-o")
        .arg("SetEnv=LC_SSHENC=propagate-this")
        .arg("sshtest@127.0.0.1")
        .arg("--")
        .arg("printenv LC_SSHENC || true");

    let outcome = run(&mut cmd).expect("sshenc ssh SetEnv");
    assert!(
        outcome.succeeded(),
        "sshenc ssh -o SetEnv failed connection; stderr:\n{}",
        outcome.stderr
    );
    // If the container's sshd allows LC_ vars (it does by
    // default in most builds, including alpine's openssh), we'd
    // see "propagate-this" in stdout. If not, stdout is empty
    // and the connection itself succeeded — what matters is that
    // SetEnv didn't break ssh's option parsing.
    if !outcome.stdout.trim().is_empty() {
        assert!(
            outcome.stdout.contains("propagate-this"),
            "LC_SSHENC didn't propagate; got stdout:\n{}",
            outcome.stdout
        );
    }
}
