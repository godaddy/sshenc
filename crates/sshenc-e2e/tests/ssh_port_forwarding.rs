// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `sshenc ssh -L`/`-R`/ProxyCommand exercises authentication
//! through the agent during connection setup. The auth itself is
//! the same code path as a plain interactive ssh, but each
//! forwarding mode opens its own channel-multiplex state machine
//! and a regression that strips forwarding flags from the args
//! the CLI passes to OpenSSH would silently break tunneling
//! workflows. None of these scenarios were e2e-tested before:
//! `agent_forwarding.rs` covers `-A` (agent forwarding), but
//! tunneling and ProxyCommand are different beasts.
//!
//! All three tests just establish the connection and verify it
//! authenticated — the actual data flow through the tunnel is
//! incidental. If auth held, the channel was set up correctly.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{
    docker_skip_reason, ensure_image, pick_free_port, run, shared_enclave_pubkey, SshdContainer,
    SshencEnv, IMAGE_TAG,
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

fn setup() -> (SshencEnv, SshdContainer) {
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let container = SshdContainer::start(&[&enclave]).expect("start sshd");
    (env, container)
}

/// `sshenc ssh -L <local>:127.0.0.1:22` opens a local-forward
/// tunnel; the test verifies the tunnel is alive by connecting
/// to `127.0.0.1:<local>` and reading the SSH banner from the
/// container's sshd through the tunnel.
#[test]
#[ignore = "requires docker"]
fn sshenc_ssh_local_forward_tunnel_carries_traffic() {
    if skip_if_no_docker("sshenc_ssh_local_forward_tunnel_carries_traffic") {
        return;
    }
    let (env, container) = setup();
    let local_port = pick_free_port().expect("pick port");

    // -N (no remote command), -f (background), -L localport:host:remoteport.
    // The server-side endpoint is the container's own sshd at 127.0.0.1:22
    // (inside the container) — when we connect to localhost:local_port, ssh
    // tunnels through to localhost:22 inside the container, and that's the
    // sshd we'd read SSH-2.0 from.
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
        .arg("ConnectTimeout=10")
        .arg("-o")
        .arg("PreferredAuthentications=publickey")
        .arg("-o")
        .arg("ExitOnForwardFailure=yes")
        .arg("-N")
        .arg("-f")
        .arg("-L")
        .arg(format!("{local_port}:127.0.0.1:22"))
        .arg("sshtest@127.0.0.1");
    let outcome = run(&mut cmd).expect("spawn sshenc ssh -L");
    assert!(
        outcome.succeeded(),
        "sshenc ssh -L failed; stderr:\n{}",
        outcome.stderr
    );

    // The tunnel is open; connect through it and verify the
    // far-side sshd answers with the SSH-2.0 banner.
    let banner_ok = read_ssh_banner(local_port, Duration::from_secs(5));
    // Best-effort cleanup: kill the backgrounded ssh by closing
    // its tunnel-listening port via pkill on host. If pkill fails
    // we leak the process; SshencEnv drop will not catch it
    // because it's not tracked. The container's drop kills the
    // container side, which closes the channel and lets ssh exit.
    drop(
        Command::new("pkill")
            .arg("-f")
            .arg(format!("{local_port}:127.0.0.1:22"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status(),
    );
    assert!(
        banner_ok,
        "tunnel established but did not carry SSH banner from far-side sshd"
    );
}

/// `sshenc ssh -D <port>` opens a SOCKS5 proxy listener locally.
/// We don't need a real SOCKS5 client — the bound listener is
/// proof the auth completed and the dynamic-forward channel was
/// set up. A regression that strips `-D` would either fail auth
/// or fail to bind the port; both are caught here.
#[test]
#[ignore = "requires docker"]
fn sshenc_ssh_dynamic_forward_opens_socks_listener() {
    if skip_if_no_docker("sshenc_ssh_dynamic_forward_opens_socks_listener") {
        return;
    }
    let (env, container) = setup();
    let socks_port = pick_free_port().expect("pick port");

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
        .arg("ConnectTimeout=10")
        .arg("-o")
        .arg("PreferredAuthentications=publickey")
        .arg("-o")
        .arg("ExitOnForwardFailure=yes")
        .arg("-N")
        .arg("-f")
        .arg("-D")
        .arg(socks_port.to_string())
        .arg("sshtest@127.0.0.1");
    let outcome = run(&mut cmd).expect("spawn sshenc ssh -D");
    assert!(
        outcome.succeeded(),
        "sshenc ssh -D failed; stderr:\n{}",
        outcome.stderr
    );

    // SOCKS listener should be accepting on socks_port. We don't
    // do a SOCKS handshake; just prove the TCP bind happened.
    let connected = std::net::TcpStream::connect_timeout(
        &format!("127.0.0.1:{socks_port}").parse().expect("addr"),
        Duration::from_secs(2),
    )
    .is_ok();
    drop(
        Command::new("pkill")
            .arg("-f")
            .arg(format!("-D {socks_port}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status(),
    );
    assert!(
        connected,
        "SOCKS listener at 127.0.0.1:{socks_port} did not accept connections"
    );
}

/// `ssh -o ProxyCommand=…` chains via an intermediate host. Both
/// hops authenticate through the same sshenc agent. If the agent
/// can't service two interleaved auth requests through a single
/// invocation (or if the CLI's argument forwarding strips -W /
/// the ProxyCommand value), this fails.
///
/// The simpler and more reliable test of the chain: open a
/// container, then `sshenc ssh -o ProxyCommand=…` to the same
/// container's sshd through itself. The proxy hop opens via
/// ssh -W, which exercises the same auth path twice through one
/// agent.
#[test]
#[ignore = "requires docker"]
fn sshenc_ssh_proxycommand_chains_through_agent() {
    if skip_if_no_docker("sshenc_ssh_proxycommand_chains_through_agent") {
        return;
    }
    ensure_image().expect("e2e image");
    let _ = IMAGE_TAG; // silence unused-import warning if ensure_image refactors

    let (env, container) = setup();

    // ProxyCommand uses the system `ssh` via env.scrubbed_command;
    // sshenc-ssh's PATH-prepend makes sure the inner `ssh` is the
    // same shell-callable binary. The proxy opens the connection
    // through the container's own sshd (loops back through itself);
    // the outer `sshenc ssh` then talks to that proxied stream.
    //
    // This is contrived but it exercises the right interaction:
    // two ssh connection setups against one shared agent.
    // ProxyCommand uses `sshenc ssh -W` so the inner hop also
    // authenticates through the same agent — that's the contract
    // we're pinning. A regression where sshenc-ssh doesn't pass
    // IdentityAgent into ssh's environment for the inner hop
    // would surface as "publickey rejected" on the proxy step.
    let proxy_cmd = format!(
        "sshenc ssh -W %h:%p \
              -F /dev/null \
              -o StrictHostKeyChecking=accept-new \
              -o UserKnownHostsFile={} \
              -o ConnectTimeout=10 \
              -o PreferredAuthentications=publickey \
              -p {} \
              sshtest@127.0.0.1",
        env.known_hosts().display(),
        container.host_port,
    );

    let mut cmd = env.sshenc_cmd().expect("sshenc cmd");
    cmd.arg("ssh")
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
        .arg(format!("ProxyCommand={proxy_cmd}"))
        .arg("sshtest@127.0.0.1")
        .arg("--")
        .arg("echo proxy-ok");
    let outcome = run(&mut cmd).expect("sshenc ssh ProxyCommand");
    assert!(
        outcome.succeeded(),
        "sshenc ssh with ProxyCommand chain failed; stderr:\n{}",
        outcome.stderr
    );
    assert!(
        outcome.stdout.contains("proxy-ok"),
        "expected 'proxy-ok' in remote stdout; got:\n{}",
        outcome.stdout
    );
}

fn read_ssh_banner(port: u16, timeout: Duration) -> bool {
    use std::io::Read;
    let deadline = Instant::now() + timeout;
    let addr = format!("127.0.0.1:{port}");
    let Ok(addr) = addr.parse() else {
        return false;
    };
    while Instant::now() < deadline {
        if let Ok(mut stream) =
            std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(500))
        {
            stream
                .set_read_timeout(Some(Duration::from_millis(500)))
                .ok();
            let mut buf = [0_u8; 7];
            if stream.read_exact(&mut buf).is_ok() && &buf == b"SSH-2.0" {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}
