// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! sshenc-agent: SSH agent daemon for Secure Enclave keys.

use anyhow::Result;
use clap::Parser;
use std::path::{Path, PathBuf};

use sshenc_agent::server;

#[derive(Parser)]
#[command(
    name = "sshenc-agent",
    about = "SSH agent daemon exposing Secure Enclave-backed identities to OpenSSH",
    long_about = "sshenc-agent is an ssh-agent-compatible daemon that serves Secure Enclave-backed\n\
                   SSH identities. It creates a Unix socket and handles identity enumeration\n\
                   and signing requests using keys stored in the macOS Secure Enclave.\n\n\
                   By default the agent daemonizes (backgrounds itself). Use --foreground to\n\
                   keep it in the terminal.",
    version
)]
struct Cli {
    /// Path for the agent Unix socket.
    #[arg(long, short = 's', default_value_os_t = default_socket_path())]
    socket: PathBuf,

    /// Run in foreground (don't daemonize).
    #[arg(long, short = 'f')]
    foreground: bool,

    /// Enable debug logging.
    #[arg(long, short = 'd')]
    debug: bool,

    /// Config file path.
    #[arg(long, short = 'c')]
    config: Option<PathBuf>,

    /// Only expose keys matching these labels (comma-separated).
    #[arg(long, value_delimiter = ',')]
    labels: Vec<String>,
}

fn default_socket_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".sshenc")
        .join("agent.sock")
}

fn default_pid_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".sshenc")
        .join("agent.pid")
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if !cli.foreground {
        daemonize(&cli.socket)?;
    }

    let level = if cli.debug { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level)),
        )
        .init();

    let config = match &cli.config {
        Some(path) => sshenc_core::Config::load(path)?,
        None => sshenc_core::Config::load_default()?,
    };

    let allowed_labels = if cli.labels.is_empty() {
        config.allowed_labels.clone()
    } else {
        cli.labels.clone()
    };

    tracing::info!(
        socket = %cli.socket.display(),
        labels = ?allowed_labels,
        "starting sshenc-agent"
    );

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(server::run_agent(cli.socket, allowed_labels))
}

/// Fork to background, detach from terminal, write pidfile.
fn daemonize(socket_path: &Path) -> Result<()> {
    // Print connection info before forking (parent process)
    println!("SSH_AUTH_SOCK={}", socket_path.display());
    println!("export SSH_AUTH_SOCK={}", socket_path.display());

    // Fork
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        anyhow::bail!("fork failed");
    }
    if pid > 0 {
        // Parent — write pidfile and exit
        let pid_path = default_pid_path();
        if let Some(parent) = pid_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(&pid_path, format!("{pid}\n")).ok();
        std::process::exit(0);
    }

    // Child — new session, close stdio
    unsafe {
        libc::setsid();
    }

    // Redirect stdin/stdout/stderr to /dev/null
    use std::os::unix::io::AsRawFd;
    let devnull = std::fs::File::open("/dev/null")?;
    let fd = devnull.as_raw_fd();
    unsafe {
        libc::dup2(fd, 0); // stdin
        libc::dup2(fd, 1); // stdout
        libc::dup2(fd, 2); // stderr
    }

    Ok(())
}
