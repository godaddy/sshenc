// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! sshenc-agent: SSH agent daemon for Secure Enclave keys.

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

#[cfg(unix)]
use std::path::Path;

use sshenc_agent::server;

#[derive(Parser)]
#[command(
    name = "sshenc-agent",
    about = "SSH agent daemon exposing hardware-backed identities to OpenSSH",
    long_about = "sshenc-agent is an ssh-agent-compatible daemon that serves hardware-backed\n\
                   SSH identities. It creates a Unix socket (macOS/Linux) or named pipe (Windows)\n\
                   and handles identity enumeration and signing requests using keys stored in\n\
                   the platform's hardware security module.\n\n\
                   By default the agent daemonizes (backgrounds itself). Use --foreground to\n\
                   keep it in the terminal.",
    version
)]
struct Cli {
    /// Path for the agent socket (Unix) or pipe name (Windows).
    #[arg(long, short = 's', default_value_t = default_socket_or_pipe())]
    socket: String,

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

    /// Internal flag: the process is already the daemon child (Windows only).
    #[arg(long = "_internal-daemon", hide = true)]
    _internal_daemon: bool,
}

#[cfg(unix)]
fn default_socket_or_pipe() -> String {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".sshenc")
        .join("agent.sock")
        .to_string_lossy()
        .into_owned()
}

#[cfg(windows)]
fn default_socket_or_pipe() -> String {
    r"\\.\pipe\sshenc-agent".to_string()
}

fn default_pid_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".sshenc")
        .join("agent.pid")
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Daemonize MUST happen before any threads are spawned (e.g., tokio runtime),
    // because fork() in a multi-threaded process leads to undefined behavior.
    #[cfg(unix)]
    if !cli.foreground {
        daemonize(&cli.socket)?;
    }

    #[cfg(windows)]
    #[allow(clippy::used_underscore_binding)]
    if !cli.foreground && !cli._internal_daemon {
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
        socket = %cli.socket,
        labels = ?allowed_labels,
        "starting sshenc-agent"
    );

    let rt = tokio::runtime::Runtime::new()?;

    #[cfg(unix)]
    {
        let socket_path = PathBuf::from(&cli.socket);
        rt.block_on(server::run_agent(socket_path, allowed_labels))
    }

    #[cfg(windows)]
    {
        rt.block_on(server::run_agent(cli.socket, allowed_labels))
    }
}

/// Fork to background, detach from terminal, write pidfile.
#[cfg(unix)]
#[allow(unsafe_code, clippy::print_stdout, clippy::exit)]
fn daemonize(socket_path: &str) -> Result<()> {
    let socket_display = Path::new(socket_path).display();
    // Print connection info before forking (parent process)
    println!("SSH_AUTH_SOCK={socket_display}");
    println!("export SSH_AUTH_SOCK={socket_display}");

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
        if libc::dup2(fd, 0) == -1 {
            anyhow::bail!("dup2 stdin failed: {}", std::io::Error::last_os_error());
        }
        if libc::dup2(fd, 1) == -1 {
            anyhow::bail!("dup2 stdout failed: {}", std::io::Error::last_os_error());
        }
        if libc::dup2(fd, 2) == -1 {
            anyhow::bail!("dup2 stderr failed: {}", std::io::Error::last_os_error());
        }
    }

    Ok(())
}

/// Re-exec as a detached background process and write pidfile (Windows).
#[cfg(windows)]
#[allow(clippy::exit)]
fn daemonize(pipe_name: &str) -> Result<()> {
    use std::os::windows::process::CommandExt;

    // CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const DETACHED_PROCESS: u32 = 0x0000_0008;

    let exe = std::env::current_exe()?;
    let child = std::process::Command::new(&exe)
        .arg("--socket")
        .arg(pipe_name)
        .arg("--_internal-daemon")
        .creation_flags(CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to spawn daemon: {e}"))?;

    // Write pidfile
    let pid_path = default_pid_path();
    if let Some(parent) = pid_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&pid_path, format!("{}\n", child.id())).ok();

    std::process::exit(0);
}
