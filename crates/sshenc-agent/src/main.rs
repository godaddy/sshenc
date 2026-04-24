// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! sshenc-agent: SSH agent daemon for Secure Enclave keys.

use anyhow::{Context, Result};
use clap::Parser;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sshenc_agent::server;

const READY_FILE_ENV: &str = "SSHENC_AGENT_READY_FILE";
const DAEMON_READY_TIMEOUT: Duration = Duration::from_secs(10);

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
        .unwrap_or_else(|| std::env::temp_dir().join("sshenc"))
        .join(".sshenc")
        .join("agent.sock")
        .to_string_lossy()
        .into_owned()
}

#[cfg(windows)]
fn default_socket_or_pipe() -> String {
    r"\\.\pipe\openssh-ssh-agent".to_string()
}

fn default_pid_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| std::env::temp_dir().join("sshenc"))
        .join(".sshenc")
        .join("agent.pid")
}

fn write_pid_file(pid_path: &Path, pid: u32) -> Result<()> {
    if let Some(parent) = pid_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create pid directory {}", parent.display()))?;
    }
    std::fs::write(pid_path, format!("{pid}\n"))
        .with_context(|| format!("failed to write pid file {}", pid_path.display()))?;
    Ok(())
}

fn remove_pid_file(pid_path: &Path) -> Result<()> {
    match std::fs::remove_file(pid_path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("failed to remove pid file {}", pid_path.display()))
        }
    }
}

fn write_ready_file_contents(path: &Path, content: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!("failed to create readiness directory {}", parent.display())
        })?;
    }

    std::fs::write(path, content)
        .with_context(|| format!("failed to write readiness file {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        drop(std::fs::set_permissions(
            path,
            std::fs::Permissions::from_mode(0o600),
        ));
    }
    Ok(())
}

#[cfg(test)]
fn write_ready_file(path: &Path) -> Result<()> {
    write_ready_file_contents(path, "ready\n")
}

fn write_ready_error_file(path: &Path, message: &str) -> Result<()> {
    write_ready_file_contents(path, &format!("error:{message}\n"))
}

fn wait_for_ready_file(path: &Path, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if path.exists() {
            let content = std::fs::read_to_string(path)
                .with_context(|| format!("failed to read readiness file {}", path.display()))?;
            let trimmed = content.trim();
            if trimmed == "ready" {
                return Ok(());
            }
            if let Some(error) = trimmed.strip_prefix("error:") {
                anyhow::bail!("{error}");
            }
            // File exists but content is empty or not yet fully written —
            // keep polling until the deadline.
            if trimmed.is_empty() {
                std::thread::sleep(Duration::from_millis(20));
                continue;
            }
            anyhow::bail!("invalid readiness marker in {}", path.display());
        }

        if Instant::now() >= deadline {
            anyhow::bail!("sshenc-agent timed out waiting for readiness");
        }

        std::thread::sleep(Duration::from_millis(20));
    }
}

fn unique_ready_file_path() -> PathBuf {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!("sshenc-agent-ready-{pid}-{nanos}.tmp"))
}

fn take_ready_file_from_env() -> Option<PathBuf> {
    std::env::var_os(READY_FILE_ENV).map(PathBuf::from)
}

fn signal_ready_error(path: Option<&Path>, error: &anyhow::Error) {
    if let Some(path) = path {
        let _unused = write_ready_error_file(path, &error.to_string());
    }
}

#[cfg(unix)]
fn validate_setsid_result(result: libc::pid_t) -> Result<()> {
    if result == -1 {
        anyhow::bail!("setsid failed: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn start_new_session() -> Result<()> {
    validate_setsid_result(unsafe { libc::setsid() })
}

fn main() -> Result<()> {
    enclaveapp_core::process::harden_process();

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
        daemonize(&cli)?;
    }

    let ready_file = take_ready_file_from_env();
    let config = match &cli.config {
        Some(path) => sshenc_core::Config::load(path),
        None => sshenc_core::Config::load_default(),
    };
    let config = match config {
        Ok(config) => config,
        Err(error) => {
            let error = anyhow::Error::from(error);
            signal_ready_error(ready_file.as_deref(), &error);
            return Err(error);
        }
    };

    let level = if cli.debug {
        "debug"
    } else {
        config.log_level.as_tracing_str()
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level)),
        )
        .init();

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

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(error) => {
            let error = anyhow::Error::from(error);
            signal_ready_error(ready_file.as_deref(), &error);
            return Err(error);
        }
    };

    // Wrapping-key cache TTL precedence:
    //   1. SSHENC_WRAPPING_KEY_CACHE_TTL_SECS env (test/ad-hoc override)
    //   2. config.toml `wrapping_key_cache_ttl_secs`
    //   3. compiled-in default (300s)
    let wrapping_key_cache_ttl = std::env::var_os("SSHENC_WRAPPING_KEY_CACHE_TTL_SECS")
        .and_then(|v| v.to_string_lossy().parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(config.wrapping_key_cache_ttl_secs));

    #[cfg(unix)]
    {
        let socket_path = PathBuf::from(&cli.socket);
        let result = rt.block_on(server::run_agent(
            socket_path,
            config.pub_dir.clone(),
            allowed_labels,
            config.prompt_policy,
            wrapping_key_cache_ttl,
            ready_file.as_deref(),
        ));
        if let Err(ref error) = result {
            signal_ready_error(ready_file.as_deref(), error);
        }
        result
    }

    #[cfg(windows)]
    {
        let result = rt.block_on(server::run_agent(
            cli.socket,
            config.pub_dir.clone(),
            allowed_labels,
            config.prompt_policy,
            wrapping_key_cache_ttl,
            ready_file.as_deref(),
        ));
        if let Err(ref error) = result {
            signal_ready_error(ready_file.as_deref(), error);
        }
        result
    }
}

/// Fork to background, detach from terminal, write pidfile.
#[cfg(unix)]
#[allow(unsafe_code, clippy::print_stdout, clippy::exit)]
fn daemonize(socket_path: &str) -> Result<()> {
    let socket_display = Path::new(socket_path).display();
    let ready_path = unique_ready_file_path();
    let _unused = std::fs::remove_file(&ready_path);

    // Fork
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        anyhow::bail!("fork failed");
    }
    if pid > 0 {
        // Parent — write pidfile and exit
        let pid_path = default_pid_path();
        if let Err(error) = write_pid_file(&pid_path, pid as u32) {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                libc::waitpid(pid, std::ptr::null_mut(), 0);
            }
            return Err(error);
        }
        if let Err(error) = wait_for_ready_file(&ready_path, DAEMON_READY_TIMEOUT) {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                libc::waitpid(pid, std::ptr::null_mut(), 0);
            }
            let _unused = std::fs::remove_file(&ready_path);
            let _unused = remove_pid_file(&pid_path);
            return Err(error);
        }
        let _unused = std::fs::remove_file(&ready_path);
        println!("SSH_AUTH_SOCK={socket_display}");
        println!("export SSH_AUTH_SOCK={socket_display}");
        std::process::exit(0);
    }

    // Child — new session, close stdio
    start_new_session()?;

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

    // SAFETY: setting process environment in the single-threaded post-fork child
    // before any runtime threads are created is safe.
    unsafe {
        std::env::set_var(READY_FILE_ENV, &ready_path);
    }

    Ok(())
}

/// Re-exec as a detached background process and write pidfile (Windows).
#[cfg(windows)]
#[allow(clippy::exit)]
fn daemonize(cli: &Cli) -> Result<()> {
    use std::os::windows::process::CommandExt;

    // CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const DETACHED_PROCESS: u32 = 0x0000_0008;

    let exe = std::env::current_exe()?;
    let ready_path = unique_ready_file_path();
    let _unused = std::fs::remove_file(&ready_path);
    let mut cmd = std::process::Command::new(&exe);
    cmd.arg("--socket")
        .arg(&cli.socket)
        .arg("--_internal-daemon");
    if cli.debug {
        cmd.arg("--debug");
    }
    if let Some(ref config) = cli.config {
        cmd.arg("--config").arg(config);
    }
    if !cli.labels.is_empty() {
        cmd.arg("--labels").arg(cli.labels.join(","));
    }
    let mut child = cmd
        .creation_flags(CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .env(READY_FILE_ENV, &ready_path)
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to spawn daemon: {e}"))?;

    // Write pidfile
    let pid_path = default_pid_path();
    if let Err(error) = write_pid_file(&pid_path, child.id()) {
        let _unused = child.kill();
        let _unused = child.wait();
        return Err(error);
    }
    if let Err(error) = wait_for_ready_file(&ready_path, DAEMON_READY_TIMEOUT) {
        let _unused = child.kill();
        let _unused = child.wait();
        let _unused = std::fs::remove_file(&ready_path);
        let _unused = remove_pid_file(&pid_path);
        return Err(error);
    }
    let _unused = std::fs::remove_file(&ready_path);

    std::process::exit(0);
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::thread;

    fn test_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("sshenc-agent-test-{}-{name}", std::process::id()))
    }

    #[test]
    fn write_pid_file_creates_parent_and_persists_pid() {
        let path = test_path("pid").join("subdir").join("agent.pid");
        if let Some(parent) = path.parent() {
            let _unused = std::fs::remove_dir_all(parent);
        }

        write_pid_file(&path, 4242).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "4242\n");

        if let Some(parent) = path.parent() {
            std::fs::remove_dir_all(parent.parent().unwrap_or(parent)).unwrap();
        }
    }

    #[test]
    fn write_pid_file_errors_when_parent_is_not_a_directory() {
        let root = test_path("bad-parent");
        let _unused = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let blocker = root.join("not-a-dir");
        std::fs::write(&blocker, b"blocker").unwrap();
        let pid_path = blocker.join("agent.pid");

        let err = write_pid_file(&pid_path, 7).unwrap_err();
        assert!(err.to_string().contains("failed to create pid directory"));

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn remove_pid_file_removes_existing_file() {
        let path = test_path("remove-pid");
        let _unused = std::fs::remove_file(&path);
        std::fs::write(&path, b"4242\n").unwrap();

        remove_pid_file(&path).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn remove_pid_file_ignores_missing_file() {
        let path = test_path("remove-missing-pid");
        let _unused = std::fs::remove_file(&path);
        remove_pid_file(&path).unwrap();
    }

    #[test]
    fn wait_for_ready_file_observes_ready_marker() {
        let path = test_path("ready-marker");
        let _unused = std::fs::remove_file(&path);
        let writer_path = path.clone();

        let writer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            write_ready_file(&writer_path).unwrap();
        });

        wait_for_ready_file(&path, Duration::from_secs(1)).unwrap();
        writer.join().unwrap();
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn wait_for_ready_file_reports_child_error() {
        let path = test_path("ready-error");
        let _unused = std::fs::remove_file(&path);
        write_ready_error_file(&path, "backend init failed").unwrap();

        let error = wait_for_ready_file(&path, Duration::from_secs(1)).unwrap_err();
        assert!(error.to_string().contains("backend init failed"));

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn wait_for_ready_file_times_out() {
        let path = test_path("ready-timeout");
        let _unused = std::fs::remove_file(&path);

        let error = wait_for_ready_file(&path, Duration::from_millis(50)).unwrap_err();
        assert!(error.to_string().contains("timed out"));
    }

    #[test]
    fn default_socket_or_pipe_returns_valid_path() {
        let path = default_socket_or_pipe();
        assert!(
            !path.is_empty(),
            "default socket/pipe path should not be empty"
        );
        #[cfg(unix)]
        assert!(
            path.contains("agent.sock"),
            "Unix socket path should contain 'agent.sock': {path}"
        );
        #[cfg(windows)]
        assert!(
            path.contains(r"\\.\pipe\"),
            "Windows pipe path should contain named pipe prefix: {path}"
        );
    }

    #[test]
    fn default_pid_path_returns_valid_path() {
        let path = default_pid_path();
        let path_str = path.to_string_lossy();
        assert!(
            path_str.contains("agent.pid"),
            "pid path should contain 'agent.pid': {path_str}"
        );
    }

    #[test]
    fn write_ready_file_creates_file_with_ready_content() {
        let path = test_path("ready-content");
        let _unused = std::fs::remove_file(&path);

        write_ready_file(&path).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "ready\n");

        std::fs::remove_file(&path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn write_ready_file_contents_sets_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let path = test_path("ready-perms");
        let _unused = std::fs::remove_file(&path);

        write_ready_file_contents(&path, "ready\n").unwrap();
        let metadata = std::fs::metadata(&path).unwrap();
        assert_eq!(
            metadata.permissions().mode() & 0o777,
            0o600,
            "ready file should have 0o600 permissions"
        );

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn write_ready_error_file_creates_error_content() {
        let path = test_path("ready-error-content");
        let _unused = std::fs::remove_file(&path);

        write_ready_error_file(&path, "something broke").unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "error:something broke\n");

        std::fs::remove_file(&path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn validate_setsid_result_rejects_failure() {
        let error = validate_setsid_result(-1).unwrap_err();
        assert!(error.to_string().contains("setsid failed"));
    }

    #[cfg(unix)]
    #[test]
    fn validate_setsid_result_accepts_success() {
        validate_setsid_result(1).unwrap();
    }
}
