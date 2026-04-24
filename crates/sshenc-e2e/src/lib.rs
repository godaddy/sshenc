// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! End-to-end test harness for sshenc.
//!
//! Stands up a throwaway OpenSSH server in a Docker container and provides
//! fixtures that exercise the sshenc binaries against it. See
//! `docs/e2e-design.md` for rationale.

#![allow(clippy::print_stderr, clippy::print_stdout)]

use anyhow::{anyhow, bail, Context, Result};
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};

/// Docker image tag used by the e2e tests.
pub const IMAGE_TAG: &str = "sshenc-e2e-sshd:latest";

/// Binaries the e2e tests invoke, paired with the workspace package that
/// produces them. Built on demand by [`ensure_binaries`].
pub const REQUIRED_BINS: &[(&str, &str)] = &[
    ("sshenc", "sshenc-cli"),
    ("sshenc-agent", "sshenc-agent"),
    ("gitenc", "sshenc-gitenc"),
];

/// Label used for the single shared enclave key that all scenarios reuse.
///
/// Reusing one key dramatically reduces macOS keychain "Always Allow"
/// prompts: each SE key gets its own keychain ACL entry, and each fresh ACL
/// entry means a fresh first-use prompt per binary. One shared label → one
/// ACL entry → one prompt per binary per rebuild.
pub const SHARED_ENCLAVE_LABEL: &str = "e2e-shared";

/// Persistent directory for sshenc's key state, independent of the per-test
/// tempdir `HOME`. Lives under the real user's home so `SshencEnv` tempdir
/// teardown doesn't wipe it — the whole point is that the key survives
/// across test runs so we don't re-create (and re-prompt) every time.
pub fn persistent_keys_dir() -> PathBuf {
    if let Some(override_path) = std::env::var_os("SSHENC_KEYS_DIR") {
        return PathBuf::from(override_path);
    }
    // Hidden directory in the real user's home. Matches the `~/.sshenc` root
    // the product uses, with an `-e2e` suffix so it can never be mistaken
    // for real state.
    let home_var = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .unwrap_or_else(|| std::ffi::OsString::from("/tmp"));
    PathBuf::from(home_var).join(".sshenc-e2e").join("keys")
}

/// Return `Some(reason)` if the e2e suite cannot run on this host.
///
/// Callers print the reason and skip gracefully rather than failing.
pub fn docker_skip_reason() -> Option<String> {
    let Ok(output) = Command::new("docker")
        .args(["info", "--format", "{{.ServerVersion}}"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
    else {
        return Some("docker binary not found in PATH".to_string());
    };
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Some(format!("`docker info` failed: {}", stderr.trim()));
    }
    None
}

/// Compile the binaries this suite needs. Idempotent; runs once per process.
pub fn ensure_binaries() -> Result<()> {
    static BUILT: OnceLock<Result<(), String>> = OnceLock::new();
    let result = BUILT.get_or_init(|| build_binaries().map_err(|e| e.to_string()));
    match result {
        Ok(()) => Ok(()),
        Err(msg) => Err(anyhow!("failed to build required binaries: {msg}")),
    }
}

fn build_binaries() -> Result<()> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let mut cmd = Command::new(cargo);
    cmd.arg("build");
    for (bin, package) in REQUIRED_BINS {
        cmd.args(["-p", package, "--bin", bin]);
    }
    if is_release_profile() {
        cmd.arg("--release");
    }
    let output = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("invoke cargo build")?;
    if !output.status.success() {
        bail!(
            "cargo build failed (exit {:?}):\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    Ok(())
}

/// Build the OpenSSH test image once per process.
pub fn ensure_image() -> Result<()> {
    static BUILT: OnceLock<Result<(), String>> = OnceLock::new();
    let result = BUILT.get_or_init(|| build_image().map_err(|e| e.to_string()));
    match result {
        Ok(()) => Ok(()),
        Err(msg) => Err(anyhow!("failed to build e2e image: {msg}")),
    }
}

fn build_image() -> Result<()> {
    let docker_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("docker");
    let output = Command::new("docker")
        .args(["build", "-t", IMAGE_TAG, "."])
        .current_dir(&docker_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("failed to invoke docker build in {}", docker_dir.display()))?;
    if !output.status.success() {
        bail!(
            "docker build failed (exit {:?}):\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    Ok(())
}

/// Resolve `target/<profile>/<bin_name>` by walking up from `current_exe`.
pub fn workspace_bin(name: &str) -> Result<PathBuf> {
    let exe = std::env::current_exe().context("current_exe")?;
    let target_profile_dir = exe
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| anyhow!("could not locate target/<profile>/ from {}", exe.display()))?;
    let candidate = target_profile_dir.join(name);
    if candidate.exists() {
        return Ok(candidate);
    }
    bail!("binary {name} not found at {}", candidate.display());
}

fn is_release_profile() -> bool {
    std::env::current_exe()
        .ok()
        .and_then(|exe| {
            exe.parent()
                .and_then(Path::parent)
                .and_then(|p| p.file_name().map(|s| s.to_os_string()))
        })
        .is_some_and(|name| name == OsStr::new("release"))
}

/// A running OpenSSH container. Killed on drop.
#[derive(Debug)]
pub struct SshdContainer {
    id: String,
    /// Host-side TCP port mapped to the container's sshd.
    pub host_port: u16,
}

impl SshdContainer {
    /// Start a container with `authorized_keys` lines installed for user
    /// `sshtest`. Binds to a random `127.0.0.1` port.
    pub fn start(authorized_keys: &[&str]) -> Result<Self> {
        ensure_image()?;

        let tmp = tempdir()?;
        let auth_path = tmp.join("authorized_keys");
        let content: String = authorized_keys
            .iter()
            .map(|line| {
                let trimmed = line.trim_end_matches('\n');
                format!("{trimmed}\n")
            })
            .collect();
        fs::write(&auth_path, content)
            .with_context(|| format!("writing {}", auth_path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&auth_path, fs::Permissions::from_mode(0o644))?;
        }

        let output = Command::new("docker")
            .args(["run", "--rm", "-d", "-p", "127.0.0.1:0:22", "-v"])
            .arg(format!("{}:/authorized_keys:ro", auth_path.display()))
            .arg(IMAGE_TAG)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context("docker run")?;
        if !output.status.success() {
            drop(tmp_cleanup(&tmp));
            bail!(
                "docker run failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        let id = String::from_utf8(output.stdout)
            .context("container id not utf-8")?
            .trim()
            .to_string();
        if id.is_empty() {
            drop(tmp_cleanup(&tmp));
            bail!("docker run returned empty container id");
        }

        let mut container = SshdContainer { id, host_port: 0 };
        match container.discover_host_port().and_then(|port| {
            container.wait_for_tcp(port, Duration::from_secs(15))?;
            Ok(port)
        }) {
            Ok(port) => container.host_port = port,
            Err(e) => {
                eprintln!("e2e: container failed to become ready: {e}");
                drop(container); // kill on failure
                drop(tmp_cleanup(&tmp));
                return Err(e);
            }
        }

        drop(tmp_cleanup(&tmp));
        Ok(container)
    }

    fn discover_host_port(&self) -> Result<u16> {
        let output = Command::new("docker")
            .args(["port", &self.id, "22/tcp"])
            .output()
            .context("docker port")?;
        if !output.status.success() {
            bail!(
                "docker port failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if let Some((_, port)) = line.rsplit_once(':') {
                if let Ok(port) = port.trim().parse::<u16>() {
                    return Ok(port);
                }
            }
        }
        bail!("could not parse host port from: {stdout}")
    }

    /// Wait until sshd is talking SSH on the host-mapped port. TCP accept
    /// alone is not enough: Docker's userspace proxy binds the host port
    /// before the container's sshd starts, so a plain `connect` returns
    /// `Ok` long before the server can complete a kex. We wait for the
    /// `SSH-2.0` banner on stdin.
    fn wait_for_tcp(&self, port: u16, timeout: Duration) -> Result<()> {
        use std::io::Read;
        let deadline = Instant::now() + timeout;
        let addr: std::net::SocketAddr =
            format!("127.0.0.1:{port}").parse().context("addr parse")?;
        loop {
            if let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(500)) {
                stream
                    .set_read_timeout(Some(Duration::from_millis(500)))
                    .ok();
                let mut buf = [0_u8; 7];
                if stream.read_exact(&mut buf).is_ok() && &buf == b"SSH-2.0" {
                    return Ok(());
                }
            }
            if Instant::now() >= deadline {
                bail!("sshd did not answer SSH banner on {addr} within {timeout:?}");
            }
            thread::sleep(Duration::from_millis(200));
        }
    }
}

impl Drop for SshdContainer {
    fn drop(&mut self) {
        drop(
            Command::new("docker")
                .args(["kill", &self.id])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status(),
        );
    }
}

/// Isolated `HOME` + child process environment for one sshenc test.
#[derive(Debug)]
pub struct SshencEnv {
    home: PathBuf,
    /// Override for `SSHENC_KEYS_DIR`. When `None`, children inherit the
    /// shared persistent path from [`persistent_keys_dir`] so the one
    /// shared enclave key stays reachable. When `Some(path)`, children use
    /// that path — the escape hatch for scenarios like "agent has no
    /// enclave keys" that need a truly empty backend without disturbing
    /// the shared key.
    keys_dir_override: Option<PathBuf>,
    agent: Option<Child>,
}

impl SshencEnv {
    pub fn new() -> Result<Self> {
        ensure_binaries()?;
        let home = tempdir()?;
        fs::create_dir_all(home.join(".ssh"))?;
        fs::create_dir_all(home.join(".sshenc"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(home.join(".ssh"), fs::Permissions::from_mode(0o700))?;
            fs::set_permissions(home.join(".sshenc"), fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self {
            home,
            keys_dir_override: None,
            agent: None,
        })
    }

    /// Point this env's `SSHENC_KEYS_DIR` at a fresh tempdir instead of the
    /// shared persistent path. Use this for scenarios that require an
    /// empty sshenc backend (no enclave keys present). The shared enclave
    /// key remains untouched in its persistent location.
    pub fn use_ephemeral_keys_dir(&mut self) -> Result<()> {
        let dir = self.home.join(".sshenc-keys-ephemeral");
        fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        }
        self.keys_dir_override = Some(dir);
        Ok(())
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    pub fn ssh_dir(&self) -> PathBuf {
        self.home.join(".ssh")
    }

    pub fn socket_path(&self) -> PathBuf {
        self.home.join(".sshenc").join("agent.sock")
    }

    pub fn known_hosts(&self) -> PathBuf {
        self.home.join(".ssh").join("known_hosts")
    }

    /// Start `sshenc-agent --foreground` bound to `socket_path()`. Blocks
    /// until the socket is listening.
    pub fn start_agent(&mut self) -> Result<()> {
        if self.agent.is_some() {
            return Ok(());
        }
        let socket = self.socket_path();
        if socket.exists() {
            drop(fs::remove_file(&socket));
        }
        let bin = workspace_bin("sshenc-agent")?;
        let child = self
            .scrubbed_command(&bin)
            .args(["--foreground", "--socket"])
            .arg(&socket)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("spawn sshenc-agent")?;
        self.agent = Some(child);

        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if socket.exists() {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(50));
        }
        bail!(
            "sshenc-agent did not create socket {} in time",
            socket.display()
        );
    }

    pub fn stop_agent(&mut self) {
        if let Some(mut child) = self.agent.take() {
            drop(child.kill());
            drop(child.wait());
        }
    }

    /// `Command` with `HOME` pinned and common env scrubbed so tests don't
    /// pick up the developer's actual ssh state.
    ///
    /// Also pins `SSHENC_KEYS_DIR` to a persistent path so the shared
    /// enclave key survives across test runs. Without this, every run would
    /// create a fresh SE key and the macOS keychain would prompt again.
    pub fn scrubbed_command<S: AsRef<OsStr>>(&self, program: S) -> Command {
        let mut cmd = Command::new(program);
        cmd.env_clear();
        cmd.env("PATH", std::env::var("PATH").unwrap_or_default());
        cmd.env("HOME", &self.home);
        cmd.env("USER", whoami());
        cmd.env("LOGNAME", whoami());
        cmd.env("LANG", "C.UTF-8");
        cmd.env("TERM", "dumb");
        let keys_dir = self
            .keys_dir_override
            .clone()
            .unwrap_or_else(persistent_keys_dir);
        cmd.env("SSHENC_KEYS_DIR", keys_dir);
        cmd
    }

    pub fn sshenc_cmd(&self) -> Result<Command> {
        Ok(self.scrubbed_command(workspace_bin("sshenc")?))
    }

    /// Run the system `ssh` against the container. Writes to `known_hosts`
    /// in the tempdir, never to the real `~/.ssh/known_hosts`.
    ///
    /// Passes `-F /dev/null` to skip the user's real `~/.ssh/config` — on
    /// macOS OpenSSH resolves that path via `getpwuid`, not `$HOME`, so
    /// setting `HOME` to the tempdir is not enough on its own.
    pub fn ssh_cmd(&self, container: &SshdContainer) -> Command {
        let mut cmd = self.scrubbed_command("ssh");
        Self::apply_ssh_isolation(&mut cmd, container.host_port, &self.known_hosts());
        cmd
    }

    /// Append the per-test ssh option set: skip user config, pinned
    /// `known_hosts`, pubkey-only, short timeouts. Shared between the
    /// direct `ssh_cmd` path and `sshenc ssh -- ...` invocations.
    pub fn apply_ssh_isolation(cmd: &mut Command, port: u16, known_hosts: &Path) {
        cmd.arg("-p")
            .arg(port.to_string())
            .arg("-F")
            .arg("/dev/null")
            .arg("-o")
            .arg("StrictHostKeyChecking=accept-new")
            .arg("-o")
            .arg(format!("UserKnownHostsFile={}", known_hosts.display()))
            .arg("-o")
            .arg("ConnectTimeout=10")
            .arg("-o")
            .arg("NumberOfPasswordPrompts=0")
            .arg("-o")
            .arg("PreferredAuthentications=publickey");
    }
}

impl Drop for SshencEnv {
    fn drop(&mut self) {
        self.stop_agent();
        drop(fs::remove_dir_all(&self.home));
    }
}

/// Generate an on-disk ed25519 key pair at `$HOME/.ssh/id_ed25519`.
/// Returns the OpenSSH pubkey line.
pub fn generate_on_disk_ed25519(env: &SshencEnv, comment: &str) -> Result<String> {
    let priv_path = env.ssh_dir().join("id_ed25519");
    if priv_path.exists() {
        drop(fs::remove_file(&priv_path));
    }
    let pub_path = env.ssh_dir().join("id_ed25519.pub");
    let status = env
        .scrubbed_command("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-C", comment, "-f"])
        .arg(&priv_path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .status()
        .context("spawn ssh-keygen")?;
    if !status.success() {
        bail!("ssh-keygen -t ed25519 failed: {status}");
    }
    let line =
        fs::read_to_string(&pub_path).with_context(|| format!("reading {}", pub_path.display()))?;
    Ok(line.trim().to_string())
}

/// Ensure the shared enclave key exists, creating it idempotently on first
/// use. Returns the OpenSSH pubkey line. Subsequent calls short-circuit
/// via a process-local `OnceLock` and cross-run persistence via
/// [`persistent_keys_dir`].
///
/// The key is intentionally shared across all enclave-needing scenarios so
/// macOS only prompts once-per-binary-per-rebuild for keychain access.
pub fn shared_enclave_pubkey(env: &SshencEnv) -> Result<String> {
    static CACHE: OnceLock<Result<String, String>> = OnceLock::new();
    let result = CACHE.get_or_init(|| init_shared_enclave_key(env).map_err(|e| e.to_string()));
    match result {
        Ok(line) => Ok(line.clone()),
        Err(msg) => Err(anyhow!("shared enclave key init failed: {msg}")),
    }
}

fn init_shared_enclave_key(env: &SshencEnv) -> Result<String> {
    // Fast path: key already exists from a prior run — just export its pubkey.
    if let Some(line) = try_export_pub(env, SHARED_ENCLAVE_LABEL)? {
        return Ok(line);
    }
    // Slow path: generate once. On macOS this is the step that can prompt
    // the user (for the keychain wrapping-key entry), and it will prompt
    // zero times on subsequent runs because we reuse the same label+dir.
    let output = env
        .sshenc_cmd()?
        .args([
            "keygen",
            "--label",
            SHARED_ENCLAVE_LABEL,
            "--auth-policy",
            "none",
            "--no-pub-file",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("spawn sshenc keygen")?;
    if !output.status.success() {
        bail!(
            "sshenc keygen --label {SHARED_ENCLAVE_LABEL} failed: {}\nstderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    try_export_pub(env, SHARED_ENCLAVE_LABEL)?
        .ok_or_else(|| anyhow!("keygen succeeded but export-pub found nothing"))
}

/// Return `Ok(Some(line))` if `sshenc export-pub <label>` succeeds with a
/// non-empty line, `Ok(None)` if the key does not exist. Bubbles other
/// errors up.
fn try_export_pub(env: &SshencEnv, label: &str) -> Result<Option<String>> {
    let output = env
        .sshenc_cmd()?
        .args(["export-pub", label])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("spawn sshenc export-pub")?;
    if output.status.success() {
        let line = String::from_utf8(output.stdout)
            .context("export-pub output not utf-8")?
            .trim()
            .to_string();
        return Ok(if line.is_empty() { None } else { Some(line) });
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    // The CLI does not expose a stable "not found" exit code; fall back to
    // substring detection. Any unrelated error surfaces up the stack.
    if stderr.contains("not found")
        || stderr.contains("does not exist")
        || stderr.contains("no key")
    {
        return Ok(None);
    }
    // Treat as "not present" if the keys dir is empty or the underlying
    // backend reports no such label; this matches what happens on a clean
    // first run before the shared key exists.
    if stderr.contains("KeyNotFound") || stderr.contains("label") {
        return Ok(None);
    }
    bail!(
        "sshenc export-pub {label} failed unexpectedly: {}\nstderr: {}",
        output.status,
        stderr
    );
}

/// Result of a completed child process, with stdout/stderr captured as UTF-8.
#[derive(Debug)]
pub struct RunOutcome {
    pub status: std::process::ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

impl RunOutcome {
    pub fn succeeded(&self) -> bool {
        self.status.success()
    }
}

pub fn run(cmd: &mut Command) -> Result<RunOutcome> {
    let output = cmd.output().context("spawn child")?;
    Ok(RunOutcome {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

fn tempdir() -> Result<PathBuf> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let pid = std::process::id();
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!("sshenc-e2e-{pid}-{nanos}-{n}"));
    fs::create_dir_all(&path)?;
    Ok(path)
}

fn tmp_cleanup(path: &Path) -> io::Result<()> {
    fs::remove_dir_all(path)
}

fn whoami() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "sshenc-e2e".into())
}
