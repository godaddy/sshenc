// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! SSH agent server implementation (Unix sockets / Windows named pipes).
//!
//! Serves only hardware-backed keys. Legacy SSH keys from ~/.ssh/ are
//! handled by OpenSSH directly — the agent doesn't need to proxy them.

use anyhow::Result;
use sshenc_agent_proto::message::{self, AgentRequest, AgentResponse, Identity};
use sshenc_agent_proto::signature;
use sshenc_core::config::PromptPolicy;
use sshenc_core::pubkey::SshPublicKey;
use sshenc_core::AccessPolicy;
use sshenc_se::KeyBackend;
use std::collections::HashSet;
#[cfg(unix)]
use std::collections::VecDeque;
#[cfg(target_os = "linux")]
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(unix)]
use std::time::Instant;
use tokio::signal;

#[cfg(unix)]
use tokio::net::UnixListener;

/// Verify the connecting process has the same UID as the agent.
///
/// Uses `getpeereid` on macOS/BSDs, falling back to `SO_PEERCRED` on Linux.
/// Returns `false` (reject) if peer credentials cannot be determined.
///
/// # Safety rationale
///
/// The unsafe blocks call well-defined POSIX C functions (`getuid`,
/// `getpeereid`, `getsockopt`) with correct argument types. The fd comes
/// from an owned `UnixStream` so it is guaranteed valid for the duration
/// of this call.
#[cfg(unix)]
#[allow(unsafe_code)]
fn verify_peer_uid(stream: &tokio::net::UnixStream) -> bool {
    use std::os::unix::io::AsRawFd;

    let our_uid = unsafe { libc::getuid() };
    let fd = stream.as_raw_fd();

    // getpeereid works on macOS and BSDs
    #[cfg(not(target_os = "linux"))]
    {
        let mut peer_uid: libc::uid_t = 0;
        let mut peer_gid: libc::gid_t = 0;
        let result = unsafe { libc::getpeereid(fd, &mut peer_uid, &mut peer_gid) };
        if result == 0 {
            return peer_uid == our_uid;
        }
    }

    // SO_PEERCRED on Linux
    #[cfg(target_os = "linux")]
    {
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = size_of::<libc::ucred>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                #[allow(trivial_casts, clippy::ptr_as_ptr)]
                (&mut cred as *mut libc::ucred as *mut libc::c_void),
                &mut len,
            )
        };
        if result == 0 {
            return cred.uid == our_uid;
        }
    }

    // If we can't verify, reject
    false
}

/// Simple sliding-window rate limiter for connection acceptance.
///
/// Tracks timestamps of recent connections and rejects when the count
/// in the last second exceeds the configured maximum.
#[cfg(unix)]
struct RateLimiter {
    window: VecDeque<Instant>,
    max_per_second: usize,
}

#[cfg(unix)]
impl RateLimiter {
    fn new(max_per_second: usize) -> Self {
        Self {
            window: VecDeque::new(),
            max_per_second,
        }
    }

    /// Returns `true` if the connection is allowed, `false` if rate-limited.
    fn check(&mut self) -> bool {
        let now = Instant::now();
        let one_second_ago = now - std::time::Duration::from_secs(1);

        // Remove entries older than 1 second
        while self.window.front().is_some_and(|t| *t < one_second_ago) {
            self.window.pop_front();
        }

        if self.window.len() >= self.max_per_second {
            return false;
        }

        self.window.push_back(now);
        true
    }
}

/// Default maximum connections per second before rate limiting kicks in.
#[cfg(unix)]
const DEFAULT_MAX_CONNECTIONS_PER_SECOND: usize = 50;

/// Run the SSH agent server on a Unix socket.
#[cfg(unix)]
#[allow(clippy::print_stdout)]
pub async fn run_agent(
    socket_path: PathBuf,
    pub_dir: PathBuf,
    allowed_labels: Vec<String>,
    prompt_policy: PromptPolicy,
    ready_file: Option<&Path>,
) -> Result<()> {
    prepare_socket_path(&socket_path)?;

    let backend: Arc<dyn KeyBackend> = Arc::new(
        sshenc_se::SshencBackend::new(pub_dir, false)
            .map_err(|e| anyhow::anyhow!("failed to initialize backend: {e}"))?,
    );

    let listener = UnixListener::bind(&socket_path)?;

    // Set restrictive permissions on the socket
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;
    }

    signal_ready(ready_file)?;
    tracing::info!(socket = %socket_path.display(), "agent listening");

    // Print SSH_AUTH_SOCK hint
    println!("SSH_AUTH_SOCK={}", socket_path.display());

    let allowed: Arc<HashSet<String>> = Arc::new(allowed_labels.into_iter().collect());
    let mut rate_limiter = RateLimiter::new(DEFAULT_MAX_CONNECTIONS_PER_SECOND);

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (stream, _addr) = accept_result?;

                if !verify_peer_uid(&stream) {
                    tracing::warn!("rejected connection from different user");
                    drop(stream);
                    continue;
                }

                if !rate_limiter.check() {
                    tracing::warn!("connection rate limited");
                    drop(stream);
                    continue;
                }

                verify_peer_binary(&stream);
                let backend = Arc::clone(&backend);
                let allowed = Arc::clone(&allowed);
                tokio::spawn(async move {
                    if let Err(e) =
                        handle_connection(stream, &*backend, &allowed, prompt_policy).await
                    {
                        tracing::warn!("connection error: {e}");
                    }
                });
            }
            _ = signal::ctrl_c() => {
                tracing::info!("shutting down");
                break;
            }
        }
    }

    // Cleanup socket
    drop(std::fs::remove_file(&socket_path));
    Ok(())
}

#[cfg(unix)]
fn prepare_socket_path(socket_path: &Path) -> Result<()> {
    use std::os::unix::fs::FileTypeExt;
    use std::os::unix::net::UnixStream;

    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
    }

    if !socket_path.exists() {
        return Ok(());
    }

    let file_type = std::fs::symlink_metadata(socket_path)?.file_type();
    if !file_type.is_socket() {
        anyhow::bail!(
            "refusing to replace existing non-socket path: {}",
            socket_path.display()
        );
    }

    match UnixStream::connect(socket_path) {
        Ok(_) => anyhow::bail!("agent socket already in use: {}", socket_path.display()),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
            ) =>
        {
            std::fs::remove_file(socket_path)?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

/// Run the SSH agent server on a Windows named pipe.
///
/// Also listens on a Unix domain socket (`~/.sshenc/agent.sock`) so that
/// Git for Windows' MINGW SSH (which cannot use named pipes) can connect
/// via `SSH_AUTH_SOCK`.
#[cfg(windows)]
pub async fn run_agent(
    pipe_name: String,
    pub_dir: PathBuf,
    allowed_labels: Vec<String>,
    prompt_policy: PromptPolicy,
    ready_file: Option<&Path>,
) -> Result<()> {
    use tokio::net::windows::named_pipe::ServerOptions;

    let backend: Arc<dyn KeyBackend> = Arc::new(
        sshenc_se::SshencBackend::new(pub_dir, false)
            .map_err(|e| anyhow::anyhow!("failed to initialize backend: {e}"))?,
    );

    let allowed: Arc<HashSet<String>> = Arc::new(allowed_labels.into_iter().collect());

    // Restrict the named pipe's DACL to the current user ("creator owner") and
    // SYSTEM only. The default pipe DACL also grants Administrators and
    // Authenticated Users read access, which widens the attacker surface for
    // any local privilege-escalation that lands in another account.
    let pipe_sa = PipeSecurityAttributes::restricted()
        .map_err(|e| anyhow::anyhow!("building pipe security descriptor: {e}"))?;
    let mut server = unsafe {
        ServerOptions::new()
            .first_pipe_instance(true)
            .create_with_security_attributes_raw(&pipe_name, pipe_sa.as_ptr())?
    };

    signal_ready(ready_file)?;
    tracing::info!(pipe = %pipe_name, "agent listening on named pipe");

    // Also listen on a Unix domain socket (AF_UNIX) for Git Bash / MINGW SSH
    // compatibility. MINGW SSH doesn't support named pipes but does support
    // AF_UNIX sockets via SSH_AUTH_SOCK.
    {
        use socket2::{Domain, SockAddr, Socket, Type};

        let sock_dir = dirs::home_dir()
            .ok_or_else(|| anyhow::anyhow!("could not determine home directory; set USERPROFILE"))?
            .join(".sshenc");
        let sock_path = sock_dir.join("agent.sock");
        let _unused = std::fs::create_dir_all(&sock_dir);
        let _unused = std::fs::remove_file(&sock_path);

        let backend_for_unix = Arc::clone(&backend);
        let allowed_for_unix = Arc::clone(&allowed);
        let prompt_policy_for_unix = prompt_policy;

        std::thread::spawn(move || {
            let socket = match Socket::new(Domain::UNIX, Type::STREAM, None) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(path = %sock_path.display(), "AF_UNIX not available: {e}");
                    return;
                }
            };
            let addr = match SockAddr::unix(&sock_path) {
                Ok(a) => a,
                Err(e) => {
                    tracing::warn!("invalid socket path: {e}");
                    return;
                }
            };
            if let Err(e) = socket.bind(&addr) {
                tracing::warn!(path = %sock_path.display(), "Unix socket bind failed: {e}");
                return;
            }
            if let Err(e) = socket.listen(8) {
                tracing::warn!("Unix socket listen failed: {e}");
                return;
            }
            tracing::info!(path = %sock_path.display(), "agent listening on Unix socket");

            loop {
                match socket.accept() {
                    Ok((conn, _)) => {
                        let backend = Arc::clone(&backend_for_unix);
                        let allowed = Arc::clone(&allowed_for_unix);
                        std::thread::spawn(move || {
                            handle_blocking_connection(
                                conn,
                                &*backend,
                                &allowed,
                                prompt_policy_for_unix,
                            );
                        });
                    }
                    Err(e) => {
                        tracing::warn!("Unix socket accept error: {e}");
                        break;
                    }
                }
            }
        });
    }

    loop {
        tokio::select! {
            connect_result = server.connect() => {
                connect_result?;
                let stream = server;
                server = unsafe {
                    ServerOptions::new()
                        .create_with_security_attributes_raw(&pipe_name, pipe_sa.as_ptr())?
                };

                let backend = Arc::clone(&backend);
                let allowed = Arc::clone(&allowed);
                tokio::spawn(async move {
                    if let Err(e) =
                        handle_connection(stream, &*backend, &allowed, prompt_policy).await
                    {
                        tracing::warn!("pipe connection error: {e}");
                    }
                });
            }
            _ = signal::ctrl_c() => {
                tracing::info!("shutting down");
                break;
            }
        }
    }

    // Clean up Unix socket on exit
    if let Some(home) = dirs::home_dir() {
        let sock_path = home.join(".sshenc").join("agent.sock");
        let _unused = std::fs::remove_file(&sock_path);
    }

    Ok(())
}

fn signal_ready(path: Option<&Path>) -> Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, b"ready\n")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Known SSH-related binary names that are expected to connect to the agent.
#[cfg(unix)]
const ALLOWED_PEER_BINARIES: &[&str] = &[
    "ssh",
    "ssh-add",
    "ssh-agent",
    "ssh-keygen",
    "ssh-keyscan",
    "scp",
    "sftp",
    "rsync",
    "git",
    "git-remote-ssh",
    "sshenc",
    "sshenc-agent",
    "gitenc",
    "code",   // VS Code remote SSH
    "cursor", // Cursor editor
];

/// Verify the connecting process is a known SSH-related binary.
///
/// Checks the binary path of the peer process against a list of known
/// SSH clients. This is defense-in-depth — an attacker running as the
/// same user can work around this by naming their binary "ssh", but it
/// prevents casual misuse and raises the bar for automated attacks.
#[cfg(unix)]
fn verify_peer_binary(stream: &tokio::net::UnixStream) {
    let Some(pid) = get_peer_pid(stream) else {
        // Can't determine PID — allow (UID check already passed via socket permissions)
        return;
    };

    let Some(exe_path) = get_process_exe(pid) else {
        // Can't read binary path — allow (may be a kernel thread or permission issue)
        return;
    };

    let filename = exe_path.file_name().and_then(|f| f.to_str()).unwrap_or("");

    if ALLOWED_PEER_BINARIES.contains(&filename) {
        return;
    }

    tracing::info!(
        "agent connection from unrecognized binary: {} (pid {})",
        exe_path.display(),
        pid
    );

    // Allow but log — don't break legitimate use cases we didn't anticipate
}

/// Get the peer process ID from a Unix stream.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn get_peer_pid(stream: &tokio::net::UnixStream) -> Option<u32> {
    use std::mem::size_of;
    use std::os::unix::io::AsRawFd;

    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    if result == 0 {
        Some(cred.pid as u32)
    } else {
        None
    }
}

/// Get the peer process ID from a Unix stream.
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn get_peer_pid(stream: &tokio::net::UnixStream) -> Option<u32> {
    use std::mem::size_of;
    use std::os::unix::io::AsRawFd;

    let mut pid: libc::pid_t = 0;
    let mut len = size_of::<libc::pid_t>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&raw mut pid).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    if result == 0 && pid > 0 {
        Some(pid as u32)
    } else {
        None
    }
}

/// Get the executable path for a process by PID.
#[cfg(target_os = "linux")]
fn get_process_exe(pid: u32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe")).ok()
}

/// Get the executable path for a process by PID.
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn get_process_exe(pid: u32) -> Option<PathBuf> {
    let mut buf = vec![0_u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let result = unsafe {
        libc::proc_pidpath(
            pid as libc::c_int,
            buf.as_mut_ptr().cast::<libc::c_void>(),
            buf.len() as u32,
        )
    };
    if result > 0 {
        let path = std::ffi::CStr::from_bytes_until_nul(&buf).ok()?;
        Some(PathBuf::from(path.to_string_lossy().as_ref()))
    } else {
        None
    }
}

async fn handle_connection<S: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + Unpin>(
    mut stream: S,
    backend: &dyn KeyBackend,
    allowed_labels: &HashSet<String>,
    prompt_policy: PromptPolicy,
) -> Result<()> {
    tracing::debug!("new agent connection");

    loop {
        // Read message length
        let len = match stream.read_u32().await {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                tracing::debug!("client disconnected");
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };

        if len == 0 || len > 256 * 1024 {
            tracing::warn!("invalid message length: {len}");
            return Ok(());
        }

        // Read message body
        let mut payload = vec![0_u8; len as usize];
        stream.read_exact(&mut payload).await?;

        // Parse and handle
        let request = message::parse_request(&payload)?;
        let response = handle_request(request, backend, allowed_labels, prompt_policy)?;
        let response_payload = message::serialize_response(&response);

        // Write response
        stream.write_u32(response_payload.len() as u32).await?;
        stream.write_all(&response_payload).await?;
    }
}

/// Synchronous connection handler for the Windows AF_UNIX socket bridge.
/// Uses `socket2::Socket` with blocking I/O on a dedicated thread.
#[cfg(windows)]
fn handle_blocking_connection(
    conn: socket2::Socket,
    backend: &dyn KeyBackend,
    allowed_labels: &HashSet<String>,
    prompt_policy: PromptPolicy,
) {
    use std::io::{Read, Write};

    // Wrap socket2::Socket in a helper that implements Read/Write.
    let mut stream = SocketReadWriter(conn);

    loop {
        // Read 4-byte message length (big-endian)
        let mut len_buf = [0_u8; 4];
        match stream.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return,
            Err(e) => {
                tracing::warn!("unix socket read error: {e}");
                return;
            }
        }
        let len = u32::from_be_bytes(len_buf);

        if len == 0 || len > 256 * 1024 {
            return;
        }

        // Read message body
        let mut payload = vec![0_u8; len as usize];
        if let Err(e) = stream.read_exact(&mut payload) {
            tracing::warn!("unix socket read error: {e}");
            return;
        }

        // Parse and handle
        let request = match message::parse_request(&payload) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("unix socket parse error: {e}");
                return;
            }
        };
        let response = match handle_request(request, backend, allowed_labels, prompt_policy) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("unix socket request error: {e}");
                return;
            }
        };
        let response_payload = message::serialize_response(&response);

        // Write response
        let resp_len = (response_payload.len() as u32).to_be_bytes();
        if stream.write_all(&resp_len).is_err() || stream.write_all(&response_payload).is_err() {
            return;
        }
    }
}

/// Wrapper to implement `Read` and `Write` on `socket2::Socket`.
#[cfg(windows)]
struct SocketReadWriter(socket2::Socket);

#[cfg(windows)]
impl std::io::Read for SocketReadWriter {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

#[cfg(windows)]
impl std::io::Write for SocketReadWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

fn handle_request(
    request: AgentRequest,
    backend: &dyn KeyBackend,
    allowed_labels: &HashSet<String>,
    prompt_policy: PromptPolicy,
) -> Result<AgentResponse> {
    match request {
        AgentRequest::RequestIdentities => {
            tracing::debug!("handling identity request");

            let keys = backend.list()?;
            let mut identities: Vec<(bool, Identity)> = keys
                .into_iter()
                .filter(|k| {
                    allowed_labels.is_empty() || allowed_labels.contains(k.metadata.label.as_str())
                })
                .filter_map(|k| {
                    let is_default = k.metadata.label.as_str() == "default";
                    let pubkey = SshPublicKey::from_sec1_bytes(
                        &k.public_key_bytes,
                        k.metadata.comment.clone(),
                    )
                    .ok()?;
                    Some((
                        is_default,
                        Identity {
                            key_blob: pubkey.to_wire_format(),
                            comment: k
                                .metadata
                                .comment
                                .unwrap_or_else(|| k.metadata.label.as_str().to_string()),
                        },
                    ))
                })
                .collect();
            // Present "default" key first so SSH tries it before others
            identities.sort_by_key(|(is_default, _)| !*is_default);
            let identities: Vec<Identity> = identities.into_iter().map(|(_, id)| id).collect();

            tracing::debug!(count = identities.len(), "returning identities");
            Ok(AgentResponse::IdentitiesAnswer(identities))
        }
        AgentRequest::SignRequest { key_blob, data, .. } => {
            tracing::debug!(
                blob_len = key_blob.len(),
                data_len = data.len(),
                "handling sign request"
            );

            // Find which SE key matches this blob
            let keys = backend.list()?;
            let matching_key = keys.into_iter().find(|k| {
                if let Ok(pubkey) = SshPublicKey::from_sec1_bytes(&k.public_key_bytes, None) {
                    pubkey.to_wire_format() == key_blob
                } else {
                    false
                }
            });

            let Some(key) = matching_key else {
                tracing::warn!("no matching key for sign request");
                return Ok(AgentResponse::Failure);
            };

            // Check allowed labels (O(n) scan; acceptable for small key counts)
            if !allowed_labels.is_empty() && !allowed_labels.contains(key.metadata.label.as_str()) {
                tracing::warn!(
                    label = key.metadata.label.as_str(),
                    "key not in allowed list"
                );
                return Ok(AgentResponse::Failure);
            }

            let should_verify = match prompt_policy {
                PromptPolicy::Always => true,
                PromptPolicy::Never => false,
                PromptPolicy::KeyDefault => key.metadata.access_policy != AccessPolicy::None,
            };

            if should_verify {
                // On macOS the Secure Enclave enforces user presence during
                // SecKeyCreateSignature — the biometric/password prompt fires
                // automatically.  On Windows the TPM backend enforces it via
                // Windows Hello during the sign operation.
                //
                // On Linux with the software backend there is no hardware
                // enforcement and the agent has no terminal to prompt the
                // user, so we log a warning.
                #[cfg(not(any(target_os = "macos", windows)))]
                {
                    tracing::warn!(
                        label = key.metadata.label.as_str(),
                        "user verification requested but software backend cannot enforce it"
                    );
                }
            }

            // Sign with Secure Enclave
            let der_sig = backend.sign(key.metadata.label.as_str(), &data)?;
            let ssh_sig = signature::der_to_ssh_signature(&der_sig)?;

            tracing::debug!(
                label = key.metadata.label.as_str(),
                sig_len = ssh_sig.len(),
                "signing complete"
            );

            Ok(AgentResponse::SignResponse {
                signature_blob: ssh_sig,
            })
        }
        AgentRequest::Unknown(msg_type) => {
            tracing::debug!(msg_type, "unknown message type");
            Ok(AgentResponse::Failure)
        }
    }
}

/// Windows named-pipe security-attributes holder.
///
/// Owns the SECURITY_DESCRIPTOR returned by
/// `ConvertStringSecurityDescriptorToSecurityDescriptorW` and the
/// SECURITY_ATTRIBUTES struct that references it. Both must outlive the
/// `CreateNamedPipeW` call that consumes the pointer; `Drop` calls
/// `LocalFree` to release the descriptor.
#[cfg(windows)]
struct PipeSecurityAttributes {
    attrs: windows::Win32::Security::SECURITY_ATTRIBUTES,
    descriptor: windows::Win32::Security::PSECURITY_DESCRIPTOR,
}

#[cfg(windows)]
impl PipeSecurityAttributes {
    /// Build a DACL that grants full control to the pipe's creator-owner
    /// and to SYSTEM, and denies everyone else. Protected (`P`) so parent
    /// inheritance can't widen it.
    ///
    /// SDDL breakdown:
    ///   D:P              Discretionary ACL, protected
    ///   (A;;GA;;;OW)     Allow, Generic-All, Creator-Owner
    ///   (A;;GA;;;SY)     Allow, Generic-All, Local-System
    #[allow(unsafe_code)]
    fn restricted() -> Result<Self> {
        use std::ptr;
        use windows::core::PCWSTR;
        use windows::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

        let sddl: Vec<u16> = "D:P(A;;GA;;;OW)(A;;GA;;;SY)\0".encode_utf16().collect();
        let mut descriptor = PSECURITY_DESCRIPTOR(ptr::null_mut());

        // Safety: SDDL is a NUL-terminated UTF-16 buffer; we pass a
        // valid PSECURITY_DESCRIPTOR out-pointer and no size-out (None).
        // The returned descriptor is owned by the caller and freed in
        // Drop via LocalFree.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor as *mut PSECURITY_DESCRIPTOR,
                None,
            )
            .map_err(|e| anyhow::anyhow!("ConvertStringSecurityDescriptor failed: {e}"))?;
        }

        let attrs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: false.into(),
        };

        Ok(Self { attrs, descriptor })
    }

    /// Returns a pointer suitable for Tokio's
    /// `ServerOptions::create_with_security_attributes_raw`. The
    /// `PipeSecurityAttributes` must outlive the call.
    fn as_ptr(&self) -> *mut std::ffi::c_void {
        // Cast away the immutable borrow to a raw pointer. The
        // Win32 API doesn't actually mutate the SECURITY_ATTRIBUTES
        // struct, but the signature is historically *mut.
        &self.attrs as *const _ as *mut std::ffi::c_void
    }
}

#[cfg(windows)]
impl Drop for PipeSecurityAttributes {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        use windows::Win32::Foundation::{LocalFree, HLOCAL};

        if !self.descriptor.0.is_null() {
            // Safety: descriptor was allocated by
            // ConvertStringSecurityDescriptorToSecurityDescriptorW,
            // which documents LocalFree as the correct release call.
            unsafe {
                drop(LocalFree(HLOCAL(self.descriptor.0)));
            }
            self.descriptor.0 = std::ptr::null_mut();
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use sshenc_core::key::{KeyGenOptions, KeyLabel};
    use sshenc_core::AccessPolicy;
    use sshenc_test_support::MockKeyBackend;
    use std::collections::HashSet;

    fn empty_labels() -> HashSet<String> {
        HashSet::new()
    }

    #[cfg(unix)]
    fn test_socket_path(name: &str) -> PathBuf {
        // Keep path short — macOS SUN_LEN is 104 bytes.
        let dir = std::env::temp_dir().join(format!("se-{}-{name}", std::process::id()));
        drop(std::fs::remove_dir_all(&dir));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("a.sock")
    }

    fn setup_backend() -> MockKeyBackend {
        let backend = MockKeyBackend::new();
        let opts = KeyGenOptions {
            label: KeyLabel::new("test-key").unwrap(),
            comment: Some("test".into()),
            access_policy: AccessPolicy::None,
            write_pub_path: None,
        };
        backend.generate(&opts).unwrap();
        backend
    }

    fn get_key_blob(backend: &MockKeyBackend) -> Vec<u8> {
        let keys = backend.list().unwrap();
        let key = &keys[0];
        let pubkey = SshPublicKey::from_sec1_bytes(&key.public_key_bytes, None).unwrap();
        pubkey.to_wire_format()
    }

    #[test]
    fn test_request_identities_returns_keys() {
        let backend = setup_backend();
        let resp = handle_request(
            AgentRequest::RequestIdentities,
            &backend,
            &empty_labels(),
            PromptPolicy::KeyDefault,
        )
        .unwrap();
        match resp {
            AgentResponse::IdentitiesAnswer(ids) => {
                assert_eq!(ids.len(), 1);
                assert!(!ids[0].key_blob.is_empty());
            }
            _ => panic!("expected IdentitiesAnswer"),
        }
    }

    #[test]
    fn test_request_identities_empty_backend() {
        let backend = MockKeyBackend::new();
        let resp = handle_request(
            AgentRequest::RequestIdentities,
            &backend,
            &empty_labels(),
            PromptPolicy::KeyDefault,
        )
        .unwrap();
        match resp {
            AgentResponse::IdentitiesAnswer(ids) => assert!(ids.is_empty()),
            _ => panic!("expected IdentitiesAnswer"),
        }
    }

    #[test]
    fn test_request_identities_filtered_by_labels() {
        let backend = MockKeyBackend::new();
        backend
            .generate(&KeyGenOptions {
                label: KeyLabel::new("allowed").unwrap(),
                comment: None,
                access_policy: AccessPolicy::None,
                write_pub_path: None,
            })
            .unwrap();
        backend
            .generate(&KeyGenOptions {
                label: KeyLabel::new("blocked").unwrap(),
                comment: None,
                access_policy: AccessPolicy::None,
                write_pub_path: None,
            })
            .unwrap();

        let allowed: HashSet<String> = ["allowed".to_string()].into_iter().collect();
        let resp = handle_request(
            AgentRequest::RequestIdentities,
            &backend,
            &allowed,
            PromptPolicy::KeyDefault,
        )
        .unwrap();
        match resp {
            AgentResponse::IdentitiesAnswer(ids) => assert_eq!(ids.len(), 1),
            _ => panic!("expected IdentitiesAnswer"),
        }
    }

    #[test]
    fn test_sign_request_valid_key() {
        let backend = setup_backend();
        let key_blob = get_key_blob(&backend);

        let resp = handle_request(
            AgentRequest::SignRequest {
                key_blob,
                data: b"test data".to_vec(),
                flags: 0,
            },
            &backend,
            &empty_labels(),
            PromptPolicy::KeyDefault,
        )
        .unwrap();
        match resp {
            AgentResponse::SignResponse { signature_blob } => {
                assert!(!signature_blob.is_empty());
            }
            _ => panic!("expected SignResponse"),
        }
    }

    #[test]
    fn test_sign_request_unknown_key() {
        let backend = setup_backend();
        let resp = handle_request(
            AgentRequest::SignRequest {
                key_blob: b"nonexistent-key-blob".to_vec(),
                data: b"test data".to_vec(),
                flags: 0,
            },
            &backend,
            &empty_labels(),
            PromptPolicy::KeyDefault,
        )
        .unwrap();
        assert!(matches!(resp, AgentResponse::Failure));
    }

    #[test]
    fn test_sign_request_blocked_by_label_filter() {
        let backend = setup_backend();
        let key_blob = get_key_blob(&backend);

        let allowed: HashSet<String> = ["other-key".to_string()].into_iter().collect();
        let resp = handle_request(
            AgentRequest::SignRequest {
                key_blob,
                data: b"test data".to_vec(),
                flags: 0,
            },
            &backend,
            &allowed,
            PromptPolicy::KeyDefault,
        )
        .unwrap();
        assert!(matches!(resp, AgentResponse::Failure));
    }

    #[test]
    fn test_unknown_message_type() {
        let backend = setup_backend();
        let resp = handle_request(
            AgentRequest::Unknown(255),
            &backend,
            &empty_labels(),
            PromptPolicy::KeyDefault,
        )
        .unwrap();
        assert!(matches!(resp, AgentResponse::Failure));
    }

    #[test]
    fn test_sign_produces_valid_ssh_signature() {
        let backend = setup_backend();
        let key_blob = get_key_blob(&backend);

        let resp = handle_request(
            AgentRequest::SignRequest {
                key_blob,
                data: b"challenge data".to_vec(),
                flags: 0,
            },
            &backend,
            &empty_labels(),
            PromptPolicy::KeyDefault,
        )
        .unwrap();

        if let AgentResponse::SignResponse { signature_blob } = resp {
            // SSH signature format: string(algo) + string(sig_data)
            let (algo, _) = sshenc_core::pubkey::read_ssh_string(&signature_blob).unwrap();
            assert_eq!(algo, b"ecdsa-sha2-nistp256");
        } else {
            panic!("expected SignResponse");
        }
    }

    #[test]
    #[cfg(unix)]
    fn test_prepare_socket_path_rejects_live_socket() {
        let socket_path = test_socket_path("live");
        let _listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();

        let error = prepare_socket_path(&socket_path).unwrap_err();
        assert!(error.to_string().contains("already in use"));
        assert!(socket_path.exists());

        drop(std::fs::remove_file(socket_path));
    }

    #[test]
    #[cfg(unix)]
    fn test_prepare_socket_path_removes_stale_socket() {
        let socket_path = test_socket_path("stale");
        let listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
        drop(listener);

        assert!(socket_path.exists());
        prepare_socket_path(&socket_path).unwrap();
        assert!(!socket_path.exists());
    }

    #[test]
    #[cfg(unix)]
    fn test_prepare_socket_path_rejects_regular_file() {
        let socket_path = test_socket_path("file");
        std::fs::write(&socket_path, "not a socket").unwrap();

        let error = prepare_socket_path(&socket_path).unwrap_err();
        assert!(error.to_string().contains("non-socket"));
        assert!(socket_path.exists());

        drop(std::fs::remove_file(socket_path));
    }

    #[test]
    fn test_request_identities_default_key_sorted_first() {
        let backend = MockKeyBackend::new();
        // Generate a non-default key first
        backend
            .generate(&KeyGenOptions {
                label: KeyLabel::new("other").unwrap(),
                comment: Some("other".into()),
                access_policy: AccessPolicy::None,
                write_pub_path: None,
            })
            .unwrap();
        // Generate the "default" key second
        backend
            .generate(&KeyGenOptions {
                label: KeyLabel::new("default").unwrap(),
                comment: Some("default".into()),
                access_policy: AccessPolicy::None,
                write_pub_path: None,
            })
            .unwrap();

        let resp = handle_request(
            AgentRequest::RequestIdentities,
            &backend,
            &empty_labels(),
            PromptPolicy::KeyDefault,
        )
        .unwrap();
        match resp {
            AgentResponse::IdentitiesAnswer(ids) => {
                assert_eq!(ids.len(), 2);
                // "default" key should be first due to sorting
                assert_eq!(ids[0].comment, "default");
            }
            _ => panic!("expected IdentitiesAnswer"),
        }
    }

    #[test]
    fn test_request_identities_comment_fallback_to_label() {
        let backend = MockKeyBackend::new();
        backend
            .generate(&KeyGenOptions {
                label: KeyLabel::new("no-comment").unwrap(),
                comment: None,
                access_policy: AccessPolicy::None,
                write_pub_path: None,
            })
            .unwrap();

        let resp = handle_request(
            AgentRequest::RequestIdentities,
            &backend,
            &empty_labels(),
            PromptPolicy::KeyDefault,
        )
        .unwrap();
        match resp {
            AgentResponse::IdentitiesAnswer(ids) => {
                assert_eq!(ids.len(), 1);
                // When comment is None, the label should be used as comment
                assert_eq!(ids[0].comment, "no-comment");
            }
            _ => panic!("expected IdentitiesAnswer"),
        }
    }

    #[tokio::test]
    async fn test_handle_connection_request_identities() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let backend = setup_backend();
        let allowed = empty_labels();

        // Build a framed RequestIdentities message
        let payload = message::serialize_request(&AgentRequest::RequestIdentities);
        let mut frame = Vec::new();
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);

        let (client, server) = tokio::io::duplex(8192);
        let (server_read, server_write) = tokio::io::split(server);
        let (mut client_read, mut client_write) = tokio::io::split(client);

        // Spawn writer that sends request then closes
        let writer = tokio::spawn(async move {
            client_write.write_all(&frame).await.unwrap();
            client_write.shutdown().await.unwrap();
        });

        // Run handle_connection with the server side
        let server_stream = tokio::io::join(server_read, server_write);
        let conn_result =
            handle_connection(server_stream, &backend, &allowed, PromptPolicy::KeyDefault).await;
        assert!(conn_result.is_ok());

        writer.await.unwrap();

        // Read the response from client side
        let mut response_data = Vec::new();
        client_read.read_to_end(&mut response_data).await.unwrap();

        // Parse the response: u32 length + payload
        assert!(response_data.len() >= 4, "response too short");
        let resp_len = u32::from_be_bytes([
            response_data[0],
            response_data[1],
            response_data[2],
            response_data[3],
        ]) as usize;
        assert_eq!(response_data.len(), 4 + resp_len);

        let resp_payload = &response_data[4..];
        let response = message::parse_response(resp_payload).unwrap();
        match response {
            AgentResponse::IdentitiesAnswer(ids) => {
                assert_eq!(ids.len(), 1);
                assert!(!ids[0].key_blob.is_empty());
            }
            other => panic!("expected IdentitiesAnswer, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_handle_connection_unknown_message() {
        let backend = setup_backend();
        let allowed = empty_labels();

        // Build a framed unknown message
        let payload = message::serialize_request(&AgentRequest::Unknown(255));
        let mut frame = Vec::new();
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);

        let (client, server) = tokio::io::duplex(8192);
        let (server_read, server_write) = tokio::io::split(server);
        let (mut client_read, mut client_write) = tokio::io::split(client);

        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let writer = tokio::spawn(async move {
            client_write.write_all(&frame).await.unwrap();
            client_write.shutdown().await.unwrap();
        });

        let server_stream = tokio::io::join(server_read, server_write);
        let conn_result =
            handle_connection(server_stream, &backend, &allowed, PromptPolicy::KeyDefault).await;
        assert!(conn_result.is_ok());

        writer.await.unwrap();

        let mut response_data = Vec::new();
        client_read.read_to_end(&mut response_data).await.unwrap();

        assert!(response_data.len() >= 4);
        let resp_payload = &response_data[4..];
        let response = message::parse_response(resp_payload).unwrap();
        assert!(matches!(response, AgentResponse::Failure));
    }

    #[tokio::test]
    async fn test_handle_connection_empty_stream() {
        let backend = setup_backend();
        let allowed = empty_labels();

        // Empty stream (client disconnects immediately)
        let (client, server) = tokio::io::duplex(8192);
        let (server_read, server_write) = tokio::io::split(server);

        // Drop client immediately to close the connection
        drop(client);

        let server_stream = tokio::io::join(server_read, server_write);
        let conn_result =
            handle_connection(server_stream, &backend, &allowed, PromptPolicy::KeyDefault).await;
        // Should return Ok(()) on client disconnect (UnexpectedEof)
        assert!(conn_result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_connection_invalid_message_length() {
        let backend = setup_backend();
        let allowed = empty_labels();

        // Send a message with length 0
        let mut frame = Vec::new();
        frame.extend_from_slice(&0_u32.to_be_bytes());

        let (client, server) = tokio::io::duplex(8192);
        let (server_read, server_write) = tokio::io::split(server);
        let (_client_read, mut client_write) = tokio::io::split(client);

        use tokio::io::AsyncWriteExt as _;

        let writer = tokio::spawn(async move {
            client_write.write_all(&frame).await.unwrap();
            client_write.shutdown().await.unwrap();
        });

        let server_stream = tokio::io::join(server_read, server_write);
        let conn_result =
            handle_connection(server_stream, &backend, &allowed, PromptPolicy::KeyDefault).await;
        // Zero length should cause early return with Ok(())
        assert!(conn_result.is_ok());

        writer.await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_connection_oversized_message_length() {
        let backend = setup_backend();
        let allowed = empty_labels();

        // Send a message with length > 256KB
        let mut frame = Vec::new();
        frame.extend_from_slice(&(512 * 1024_u32).to_be_bytes());

        let (client, server) = tokio::io::duplex(8192);
        let (server_read, server_write) = tokio::io::split(server);
        let (_client_read, mut client_write) = tokio::io::split(client);

        use tokio::io::AsyncWriteExt as _;

        let writer = tokio::spawn(async move {
            client_write.write_all(&frame).await.unwrap();
            client_write.shutdown().await.unwrap();
        });

        let server_stream = tokio::io::join(server_read, server_write);
        let conn_result =
            handle_connection(server_stream, &backend, &allowed, PromptPolicy::KeyDefault).await;
        // Oversized length should cause early return with Ok(())
        assert!(conn_result.is_ok());

        writer.await.unwrap();
    }

    fn signal_ready_test_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "sshenc-signal-ready-test-{}-{name}",
            std::process::id()
        ))
    }

    #[test]
    fn signal_ready_creates_file() {
        let path = signal_ready_test_path("creates-file");
        let _unused = std::fs::remove_file(&path);

        signal_ready(Some(&path)).unwrap();
        assert!(path.exists());
        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents, "ready\n");

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn signal_ready_none_is_noop() {
        assert!(signal_ready(None).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn signal_ready_sets_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let path = signal_ready_test_path("permissions");
        let _unused = std::fs::remove_file(&path);

        signal_ready(Some(&path)).unwrap();
        let metadata = std::fs::metadata(&path).unwrap();
        assert_eq!(
            metadata.permissions().mode() & 0o777,
            0o600,
            "signal_ready file should have 0o600 permissions"
        );

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn signal_ready_creates_parent_dirs() {
        let base = signal_ready_test_path("nested-parent");
        let _unused = std::fs::remove_dir_all(&base);
        let path = base.join("nested").join("deep").join("ready");

        signal_ready(Some(&path)).unwrap();
        assert!(path.exists());

        std::fs::remove_dir_all(&base).unwrap();
    }

    #[tokio::test]
    async fn test_handle_connection_sign_request() {
        let backend = setup_backend();
        let key_blob = get_key_blob(&backend);
        let allowed = empty_labels();

        let payload = message::serialize_request(&AgentRequest::SignRequest {
            key_blob,
            data: b"sign this data".to_vec(),
            flags: 0,
        });
        let mut frame = Vec::new();
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);

        let (client, server) = tokio::io::duplex(8192);
        let (server_read, server_write) = tokio::io::split(server);
        let (mut client_read, mut client_write) = tokio::io::split(client);

        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let writer = tokio::spawn(async move {
            client_write.write_all(&frame).await.unwrap();
            client_write.shutdown().await.unwrap();
        });

        let server_stream = tokio::io::join(server_read, server_write);
        let conn_result =
            handle_connection(server_stream, &backend, &allowed, PromptPolicy::KeyDefault).await;
        assert!(conn_result.is_ok());

        writer.await.unwrap();

        let mut response_data = Vec::new();
        client_read.read_to_end(&mut response_data).await.unwrap();

        assert!(response_data.len() >= 4);
        let resp_payload = &response_data[4..];
        let response = message::parse_response(resp_payload).unwrap();
        match response {
            AgentResponse::SignResponse { signature_blob } => {
                assert!(!signature_blob.is_empty());
            }
            other => panic!("expected SignResponse, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_rate_limiter_allows_within_limit() {
        let mut rl = RateLimiter::new(5);
        for _ in 0..5 {
            assert!(rl.check());
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_rate_limiter_rejects_over_limit() {
        let mut rl = RateLimiter::new(3);
        assert!(rl.check());
        assert!(rl.check());
        assert!(rl.check());
        assert!(!rl.check());
        assert!(!rl.check());
    }

    #[cfg(unix)]
    #[test]
    fn test_rate_limiter_allows_after_window_expires() {
        let mut rl = RateLimiter::new(2);
        assert!(rl.check());
        assert!(rl.check());
        assert!(!rl.check());

        // Manually expire the window entries by replacing them with old timestamps
        let old = Instant::now() - std::time::Duration::from_secs(2);
        rl.window.clear();
        rl.window.push_back(old);
        rl.window.push_back(old);

        // Now the limiter should allow new connections
        assert!(rl.check());
    }

    #[cfg(unix)]
    #[test]
    fn test_rate_limiter_zero_max_rejects_all() {
        let mut rl = RateLimiter::new(0);
        assert!(!rl.check());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_verify_peer_uid_accepts_same_user() {
        let socket_path = test_socket_path("peer-uid");
        let listener = UnixListener::bind(&socket_path).unwrap();

        let connect = tokio::net::UnixStream::connect(&socket_path);
        let accept = listener.accept();

        let (connect_result, accept_result) = tokio::join!(connect, accept);
        let _client = connect_result.unwrap();
        let (server_stream, _addr) = accept_result.unwrap();

        // Connection from our own process should be accepted
        assert!(verify_peer_uid(&server_stream));

        drop(std::fs::remove_file(&socket_path));
    }

    #[cfg(unix)]
    #[test]
    fn known_ssh_binaries_are_recognized() {
        let expected = ["ssh", "git", "scp", "sshenc", "gitenc", "ssh-add"];
        for name in &expected {
            assert!(
                ALLOWED_PEER_BINARIES.contains(name),
                "{name} should be in ALLOWED_PEER_BINARIES"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn allowed_peer_binaries_contains_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for name in ALLOWED_PEER_BINARIES {
            assert!(
                seen.insert(name),
                "duplicate entry in ALLOWED_PEER_BINARIES: {name}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn get_process_exe_returns_path_for_current_process() {
        let pid = std::process::id();
        let exe = get_process_exe(pid);
        assert!(exe.is_some(), "should be able to read own binary path");
        let path = exe.unwrap();
        assert!(
            path.exists(),
            "binary path should exist: {}",
            path.display()
        );
    }

    #[cfg(unix)]
    #[test]
    fn get_process_exe_returns_none_for_invalid_pid() {
        // PID 0 is the kernel / swapper — we shouldn't be able to read its exe
        // Use a very high PID that's unlikely to exist
        let result = get_process_exe(u32::MAX);
        assert!(result.is_none(), "should return None for non-existent PID");
    }
}
