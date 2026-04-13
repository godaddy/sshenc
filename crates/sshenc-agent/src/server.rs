// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! SSH agent server implementation (Unix sockets / Windows named pipes).
//!
//! Serves only hardware-backed keys. Legacy SSH keys from ~/.ssh/ are
//! handled by OpenSSH directly — the agent doesn't need to proxy them.

use anyhow::Result;
use sshenc_agent_proto::message::{self, AgentRequest, AgentResponse, Identity};
use sshenc_agent_proto::signature;
use sshenc_core::pubkey::SshPublicKey;
use sshenc_se::KeyBackend;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::signal;

#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use tokio::net::UnixListener;

/// Run the SSH agent server on a Unix socket.
#[cfg(unix)]
#[allow(clippy::print_stdout)]
pub async fn run_agent(socket_path: PathBuf, allowed_labels: Vec<String>) -> Result<()> {
    // Clean up stale socket
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
    }

    // Ensure parent directory exists
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(&socket_path)?;

    // Set restrictive permissions on the socket
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;
    }

    tracing::info!(socket = %socket_path.display(), "agent listening");

    // Print SSH_AUTH_SOCK hint
    println!("SSH_AUTH_SOCK={}", socket_path.display());

    let ssh_dir = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".ssh");

    let backend: Arc<dyn KeyBackend> = Arc::new(
        sshenc_se::SshencBackend::new(ssh_dir.clone())
            .map_err(|e| anyhow::anyhow!("failed to initialize backend: {e}"))?,
    );

    let allowed: Arc<HashSet<String>> = Arc::new(allowed_labels.into_iter().collect());

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (stream, _addr) = accept_result?;
                let backend = Arc::clone(&backend);
                let allowed = Arc::clone(&allowed);
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, &*backend, &allowed).await {
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

/// Run the SSH agent server on a Windows named pipe.
///
/// Also listens on a Unix domain socket (`~/.sshenc/agent.sock`) so that
/// Git for Windows' MINGW SSH (which cannot use named pipes) can connect
/// via `SSH_AUTH_SOCK`.
#[cfg(windows)]
pub async fn run_agent(pipe_name: String, allowed_labels: Vec<String>) -> Result<()> {
    use tokio::net::windows::named_pipe::ServerOptions;

    let ssh_dir = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("C:\\Users\\Default"))
        .join(".ssh");

    let backend: Arc<dyn KeyBackend> = Arc::new(
        sshenc_se::SshencBackend::new(ssh_dir.clone())
            .map_err(|e| anyhow::anyhow!("failed to initialize backend: {e}"))?,
    );

    let allowed: Arc<HashSet<String>> = Arc::new(allowed_labels.into_iter().collect());

    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&pipe_name)?;

    tracing::info!(pipe = %pipe_name, "agent listening on named pipe");

    // Also listen on a Unix domain socket (AF_UNIX) for Git Bash / MINGW SSH
    // compatibility. MINGW SSH doesn't support named pipes but does support
    // AF_UNIX sockets via SSH_AUTH_SOCK.
    {
        use socket2::{Domain, SockAddr, Socket, Type};

        let sock_path = dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("C:\\Users\\Default"))
            .join(".sshenc")
            .join("agent.sock");
        let _unused = std::fs::create_dir_all(sock_path.parent().unwrap());
        let _unused = std::fs::remove_file(&sock_path);

        let backend_for_unix = Arc::clone(&backend);
        let allowed_for_unix = Arc::clone(&allowed);

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
                            handle_blocking_connection(conn, &*backend, &allowed);
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
                server = ServerOptions::new().create(&pipe_name)?;

                let backend = Arc::clone(&backend);
                let allowed = Arc::clone(&allowed);
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, &*backend, &allowed).await {
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
    let sock_path = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("C:\\Users\\Default"))
        .join(".sshenc")
        .join("agent.sock");
    let _unused = std::fs::remove_file(&sock_path);

    Ok(())
}

async fn handle_connection<S: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + Unpin>(
    mut stream: S,
    backend: &dyn KeyBackend,
    allowed_labels: &HashSet<String>,
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
        let response = handle_request(request, backend, allowed_labels)?;
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
            Err(_) => return,
        }
        let len = u32::from_be_bytes(len_buf);

        if len == 0 || len > 256 * 1024 {
            return;
        }

        // Read message body
        let mut payload = vec![0_u8; len as usize];
        if stream.read_exact(&mut payload).is_err() {
            return;
        }

        // Parse and handle
        let request = match message::parse_request(&payload) {
            Ok(r) => r,
            Err(_) => return,
        };
        let response = match handle_request(request, backend, allowed_labels) {
            Ok(r) => r,
            Err(_) => return,
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use sshenc_core::key::{KeyGenOptions, KeyLabel};
    use sshenc_test_support::MockKeyBackend;
    use std::collections::HashSet;

    fn empty_labels() -> HashSet<String> {
        HashSet::new()
    }

    fn setup_backend() -> MockKeyBackend {
        let backend = MockKeyBackend::new();
        let opts = KeyGenOptions {
            label: KeyLabel::new("test-key").unwrap(),
            comment: Some("test".into()),
            requires_user_presence: false,
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
        let resp =
            handle_request(AgentRequest::RequestIdentities, &backend, &empty_labels()).unwrap();
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
        let resp =
            handle_request(AgentRequest::RequestIdentities, &backend, &empty_labels()).unwrap();
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
                requires_user_presence: false,
                write_pub_path: None,
            })
            .unwrap();
        backend
            .generate(&KeyGenOptions {
                label: KeyLabel::new("blocked").unwrap(),
                comment: None,
                requires_user_presence: false,
                write_pub_path: None,
            })
            .unwrap();

        let allowed: HashSet<String> = ["allowed".to_string()].into_iter().collect();
        let resp = handle_request(AgentRequest::RequestIdentities, &backend, &allowed).unwrap();
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
        )
        .unwrap();
        assert!(matches!(resp, AgentResponse::Failure));
    }

    #[test]
    fn test_unknown_message_type() {
        let backend = setup_backend();
        let resp = handle_request(AgentRequest::Unknown(255), &backend, &empty_labels()).unwrap();
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
    fn test_request_identities_default_key_sorted_first() {
        let backend = MockKeyBackend::new();
        // Generate a non-default key first
        backend
            .generate(&KeyGenOptions {
                label: KeyLabel::new("other").unwrap(),
                comment: Some("other".into()),
                requires_user_presence: false,
                write_pub_path: None,
            })
            .unwrap();
        // Generate the "default" key second
        backend
            .generate(&KeyGenOptions {
                label: KeyLabel::new("default").unwrap(),
                comment: Some("default".into()),
                requires_user_presence: false,
                write_pub_path: None,
            })
            .unwrap();

        let resp =
            handle_request(AgentRequest::RequestIdentities, &backend, &empty_labels()).unwrap();
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
                requires_user_presence: false,
                write_pub_path: None,
            })
            .unwrap();

        let resp =
            handle_request(AgentRequest::RequestIdentities, &backend, &empty_labels()).unwrap();
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
        let conn_result = handle_connection(server_stream, &backend, &allowed).await;
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
        let conn_result = handle_connection(server_stream, &backend, &allowed).await;
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
        let conn_result = handle_connection(server_stream, &backend, &allowed).await;
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
        let conn_result = handle_connection(server_stream, &backend, &allowed).await;
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
        let conn_result = handle_connection(server_stream, &backend, &allowed).await;
        // Oversized length should cause early return with Ok(())
        assert!(conn_result.is_ok());

        writer.await.unwrap();
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
        let conn_result = handle_connection(server_stream, &backend, &allowed).await;
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
}
