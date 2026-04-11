// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! SSH agent Unix socket server implementation.
//!
//! Serves only Secure Enclave keys. Legacy SSH keys from ~/.ssh/ are
//! handled by OpenSSH directly — the agent doesn't need to proxy them.

use anyhow::Result;
use sshenc_agent_proto::message::{self, AgentRequest, AgentResponse, Identity};
use sshenc_agent_proto::signature;
use sshenc_core::pubkey::SshPublicKey;
use sshenc_se::KeyBackend;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::signal;

/// Run the SSH agent server on a Unix socket.
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
    #[cfg(unix)]
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

    #[cfg(target_os = "macos")]
    let backend: Arc<dyn KeyBackend> =
        Arc::new(sshenc_se::SecureEnclaveBackend::new(ssh_dir.clone()));

    #[cfg(not(target_os = "macos"))]
    compile_error!("sshenc-agent requires macOS");

    let allowed = Arc::new(allowed_labels);

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
    let _ = std::fs::remove_file(&socket_path);
    Ok(())
}

async fn handle_connection(
    mut stream: tokio::net::UnixStream,
    backend: &dyn KeyBackend,
    allowed_labels: &[String],
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
        let mut payload = vec![0u8; len as usize];
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

fn handle_request(
    request: AgentRequest,
    backend: &dyn KeyBackend,
    allowed_labels: &[String],
) -> Result<AgentResponse> {
    match request {
        AgentRequest::RequestIdentities => {
            tracing::debug!("handling identity request");

            let keys = backend.list()?;
            let identities: Vec<Identity> = keys
                .into_iter()
                .filter(|k| {
                    // O(n) scan over allowed_labels; acceptable for small key counts
                    allowed_labels.is_empty()
                        || allowed_labels
                            .iter()
                            .any(|l| l == k.metadata.label.as_str())
                })
                .filter_map(|k| {
                    let pubkey = SshPublicKey::from_sec1_bytes(
                        &k.public_key_bytes,
                        k.metadata.comment.clone(),
                    )
                    .ok()?;
                    Some(Identity {
                        key_blob: pubkey.to_wire_format(),
                        comment: k
                            .metadata
                            .comment
                            .unwrap_or_else(|| k.metadata.label.as_str().to_string()),
                    })
                })
                .collect();

            tracing::debug!(count = identities.len(), "returning identities");
            Ok(AgentResponse::IdentitiesAnswer(identities))
        }
        AgentRequest::SignRequest {
            key_blob,
            data,
            flags: _,
        } => {
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
            if !allowed_labels.is_empty()
                && !allowed_labels
                    .iter()
                    .any(|l| l == key.metadata.label.as_str())
            {
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
mod tests {
    use super::*;
    use sshenc_core::key::{KeyGenOptions, KeyLabel};
    use sshenc_test_support::MockKeyBackend;

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
        let resp = handle_request(AgentRequest::RequestIdentities, &backend, &[]).unwrap();
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
        let resp = handle_request(AgentRequest::RequestIdentities, &backend, &[]).unwrap();
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

        let allowed = vec!["allowed".to_string()];
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
            &[],
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
            &[],
        )
        .unwrap();
        assert!(matches!(resp, AgentResponse::Failure));
    }

    #[test]
    fn test_sign_request_blocked_by_label_filter() {
        let backend = setup_backend();
        let key_blob = get_key_blob(&backend);

        let allowed = vec!["other-key".to_string()];
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
        let resp = handle_request(AgentRequest::Unknown(255), &backend, &[]).unwrap();
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
            &[],
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
}
