// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! SSH agent Unix socket server implementation.

use crate::legacy_keys::{self, LegacyKey};
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

    // Load legacy SSH keys from ~/.ssh/
    let legacy = Arc::new(legacy_keys::load_legacy_keys(&ssh_dir));
    tracing::info!(count = legacy.len(), "loaded legacy SSH keys");

    let allowed = Arc::new(allowed_labels);

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (stream, _addr) = accept_result?;
                let backend = Arc::clone(&backend);
                let allowed = Arc::clone(&allowed);
                let legacy = Arc::clone(&legacy);
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, &*backend, &allowed, &legacy).await {
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
    legacy_keys: &[LegacyKey],
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
        let response = handle_request(request, backend, allowed_labels, legacy_keys)?;
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
    legacy_keys: &[LegacyKey],
) -> Result<AgentResponse> {
    match request {
        AgentRequest::RequestIdentities => {
            tracing::debug!("handling identity request");

            // Collect Secure Enclave keys
            let keys = backend.list()?;
            let mut identities: Vec<Identity> = keys
                .into_iter()
                .filter(|k| {
                    allowed_labels.is_empty()
                        || allowed_labels.contains(&k.metadata.label.as_str().to_string())
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

            // Append legacy SSH keys
            for lk in legacy_keys {
                identities.push(lk.to_identity());
            }

            tracing::debug!(
                se_keys = identities.len() - legacy_keys.len(),
                legacy_keys = legacy_keys.len(),
                total = identities.len(),
                "returning identities"
            );
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

            // Try Secure Enclave keys first
            let keys = backend.list()?;
            let matching_key = keys.into_iter().find(|k| {
                if let Ok(pubkey) = SshPublicKey::from_sec1_bytes(&k.public_key_bytes, None) {
                    pubkey.to_wire_format() == key_blob
                } else {
                    false
                }
            });

            if let Some(key) = matching_key {
                // Check allowed labels
                if !allowed_labels.is_empty()
                    && !allowed_labels.contains(&key.metadata.label.as_str().to_string())
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
                    "SE signing complete"
                );

                return Ok(AgentResponse::SignResponse {
                    signature_blob: ssh_sig,
                });
            }

            // Try legacy keys
            let legacy_match = legacy_keys.iter().find(|lk| lk.key_blob == key_blob);
            if let Some(lk) = legacy_match {
                match lk.sign(&data) {
                    Ok(sig_blob) => {
                        tracing::debug!(
                            comment = %lk.comment,
                            sig_len = sig_blob.len(),
                            "legacy signing complete"
                        );
                        return Ok(AgentResponse::SignResponse {
                            signature_blob: sig_blob,
                        });
                    }
                    Err(e) => {
                        tracing::warn!(
                            comment = %lk.comment,
                            error = %e,
                            "legacy signing failed"
                        );
                        return Ok(AgentResponse::Failure);
                    }
                }
            }

            tracing::warn!("no matching key for sign request");
            Ok(AgentResponse::Failure)
        }
        AgentRequest::Unknown(msg_type) => {
            tracing::debug!(msg_type, "unknown message type");
            Ok(AgentResponse::Failure)
        }
    }
}
