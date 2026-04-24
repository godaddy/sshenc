// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `AgentProxyBackend` — a `KeyBackend` implementation that routes
//! every write-side operation (`generate` / `sign` / `delete` /
//! `rename`) over the `sshenc-agent` Unix socket so the CLI process
//! never links those calls into its own code signature.
//!
//! **This is the contract that makes "the agent is the only
//! keychain / Secure-Enclave toucher" hold.** On unsigned macOS
//! builds the legacy keychain's ACL is keyed to the creating
//! binary. When the CLI (`sshenc`, `sshenc-keygen`) constructs an
//! `AgentProxyBackend` instead of a direct `SshencBackend`, the
//! `SecItemAdd` for a wrapping-key entry and every later read or
//! delete of the same entry all run inside `sshenc-agent` — same
//! code-signature for creator and reader, no cross-binary approval
//! sheet. Read-only ops (`list`, `get`, `is_available`) touch only
//! on-disk state (Wart 1 ensured `load_pub_key` reads the cached
//! `.pub` file) and are delegated to a thin inner backend.
//!
//! Ensures the agent is running before any proxied op (auto-spawns
//! at `config.socket_path` if needed); refuses to silently fall
//! back to a local write path — if the proxy fails, the caller
//! sees an error, because the alternative is the cross-binary
//! prompt we're trying to eliminate.

use crate::backend::KeyBackend;
use crate::unified::SshencBackend;
use sshenc_core::error::{Error, Result};
use sshenc_core::key::{KeyGenOptions, KeyInfo};
use std::path::PathBuf;

#[cfg(unix)]
use sshenc_agent_proto::client;
#[cfg(unix)]
use sshenc_core::fingerprint;
#[cfg(unix)]
use sshenc_core::key::KeyMetadata;
#[cfg(unix)]
use sshenc_core::pubkey::SshPublicKey;

/// `KeyBackend` that forwards every secret-touching op to
/// `sshenc-agent` over a Unix socket. Reads fall through to a local
/// `SshencBackend`; writes never do.
#[derive(Debug)]
pub struct AgentProxyBackend {
    #[cfg_attr(not(unix), allow(dead_code))]
    socket_path: PathBuf,
    inner: SshencBackend,
}

impl AgentProxyBackend {
    /// Build a proxy backend for operations against the agent
    /// listening at `socket_path`. The agent is spawned via
    /// `sshenc_agent_proto::client::ensure_agent_ready` if it isn't
    /// already running; returns `Err` if the agent can't be
    /// reached.
    ///
    /// `pub_dir` / `force_keyring` are forwarded to the inner
    /// `SshencBackend` used only for read-only ops (list / get /
    /// `is_available`). The inner backend never performs write
    /// operations that touch the keychain.
    pub fn new(
        pub_dir: PathBuf,
        force_keyring: bool,
        socket_path: PathBuf,
    ) -> std::result::Result<Self, enclaveapp_app_storage::StorageError> {
        #[cfg(unix)]
        client::ensure_agent_ready(&socket_path).map_err(|e| {
            enclaveapp_app_storage::StorageError::KeyInitFailed(format!(
                "sshenc-agent not reachable at {}: {e}",
                socket_path.display()
            ))
        })?;
        let inner = SshencBackend::new(pub_dir, force_keyring)?;
        Ok(Self { socket_path, inner })
    }

    fn agent_refused(op: &'static str, detail: impl Into<String>) -> Error {
        Error::SecureEnclave {
            operation: op.into(),
            detail: detail.into(),
        }
    }
}

impl KeyBackend for AgentProxyBackend {
    fn generate(&self, opts: &KeyGenOptions) -> Result<KeyInfo> {
        #[cfg(unix)]
        {
            let public_bytes = client::try_generate_via_socket(
                &self.socket_path,
                opts.label.as_str(),
                opts.comment.as_deref(),
                opts.access_policy.as_ffi_value() as u32,
            )
            .ok_or_else(|| {
                Self::agent_refused(
                    "generate",
                    format!(
                        "sshenc-agent refused generate for label '{}' \
                         (check agent logs)",
                        opts.label.as_str()
                    ),
                )
            })?;

            let ssh_pubkey = SshPublicKey::from_sec1_bytes(&public_bytes, opts.comment.clone())?;
            let (fp_sha256, fp_md5) = fingerprint::fingerprints(&ssh_pubkey);

            let pub_file_path = if let Some(ref path) = opts.write_pub_path {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| Error::SecureEnclave {
                        operation: "generate".into(),
                        detail: format!("create pub-file parent {}: {e}", parent.display()),
                    })?;
                }
                std::fs::write(path, format!("{}\n", ssh_pubkey.to_openssh_line())).map_err(
                    |e| Error::SecureEnclave {
                        operation: "generate".into(),
                        detail: format!("write {}: {e}", path.display()),
                    },
                )?;
                Some(path.clone())
            } else {
                None
            };

            Ok(KeyInfo {
                metadata: KeyMetadata::new(
                    opts.label.clone(),
                    opts.access_policy,
                    opts.comment.clone(),
                ),
                public_key_bytes: public_bytes,
                fingerprint_sha256: fp_sha256,
                fingerprint_md5: fp_md5,
                pub_file_path,
            })
        }
        #[cfg(not(unix))]
        {
            let _ = opts;
            Err(Self::agent_refused(
                "generate",
                "AgentProxyBackend is Unix-only; use SshencBackend on Windows",
            ))
        }
    }

    fn list(&self) -> Result<Vec<KeyInfo>> {
        self.inner.list()
    }

    fn get(&self, label: &str) -> Result<KeyInfo> {
        self.inner.get(label)
    }

    fn delete(&self, label: &str) -> Result<()> {
        #[cfg(unix)]
        {
            client::try_delete_via_socket(&self.socket_path, label).ok_or_else(|| {
                Self::agent_refused(
                    "delete",
                    format!(
                        "sshenc-agent refused delete for label '{label}' \
                         (check agent logs)"
                    ),
                )
            })
        }
        #[cfg(not(unix))]
        {
            let _ = label;
            Err(Self::agent_refused("delete", "Unix-only"))
        }
    }

    fn rename(&self, old_label: &str, new_label: &str) -> Result<()> {
        #[cfg(unix)]
        {
            client::try_rename_via_socket(&self.socket_path, old_label, new_label).ok_or_else(
                || {
                    Self::agent_refused(
                        "rename",
                        format!(
                            "sshenc-agent refused rename '{old_label}' -> \
                             '{new_label}' (check agent logs and \
                             allowed_labels)"
                        ),
                    )
                },
            )
        }
        #[cfg(not(unix))]
        {
            let _ = (old_label, new_label);
            Err(Self::agent_refused("rename", "Unix-only"))
        }
    }

    /// Signs via the agent and converts the returned SSH-format
    /// signature (`string(algo) || string(mpint r || mpint s)`) back
    /// to DER so the `KeyBackend::sign` contract (which promises
    /// DER-encoded ECDSA) is honored.
    fn sign(&self, label: &str, data: &[u8]) -> Result<Vec<u8>> {
        #[cfg(unix)]
        {
            let info = self.inner.get(label)?;
            let pubkey =
                SshPublicKey::from_sec1_bytes(&info.public_key_bytes, info.metadata.comment)?;
            let wire_blob = pubkey.wire_blob();
            let ssh_sig = client::try_sign_via_socket(&self.socket_path, &wire_blob, data)
                .ok_or_else(|| {
                    Self::agent_refused(
                        "sign",
                        "sshenc-agent refused sign request (check agent logs)",
                    )
                })?;
            ssh_sig_to_der(&ssh_sig)
        }
        #[cfg(not(unix))]
        {
            let _ = (label, data);
            Err(Self::agent_refused("sign", "Unix-only"))
        }
    }

    fn is_available(&self) -> bool {
        self.inner.is_available()
    }
}

/// Invert `signature::der_to_ssh_signature`: read the agent's
/// SSH-format sign response and emit a DER-encoded ECDSA signature
/// so callers that expected `KeyBackend::sign` to return DER still
/// work.
#[cfg(unix)]
fn ssh_sig_to_der(ssh_sig: &[u8]) -> Result<Vec<u8>> {
    let (_algo, rest) = sshenc_core::pubkey::read_ssh_string(ssh_sig)?;
    let (inner, _tail) = sshenc_core::pubkey::read_ssh_string(rest)?;
    let (r, rest) = sshenc_core::pubkey::read_ssh_string(inner)?;
    let (s, _) = sshenc_core::pubkey::read_ssh_string(rest)?;

    let mut der_inner = Vec::new();
    write_der_integer(&mut der_inner, r);
    write_der_integer(&mut der_inner, s);

    let mut der = Vec::with_capacity(2 + der_inner.len());
    der.push(0x30); // SEQUENCE
    der.push(der_inner.len() as u8);
    der.extend_from_slice(&der_inner);
    Ok(der)
}

#[cfg(unix)]
fn write_der_integer(buf: &mut Vec<u8>, bytes: &[u8]) {
    // Strip redundant leading zeros unless needed to disambiguate
    // sign (high bit of first remaining byte set).
    let mut i = 0;
    while i + 1 < bytes.len() && bytes[i] == 0 && (bytes[i + 1] & 0x80) == 0 {
        i += 1;
    }
    let trimmed = &bytes[i..];
    let needs_leading_zero = trimmed.first().is_some_and(|b| b & 0x80 != 0);
    let content_len = trimmed.len() + usize::from(needs_leading_zero);
    buf.push(0x02); // INTEGER
    buf.push(content_len as u8);
    if needs_leading_zero {
        buf.push(0x00);
    }
    buf.extend_from_slice(trimmed);
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use sshenc_agent_proto::signature::der_to_ssh_signature;

    #[test]
    fn ssh_sig_to_der_round_trips_known_values() {
        // r=1..=32, s=33..=64 — neither has the high bit set, so no
        // leading-zero pad needed.
        let r: Vec<u8> = (1_u8..=32).collect();
        let s: Vec<u8> = (33_u8..=64).collect();
        let mut der_original = Vec::new();
        der_original.push(0x30);
        // inner = 0x02, len(r), r, 0x02, len(s), s
        let mut inner = Vec::new();
        inner.push(0x02);
        inner.push(r.len() as u8);
        inner.extend_from_slice(&r);
        inner.push(0x02);
        inner.push(s.len() as u8);
        inner.extend_from_slice(&s);
        der_original.push(inner.len() as u8);
        der_original.extend_from_slice(&inner);

        let ssh_sig = der_to_ssh_signature(&der_original).unwrap();
        let der_round = ssh_sig_to_der(&ssh_sig).unwrap();
        assert_eq!(der_round, der_original);
    }

    #[test]
    fn ssh_sig_to_der_handles_high_bit_values() {
        // r with high bit set on first byte — DER needs a leading
        // zero to stay positive. SSH mpint mirrors that. Round-trip
        // must preserve the representation.
        let r = vec![0xFF_u8; 32];
        let s = vec![0x42_u8; 32];
        let mut inner = Vec::new();
        inner.push(0x02);
        inner.push((r.len() + 1) as u8);
        inner.push(0x00);
        inner.extend_from_slice(&r);
        inner.push(0x02);
        inner.push(s.len() as u8);
        inner.extend_from_slice(&s);
        let mut der_original = Vec::new();
        der_original.push(0x30);
        der_original.push(inner.len() as u8);
        der_original.extend_from_slice(&inner);

        let ssh_sig = der_to_ssh_signature(&der_original).unwrap();
        let der_round = ssh_sig_to_der(&ssh_sig).unwrap();
        assert_eq!(der_round, der_original);
    }
}
