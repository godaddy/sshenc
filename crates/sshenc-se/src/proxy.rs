// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `AgentProxyBackend` — a `KeyBackend` implementation used by CLI
//! binaries on Unix that *never* calls into Secure Enclave or the
//! keychain directly. Every write-side operation (`generate` /
//! `sign` / `delete` / `rename`) is forwarded over the
//! `sshenc-agent` Unix socket, and read-side operations (`list` /
//! `get` / `is_available`) are served by reading `.pub` / `.meta`
//! files from disk — **there is no code path inside
//! `AgentProxyBackend` that reaches `SecItem*` or `SecKey*` or
//! `enclaveapp_se_*`.** The CLI binary's code signature therefore
//! never appears on any of those calls, which eliminates the legacy
//! keychain cross-binary ACL prompt that unsigned macOS builds
//! would otherwise fire between the CLI (creator) and the agent
//! (reader).
//!
//! The agent is auto-spawned lazily: `new()` only stores config, and
//! each proxied write op calls
//! `sshenc_agent_proto::client::ensure_agent_ready` just before
//! sending its RPC. Read-only ops don't touch the agent at all, so
//! `sshenc list` / `inspect` / `export-pub` never force the agent
//! up for cosmetic queries.
//!
//! If a `.pub` file is missing on disk (key created by a pre–Wart-1
//! version of sshenc, or manually deleted), `get` errors out with a
//! `KeyNotFound`-style message rather than falling back to a
//! handle-decrypt path — because that fallback would exit the
//! agent-only contract.

use crate::backend::KeyBackend;
use enclaveapp_core::metadata;
use sshenc_core::error::{Error, Result};
use sshenc_core::fingerprint;
use sshenc_core::key::{KeyGenOptions, KeyInfo, KeyLabel, KeyMetadata};
use sshenc_core::pubkey::SshPublicKey;
use std::path::PathBuf;

#[cfg(unix)]
use sshenc_agent_proto::client;

/// `KeyBackend` that serves reads from `.pub` / `.meta` files and
/// forwards every write-side op to `sshenc-agent`. Has no code
/// path that invokes the Secure-Enclave FFI or the keychain.
#[derive(Debug)]
pub struct AgentProxyBackend {
    /// Directory holding `<label>.pub` / `<label>.meta` /
    /// `<label>.handle` files. The CLI only reads `.pub` and
    /// `.meta` (never `.handle`) — `.handle` would require the
    /// wrapping key and thus the keychain, which is the agent's
    /// job.
    keys_dir: PathBuf,
    /// User's `~/.ssh`-style directory where copies of `<label>.pub`
    /// in OpenSSH format may be written. Used purely for
    /// [`KeyInfo::pub_file_path`] population.
    pub_dir: PathBuf,
    /// Socket the agent listens on for proxied write ops.
    #[cfg_attr(not(unix), allow(dead_code))]
    socket_path: PathBuf,
}

impl AgentProxyBackend {
    /// Build a proxy backend for operations against the agent
    /// listening at `socket_path`. **Does not spawn the agent.**
    /// Each write-side op does a lazy `ensure_agent_ready` before
    /// its RPC, so read-only invocations (`sshenc list`,
    /// `inspect`, `export-pub`) don't force the agent up.
    ///
    /// `pub_dir` is the OpenSSH `.pub` destination reported in
    /// [`KeyInfo::pub_file_path`]. `force_keyring` is accepted for
    /// API parity with [`SshencBackend::new`] but isn't used — the
    /// agent already honors whatever backend policy the user
    /// configured.
    pub fn new(
        pub_dir: PathBuf,
        _force_keyring: bool,
        socket_path: PathBuf,
    ) -> std::result::Result<Self, enclaveapp_app_storage::StorageError> {
        Ok(Self {
            keys_dir: crate::unified::sshenc_keys_dir(),
            pub_dir,
            socket_path,
        })
    }

    #[cfg(unix)]
    fn ensure_agent(&self) -> Result<()> {
        client::ensure_agent_ready(&self.socket_path).map_err(|e| Error::SecureEnclave {
            operation: "ensure_agent".into(),
            detail: format!(
                "sshenc-agent not reachable at {}: {e}",
                self.socket_path.display()
            ),
        })
    }

    fn agent_refused(op: &'static str, detail: impl Into<String>) -> Error {
        Error::SecureEnclave {
            operation: op.into(),
            detail: detail.into(),
        }
    }

    /// Match [`SshencBackend::persisted_pub_file_path`] semantics:
    /// prefer an explicit `pub_file_path` recorded in metadata,
    /// otherwise probe `pub_dir/<label>.pub`. Disk-only; never
    /// reaches into the keychain.
    fn persisted_pub_file_path(
        &self,
        meta: &enclaveapp_core::KeyMeta,
        label: &str,
    ) -> Option<PathBuf> {
        match meta.app_specific.get("pub_file_path") {
            Some(value) if value.is_string() => value.as_str().map(PathBuf::from),
            Some(_) | None => {
                let candidate = self.pub_dir.join(format!("{label}.pub"));
                candidate.exists().then_some(candidate)
            }
        }
    }
}

fn map_meta_err(operation: &str, e: enclaveapp_core::Error) -> Error {
    Error::SecureEnclave {
        operation: operation.into(),
        detail: e.to_string(),
    }
}

impl KeyBackend for AgentProxyBackend {
    fn generate(&self, opts: &KeyGenOptions) -> Result<KeyInfo> {
        #[cfg(unix)]
        {
            self.ensure_agent()?;
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

    /// Enumerate keys by walking `.meta` files on disk. Never
    /// touches the keychain or the Secure Enclave — if a key's
    /// `.pub` is missing we log and skip it rather than falling
    /// back to a handle-decrypt path.
    fn list(&self) -> Result<Vec<KeyInfo>> {
        let labels =
            metadata::list_labels(&self.keys_dir).map_err(|e| map_meta_err("list_labels", e))?;
        let mut keys = Vec::with_capacity(labels.len());
        for label in labels {
            match self.get(&label) {
                Ok(info) => keys.push(info),
                Err(e) => tracing::warn!("skipping key {label}: {e}"),
            }
        }
        Ok(keys)
    }

    /// Read `<label>.pub` and `<label>.meta` straight from disk and
    /// assemble a [`KeyInfo`]. Never reads the wrapping key or
    /// calls `load_handle` — if the `.pub` cache is missing the
    /// caller gets a plain "not found" error rather than a silent
    /// fallback that would bypass the agent-only invariant.
    fn get(&self, label: &str) -> Result<KeyInfo> {
        let owned_label = KeyLabel::new(label)?;

        let public_bytes = metadata::load_pub_key(&self.keys_dir, label)
            .map_err(|e| map_meta_err("load_pub_key", e))?;
        let meta = crate::compat::load_sshenc_meta(&self.keys_dir, label)
            .map_err(|e| map_meta_err("load_meta", e))?;

        let comment = meta
            .app_specific
            .get("comment")
            .and_then(|v| v.as_str())
            .map(str::to_string);

        let ssh_pubkey = SshPublicKey::from_sec1_bytes(&public_bytes, comment.clone())?;
        let (fp_sha256, fp_md5) = fingerprint::fingerprints(&ssh_pubkey);
        let pub_file_path = self.persisted_pub_file_path(&meta, label);

        Ok(KeyInfo {
            metadata: KeyMetadata::new(owned_label, meta.access_policy, comment),
            public_key_bytes: public_bytes,
            fingerprint_sha256: fp_sha256,
            fingerprint_md5: fp_md5,
            pub_file_path,
        })
    }

    fn delete(&self, label: &str) -> Result<()> {
        #[cfg(unix)]
        {
            self.ensure_agent()?;
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
            self.ensure_agent()?;
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
            self.ensure_agent()?;
            let info = self.get(label)?;
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

    /// Always `true`. The CLI trusts the agent; actual hardware
    /// availability is the agent's concern to verify when it
    /// services a request.
    fn is_available(&self) -> bool {
        true
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
