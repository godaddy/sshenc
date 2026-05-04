// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `AgentProxyBackend` — a cross-platform `KeyBackend` that never
//! calls into Secure Enclave / Windows CNG / the macOS keychain /
//! the Linux keyring directly. Every write-side operation
//! (`generate` / `sign` / `delete` / `rename`) is forwarded over
//! the `sshenc-agent` IPC endpoint — a Unix socket on macOS and
//! Linux (including WSLv2), a named pipe on native Windows (Git
//! Bash, PowerShell, cmd.exe). Read-side operations (`list` /
//! `get`) are served by reading `.pub` / `.meta` files from disk.
//! There is **no code path** inside `AgentProxyBackend` that
//! reaches the platform crypto FFI; the CLI binary's code
//! signature therefore never appears on a `SecItem*` / `SecKey*`
//! / `BCryptSignHash` / `keyutils`-family call, so the
//! cross-binary ACL prompt class the centralization eliminates on
//! macOS also doesn't exist on the other platforms.
//!
//! The agent is auto-spawned lazily on Unix: `new()` only stores
//! config, and each proxied write op calls
//! `sshenc_agent_proto::client::ensure_agent_ready` just before
//! sending its RPC. Read-only ops don't touch the agent at all, so
//! `sshenc list` / `inspect` / `export-pub` never force the agent
//! up for cosmetic queries. On Windows `ensure_agent_ready`
//! probes the named pipe but does **not** spawn the agent —
//! Windows services / scheduled-task lifecycle choices belong to
//! `sshenc install`, not to ad-hoc CLI invocations.
//!
//! If a `.pub` file is missing on disk (key created by a pre–Wart-1
//! version of sshenc, or manually deleted), `get` errors out with a
//! `KeyNotFound`-style message rather than falling back to a
//! handle-decrypt path — because that fallback would exit the
//! agent-only contract.

use crate::backend::KeyBackend;
use enclaveapp_core::metadata;
use enclaveapp_core::types::PresenceMode;
use sshenc_agent_proto::client;
use sshenc_core::error::{Error, Result};
use sshenc_core::fingerprint;
use sshenc_core::key::{KeyGenOptions, KeyInfo, KeyLabel, KeyMetadata};
use sshenc_core::pubkey::SshPublicKey;
use std::path::PathBuf;

/// Wire encoding for [`PresenceMode`] in the
/// `SSH_AGENTC_SSHENC_GENERATE_KEY` extension. Kept in one place so
/// the agent and the proxy can never disagree on the mapping. See
/// [`PresenceMode::migration_default`] for the legacy fallback.
pub fn presence_mode_to_wire(mode: PresenceMode) -> u8 {
    match mode {
        PresenceMode::Cached => 0,
        PresenceMode::Strict => 1,
        PresenceMode::None => 2,
    }
}

pub fn presence_mode_from_wire(byte: u8) -> Option<PresenceMode> {
    match byte {
        0 => Some(PresenceMode::Cached),
        1 => Some(PresenceMode::Strict),
        2 => Some(PresenceMode::None),
        _ => None,
    }
}

/// Read the `presence_mode` field out of `app_specific`. Returns
/// `None` if the field is absent or unrecognized; the caller applies
/// the migration default.
pub fn presence_mode_from_app_specific(app_specific: &serde_json::Value) -> Option<PresenceMode> {
    let s = app_specific.get("presence_mode")?.as_str()?;
    match s {
        "cached" => Some(PresenceMode::Cached),
        "strict" => Some(PresenceMode::Strict),
        "none" => Some(PresenceMode::None),
        _ => None,
    }
}

pub fn presence_mode_to_app_specific_str(mode: PresenceMode) -> &'static str {
    match mode {
        PresenceMode::Cached => "cached",
        PresenceMode::Strict => "strict",
        PresenceMode::None => "none",
    }
}

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
    /// Endpoint the agent listens on. On Unix this is a Unix socket
    /// path like `~/.sshenc/agent.sock`; on Windows a named-pipe
    /// path like `\\.\pipe\openssh-ssh-agent`. Either way,
    /// `sshenc_agent_proto::client::*` takes care of dispatching to
    /// the right native IPC.
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
    /// [`KeyInfo::pub_file_path`]. The backend policy on the agent
    /// side is decided by `sshenc-agent`'s own config; the proxy
    /// has nothing to switch on, so unlike [`SshencBackend::new`]
    /// there's no `force_keyring` knob to plumb through.
    pub fn new(
        pub_dir: PathBuf,
        socket_path: PathBuf,
    ) -> std::result::Result<Self, enclaveapp_app_storage::StorageError> {
        Ok(Self {
            keys_dir: crate::unified::sshenc_keys_dir(),
            pub_dir,
            socket_path,
        })
    }

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

    /// After a successful `generate` over the wire, persist the SEC1
    /// public-key cache and the JSON metadata under `keys_dir` so the
    /// proxy's read-only ops (`get` / `list` / `inspect` /
    /// `export-pub`) can find the freshly-created key on the next
    /// invocation. This duplicates the persistence step
    /// [`crate::unified::SshencBackend::generate`] performs on the
    /// agent's host — necessary because the CLI's `keys_dir` and the
    /// agent's `keys_dir` are NOT the same path when the agent runs
    /// on a different OS than the CLI (the WSL → Windows
    /// socat/named-pipe case).
    fn cache_key_artifacts_locally(
        &self,
        opts: &KeyGenOptions,
        public_bytes: &[u8],
        pub_file_path: Option<&std::path::Path>,
    ) -> Result<()> {
        metadata::ensure_dir(&self.keys_dir).map_err(|e| map_meta_err("ensure_keys_dir", e))?;

        // SEC1 public-key cache — `metadata::load_pub_key` reads this
        // back during `get` and would otherwise fail with KeyNotFound.
        metadata::save_pub_key(&self.keys_dir, opts.label.as_str(), public_bytes)
            .map_err(|e| map_meta_err("save_pub_key", e))?;

        // JSON `.meta`. Mirror the field set written by
        // `SshencBackend::generate`: comment, pub_file_path,
        // presence_mode. Use the same load-or-init helper so we
        // preserve any unexpected app-specific fields a future agent
        // may have already written on a shared filesystem.
        let mut meta = crate::compat::load_sshenc_meta(&self.keys_dir, opts.label.as_str())
            .map_err(|e| map_meta_err("load_meta", e))?;
        // `load_sshenc_meta` returns a default with AccessPolicy::None
        // when the file is absent — overwrite with the policy we just
        // generated under so subsequent `inspect` shows the right value.
        meta.access_policy = opts.access_policy;
        if let Some(ref comment) = opts.comment {
            meta.set_app_field("comment", comment.clone());
        }
        match pub_file_path {
            Some(path) => meta.set_app_field(
                "pub_file_path",
                path.as_os_str().to_string_lossy().to_string(),
            ),
            None => meta.set_app_field("pub_file_path", serde_json::Value::Null),
        }
        meta.set_app_field(
            "presence_mode",
            presence_mode_to_app_specific_str(opts.presence_mode),
        );
        metadata::save_meta(&self.keys_dir, opts.label.as_str(), &meta)
            .map_err(|e| map_meta_err("save_meta", e))?;
        Ok(())
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

    /// Build a `KeyInfo` for a SK / FIDO2 key from its `.meta` file.
    /// Reads the SK wire-format `.pub` from the path the meta
    /// recorded, parses out the EC point + application string, and
    /// recomputes the SK fingerprint. Used by the proxy's `get()`
    /// when the meta carries the `sk-ecdsa-sha2-nistp256` marker.
    fn sk_keyinfo_from_meta(
        keys_dir: &std::path::Path,
        label: &KeyLabel,
        meta: &enclaveapp_core::KeyMeta,
        comment: Option<String>,
    ) -> Result<KeyInfo> {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        use sshenc_core::pubkey::{read_ssh_string, SshSkPublicKey};

        let credential_id_b64 = meta.get_app_field("credential_id_b64").ok_or_else(|| {
            Error::Other(format!(
                "SK key '{}' missing credential_id_b64",
                label.as_str()
            ))
        })?;
        let credential_id = STANDARD.decode(credential_id_b64).map_err(Error::Base64)?;
        let rp_id = meta
            .get_app_field("rp_id")
            .ok_or_else(|| Error::Other(format!("SK key '{}' missing rp_id", label.as_str())))?
            .to_string();

        let pub_path = meta
            .get_app_field("pub_file_path")
            .map(PathBuf::from)
            .filter(|p| p.exists())
            .ok_or_else(|| {
                Error::Other(format!(
                    "SK key '{}' has no readable .pub file -- regenerate",
                    label.as_str()
                ))
            })?;

        let line = std::fs::read_to_string(&pub_path)?;
        let parts: Vec<&str> = line.trim().splitn(3, ' ').collect();
        if parts.len() < 2 {
            return Err(Error::InvalidPublicKey(format!(
                "SK key '{}' .pub file is malformed",
                label.as_str()
            )));
        }
        let blob = STANDARD
            .decode(parts[1])
            .map_err(|e| Error::InvalidPublicKey(format!("invalid base64: {e}")))?;

        let (key_type, rest) = read_ssh_string(&blob)?;
        if key_type != b"sk-ecdsa-sha2-nistp256@openssh.com" {
            return Err(Error::InvalidPublicKey(format!(
                "SK key '{}' .pub file has wrong key type",
                label.as_str()
            )));
        }
        let (_curve, rest) = read_ssh_string(rest)?;
        let (q, _rest) = read_ssh_string(rest)?;
        let public_key_bytes = q.to_vec();

        let sk_pubkey =
            SshSkPublicKey::from_sec1_bytes(&public_key_bytes, rp_id.clone(), comment.clone())?;
        let (fp_sha256, fp_md5) = fingerprint::sk_fingerprints(&sk_pubkey);

        // Suppress unused-warning when we don't actually use keys_dir
        // here -- meta resolution already happened via the caller.
        let _ = keys_dir;

        Ok(KeyInfo {
            metadata: KeyMetadata::for_sk(
                label.clone(),
                meta.access_policy,
                presence_mode_from_app_specific(&meta.app_specific),
                comment,
                credential_id,
                rp_id,
            ),
            public_key_bytes,
            fingerprint_sha256: fp_sha256,
            fingerprint_md5: fp_md5,
            pub_file_path: Some(pub_path),
        })
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
        self.ensure_agent()?;
        let public_bytes = client::try_generate_via_socket(
            &self.socket_path,
            opts.label.as_str(),
            opts.comment.as_deref(),
            opts.access_policy.as_ffi_value() as u32,
            presence_mode_to_wire(opts.presence_mode),
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
            std::fs::write(path, format!("{}\n", ssh_pubkey.to_openssh_line())).map_err(|e| {
                Error::SecureEnclave {
                    operation: "generate".into(),
                    detail: format!("write {}: {e}", path.display()),
                }
            })?;
            Some(path.clone())
        } else {
            None
        };

        // Mirror the metadata + SEC1 cache that `SshencBackend::generate`
        // writes on the agent's host. When the CLI and agent run on the
        // same host this is a redundant idempotent write to the same
        // `.pub` / `.meta` paths the agent just wrote. When the CLI
        // sits in WSL and reaches a Windows agent over socat / the
        // OpenSSH named pipe, the agent's writes land under
        // `%APPDATA%\sshenc\keys` on Windows and the WSL keys_dir
        // would otherwise be empty — making subsequent
        // `inspect` / `export-pub` / `list` fail with
        // `load_pub_key: key not found`. Persisting locally here
        // restores the read-side invariants AgentProxyBackend depends
        // on without expanding the wire protocol.
        self.cache_key_artifacts_locally(opts, &public_bytes, pub_file_path.as_deref())?;

        Ok(KeyInfo {
            metadata: KeyMetadata::with_presence_mode(
                opts.label.clone(),
                opts.access_policy,
                Some(opts.presence_mode),
                opts.comment.clone(),
            ),
            public_key_bytes: public_bytes,
            fingerprint_sha256: fp_sha256,
            fingerprint_md5: fp_md5,
            pub_file_path,
        })
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
    ///
    /// SK / FIDO2 keys take a separate path: their `.meta` carries
    /// an `algorithm: sk-ecdsa-sha2-nistp256` marker, the SSH
    /// `.pub` lives at the user's chosen path (typically
    /// `~/.ssh/<label>.pub`) in the SK wire format, and there is
    /// no SEC1 cache in `keys_dir`. The proxy detects the marker
    /// and assembles a `KeyInfo` from those sources without going
    /// through the legacy SEC1 path.
    fn get(&self, label: &str) -> Result<KeyInfo> {
        let owned_label = KeyLabel::new(label)?;
        let meta = crate::compat::load_sshenc_meta(&self.keys_dir, label)
            .map_err(|e| map_meta_err("load_meta", e))?;
        let comment = meta
            .app_specific
            .get("comment")
            .and_then(|v| v.as_str())
            .map(str::to_string);

        if meta.get_app_field("algorithm") == Some("sk-ecdsa-sha2-nistp256") {
            return Self::sk_keyinfo_from_meta(&self.keys_dir, &owned_label, &meta, comment);
        }

        let public_bytes = metadata::load_pub_key(&self.keys_dir, label)
            .map_err(|e| map_meta_err("load_pub_key", e))?;
        let ssh_pubkey = SshPublicKey::from_sec1_bytes(&public_bytes, comment.clone())?;
        let (fp_sha256, fp_md5) = fingerprint::fingerprints(&ssh_pubkey);
        let pub_file_path = self.persisted_pub_file_path(&meta, label);
        let presence_mode = presence_mode_from_app_specific(&meta.app_specific);

        Ok(KeyInfo {
            metadata: KeyMetadata::with_presence_mode(
                owned_label,
                meta.access_policy,
                presence_mode,
                comment,
            ),
            public_key_bytes: public_bytes,
            fingerprint_sha256: fp_sha256,
            fingerprint_md5: fp_md5,
            pub_file_path,
        })
    }

    fn delete(&self, label: &str) -> Result<()> {
        self.ensure_agent()?;
        client::try_delete_via_socket(&self.socket_path, label).ok_or_else(|| {
            Self::agent_refused(
                "delete",
                format!(
                    "sshenc-agent refused delete for label '{label}' \
                     (check agent logs)"
                ),
            )
        })?;
        // Symmetrical to `cache_key_artifacts_locally`: when CLI and
        // agent share keys_dir the agent already removed these; when
        // they don't (WSL → Windows agent) the local cache would
        // otherwise stay around as ghost entries surfaced by `list`.
        // Failures here are not fatal — the authoritative state is in
        // the hardware key store, not the cache.
        let pub_path = self.keys_dir.join(format!("{label}.pub"));
        let meta_path = self.keys_dir.join(format!("{label}.meta"));
        let meta_hmac = self.keys_dir.join(format!("{label}.meta.hmac"));
        for p in [pub_path, meta_path, meta_hmac] {
            if let Err(e) = std::fs::remove_file(&p) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::debug!(path = %p.display(), error = %e, "post-delete cache cleanup");
                }
            }
        }
        Ok(())
    }

    fn rename(&self, old_label: &str, new_label: &str) -> Result<()> {
        self.ensure_agent()?;
        client::try_rename_via_socket(&self.socket_path, old_label, new_label).ok_or_else(|| {
            Self::agent_refused(
                "rename",
                format!(
                    "sshenc-agent refused rename '{old_label}' -> '{new_label}' \
                     (check agent logs and allowed_labels)"
                ),
            )
        })
    }

    /// Signs via the agent and converts the returned SSH-format
    /// signature (`string(algo) || string(mpint r || mpint s)`) back
    /// to DER so the `KeyBackend::sign` contract (which promises
    /// DER-encoded ECDSA) is honored.
    fn sign(&self, label: &str, data: &[u8]) -> Result<Vec<u8>> {
        self.ensure_agent()?;
        let info = self.get(label)?;
        let pubkey = SshPublicKey::from_sec1_bytes(&info.public_key_bytes, info.metadata.comment)?;
        let wire_blob = pubkey.wire_blob();
        let ssh_sig =
            client::try_sign_via_socket(&self.socket_path, &wire_blob, data).ok_or_else(|| {
                Self::agent_refused(
                    "sign",
                    "sshenc-agent refused sign request (check agent logs)",
                )
            })?;
        ssh_sig_to_der(&ssh_sig)
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

#[cfg(test)]
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
        // must preserve the representation. Use 0x80 (within P-256 order)
        // rather than 0xFF (which exceeds the order and is rejected by p256).
        let r = vec![0x80_u8; 32];
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

    // ---- Local cache after agent-side generate (Issue: WSL → Windows
    // agent leaves CLI keys_dir empty, breaking inspect/list) ----

    use sshenc_core::key::KeyGenOptions;
    use std::sync::atomic::{AtomicU64, Ordering};

    static CACHE_TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn cache_test_dirs() -> (PathBuf, PathBuf) {
        let id = CACHE_TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let base =
            std::env::temp_dir().join(format!("sshenc-proxy-cache-{}-{id}", std::process::id(),));
        let keys = base.join("keys");
        let pubs = base.join("pub");
        std::fs::create_dir_all(&keys).unwrap();
        std::fs::create_dir_all(&pubs).unwrap();
        (keys, pubs)
    }

    fn make_backend(keys: PathBuf, pubs: PathBuf, sock: PathBuf) -> AgentProxyBackend {
        AgentProxyBackend {
            keys_dir: keys,
            pub_dir: pubs,
            socket_path: sock,
        }
    }

    fn p256_pub_bytes() -> Vec<u8> {
        // Valid P-256 generator G in uncompressed SEC1 form
        // (`0x04 || Gx || Gy`). The canonical generator coordinates
        // are spelled out byte-for-byte so the test stays free of any
        // hex-decode dependency. Source: SEC2 §2.4.2.
        let gx: [u8; 32] = [
            0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4,
            0x40, 0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45,
            0xD8, 0x98, 0xC2, 0x96,
        ];
        let gy: [u8; 32] = [
            0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F,
            0x9E, 0x16, 0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68,
            0x37, 0xBF, 0x51, 0xF5,
        ];
        let mut bytes = Vec::with_capacity(65);
        bytes.push(0x04);
        bytes.extend_from_slice(&gx);
        bytes.extend_from_slice(&gy);
        bytes
    }

    #[test]
    fn cache_key_artifacts_writes_pub_and_meta_to_keys_dir() {
        let (keys_dir, pub_dir) = cache_test_dirs();
        let backend = make_backend(keys_dir.clone(), pub_dir, PathBuf::from("/dev/null"));

        let opts = KeyGenOptions {
            label: KeyLabel::new("ub-test").unwrap(),
            comment: Some("test@host".into()),
            access_policy: enclaveapp_core::AccessPolicy::None,
            presence_mode: PresenceMode::None,
            write_pub_path: None,
        };
        let pub_bytes = p256_pub_bytes();
        backend
            .cache_key_artifacts_locally(&opts, &pub_bytes, None)
            .unwrap();

        // SEC1 .pub cache landed where load_pub_key reads it.
        let cached_pub = metadata::load_pub_key(&keys_dir, "ub-test").unwrap();
        assert_eq!(cached_pub, pub_bytes);

        // .meta carries the comment, presence_mode, null pub_file_path.
        let meta = crate::compat::load_sshenc_meta(&keys_dir, "ub-test").unwrap();
        assert_eq!(
            meta.app_specific.get("comment").and_then(|v| v.as_str()),
            Some("test@host")
        );
        assert_eq!(
            meta.app_specific
                .get("presence_mode")
                .and_then(|v| v.as_str()),
            Some("none")
        );
        assert!(meta
            .app_specific
            .get("pub_file_path")
            .map(serde_json::Value::is_null)
            .unwrap_or(false));
        std::fs::remove_dir_all(keys_dir.parent().unwrap()).unwrap();
    }

    #[test]
    fn cache_key_artifacts_records_pub_file_path_when_present() {
        let (keys_dir, pub_dir) = cache_test_dirs();
        let backend = make_backend(
            keys_dir.clone(),
            pub_dir.clone(),
            PathBuf::from("/dev/null"),
        );

        let opts = KeyGenOptions {
            label: KeyLabel::new("with-pub").unwrap(),
            comment: None,
            access_policy: enclaveapp_core::AccessPolicy::Any,
            presence_mode: PresenceMode::Cached,
            write_pub_path: None,
        };
        let pub_bytes = p256_pub_bytes();
        let pub_file = pub_dir.join("with-pub.pub");
        backend
            .cache_key_artifacts_locally(&opts, &pub_bytes, Some(&pub_file))
            .unwrap();

        let meta = crate::compat::load_sshenc_meta(&keys_dir, "with-pub").unwrap();
        assert_eq!(meta.access_policy, enclaveapp_core::AccessPolicy::Any);
        assert_eq!(
            meta.app_specific
                .get("pub_file_path")
                .and_then(|v| v.as_str()),
            Some(pub_file.to_string_lossy().as_ref())
        );
        assert_eq!(
            meta.app_specific
                .get("presence_mode")
                .and_then(|v| v.as_str()),
            Some("cached")
        );
        std::fs::remove_dir_all(keys_dir.parent().unwrap()).unwrap();
    }

    #[test]
    fn cache_then_get_round_trips_via_disk_only() {
        // Once cache_key_artifacts_locally has run, AgentProxyBackend::get
        // (which reads only from keys_dir, never the agent) must return
        // the same KeyInfo. This is the exact path that was failing
        // for `sshenc inspect` after a WSL → Windows agent keygen.
        let (keys_dir, pub_dir) = cache_test_dirs();
        let backend = make_backend(keys_dir.clone(), pub_dir, PathBuf::from("/dev/null"));

        let opts = KeyGenOptions {
            label: KeyLabel::new("rt-key").unwrap(),
            comment: Some("round@trip".into()),
            access_policy: enclaveapp_core::AccessPolicy::None,
            presence_mode: PresenceMode::None,
            write_pub_path: None,
        };
        let pub_bytes = p256_pub_bytes();
        backend
            .cache_key_artifacts_locally(&opts, &pub_bytes, None)
            .unwrap();

        let info = backend.get("rt-key").unwrap();
        assert_eq!(info.metadata.label.as_str(), "rt-key");
        assert_eq!(info.metadata.comment.as_deref(), Some("round@trip"));
        assert_eq!(info.public_key_bytes, pub_bytes);
        assert!(info.fingerprint_sha256.starts_with("SHA256:"));
        std::fs::remove_dir_all(keys_dir.parent().unwrap()).unwrap();
    }
}
