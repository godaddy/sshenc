// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! FIDO2 / WebAuthn-backed SK key operations.
//!
//! Wraps `hardware_enclave::SecurityKeyHandle` to keygen and sign with
//! `sk-ecdsa-sha2-nistp256@openssh.com` keys whose private material
//! lives inside the Windows TPM. Compiled in only when the
//! `webauthn-sk` feature is enabled.

#![cfg(feature = "webauthn-sk")]

use hardware_enclave::{AccessPolicy, EnclaveConfig, PresenceMode};
use sshenc_core::error::{Error, Result};
use sshenc_core::fingerprint;
#[cfg(test)]
use sshenc_core::key::KeyLabel;
use sshenc_core::key::{KeyAlgorithm, KeyInfo, KeyMetadata, SkKeyGenOptions};
use sshenc_core::pubkey::{encode_sk_signature_blob, SshSkPublicKey};
use std::path::PathBuf;

/// Construct the deterministic per-key RP ID from a sshenc label.
/// This matches `hardware_enclave::security_key::rp_id_for("sshenc", label)`.
pub fn rp_id_for_label(label: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"sshenc-rp-id-v1\x00");
    hasher.update(label.as_bytes());
    let digest = hasher.finalize();
    let hex: String = digest.iter().take(4).map(|b| format!("{b:02x}")).collect();
    format!("sshenc-{hex}.local")
}

fn sk_handle(keys_dir: Option<PathBuf>) -> hardware_enclave::SecurityKeyHandle {
    let config = EnclaveConfig {
        app_name: "sshenc".into(),
        default_key_label: "default".into(),
        access_policy: Some(AccessPolicy::Any),
        keys_dir,
        platform: hardware_enclave::PlatformConfig::Default,
    };
    hardware_enclave::create_security_key(&config)
}

/// True if SK keys are usable on this host.
pub fn is_available() -> bool {
    sk_handle(None).is_available()
}

/// Create a new SK key for `label`. Triggers a Hello-enrollment
/// prompt on the Windows desktop; the resulting credential is sealed
/// by the TPM and returned as a `KeyInfo`.
pub fn generate(opts: &SkKeyGenOptions) -> Result<KeyInfo> {
    let label_str = opts.label.as_str();
    let keys_dir = crate::unified::sshenc_keys_dir();

    let handle = sk_handle(Some(keys_dir.clone()));
    if !handle.is_available() {
        return Err(Error::Other(
            "SK backend not available (no Hello, no bridge)".into(),
        ));
    }

    let info = handle
        .generate(label_str, opts.comment.as_deref())
        .map_err(|e| Error::Other(format!("SK keygen failed: {e}")))?;

    let rp_id = info.rp_id.clone();
    let sec1 = info.public_key.clone();

    let ssh_pubkey = SshSkPublicKey::from_sec1_bytes(&sec1, rp_id.clone(), opts.comment.clone())?;
    let (fp_sha256, fp_md5) = fingerprint::sk_fingerprints(&ssh_pubkey);

    let pub_file_path: Option<PathBuf> = if let Some(ref path) = opts.write_pub_path {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let line = ssh_pubkey.to_openssh_line();
        std::fs::write(path, format!("{line}\n"))?;
        Some(path.clone())
    } else {
        None
    };

    let metadata = KeyMetadata::for_sk(
        opts.label.clone(),
        AccessPolicy::Any,
        Some(PresenceMode::Strict),
        opts.comment.clone(),
        info.credential_id,
        rp_id,
    );

    Ok(KeyInfo {
        metadata,
        public_key_bytes: sec1,
        fingerprint_sha256: fp_sha256,
        fingerprint_md5: fp_md5,
        pub_file_path,
    })
}

/// Best-effort removal of a platform credential from the user's
/// passkey list.
pub fn delete_platform_credential(credential_id: &[u8]) -> Result<()> {
    let keys_dir = crate::unified::sshenc_keys_dir();
    let handle = sk_handle(Some(keys_dir));
    if !handle.is_available() {
        return Err(Error::Other("SK backend not available for delete".into()));
    }
    // Delete by credential_id: find the label that matches.
    // SecurityKeyHandle::delete_credential takes a label, not a credential_id.
    // Search through credentials to find the matching one.
    let creds = handle
        .list_credentials()
        .map_err(|e| Error::Other(format!("list credentials: {e}")))?;
    let matching = creds.iter().find(|c| c.credential_id == credential_id);
    if let Some(cred) = matching {
        handle
            .delete_credential(&cred.label)
            .map_err(|e| Error::Other(format!("delete credential: {e}")))
    } else {
        // Not found — treat as success (already deleted)
        Ok(())
    }
}

/// Sign `data` with an SK key identified by `credential_id` and `rp_id`.
/// Returns a fully-formed SK signature blob.
pub fn sign(credential_id: &[u8], rp_id: &str, data: &[u8]) -> Result<Vec<u8>> {
    let keys_dir = crate::unified::sshenc_keys_dir();
    let handle = sk_handle(Some(keys_dir));
    if !handle.is_available() {
        return Err(Error::Other("SK backend not available for sign".into()));
    }

    // Find the label for this credential_id so we can call handle.sign(label, data).
    let creds = handle
        .list_credentials()
        .map_err(|e| Error::Other(format!("list credentials for sign: {e}")))?;
    let matching = creds
        .iter()
        .find(|c| c.credential_id == credential_id && c.rp_id == rp_id);

    if let Some(cred) = matching {
        let sig = handle
            .sign(&cred.label, data)
            .map_err(|e| Error::Other(format!("SK sign failed: {e}")))?;
        encode_sk_signature_blob(&sig.signature_der, sig.flags, sig.counter)
    } else {
        Err(Error::Other(format!(
            "SK credential not found for rp_id={rp_id}"
        )))
    }
}

/// Validate that the metadata stored for a label looks like an SK
/// key (algorithm tagged + credential_id and rp_id present).
/// Returns the unwrapped fields ready for sign().
pub fn extract_sk_fields(meta: &KeyMetadata) -> Result<(&[u8], &str)> {
    if !matches!(meta.algorithm, KeyAlgorithm::SkEcdsaP256) {
        return Err(Error::Other(
            "extract_sk_fields called on non-SK metadata".into(),
        ));
    }
    let credential_id = meta
        .credential_id
        .as_deref()
        .ok_or_else(|| Error::Other("SK metadata missing credential_id".into()))?;
    let rp_id = meta
        .rp_id
        .as_deref()
        .ok_or_else(|| Error::Other("SK metadata missing rp_id".into()))?;
    Ok((credential_id, rp_id))
}

/// Reconstruct an `SshSkPublicKey` from a `KeyInfo`.
pub fn ssh_pubkey_from_keyinfo(info: &KeyInfo) -> Result<SshSkPublicKey> {
    if !matches!(info.metadata.algorithm, KeyAlgorithm::SkEcdsaP256) {
        return Err(Error::Other(
            "ssh_pubkey_from_keyinfo: not an SK key".into(),
        ));
    }
    let rp_id = info
        .metadata
        .rp_id
        .clone()
        .ok_or_else(|| Error::Other("SK metadata missing rp_id".into()))?;
    SshSkPublicKey::from_sec1_bytes(&info.public_key_bytes, rp_id, info.metadata.comment.clone())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn rp_id_is_deterministic() {
        let a = rp_id_for_label("default");
        let b = rp_id_for_label("default");
        assert_eq!(a, b);
    }

    #[test]
    fn rp_id_differs_per_label() {
        let a = rp_id_for_label("github");
        let b = rp_id_for_label("gitlab");
        assert_ne!(a, b);
    }

    #[test]
    fn rp_id_matches_expected_format() {
        let id = rp_id_for_label("default");
        assert!(
            id.starts_with("sshenc-"),
            "rp_id must start with 'sshenc-': {id}"
        );
        assert!(id.ends_with(".local"), "rp_id must end with '.local': {id}");
        // Total format: "sshenc-" (7) + 8 hex chars + ".local" (6) = 21
        assert_eq!(id.len(), 21, "rp_id must be 21 chars: {id}");
    }

    #[test]
    fn extract_sk_fields_errors_on_non_sk() {
        let label = KeyLabel::new("test").unwrap();
        let meta = KeyMetadata::new(label, AccessPolicy::None, None);
        assert!(extract_sk_fields(&meta).is_err());
    }
}
