// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! FIDO2 / WebAuthn-backed SK key operations.
//!
//! Wraps `enclaveapp-windows-webauthn` to keygen and sign with
//! `sk-ecdsa-sha2-nistp256@openssh.com` keys whose private material
//! lives inside the Windows TPM. Compiled in only when the
//! `webauthn-sk` feature is enabled.
//!
//! ## Why this is a separate module
//!
//! The legacy `SshencBackend` path -- TPM via NCrypt + UserConsentVerifier
//! -- stays in `unified.rs` byte-for-byte. SK keygen and sign live
//! here so reviewing the WebAuthn diff is a self-contained read,
//! and so non-Windows or feature-disabled builds never compile any
//! WebAuthn code at all.
//!
//! ## RP ID per key
//!
//! Win11 26200+ silently upgrades platform-authenticator
//! credentials to discoverable / passkey-style, and Windows shows
//! a "choose passkey" interstitial at sign time enumerating every
//! discoverable credential under the requested RP ID. We can't
//! suppress the interstitial via API, so we limit its scope: each
//! sshenc key gets a deterministic-from-label *unique* RP ID
//! (`sshenc-<hex>.local`). The chooser then only ever sees the one
//! credential we care about and degenerates to a confirmation step
//! before the auth gesture.

#![cfg(feature = "webauthn-sk")]

use enclaveapp_windows_webauthn::{
    delete_platform_credential as platform_delete, get_assertion,
    is_platform_authenticator_available, make_credential, GetAssertionParams, MakeCredentialParams,
    WebAuthnError,
};
use sha2::{Digest, Sha256};
use sshenc_core::error::{Error, Result};
use sshenc_core::fingerprint;
use sshenc_core::key::{KeyAlgorithm, KeyInfo, KeyMetadata, SkKeyGenOptions};
use sshenc_core::pubkey::{encode_sk_signature_blob, SshSkPublicKey};
use std::path::PathBuf;

/// Construct the deterministic per-key RP ID from a sshenc label.
/// Looks like `sshenc-<8-hex>.local`. The hex is the first 4 bytes
/// of `SHA-256(label)`, so two distinct labels almost certainly map
/// to distinct RPs (collision probability ~2^-32). The form is
/// stable -- recreating a key with the same label produces the
/// same RP, which lets `sshenc rebind` operations deterministically
/// land on the prior credential's slot.
pub fn rp_id_for_label(label: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"sshenc-rp-id-v1\x00");
    hasher.update(label.as_bytes());
    let digest = hasher.finalize();
    let hex: String = digest
        .iter()
        .take(4)
        .map(|b| format!("{:02x}", b))
        .collect();
    format!("sshenc-{hex}.local")
}

/// Per-key user identifier the platform authenticator scopes the
/// credential under. We hash the label so an attacker who can
/// enumerate the user's passkeys can't read the raw label out of
/// the user.id field; the display name (the human label) shows up
/// in the chooser regardless, so this is just defense-in-depth.
fn user_id_for_label(label: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"sshenc-user-id-v1\x00");
    hasher.update(label.as_bytes());
    hasher.finalize().to_vec()
}

/// True if the platform authenticator is reachable on this host
/// (Hello enrolled, WebAuthN.dll loadable). On non-Windows this is
/// always false (the wrapper crate's stub).
pub fn is_available() -> bool {
    is_platform_authenticator_available()
}

/// Create a new SK key for `label`. Triggers a Hello-enrollment
/// prompt; the resulting credential is sealed by the TPM and
/// recorded as a passkey under our per-key RP id.
pub fn generate(opts: &SkKeyGenOptions) -> Result<KeyInfo> {
    let label_str = opts.label.as_str();
    let rp_id = rp_id_for_label(label_str);
    let user_id = user_id_for_label(label_str);

    let cred = make_credential(MakeCredentialParams {
        rp_id: &rp_id,
        rp_name: "sshenc",
        user_id: &user_id,
        user_name: label_str,
        user_display_name: label_str,
        timeout_ms: 60_000,
        hwnd: None,
    })
    .map_err(map_webauthn_error)?;

    let ssh_pubkey = SshSkPublicKey::from_xy(
        &cred.public_key_x,
        &cred.public_key_y,
        rp_id.clone(),
        opts.comment.clone(),
    );
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

    // The on-disk metadata flavour stored alongside the public key.
    let metadata = KeyMetadata::for_sk(
        opts.label.clone(),
        enclaveapp_core::types::AccessPolicy::Any,
        Some(enclaveapp_core::types::PresenceMode::Strict),
        opts.comment.clone(),
        cred.credential_id.clone(),
        rp_id,
    );

    // Note: SEC1 uncompressed point is what existing code stores
    // for legacy keys; SK keys reuse the same field for parity
    // (callers can still address by fingerprint or label without
    // needing to know which algorithm is in play).
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&cred.public_key_x);
    sec1.extend_from_slice(&cred.public_key_y);

    Ok(KeyInfo {
        metadata,
        public_key_bytes: sec1,
        fingerprint_sha256: fp_sha256,
        fingerprint_md5: fp_md5,
        pub_file_path,
    })
}

/// Best-effort removal of a platform credential from the user's
/// passkey list. The TPM-bound key material is unrecoverable after
/// this returns Ok; callers must have already deleted any
/// reference to the credential id from their own metadata.
pub fn delete_platform_credential(credential_id: &[u8]) -> Result<()> {
    platform_delete(credential_id).map_err(map_webauthn_error)
}

/// Sign `data` with an SK key. `credential_id` and `rp_id` come
/// from the persisted metadata for the key. Returns a fully-formed
/// SK signature blob (the wire bytes that go inside the SSH agent
/// `SIGN_RESPONSE` envelope).
pub fn sign(credential_id: &[u8], rp_id: &str, data: &[u8]) -> Result<Vec<u8>> {
    let asn = get_assertion(GetAssertionParams {
        rp_id,
        credential_id,
        client_data: data,
        timeout_ms: 60_000,
        hwnd: None,
    })
    .map_err(map_webauthn_error)?;

    encode_sk_signature_blob(&asn.signature_der, asn.flags, asn.counter)
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

/// Reconstruct an `SshSkPublicKey` from a `KeyInfo`. The SK
/// metadata holds the application/rp-id; the SEC1 point comes from
/// `public_key_bytes`. Returns `Err` if the key isn't actually an
/// SK key.
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

fn map_webauthn_error(e: WebAuthnError) -> Error {
    match e {
        WebAuthnError::NotAvailable => Error::Other(
            "Windows Hello platform authenticator is not available -- enroll Hello first".into(),
        ),
        WebAuthnError::UserCanceled => Error::Cancelled,
        WebAuthnError::Timeout => Error::Other("Windows Hello prompt timed out".into()),
        WebAuthnError::Backend { hr, name } => {
            Error::Other(format!("WebAuthn API error {name} (hr=0x{hr:08x})"))
        }
        WebAuthnError::InvalidResponse(msg) => {
            Error::Other(format!("WebAuthn API returned invalid response: {msg}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rp_id_is_stable_across_calls() {
        let a = rp_id_for_label("foo");
        let b = rp_id_for_label("foo");
        assert_eq!(a, b);
    }

    #[test]
    fn rp_id_differs_per_label() {
        let a = rp_id_for_label("foo");
        let b = rp_id_for_label("bar");
        assert_ne!(a, b);
    }

    #[test]
    fn rp_id_format_looks_like_a_domain() {
        let id = rp_id_for_label("github-personal");
        assert!(id.starts_with("sshenc-"));
        assert!(id.ends_with(".local"));
        // 8 hex chars between
        let middle = &id["sshenc-".len()..id.len() - ".local".len()];
        assert_eq!(middle.len(), 8);
        assert!(middle.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn user_id_is_32_bytes() {
        let id = user_id_for_label("anything");
        assert_eq!(id.len(), 32);
    }
}
