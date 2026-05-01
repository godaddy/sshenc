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
//!
//! ## Two-backend dispatch (native vs bridge)
//!
//! On Windows, this module calls `enclaveapp_windows_webauthn`
//! directly -- the wrapper crate links against `webauthn.dll`.
//!
//! On Linux (specifically WSL) the local wrapper is a no-op stub,
//! so we instead probe `enclaveapp_bridge::find_bridge("sshenc")`
//! for `sshenc-tpm-bridge.exe` on the mounted Windows filesystem
//! and call `bridge_webauthn_*` helpers that forward to
//! `webauthn.dll` on the Windows side via JSON-RPC over the
//! bridge process's stdio. Same hardware-enforced gate, same
//! `sk-ecdsa-sha2-nistp256@openssh.com` wire format, same Hello
//! prompt -- it just fires on the Windows desktop where the user
//! sees it. The SSH key lives in WSL `~/.ssh/<label>.pub`; the
//! TPM-bound private key never crosses the boundary.

#![cfg(feature = "webauthn-sk")]

use enclaveapp_windows_webauthn::{
    delete_platform_credential as platform_delete, get_assertion, make_credential,
    GetAssertionParams, MakeCredentialParams, WebAuthnError,
};
// `is_platform_authenticator_available` is only called from the
// Windows branch of `detect_backend`; on other targets the bridge
// probe takes over, and pulling the symbol in unconditionally
// triggers an unused-import lint failure.
#[cfg(target_os = "windows")]
use enclaveapp_windows_webauthn::is_platform_authenticator_available;
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

/// Internal: which WebAuthn backend services this process. Native
/// on Windows; bridge-routed elsewhere when a `sshenc-tpm-bridge`
/// binary is reachable. `None` means SK keys aren't usable on
/// this host.
#[allow(dead_code)] // Bridge is unreachable on Windows; live on other OSes.
enum SkBackend {
    Native,
    Bridge(PathBuf),
}

/// Detect the active SK backend. Cheap to call repeatedly -- the
/// bridge probe is a stdin/stdout JSON-RPC roundtrip, not a Hello
/// prompt; only triggered on non-Windows when a bridge binary is
/// found. Returns `None` if neither path is available.
fn detect_backend() -> Option<SkBackend> {
    #[cfg(target_os = "windows")]
    {
        if is_platform_authenticator_available() {
            return Some(SkBackend::Native);
        }
        None
    }
    #[cfg(not(target_os = "windows"))]
    {
        let bridge = enclaveapp_bridge::find_bridge("sshenc")?;
        match enclaveapp_bridge::bridge_webauthn_is_available(&bridge) {
            Ok(true) => Some(SkBackend::Bridge(bridge)),
            _ => None,
        }
    }
}

/// True if SK keys are usable on this host. On Windows this is
/// the local `WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable`
/// probe. On WSL it's a JSON-RPC roundtrip to the Windows-side
/// bridge that performs the same probe. Returns `false` on hosts
/// with neither path (e.g. macOS, Linux without the bridge).
pub fn is_available() -> bool {
    detect_backend().is_some()
}

/// Create a new SK key for `label`. Triggers a Hello-enrollment
/// prompt (on the Windows desktop, whether the caller is on
/// Windows or in WSL); the resulting credential is sealed by the
/// TPM and recorded as a passkey under our per-key RP id.
pub fn generate(opts: &SkKeyGenOptions) -> Result<KeyInfo> {
    let label_str = opts.label.as_str();
    let rp_id = rp_id_for_label(label_str);
    let user_id = user_id_for_label(label_str);

    let backend = detect_backend()
        .ok_or_else(|| Error::Other("SK backend not available (no Hello, no bridge)".into()))?;

    // Yields (credential_id, public_key_x: [u8;32], public_key_y: [u8;32]).
    let (credential_id, public_key_x, public_key_y) = match backend {
        SkBackend::Native => {
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
            (cred.credential_id, cred.public_key_x, cred.public_key_y)
        }
        SkBackend::Bridge(path) => {
            let result = enclaveapp_bridge::bridge_webauthn_make_credential(
                &path, &rp_id, "sshenc", &user_id, label_str, label_str, 60_000,
            )
            .map_err(|e| Error::Other(format!("bridge make_credential: {e}")))?;
            let credential_id = base64_decode(&result.credential_id_b64)?;
            let public_key_x = hex_decode_32(&result.public_key_x_hex)?;
            let public_key_y = hex_decode_32(&result.public_key_y_hex)?;
            (credential_id, public_key_x, public_key_y)
        }
    };

    let ssh_pubkey = SshSkPublicKey::from_xy(
        &public_key_x,
        &public_key_y,
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
        credential_id.clone(),
        rp_id,
    );

    // Note: SEC1 uncompressed point is what existing code stores
    // for legacy keys; SK keys reuse the same field for parity
    // (callers can still address by fingerprint or label without
    // needing to know which algorithm is in play).
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&public_key_x);
    sec1.extend_from_slice(&public_key_y);

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
    let backend = detect_backend()
        .ok_or_else(|| Error::Other("SK backend not available for delete".into()))?;
    match backend {
        SkBackend::Native => platform_delete(credential_id).map_err(map_webauthn_error),
        SkBackend::Bridge(path) => {
            enclaveapp_bridge::bridge_webauthn_delete_platform_credential(&path, credential_id)
                .map_err(|e| Error::Other(format!("bridge delete_platform_credential: {e}")))
        }
    }
}

/// Sign `data` with an SK key. `credential_id` and `rp_id` come
/// from the persisted metadata for the key. Returns a fully-formed
/// SK signature blob (the wire bytes that go inside the SSH agent
/// `SIGN_RESPONSE` envelope). Hello prompt fires on the Windows
/// desktop whether the caller is on Windows or in WSL.
pub fn sign(credential_id: &[u8], rp_id: &str, data: &[u8]) -> Result<Vec<u8>> {
    let backend =
        detect_backend().ok_or_else(|| Error::Other("SK backend not available for sign".into()))?;
    let (signature_der, flags, counter) = match backend {
        SkBackend::Native => {
            let asn = get_assertion(GetAssertionParams {
                rp_id,
                credential_id,
                client_data: data,
                timeout_ms: 60_000,
                hwnd: None,
            })
            .map_err(map_webauthn_error)?;
            (asn.signature_der, asn.flags, asn.counter)
        }
        SkBackend::Bridge(path) => {
            let result = enclaveapp_bridge::bridge_webauthn_get_assertion(
                &path,
                rp_id,
                credential_id,
                data,
                60_000,
            )
            .map_err(|e| Error::Other(format!("bridge get_assertion: {e}")))?;
            let signature_der = base64_decode(&result.signature_der_b64)?;
            (signature_der, result.flags, result.counter)
        }
    };
    encode_sk_signature_blob(&signature_der, flags, counter)
}

fn base64_decode(s: &str) -> Result<Vec<u8>> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    STANDARD.decode(s).map_err(Error::Base64)
}

fn hex_decode_32(s: &str) -> Result<[u8; 32]> {
    if s.len() != 64 {
        return Err(Error::Other(format!(
            "hex pubkey coordinate has wrong length: {}",
            s.len()
        )));
    }
    let mut out = [0_u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|e| Error::Other(format!("hex decode at byte {i}: {e}")))?;
    }
    Ok(out)
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
