// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Windows TPM 2.0 operations via CNG (NCrypt API).
//!
//! ## CNG APIs Used
//!
//! - `NCryptOpenStorageProvider` — Open the Microsoft Platform Crypto Provider (TPM).
//! - `NCryptCreatePersistedKey` — Generate a new ECDSA P-256 key in the TPM.
//! - `NCryptFinalizeKey` — Persist the key to the TPM.
//! - `NCryptSignHash` — Sign a SHA-256 digest using a TPM-backed key.
//! - `NCryptExportKey` — Export the public key (ECCPUBLIC_BLOB format).
//! - `NCryptEnumKeys` — List keys by name prefix.
//! - `NCryptOpenKey` — Open an existing key by name.
//! - `NCryptDeleteKey` — Delete a key from the TPM.
//!
//! ## Key naming
//!
//! All sshenc-managed keys use the name prefix `sshenc-` followed by the label.
//! CNG persists keys in the TPM's key hierarchy — no files needed for key storage.
//! Only metadata (.meta), cached public keys (.pub, .ssh.pub) are stored on disk
//! in `%APPDATA%\sshenc\keys\`.

use sha2::{Digest, Sha256};
use std::path::PathBuf;
use thiserror::Error;
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Security::Cryptography::*;

/// Key name prefix for sshenc-managed TPM keys.
const KEY_PREFIX: &str = "sshenc-";

/// The CNG provider name for TPM-backed keys.
const PLATFORM_PROVIDER: &str = "Microsoft Platform Crypto Provider";

#[derive(Debug, Error)]
pub enum TpmError {
    #[error("TPM not available")]
    NotAvailable,
    #[error("key generation failed: {0}")]
    GenerateFailed(String),
    #[error("key not found: {0}")]
    KeyNotFound(String),
    #[error("signing failed: {0}")]
    SignFailed(String),
    #[error("key export failed: {0}")]
    ExportFailed(String),
    #[error("key deletion failed: {0}")]
    DeleteFailed(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, TpmError>;

/// Authentication policy for signing operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthPolicy {
    /// No authentication required.
    None = 0,
    /// Windows Hello (PIN, biometric, or security key).
    Any = 1,
    /// Biometric only (fingerprint, face).
    Biometric = 2,
    /// PIN only.
    Pin = 3,
}

/// RAII wrapper for NCrypt handles.
struct NcryptHandle(NCRYPT_HANDLE);

impl Drop for NcryptHandle {
    fn drop(&mut self) {
        if self.0 .0 != 0 {
            unsafe {
                NCryptFreeObject(self.0);
            }
        }
    }
}

impl NcryptHandle {
    fn as_prov(&self) -> NCRYPT_PROV_HANDLE {
        NCRYPT_PROV_HANDLE(self.0 .0)
    }

    fn as_key(&self) -> NCRYPT_KEY_HANDLE {
        NCRYPT_KEY_HANDLE(self.0 .0)
    }
}

/// Open the TPM storage provider.
fn open_provider() -> Result<NcryptHandle> {
    let provider_name = HSTRING::from(PLATFORM_PROVIDER);
    let mut handle = NCRYPT_PROV_HANDLE::default();
    let status =
        unsafe { NCryptOpenStorageProvider(&mut handle, PCWSTR(provider_name.as_ptr()), 0) };
    if status.is_err() {
        return Err(TpmError::NotAvailable);
    }
    Ok(NcryptHandle(NCRYPT_HANDLE(handle.0)))
}

/// Full CNG key name for a label.
fn key_name(label: &str) -> HSTRING {
    HSTRING::from(format!("{KEY_PREFIX}{label}"))
}

/// Check if the TPM is available.
pub fn is_available() -> bool {
    open_provider().is_ok()
}

/// Directory where metadata and cached public keys are stored.
pub fn keys_dir() -> PathBuf {
    dirs::data_dir()
        .or_else(dirs::home_dir)
        .unwrap_or_else(|| {
            eprintln!("warning: could not determine app data directory, using temp");
            std::env::temp_dir()
        })
        .join("sshenc")
        .join("keys")
}

/// Key metadata stored alongside TPM keys.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KeyMeta {
    pub label: String,
    pub comment: Option<String>,
    pub auth_policy: i32,
    pub created: String,
    #[serde(default)]
    pub git_name: Option<String>,
    #[serde(default)]
    pub git_email: Option<String>,
}

/// Generate a new TPM-backed ECDSA P-256 key.
/// Returns the 65-byte uncompressed public key (0x04 || X || Y).
pub fn generate(label: &str, auth_policy: AuthPolicy) -> Result<Vec<u8>> {
    let provider = open_provider()?;
    let name = key_name(label);
    let algo = HSTRING::from("ECDSA_P256");

    let mut key_handle = NCRYPT_KEY_HANDLE::default();
    let status = unsafe {
        NCryptCreatePersistedKey(
            provider.as_prov(),
            &mut key_handle,
            PCWSTR(algo.as_ptr()),
            PCWSTR(name.as_ptr()),
            CERT_KEY_SPEC::default(),
            NCRYPT_FLAGS::default(),
        )
    };
    if status.is_err() {
        return Err(TpmError::GenerateFailed(format!(
            "NCryptCreatePersistedKey: {status:?}"
        )));
    }
    let key = NcryptHandle(NCRYPT_HANDLE(key_handle.0));

    // Set UI policy for Windows Hello if requested
    if auth_policy != AuthPolicy::None {
        set_ui_policy(key.as_key(), auth_policy)?;
    }

    // Finalize (persist to TPM)
    let status = unsafe { NCryptFinalizeKey(key.as_key(), NCRYPT_FLAGS::default()) };
    if status.is_err() {
        return Err(TpmError::GenerateFailed(format!(
            "NCryptFinalizeKey: {status:?}"
        )));
    }

    // Export public key
    export_public_key(key.as_key())
}

/// Set Windows Hello UI policy on a key.
fn set_ui_policy(key: NCRYPT_KEY_HANDLE, _policy: AuthPolicy) -> Result<()> {
    // NCRYPT_UI_POLICY structure: version=1, flags based on policy
    // For now, set NCRYPT_UI_PROTECT_KEY_FLAG to require user consent
    let policy = NCRYPT_UI_POLICY {
        dwVersion: 1,
        dwFlags: NCRYPT_UI_PROTECT_KEY_FLAG,
        pszCreationTitle: PCWSTR::null(),
        pszFriendlyName: PCWSTR::null(),
        pszDescription: PCWSTR::null(),
    };
    let prop_name = HSTRING::from("UI Policy");
    let status = unsafe {
        NCryptSetProperty(
            NCRYPT_HANDLE(key.0),
            PCWSTR(prop_name.as_ptr()),
            std::slice::from_raw_parts(
                &policy as *const _ as *const u8,
                std::mem::size_of::<NCRYPT_UI_POLICY>(),
            ),
            NCRYPT_FLAGS::default(),
        )
    };
    if status.is_err() {
        // Non-fatal — Windows Hello may not be configured
        eprintln!("warning: could not set UI policy (Windows Hello may not be available)");
    }
    Ok(())
}

/// Export the public key from a key handle as 65-byte uncompressed SEC1 point.
fn export_public_key(key: NCRYPT_KEY_HANDLE) -> Result<Vec<u8>> {
    let blob_type = HSTRING::from("ECCPUBLICBLOB");
    let mut blob_size: u32 = 0;

    // Query size
    let status = unsafe {
        NCryptExportKey(
            key,
            NCRYPT_KEY_HANDLE::default(),
            PCWSTR(blob_type.as_ptr()),
            None,
            None,
            &mut blob_size,
            NCRYPT_FLAGS::default(),
        )
    };
    if status.is_err() {
        return Err(TpmError::ExportFailed(format!(
            "NCryptExportKey size query: {status:?}"
        )));
    }

    // Export
    let mut blob = vec![0u8; blob_size as usize];
    let status = unsafe {
        NCryptExportKey(
            key,
            NCRYPT_KEY_HANDLE::default(),
            PCWSTR(blob_type.as_ptr()),
            None,
            Some(&mut blob),
            &mut blob_size,
            NCRYPT_FLAGS::default(),
        )
    };
    if status.is_err() {
        return Err(TpmError::ExportFailed(format!(
            "NCryptExportKey: {status:?}"
        )));
    }
    blob.truncate(blob_size as usize);

    // Parse BCRYPT_ECCKEY_BLOB: { magic: u32, cbKey: u32, X: [u8; cbKey], Y: [u8; cbKey] }
    if blob.len() < 8 {
        return Err(TpmError::ExportFailed("blob too short".into()));
    }
    let cb_key = u32::from_le_bytes([blob[4], blob[5], blob[6], blob[7]]) as usize;
    if blob.len() < 8 + cb_key * 2 {
        return Err(TpmError::ExportFailed("blob truncated".into()));
    }

    // Build uncompressed SEC1 point: 0x04 || X || Y
    let mut point = Vec::with_capacity(1 + cb_key * 2);
    point.push(0x04);
    point.extend_from_slice(&blob[8..8 + cb_key]);
    point.extend_from_slice(&blob[8 + cb_key..8 + cb_key * 2]);

    if point.len() != 65 {
        return Err(TpmError::ExportFailed(format!(
            "unexpected point size: {} (expected 65)",
            point.len()
        )));
    }

    Ok(point)
}

/// Get the public key for an existing key by label.
pub fn public_key(label: &str) -> Result<Vec<u8>> {
    let provider = open_provider()?;
    let name = key_name(label);
    let mut key_handle = NCRYPT_KEY_HANDLE::default();

    let status = unsafe {
        NCryptOpenKey(
            provider.as_prov(),
            &mut key_handle,
            PCWSTR(name.as_ptr()),
            CERT_KEY_SPEC::default(),
            NCRYPT_FLAGS::default(),
        )
    };
    if status.is_err() {
        return Err(TpmError::KeyNotFound(label.to_string()));
    }
    let key = NcryptHandle(NCRYPT_HANDLE(key_handle.0));
    export_public_key(key.as_key())
}

/// Sign data using a TPM-backed key.
/// Hashes the message with SHA-256, then calls NCryptSignHash.
/// Returns a DER-encoded ECDSA signature.
pub fn sign(label: &str, message: &[u8]) -> Result<Vec<u8>> {
    let provider = open_provider()?;
    let name = key_name(label);
    let mut key_handle = NCRYPT_KEY_HANDLE::default();

    let status = unsafe {
        NCryptOpenKey(
            provider.as_prov(),
            &mut key_handle,
            PCWSTR(name.as_ptr()),
            CERT_KEY_SPEC::default(),
            NCRYPT_FLAGS::default(),
        )
    };
    if status.is_err() {
        return Err(TpmError::KeyNotFound(label.to_string()));
    }
    let key = NcryptHandle(NCRYPT_HANDLE(key_handle.0));

    // Hash the message with SHA-256
    let digest = Sha256::digest(message);

    // Sign the digest
    let mut sig_size: u32 = 0;

    // Query signature size
    let status = unsafe {
        NCryptSignHash(
            key.as_key(),
            None,
            &digest,
            None,
            &mut sig_size,
            NCRYPT_FLAGS::default(),
        )
    };
    if status.is_err() {
        return Err(TpmError::SignFailed(format!(
            "NCryptSignHash size query: {status:?}"
        )));
    }

    // Sign
    let mut sig = vec![0u8; sig_size as usize];
    let status = unsafe {
        NCryptSignHash(
            key.as_key(),
            None,
            &digest,
            Some(&mut sig),
            &mut sig_size,
            NCRYPT_FLAGS::default(),
        )
    };
    if status.is_err() {
        return Err(TpmError::SignFailed(format!("NCryptSignHash: {status:?}")));
    }
    sig.truncate(sig_size as usize);

    // Convert P1363 (r || s) to DER
    Ok(p1363_to_der(&sig))
}

/// List all sshenc-managed key labels.
pub fn list_keys() -> Result<Vec<String>> {
    let provider = open_provider()?;
    let mut labels = Vec::new();
    let mut enum_state: *mut NCryptKeyName = std::ptr::null_mut();

    loop {
        let result = unsafe {
            NCryptEnumKeys(
                provider.as_prov(),
                PCWSTR::null(),
                &mut enum_state,
                std::ptr::null_mut(),
                NCRYPT_FLAGS::default(),
            )
        };

        if result.is_err() {
            // NTE_NO_MORE_ITEMS or any other error ends enumeration
            break;
        }

        if !enum_state.is_null() {
            let key_info = unsafe { &*enum_state };
            let name = unsafe { key_info.pszName.to_string() };
            if let Ok(name_str) = name {
                if name_str.starts_with(KEY_PREFIX) {
                    labels.push(name_str[KEY_PREFIX.len()..].to_string());
                }
            }
            unsafe {
                NCryptFreeBuffer(enum_state as *mut _);
            }
        }
    }

    labels.sort();
    Ok(labels)
}

/// Delete a key from the TPM.
pub fn delete_key(label: &str) -> Result<()> {
    let provider = open_provider()?;
    let name = key_name(label);
    let mut key_handle = NCRYPT_KEY_HANDLE::default();

    let status = unsafe {
        NCryptOpenKey(
            provider.as_prov(),
            &mut key_handle,
            PCWSTR(name.as_ptr()),
            CERT_KEY_SPEC::default(),
            NCRYPT_FLAGS::default(),
        )
    };
    if status.is_err() {
        return Err(TpmError::KeyNotFound(label.to_string()));
    }

    let status = unsafe { NCryptDeleteKey(NCRYPT_KEY_HANDLE(key_handle.0), 0) };
    if status.is_err() {
        return Err(TpmError::DeleteFailed(format!(
            "NCryptDeleteKey: {status:?}"
        )));
    }

    // Also remove metadata files
    let dir = keys_dir();
    let _ = std::fs::remove_file(dir.join(format!("{label}.pub")));
    let _ = std::fs::remove_file(dir.join(format!("{label}.ssh.pub")));
    let _ = std::fs::remove_file(dir.join(format!("{label}.meta")));

    Ok(())
}

/// Save metadata and cached public key files.
pub fn save_key(label: &str, pub_key: &[u8], meta: &KeyMeta) -> Result<()> {
    let dir = keys_dir();
    std::fs::create_dir_all(&dir)?;

    let pub_path = dir.join(format!("{label}.pub"));
    let ssh_pub_path = dir.join(format!("{label}.ssh.pub"));
    let meta_path = dir.join(format!("{label}.meta"));

    // Atomic writes
    atomic_write(&pub_path, pub_key)?;
    let ssh_line = format_ssh_pub_key(pub_key, label);
    atomic_write(&ssh_pub_path, format!("{ssh_line}\n").as_bytes())?;
    let meta_json =
        serde_json::to_string_pretty(meta).map_err(|e| TpmError::Io(std::io::Error::other(e)))?;
    atomic_write(&meta_path, meta_json.as_bytes())?;

    Ok(())
}

/// Load key metadata.
pub fn load_meta(label: &str) -> Result<KeyMeta> {
    let path = keys_dir().join(format!("{label}.meta"));
    if !path.exists() {
        return Ok(KeyMeta {
            label: label.to_string(),
            comment: None,
            auth_policy: 0,
            created: String::new(),
        });
    }
    let content = std::fs::read_to_string(&path)?;
    serde_json::from_str(&content).map_err(|e| {
        TpmError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("corrupted metadata for {label}: {e}"),
        ))
    })
}

/// Load cached public key bytes.
pub fn load_pub_key(label: &str) -> Result<Vec<u8>> {
    let path = keys_dir().join(format!("{label}.pub"));
    if !path.exists() {
        return public_key(label);
    }
    Ok(std::fs::read(&path)?)
}

/// Get the SSH-formatted public key file path.
pub fn ssh_pub_path(label: &str) -> PathBuf {
    keys_dir().join(format!("{label}.ssh.pub"))
}

/// Write an SSH-formatted public key file.
pub fn save_ssh_pub_key(label: &str, pub_key: &[u8]) -> Result<()> {
    let dir = keys_dir();
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{label}.ssh.pub"));
    let line = format_ssh_pub_key(pub_key, label);
    std::fs::write(&path, format!("{line}\n"))?;
    Ok(())
}

// ─── Helpers ─────────────────────────────────────────────────────

/// Convert IEEE P1363 signature (r || s, 64 bytes) to DER SEQUENCE.
fn p1363_to_der(sig: &[u8]) -> Vec<u8> {
    assert!(sig.len() == 64, "P1363 signature must be 64 bytes");
    let r = &sig[0..32];
    let s = &sig[32..64];

    let r_der = int_to_der(r);
    let s_der = int_to_der(s);

    let inner_len = r_der.len() + s_der.len();
    let mut der = Vec::with_capacity(2 + inner_len);
    der.push(0x30); // SEQUENCE
    der.push(inner_len as u8);
    der.extend_from_slice(&r_der);
    der.extend_from_slice(&s_der);
    der
}

/// Encode a big-endian unsigned integer as DER INTEGER.
fn int_to_der(val: &[u8]) -> Vec<u8> {
    // Strip leading zeros
    let mut start = 0;
    while start < val.len() - 1 && val[start] == 0 {
        start += 1;
    }
    let stripped = &val[start..];

    // If high bit set, prepend 0x00 (positive integer)
    let needs_pad = stripped[0] & 0x80 != 0;
    let len = stripped.len() + if needs_pad { 1 } else { 0 };

    let mut der = Vec::with_capacity(2 + len);
    der.push(0x02); // INTEGER
    der.push(len as u8);
    if needs_pad {
        der.push(0x00);
    }
    der.extend_from_slice(stripped);
    der
}

/// Write data atomically: write to temp, then rename.
fn atomic_write(path: &std::path::Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(TpmError::Io(e));
    }
    Ok(())
}

/// Format raw EC point bytes as an SSH public key line.
fn format_ssh_pub_key(pub_key: &[u8], comment: &str) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    let mut blob = Vec::new();
    write_ssh_string(&mut blob, b"ecdsa-sha2-nistp256");
    write_ssh_string(&mut blob, b"nistp256");
    write_ssh_string(&mut blob, pub_key);

    let encoded = STANDARD.encode(&blob);
    format!("ecdsa-sha2-nistp256 {encoded} {comment}")
}

fn write_ssh_string(buf: &mut Vec<u8>, data: &[u8]) {
    // Writing to Vec cannot fail
    let len = (data.len() as u32).to_be_bytes();
    buf.extend_from_slice(&len);
    buf.extend_from_slice(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p1363_to_der_simple() {
        let mut sig = vec![0u8; 64];
        sig[31] = 1; // r = 1
        sig[63] = 2; // s = 2
        let der = p1363_to_der(&sig);
        assert_eq!(der[0], 0x30); // SEQUENCE
        assert_eq!(der[2], 0x02); // INTEGER (r)
        assert_eq!(der[4], 1); // r = 1
        assert_eq!(der[5], 0x02); // INTEGER (s)
        assert_eq!(der[7], 2); // s = 2
    }

    #[test]
    fn test_p1363_to_der_high_bit() {
        let mut sig = vec![0u8; 64];
        sig[0] = 0x80; // r has high bit set
        sig[31] = 1;
        sig[32] = 0x80; // s has high bit set
        sig[63] = 2;
        let der = p1363_to_der(&sig);
        // r should have 0x00 prefix
        assert_eq!(der[2], 0x02); // INTEGER
        assert_eq!(der[4], 0x00); // padding
        assert_eq!(der[5], 0x80); // actual r byte
    }

    #[test]
    fn test_int_to_der() {
        // Simple case
        assert_eq!(int_to_der(&[0, 0, 1]), vec![0x02, 0x01, 0x01]);
        // High bit needs padding
        assert_eq!(int_to_der(&[0x80]), vec![0x02, 0x02, 0x00, 0x80]);
        // Zero
        assert_eq!(int_to_der(&[0]), vec![0x02, 0x01, 0x00]);
    }

    #[test]
    fn test_format_ssh_pub_key() {
        let mut point = vec![0x04];
        point.extend_from_slice(&[1u8; 32]);
        point.extend_from_slice(&[2u8; 32]);
        let line = format_ssh_pub_key(&point, "test@host");
        assert!(line.starts_with("ecdsa-sha2-nistp256 "));
        assert!(line.ends_with(" test@host"));
    }

    #[test]
    fn test_keys_dir() {
        let dir = keys_dir();
        let dir_str = dir.to_string_lossy();
        assert!(dir_str.contains("sshenc"));
        assert!(dir_str.contains("keys"));
    }
}
