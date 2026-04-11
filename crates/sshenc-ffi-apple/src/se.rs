// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Rust FFI bindings to the CryptoKit Swift bridge.
//!
//! Keys are stored as files in `~/.sshenc/keys/<label>.key` containing the
//! CryptoKit `dataRepresentation`. A companion `<label>.pub` in the same
//! directory caches the uncompressed public key bytes for fast enumeration.

use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SeError {
    #[error("Secure Enclave not available")]
    NotAvailable,
    #[error("key generation failed")]
    GenerateFailed,
    #[error("failed to load key: {0}")]
    LoadFailed(String),
    #[error("signing failed")]
    SignFailed,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, SeError>;

// FFI declarations for the Swift bridge
extern "C" {
    fn sshenc_se_available() -> i32;
    fn sshenc_se_generate(
        pub_key_out: *mut u8,
        pub_key_len: *mut i32,
        data_rep_out: *mut u8,
        data_rep_len: *mut i32,
    ) -> i32;
    fn sshenc_se_public_key(
        data_rep: *const u8,
        data_rep_len: i32,
        pub_key_out: *mut u8,
        pub_key_len: *mut i32,
    ) -> i32;
    fn sshenc_se_sign(
        data_rep: *const u8,
        data_rep_len: i32,
        message: *const u8,
        message_len: i32,
        sig_out: *mut u8,
        sig_len: *mut i32,
    ) -> i32;
}

/// Check if the Secure Enclave is available.
pub fn is_available() -> bool {
    unsafe { sshenc_se_available() == 1 }
}

/// Directory where SE key data representations are stored.
pub fn keys_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".sshenc")
        .join("keys")
}

/// Generate a new Secure Enclave P-256 key.
/// Returns (uncompressed_public_key_65_bytes, data_representation).
pub fn generate() -> Result<(Vec<u8>, Vec<u8>)> {
    if !is_available() {
        return Err(SeError::NotAvailable);
    }

    let mut pub_key = vec![0u8; 65];
    let mut pub_key_len: i32 = 65;
    let mut data_rep = vec![0u8; 512];
    let mut data_rep_len: i32 = 512;

    let rc = unsafe {
        sshenc_se_generate(
            pub_key.as_mut_ptr(),
            &mut pub_key_len,
            data_rep.as_mut_ptr(),
            &mut data_rep_len,
        )
    };

    if rc != 0 {
        return Err(SeError::GenerateFailed);
    }

    pub_key.truncate(pub_key_len as usize);
    data_rep.truncate(data_rep_len as usize);
    Ok((pub_key, data_rep))
}

/// Extract the public key from a persisted data representation.
/// Returns 65-byte uncompressed public key.
pub fn public_key_from_data_rep(data_rep: &[u8]) -> Result<Vec<u8>> {
    let mut pub_key = vec![0u8; 65];
    let mut pub_key_len: i32 = 65;

    let rc = unsafe {
        sshenc_se_public_key(
            data_rep.as_ptr(),
            data_rep.len() as i32,
            pub_key.as_mut_ptr(),
            &mut pub_key_len,
        )
    };

    if rc != 0 {
        return Err(SeError::LoadFailed("invalid data representation".into()));
    }

    pub_key.truncate(pub_key_len as usize);
    Ok(pub_key)
}

/// Sign data using a key from its data representation.
/// Returns DER-encoded ECDSA signature.
pub fn sign(data_rep: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    let mut sig = vec![0u8; 128]; // DER ECDSA P-256 sig is at most ~72 bytes
    let mut sig_len: i32 = 128;

    let rc = unsafe {
        sshenc_se_sign(
            data_rep.as_ptr(),
            data_rep.len() as i32,
            message.as_ptr(),
            message.len() as i32,
            sig.as_mut_ptr(),
            &mut sig_len,
        )
    };

    if rc != 0 {
        return Err(SeError::SignFailed);
    }

    sig.truncate(sig_len as usize);
    Ok(sig)
}

/// Save a key's data representation and public key to the keys directory.
pub fn save_key(label: &str, data_rep: &[u8], pub_key: &[u8]) -> Result<()> {
    let dir = keys_dir();
    std::fs::create_dir_all(&dir)?;

    // Restrictive permissions on the keys directory
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }

    let key_path = dir.join(format!("{label}.key"));
    let pub_path = dir.join(format!("{label}.pub"));

    std::fs::write(&key_path, data_rep)?;
    std::fs::write(&pub_path, pub_key)?;

    // Restrictive permissions on the key file
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

/// Load a key's data representation from the keys directory.
pub fn load_key(label: &str) -> Result<Vec<u8>> {
    let path = keys_dir().join(format!("{label}.key"));
    if !path.exists() {
        return Err(SeError::LoadFailed(format!(
            "key file not found: {}",
            path.display()
        )));
    }
    Ok(std::fs::read(&path)?)
}

/// Load the cached public key bytes for a label.
pub fn load_pub_key(label: &str) -> Result<Vec<u8>> {
    let path = keys_dir().join(format!("{label}.pub"));
    if !path.exists() {
        // Fall back to extracting from data rep
        let data_rep = load_key(label)?;
        return public_key_from_data_rep(&data_rep);
    }
    Ok(std::fs::read(&path)?)
}

/// Delete a key from the keys directory.
pub fn delete_key(label: &str) -> Result<()> {
    let dir = keys_dir();
    let key_path = dir.join(format!("{label}.key"));
    let pub_path = dir.join(format!("{label}.pub"));

    if !key_path.exists() {
        return Err(SeError::LoadFailed(format!("key not found: {label}")));
    }

    std::fs::remove_file(&key_path)?;
    let _ = std::fs::remove_file(&pub_path); // pub file may not exist
    Ok(())
}

/// List all key labels in the keys directory.
pub fn list_key_labels() -> Result<Vec<String>> {
    let dir = keys_dir();
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut labels = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if let Some(ext) = path.extension() {
            if ext == "key" {
                if let Some(stem) = path.file_stem() {
                    labels.push(stem.to_string_lossy().to_string());
                }
            }
        }
    }
    labels.sort();
    Ok(labels)
}
