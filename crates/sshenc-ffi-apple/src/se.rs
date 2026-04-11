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
    let ssh_pub_path = dir.join(format!("{label}.ssh.pub"));

    std::fs::write(&key_path, data_rep)?;
    std::fs::write(&pub_path, pub_key)?;

    // Write SSH-formatted public key for use with IdentityFile selection
    let ssh_line = format_ssh_pub_key(pub_key, label);
    std::fs::write(&ssh_pub_path, format!("{ssh_line}\n"))?;

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

/// Get the path to the SSH-formatted public key file for a label.
pub fn ssh_pub_path(label: &str) -> PathBuf {
    keys_dir().join(format!("{label}.ssh.pub"))
}

/// Write an SSH-formatted public key file from raw EC point bytes.
pub fn save_ssh_pub_key(label: &str, pub_key: &[u8]) -> Result<()> {
    let dir = keys_dir();
    std::fs::create_dir_all(&dir)?;
    let ssh_pub_path = dir.join(format!("{label}.ssh.pub"));
    let ssh_line = format_ssh_pub_key(pub_key, label);
    std::fs::write(&ssh_pub_path, format!("{ssh_line}\n"))?;
    Ok(())
}

/// Format raw EC point bytes as an SSH public key line.
fn format_ssh_pub_key(pub_key: &[u8], comment: &str) -> String {
    // SSH wire format: string("ecdsa-sha2-nistp256") || string("nistp256") || string(ec_point)
    let mut blob = Vec::new();
    write_ssh_string(&mut blob, b"ecdsa-sha2-nistp256");
    write_ssh_string(&mut blob, b"nistp256");
    write_ssh_string(&mut blob, pub_key);

    let encoded = base64_encode(&blob);
    format!("ecdsa-sha2-nistp256 {encoded} {comment}")
}

fn write_ssh_string(buf: &mut Vec<u8>, data: &[u8]) {
    let len = (data.len() as u32).to_be_bytes();
    buf.extend_from_slice(&len);
    buf.extend_from_slice(data);
}

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(CHARS[((n >> 18) & 63) as usize] as char);
        out.push(CHARS[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(CHARS[((n >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(CHARS[(n & 63) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_encode_rfc4648_vectors() {
        // RFC 4648 §10 test vectors
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn test_write_ssh_string() {
        let mut buf = Vec::new();
        write_ssh_string(&mut buf, b"hello");
        // 4-byte big-endian length (5) followed by "hello"
        assert_eq!(buf.len(), 4 + 5);
        assert_eq!(&buf[..4], &[0, 0, 0, 5]);
        assert_eq!(&buf[4..], b"hello");
    }

    #[test]
    fn test_write_ssh_string_empty() {
        let mut buf = Vec::new();
        write_ssh_string(&mut buf, b"");
        assert_eq!(buf, vec![0, 0, 0, 0]);
    }

    #[test]
    fn test_format_ssh_pub_key() {
        // Create a fake 65-byte uncompressed EC point (0x04 prefix + 64 bytes)
        let mut ec_point = vec![0x04u8];
        ec_point.extend_from_slice(&[0xAB; 32]); // fake X
        ec_point.extend_from_slice(&[0xCD; 32]); // fake Y
        assert_eq!(ec_point.len(), 65);

        let line = format_ssh_pub_key(&ec_point, "testkey");

        // Must start with the key type
        assert!(line.starts_with("ecdsa-sha2-nistp256 "));
        // Must end with the comment
        assert!(line.ends_with(" testkey"));

        // Extract the base64 portion and verify it decodes
        let parts: Vec<&str> = line.split(' ').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "ecdsa-sha2-nistp256");
        assert_eq!(parts[2], "testkey");

        // The base64 portion should only contain valid base64 characters
        let b64 = parts[1];
        assert!(b64
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='));
        assert!(!b64.is_empty());
    }

    #[test]
    fn test_ssh_pub_path() {
        let path = ssh_pub_path("mykey");
        let path_str = path.to_string_lossy();
        // Should end with the label's ssh.pub file
        assert!(path_str.ends_with("mykey.ssh.pub"));
        // Should be inside the keys directory
        assert!(path_str.contains(".sshenc/keys"));
    }

    #[test]
    fn test_keys_dir() {
        let dir = keys_dir();
        let dir_str = dir.to_string_lossy();
        assert!(
            dir_str.contains(".sshenc/keys"),
            "keys_dir should contain .sshenc/keys, got: {dir_str}"
        );
        // Should be an absolute path
        assert!(
            dir.is_absolute() || dir_str.starts_with("/tmp"),
            "keys_dir should be absolute, got: {dir_str}"
        );
    }
}
