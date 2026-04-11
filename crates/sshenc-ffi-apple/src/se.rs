// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Rust FFI bindings to the CryptoKit Swift bridge.
//!
//! Keys are stored as files in `~/.sshenc/keys/<label>.key` containing the
//! CryptoKit `dataRepresentation`. A companion `<label>.pub` in the same
//! directory caches the uncompressed public key bytes for fast enumeration.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
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
        auth_policy: i32,
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
        .unwrap_or_else(|| {
            eprintln!("warning: HOME not set, using /tmp for key storage");
            PathBuf::from("/tmp")
        })
        .join(".sshenc")
        .join("keys")
}

/// Authentication policy for signing operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthPolicy {
    /// No authentication required (default).
    None = 0,
    /// Touch ID or device password.
    Any = 1,
    /// Touch ID only.
    Biometric = 2,
    /// Device password only.
    Password = 3,
}

/// Generate a new Secure Enclave P-256 key.
/// Returns (uncompressed_public_key_65_bytes, data_representation).
pub fn generate(auth_policy: AuthPolicy) -> Result<(Vec<u8>, Vec<u8>)> {
    if !is_available() {
        return Err(SeError::NotAvailable);
    }

    let mut pub_key = vec![0u8; 65];
    let mut pub_key_len: i32 = 65;
    let mut data_rep = vec![0u8; 1024]; // generous for future format changes
    let mut data_rep_len: i32 = 1024;

    let rc = unsafe {
        sshenc_se_generate(
            pub_key.as_mut_ptr(),
            &mut pub_key_len,
            data_rep.as_mut_ptr(),
            &mut data_rep_len,
            auth_policy as i32,
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

/// Key metadata stored alongside the handle.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KeyMeta {
    pub label: String,
    pub comment: Option<String>,
    pub auth_policy: i32, // 0=none, 1=any, 2=biometric, 3=password
    pub created: String,  // ISO 8601
}

/// Save a key's data representation, public key, and metadata to the keys directory.
/// Uses a file lock to prevent concurrent writes and atomic writes to prevent partial files.
pub fn save_key(label: &str, data_rep: &[u8], pub_key: &[u8], meta: &KeyMeta) -> Result<()> {
    let dir = keys_dir();

    // Set umask before mkdir to avoid a race where the directory briefly exists
    // with overly-permissive mode before set_permissions can tighten it.
    #[cfg(unix)]
    let old_umask = unsafe { libc::umask(0o077) };
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    unsafe {
        libc::umask(old_umask);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }

    // Lock the keys directory to prevent concurrent writes
    let _lock = DirLock::acquire(&dir)?;

    let handle_path = dir.join(format!("{label}.handle"));
    let pub_path = dir.join(format!("{label}.pub"));
    let ssh_pub_path = dir.join(format!("{label}.ssh.pub"));
    let meta_path = dir.join(format!("{label}.meta"));

    // Atomic write: temp file + rename
    atomic_write(&handle_path, data_rep)?;
    atomic_write(&pub_path, pub_key)?;
    let ssh_line = format_ssh_pub_key(pub_key, label);
    atomic_write(&ssh_pub_path, format!("{ssh_line}\n").as_bytes())?;
    let meta_json =
        serde_json::to_string_pretty(meta).map_err(|e| SeError::Io(std::io::Error::other(e)))?;
    atomic_write(&meta_path, meta_json.as_bytes())?;

    // Restrictive permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&handle_path, std::fs::Permissions::from_mode(0o600))?;
        std::fs::set_permissions(&ssh_pub_path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

/// File-based directory lock using flock. Dropped when the guard goes out of scope.
/// Note: this relies on flock(2) which is reliable on macOS but has different
/// semantics on some Linux filesystems (e.g., NFS). macOS-only for now.
struct DirLock {
    _file: std::fs::File,
}

impl DirLock {
    fn acquire(dir: &std::path::Path) -> Result<Self> {
        let lock_path = dir.join(".lock");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
            if rc != 0 {
                return Err(SeError::Io(std::io::Error::last_os_error()));
            }
        }
        Ok(DirLock { _file: file })
    }
}

/// Write data atomically: write to a temp file, then rename.
fn atomic_write(path: &std::path::Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

/// Load key metadata.
pub fn load_meta(label: &str) -> Result<KeyMeta> {
    let path = keys_dir().join(format!("{label}.meta"));
    if !path.exists() {
        // Backwards compatibility: no .meta file means old key with no metadata
        return Ok(KeyMeta {
            label: label.to_string(),
            comment: None,
            auth_policy: 0,
            created: String::new(),
        });
    }
    let content = std::fs::read_to_string(&path)?;
    serde_json::from_str(&content)
        .map_err(|e| SeError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))
}

/// Load a key's data representation from the keys directory.
pub fn load_key(label: &str) -> Result<Vec<u8>> {
    let path = keys_dir().join(format!("{label}.handle"));
    if !path.exists() {
        return Err(SeError::LoadFailed(format!(
            "key not found: {}",
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

/// Delete a key and all associated files from the keys directory.
pub fn delete_key(label: &str) -> Result<()> {
    let dir = keys_dir();
    let handle_path = dir.join(format!("{label}.handle"));

    if !handle_path.exists() {
        return Err(SeError::LoadFailed(format!("key not found: {label}")));
    }

    let _lock = DirLock::acquire(&dir)?;

    std::fs::remove_file(&handle_path)?;
    let _ = std::fs::remove_file(dir.join(format!("{label}.pub")));
    let _ = std::fs::remove_file(dir.join(format!("{label}.ssh.pub")));
    let _ = std::fs::remove_file(dir.join(format!("{label}.meta")));
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&ssh_pub_path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Format raw EC point bytes as an SSH public key line.
fn format_ssh_pub_key(pub_key: &[u8], comment: &str) -> String {
    // SSH wire format: string("ecdsa-sha2-nistp256") || string("nistp256") || string(ec_point)
    let mut blob = Vec::new();
    write_ssh_string(&mut blob, b"ecdsa-sha2-nistp256");
    write_ssh_string(&mut blob, b"nistp256");
    write_ssh_string(&mut blob, pub_key);

    let encoded = STANDARD.encode(&blob);
    format!("ecdsa-sha2-nistp256 {encoded} {comment}")
}

fn write_ssh_string(buf: &mut Vec<u8>, data: &[u8]) {
    let len = (data.len() as u32).to_be_bytes();
    buf.extend_from_slice(&len);
    buf.extend_from_slice(data);
}

/// Kept as a test helper so existing tests continue to compile.
#[cfg(test)]
fn base64_encode(data: &[u8]) -> String {
    STANDARD.encode(data)
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
            if ext == "handle" {
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
