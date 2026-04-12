// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! macOS Secure Enclave backend implementation using libenclaveapp.

use crate::backend::KeyBackend;
use enclaveapp_apple::SecureEnclaveSigner;
use enclaveapp_core::metadata;
use enclaveapp_core::traits::{EnclaveKeyManager, EnclaveSigner};
use enclaveapp_core::types::{AccessPolicy, KeyType};
use sshenc_core::error::{Error, Result};
use sshenc_core::fingerprint;
use sshenc_core::key::{KeyGenOptions, KeyInfo, KeyLabel, KeyMetadata};
use sshenc_core::pubkey::SshPublicKey;
use std::path::PathBuf;

/// Secure Enclave backend using CryptoKit via libenclaveapp.
///
/// Keys are stored as CryptoKit data representation files in `~/.sshenc/keys/`.
#[derive(Debug)]
pub struct SecureEnclaveBackend {
    /// Directory where SSH .pub files are written (typically ~/.ssh).
    pub_dir: PathBuf,
    /// The libenclaveapp signer, configured to use ~/.sshenc/keys/.
    signer: SecureEnclaveSigner,
}

/// Return the sshenc keys directory (~/.sshenc/keys/).
pub fn sshenc_keys_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".sshenc")
        .join("keys")
}

impl SecureEnclaveBackend {
    pub fn new(pub_dir: PathBuf) -> Self {
        SecureEnclaveBackend {
            pub_dir,
            signer: SecureEnclaveSigner::with_keys_dir("sshenc", sshenc_keys_dir()),
        }
    }

    fn find_pub_file(&self, label: &str) -> Option<PathBuf> {
        // "default" label uses standard OpenSSH naming (id_ecdsa.pub)
        let path = if label == "default" {
            self.pub_dir.join("id_ecdsa.pub")
        } else {
            self.pub_dir.join(format!("{label}.pub"))
        };
        if path.exists() {
            Some(path)
        } else {
            None
        }
    }
}

/// Map an enclaveapp_core error to an sshenc_core error.
fn map_err(operation: &str, e: enclaveapp_core::Error) -> Error {
    Error::SecureEnclave {
        operation: operation.into(),
        detail: e.to_string(),
    }
}

fn load_sshenc_meta(
    label: &str,
) -> std::result::Result<enclaveapp_core::KeyMeta, enclaveapp_core::Error> {
    crate::compat::load_sshenc_meta(&sshenc_keys_dir(), label)
}

impl KeyBackend for SecureEnclaveBackend {
    fn generate(&self, opts: &KeyGenOptions) -> Result<KeyInfo> {
        let label_str = opts.label.as_str();

        // Check for duplicates
        if self.signer.public_key(label_str).is_ok() {
            return Err(Error::DuplicateLabel {
                label: label_str.to_string(),
            });
        }

        // Map requires_user_presence to access policy
        let policy = if opts.requires_user_presence {
            AccessPolicy::Any
        } else {
            AccessPolicy::None
        };

        // Generate key in Secure Enclave
        let public_bytes = self
            .signer
            .generate(label_str, KeyType::Signing, policy)
            .map_err(|e| map_err("generate", e))?;

        // Save app-specific metadata (comment, git_name, git_email)
        let keys_dir = sshenc_keys_dir();
        let mut meta = load_sshenc_meta(label_str).map_err(|e| map_err("load_meta", e))?;
        if let Some(ref comment) = opts.comment {
            meta.set_app_field("comment", comment.clone());
        }
        metadata::save_meta(&keys_dir, label_str, &meta).map_err(|e| map_err("save_meta", e))?;

        let ssh_pubkey = SshPublicKey::from_sec1_bytes(&public_bytes, opts.comment.clone())?;
        let (fp_sha256, fp_md5) = fingerprint::fingerprints(&ssh_pubkey);

        // Write SSH .pub file if requested
        let pub_file_path = if let Some(ref path) = opts.write_pub_path {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let line = ssh_pubkey.to_openssh_line();
            std::fs::write(path, format!("{line}\n"))?;
            Some(path.clone())
        } else {
            None
        };

        Ok(KeyInfo {
            metadata: KeyMetadata::new(
                opts.label.clone(),
                opts.requires_user_presence,
                opts.comment.clone(),
            ),
            public_key_bytes: public_bytes,
            fingerprint_sha256: fp_sha256,
            fingerprint_md5: fp_md5,
            pub_file_path,
        })
    }

    fn list(&self) -> Result<Vec<KeyInfo>> {
        let labels = self
            .signer
            .list_keys()
            .map_err(|e| map_err("list_keys", e))?;

        let mut keys = Vec::new();
        for label_str in labels {
            match self.get(&label_str) {
                Ok(info) => keys.push(info),
                Err(e) => {
                    tracing::warn!("skipping key {label_str}: {e}");
                }
            }
        }
        Ok(keys)
    }

    fn get(&self, label: &str) -> Result<KeyInfo> {
        drop(KeyLabel::new(label)?);

        let public_bytes = self
            .signer
            .public_key(label)
            .map_err(|e| map_err("load_pub_key", e))?;

        // Load persisted metadata (handles old and new format)
        let meta = load_sshenc_meta(label).map_err(|e| map_err("load_meta", e))?;

        let comment = meta.get_app_field("comment").map(|s| s.to_string());
        let requires_user_presence = meta.access_policy != AccessPolicy::None;

        let ssh_pubkey = SshPublicKey::from_sec1_bytes(&public_bytes, comment.clone())?;
        let (fp_sha256, fp_md5) = fingerprint::fingerprints(&ssh_pubkey);
        let pub_file = self.find_pub_file(label);

        Ok(KeyInfo {
            metadata: KeyMetadata::new(KeyLabel::new(label)?, requires_user_presence, comment),
            public_key_bytes: public_bytes,
            fingerprint_sha256: fp_sha256,
            fingerprint_md5: fp_md5,
            pub_file_path: pub_file,
        })
    }

    fn delete(&self, label: &str) -> Result<()> {
        drop(KeyLabel::new(label)?);
        self.signer
            .delete_key(label)
            .map_err(|e| map_err("delete_key", e))
    }

    fn sign(&self, label: &str, data: &[u8]) -> Result<Vec<u8>> {
        drop(KeyLabel::new(label)?);
        self.signer
            .sign(label, data)
            .map_err(|e| map_err("sign", e))
    }

    fn is_available(&self) -> bool {
        self.signer.is_available()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_pub_dir() -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("sshenc-se-macos-test-{pid}-{id}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn make_backend(pub_dir: PathBuf) -> SecureEnclaveBackend {
        SecureEnclaveBackend::new(pub_dir)
    }

    #[test]
    fn find_pub_file_default_label_uses_id_ecdsa() {
        let pub_dir = test_pub_dir();
        std::fs::write(pub_dir.join("id_ecdsa.pub"), "key content").unwrap();

        let backend = make_backend(pub_dir.clone());
        let path = backend.find_pub_file("default");
        assert!(path.is_some());
        assert!(path.unwrap().ends_with("id_ecdsa.pub"));

        std::fs::remove_dir_all(&pub_dir).unwrap();
    }

    #[test]
    fn find_pub_file_custom_label_uses_label_name() {
        let pub_dir = test_pub_dir();
        std::fs::write(pub_dir.join("github-work.pub"), "key content").unwrap();

        let backend = make_backend(pub_dir.clone());
        let path = backend.find_pub_file("github-work");
        assert!(path.is_some());
        assert!(path.unwrap().ends_with("github-work.pub"));

        std::fs::remove_dir_all(&pub_dir).unwrap();
    }

    #[test]
    fn find_pub_file_returns_none_when_missing() {
        let pub_dir = test_pub_dir();

        let backend = make_backend(pub_dir.clone());
        let path = backend.find_pub_file("nonexistent");
        assert!(path.is_none());

        std::fs::remove_dir_all(&pub_dir).unwrap();
    }

    #[test]
    fn find_pub_file_default_returns_none_when_missing() {
        let pub_dir = test_pub_dir();

        let backend = make_backend(pub_dir.clone());
        let path = backend.find_pub_file("default");
        assert!(path.is_none());

        std::fs::remove_dir_all(&pub_dir).unwrap();
    }

    #[test]
    fn key_info_has_correct_fingerprints_for_known_pubkey() {
        // A deterministic 65-byte SEC1 point
        let mut point = vec![0x04];
        for i in 0_u8..32 {
            point.push(i.wrapping_mul(7).wrapping_add(3));
        }
        for i in 0_u8..32 {
            point.push(i.wrapping_mul(11).wrapping_add(5));
        }

        let ssh_pubkey =
            SshPublicKey::from_sec1_bytes(&point, Some("test@host".to_string())).unwrap();
        let (fp_sha256, fp_md5) = fingerprint::fingerprints(&ssh_pubkey);

        // SHA-256 fingerprint must start with SHA256:
        assert!(fp_sha256.starts_with("SHA256:"));
        // MD5 fingerprint must start with MD5: and have colon-separated hex
        assert!(fp_md5.starts_with("MD5:"));
        let hex_part = &fp_md5["MD5:".len()..];
        let parts: Vec<&str> = hex_part.split(':').collect();
        assert_eq!(parts.len(), 16);

        // Fingerprints should be deterministic
        let (fp_sha256_2, fp_md5_2) = fingerprint::fingerprints(&ssh_pubkey);
        assert_eq!(fp_sha256, fp_sha256_2);
        assert_eq!(fp_md5, fp_md5_2);
    }

    #[test]
    fn sshenc_keys_dir_is_absolute() {
        let dir = sshenc_keys_dir();
        assert!(dir.is_absolute());
        assert!(dir.to_string_lossy().contains(".sshenc"));
        assert!(dir.to_string_lossy().contains("keys"));
    }
}
