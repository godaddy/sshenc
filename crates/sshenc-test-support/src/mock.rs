// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! In-memory mock key backend for testing.

use sshenc_core::error::{Error, Result};
use sshenc_core::fingerprint;
use sshenc_core::key::{KeyGenOptions, KeyInfo, KeyMetadata};
use sshenc_core::pubkey::SshPublicKey;
use sshenc_se::backend::KeyBackend;
use std::collections::HashMap;
use std::sync::Mutex;

/// A stored mock key.
#[derive(Debug)]
struct MockKey {
    info: KeyInfo,
    /// Seed used to generate deterministic signatures.
    seed: u8,
}

/// In-memory key backend for testing without Secure Enclave hardware.
#[derive(Debug)]
pub struct MockKeyBackend {
    keys: Mutex<HashMap<String, MockKey>>,
    next_seed: Mutex<u8>,
}

fn lock_err() -> Error {
    Error::Other("mock mutex poisoned".into())
}

impl MockKeyBackend {
    pub fn new() -> Self {
        MockKeyBackend {
            keys: Mutex::new(HashMap::new()),
            next_seed: Mutex::new(1),
        }
    }

    /// Return the number of stored keys.
    pub fn key_count(&self) -> usize {
        self.keys.lock().expect("mock keys mutex poisoned").len()
    }
}

impl Default for MockKeyBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(clippy::unwrap_in_result)]
impl KeyBackend for MockKeyBackend {
    fn generate(&self, opts: &KeyGenOptions) -> Result<KeyInfo> {
        let label_str = opts.label.as_str().to_string();
        let mut keys = self.keys.lock().map_err(|_| lock_err())?;

        if keys.contains_key(&label_str) {
            return Err(Error::DuplicateLabel { label: label_str });
        }

        let mut seed_guard = self.next_seed.lock().map_err(|_| lock_err())?;
        let seed = *seed_guard;
        *seed_guard = seed.wrapping_add(1);
        drop(seed_guard);

        let public_key_bytes = crate::test_ec_point(seed);
        let ssh_pubkey = SshPublicKey::from_sec1_bytes(&public_key_bytes, opts.comment.clone())
            .expect("mock EC point must be valid");
        let (fp_sha256, fp_md5) = fingerprint::fingerprints(&ssh_pubkey);

        let pub_file_path = if let Some(ref path) = opts.write_pub_path {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).ok();
            }
            let line = ssh_pubkey.to_openssh_line();
            std::fs::write(path, format!("{line}\n")).ok();
            Some(path.clone())
        } else {
            None
        };

        let info = KeyInfo {
            metadata: KeyMetadata::new(
                opts.label.clone(),
                opts.access_policy,
                opts.comment.clone(),
            ),
            public_key_bytes,
            fingerprint_sha256: fp_sha256,
            fingerprint_md5: fp_md5,
            pub_file_path,
        };

        keys.insert(
            label_str,
            MockKey {
                info: info.clone(),
                seed,
            },
        );
        Ok(info)
    }

    fn list(&self) -> Result<Vec<KeyInfo>> {
        let keys = self.keys.lock().map_err(|_| lock_err())?;
        Ok(keys.values().map(|k| k.info.clone()).collect())
    }

    fn get(&self, label: &str) -> Result<KeyInfo> {
        let keys = self.keys.lock().map_err(|_| lock_err())?;
        keys.get(label)
            .map(|k| k.info.clone())
            .ok_or_else(|| Error::KeyNotFound {
                label: label.to_string(),
            })
    }

    fn delete(&self, label: &str) -> Result<()> {
        let mut keys = self.keys.lock().map_err(|_| lock_err())?;
        if keys.remove(label).is_some() {
            Ok(())
        } else {
            Err(Error::KeyNotFound {
                label: label.to_string(),
            })
        }
    }

    fn sign(&self, label: &str, data: &[u8]) -> Result<Vec<u8>> {
        let keys = self.keys.lock().map_err(|_| lock_err())?;
        let key = keys.get(label).ok_or_else(|| Error::KeyNotFound {
            label: label.to_string(),
        })?;
        Ok(crate::test_signature(data, key.seed))
    }

    fn is_available(&self) -> bool {
        true
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use sshenc_core::key::KeyLabel;
    use sshenc_core::AccessPolicy;

    fn make_opts(label: &str) -> KeyGenOptions {
        KeyGenOptions {
            label: KeyLabel::new(label).unwrap(),
            comment: Some("test".into()),
            access_policy: AccessPolicy::None,
            write_pub_path: None,
        }
    }

    #[test]
    fn test_mock_generate_and_get() {
        let backend = MockKeyBackend::new();
        let info = backend.generate(&make_opts("test-key")).unwrap();
        assert_eq!(info.metadata.label.as_str(), "test-key");
        assert_eq!(info.public_key_bytes.len(), 65);

        let retrieved = backend.get("test-key").unwrap();
        assert_eq!(retrieved.metadata.label.as_str(), "test-key");
    }

    #[test]
    fn test_mock_duplicate_label() {
        let backend = MockKeyBackend::new();
        backend.generate(&make_opts("dup")).unwrap();
        let result = backend.generate(&make_opts("dup"));
        assert!(matches!(result, Err(Error::DuplicateLabel { .. })));
    }

    #[test]
    fn test_mock_list() {
        let backend = MockKeyBackend::new();
        backend.generate(&make_opts("key-a")).unwrap();
        backend.generate(&make_opts("key-b")).unwrap();
        let list = backend.list().unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_mock_delete() {
        let backend = MockKeyBackend::new();
        backend.generate(&make_opts("del-me")).unwrap();
        assert_eq!(backend.key_count(), 1);
        backend.delete("del-me").unwrap();
        assert_eq!(backend.key_count(), 0);
    }

    #[test]
    fn test_mock_delete_not_found() {
        let backend = MockKeyBackend::new();
        let result = backend.delete("nonexistent");
        assert!(matches!(result, Err(Error::KeyNotFound { .. })));
    }

    #[test]
    fn test_mock_sign() {
        let backend = MockKeyBackend::new();
        backend.generate(&make_opts("sign-key")).unwrap();
        let sig = backend.sign("sign-key", b"hello world").unwrap();
        // Should be a DER-encoded structure
        assert_eq!(sig[0], 0x30); // SEQUENCE tag
        assert!(sig.len() > 10);
    }

    #[test]
    fn test_mock_sign_deterministic() {
        let backend = MockKeyBackend::new();
        backend.generate(&make_opts("det-key")).unwrap();
        let sig1 = backend.sign("det-key", b"data").unwrap();
        let sig2 = backend.sign("det-key", b"data").unwrap();
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_mock_sign_not_found() {
        let backend = MockKeyBackend::new();
        let result = backend.sign("missing", b"data");
        assert!(matches!(result, Err(Error::KeyNotFound { .. })));
    }

    #[test]
    fn test_mock_generate_empty_comment() {
        let backend = MockKeyBackend::new();
        let opts = KeyGenOptions {
            label: KeyLabel::new("no-comment").unwrap(),
            comment: None,
            access_policy: AccessPolicy::None,
            write_pub_path: None,
        };
        let info = backend.generate(&opts).unwrap();
        assert!(info.metadata.comment.is_none());
        assert_eq!(info.metadata.label.as_str(), "no-comment");
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O (mkdir) not supported under Miri isolation
    fn test_mock_generate_with_write_pub_path() {
        let dir = std::env::temp_dir().join("sshenc-test-mock-pubkey");
        std::fs::create_dir_all(&dir).unwrap();
        let pub_path = dir.join("test-key.pub");

        let backend = MockKeyBackend::new();
        let opts = KeyGenOptions {
            label: KeyLabel::new("pub-write-key").unwrap(),
            comment: Some("test@host".into()),
            access_policy: AccessPolicy::None,
            write_pub_path: Some(pub_path.clone()),
        };
        let info = backend.generate(&opts).unwrap();
        assert_eq!(info.pub_file_path, Some(pub_path.clone()));

        let contents = std::fs::read_to_string(&pub_path).unwrap();
        assert!(
            contents.contains("ecdsa-sha2-nistp256"),
            "pub file should contain ecdsa-sha2-nistp256, got: {contents}"
        );
        assert!(
            contents.contains("test@host"),
            "pub file should contain the comment"
        );

        // Cleanup
        std::fs::remove_file(&pub_path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn test_mock_list_returns_all_keys() {
        let backend = MockKeyBackend::new();
        backend.generate(&make_opts("alpha")).unwrap();
        backend.generate(&make_opts("beta")).unwrap();
        backend.generate(&make_opts("gamma")).unwrap();

        let list = backend.list().unwrap();
        assert_eq!(list.len(), 3);

        let labels: Vec<&str> = list.iter().map(|k| k.metadata.label.as_str()).collect();
        assert!(labels.contains(&"alpha"));
        assert!(labels.contains(&"beta"));
        assert!(labels.contains(&"gamma"));
    }

    #[test]
    fn test_mock_sign_different_data_produces_different_signatures() {
        let backend = MockKeyBackend::new();
        backend.generate(&make_opts("sig-key")).unwrap();
        let sig1 = backend.sign("sig-key", b"message-one").unwrap();
        let sig2 = backend.sign("sig-key", b"message-two").unwrap();
        assert_ne!(
            sig1, sig2,
            "different data should produce different signatures"
        );
    }

    #[test]
    fn test_mock_sign_different_keys_produce_different_signatures() {
        let backend = MockKeyBackend::new();
        backend.generate(&make_opts("key-x")).unwrap();
        backend.generate(&make_opts("key-y")).unwrap();
        let sig1 = backend.sign("key-x", b"same-data").unwrap();
        let sig2 = backend.sign("key-y", b"same-data").unwrap();
        assert_ne!(
            sig1, sig2,
            "different keys (different seeds) should produce different signatures for same data"
        );
    }

    #[test]
    fn test_mock_get_after_delete_returns_key_not_found() {
        let backend = MockKeyBackend::new();
        backend.generate(&make_opts("ephemeral")).unwrap();
        // Verify it exists
        backend.get("ephemeral").unwrap();
        // Delete it
        backend.delete("ephemeral").unwrap();
        // Now get should fail
        let result = backend.get("ephemeral");
        assert!(
            matches!(result, Err(Error::KeyNotFound { .. })),
            "get after delete should return KeyNotFound"
        );
    }
}
