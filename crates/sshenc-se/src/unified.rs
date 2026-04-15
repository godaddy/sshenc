// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Unified backend implementation using `enclaveapp-app-storage`.
//!
//! Replaces the per-platform macos.rs, windows.rs, linux.rs with a single
//! implementation that delegates platform detection to `AppSigningBackend`.

use crate::backend::KeyBackend;
use crate::compat;
use enclaveapp_app_storage::{
    AccessPolicy, AppSigningBackend, BackendKind, EnclaveKeyManager, EnclaveSigner, StorageConfig,
};
use enclaveapp_core::metadata;
use enclaveapp_core::types::KeyType;
use sshenc_core::error::{Error, Result};
use sshenc_core::fingerprint;
use sshenc_core::key::{KeyGenOptions, KeyInfo, KeyLabel, KeyMetadata};
use sshenc_core::pubkey::SshPublicKey;
use std::path::PathBuf;

/// Unified sshenc backend using `AppSigningBackend` for platform dispatch.
///
/// Handles SSH-specific concerns (pub file writing, fingerprinting, metadata
/// with comments and git identity) on top of the shared signing backend.
#[derive(Debug)]
pub struct SshencBackend {
    /// Directory where SSH .pub files are written (typically ~/.ssh).
    pub_dir: PathBuf,
    /// Keys directory (typically ~/.sshenc/keys/).
    keys_dir: PathBuf,
    /// The platform-detected signing backend.
    backend: AppSigningBackend,
}

/// Return the sshenc keys directory (~/.sshenc/keys/).
pub fn sshenc_keys_dir() -> PathBuf {
    // sshenc uses ~/.sshenc/keys/ on Unix, %APPDATA%\sshenc\keys\ on Windows.
    #[cfg(windows)]
    {
        dirs::data_dir()
            .or_else(dirs::home_dir)
            .unwrap_or_else(std::env::temp_dir)
            .join("sshenc")
            .join("keys")
    }
    #[cfg(not(windows))]
    {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join(".sshenc")
            .join("keys")
    }
}

impl SshencBackend {
    /// Create a new sshenc backend with automatic platform detection.
    pub fn new(
        pub_dir: PathBuf,
    ) -> std::result::Result<Self, enclaveapp_app_storage::StorageError> {
        let keys_dir = sshenc_keys_dir();
        let backend = AppSigningBackend::init(StorageConfig {
            app_name: "sshenc".into(),
            key_label: String::new(), // sshenc manages multiple keys, no single label
            access_policy: AccessPolicy::None, // per-key policy, not global
            extra_bridge_paths: vec![],
            keys_dir: Some(keys_dir.clone()),
        })?;

        Ok(Self {
            pub_dir,
            keys_dir,
            backend,
        })
    }

    /// Which platform backend is in use.
    pub fn backend_kind(&self) -> BackendKind {
        self.backend.backend_kind()
    }

    fn signer(&self) -> &dyn EnclaveSigner {
        self.backend.signer()
    }

    fn key_manager(&self) -> &dyn EnclaveKeyManager {
        self.backend.key_manager()
    }

    fn find_pub_file(&self, label: &str) -> Option<PathBuf> {
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

    #[allow(clippy::match_same_arms)] // arms kept separate for intent documentation
    fn persisted_pub_file_path(&self, meta: &metadata::KeyMeta, label: &str) -> Option<PathBuf> {
        match meta.app_specific.get("pub_file_path") {
            // Explicit path recorded — use it
            Some(value) if value.is_string() => value.as_str().map(PathBuf::from),
            // Field present but null — key was generated without a pub file.
            // Fall through to filesystem discovery in case one was created later.
            Some(_) => self.find_pub_file(label),
            // Field absent (legacy metadata) — discover from filesystem
            None => self.find_pub_file(label),
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

impl KeyBackend for SshencBackend {
    fn generate(&self, opts: &KeyGenOptions) -> Result<KeyInfo> {
        let label_str = opts.label.as_str();

        // Check for duplicates
        if self.key_manager().public_key(label_str).is_ok() {
            return Err(Error::DuplicateLabel {
                label: label_str.to_string(),
            });
        }

        // Generate key via platform backend
        let public_bytes = self
            .key_manager()
            .generate(label_str, KeyType::Signing, opts.access_policy)
            .map_err(|e| map_err("generate", e))?;

        // Save app-specific metadata (comment, git_name, git_email)
        let mut meta = compat::load_sshenc_meta(&self.keys_dir, label_str)
            .map_err(|e| map_err("load_meta", e))?;
        if let Some(ref comment) = opts.comment {
            meta.set_app_field("comment", comment.clone());
        }
        match opts.write_pub_path.as_ref() {
            Some(path) => meta.set_app_field(
                "pub_file_path",
                path.as_os_str().to_string_lossy().to_string(),
            ),
            None => meta.set_app_field("pub_file_path", serde_json::Value::Null),
        }
        metadata::save_meta(&self.keys_dir, label_str, &meta)
            .map_err(|e| map_err("save_meta", e))?;

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
                opts.access_policy,
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
            .key_manager()
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
            .key_manager()
            .public_key(label)
            .map_err(|e| map_err("load_pub_key", e))?;

        // Load persisted metadata (handles old and new format)
        let meta =
            compat::load_sshenc_meta(&self.keys_dir, label).map_err(|e| map_err("load_meta", e))?;

        let comment = meta.get_app_field("comment").map(|s| s.to_string());
        let ssh_pubkey = SshPublicKey::from_sec1_bytes(&public_bytes, comment.clone())?;
        let (fp_sha256, fp_md5) = fingerprint::fingerprints(&ssh_pubkey);
        let pub_file = self.persisted_pub_file_path(&meta, label);

        Ok(KeyInfo {
            metadata: KeyMetadata::new(KeyLabel::new(label)?, meta.access_policy, comment),
            public_key_bytes: public_bytes,
            fingerprint_sha256: fp_sha256,
            fingerprint_md5: fp_md5,
            pub_file_path: pub_file,
        })
    }

    fn delete(&self, label: &str) -> Result<()> {
        drop(KeyLabel::new(label)?);
        self.key_manager()
            .delete_key(label)
            .map_err(|e| map_err("delete_key", e))
    }

    fn sign(&self, label: &str, data: &[u8]) -> Result<Vec<u8>> {
        drop(KeyLabel::new(label)?);
        self.signer()
            .sign(label, data)
            .map_err(|e| map_err("sign", e))
    }

    fn is_available(&self) -> bool {
        self.key_manager().is_available()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_pub_dir() -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("sshenc-se-unified-test-{pid}-{id}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn sshenc_keys_dir_is_absolute() {
        let dir = sshenc_keys_dir();
        assert!(dir.is_absolute());
        assert!(dir.to_string_lossy().contains("sshenc"));
        assert!(dir.to_string_lossy().contains("keys"));
    }

    #[test]
    fn find_pub_file_default_label_uses_id_ecdsa() {
        let pub_dir = test_pub_dir();
        std::fs::write(pub_dir.join("id_ecdsa.pub"), "key content").unwrap();

        let backend = SshencBackend {
            pub_dir: pub_dir.clone(),
            keys_dir: sshenc_keys_dir(),
            backend: AppSigningBackend::init(StorageConfig {
                app_name: "sshenc-test".into(),
                key_label: String::new(),
                access_policy: AccessPolicy::None,
                extra_bridge_paths: vec![],
                keys_dir: None,
            })
            .unwrap(),
        };
        let path = backend.find_pub_file("default");
        assert!(path.is_some());
        assert!(path.unwrap().ends_with("id_ecdsa.pub"));

        std::fs::remove_dir_all(&pub_dir).unwrap();
    }

    #[test]
    fn find_pub_file_custom_label() {
        let pub_dir = test_pub_dir();
        std::fs::write(pub_dir.join("github-work.pub"), "key content").unwrap();

        let backend = SshencBackend {
            pub_dir: pub_dir.clone(),
            keys_dir: sshenc_keys_dir(),
            backend: AppSigningBackend::init(StorageConfig {
                app_name: "sshenc-test".into(),
                key_label: String::new(),
                access_policy: AccessPolicy::None,
                extra_bridge_paths: vec![],
                keys_dir: None,
            })
            .unwrap(),
        };
        let path = backend.find_pub_file("github-work");
        assert!(path.is_some());
        assert!(path.unwrap().ends_with("github-work.pub"));

        std::fs::remove_dir_all(&pub_dir).unwrap();
    }

    #[test]
    fn find_pub_file_returns_none_when_missing() {
        let pub_dir = test_pub_dir();

        let backend = SshencBackend {
            pub_dir: pub_dir.clone(),
            keys_dir: sshenc_keys_dir(),
            backend: AppSigningBackend::init(StorageConfig {
                app_name: "sshenc-test".into(),
                key_label: String::new(),
                access_policy: AccessPolicy::None,
                extra_bridge_paths: vec![],
                keys_dir: None,
            })
            .unwrap(),
        };
        let path = backend.find_pub_file("nonexistent");
        assert!(path.is_none());

        std::fs::remove_dir_all(&pub_dir).unwrap();
    }

    fn test_backend(pub_dir: &Path) -> SshencBackend {
        SshencBackend {
            pub_dir: pub_dir.to_path_buf(),
            keys_dir: sshenc_keys_dir(),
            backend: AppSigningBackend::init(StorageConfig {
                app_name: "sshenc-test".into(),
                key_label: String::new(),
                access_policy: AccessPolicy::None,
                extra_bridge_paths: vec![],
                keys_dir: None,
            })
            .unwrap(),
        }
    }

    #[test]
    fn persisted_pub_file_path_uses_recorded_string() {
        let pub_dir = test_pub_dir();
        let backend = test_backend(&pub_dir);

        let mut meta = metadata::KeyMeta::new("test-key", KeyType::Signing, AccessPolicy::None);
        meta.set_app_field("pub_file_path", "/custom/path/test-key.pub");

        let result = backend.persisted_pub_file_path(&meta, "test-key");
        assert_eq!(result, Some(PathBuf::from("/custom/path/test-key.pub")));

        std::fs::remove_dir_all(&pub_dir).unwrap();
    }

    #[test]
    fn persisted_pub_file_path_null_falls_through_to_filesystem() {
        let pub_dir = test_pub_dir();
        std::fs::write(pub_dir.join("test-key.pub"), "key content").unwrap();
        let backend = test_backend(&pub_dir);

        let mut meta = metadata::KeyMeta::new("test-key", KeyType::Signing, AccessPolicy::None);
        meta.set_app_field("pub_file_path", serde_json::Value::Null);

        let result = backend.persisted_pub_file_path(&meta, "test-key");
        assert!(result.is_some());
        assert!(result.unwrap().ends_with("test-key.pub"));

        std::fs::remove_dir_all(&pub_dir).unwrap();
    }

    #[test]
    fn persisted_pub_file_path_absent_field_falls_through_to_filesystem() {
        let pub_dir = test_pub_dir();
        std::fs::write(pub_dir.join("legacy.pub"), "key content").unwrap();
        let backend = test_backend(&pub_dir);

        // Legacy metadata has no pub_file_path field at all
        let meta = metadata::KeyMeta::new("legacy", KeyType::Signing, AccessPolicy::None);

        let result = backend.persisted_pub_file_path(&meta, "legacy");
        assert!(result.is_some());
        assert!(result.unwrap().ends_with("legacy.pub"));

        std::fs::remove_dir_all(&pub_dir).unwrap();
    }

    #[test]
    fn persisted_pub_file_path_null_no_filesystem_returns_none() {
        let pub_dir = test_pub_dir();
        let backend = test_backend(&pub_dir);

        let mut meta = metadata::KeyMeta::new("no-pub", KeyType::Signing, AccessPolicy::None);
        meta.set_app_field("pub_file_path", serde_json::Value::Null);

        let result = backend.persisted_pub_file_path(&meta, "no-pub");
        assert!(result.is_none());

        std::fs::remove_dir_all(&pub_dir).unwrap();
    }
}
