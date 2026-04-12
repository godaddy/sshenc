// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! macOS Secure Enclave backend implementation using CryptoKit.

use crate::backend::KeyBackend;
use sshenc_core::error::{Error, Result};
use sshenc_core::fingerprint;
use sshenc_core::key::{KeyGenOptions, KeyInfo, KeyLabel, KeyMetadata};
use sshenc_core::pubkey::SshPublicKey;
use sshenc_ffi_apple::se;
use std::path::PathBuf;

/// Secure Enclave backend using CryptoKit via Swift bridge.
///
/// Keys are stored as CryptoKit data representation files in `~/.sshenc/keys/`.
pub struct SecureEnclaveBackend {
    /// Directory where SSH .pub files are written (typically ~/.ssh).
    pub_dir: PathBuf,
}

impl SecureEnclaveBackend {
    pub fn new(pub_dir: PathBuf) -> Self {
        SecureEnclaveBackend { pub_dir }
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

impl KeyBackend for SecureEnclaveBackend {
    fn generate(&self, opts: &KeyGenOptions) -> Result<KeyInfo> {
        let label_str = opts.label.as_str();

        // Check for duplicates
        if se::load_key(label_str).is_ok() {
            return Err(Error::DuplicateLabel {
                label: label_str.to_string(),
            });
        }

        // Map requires_user_presence to auth policy
        let auth_policy = if opts.requires_user_presence {
            se::AuthPolicy::Any
        } else {
            se::AuthPolicy::None
        };

        // Generate key in Secure Enclave
        let (public_bytes, data_rep) =
            se::generate(auth_policy).map_err(|e| Error::SecureEnclave {
                operation: "generate".into(),
                detail: e.to_string(),
            })?;

        // Build metadata
        let meta = se::KeyMeta {
            label: label_str.to_string(),
            comment: opts.comment.clone(),
            auth_policy: auth_policy as i32,
            git_name: None,
            git_email: None,
            created: chrono_now(),
        };

        // Save handle, public key, and metadata to ~/.sshenc/keys/
        se::save_key(label_str, &data_rep, &public_bytes, &meta).map_err(|e| {
            Error::SecureEnclave {
                operation: "save_key".into(),
                detail: e.to_string(),
            }
        })?;

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
        let labels = se::list_key_labels().map_err(|e| Error::SecureEnclave {
            operation: "list_keys".into(),
            detail: e.to_string(),
        })?;

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
        let _ = KeyLabel::new(label)?;

        let public_bytes = se::load_pub_key(label).map_err(|e| Error::SecureEnclave {
            operation: "load_pub_key".into(),
            detail: e.to_string(),
        })?;

        // Load persisted metadata
        let meta = se::load_meta(label).map_err(|e| Error::SecureEnclave {
            operation: "load_meta".into(),
            detail: e.to_string(),
        })?;

        let ssh_pubkey = SshPublicKey::from_sec1_bytes(&public_bytes, meta.comment.clone())?;
        let (fp_sha256, fp_md5) = fingerprint::fingerprints(&ssh_pubkey);
        let pub_file = self.find_pub_file(label);

        Ok(KeyInfo {
            metadata: KeyMetadata::new(KeyLabel::new(label)?, meta.auth_policy != 0, meta.comment),
            public_key_bytes: public_bytes,
            fingerprint_sha256: fp_sha256,
            fingerprint_md5: fp_md5,
            pub_file_path: pub_file,
        })
    }

    fn delete(&self, label: &str) -> Result<()> {
        let _ = KeyLabel::new(label)?;
        se::delete_key(label).map_err(|e| Error::SecureEnclave {
            operation: "delete_key".into(),
            detail: e.to_string(),
        })
    }

    fn sign(&self, label: &str, data: &[u8]) -> Result<Vec<u8>> {
        let _ = KeyLabel::new(label)?;
        let data_rep = se::load_key(label).map_err(|e| Error::SecureEnclave {
            operation: "load_key".into(),
            detail: e.to_string(),
        })?;
        se::sign(&data_rep, data).map_err(|e| Error::SecureEnclave {
            operation: "sign".into(),
            detail: e.to_string(),
        })
    }

    fn is_available(&self) -> bool {
        se::is_available()
    }
}

/// Returns the current time as unix epoch seconds (string).
fn chrono_now() -> String {
    format!(
        "{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    )
}
