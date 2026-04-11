// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! macOS Secure Enclave backend implementation.

use crate::backend::KeyBackend;
use sshenc_core::error::{Error, Result};
use sshenc_core::fingerprint;
use sshenc_core::key::{KeyGenOptions, KeyInfo, KeyLabel, KeyMetadata};
use sshenc_core::pubkey::SshPublicKey;
use sshenc_ffi_apple::keychain;
use std::path::PathBuf;

/// Real Secure Enclave backend using macOS Security.framework.
pub struct SecureEnclaveBackend {
    /// Directory where .pub files are stored.
    pub_dir: PathBuf,
}

impl SecureEnclaveBackend {
    pub fn new(pub_dir: PathBuf) -> Self {
        SecureEnclaveBackend { pub_dir }
    }

    /// Find the .pub file for a given label, if it exists.
    fn find_pub_file(&self, label: &str) -> Option<PathBuf> {
        let path = self.pub_dir.join(format!("{label}.pub"));
        if path.exists() {
            Some(path)
        } else {
            // Also check with "sshenc-" prefix
            let path = self.pub_dir.join(format!("sshenc-{label}.pub"));
            if path.exists() {
                Some(path)
            } else {
                None
            }
        }
    }

    fn key_info_from_tag_label(&self, app_tag: &str, label_str: &str) -> Result<KeyInfo> {
        let private_key = keychain::find_key_by_tag(app_tag).map_err(|e| Error::SecureEnclave {
            operation: "find_key".into(),
            detail: e.to_string(),
        })?;

        let public_bytes =
            keychain::extract_public_key_bytes(&private_key).map_err(|e| Error::SecureEnclave {
                operation: "extract_public_key".into(),
                detail: e.to_string(),
            })?;

        let label = KeyLabel::new(label_str)?;
        let ssh_pubkey = SshPublicKey::from_sec1_bytes(&public_bytes, None)?;
        let (fp_sha256, fp_md5) = fingerprint::fingerprints(&ssh_pubkey);
        let pub_file = self.find_pub_file(label_str);

        Ok(KeyInfo {
            metadata: KeyMetadata::new(label, false, None),
            public_key_bytes: public_bytes,
            fingerprint_sha256: fp_sha256,
            fingerprint_md5: fp_md5,
            pub_file_path: pub_file,
        })
    }
}

impl KeyBackend for SecureEnclaveBackend {
    fn generate(&self, opts: &KeyGenOptions) -> Result<KeyInfo> {
        let app_tag = opts.label.app_tag();
        let label_str = opts.label.as_str();

        // Check for duplicates
        if keychain::find_key_by_tag(&app_tag).is_ok() {
            return Err(Error::DuplicateLabel {
                label: label_str.to_string(),
            });
        }

        let private_key = keychain::generate_key(&app_tag, label_str, opts.requires_user_presence)
            .map_err(|e| Error::SecureEnclave {
                operation: "generate_key".into(),
                detail: e.to_string(),
            })?;

        let public_bytes =
            keychain::extract_public_key_bytes(&private_key).map_err(|e| Error::SecureEnclave {
                operation: "extract_public_key".into(),
                detail: e.to_string(),
            })?;

        let ssh_pubkey = SshPublicKey::from_sec1_bytes(&public_bytes, opts.comment.clone())?;
        let (fp_sha256, fp_md5) = fingerprint::fingerprints(&ssh_pubkey);

        // Write .pub file if requested
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
        let tags = keychain::list_key_tags().map_err(|e| Error::SecureEnclave {
            operation: "list_keys".into(),
            detail: e.to_string(),
        })?;

        let mut keys = Vec::new();
        for (tag, label) in tags {
            match self.key_info_from_tag_label(&tag, &label) {
                Ok(info) => keys.push(info),
                Err(e) => {
                    tracing::warn!("skipping key {label}: {e}");
                }
            }
        }
        Ok(keys)
    }

    fn get(&self, label: &str) -> Result<KeyInfo> {
        let validated = KeyLabel::new(label)?;
        let app_tag = validated.app_tag();
        self.key_info_from_tag_label(&app_tag, label)
    }

    fn delete(&self, label: &str) -> Result<()> {
        let validated = KeyLabel::new(label)?;
        let app_tag = validated.app_tag();
        keychain::delete_key_by_tag(&app_tag).map_err(|e| Error::SecureEnclave {
            operation: "delete_key".into(),
            detail: e.to_string(),
        })
    }

    fn sign(&self, label: &str, data: &[u8]) -> Result<Vec<u8>> {
        let validated = KeyLabel::new(label)?;
        let app_tag = validated.app_tag();
        let private_key =
            keychain::find_key_by_tag(&app_tag).map_err(|e| Error::SecureEnclave {
                operation: "find_key_for_signing".into(),
                detail: e.to_string(),
            })?;
        keychain::sign_data(&private_key, data).map_err(|e| Error::SecureEnclave {
            operation: "sign".into(),
            detail: e.to_string(),
        })
    }

    fn is_available(&self) -> bool {
        keychain::is_secure_enclave_available()
    }
}
