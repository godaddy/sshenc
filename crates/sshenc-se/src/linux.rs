// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Linux software backend implementation using libenclaveapp.
//!
//! Keys are software-backed ECDSA P-256, stored on disk in `~/.sshenc/keys/`.
//! This is NOT hardware-protected — use macOS Secure Enclave or Windows TPM
//! when hardware security is required.

use crate::backend::KeyBackend;
use crate::compat;
use enclaveapp_core::metadata;
use enclaveapp_core::traits::{EnclaveKeyManager, EnclaveSigner};
use enclaveapp_core::types::{AccessPolicy, KeyType};
use enclaveapp_software::SoftwareSigner;
use sshenc_core::error::{Error, Result};
use sshenc_core::fingerprint;
use sshenc_core::key::{KeyGenOptions, KeyInfo, KeyLabel, KeyMetadata};
use sshenc_core::pubkey::SshPublicKey;
use std::path::PathBuf;

/// Software backend using ECDSA P-256 keys on disk via libenclaveapp.
///
/// Keys are stored as files in `~/.sshenc/keys/`. Unlike the macOS and
/// Windows backends, keys are NOT hardware-protected.
#[derive(Debug)]
pub struct SoftwareBackend {
    /// Directory where SSH .pub files are written (typically ~/.ssh).
    pub_dir: PathBuf,
    /// The libenclaveapp signer, configured to use ~/.sshenc/keys/.
    signer: SoftwareSigner,
}

/// Return the sshenc keys directory (~/.sshenc/keys/).
pub fn sshenc_keys_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".sshenc")
        .join("keys")
}

impl SoftwareBackend {
    pub fn new(pub_dir: PathBuf) -> Self {
        SoftwareBackend {
            pub_dir,
            signer: SoftwareSigner::with_keys_dir("sshenc", sshenc_keys_dir()),
        }
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
}

/// Map an enclaveapp_core error to an sshenc_core error.
fn map_err(operation: &str, e: enclaveapp_core::Error) -> Error {
    Error::SecureEnclave {
        operation: operation.into(),
        detail: e.to_string(),
    }
}

impl KeyBackend for SoftwareBackend {
    fn generate(&self, opts: &KeyGenOptions) -> Result<KeyInfo> {
        let label_str = opts.label.as_str();

        // Check for duplicates
        if self.signer.public_key(label_str).is_ok() {
            return Err(Error::DuplicateLabel {
                label: label_str.to_string(),
            });
        }

        let policy = if opts.requires_user_presence {
            AccessPolicy::Any
        } else {
            AccessPolicy::None
        };

        // Generate key (software-backed)
        let public_bytes = self
            .signer
            .generate(label_str, KeyType::Signing, policy)
            .map_err(|e| map_err("generate", e))?;

        // Save app-specific metadata (comment, git_name, git_email)
        let keys_dir = sshenc_keys_dir();
        let mut meta =
            compat::load_sshenc_meta(&keys_dir, label_str).map_err(|e| map_err("load_meta", e))?;
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

        // Load persisted metadata
        let keys_dir = sshenc_keys_dir();
        let meta =
            compat::load_sshenc_meta(&keys_dir, label).map_err(|e| map_err("load_meta", e))?;

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
