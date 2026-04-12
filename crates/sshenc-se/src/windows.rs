// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Windows TPM 2.0 backend implementation using CNG.

use crate::backend::KeyBackend;
use sshenc_core::error::{Error, Result};
use sshenc_core::fingerprint;
use sshenc_core::key::{KeyGenOptions, KeyInfo, KeyLabel, KeyMetadata};
use sshenc_core::pubkey::SshPublicKey;
use sshenc_ffi_windows::tpm;
use std::path::PathBuf;

/// TPM backend using Windows CNG via the Microsoft Platform Crypto Provider.
///
/// Keys are stored in the TPM's key hierarchy by CNG. Only metadata and
/// cached public keys are stored on disk.
pub struct TpmBackend {
    /// Directory where SSH .pub files are written (typically ~/.ssh).
    pub_dir: PathBuf,
}

impl TpmBackend {
    pub fn new(pub_dir: PathBuf) -> Self {
        TpmBackend { pub_dir }
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

impl KeyBackend for TpmBackend {
    fn generate(&self, opts: &KeyGenOptions) -> Result<KeyInfo> {
        let label_str = opts.label.as_str();

        // Check for duplicates (try to get the public key)
        if tpm::public_key(label_str).is_ok() {
            return Err(Error::DuplicateLabel {
                label: label_str.to_string(),
            });
        }

        let auth_policy = if opts.requires_user_presence {
            tpm::AuthPolicy::Any
        } else {
            tpm::AuthPolicy::None
        };

        // Generate key in TPM
        let public_bytes =
            tpm::generate(label_str, auth_policy).map_err(|e| Error::SecureEnclave {
                operation: "generate".into(),
                detail: e.to_string(),
            })?;

        // Build metadata
        let meta = tpm::KeyMeta {
            label: label_str.to_string(),
            comment: opts.comment.clone(),
            auth_policy: auth_policy as i32,
            created: format!(
                "{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            ),
            git_name: None,
            git_email: None,
        };

        // Save metadata and cached public key
        tpm::save_key(label_str, &public_bytes, &meta).map_err(|e| Error::SecureEnclave {
            operation: "save_key".into(),
            detail: e.to_string(),
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
        let labels = tpm::list_keys().map_err(|e| Error::SecureEnclave {
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

        let public_bytes = tpm::load_pub_key(label).map_err(|e| Error::SecureEnclave {
            operation: "load_pub_key".into(),
            detail: e.to_string(),
        })?;

        let meta = tpm::load_meta(label).map_err(|e| Error::SecureEnclave {
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
        tpm::delete_key(label).map_err(|e| Error::SecureEnclave {
            operation: "delete_key".into(),
            detail: e.to_string(),
        })
    }

    fn sign(&self, label: &str, data: &[u8]) -> Result<Vec<u8>> {
        let _ = KeyLabel::new(label)?;
        tpm::sign(label, data).map_err(|e| Error::SecureEnclave {
            operation: "sign".into(),
            detail: e.to_string(),
        })
    }

    fn is_available(&self) -> bool {
        tpm::is_available()
    }
}
