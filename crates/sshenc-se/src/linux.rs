// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Linux backend implementation for sshenc.
//!
//! Tries backends in order:
//! 1. TPM 2.0 via tss-esapi (hardware-protected, same security model as macOS/Windows)
//! 2. Software P-256 keys on disk, encrypted via system keyring if available
//!
//! The selected backend is transparent to the rest of sshenc.

use crate::backend::KeyBackend;
use crate::compat;
use enclaveapp_core::metadata;
use enclaveapp_core::traits::{EnclaveKeyManager, EnclaveSigner};
use enclaveapp_core::types::{AccessPolicy, KeyType};
use sshenc_core::error::{Error, Result};
use sshenc_core::fingerprint;
use sshenc_core::key::{KeyGenOptions, KeyInfo, KeyLabel, KeyMetadata};
use sshenc_core::pubkey::SshPublicKey;
use std::path::PathBuf;

/// Return the sshenc keys directory (~/.sshenc/keys/).
pub fn sshenc_keys_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".sshenc")
        .join("keys")
}

/// Linux backend that auto-selects TPM or software.
#[derive(Debug)]
pub struct LinuxBackend {
    pub_dir: PathBuf,
    inner: LinuxSigner,
}

#[derive(Debug)]
enum LinuxSigner {
    #[cfg(target_env = "gnu")]
    Tpm(enclaveapp_linux_tpm::LinuxTpmSigner),
    Software(enclaveapp_software::SoftwareSigner),
}

impl LinuxBackend {
    #[allow(clippy::print_stderr)]
    pub fn new(pub_dir: PathBuf) -> Self {
        let keys_dir = sshenc_keys_dir();

        #[cfg(target_env = "gnu")]
        let inner = if enclaveapp_linux_tpm::is_available() {
            eprintln!("sshenc: using TPM 2.0 for hardware-backed keys");
            LinuxSigner::Tpm(enclaveapp_linux_tpm::LinuxTpmSigner::with_keys_dir(
                "sshenc", keys_dir,
            ))
        } else {
            eprintln!(
                "sshenc: no TPM detected, using software-backed keys \
                 (private keys stored on disk)"
            );
            LinuxSigner::Software(enclaveapp_software::SoftwareSigner::with_keys_dir(
                "sshenc", keys_dir,
            ))
        };

        #[cfg(not(target_env = "gnu"))]
        let inner = {
            eprintln!("sshenc: using software-backed keys (musl/static build)");
            LinuxSigner::Software(enclaveapp_software::SoftwareSigner::with_keys_dir(
                "sshenc", keys_dir,
            ))
        };

        LinuxBackend { pub_dir, inner }
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

    fn signer(&self) -> &dyn EnclaveSigner {
        match &self.inner {
            #[cfg(target_env = "gnu")]
            LinuxSigner::Tpm(s) => s,
            LinuxSigner::Software(s) => s,
        }
    }

    fn key_manager(&self) -> &dyn EnclaveKeyManager {
        match &self.inner {
            #[cfg(target_env = "gnu")]
            LinuxSigner::Tpm(s) => s,
            LinuxSigner::Software(s) => s,
        }
    }
}

fn map_err(operation: &str, e: enclaveapp_core::Error) -> Error {
    Error::SecureEnclave {
        operation: operation.into(),
        detail: e.to_string(),
    }
}

impl KeyBackend for LinuxBackend {
    fn generate(&self, opts: &KeyGenOptions) -> Result<KeyInfo> {
        let label_str = opts.label.as_str();

        if self.key_manager().public_key(label_str).is_ok() {
            return Err(Error::DuplicateLabel {
                label: label_str.to_string(),
            });
        }

        let policy = if opts.requires_user_presence {
            AccessPolicy::Any
        } else {
            AccessPolicy::None
        };

        let public_bytes = self
            .key_manager()
            .generate(label_str, KeyType::Signing, policy)
            .map_err(|e| map_err("generate", e))?;

        let keys_dir = sshenc_keys_dir();
        let mut meta =
            compat::load_sshenc_meta(&keys_dir, label_str).map_err(|e| map_err("load_meta", e))?;
        if let Some(ref comment) = opts.comment {
            meta.set_app_field("comment", comment.clone());
        }
        metadata::save_meta(&keys_dir, label_str, &meta).map_err(|e| map_err("save_meta", e))?;

        let ssh_pubkey = SshPublicKey::from_sec1_bytes(&public_bytes, opts.comment.clone())?;
        let (fp_sha256, fp_md5) = fingerprint::fingerprints(&ssh_pubkey);

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
