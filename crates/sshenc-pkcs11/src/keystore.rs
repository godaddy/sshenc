// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Key store for the PKCS#11 provider.
//!
//! Loads Secure Enclave keys and legacy SSH keys from ~/.ssh/ and exposes
//! them as PKCS#11 objects. Each key produces two objects: a public key
//! and a private key, with sequential handles.

use crate::types::*;
use ssh_key::private::PrivateKey;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Well-known SSH private key filenames.
const WELL_KNOWN_KEY_FILES: &[&str] = &[
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    "id_ecdsa_sk",
    "id_ed25519_sk",
];

/// A key managed by the PKCS#11 provider.
pub enum KeyEntry {
    /// A Secure Enclave key (sign via Security.framework).
    #[cfg(target_os = "macos")]
    SecureEnclave {
        label: String,
        /// Uncompressed SEC1 EC point (65 bytes).
        ec_point: Vec<u8>,
        /// Application tag for SE lookup.
        app_tag: String,
    },
    /// A legacy SSH key loaded from a file.
    Legacy {
        label: String,
        private_key: Box<PrivateKey>,
    },
}

impl KeyEntry {
    pub fn label(&self) -> &str {
        match self {
            #[cfg(target_os = "macos")]
            KeyEntry::SecureEnclave { label, .. } => label,
            KeyEntry::Legacy { label, .. } => label,
        }
    }

    /// Return the PKCS#11 key type constant.
    pub fn key_type(&self) -> u64 {
        match self {
            #[cfg(target_os = "macos")]
            KeyEntry::SecureEnclave { .. } => CKK_EC,
            KeyEntry::Legacy { private_key, .. } => match private_key.algorithm() {
                ssh_key::Algorithm::Rsa { .. } => CKK_RSA,
                ssh_key::Algorithm::Ecdsa { .. } => CKK_EC,
                _ => CKK_EC, // Ed25519 mapped to EC for PKCS#11 purposes
            },
        }
    }

    /// Sign data with this key. Returns the raw signature bytes.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        match self {
            #[cfg(target_os = "macos")]
            KeyEntry::SecureEnclave { app_tag, .. } => {
                let sec_key = sshenc_ffi_apple::keychain::find_key_by_tag(app_tag)
                    .map_err(|e| e.to_string())?;
                sshenc_ffi_apple::keychain::sign_data(&sec_key, data).map_err(|e| e.to_string())
            }
            KeyEntry::Legacy { private_key, .. } => {
                use signature::Signer;
                let sig = private_key.try_sign(data).map_err(|e| e.to_string())?;
                Ok(sig.as_bytes().to_vec())
            }
        }
    }

    /// Get the public key blob in a format suitable for PKCS#11 attributes.
    /// For EC keys: returns the uncompressed EC point (DER OCTET STRING wrapped).
    /// For RSA keys: returns (modulus, exponent) via a separate method.
    pub fn ec_point_der(&self) -> Option<Vec<u8>> {
        match self {
            #[cfg(target_os = "macos")]
            KeyEntry::SecureEnclave { ec_point, .. } => {
                // Wrap the raw EC point in a DER OCTET STRING for CKA_EC_POINT.
                Some(der_octet_string(ec_point))
            }
            KeyEntry::Legacy { private_key, .. } => {
                if let ssh_key::public::KeyData::Ecdsa(ec) = private_key.public_key().key_data() {
                    let point_bytes = ec.as_sec1_bytes();
                    Some(der_octet_string(point_bytes))
                } else {
                    None
                }
            }
        }
    }

    /// For EC keys, return the DER-encoded OID for the curve.
    pub fn ec_params_der(&self) -> Option<Vec<u8>> {
        match self {
            #[cfg(target_os = "macos")]
            KeyEntry::SecureEnclave { .. } => {
                // P-256 OID: 1.2.840.10045.3.1.7
                Some(P256_OID_DER.to_vec())
            }
            KeyEntry::Legacy { private_key, .. } => match private_key.public_key().key_data() {
                ssh_key::public::KeyData::Ecdsa(ec) => match ec.curve() {
                    ssh_key::EcdsaCurve::NistP256 => Some(P256_OID_DER.to_vec()),
                    ssh_key::EcdsaCurve::NistP384 => Some(P384_OID_DER.to_vec()),
                    ssh_key::EcdsaCurve::NistP521 => Some(P521_OID_DER.to_vec()),
                },
                _ => None,
            },
        }
    }

    /// For RSA keys, return (modulus, public_exponent) as raw bytes.
    pub fn rsa_params(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        match self {
            KeyEntry::Legacy { private_key, .. } => {
                if let ssh_key::public::KeyData::Rsa(rsa) = private_key.public_key().key_data() {
                    Some((rsa.n.as_bytes().to_vec(), rsa.e.as_bytes().to_vec()))
                } else {
                    None
                }
            }
            #[cfg(target_os = "macos")]
            _ => None,
        }
    }

    /// Get the key ID bytes (used for CKA_ID to link public/private objects).
    pub fn key_id(&self) -> Vec<u8> {
        self.label().as_bytes().to_vec()
    }
}

// DER-encoded OID for NIST P-256 (secp256r1): 1.2.840.10045.3.1.7
const P256_OID_DER: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
// DER-encoded OID for NIST P-384 (secp384r1): 1.3.132.0.34
const P384_OID_DER: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
// DER-encoded OID for NIST P-521 (secp521r1): 1.3.132.0.35
const P521_OID_DER: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23];

/// Wrap raw bytes in a DER OCTET STRING.
fn der_octet_string(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + data.len());
    out.push(0x04); // OCTET STRING tag
    if data.len() < 128 {
        out.push(data.len() as u8);
    } else if data.len() < 256 {
        out.push(0x81);
        out.push(data.len() as u8);
    } else {
        out.push(0x82);
        out.push((data.len() >> 8) as u8);
        out.push(data.len() as u8);
    }
    out.extend_from_slice(data);
    out
}

/// The key store holds all loaded keys and provides PKCS#11 object handles.
///
/// Object handles are assigned as: key index * 2 + 1 for private key,
/// key index * 2 + 2 for public key. Handle 0 is invalid.
pub struct KeyStore {
    pub keys: Vec<KeyEntry>,
}

#[allow(dead_code)]
impl KeyStore {
    /// Number of PKCS#11 objects (2 per key: public + private).
    pub fn object_count(&self) -> usize {
        self.keys.len() * 2
    }

    /// Check if a handle is valid.
    pub fn is_valid_handle(&self, handle: u64) -> bool {
        handle >= 1 && handle <= self.object_count() as u64
    }

    /// Check if a handle refers to a private key.
    pub fn is_private_key(&self, handle: u64) -> bool {
        handle >= 1 && (handle % 2) == 1
    }

    /// Check if a handle refers to a public key.
    pub fn is_public_key(&self, handle: u64) -> bool {
        handle >= 1 && (handle % 2) == 0
    }

    /// Get the key entry for a handle.
    pub fn key_for_handle(&self, handle: u64) -> Option<&KeyEntry> {
        if !self.is_valid_handle(handle) {
            return None;
        }
        let idx = ((handle - 1) / 2) as usize;
        self.keys.get(idx)
    }

    /// Get all object handles matching a class filter (or all if None).
    pub fn find_objects(&self, class_filter: Option<u64>) -> Vec<u64> {
        let mut handles = Vec::new();
        for i in 0..self.keys.len() {
            let priv_handle = (i as u64) * 2 + 1;
            let pub_handle = (i as u64) * 2 + 2;
            match class_filter {
                Some(CKO_PRIVATE_KEY) => handles.push(priv_handle),
                Some(CKO_PUBLIC_KEY) => handles.push(pub_handle),
                None => {
                    handles.push(priv_handle);
                    handles.push(pub_handle);
                }
                _ => {}
            }
        }
        handles
    }
}

/// Load all available keys (SE + legacy) and build a KeyStore.
pub fn load_keys() -> KeyStore {
    let mut keys = Vec::new();

    // Load Secure Enclave keys
    #[cfg(target_os = "macos")]
    {
        if let Ok(tags) = sshenc_ffi_apple::keychain::list_key_tags() {
            for (app_tag, label) in tags {
                if let Ok(sec_key) = sshenc_ffi_apple::keychain::find_key_by_tag(&app_tag) {
                    if let Ok(ec_point) =
                        sshenc_ffi_apple::keychain::extract_public_key_bytes(&sec_key)
                    {
                        keys.push(KeyEntry::SecureEnclave {
                            label,
                            ec_point,
                            app_tag,
                        });
                    }
                }
            }
        }
    }

    // Load legacy SSH keys from ~/.ssh/
    let ssh_dir = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".ssh");

    if ssh_dir.is_dir() {
        let mut candidates: HashSet<PathBuf> = HashSet::new();

        for name in WELL_KNOWN_KEY_FILES {
            let path = ssh_dir.join(name);
            if path.is_file() {
                candidates.insert(path);
            }
        }

        if let Ok(entries) = std::fs::read_dir(&ssh_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(ext) = path.extension() {
                    if ext == "pub" {
                        let private_path = path.with_extension("");
                        if private_path.is_file() {
                            candidates.insert(private_path);
                        }
                    }
                }
            }
        }

        for path in &candidates {
            if let Ok(content) = std::fs::read_to_string(path) {
                if let Ok(pk) = PrivateKey::from_openssh(&content) {
                    let label = read_pub_comment(path).unwrap_or_else(|| {
                        path.file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_string()
                    });
                    keys.push(KeyEntry::Legacy {
                        label,
                        private_key: Box::new(pk),
                    });
                }
            }
        }
    }

    KeyStore { keys }
}

/// Try to read the comment from a .pub file.
fn read_pub_comment(private_key_path: &Path) -> Option<String> {
    let pub_path = private_key_path.with_extension("pub");
    let content = std::fs::read_to_string(&pub_path).ok()?;
    let first_line = content.lines().next()?;
    let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
    parts.get(2).map(|s| s.to_string())
}
