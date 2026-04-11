// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Key domain models and metadata types.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

/// Application tag prefix used to identify sshenc-managed keys in the Keychain.
pub const APP_TAG_PREFIX: &str = "com.sshenc.key.";

/// The key algorithm used by sshenc (Secure Enclave only supports P-256).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyAlgorithm {
    /// ECDSA with NIST P-256 curve (secp256r1).
    EcdsaP256,
}

impl fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyAlgorithm::EcdsaP256 => write!(f, "ecdsa-p256"),
        }
    }
}

impl KeyAlgorithm {
    /// Returns the key size in bits.
    pub fn key_bits(&self) -> u32 {
        match self {
            KeyAlgorithm::EcdsaP256 => 256,
        }
    }

    /// Returns the SSH key type string.
    pub fn ssh_key_type(&self) -> &'static str {
        match self {
            KeyAlgorithm::EcdsaP256 => "ecdsa-sha2-nistp256",
        }
    }

    /// Returns the SSH curve identifier.
    pub fn ssh_curve_id(&self) -> &'static str {
        match self {
            KeyAlgorithm::EcdsaP256 => "nistp256",
        }
    }
}

/// A validated key label. Labels must be non-empty, ASCII alphanumeric plus hyphens
/// and underscores, and at most 64 characters.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct KeyLabel(String);

impl KeyLabel {
    /// Create a new KeyLabel, validating the input.
    pub fn new(label: &str) -> crate::error::Result<Self> {
        if label.is_empty() {
            return Err(crate::error::Error::InvalidLabel {
                reason: "label must not be empty".into(),
            });
        }
        if label.len() > 64 {
            return Err(crate::error::Error::InvalidLabel {
                reason: "label must be at most 64 characters".into(),
            });
        }
        if !label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(crate::error::Error::InvalidLabel {
                reason: "label must contain only ASCII alphanumeric, hyphens, or underscores"
                    .into(),
            });
        }
        Ok(KeyLabel(label.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the application tag for this key label.
    pub fn app_tag(&self) -> String {
        format!("{APP_TAG_PREFIX}{}", self.0)
    }
}

impl fmt::Display for KeyLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<KeyLabel> for String {
    fn from(label: KeyLabel) -> String {
        label.0
    }
}

impl TryFrom<String> for KeyLabel {
    type Error = crate::error::Error;
    fn try_from(s: String) -> crate::error::Result<Self> {
        KeyLabel::new(&s)
    }
}

/// Metadata about a Secure Enclave-backed key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Human-readable label.
    pub label: KeyLabel,
    /// Full application tag (com.sshenc.key.<label>).
    pub app_tag: String,
    /// Key algorithm.
    pub algorithm: KeyAlgorithm,
    /// Whether user presence (biometric/password) is required for signing.
    pub requires_user_presence: bool,
    /// Optional comment for the SSH public key line.
    pub comment: Option<String>,
}

impl KeyMetadata {
    pub fn new(label: KeyLabel, requires_user_presence: bool, comment: Option<String>) -> Self {
        let app_tag = label.app_tag();
        KeyMetadata {
            label,
            app_tag,
            algorithm: KeyAlgorithm::EcdsaP256,
            requires_user_presence,
            comment,
        }
    }
}

/// Full information about a key, including its public key material and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyInfo {
    /// Key metadata.
    pub metadata: KeyMetadata,
    /// The uncompressed SEC1 public key bytes (65 bytes: 0x04 || x || y).
    #[serde(with = "base64_bytes")]
    pub public_key_bytes: Vec<u8>,
    /// SSH fingerprint (SHA-256, base64-encoded).
    pub fingerprint_sha256: String,
    /// SSH fingerprint (MD5, hex-encoded).
    pub fingerprint_md5: String,
    /// Path to the .pub file if known.
    pub pub_file_path: Option<PathBuf>,
}

/// Serde helper for base64-encoding byte vectors.
mod base64_bytes {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

/// Options for key generation.
#[derive(Debug, Clone)]
pub struct KeyGenOptions {
    pub label: KeyLabel,
    pub comment: Option<String>,
    pub requires_user_presence: bool,
    /// If set, write the public key to this path.
    pub write_pub_path: Option<PathBuf>,
}
