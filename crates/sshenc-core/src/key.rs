// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Key domain models and metadata types.

use enclaveapp_core::types::{AccessPolicy, PresenceMode};
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
    /// Persisted access policy for signing.
    pub access_policy: AccessPolicy,
    /// User-presence prompt cadence. `None` means the key signs
    /// silently; `Cached` batches one prompt per cache-TTL window;
    /// `Strict` prompts on every signature.
    ///
    /// Backwards compatibility: legacy `.meta` files written before
    /// this field existed deserialize without it. Call
    /// [`KeyMetadata::effective_presence_mode`] to read the value
    /// with the legacy migration default applied.
    #[serde(default)]
    pub presence_mode: Option<PresenceMode>,
    /// Optional comment for the SSH public key line.
    pub comment: Option<String>,
}

impl KeyMetadata {
    pub fn new(label: KeyLabel, access_policy: AccessPolicy, comment: Option<String>) -> Self {
        Self::with_presence_mode(label, access_policy, None, comment)
    }

    /// Construct metadata with an explicit presence mode. Pass
    /// `None` for `presence_mode` to leave the field unset; the
    /// migration default in [`Self::effective_presence_mode`] then
    /// preserves legacy behaviour.
    pub fn with_presence_mode(
        label: KeyLabel,
        access_policy: AccessPolicy,
        presence_mode: Option<PresenceMode>,
        comment: Option<String>,
    ) -> Self {
        let app_tag = label.app_tag();
        KeyMetadata {
            label,
            app_tag,
            algorithm: KeyAlgorithm::EcdsaP256,
            access_policy,
            presence_mode,
            comment,
        }
    }

    /// Return the effective `PresenceMode`. If the field is unset
    /// (legacy `.meta`), apply [`PresenceMode::migration_default`].
    pub fn effective_presence_mode(&self) -> PresenceMode {
        self.presence_mode
            .unwrap_or_else(|| PresenceMode::migration_default(self.access_policy))
    }

    pub fn requires_user_presence(&self) -> bool {
        self.effective_presence_mode() != PresenceMode::None
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
    pub access_policy: AccessPolicy,
    /// User-presence prompt cadence. `Cached` (default) batches
    /// prompts within the wrapping-key cache TTL; `Strict` prompts
    /// per sign; `None` does not prompt.
    pub presence_mode: PresenceMode,
    /// If set, write the public key to this path.
    pub write_pub_path: Option<PathBuf>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // --- KeyLabel validation ---

    #[test]
    fn test_key_label_valid_simple() {
        let label = KeyLabel::new("my-key_01").unwrap();
        assert_eq!(label.as_str(), "my-key_01");
    }

    #[test]
    fn test_key_label_valid_single_char() {
        let label = KeyLabel::new("a").unwrap();
        assert_eq!(label.as_str(), "a");
    }

    #[test]
    fn test_key_label_valid_max_length() {
        let s = "a".repeat(64);
        let label = KeyLabel::new(&s).unwrap();
        assert_eq!(label.as_str(), s);
    }

    #[test]
    fn test_key_label_empty() {
        let err = KeyLabel::new("").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("empty"), "expected 'empty' in error: {msg}");
    }

    #[test]
    fn test_key_label_too_long() {
        let s = "a".repeat(65);
        let err = KeyLabel::new(&s).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("64"), "expected '64' in error: {msg}");
    }

    #[test]
    fn test_key_label_invalid_space() {
        let err = KeyLabel::new("my key").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("alphanumeric"),
            "expected 'alphanumeric' in error: {msg}"
        );
    }

    #[test]
    fn test_key_label_invalid_dot() {
        assert!(KeyLabel::new("my.key").is_err());
    }

    #[test]
    fn test_key_label_invalid_slash() {
        assert!(KeyLabel::new("my/key").is_err());
    }

    #[test]
    fn test_key_label_invalid_unicode() {
        assert!(KeyLabel::new("clé").is_err());
    }

    // --- KeyLabel conversions ---

    #[test]
    fn test_key_label_display() {
        let label = KeyLabel::new("github-personal").unwrap();
        assert_eq!(format!("{label}"), "github-personal");
    }

    #[test]
    fn test_key_label_into_string() {
        let label = KeyLabel::new("work").unwrap();
        let s: String = label.into();
        assert_eq!(s, "work");
    }

    #[test]
    fn test_key_label_try_from_string_valid() {
        let label = KeyLabel::try_from("test-key".to_string()).unwrap();
        assert_eq!(label.as_str(), "test-key");
    }

    #[test]
    fn test_key_label_try_from_string_invalid() {
        assert!(KeyLabel::try_from("bad label!".to_string()).is_err());
    }

    // --- app_tag ---

    #[test]
    fn test_app_tag_format() {
        let label = KeyLabel::new("github-personal").unwrap();
        assert_eq!(label.app_tag(), "com.sshenc.key.github-personal");
    }

    #[test]
    fn test_app_tag_prefix_constant() {
        assert_eq!(APP_TAG_PREFIX, "com.sshenc.key.");
    }

    // --- KeyMetadata ---

    #[test]
    fn test_key_metadata_construction() {
        let label = KeyLabel::new("test").unwrap();
        let meta = KeyMetadata::new(label.clone(), AccessPolicy::Any, Some("comment".into()));
        assert_eq!(meta.label, label);
        assert_eq!(meta.app_tag, "com.sshenc.key.test");
        assert!(matches!(meta.algorithm, KeyAlgorithm::EcdsaP256));
        assert!(meta.requires_user_presence());
        assert_eq!(meta.access_policy, AccessPolicy::Any);
        assert_eq!(meta.comment.as_deref(), Some("comment"));
    }

    #[test]
    fn test_key_metadata_no_comment() {
        let label = KeyLabel::new("bare").unwrap();
        let meta = KeyMetadata::new(label, AccessPolicy::None, None);
        assert!(!meta.requires_user_presence());
        assert_eq!(meta.access_policy, AccessPolicy::None);
        assert!(meta.comment.is_none());
    }

    #[test]
    fn test_key_metadata_preserves_specific_access_policy() {
        let label = KeyLabel::new("bio").unwrap();
        let meta = KeyMetadata::new(label, AccessPolicy::BiometricOnly, None);
        assert!(meta.requires_user_presence());
        assert_eq!(meta.access_policy, AccessPolicy::BiometricOnly);
    }

    // --- KeyAlgorithm ---

    #[test]
    fn test_key_algorithm_display() {
        assert_eq!(KeyAlgorithm::EcdsaP256.to_string(), "ecdsa-p256");
    }

    #[test]
    fn test_key_algorithm_key_bits() {
        assert_eq!(KeyAlgorithm::EcdsaP256.key_bits(), 256);
    }

    #[test]
    fn test_key_algorithm_ssh_key_type() {
        assert_eq!(
            KeyAlgorithm::EcdsaP256.ssh_key_type(),
            "ecdsa-sha2-nistp256"
        );
    }

    #[test]
    fn test_key_algorithm_ssh_curve_id() {
        assert_eq!(KeyAlgorithm::EcdsaP256.ssh_curve_id(), "nistp256");
    }
}
