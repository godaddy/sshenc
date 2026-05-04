// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Key domain models and metadata types.

use enclaveapp_core::types::{AccessPolicy, PresenceMode};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

/// Application tag prefix used to identify sshenc-managed keys in the Keychain.
pub const APP_TAG_PREFIX: &str = "com.godaddy.sshenc.key.";

/// The key algorithm used by sshenc.
///
/// `EcdsaP256` is the legacy / default path, backed by Secure Enclave
/// (macOS), Microsoft Platform Crypto Provider (Windows), or
/// software/keyring/Linux-TPM. Consent on Windows is gated through
/// `UserConsentVerifier` -- a soft, user-mode UI prompt.
///
/// `SkEcdsaP256` is the FIDO2-SK variant, backed by the Windows
/// Hello platform authenticator via WebAuthN.dll on Windows (and
/// libfido2 on other platforms once we add support there). Consent
/// is hardware-enforced -- the TPM will not produce a signature
/// without an OS-mediated Hello gesture actually firing. The wire
/// format is `sk-ecdsa-sha2-nistp256@openssh.com` (OpenSSH 8.2+),
/// supported by stock OpenSSH sshd and GitHub.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyAlgorithm {
    /// ECDSA with NIST P-256 curve (secp256r1). Default path.
    EcdsaP256,
    /// FIDO2 SK / WebAuthn-backed ECDSA P-256. Opt-in via
    /// `sshenc keygen --strong` on Hello-enrolled Windows hosts.
    SkEcdsaP256,
}

impl fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyAlgorithm::EcdsaP256 => write!(f, "ecdsa-p256"),
            KeyAlgorithm::SkEcdsaP256 => write!(f, "sk-ecdsa-p256"),
        }
    }
}

impl KeyAlgorithm {
    /// Returns the key size in bits.
    pub fn key_bits(&self) -> u32 {
        match self {
            KeyAlgorithm::EcdsaP256 | KeyAlgorithm::SkEcdsaP256 => 256,
        }
    }

    /// Returns the SSH key type string (the leading token in an
    /// `authorized_keys` line and the type identifier in the SSH
    /// wire format).
    pub fn ssh_key_type(&self) -> &'static str {
        match self {
            KeyAlgorithm::EcdsaP256 => "ecdsa-sha2-nistp256",
            KeyAlgorithm::SkEcdsaP256 => "sk-ecdsa-sha2-nistp256@openssh.com",
        }
    }

    /// Returns the SSH curve identifier.
    pub fn ssh_curve_id(&self) -> &'static str {
        match self {
            KeyAlgorithm::EcdsaP256 | KeyAlgorithm::SkEcdsaP256 => "nistp256",
        }
    }

    /// True if this algorithm is the FIDO2 SK variant -- i.e. the
    /// signature blob carries a flags byte and counter, the public
    /// key wire format includes an `application` string, and signing
    /// goes through the platform authenticator (WebAuthn on Windows).
    pub fn is_sk(&self) -> bool {
        matches!(self, KeyAlgorithm::SkEcdsaP256)
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
    /// Full application tag (com.godaddy.sshenc.key.<label>).
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
    /// FIDO2 SK credential ID -- opaque blob the platform
    /// authenticator (Windows Hello / libfido2 / etc.) emits at
    /// `MakeCredential` time. Used at sign time to address the
    /// TPM-bound private key. `None` for non-SK algorithms.
    ///
    /// Stored as base64 in `.meta` files for human-readable
    /// inspection. Old `.meta` files without this field deserialize
    /// to `None`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "base64_bytes_option"
    )]
    pub credential_id: Option<Vec<u8>>,
    /// FIDO2 SK Relying Party identifier. We use a unique-per-key
    /// RP (e.g. `sshenc-<keyhash>.local`) so the Windows passkey
    /// chooser never has more than one entry to display. This is
    /// also the OpenSSH SK `application` string -- it gets
    /// SHA-256'd into the `rpIdHash` slot of authenticator data,
    /// and the SSH verifier reconstructs the same hash from this
    /// value embedded in the public key wire format. `None` for
    /// non-SK algorithms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
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
            credential_id: None,
            rp_id: None,
        }
    }

    /// Construct metadata for an SK (FIDO2) key. Captures the
    /// platform-authenticator credential identifier and unique
    /// per-key RP id alongside the standard fields.
    pub fn for_sk(
        label: KeyLabel,
        access_policy: AccessPolicy,
        presence_mode: Option<PresenceMode>,
        comment: Option<String>,
        credential_id: Vec<u8>,
        rp_id: String,
    ) -> Self {
        let app_tag = label.app_tag();
        KeyMetadata {
            label,
            app_tag,
            algorithm: KeyAlgorithm::SkEcdsaP256,
            access_policy,
            presence_mode,
            comment,
            credential_id: Some(credential_id),
            rp_id: Some(rp_id),
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

/// Serde helper for base64-encoding optional byte vectors. Used by
/// SK-specific fields on `KeyMetadata` so the absence of a
/// credential id doesn't show up as an empty string in `.meta` files.
mod base64_bytes_option {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(b) => s.serialize_str(&STANDARD.encode(b)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let opt = Option::<String>::deserialize(d)?;
        match opt {
            Some(s) => STANDARD
                .decode(&s)
                .map(Some)
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

/// Options for key generation (legacy `ecdsa-sha2-nistp256` path).
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

/// Options for SK (FIDO2 / WebAuthn) key generation. Kept as a
/// distinct struct from [`KeyGenOptions`] so the legacy path stays
/// byte-for-byte unchanged at every callsite (no
/// `algorithm: KeyAlgorithm` field bleeding into existing literals).
#[derive(Debug, Clone)]
pub struct SkKeyGenOptions {
    pub label: KeyLabel,
    pub comment: Option<String>,
    /// If set, write the SK public key (`sk-ecdsa-sha2-nistp256@openssh.com ...`)
    /// to this path.
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
        assert_eq!(label.app_tag(), "com.godaddy.sshenc.key.github-personal");
    }

    #[test]
    fn test_app_tag_prefix_constant() {
        assert_eq!(APP_TAG_PREFIX, "com.godaddy.sshenc.key.");
    }

    // --- KeyMetadata ---

    #[test]
    fn test_key_metadata_construction() {
        let label = KeyLabel::new("test").unwrap();
        let meta = KeyMetadata::new(label.clone(), AccessPolicy::Any, Some("comment".into()));
        assert_eq!(meta.label, label);
        assert_eq!(meta.app_tag, "com.godaddy.sshenc.key.test");
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
