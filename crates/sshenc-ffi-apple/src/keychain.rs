// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Low-level Apple Security.framework Keychain / Secure Enclave operations.
//!
//! ## Apple APIs Used
//!
//! - `SecKeyCreateRandomKey` — Generate a new Secure Enclave-backed P-256 key.
//! - `SecItemCopyMatching` — Look up keys by application tag / label.
//! - `SecItemDelete` — Delete keys from the Keychain.
//! - `SecKeyCopyPublicKey` — Extract the public key from a private key reference.
//! - `SecKeyCopyExternalRepresentation` — Export public key bytes (SEC1 format).
//! - `SecKeyCreateSignature` — Sign data using a Secure Enclave-backed private key.
//! - `SecAccessControlCreateWithFlags` — Create access control for key generation
//!   (private key protection, user presence requirements).
//!
//! ## Key Tagging
//!
//! All sshenc-managed keys use a label prefixed with `sshenc:` followed by the
//! user-provided label. This allows sshenc to enumerate only its own keys
//! without touching unrelated Keychain items. The application tag stores the
//! full tag string (`com.sshenc.key.<label>`) as raw bytes.

use core_foundation::base::{CFOptionFlags, CFTypeRef, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::key::{Algorithm, SecKey};
use security_framework_sys::access_control::{
    kSecAccessControlPrivateKeyUsage, kSecAccessControlUserPresence,
};
use security_framework_sys::base::errSecItemNotFound;
use security_framework_sys::item::{
    kSecAttrAccessControl, kSecAttrKeyClass, kSecAttrKeyClassPrivate, kSecAttrKeySizeInBits,
    kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom, kSecAttrLabel, kSecAttrTokenID,
    kSecAttrTokenIDSecureEnclave, kSecClass, kSecClassKey, kSecMatchLimit, kSecMatchLimitAll,
    kSecPrivateKeyAttrs, kSecReturnAttributes, kSecReturnRef,
};
use security_framework_sys::key::SecKeyCreateRandomKey;
use security_framework_sys::keychain_item::{SecItemCopyMatching, SecItemDelete};
use std::ptr;
use thiserror::Error;

/// The label prefix used to identify sshenc-managed keys in the Keychain.
pub const SSHENC_LABEL_PREFIX: &str = "sshenc:";

/// The application tag prefix for sshenc-managed keys (stored as raw bytes).
pub const SSHENC_TAG_PREFIX: &str = "com.sshenc.key.";

#[derive(Debug, Error)]
pub enum AppleError {
    #[error("Security framework error: {0}")]
    SecurityFramework(#[from] security_framework::base::Error),
    #[error("key generation failed: {0}")]
    KeyGeneration(String),
    #[error("key not found")]
    KeyNotFound,
    #[error("public key extraction failed: {0}")]
    PublicKeyExtraction(String),
    #[error("signing failed: {0}")]
    Signing(String),
    #[error("key deletion failed: {0}")]
    Deletion(String),
    #[error("multiple keys match the query")]
    AmbiguousMatch,
}

pub type Result<T> = std::result::Result<T, AppleError>;

/// Check if the Secure Enclave is available on this system.
pub fn is_secure_enclave_available() -> bool {
    cfg!(target_os = "macos")
}

// kSecAttrApplicationTag is not exposed by the security-framework-sys crate.
// We link it from the Security framework directly.
extern "C" {
    static kSecAttrApplicationTag: core_foundation_sys::string::CFStringRef;
}

/// Generate a new Secure Enclave-backed P-256 key pair.
///
/// Returns the `SecKey` reference to the private key. The private key material
/// never leaves the Secure Enclave.
pub fn generate_key(app_tag: &str, label: &str, require_user_presence: bool) -> Result<SecKey> {
    let tag_data = CFData::from_buffer(app_tag.as_bytes());
    let se_label = format!("{SSHENC_LABEL_PREFIX}{label}");
    let label_str = CFString::new(&se_label);
    let key_size = CFNumber::from(256i32);

    // Build access control flags
    let mut flags: CFOptionFlags = kSecAccessControlPrivateKeyUsage;
    if require_user_presence {
        flags |= kSecAccessControlUserPresence;
    }

    let access_control = SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenPasscodeSetThisDeviceOnly),
        flags,
    )?;

    // Private key attributes
    let private_key_attrs = unsafe {
        CFDictionary::from_CFType_pairs(&[
            (
                CFString::wrap_under_get_rule(kSecAttrApplicationTag),
                tag_data.as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrAccessControl),
                access_control.as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrLabel),
                label_str.as_CFType(),
            ),
        ])
    };

    // Key generation parameters
    let params = unsafe {
        CFDictionary::from_CFType_pairs(&[
            (
                CFString::wrap_under_get_rule(kSecAttrKeyType),
                CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom).as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrKeySizeInBits),
                key_size.as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrTokenID),
                CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave).as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecPrivateKeyAttrs),
                private_key_attrs.as_CFType(),
            ),
        ])
    };

    let mut error: core_foundation_sys::error::CFErrorRef = ptr::null_mut();
    let key = unsafe { SecKeyCreateRandomKey(params.as_concrete_TypeRef(), &mut error) };

    if key.is_null() {
        if !error.is_null() {
            let err = unsafe { core_foundation::error::CFError::wrap_under_create_rule(error) };
            return Err(AppleError::KeyGeneration(format!("{err}")));
        }
        return Err(AppleError::KeyGeneration("unknown error".into()));
    }

    Ok(unsafe { SecKey::wrap_under_create_rule(key) })
}

/// Look up a Secure Enclave private key by application tag.
pub fn find_key_by_tag(app_tag: &str) -> Result<SecKey> {
    let tag_data = CFData::from_buffer(app_tag.as_bytes());

    let query = unsafe {
        CFDictionary::from_CFType_pairs(&[
            (
                CFString::wrap_under_get_rule(kSecClass),
                CFString::wrap_under_get_rule(kSecClassKey).as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrKeyClass),
                CFString::wrap_under_get_rule(kSecAttrKeyClassPrivate).as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrKeyType),
                CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom).as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrApplicationTag),
                tag_data.as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecReturnRef),
                CFBoolean::true_value().as_CFType(),
            ),
        ])
    };

    let mut result: CFTypeRef = ptr::null_mut();
    let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result) };

    if status == errSecItemNotFound {
        return Err(AppleError::KeyNotFound);
    }
    if status != 0 {
        return Err(AppleError::SecurityFramework(
            security_framework::base::Error::from_code(status),
        ));
    }

    Ok(unsafe { SecKey::wrap_under_create_rule(result as _) })
}

/// List all sshenc-managed keys by searching for keys with the sshenc label prefix.
///
/// Returns a list of (application_tag, label) pairs for each found key.
pub fn list_key_tags() -> Result<Vec<(String, String)>> {
    // We search for all EC private keys and filter client-side by label prefix,
    // because SecItemCopyMatching doesn't support prefix matching.
    let query = unsafe {
        CFDictionary::from_CFType_pairs(&[
            (
                CFString::wrap_under_get_rule(kSecClass),
                CFString::wrap_under_get_rule(kSecClassKey).as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrKeyClass),
                CFString::wrap_under_get_rule(kSecAttrKeyClassPrivate).as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrKeyType),
                CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom).as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecReturnAttributes),
                CFBoolean::true_value().as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecReturnRef),
                CFBoolean::true_value().as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecMatchLimit),
                CFString::wrap_under_get_rule(kSecMatchLimitAll).as_CFType(),
            ),
        ])
    };

    let mut result: CFTypeRef = ptr::null_mut();
    let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result) };

    if status == errSecItemNotFound {
        return Ok(Vec::new());
    }
    if status != 0 {
        return Err(AppleError::SecurityFramework(
            security_framework::base::Error::from_code(status),
        ));
    }

    // Result is a CFArray of CFDictionary
    let array = unsafe {
        core_foundation::array::CFArray::<CFDictionary>::wrap_under_create_rule(result as _)
    };

    let mut keys = Vec::new();

    for i in 0..array.len() {
        let dict = unsafe { array.get_unchecked(i) };
        // Extract label
        let label_key = unsafe { CFString::wrap_under_get_rule(kSecAttrLabel) };
        if let Some(label_val) = dict.find(label_key.as_CFTypeRef()) {
            let label_cf = unsafe { CFString::wrap_under_get_rule(*label_val as _) };
            let label_str = label_cf.to_string();

            if label_str.starts_with(SSHENC_LABEL_PREFIX) {
                let user_label = label_str
                    .strip_prefix(SSHENC_LABEL_PREFIX)
                    .unwrap_or(&label_str)
                    .to_string();
                let app_tag = format!("{SSHENC_TAG_PREFIX}{user_label}");
                keys.push((app_tag, user_label));
            }
        }
    }

    Ok(keys)
}

/// Extract the public key bytes (uncompressed SEC1 format) from a private key.
pub fn extract_public_key_bytes(private_key: &SecKey) -> Result<Vec<u8>> {
    let public_key = private_key.public_key().ok_or_else(|| {
        AppleError::PublicKeyExtraction("failed to get public key from private key".into())
    })?;

    let external = public_key.external_representation().ok_or_else(|| {
        AppleError::PublicKeyExtraction("failed to get external representation".into())
    })?;

    let bytes = external.bytes().to_vec();

    // Validate: should be 65 bytes (0x04 || 32-byte X || 32-byte Y)
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(AppleError::PublicKeyExtraction(format!(
            "unexpected public key format: {} bytes, prefix 0x{:02x}",
            bytes.len(),
            bytes.first().copied().unwrap_or(0)
        )));
    }

    Ok(bytes)
}

/// Sign data using a Secure Enclave-backed private key.
///
/// Uses ECDSA with SHA-256 (the standard for P-256 SSH keys).
/// Returns the DER-encoded ECDSA signature.
pub fn sign_data(private_key: &SecKey, data: &[u8]) -> Result<Vec<u8>> {
    let algorithm = Algorithm::ECDSASignatureMessageX962SHA256;
    let signature = private_key
        .create_signature(algorithm, data)
        .map_err(|e| AppleError::Signing(format!("{e}")))?;
    Ok(signature)
}

/// Delete a key from the Keychain by its application tag.
pub fn delete_key_by_tag(app_tag: &str) -> Result<()> {
    let tag_data = CFData::from_buffer(app_tag.as_bytes());

    let query = unsafe {
        CFDictionary::from_CFType_pairs(&[
            (
                CFString::wrap_under_get_rule(kSecClass),
                CFString::wrap_under_get_rule(kSecClassKey).as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrKeyClass),
                CFString::wrap_under_get_rule(kSecAttrKeyClassPrivate).as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrApplicationTag),
                tag_data.as_CFType(),
            ),
        ])
    };

    let status = unsafe { SecItemDelete(query.as_concrete_TypeRef()) };

    if status == errSecItemNotFound {
        return Err(AppleError::KeyNotFound);
    }
    if status != 0 {
        return Err(AppleError::Deletion(format!(
            "SecItemDelete returned {status}"
        )));
    }

    Ok(())
}
