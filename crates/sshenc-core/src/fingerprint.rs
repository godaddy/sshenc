// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! SSH key fingerprint generation.
//!
//! Supports SHA-256 (base64, the modern default) and MD5 (hex, legacy) formats.

use crate::pubkey::SshPublicKey;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use md5::{Digest, Md5};
use sha2::Sha256;

/// SHA-256 fingerprint of an SSH public key, in the format used by `ssh-keygen -l`.
///
/// Returns a string like `SHA256:abc123...` (base64, no padding).
pub fn fingerprint_sha256(key: &SshPublicKey) -> String {
    let blob = key.to_wire_format();
    let hash = Sha256::digest(&blob);
    let encoded = STANDARD_NO_PAD.encode(hash);
    format!("SHA256:{encoded}")
}

/// MD5 fingerprint of an SSH public key, in the legacy colon-separated hex format.
///
/// Returns a string like `MD5:ab:cd:ef:...`.
pub fn fingerprint_md5(key: &SshPublicKey) -> String {
    let blob = key.to_wire_format();
    let hash = Md5::digest(&blob);
    let hex_parts: Vec<String> = hash.iter().map(|b| format!("{b:02x}")).collect();
    format!("MD5:{}", hex_parts.join(":"))
}

/// Compute both SHA-256 and MD5 fingerprints.
pub fn fingerprints(key: &SshPublicKey) -> (String, String) {
    (fingerprint_sha256(key), fingerprint_md5(key))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn sample_key() -> SshPublicKey {
        let mut point = vec![0x04];
        for i in 0..32 {
            point.push((i * 7 + 3) as u8);
        }
        for i in 0..32 {
            point.push((i * 11 + 5) as u8);
        }
        SshPublicKey::from_sec1_bytes(&point, None).unwrap()
    }

    #[test]
    fn test_sha256_fingerprint_format() {
        let key = sample_key();
        let fp = fingerprint_sha256(&key);
        assert!(fp.starts_with("SHA256:"));
        // Base64 without padding
        let b64 = &fp["SHA256:".len()..];
        assert!(!b64.ends_with('='));
        assert!(!b64.is_empty());
    }

    #[test]
    fn test_md5_fingerprint_format() {
        let key = sample_key();
        let fp = fingerprint_md5(&key);
        assert!(fp.starts_with("MD5:"));
        let hex_part = &fp["MD5:".len()..];
        let parts: Vec<&str> = hex_part.split(':').collect();
        assert_eq!(parts.len(), 16); // MD5 is 16 bytes
        for part in &parts {
            assert_eq!(part.len(), 2);
        }
    }

    #[test]
    fn test_fingerprints_deterministic() {
        let key = sample_key();
        let (sha, md5) = fingerprints(&key);
        let (sha2, md5_2) = fingerprints(&key);
        assert_eq!(sha, sha2);
        assert_eq!(md5, md5_2);
    }
}
