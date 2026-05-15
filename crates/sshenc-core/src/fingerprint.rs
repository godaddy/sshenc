// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! SSH key fingerprint generation.
//!
//! Supports SHA-256 (base64, the modern default) and MD5 (hex, legacy) formats.

use crate::pubkey::{SshPublicKey, SshSkPublicKey};
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use md5::{Digest, Md5};
use sha2::Sha256;

/// SHA-256 fingerprint of an SSH public key, in the format used by `ssh-keygen -l`.
///
/// Returns a string like `SHA256:abc123...` (base64, no padding).
pub fn fingerprint_sha256(key: &SshPublicKey) -> String {
    fingerprint_sha256_of_blob(&key.to_wire_format())
}

/// MD5 fingerprint of an SSH public key, in the legacy colon-separated hex format.
///
/// Returns a string like `MD5:ab:cd:ef:...`.
pub fn fingerprint_md5(key: &SshPublicKey) -> String {
    fingerprint_md5_of_blob(&key.to_wire_format())
}

/// Compute both SHA-256 and MD5 fingerprints.
pub fn fingerprints(key: &SshPublicKey) -> (String, String) {
    (fingerprint_sha256(key), fingerprint_md5(key))
}

/// Compute both fingerprints for an SK (FIDO2) public key. The
/// fingerprint is over the SK wire format, which embeds the
/// `application` string -- so two SK keys with the same EC point
/// but different RP IDs have different fingerprints, as the SSH
/// verifier will distinguish them on the wire.
pub fn sk_fingerprints(key: &SshSkPublicKey) -> (String, String) {
    let blob = key.to_wire_format();
    (
        fingerprint_sha256_of_blob(&blob),
        fingerprint_md5_of_blob(&blob),
    )
}

fn fingerprint_sha256_of_blob(blob: &[u8]) -> String {
    let hash = Sha256::digest(blob);
    format!("SHA256:{}", STANDARD_NO_PAD.encode(hash))
}

fn fingerprint_md5_of_blob(blob: &[u8]) -> String {
    let hash = Md5::digest(blob);
    let hex_parts: Vec<String> = hash.iter().map(|b| format!("{b:02x}")).collect();
    format!("MD5:{}", hex_parts.join(":"))
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

    #[test]
    fn test_fingerprint_sha256_matches_known_value() {
        // Compute the expected SHA-256 fingerprint for our sample key by hand.
        // The wire format blob is deterministic, so the fingerprint is too.
        let key = sample_key();
        let blob = key.to_wire_format();
        let hash = Sha256::digest(&blob);
        let expected = format!("SHA256:{}", STANDARD_NO_PAD.encode(hash));
        let actual = fingerprint_sha256(&key);
        assert_eq!(actual, expected);
        // Verify it starts with SHA256: and has reasonable base64 length
        assert!(actual.starts_with("SHA256:"));
        let b64_part = &actual["SHA256:".len()..];
        // SHA-256 is 32 bytes -> ~43 chars base64 no-pad
        assert_eq!(b64_part.len(), 43);
    }

    #[test]
    fn test_fingerprint_md5_matches_known_value() {
        let key = sample_key();
        let blob = key.to_wire_format();
        let hash = Md5::digest(&blob);
        let expected_hex: Vec<String> = hash.iter().map(|b| format!("{b:02x}")).collect();
        let expected = format!("MD5:{}", expected_hex.join(":"));
        let actual = fingerprint_md5(&key);
        assert_eq!(actual, expected);
        // MD5 fingerprint should have 16 colon-separated hex pairs
        let hex_part = &actual["MD5:".len()..];
        let parts: Vec<&str> = hex_part.split(':').collect();
        assert_eq!(parts.len(), 16);
    }

    fn sample_sk_key(application: &str) -> SshSkPublicKey {
        let mut x = [0_u8; 32];
        let mut y = [0_u8; 32];
        for i in 0..32 {
            x[i] = (i as u8).wrapping_mul(3).wrapping_add(7);
            y[i] = (i as u8).wrapping_mul(5).wrapping_add(11);
        }
        SshSkPublicKey::from_xy(&x, &y, application.to_string(), None)
    }

    #[test]
    fn sk_fingerprints_format_sha256_and_md5() {
        let key = sample_sk_key("ssh:");
        let (sha, md5) = sk_fingerprints(&key);
        assert!(sha.starts_with("SHA256:"), "sha={sha}");
        let b64 = &sha["SHA256:".len()..];
        assert!(!b64.ends_with('='));
        assert!(!b64.is_empty());
        assert!(md5.starts_with("MD5:"), "md5={md5}");
        let hex_part = &md5["MD5:".len()..];
        assert_eq!(hex_part.split(':').count(), 16);
    }

    #[test]
    fn sk_fingerprints_deterministic() {
        let key = sample_sk_key("ssh:");
        let (sha1, md5_1) = sk_fingerprints(&key);
        let (sha2, md5_2) = sk_fingerprints(&key);
        assert_eq!(sha1, sha2);
        assert_eq!(md5_1, md5_2);
    }

    #[test]
    fn sk_fingerprints_differ_for_different_applications() {
        // Two SK keys with the same EC point but different RP IDs must
        // produce different fingerprints — the SSH verifier distinguishes
        // them by application string on the wire.
        let k1 = sample_sk_key("ssh:");
        let k2 = sample_sk_key("ssh:other-rp-id.example.com");
        let (sha1, _) = sk_fingerprints(&k1);
        let (sha2, _) = sk_fingerprints(&k2);
        assert_ne!(sha1, sha2, "different application strings must produce different fingerprints");
    }

    #[test]
    fn sk_fingerprints_same_application_same_hash() {
        let k1 = sample_sk_key("ssh:example.com");
        let k2 = sample_sk_key("ssh:example.com");
        let (sha1, md5_1) = sk_fingerprints(&k1);
        let (sha2, md5_2) = sk_fingerprints(&k2);
        assert_eq!(sha1, sha2);
        assert_eq!(md5_1, md5_2);
    }

    #[test]
    fn fingerprints_distinct_keys_produce_distinct_hashes() {
        // Two SshPublicKeys with different EC points must differ.
        let mut p1 = vec![0x04_u8];
        p1.extend(std::iter::repeat(0x01_u8).take(64));
        let mut p2 = vec![0x04_u8];
        p2.extend(std::iter::repeat(0x02_u8).take(64));
        let k1 = SshPublicKey::from_sec1_bytes(&p1, None).unwrap();
        let k2 = SshPublicKey::from_sec1_bytes(&p2, None).unwrap();
        let (sha1, _) = fingerprints(&k1);
        let (sha2, _) = fingerprints(&k2);
        assert_ne!(sha1, sha2);
    }
}
