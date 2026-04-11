// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Test helpers, mocks, and fixtures for sshenc.
//!
//! Provides a [`MockKeyBackend`] that stores keys in memory, usable for
//! testing on any platform without Secure Enclave hardware.

pub mod mock;

pub use mock::MockKeyBackend;

/// Generate a deterministic test EC point from a seed byte.
pub fn test_ec_point(seed: u8) -> Vec<u8> {
    let mut point = vec![0x04];
    for i in 0u8..32 {
        point.push(seed.wrapping_mul(7).wrapping_add(i).wrapping_mul(3));
    }
    for i in 0u8..32 {
        point.push(seed.wrapping_mul(11).wrapping_add(i).wrapping_mul(5));
    }
    point
}

/// Generate a deterministic test DER-encoded ECDSA signature from seed data.
/// This produces a structurally valid DER signature (not cryptographically valid).
pub fn test_signature(data: &[u8], seed: u8) -> Vec<u8> {
    // Create a fake but structurally valid DER ECDSA signature.
    // SEQUENCE { INTEGER r, INTEGER s }
    let mut r = vec![0u8; 32];
    let mut s = vec![0u8; 32];
    for i in 0..32 {
        r[i] = data.get(i).copied().unwrap_or(0).wrapping_add(seed);
        s[i] = data
            .get(i + 32)
            .copied()
            .unwrap_or(0)
            .wrapping_add(seed.wrapping_mul(2));
    }
    // Ensure high bit isn't set (positive integers in DER)
    r[0] &= 0x7F;
    s[0] &= 0x7F;
    // Avoid leading zeros that would change the length
    if r[0] == 0 {
        r[0] = 1;
    }
    if s[0] == 0 {
        s[0] = 1;
    }

    let mut sig = Vec::new();
    // SEQUENCE tag
    sig.push(0x30);
    let inner_len = 2 + r.len() + 2 + s.len();
    sig.push(inner_len as u8);
    // INTEGER r
    sig.push(0x02);
    sig.push(r.len() as u8);
    sig.extend_from_slice(&r);
    // INTEGER s
    sig.push(0x02);
    sig.push(s.len() as u8);
    sig.extend_from_slice(&s);
    sig
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ec_point_length_and_prefix() {
        let point = test_ec_point(42);
        assert_eq!(
            point.len(),
            65,
            "EC point must be 65 bytes (0x04 + 32 + 32)"
        );
        assert_eq!(
            point[0], 0x04,
            "EC point must start with 0x04 (uncompressed)"
        );
    }

    #[test]
    fn test_ec_point_different_seeds_produce_different_points() {
        let p1 = test_ec_point(0);
        let p2 = test_ec_point(1);
        let p3 = test_ec_point(255);
        assert_ne!(p1, p2);
        assert_ne!(p1, p3);
        assert_ne!(p2, p3);
    }

    #[test]
    fn test_ec_point_deterministic() {
        let p1 = test_ec_point(99);
        let p2 = test_ec_point(99);
        assert_eq!(p1, p2, "same seed must produce same point");
    }

    #[test]
    fn test_signature_starts_with_der_sequence() {
        let sig = test_signature(b"hello", 1);
        assert_eq!(
            sig[0], 0x30,
            "DER signature must start with SEQUENCE tag 0x30"
        );
    }

    #[test]
    fn test_signature_structurally_valid_der() {
        let sig = test_signature(b"test data for signing", 7);
        // sig[0] = 0x30 (SEQUENCE)
        assert_eq!(sig[0], 0x30);
        let outer_len = sig[1] as usize;
        // Total length should be 2 (tag+len) + outer_len
        assert_eq!(sig.len(), 2 + outer_len);

        // First INTEGER
        let pos = 2;
        assert_eq!(sig[pos], 0x02, "first element must be INTEGER tag");
        let r_len = sig[pos + 1] as usize;
        // r bytes
        let r_bytes = &sig[pos + 2..pos + 2 + r_len];
        // High bit must not be set (positive integer)
        assert_eq!(r_bytes[0] & 0x80, 0, "r must be positive (high bit clear)");
        // r must not have a leading zero
        assert_ne!(r_bytes[0], 0, "r must not have leading zero");

        // Second INTEGER
        let pos2 = pos + 2 + r_len;
        assert_eq!(sig[pos2], 0x02, "second element must be INTEGER tag");
        let s_len = sig[pos2 + 1] as usize;
        let s_bytes = &sig[pos2 + 2..pos2 + 2 + s_len];
        assert_eq!(s_bytes[0] & 0x80, 0, "s must be positive (high bit clear)");
        assert_ne!(s_bytes[0], 0, "s must not have leading zero");

        // Should consume entire signature
        assert_eq!(pos2 + 2 + s_len, sig.len());
    }

    #[test]
    fn test_signature_deterministic() {
        let sig1 = test_signature(b"data", 5);
        let sig2 = test_signature(b"data", 5);
        assert_eq!(sig1, sig2, "same data+seed must produce same signature");
    }

    #[test]
    fn test_signature_different_data_produces_different_output() {
        let sig1 = test_signature(b"data-a", 5);
        let sig2 = test_signature(b"data-b", 5);
        assert_ne!(
            sig1, sig2,
            "different data should produce different signatures"
        );
    }

    #[test]
    fn test_signature_different_seed_produces_different_output() {
        let sig1 = test_signature(b"same-data", 1);
        let sig2 = test_signature(b"same-data", 2);
        assert_ne!(
            sig1, sig2,
            "different seeds should produce different signatures"
        );
    }

    #[test]
    fn test_signature_empty_data() {
        // Should not panic on empty data
        let sig = test_signature(b"", 10);
        assert_eq!(sig[0], 0x30);
        assert!(sig.len() > 10);
    }
}
