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
