// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! SSH signature encoding for ECDSA-SHA2-NISTP256.
//!
//! OpenSSH expects ECDSA signatures in a specific format:
//! string("ecdsa-sha2-nistp256") || string(signature_blob)
//! where signature_blob = string(mpint(r)) || string(mpint(s))
//!
//! The Secure Enclave returns DER-encoded ECDSA signatures, so we need
//! to convert between DER and SSH wire format.

use p256::ecdsa::Signature;
use sshenc_core::error::{Error, Result};
use sshenc_core::key::KeyAlgorithm;
use sshenc_core::pubkey::write_ssh_string;

/// Convert a DER-encoded ECDSA signature to SSH wire format.
///
/// DER format: SEQUENCE { INTEGER r, INTEGER s }
/// SSH format: string("ecdsa-sha2-nistp256") || string(mpint(r) || mpint(s))
pub fn der_to_ssh_signature(der: &[u8]) -> Result<Vec<u8>> {
    // Parse DER via the p256 crate. from_der() validates the encoding and
    // returns a normalized (r, s) pair — each a 32-byte P-256 scalar.
    let sig = Signature::from_der(der)
        .map_err(|_| Error::AgentProtocol("invalid DER-encoded ECDSA signature".into()))?;

    // to_bytes() returns the fixed-size r || s concatenation (64 bytes total).
    let sig_bytes = sig.to_bytes();
    let r = &sig_bytes[..32];
    let s = &sig_bytes[32..];

    let mut inner = Vec::new();
    write_ssh_mpint(&mut inner, r);
    write_ssh_mpint(&mut inner, s);

    let mut result = Vec::new();
    write_ssh_string(
        &mut result,
        KeyAlgorithm::EcdsaP256.ssh_key_type().as_bytes(),
    );
    write_ssh_string(&mut result, &inner);

    Ok(result)
}

/// Write an SSH mpint (multi-precision integer) to a buffer.
///
/// SSH mpints are big-endian unsigned integers. A leading zero byte is
/// required when the high bit of the most significant byte is set, to
/// distinguish the value from a negative integer in the wire format.
/// p256 returns normalized 32-byte field elements (no leading zeros), so
/// this function adds the zero prefix as needed rather than stripping one.
fn write_ssh_mpint(buf: &mut Vec<u8>, value: &[u8]) {
    // Strip any redundant leading zeros first (guards against callers that
    // pass DER-style padding), then add the required SSH leading zero if
    // the high bit of the remaining first byte is set.
    let stripped = strip_leading_zeros(value);
    if stripped.first().is_some_and(|b| b & 0x80 != 0) {
        let mut padded = Vec::with_capacity(1 + stripped.len());
        padded.push(0x00);
        padded.extend_from_slice(stripped);
        write_ssh_string(buf, &padded);
    } else {
        write_ssh_string(buf, stripped);
    }
}

/// Strip leading zero bytes, keeping at least one byte.
fn strip_leading_zeros(data: &[u8]) -> &[u8] {
    if data.is_empty() {
        return data;
    }
    let mut i = 0;
    while i < data.len() - 1 && data[i] == 0 {
        i += 1;
    }
    &data[i..]
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Build a minimal valid DER ECDSA signature for testing.
    fn make_der_signature(r: &[u8], s: &[u8]) -> Vec<u8> {
        let mut inner = Vec::new();
        // INTEGER r
        inner.push(0x02);
        inner.push(r.len() as u8);
        inner.extend_from_slice(r);
        // INTEGER s
        inner.push(0x02);
        inner.push(s.len() as u8);
        inner.extend_from_slice(s);

        let mut der = Vec::new();
        der.push(0x30);
        der.push(inner.len() as u8);
        der.extend_from_slice(&inner);
        der
    }

    #[test]
    fn test_der_to_ssh_signature() {
        let r = vec![0x01; 32];
        let s = vec![0x02; 32];
        let der = make_der_signature(&r, &s);
        let ssh_sig = der_to_ssh_signature(&der).unwrap();

        // Parse back: should start with string("ecdsa-sha2-nistp256")
        let (algo, rest) = sshenc_core::pubkey::read_ssh_string(&ssh_sig).unwrap();
        assert_eq!(algo, b"ecdsa-sha2-nistp256");

        // Then string(mpint(r) || mpint(s))
        let (inner, _) = sshenc_core::pubkey::read_ssh_string(rest).unwrap();
        assert!(!inner.is_empty());
    }

    #[test]
    fn test_der_with_leading_zeros() {
        // r with leading zero (high bit set on next byte)
        let r = vec![0x00, 0x80, 0x01, 0x02];
        let s = vec![0x03; 32];
        let der = make_der_signature(&r, &s);
        let ssh_sig = der_to_ssh_signature(&der).unwrap();
        assert!(!ssh_sig.is_empty());
    }

    #[test]
    fn test_strip_leading_zeros() {
        assert_eq!(strip_leading_zeros(&[0, 0, 1, 2]), &[1, 2]);
        // Leading zero before a high-bit byte is stripped; write_ssh_mpint
        // re-adds it when encoding the SSH mpint.
        assert_eq!(strip_leading_zeros(&[0, 0x80, 1]), &[0x80, 1]);
        assert_eq!(strip_leading_zeros(&[1, 2, 3]), &[1, 2, 3]);
        assert_eq!(strip_leading_zeros(&[0]), &[0]);
    }

    #[test]
    fn test_invalid_der() {
        // Not a SEQUENCE
        assert!(der_to_ssh_signature(&[0x31, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]).is_err());
        // Too short
        assert!(der_to_ssh_signature(&[0x30]).is_err());
        // Empty
        assert!(der_to_ssh_signature(&[]).is_err());
    }

    #[test]
    fn test_real_sized_32_byte_values() {
        // Realistic 32-byte r and s values (low high bits, no leading zero needed)
        let r: Vec<u8> = (1..=32).collect();
        let s: Vec<u8> = (33..=64).collect();
        let der = make_der_signature(&r, &s);
        let ssh_sig = der_to_ssh_signature(&der).unwrap();

        // Verify outer structure
        let (algo, rest) = sshenc_core::pubkey::read_ssh_string(&ssh_sig).unwrap();
        assert_eq!(algo, b"ecdsa-sha2-nistp256");

        let (inner, tail) = sshenc_core::pubkey::read_ssh_string(rest).unwrap();
        assert!(tail.is_empty());

        // Parse inner: mpint(r) || mpint(s)
        let (parsed_r, remaining) = sshenc_core::pubkey::read_ssh_string(inner).unwrap();
        let (parsed_s, remaining2) = sshenc_core::pubkey::read_ssh_string(remaining).unwrap();
        assert!(remaining2.is_empty());

        assert_eq!(parsed_r, &r[..]);
        assert_eq!(parsed_s, &s[..]);
    }

    #[test]
    fn test_r_with_high_bit_set_leading_zero() {
        // r starts with 0x80 — DER will have a leading zero byte, SSH mpint should preserve it
        let mut r = vec![0x00]; // DER leading zero for positive representation
        r.push(0x80);
        r.extend_from_slice(&[0x01; 31]);
        // s is normal
        let s: Vec<u8> = vec![0x42; 32];

        let der = make_der_signature(&r, &s);
        let ssh_sig = der_to_ssh_signature(&der).unwrap();

        let (algo, rest) = sshenc_core::pubkey::read_ssh_string(&ssh_sig).unwrap();
        assert_eq!(algo, b"ecdsa-sha2-nistp256");

        let (inner, _) = sshenc_core::pubkey::read_ssh_string(rest).unwrap();
        let (parsed_r, remaining) = sshenc_core::pubkey::read_ssh_string(inner).unwrap();
        let (parsed_s, _) = sshenc_core::pubkey::read_ssh_string(remaining).unwrap();

        // The leading zero should be preserved because the next byte has high bit set
        assert_eq!(parsed_r[0], 0x00);
        assert_eq!(parsed_r[1], 0x80);
        assert_eq!(parsed_s, &s[..]);
    }

    #[test]
    fn test_both_r_and_s_high_bit() {
        // Both r and s have high bit set in their first real byte
        let r = vec![0x00, 0xFF, 0x01, 0x02, 0x03];
        let s = vec![0x00, 0x80, 0x04, 0x05, 0x06];
        let der = make_der_signature(&r, &s);
        let ssh_sig = der_to_ssh_signature(&der).unwrap();

        let (_, rest) = sshenc_core::pubkey::read_ssh_string(&ssh_sig).unwrap();
        let (inner, _) = sshenc_core::pubkey::read_ssh_string(rest).unwrap();
        let (parsed_r, remaining) = sshenc_core::pubkey::read_ssh_string(inner).unwrap();
        let (parsed_s, _) = sshenc_core::pubkey::read_ssh_string(remaining).unwrap();

        // Leading zeros preserved for both
        assert_eq!(parsed_r[0], 0x00);
        assert_eq!(parsed_r[1], 0xFF);
        assert_eq!(parsed_s[0], 0x00);
        assert_eq!(parsed_s[1], 0x80);
    }

    #[test]
    fn test_der_to_ssh_signature_known_bytes() {
        // Known r=1..32, s=33..64 should produce a deterministic SSH signature
        let r: Vec<u8> = (1..=32).collect();
        let s: Vec<u8> = (33..=64).collect();
        let der = make_der_signature(&r, &s);
        let ssh_sig = der_to_ssh_signature(&der).unwrap();

        // Parse outer: string("ecdsa-sha2-nistp256") || string(inner)
        let (algo, rest) = sshenc_core::pubkey::read_ssh_string(&ssh_sig).unwrap();
        assert_eq!(algo, b"ecdsa-sha2-nistp256");

        let (inner, tail) = sshenc_core::pubkey::read_ssh_string(rest).unwrap();
        assert!(tail.is_empty());

        // Parse inner: mpint(r) || mpint(s)
        let (parsed_r, remaining) = sshenc_core::pubkey::read_ssh_string(inner).unwrap();
        let (parsed_s, rest2) = sshenc_core::pubkey::read_ssh_string(remaining).unwrap();
        assert!(rest2.is_empty());

        assert_eq!(parsed_r, &r[..]);
        assert_eq!(parsed_s, &s[..]);
    }

    #[test]
    fn test_der_to_ssh_signature_minimum_length() {
        // Minimum valid DER: r=1 byte, s=1 byte
        let r = vec![0x01];
        let s = vec![0x02];
        let der = make_der_signature(&r, &s);
        let ssh_sig = der_to_ssh_signature(&der).unwrap();

        let (algo, rest) = sshenc_core::pubkey::read_ssh_string(&ssh_sig).unwrap();
        assert_eq!(algo, b"ecdsa-sha2-nistp256");

        let (inner, _) = sshenc_core::pubkey::read_ssh_string(rest).unwrap();
        let (parsed_r, remaining) = sshenc_core::pubkey::read_ssh_string(inner).unwrap();
        let (parsed_s, _) = sshenc_core::pubkey::read_ssh_string(remaining).unwrap();
        assert_eq!(parsed_r, &[0x01]);
        assert_eq!(parsed_s, &[0x02]);
    }

    #[test]
    fn test_der_to_ssh_signature_maximum_length_p256() {
        // P-256 DER with 33-byte integers: the leading 0x00 appears when the
        // high bit of the integer is set. Use values well within the P-256 order
        // (0x80 followed by 0x01 bytes) so p256 accepts the signature.
        let mut r = vec![0x00_u8, 0x80];
        r.extend_from_slice(&[0x01; 30]);
        let mut s = vec![0x00_u8, 0x80];
        s.extend_from_slice(&[0x02; 30]);
        let der = make_der_signature(&r, &s);
        let ssh_sig = der_to_ssh_signature(&der).unwrap();

        let (algo, rest) = sshenc_core::pubkey::read_ssh_string(&ssh_sig).unwrap();
        assert_eq!(algo, b"ecdsa-sha2-nistp256");

        let (inner, _) = sshenc_core::pubkey::read_ssh_string(rest).unwrap();
        let (parsed_r, remaining) = sshenc_core::pubkey::read_ssh_string(inner).unwrap();
        let (parsed_s, _) = sshenc_core::pubkey::read_ssh_string(remaining).unwrap();

        // write_ssh_mpint adds the leading zero when the high bit is set.
        assert_eq!(parsed_r[0], 0x00);
        assert_eq!(parsed_r[1], 0x80);
        assert_eq!(parsed_s[0], 0x00);
        assert_eq!(parsed_s[1], 0x80);
    }

    #[test]
    fn test_parse_der_signature_wrong_tag() {
        // First byte is 0x31 (SET) instead of 0x30 (SEQUENCE)
        let bad = vec![0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        let result = der_to_ssh_signature(&bad);
        assert!(result.is_err(), "wrong DER tag should fail");
    }

    #[test]
    fn test_parse_der_signature_truncated() {
        // Valid start but truncated in the middle
        let truncated = vec![0x30, 0x10, 0x02, 0x01];
        let result = der_to_ssh_signature(&truncated);
        assert!(result.is_err());
    }
}
