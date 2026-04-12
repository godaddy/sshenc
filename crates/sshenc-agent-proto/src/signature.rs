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

use sshenc_core::error::{Error, Result};
use sshenc_core::key::KeyAlgorithm;
use sshenc_core::pubkey::write_ssh_string;

/// Convert a DER-encoded ECDSA signature to SSH wire format.
///
/// DER format: SEQUENCE { INTEGER r, INTEGER s }
/// SSH format: string("ecdsa-sha2-nistp256") || string(mpint(r) || mpint(s))
pub fn der_to_ssh_signature(der: &[u8]) -> Result<Vec<u8>> {
    let (r, s) = parse_der_signature(der)?;

    // Build the inner signature blob: mpint(r) || mpint(s)
    let mut inner = Vec::new();
    write_ssh_mpint(&mut inner, &r);
    write_ssh_mpint(&mut inner, &s);

    // Build the outer signature: string(algorithm) || string(inner)
    let mut sig = Vec::new();
    write_ssh_string(&mut sig, KeyAlgorithm::EcdsaP256.ssh_key_type().as_bytes());
    write_ssh_string(&mut sig, &inner);

    Ok(sig)
}

/// Parse a DER-encoded ECDSA signature into (r, s) byte vectors.
fn parse_der_signature(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if der.len() < 6 {
        return Err(Error::AgentProtocol("DER signature too short".into()));
    }
    if der[0] != 0x30 {
        return Err(Error::AgentProtocol(format!(
            "expected SEQUENCE tag (0x30), got 0x{:02x}",
            der[0]
        )));
    }

    let (seq_len, offset) = read_der_length(&der[1..])?;
    let seq_data = &der[offset + 1..];
    if seq_data.len() < seq_len {
        return Err(Error::AgentProtocol("DER sequence truncated".into()));
    }

    let (r, rest) = read_der_integer(seq_data)?;
    let (s, _) = read_der_integer(rest)?;

    Ok((r, s))
}

/// Read a DER length field. Returns (length, bytes_consumed).
fn read_der_length(data: &[u8]) -> Result<(usize, usize)> {
    if data.is_empty() {
        return Err(Error::AgentProtocol("unexpected end of DER data".into()));
    }
    if data[0] < 0x80 {
        Ok((data[0] as usize, 1))
    } else {
        let num_bytes = (data[0] & 0x7F) as usize;
        if num_bytes == 0 || num_bytes > 4 || data.len() < 1 + num_bytes {
            return Err(Error::AgentProtocol("invalid DER length".into()));
        }
        let mut len = 0_usize;
        for i in 0..num_bytes {
            len = (len << 8) | (data[1 + i] as usize);
        }
        Ok((len, 1 + num_bytes))
    }
}

/// Read a DER INTEGER, returning (value_bytes, remaining_data).
fn read_der_integer(data: &[u8]) -> Result<(Vec<u8>, &[u8])> {
    if data.len() < 2 {
        return Err(Error::AgentProtocol("DER integer too short".into()));
    }
    if data[0] != 0x02 {
        return Err(Error::AgentProtocol(format!(
            "expected INTEGER tag (0x02), got 0x{:02x}",
            data[0]
        )));
    }

    let (len, offset) = read_der_length(&data[1..])?;
    let start = 1 + offset;
    if data.len() < start + len {
        return Err(Error::AgentProtocol("DER integer truncated".into()));
    }

    let value = data[start..start + len].to_vec();
    let rest = &data[start + len..];
    Ok((value, rest))
}

/// Write an SSH mpint (multi-precision integer) to a buffer.
/// SSH mpints are big-endian, with a leading zero byte if the high bit is set.
fn write_ssh_mpint(buf: &mut Vec<u8>, value: &[u8]) {
    // Strip leading zeros (but keep at least one byte)
    let stripped = strip_leading_zeros(value);
    write_ssh_string(buf, stripped);
}

/// Strip leading zero bytes, keeping at least one byte.
fn strip_leading_zeros(data: &[u8]) -> &[u8] {
    if data.is_empty() {
        return data;
    }
    let mut i = 0;
    while i < data.len() - 1 && data[i] == 0 {
        // Keep a leading zero if the next byte has high bit set (positive mpint)
        if data[i + 1] & 0x80 != 0 {
            break;
        }
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
        assert_eq!(strip_leading_zeros(&[0, 0x80, 1]), &[0, 0x80, 1]); // keep zero before high bit
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
        // Maximum P-256 DER: 33 bytes per integer (leading 0x00 + 32 bytes with high bit set)
        let mut r = vec![0x00_u8];
        r.extend_from_slice(&[0xFF; 32]);
        let mut s = vec![0x00_u8];
        s.extend_from_slice(&[0x80; 32]);
        let der = make_der_signature(&r, &s);
        let ssh_sig = der_to_ssh_signature(&der).unwrap();

        let (algo, rest) = sshenc_core::pubkey::read_ssh_string(&ssh_sig).unwrap();
        assert_eq!(algo, b"ecdsa-sha2-nistp256");

        let (inner, _) = sshenc_core::pubkey::read_ssh_string(rest).unwrap();
        let (parsed_r, remaining) = sshenc_core::pubkey::read_ssh_string(inner).unwrap();
        let (parsed_s, _) = sshenc_core::pubkey::read_ssh_string(remaining).unwrap();

        // Leading zeros should be preserved since next byte has high bit set
        assert_eq!(parsed_r[0], 0x00);
        assert_eq!(parsed_r[1], 0xFF);
        assert_eq!(parsed_s[0], 0x00);
        assert_eq!(parsed_s[1], 0x80);
    }

    #[test]
    fn test_parse_der_signature_wrong_tag() {
        // First byte is 0x31 (SET) instead of 0x30 (SEQUENCE)
        let bad = vec![0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        let result = der_to_ssh_signature(&bad);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("SEQUENCE") || err_msg.contains("0x30"),
            "error should mention SEQUENCE tag: {err_msg}"
        );
    }

    #[test]
    fn test_parse_der_signature_truncated() {
        // Valid start but truncated in the middle
        let truncated = vec![0x30, 0x10, 0x02, 0x01];
        let result = der_to_ssh_signature(&truncated);
        assert!(result.is_err());
    }
}
