// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! SSH public key encoding and formatting (ecdsa-sha2-nistp256).
//!
//! Implements the OpenSSH public key wire format per RFC 5656 and the
//! OpenSSH authorized_keys file format.

use crate::error::{Error, Result};
use crate::key::KeyAlgorithm;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use byteorder::{BigEndian, WriteBytesExt};
use std::io::Write;

/// An SSH public key in the ecdsa-sha2-nistp256 format.
#[derive(Debug, Clone)]
pub struct SshPublicKey {
    /// The uncompressed SEC1 EC point (65 bytes: 0x04 || x || y).
    ec_point: Vec<u8>,
    /// Algorithm metadata.
    algorithm: KeyAlgorithm,
    /// Optional comment.
    comment: Option<String>,
}

impl SshPublicKey {
    /// Create a new SSH public key from uncompressed SEC1 EC point bytes.
    ///
    /// The bytes must be exactly 65 bytes: 0x04 prefix followed by 32-byte X
    /// and 32-byte Y coordinates.
    pub fn from_sec1_bytes(bytes: &[u8], comment: Option<String>) -> Result<Self> {
        if bytes.len() != 65 {
            return Err(Error::InvalidPublicKey(format!(
                "expected 65 bytes for uncompressed P-256 point, got {}",
                bytes.len()
            )));
        }
        if bytes[0] != 0x04 {
            return Err(Error::InvalidPublicKey(
                "expected uncompressed point (0x04 prefix)".into(),
            ));
        }
        Ok(SshPublicKey {
            ec_point: bytes.to_vec(),
            algorithm: KeyAlgorithm::EcdsaP256,
            comment,
        })
    }

    /// Encode the public key in SSH wire format (the binary blob).
    ///
    /// Format: string("ecdsa-sha2-nistp256") || string("nistp256") || string(Q)
    /// where Q is the uncompressed EC point and string() is a uint32 length prefix
    /// followed by the data.
    pub fn to_wire_format(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        write_ssh_string(&mut buf, self.algorithm.ssh_key_type().as_bytes());
        write_ssh_string(&mut buf, self.algorithm.ssh_curve_id().as_bytes());
        write_ssh_string(&mut buf, &self.ec_point);
        buf
    }

    /// Format as an OpenSSH public key line (e.g., for authorized_keys or .pub files).
    ///
    /// Format: `ecdsa-sha2-nistp256 <base64-blob> [comment]`
    pub fn to_openssh_line(&self) -> String {
        let blob = self.to_wire_format();
        let encoded = STANDARD.encode(&blob);
        match &self.comment {
            Some(c) => format!("{} {} {}", self.algorithm.ssh_key_type(), encoded, c),
            None => format!("{} {}", self.algorithm.ssh_key_type(), encoded),
        }
    }

    /// Format as an authorized_keys line (same as openssh line).
    pub fn to_authorized_keys_line(&self) -> String {
        self.to_openssh_line()
    }

    /// Returns the raw wire-format blob bytes.
    pub fn wire_blob(&self) -> Vec<u8> {
        self.to_wire_format()
    }

    /// Returns the uncompressed SEC1 EC point bytes.
    pub fn ec_point(&self) -> &[u8] {
        &self.ec_point
    }

    /// Returns the algorithm.
    pub fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    /// Returns the comment, if any.
    pub fn comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }

    /// Parse an OpenSSH public key line back into an SshPublicKey.
    pub fn from_openssh_line(line: &str) -> Result<Self> {
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        if parts.len() < 2 {
            return Err(Error::InvalidPublicKey(
                "expected at least 'key-type base64-blob'".into(),
            ));
        }
        let key_type = parts[0];
        if key_type != KeyAlgorithm::EcdsaP256.ssh_key_type() {
            return Err(Error::InvalidPublicKey(format!(
                "unsupported key type: {key_type}"
            )));
        }
        let blob = STANDARD
            .decode(parts[1])
            .map_err(|e| Error::InvalidPublicKey(format!("invalid base64: {e}")))?;
        let comment = parts.get(2).map(|s| s.to_string());
        let ec_point = parse_wire_format(&blob)?;
        SshPublicKey::from_sec1_bytes(&ec_point, comment)
    }
}

/// Write an SSH string (uint32 length prefix + data) to a buffer.
pub fn write_ssh_string(buf: &mut Vec<u8>, data: &[u8]) {
    buf.write_u32::<BigEndian>(data.len() as u32).unwrap();
    buf.write_all(data).unwrap();
}

/// Read an SSH string from a byte slice, returning (data, remaining).
pub fn read_ssh_string(buf: &[u8]) -> Result<(&[u8], &[u8])> {
    if buf.len() < 4 {
        return Err(Error::SshEncoding(
            "buffer too short for string length".into(),
        ));
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let buf = &buf[4..];
    if buf.len() < len {
        return Err(Error::SshEncoding(format!(
            "buffer too short: need {len} bytes, have {}",
            buf.len()
        )));
    }
    Ok((&buf[..len], &buf[len..]))
}

/// Parse SSH wire format blob into the EC point bytes.
fn parse_wire_format(blob: &[u8]) -> Result<Vec<u8>> {
    // string("ecdsa-sha2-nistp256") || string("nistp256") || string(Q)
    let (key_type, rest) = read_ssh_string(blob)?;
    let expected = KeyAlgorithm::EcdsaP256.ssh_key_type().as_bytes();
    if key_type != expected {
        return Err(Error::InvalidPublicKey(format!(
            "key type mismatch: expected {:?}, got {:?}",
            std::str::from_utf8(expected).unwrap(),
            std::str::from_utf8(key_type).unwrap_or("<invalid utf8>"),
        )));
    }
    let (curve_id, rest) = read_ssh_string(rest)?;
    let expected_curve = KeyAlgorithm::EcdsaP256.ssh_curve_id().as_bytes();
    if curve_id != expected_curve {
        return Err(Error::InvalidPublicKey("curve identifier mismatch".into()));
    }
    let (ec_point, _) = read_ssh_string(rest)?;
    Ok(ec_point.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ec_point() -> Vec<u8> {
        // A valid uncompressed P-256 point (0x04 + 32 bytes X + 32 bytes Y).
        let mut point = vec![0x04];
        // Use deterministic test data
        for i in 0..32 {
            point.push((i * 7 + 3) as u8); // X coordinate
        }
        for i in 0..32 {
            point.push((i * 11 + 5) as u8); // Y coordinate
        }
        point
    }

    #[test]
    fn test_from_sec1_bytes_valid() {
        let point = sample_ec_point();
        let key = SshPublicKey::from_sec1_bytes(&point, Some("test@host".into())).unwrap();
        assert_eq!(key.ec_point().len(), 65);
        assert_eq!(key.comment(), Some("test@host"));
    }

    #[test]
    fn test_from_sec1_bytes_wrong_length() {
        let result = SshPublicKey::from_sec1_bytes(&[0x04; 33], None);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_sec1_bytes_wrong_prefix() {
        let mut point = sample_ec_point();
        point[0] = 0x02; // compressed, not uncompressed
        let result = SshPublicKey::from_sec1_bytes(&point, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_wire_format_roundtrip() {
        let point = sample_ec_point();
        let key = SshPublicKey::from_sec1_bytes(&point, None).unwrap();
        let wire = key.to_wire_format();

        // Parse it back
        let parsed_point = parse_wire_format(&wire).unwrap();
        assert_eq!(parsed_point, point);
    }

    #[test]
    fn test_openssh_line_format() {
        let point = sample_ec_point();
        let key = SshPublicKey::from_sec1_bytes(&point, Some("test@host".into())).unwrap();
        let line = key.to_openssh_line();
        assert!(line.starts_with("ecdsa-sha2-nistp256 "));
        assert!(line.ends_with(" test@host"));

        // Parse it back
        let parsed = SshPublicKey::from_openssh_line(&line).unwrap();
        assert_eq!(parsed.ec_point(), key.ec_point());
        assert_eq!(parsed.comment(), Some("test@host"));
    }

    #[test]
    fn test_openssh_line_no_comment() {
        let point = sample_ec_point();
        let key = SshPublicKey::from_sec1_bytes(&point, None).unwrap();
        let line = key.to_openssh_line();
        assert!(line.starts_with("ecdsa-sha2-nistp256 "));
        assert!(!line.contains("  ")); // no trailing space

        let parsed = SshPublicKey::from_openssh_line(&line).unwrap();
        assert_eq!(parsed.ec_point(), key.ec_point());
        assert!(parsed.comment().is_none());
    }

    #[test]
    fn test_wire_format_structure() {
        let point = sample_ec_point();
        let key = SshPublicKey::from_sec1_bytes(&point, None).unwrap();
        let wire = key.to_wire_format();

        // Verify structure: string("ecdsa-sha2-nistp256") || string("nistp256") || string(Q)
        let (key_type, rest) = read_ssh_string(&wire).unwrap();
        assert_eq!(key_type, b"ecdsa-sha2-nistp256");

        let (curve_id, rest) = read_ssh_string(rest).unwrap();
        assert_eq!(curve_id, b"nistp256");

        let (ec_point, rest) = read_ssh_string(rest).unwrap();
        assert_eq!(ec_point, &point[..]);
        assert!(rest.is_empty());
    }

    #[test]
    fn test_openssh_line_empty_comment() {
        // Some("") should produce a trailing space + empty string, but still parse
        let point = sample_ec_point();
        let key = SshPublicKey::from_sec1_bytes(&point, Some("".into())).unwrap();
        let line = key.to_openssh_line();
        // Format: "ecdsa-sha2-nistp256 <base64> "
        assert!(line.starts_with("ecdsa-sha2-nistp256 "));
        // Should roundtrip: the comment comes back as empty string
        let parsed = SshPublicKey::from_openssh_line(&line).unwrap();
        assert_eq!(parsed.ec_point(), key.ec_point());
        // The parsed comment should be Some("") since splitn(3, ' ') returns the 3rd part
        assert_eq!(parsed.comment(), Some(""));
    }

    #[test]
    fn test_parse_invalid_key_type() {
        let line = "ssh-rsa AAAAB3NzaC1yc2EAAA== user@host";
        let err = SshPublicKey::from_openssh_line(line).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unsupported key type"),
            "expected 'unsupported key type' in error: {msg}"
        );
    }

    #[test]
    fn test_parse_truncated_blob() {
        // Valid key type, but the base64 decodes to a truncated wire blob
        // Build a blob that has the key type string but is truncated after that
        let mut truncated_wire = Vec::new();
        write_ssh_string(&mut truncated_wire, b"ecdsa-sha2-nistp256");
        // Don't write curve or EC point — this is truncated
        let encoded = STANDARD.encode(&truncated_wire);
        let line = format!("ecdsa-sha2-nistp256 {encoded} user@host");
        let err = SshPublicKey::from_openssh_line(&line).unwrap_err();
        // Should fail when trying to read the curve id string
        assert!(err.to_string().contains("too short") || err.to_string().contains("buffer"));
    }

    #[test]
    fn test_parse_single_field_line() {
        // Only one field, no base64 blob
        let err = SshPublicKey::from_openssh_line("ecdsa-sha2-nistp256").unwrap_err();
        assert!(err.to_string().contains("at least"));
    }
}
