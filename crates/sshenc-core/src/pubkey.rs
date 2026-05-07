// Copyright 2026 Jay Gowdy
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
        let comment = parts.get(2).map(|s| (*s).to_string());
        let ec_point = parse_wire_format(&blob)?;
        SshPublicKey::from_sec1_bytes(&ec_point, comment)
    }
}

/// An SSH FIDO2 SK public key (`sk-ecdsa-sha2-nistp256@openssh.com`).
///
/// Wire format per `PROTOCOL.u2f`:
/// ```text
///   string  "sk-ecdsa-sha2-nistp256@openssh.com"
///   string  "nistp256"
///   string  ec_point   (uncompressed: 0x04 || X || Y, 65 bytes)
///   string  application  (the SSH-side RP identifier; SHA-256
///                         hashed by sshd to compare with rpIdHash)
/// ```
///
/// The `application` value is what gets SHA-256'd into the
/// `rpIdHash` slot of the WebAuthn `authenticator_data` -- so for
/// sshenc SK keys we set `application = rp_id` we used at make-
/// credential time (e.g. `sshenc-<keyhash>.local`). The verifier
/// reconstructs the same hash from this string when checking
/// signatures.
#[derive(Debug, Clone)]
pub struct SshSkPublicKey {
    /// Uncompressed SEC1 EC point: 0x04 || X (32) || Y (32).
    ec_point: Vec<u8>,
    /// SSH application string (= our RP ID for sshenc keys).
    application: String,
    /// Optional comment.
    comment: Option<String>,
}

impl SshSkPublicKey {
    /// Build an SK public key from its component parts. `x` and `y`
    /// are the 32-byte ECDSA P-256 coordinates returned by the
    /// platform authenticator.
    pub fn from_xy(
        x: &[u8; 32],
        y: &[u8; 32],
        application: String,
        comment: Option<String>,
    ) -> Self {
        let mut ec_point = Vec::with_capacity(65);
        ec_point.push(0x04);
        ec_point.extend_from_slice(x);
        ec_point.extend_from_slice(y);
        SshSkPublicKey {
            ec_point,
            application,
            comment,
        }
    }

    /// Construct from a pre-formed uncompressed SEC1 EC point.
    pub fn from_sec1_bytes(
        bytes: &[u8],
        application: String,
        comment: Option<String>,
    ) -> Result<Self> {
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
        Ok(SshSkPublicKey {
            ec_point: bytes.to_vec(),
            application,
            comment,
        })
    }

    /// Encode as an SSH wire-format blob (the contents of the
    /// `<base64-blob>` portion of an authorized_keys line).
    pub fn to_wire_format(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(160);
        write_ssh_string(
            &mut buf,
            KeyAlgorithm::SkEcdsaP256.ssh_key_type().as_bytes(),
        );
        write_ssh_string(
            &mut buf,
            KeyAlgorithm::SkEcdsaP256.ssh_curve_id().as_bytes(),
        );
        write_ssh_string(&mut buf, &self.ec_point);
        write_ssh_string(&mut buf, self.application.as_bytes());
        buf
    }

    /// Format as an OpenSSH public key line.
    pub fn to_openssh_line(&self) -> String {
        let blob = self.to_wire_format();
        let encoded = STANDARD.encode(&blob);
        let key_type = KeyAlgorithm::SkEcdsaP256.ssh_key_type();
        match &self.comment {
            Some(c) => format!("{key_type} {encoded} {c}"),
            None => format!("{key_type} {encoded}"),
        }
    }

    /// Returns the SSH application string (the RP-id we registered
    /// the credential under).
    pub fn application(&self) -> &str {
        &self.application
    }

    /// Returns the uncompressed SEC1 EC point bytes.
    pub fn ec_point(&self) -> &[u8] {
        &self.ec_point
    }

    /// Returns the comment, if any.
    pub fn comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }

    /// Parse an OpenSSH `sk-ecdsa-sha2-nistp256@openssh.com` line back
    /// into an SshSkPublicKey. Mirrors `SshPublicKey::from_openssh_line`
    /// for the SK key type so callers (notably the CLI's `-Y sign`
    /// path) can accept either format and route the resulting wire
    /// blob to the agent for signing.
    pub fn from_openssh_line(line: &str) -> Result<Self> {
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        if parts.len() < 2 {
            return Err(Error::InvalidPublicKey(
                "expected at least 'key-type base64-blob'".into(),
            ));
        }
        let key_type = parts[0];
        if key_type != KeyAlgorithm::SkEcdsaP256.ssh_key_type() {
            return Err(Error::InvalidPublicKey(format!(
                "expected sk-ecdsa-sha2-nistp256@openssh.com, got: {key_type}"
            )));
        }
        let blob = STANDARD
            .decode(parts[1])
            .map_err(|e| Error::InvalidPublicKey(format!("invalid base64: {e}")))?;
        let comment = parts.get(2).map(|s| (*s).to_string());
        // Wire format per PROTOCOL.u2f:
        //   string  "sk-ecdsa-sha2-nistp256@openssh.com"
        //   string  "nistp256"
        //   string  ec_point   (uncompressed: 0x04 || X || Y, 65 bytes)
        //   string  application
        let (algo, rest) = read_ssh_string(&blob)?;
        if algo != KeyAlgorithm::SkEcdsaP256.ssh_key_type().as_bytes() {
            return Err(Error::InvalidPublicKey(format!(
                "wire algo mismatch: got {}",
                String::from_utf8_lossy(algo)
            )));
        }
        let (curve, rest) = read_ssh_string(rest)?;
        if curve != KeyAlgorithm::SkEcdsaP256.ssh_curve_id().as_bytes() {
            return Err(Error::InvalidPublicKey(format!(
                "wire curve mismatch: got {}",
                String::from_utf8_lossy(curve)
            )));
        }
        let (ec_point, rest) = read_ssh_string(rest)?;
        let (application, rest) = read_ssh_string(rest)?;
        if !rest.is_empty() {
            return Err(Error::InvalidPublicKey(
                "trailing bytes in sk-ecdsa pubkey blob".into(),
            ));
        }
        let application = String::from_utf8(application.to_vec())
            .map_err(|e| Error::InvalidPublicKey(format!("invalid application string: {e}")))?;
        SshSkPublicKey::from_sec1_bytes(ec_point, application, comment)
    }
}

/// Encode an SSH SK signature blob from a DER-encoded ECDSA
/// signature, the platform-authenticator flags byte, and the
/// monotonic counter.
///
/// Wire format:
/// ```text
///   string  "sk-ecdsa-sha2-nistp256@openssh.com"
///   string  ecdsa_signature_blob   // mpint r || mpint s
///   byte    flags                  // bit 0 = UP, bit 2 = UV
///   uint32  counter
/// ```
///
/// The DER-encoded signature is SEQUENCE { INTEGER r, INTEGER s };
/// we extract r and s, encode each as an SSH `mpint` (length-
/// prefixed two's-complement big-endian, with a leading zero byte
/// if the high bit of the magnitude is set), and wrap them in an
/// SSH `string`.
pub fn encode_sk_signature_blob(der_signature: &[u8], flags: u8, counter: u32) -> Result<Vec<u8>> {
    let (r, s) = parse_der_ecdsa_signature(der_signature)?;

    let mut sig_inner = Vec::with_capacity(80);
    write_mpint(&mut sig_inner, r);
    write_mpint(&mut sig_inner, s);

    let mut out = Vec::with_capacity(160);
    write_ssh_string(
        &mut out,
        KeyAlgorithm::SkEcdsaP256.ssh_key_type().as_bytes(),
    );
    write_ssh_string(&mut out, &sig_inner);
    out.push(flags);
    // `write_u32` to a `Vec<u8>` is infallible; surface the
    // io::Error via `?` instead of panic'ing to keep the
    // `unwrap_in_result` lint happy.
    out.write_u32::<BigEndian>(counter)?;
    Ok(out)
}

/// Parse a DER-encoded ECDSA signature into raw `(r, s)` byte
/// slices. The bytes are the *magnitude* with leading zeros from
/// the DER INTEGER encoding stripped -- i.e. canonical big-endian
/// big integer bytes. Caller wraps each in `mpint` for SSH.
fn parse_der_ecdsa_signature(der: &[u8]) -> Result<(&[u8], &[u8])> {
    if der.len() < 2 || der[0] != 0x30 {
        return Err(Error::InvalidSignature(
            "DER ECDSA signature must start with SEQUENCE (0x30)".into(),
        ));
    }
    // Length octet: short form (single byte, < 0x80) or long form.
    let (seq_body, _) = parse_der_length(&der[1..])?;
    if seq_body.is_empty() || seq_body[0] != 0x02 {
        return Err(Error::InvalidSignature(
            "expected INTEGER (0x02) for r component".into(),
        ));
    }
    let (r_bytes, after_r) = parse_der_length(&seq_body[1..])?;
    if after_r.is_empty() || after_r[0] != 0x02 {
        return Err(Error::InvalidSignature(
            "expected INTEGER (0x02) for s component".into(),
        ));
    }
    let (s_bytes, _after_s) = parse_der_length(&after_r[1..])?;

    // Strip leading zero byte that DER adds when the high bit of
    // the magnitude would otherwise make the integer look negative.
    let r_stripped = strip_der_int_leading_zero(r_bytes);
    let s_stripped = strip_der_int_leading_zero(s_bytes);
    Ok((r_stripped, s_stripped))
}

fn parse_der_length(buf: &[u8]) -> Result<(&[u8], &[u8])> {
    if buf.is_empty() {
        return Err(Error::InvalidSignature("DER buffer empty".into()));
    }
    let first = buf[0];
    if first < 0x80 {
        let len = first as usize;
        let rest = &buf[1..];
        if rest.len() < len {
            return Err(Error::InvalidSignature(
                "DER short-form length exceeds buffer".into(),
            ));
        }
        Ok((&rest[..len], &rest[len..]))
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 {
            return Err(Error::InvalidSignature(
                "unsupported DER long-form length".into(),
            ));
        }
        if buf.len() < 1 + count {
            return Err(Error::InvalidSignature(
                "DER long-form length truncated".into(),
            ));
        }
        let mut len: usize = 0;
        for &b in &buf[1..=count] {
            len = (len << 8) | (b as usize);
        }
        let rest = &buf[1 + count..];
        if rest.len() < len {
            return Err(Error::InvalidSignature(
                "DER long-form length exceeds buffer".into(),
            ));
        }
        Ok((&rest[..len], &rest[len..]))
    }
}

fn strip_der_int_leading_zero(int_bytes: &[u8]) -> &[u8] {
    if int_bytes.len() > 1 && int_bytes[0] == 0x00 && int_bytes[1] >= 0x80 {
        &int_bytes[1..]
    } else {
        int_bytes
    }
}

/// Write an SSH `mpint` (length-prefixed two's-complement
/// big-endian). For positive integers (which ECDSA r and s always
/// are): if the high bit of the first byte is set, prepend a 0
/// byte to disambiguate from negative values.
pub fn write_mpint(buf: &mut Vec<u8>, magnitude: &[u8]) {
    // Strip leading zeros from the magnitude itself (RFC 4251
    // requires no leading zero bytes unless needed to keep the
    // value positive).
    let mut start = 0;
    while start < magnitude.len() && magnitude[start] == 0 {
        start += 1;
    }
    let trimmed = &magnitude[start..];
    if trimmed.is_empty() {
        // Zero is encoded as a zero-length string.
        write_ssh_string(buf, &[]);
        return;
    }
    if trimmed[0] >= 0x80 {
        let mut padded = Vec::with_capacity(trimmed.len() + 1);
        padded.push(0x00);
        padded.extend_from_slice(trimmed);
        write_ssh_string(buf, &padded);
    } else {
        write_ssh_string(buf, trimmed);
    }
}

/// Write an SSH string (uint32 length prefix + data) to a buffer.
pub fn write_ssh_string(buf: &mut Vec<u8>, data: &[u8]) {
    // Writing to Vec<u8> cannot fail — these expect() calls are unreachable
    buf.write_u32::<BigEndian>(data.len() as u32)
        .expect("write to Vec<u8> cannot fail");
    buf.write_all(data).expect("write to Vec<u8> cannot fail");
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
            std::str::from_utf8(expected).unwrap_or("<invalid utf8>"),
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
#[allow(clippy::unwrap_used)]
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

    #[test]
    fn test_comment_with_spaces_and_special_chars() {
        let point = sample_ec_point();
        let comment = "user@host (work laptop) #2 <admin>";
        let key = SshPublicKey::from_sec1_bytes(&point, Some(comment.into())).unwrap();
        assert_eq!(key.comment(), Some(comment));

        // Roundtrip through openssh line format
        let line = key.to_openssh_line();
        assert!(line.ends_with(comment));
        let parsed = SshPublicKey::from_openssh_line(&line).unwrap();
        assert_eq!(parsed.comment(), Some(comment));
        assert_eq!(parsed.ec_point(), key.ec_point());
    }

    #[test]
    fn test_parse_openssh_line_with_extra_whitespace() {
        // from_openssh_line uses splitn(3, ' '), so leading spaces in key type
        // would cause a mismatch. But trailing spaces in the comment field are
        // preserved. Test that a well-formed line with a space-containing comment
        // parses correctly.
        let point = sample_ec_point();
        let key = SshPublicKey::from_sec1_bytes(&point, Some("my comment".into())).unwrap();
        let line = key.to_openssh_line();
        // The comment part is everything after the second space, via splitn(3, ' ')
        let parsed = SshPublicKey::from_openssh_line(&line).unwrap();
        assert_eq!(parsed.comment(), Some("my comment"));
    }

    #[test]
    fn test_wire_blob_is_deterministic() {
        let point = sample_ec_point();
        let key = SshPublicKey::from_sec1_bytes(&point, Some("det-test".into())).unwrap();
        let blob1 = key.wire_blob();
        let blob2 = key.wire_blob();
        assert_eq!(blob1, blob2, "wire_blob must be deterministic");
        // Also verify it matches to_wire_format
        assert_eq!(blob1, key.to_wire_format());
    }

    #[test]
    fn test_read_ssh_string_at_exact_boundary() {
        // Build a buffer with exactly one string, no extra bytes
        let mut buf = Vec::new();
        write_ssh_string(&mut buf, b"boundary-test");
        let (data, rest) = read_ssh_string(&buf).unwrap();
        assert_eq!(data, b"boundary-test");
        assert!(
            rest.is_empty(),
            "remainder should be empty at exact boundary"
        );
    }

    #[test]
    fn test_read_ssh_string_with_remainder() {
        let mut buf = Vec::new();
        write_ssh_string(&mut buf, b"first");
        write_ssh_string(&mut buf, b"second");
        let (data, rest) = read_ssh_string(&buf).unwrap();
        assert_eq!(data, b"first");
        // The remainder should contain the second string
        let (data2, rest2) = read_ssh_string(rest).unwrap();
        assert_eq!(data2, b"second");
        assert!(rest2.is_empty());
    }

    #[test]
    fn test_read_ssh_string_empty_string() {
        let mut buf = Vec::new();
        write_ssh_string(&mut buf, b"");
        let (data, rest) = read_ssh_string(&buf).unwrap();
        assert!(data.is_empty());
        assert!(rest.is_empty());
    }

    #[test]
    fn test_read_ssh_string_buffer_too_short() {
        // Only 3 bytes, need at least 4 for the length prefix
        let buf = [0_u8; 3];
        let result = read_ssh_string(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_ssh_string_truncated_data() {
        // Length says 10 bytes, but only 5 available
        let mut buf = Vec::new();
        buf.extend_from_slice(&10_u32.to_be_bytes());
        buf.extend_from_slice(&[0_u8; 5]);
        let result = read_ssh_string(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_sec1_bytes_wrong_prefix_0x02() {
        // 65 bytes with compressed point prefix 0x02 should be rejected
        let mut point = vec![0x02_u8];
        point.extend_from_slice(&[0x01; 64]);
        let result = SshPublicKey::from_sec1_bytes(&point, None);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("uncompressed") || err_msg.contains("0x04"),
            "error should mention uncompressed point: {err_msg}"
        );
    }

    #[test]
    fn test_from_sec1_bytes_64_bytes() {
        // 64 bytes is too short (should be 65)
        let point = vec![0x04; 64];
        let result = SshPublicKey::from_sec1_bytes(&point, None);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("65"),
            "error should mention expected 65 bytes: {err_msg}"
        );
    }

    #[test]
    fn test_to_wire_format_structure() {
        let point = sample_ec_point();
        let key = SshPublicKey::from_sec1_bytes(&point, None).unwrap();
        let wire = key.to_wire_format();

        // Verify SSH blob structure: string(key_type) || string(curve) || string(Q)
        let (key_type, rest) = read_ssh_string(&wire).unwrap();
        assert_eq!(key_type, b"ecdsa-sha2-nistp256");

        let (curve, rest) = read_ssh_string(rest).unwrap();
        assert_eq!(curve, b"nistp256");

        let (q, rest) = read_ssh_string(rest).unwrap();
        assert_eq!(q.len(), 65);
        assert_eq!(q[0], 0x04);
        assert!(rest.is_empty(), "no trailing bytes");
    }

    #[test]
    fn test_from_openssh_line_extra_whitespace_in_comment() {
        // A line with multiple spaces in the comment portion
        let point = sample_ec_point();
        let key =
            SshPublicKey::from_sec1_bytes(&point, Some("user@host  extra  spaces".into())).unwrap();
        let line = key.to_openssh_line();
        let parsed = SshPublicKey::from_openssh_line(&line).unwrap();
        assert_eq!(parsed.comment(), Some("user@host  extra  spaces"));
        assert_eq!(parsed.ec_point(), key.ec_point());
    }

    #[test]
    fn test_from_openssh_line_no_comment_roundtrip() {
        let point = sample_ec_point();
        let key = SshPublicKey::from_sec1_bytes(&point, None).unwrap();
        let line = key.to_openssh_line();

        // The line should just be "ecdsa-sha2-nistp256 <base64>" with no trailing space
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        assert_eq!(parts.len(), 2, "no comment means exactly 2 parts");

        let parsed = SshPublicKey::from_openssh_line(&line).unwrap();
        assert!(parsed.comment().is_none());
        assert_eq!(parsed.ec_point(), key.ec_point());
    }

    #[test]
    fn test_from_openssh_line_empty_base64_error() {
        // Valid key type but empty base64 blob
        let line = "ecdsa-sha2-nistp256  comment";
        let result = SshPublicKey::from_openssh_line(line);
        assert!(result.is_err());
    }

    // --- SK (FIDO2 / WebAuthn) public key tests ---

    #[test]
    fn test_sk_pubkey_wire_format_structure() {
        let x = [0x11_u8; 32];
        let y = [0x22_u8; 32];
        let app = "sshenc-test.local".to_string();
        let key = SshSkPublicKey::from_xy(&x, &y, app.clone(), None);
        let wire = key.to_wire_format();

        // string("sk-ecdsa-sha2-nistp256@openssh.com") || string("nistp256")
        //   || string(Q) || string(application)
        let (key_type, rest) = read_ssh_string(&wire).unwrap();
        assert_eq!(key_type, b"sk-ecdsa-sha2-nistp256@openssh.com");
        let (curve, rest) = read_ssh_string(rest).unwrap();
        assert_eq!(curve, b"nistp256");
        let (q, rest) = read_ssh_string(rest).unwrap();
        assert_eq!(q.len(), 65);
        assert_eq!(q[0], 0x04);
        assert_eq!(&q[1..33], &x);
        assert_eq!(&q[33..65], &y);
        let (application, rest) = read_ssh_string(rest).unwrap();
        assert_eq!(application, app.as_bytes());
        assert!(rest.is_empty());
    }

    #[test]
    fn test_sk_openssh_line_format() {
        let x = [0xAA_u8; 32];
        let y = [0xBB_u8; 32];
        let key =
            SshSkPublicKey::from_xy(&x, &y, "sshenc-abc.local".into(), Some("user@host".into()));
        let line = key.to_openssh_line();
        assert!(line.starts_with("sk-ecdsa-sha2-nistp256@openssh.com "));
        assert!(line.ends_with(" user@host"));
    }

    #[test]
    fn test_mpint_encodes_high_bit_with_leading_zero() {
        // 0x80 has the high bit set; mpint must prepend 0x00 to keep
        // the value positive in two's complement.
        let mut buf = Vec::new();
        write_mpint(&mut buf, &[0x80, 0x00, 0x00]);
        // Length prefix (4 bytes BE = 4) + 0x00 + 0x80 0x00 0x00.
        assert_eq!(buf, vec![0x00, 0x00, 0x00, 0x04, 0x00, 0x80, 0x00, 0x00]);
    }

    #[test]
    fn test_mpint_strips_leading_zeros() {
        // RFC 4251: no unnecessary leading zero bytes.
        let mut buf = Vec::new();
        write_mpint(&mut buf, &[0x00, 0x00, 0x42]);
        // Length=1, body=0x42.
        assert_eq!(buf, vec![0x00, 0x00, 0x00, 0x01, 0x42]);
    }

    #[test]
    fn test_mpint_zero_is_empty_string() {
        let mut buf = Vec::new();
        write_mpint(&mut buf, &[0x00]);
        assert_eq!(buf, vec![0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_sk_signature_blob_structure() {
        // Build a synthetic DER signature: SEQUENCE { INTEGER r, INTEGER s }
        // where r = 0x01 0x23 ... (32 bytes, no high bit) and s = 0xab cd ... (32 bytes).
        // The s value's first byte 0xab has the high bit set, so DER will
        // have prepended a 0x00 byte that we must strip then re-add as the
        // mpint pad byte.
        let mut der = Vec::new();
        der.push(0x30); // SEQUENCE
        let mut body = Vec::new();
        body.push(0x02); // INTEGER r
        body.push(0x20); // length 32
        body.extend(std::iter::repeat(0x42).take(32));
        body.push(0x02); // INTEGER s
        body.push(0x21); // length 33 (DER added a leading 0)
        body.push(0x00);
        body.extend(std::iter::repeat(0xab).take(32));
        der.push(body.len() as u8);
        der.extend(body);

        let blob = encode_sk_signature_blob(&der, 0x05, 42).expect("encode ok");

        // Expected layout:
        //   string("sk-ecdsa-sha2-nistp256@openssh.com")
        //   string(<mpint r || mpint s>)
        //   byte 0x05 (UP|UV)
        //   uint32 42
        let (sig_type, rest) = read_ssh_string(&blob).unwrap();
        assert_eq!(sig_type, b"sk-ecdsa-sha2-nistp256@openssh.com");
        let (sig_inner, rest) = read_ssh_string(rest).unwrap();

        // Parse mpint r and mpint s out of sig_inner
        let (r, rest_inner) = read_ssh_string(sig_inner).unwrap();
        // r had no high bit so it's 32 bytes flat.
        assert_eq!(r.len(), 32);
        assert!(r.iter().all(|b| *b == 0x42));
        let (s, rest_inner) = read_ssh_string(rest_inner).unwrap();
        // s had high bit set so mpint added a leading 0.
        assert_eq!(s.len(), 33);
        assert_eq!(s[0], 0x00);
        assert!(s[1..].iter().all(|b| *b == 0xab));
        assert!(rest_inner.is_empty());

        // After the inner sig string come flags + counter.
        assert_eq!(rest.len(), 5);
        assert_eq!(rest[0], 0x05);
        assert_eq!(&rest[1..5], &42_u32.to_be_bytes());
    }

    #[test]
    fn test_parse_der_rejects_non_sequence() {
        let bad = vec![0x02, 0x01, 0x00];
        let result = encode_sk_signature_blob(&bad, 0, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_der_rejects_truncated() {
        let bad = vec![0x30];
        let result = encode_sk_signature_blob(&bad, 0, 0);
        assert!(result.is_err());
    }
}
