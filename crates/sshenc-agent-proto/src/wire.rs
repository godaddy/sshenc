// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Low-level SSH agent wire format encoding/decoding.
//!
//! All agent protocol messages are framed as: uint32(length) || payload.
//! Within the payload, the first byte is the message type.

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use sshenc_core::error::{Error, Result};
use std::io::{Cursor, Read, Write};

/// Read a complete agent message frame from a reader.
/// Returns the raw payload bytes (including the message type byte).
pub fn read_message_frame<R: Read>(reader: &mut R) -> Result<Vec<u8>> {
    let len = reader
        .read_u32::<BigEndian>()
        .map_err(|e| Error::AgentProtocol(format!("failed to read message length: {e}")))?;

    if len == 0 {
        return Err(Error::AgentProtocol("empty message".into()));
    }
    if len > 256 * 1024 {
        return Err(Error::AgentProtocol(format!(
            "message too large: {len} bytes"
        )));
    }

    let mut buf = vec![0_u8; len as usize];
    reader
        .read_exact(&mut buf)
        .map_err(|e| Error::AgentProtocol(format!("failed to read message body: {e}")))?;

    Ok(buf)
}

/// Write a complete agent message frame to a writer.
pub fn write_message_frame<W: Write>(writer: &mut W, payload: &[u8]) -> Result<()> {
    writer
        .write_u32::<BigEndian>(payload.len() as u32)
        .map_err(|e| Error::AgentProtocol(format!("failed to write message length: {e}")))?;
    writer
        .write_all(payload)
        .map_err(|e| Error::AgentProtocol(format!("failed to write message body: {e}")))?;
    Ok(())
}

/// Read an SSH string (uint32 length + data) from a cursor.
pub fn read_string(cursor: &mut Cursor<&[u8]>) -> Result<Vec<u8>> {
    let len = cursor
        .read_u32::<BigEndian>()
        .map_err(|e| Error::AgentProtocol(format!("failed to read string length: {e}")))?;
    let mut buf = vec![0_u8; len as usize];
    cursor
        .read_exact(&mut buf)
        .map_err(|e| Error::AgentProtocol(format!("failed to read string data: {e}")))?;
    Ok(buf)
}

/// Write an SSH string (uint32 length + data) to a buffer.
pub fn write_string(buf: &mut Vec<u8>, data: &[u8]) {
    // Writing to Vec<u8> cannot fail — these expect() calls are unreachable
    buf.write_u32::<BigEndian>(data.len() as u32)
        .expect("write to Vec<u8> cannot fail");
    buf.write_all(data).expect("write to Vec<u8> cannot fail");
}

/// Read a uint32 from a cursor.
pub fn read_u32(cursor: &mut Cursor<&[u8]>) -> Result<u32> {
    cursor
        .read_u32::<BigEndian>()
        .map_err(|e| Error::AgentProtocol(format!("failed to read u32: {e}")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_message_frame_roundtrip() {
        let payload = b"hello agent";
        let mut buf = Vec::new();
        write_message_frame(&mut buf, payload).unwrap();

        let mut cursor = Cursor::new(buf.as_slice());
        let read_back = read_message_frame(&mut cursor).unwrap();
        assert_eq!(read_back, payload);
    }

    #[test]
    fn test_string_roundtrip() {
        let data = b"test-string-data";
        let mut buf = Vec::new();
        write_string(&mut buf, data);

        let mut cursor = Cursor::new(buf.as_slice());
        let read_back = read_string(&mut cursor).unwrap();
        assert_eq!(read_back, data);
    }

    #[test]
    fn test_empty_message_rejected() {
        let mut buf = Vec::new();
        buf.write_u32::<BigEndian>(0).unwrap();
        let mut cursor = Cursor::new(buf.as_slice());
        let result = read_message_frame(&mut cursor);
        assert!(result.is_err());
    }

    #[test]
    fn test_oversized_message_rejected() {
        let mut buf = Vec::new();
        buf.write_u32::<BigEndian>(512 * 1024).unwrap();
        let mut cursor = Cursor::new(buf.as_slice());
        let result = read_message_frame(&mut cursor);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_string_exact_buffer() {
        // Buffer contains exactly the string, no remainder
        let mut buf = Vec::new();
        write_string(&mut buf, b"exact");
        let mut cursor = Cursor::new(buf.as_slice());
        let result = read_string(&mut cursor).unwrap();
        assert_eq!(result, b"exact");
        // Cursor should be at the end
        assert_eq!(cursor.position() as usize, buf.len());
    }

    #[test]
    fn test_read_string_with_remainder() {
        // Write two strings, read the first, verify cursor position
        let mut buf = Vec::new();
        write_string(&mut buf, b"first");
        write_string(&mut buf, b"second");
        let mut cursor = Cursor::new(buf.as_slice());
        let first = read_string(&mut cursor).unwrap();
        assert_eq!(first, b"first");
        // Read the second to confirm remainder is intact
        let second = read_string(&mut cursor).unwrap();
        assert_eq!(second, b"second");
    }

    #[test]
    fn test_write_then_read_string_empty_data() {
        let mut buf = Vec::new();
        write_string(&mut buf, b"");
        // Should have written 4 bytes for length (0) and 0 data bytes
        assert_eq!(buf.len(), 4);

        let mut cursor = Cursor::new(buf.as_slice());
        let result = read_string(&mut cursor).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_write_then_read_string_large_data() {
        let large = vec![0xAB_u8; 1000];
        let mut buf = Vec::new();
        write_string(&mut buf, &large);
        assert_eq!(buf.len(), 4 + 1000);

        let mut cursor = Cursor::new(buf.as_slice());
        let result = read_string(&mut cursor).unwrap();
        assert_eq!(result, large);
    }

    #[test]
    fn test_read_u32_zero() {
        let data: [u8; 4] = [0, 0, 0, 0];
        let mut cursor = Cursor::new(data.as_slice());
        assert_eq!(read_u32(&mut cursor).unwrap(), 0);
    }

    #[test]
    fn test_read_u32_one() {
        let data: [u8; 4] = [0, 0, 0, 1];
        let mut cursor = Cursor::new(data.as_slice());
        assert_eq!(read_u32(&mut cursor).unwrap(), 1);
    }

    #[test]
    fn test_read_u32_max() {
        let data: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];
        let mut cursor = Cursor::new(data.as_slice());
        assert_eq!(read_u32(&mut cursor).unwrap(), u32::MAX);
    }

    #[test]
    fn test_read_message_frame_exactly_max_size() {
        let max_len: u32 = 256 * 1024;
        let payload = vec![0x42_u8; max_len as usize];
        let mut buf = Vec::new();
        buf.write_u32::<BigEndian>(max_len).unwrap();
        buf.extend_from_slice(&payload);

        let mut cursor = Cursor::new(buf.as_slice());
        let result = read_message_frame(&mut cursor).unwrap();
        assert_eq!(result.len(), max_len as usize);
        assert_eq!(result, payload);
    }

    #[test]
    fn test_read_message_frame_one_over_max_rejected() {
        let over_max: u32 = 256 * 1024 + 1;
        let mut buf = Vec::new();
        buf.write_u32::<BigEndian>(over_max).unwrap();
        let mut cursor = Cursor::new(buf.as_slice());
        let result = read_message_frame(&mut cursor);
        assert!(result.is_err(), "one byte over max should be rejected");
    }

    #[test]
    fn test_read_message_frame_exactly_max_size_256kb() {
        let max_len: u32 = 256 * 1024;
        let payload = vec![0x55_u8; max_len as usize];
        let mut buf = Vec::new();
        buf.write_u32::<BigEndian>(max_len).unwrap();
        buf.extend_from_slice(&payload);

        let mut cursor = Cursor::new(buf.as_slice());
        let result = read_message_frame(&mut cursor).unwrap();
        assert_eq!(result.len(), max_len as usize);
        assert!(result.iter().all(|&b| b == 0x55));
    }

    #[test]
    fn test_read_message_frame_size_over_256kb_rejected() {
        let over: u32 = 300 * 1024;
        let mut buf = Vec::new();
        buf.write_u32::<BigEndian>(over).unwrap();
        let mut cursor = Cursor::new(buf.as_slice());
        let result = read_message_frame(&mut cursor);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("too large"),
            "error should mention 'too large': {err_msg}"
        );
    }

    #[test]
    fn test_read_message_frame_size_zero_rejected() {
        let mut buf = Vec::new();
        buf.write_u32::<BigEndian>(0).unwrap();
        let mut cursor = Cursor::new(buf.as_slice());
        let result = read_message_frame(&mut cursor);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("empty"),
            "error should mention 'empty': {err_msg}"
        );
    }

    #[test]
    fn test_write_read_message_frame_roundtrip_various_sizes() {
        for size in [1, 2, 10, 100, 1000, 10_000] {
            let payload: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let mut buf = Vec::new();
            write_message_frame(&mut buf, &payload).unwrap();

            let mut cursor = Cursor::new(buf.as_slice());
            let read_back = read_message_frame(&mut cursor).unwrap();
            assert_eq!(read_back, payload, "roundtrip failed for size {size}");
        }
    }
}
