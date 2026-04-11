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

    let mut buf = vec![0u8; len as usize];
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
    let mut buf = vec![0u8; len as usize];
    cursor
        .read_exact(&mut buf)
        .map_err(|e| Error::AgentProtocol(format!("failed to read string data: {e}")))?;
    Ok(buf)
}

/// Write an SSH string (uint32 length + data) to a buffer.
pub fn write_string(buf: &mut Vec<u8>, data: &[u8]) {
    buf.write_u32::<BigEndian>(data.len() as u32).unwrap();
    buf.write_all(data).unwrap();
}

/// Read a uint32 from a cursor.
pub fn read_u32(cursor: &mut Cursor<&[u8]>) -> Result<u32> {
    cursor
        .read_u32::<BigEndian>()
        .map_err(|e| Error::AgentProtocol(format!("failed to read u32: {e}")))
}

#[cfg(test)]
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
}
