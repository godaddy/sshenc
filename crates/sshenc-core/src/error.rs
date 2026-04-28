// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Shared error types for sshenc.

use thiserror::Error;

/// Core error type shared across sshenc crates.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("key not found: {label}")]
    KeyNotFound { label: String },

    #[error("duplicate key label: {label}")]
    DuplicateLabel { label: String },

    #[error("ambiguous key selector: {selector} matches {count} keys")]
    AmbiguousSelector { selector: String, count: usize },

    #[error("invalid key label: {reason}")]
    InvalidLabel { reason: String },

    #[error("Secure Enclave operation failed: {operation}: {detail}")]
    SecureEnclave { operation: String, detail: String },

    #[error("SSH public key encoding error: {0}")]
    SshEncoding(String),

    #[error("invalid SSH public key format: {0}")]
    InvalidPublicKey(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("TOML deserialization error: {0}")]
    TomlDeserialize(#[from] toml::de::Error),

    #[error("TOML serialization error: {0}")]
    TomlSerialize(#[from] toml::ser::Error),

    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("agent protocol error: {0}")]
    AgentProtocol(String),

    #[error("PKCS#11 error: {0}")]
    Pkcs11(String),

    #[error("operation cancelled by user")]
    Cancelled,

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_display_key_not_found() {
        let e = Error::KeyNotFound {
            label: "mykey".into(),
        };
        let msg = e.to_string();
        assert!(!msg.is_empty());
        assert!(msg.contains("mykey"));
    }

    #[test]
    fn test_display_duplicate_label() {
        let e = Error::DuplicateLabel {
            label: "dup".into(),
        };
        let msg = e.to_string();
        assert!(!msg.is_empty());
        assert!(msg.contains("dup"));
    }

    #[test]
    fn test_display_ambiguous_selector() {
        let e = Error::AmbiguousSelector {
            selector: "gh".into(),
            count: 3,
        };
        let msg = e.to_string();
        assert!(!msg.is_empty());
        assert!(msg.contains("gh"));
        assert!(msg.contains("3"));
    }

    #[test]
    fn test_display_invalid_label() {
        let e = Error::InvalidLabel {
            reason: "empty".into(),
        };
        assert!(!e.to_string().is_empty());
    }

    #[test]
    fn test_display_secure_enclave() {
        let e = Error::SecureEnclave {
            operation: "sign".into(),
            detail: "timeout".into(),
        };
        let msg = e.to_string();
        assert!(msg.contains("sign"));
        assert!(msg.contains("timeout"));
    }

    #[test]
    fn test_display_ssh_encoding() {
        let e = Error::SshEncoding("bad format".into());
        assert!(!e.to_string().is_empty());
    }

    #[test]
    fn test_display_invalid_public_key() {
        let e = Error::InvalidPublicKey("wrong length".into());
        assert!(!e.to_string().is_empty());
    }

    #[test]
    fn test_display_config() {
        let e = Error::Config("missing field".into());
        assert!(!e.to_string().is_empty());
    }

    #[test]
    fn test_display_agent_protocol() {
        let e = Error::AgentProtocol("unexpected message".into());
        assert!(!e.to_string().is_empty());
    }

    #[test]
    fn test_display_pkcs11() {
        let e = Error::Pkcs11("init failed".into());
        assert!(!e.to_string().is_empty());
    }

    #[test]
    fn test_display_cancelled() {
        let e = Error::Cancelled;
        assert!(!e.to_string().is_empty());
    }

    #[test]
    fn test_display_other() {
        let e = Error::Other("something".into());
        assert_eq!(e.to_string(), "something");
    }

    #[test]
    fn test_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let e: Error = io_err.into();
        match &e {
            Error::Io(_) => {}
            other => panic!("expected Error::Io, got: {other}"),
        }
        assert!(e.to_string().contains("file missing"));
    }

    #[test]
    fn test_from_serde_json_error() {
        // Create a serde_json error by parsing invalid JSON
        let json_err = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        let e: Error = json_err.into();
        match &e {
            Error::Json(_) => {}
            other => panic!("expected Error::Json, got: {other}"),
        }
        assert!(!e.to_string().is_empty());
    }
}
