// Copyright 2026 Jay Gowdy
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

    #[error("invalid signature format: {0}")]
    InvalidSignature(String),

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

impl Error {
    /// Whether this error represents "the requested key doesn't exist".
    ///
    /// Idempotent CLI flags like `--if-exists` need to distinguish a
    /// missing key (no-op) from a real failure (surface). The typed
    /// `KeyNotFound` variant is the obvious case; `SecureEnclave` is
    /// also common because backend errors get wrapped at the proxy
    /// boundary (see `sshenc_se::proxy::map_meta_err`) into a
    /// SecureEnclave whose `detail` carries the original error's
    /// `Display`. We match on a `key not found` prefix in `detail`
    /// to recognize that wrapping; ordering matches what
    /// `KeyNotFound::Display` produces.
    pub fn is_key_not_found(&self) -> bool {
        match self {
            Error::KeyNotFound { .. } => true,
            Error::SecureEnclave { detail, .. } => detail.starts_with("key not found"),
            _ => false,
        }
    }

    /// Whether this error is a transient keychain access failure that may
    /// succeed after evicting cached wrapping keys and LAContexts.
    pub fn is_keychain_recoverable(&self) -> bool {
        match self {
            Error::SecureEnclave { detail, .. } => {
                detail.contains("keychain interaction required")
                    || detail.contains("no window server access")
            }
            _ => false,
        }
    }
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
    fn is_key_not_found_matches_typed_variant() {
        let e = Error::KeyNotFound { label: "x".into() };
        assert!(e.is_key_not_found());
    }

    #[test]
    fn is_key_not_found_matches_wrapped_secure_enclave() {
        // proxy::map_meta_err wraps the underlying Error::Display into
        // a SecureEnclave detail; KeyNotFound's Display is
        // "key not found: <label>".
        let e = Error::SecureEnclave {
            operation: "load_pub_key".into(),
            detail: "key not found: x".into(),
        };
        assert!(e.is_key_not_found());
    }

    #[test]
    fn is_key_not_found_rejects_unrelated_errors() {
        let e = Error::DuplicateLabel { label: "x".into() };
        assert!(!e.is_key_not_found());
        let e = Error::SecureEnclave {
            operation: "sign".into(),
            detail: "timeout".into(),
        };
        assert!(!e.is_key_not_found());
        let e = Error::Other("anything".into());
        assert!(!e.is_key_not_found());
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

    #[test]
    fn is_keychain_recoverable_matches_interaction_required() {
        let e = Error::SecureEnclave {
            operation: "sign_with_presence".into(),
            detail:
                "keychain interaction required for 'default': the item needs user authentication"
                    .into(),
        };
        assert!(e.is_keychain_recoverable());
    }

    #[test]
    fn is_keychain_recoverable_matches_no_window_server() {
        let e = Error::SecureEnclave {
            operation: "sign_with_presence".into(),
            detail: "no window server access for 'default': Touch ID requires a GUI session".into(),
        };
        assert!(e.is_keychain_recoverable());
    }

    #[test]
    fn is_keychain_recoverable_rejects_unrelated_errors() {
        let e = Error::SecureEnclave {
            operation: "sign".into(),
            detail: "timeout".into(),
        };
        assert!(!e.is_keychain_recoverable());
        let e = Error::KeyNotFound { label: "x".into() };
        assert!(!e.is_keychain_recoverable());
        let e = Error::Other("anything".into());
        assert!(!e.is_keychain_recoverable());
    }
}
