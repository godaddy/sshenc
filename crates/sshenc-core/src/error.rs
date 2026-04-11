// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Shared error types for sshenc.

use thiserror::Error;

/// Core error type shared across sshenc crates.
#[derive(Debug, Error)]
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
