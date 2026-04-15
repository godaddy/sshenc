// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Core domain models, SSH public key formatting, and shared types for sshenc.
//!
//! This crate provides foundational types and platform-aware utilities used
//! across all other sshenc crates.

pub mod backup;
pub mod bin_discovery;
pub mod config;
pub mod error;
pub mod fingerprint;
pub mod key;
pub mod pubkey;
pub mod ssh_config;

pub use config::{Config, PromptPolicy};
pub use enclaveapp_core::types::AccessPolicy;
pub use error::Error;
pub use key::{KeyInfo, KeyLabel, KeyMetadata};
pub use pubkey::SshPublicKey;
