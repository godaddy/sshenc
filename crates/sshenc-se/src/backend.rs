// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Trait-based abstraction over key storage backends.
//!
//! This allows the real Secure Enclave backend to be swapped out with a mock
//! for testing on non-macOS systems or in CI without hardware access.

use sshenc_core::error::Result;
use sshenc_core::key::{KeyGenOptions, KeyInfo};

/// Backend trait for key storage and cryptographic operations.
///
/// Implementors provide the actual key lifecycle: generation, lookup, signing,
/// and deletion. The real implementation uses macOS Secure Enclave; tests can
/// use an in-memory mock.
pub trait KeyBackend: Send + Sync {
    /// Generate a new key pair and return its info (including public key material).
    fn generate(&self, opts: &KeyGenOptions) -> Result<KeyInfo>;

    /// List all sshenc-managed keys.
    fn list(&self) -> Result<Vec<KeyInfo>>;

    /// Get detailed info for a key by label.
    fn get(&self, label: &str) -> Result<KeyInfo>;

    /// Delete a key by label.
    fn delete(&self, label: &str) -> Result<()>;

    /// Rename a key from `old_label` to `new_label`.
    ///
    /// Must be atomic enough that the key remains usable under exactly
    /// one label at all times from the perspective of subsequent
    /// `get`/`sign` calls. Backends with label-keyed side state (macOS
    /// keychain wrapping entries, keyring KEKs) must move that state
    /// together with the on-disk metadata — otherwise a plain metadata
    /// rename leaves the new label unable to decrypt.
    fn rename(&self, old_label: &str, new_label: &str) -> Result<()>;

    /// Sign data using the key identified by label.
    /// Returns the raw signature bytes (DER-encoded ECDSA for the real backend).
    fn sign(&self, label: &str, data: &[u8]) -> Result<Vec<u8>>;

    /// Check if the backend is available (e.g., Secure Enclave hardware present).
    fn is_available(&self) -> bool;
}
