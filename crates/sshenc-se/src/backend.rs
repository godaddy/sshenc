// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Trait-based abstraction over key storage backends.
//!
//! This allows the real Secure Enclave backend to be swapped out with a mock
//! for testing on non-macOS systems or in CI without hardware access.

use enclaveapp_core::types::PresenceMode;
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

    /// Sign with explicit user-presence cadence.
    ///
    /// `mode` controls whether the platform prompt is batched within
    /// `cache_ttl_secs` ([`PresenceMode::Cached`]), required per sign
    /// ([`PresenceMode::Strict`]), or skipped entirely ([`PresenceMode::None`]).
    /// `cache_ttl_secs == 0` collapses `Cached` into `Strict`.
    ///
    /// `reason` is shown verbatim in the Touch ID dialog as `localizedReason`.
    /// Callers should include the operation type and key label, e.g.
    /// `"sshenc: sign git commit (work-key)"`.
    ///
    /// The default impl ignores `mode`, `cache_ttl_secs`, and `reason` and
    /// falls back to [`Self::sign`]. The real backend on macOS overrides
    /// this to plumb a reusable `LAContext` to CryptoKit; mocks and
    /// the agent-proxy backend keep the default.
    fn sign_with_presence(
        &self,
        label: &str,
        data: &[u8],
        mode: PresenceMode,
        cache_ttl_secs: u64,
        reason: &str,
    ) -> Result<Vec<u8>> {
        let _ = (mode, cache_ttl_secs, reason);
        self.sign(label, data)
    }

    /// Check if the backend is available (e.g., Secure Enclave hardware present).
    fn is_available(&self) -> bool;

    // --- FIDO2 / WebAuthn SK key methods --------------------------
    //
    // Default impls error / return empty so existing trait
    // implementors (mock backend, agent-proxy backend) keep
    // compiling. Only `SshencBackend` overrides these. The agent
    // calls these when serving identities and sign requests so SK
    // keys appear alongside legacy keys to ssh.exe / git.

    /// True if `label` resolves to an SK key. Default: false.
    fn is_sk_label(&self, _label: &str) -> bool {
        false
    }

    /// Enumerate SK key labels persisted on disk. Default: empty.
    fn sk_list_labels(&self) -> Result<Vec<String>> {
        Ok(Vec::new())
    }

    /// Load full SK key info. Default: error.
    fn sk_get(&self, label: &str) -> Result<KeyInfo> {
        Err(sshenc_core::error::Error::Other(format!(
            "sk_get not supported on this backend (label '{label}')"
        )))
    }

    /// Sign with an SK key. Default: error.
    fn sk_sign(&self, label: &str, _data: &[u8]) -> Result<Vec<u8>> {
        Err(sshenc_core::error::Error::Other(format!(
            "sk_sign not supported on this backend (label '{label}')"
        )))
    }

    /// Delete an SK key (including its platform-credential entry).
    /// Default: error.
    fn sk_delete(&self, label: &str) -> Result<()> {
        Err(sshenc_core::error::Error::Other(format!(
            "sk_delete not supported on this backend (label '{label}')"
        )))
    }
}
