// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Apple Secure Enclave bridge for sshenc.
//!
//! Uses CryptoKit (via a Swift static library) for Secure Enclave P-256 key
//! operations. This avoids the keychain-access-groups entitlement requirement
//! that Security.framework imposes.
//!
//! Keys are persisted as CryptoKit `dataRepresentation` blobs in
//! `~/.sshenc/keys/<label>.key`. The private key material never leaves
//! the Secure Enclave — the blob contains only an opaque handle.

#[cfg(target_os = "macos")]
pub mod se;

#[cfg(not(target_os = "macos"))]
pub mod se {
    pub fn is_available() -> bool {
        false
    }
}
