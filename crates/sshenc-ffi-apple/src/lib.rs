// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Minimal Apple Security.framework bridge layer for sshenc.
//!
//! This crate isolates all direct Apple API calls. Higher-level crates
//! (sshenc-se) consume this through a clean Rust interface.

#[cfg(target_os = "macos")]
pub mod keychain;

#[cfg(not(target_os = "macos"))]
pub mod keychain {
    //! Stub module for non-macOS platforms (compile-only, not functional).

    pub fn is_secure_enclave_available() -> bool {
        false
    }
}
