// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Windows TPM 2.0 bridge for sshenc.
//!
//! Uses the CNG (Cryptography Next Generation) `Microsoft Platform Crypto Provider`
//! for TPM-backed ECDSA P-256 key operations. Keys are generated inside the TPM
//! hardware and never leave it.
//!
//! Key metadata is stored in `%APPDATA%\sshenc\keys\`. The actual private keys
//! are persisted by CNG in the TPM's key hierarchy — no key material on disk.

#[cfg(target_os = "windows")]
pub mod tpm;

#[cfg(not(target_os = "windows"))]
pub mod tpm {
    //! Stub module for non-Windows platforms.
    pub fn is_available() -> bool {
        false
    }
}
