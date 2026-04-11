// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Hardware-backed key management operations for sshenc.
//!
//! Provides a trait-based abstraction over key operations, with platform-specific
//! implementations for macOS (Secure Enclave) and Windows (TPM 2.0).

pub mod backend;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "windows")]
pub mod windows;

pub use backend::KeyBackend;

#[cfg(target_os = "macos")]
pub use macos::SecureEnclaveBackend;

#[cfg(target_os = "windows")]
pub use windows::TpmBackend;
