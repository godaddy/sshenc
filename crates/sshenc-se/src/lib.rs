// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Hardware-backed key management operations for sshenc.
//!
//! Provides a trait-based abstraction over key operations, with platform-specific
//! implementations for macOS (Secure Enclave), Windows (TPM 2.0), and Linux
//! (software-backed ECDSA P-256).

pub mod backend;
pub mod compat;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "linux")]
pub mod linux;

pub use backend::KeyBackend;

#[cfg(target_os = "macos")]
pub use macos::SecureEnclaveBackend;

#[cfg(target_os = "windows")]
pub use windows::TpmBackend;

#[cfg(target_os = "linux")]
pub use linux::SoftwareBackend;
