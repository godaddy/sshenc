// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Secure Enclave key management operations for sshenc.
//!
//! Provides a trait-based abstraction over key operations, with a real
//! macOS Secure Enclave implementation and a mock backend for testing.

pub mod backend;

#[cfg(target_os = "macos")]
pub mod macos;

pub use backend::KeyBackend;

#[cfg(target_os = "macos")]
pub use macos::SecureEnclaveBackend;
