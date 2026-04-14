// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Hardware-backed key management operations for sshenc.
//!
//! Uses `enclaveapp-app-storage` for platform detection and backend
//! initialization. The `SshencBackend` wraps the platform-specific signer
//! and adds SSH-specific logic (pub file management, fingerprinting,
//! metadata with comments and git identity).

pub mod backend;
pub mod compat;
mod unified;

pub use backend::KeyBackend;
pub use unified::{sshenc_keys_dir, SshencBackend};
