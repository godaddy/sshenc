// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! SSH agent protocol types and encoding/decoding.
//!
//! Implements the subset of the SSH agent protocol (draft-miller-ssh-agent)
//! needed for OpenSSH interoperability:
//! - Identity enumeration (SSH_AGENTC_REQUEST_IDENTITIES / SSH_AGENT_IDENTITIES_ANSWER)
//! - Signing (SSH_AGENTC_SIGN_REQUEST / SSH_AGENT_SIGN_RESPONSE)
//! - Failure (SSH_AGENT_FAILURE)

pub mod client;
pub mod message;
#[cfg(windows)]
pub mod pipe;
pub mod signature;
pub mod wire;

pub use message::{AgentMessage, AgentRequest, AgentResponse, Identity};
