// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! SSH agent protocol message types.
//!
//! Implements parsing and serialization for the SSH agent protocol messages
//! needed for OpenSSH interoperability.
//!
//! Reference: draft-miller-ssh-agent (OpenSSH agent protocol)

use crate::wire;
use sshenc_core::error::{Error, Result};
use std::io::Cursor;

// Agent protocol message type constants
pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
pub const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH_AGENT_SUCCESS: u8 = 6;

// Sign request flags
pub const SSH_AGENT_RSA_SHA2_256: u32 = 0x02;
pub const SSH_AGENT_RSA_SHA2_512: u32 = 0x04;

/// A public key identity advertised by the agent.
#[derive(Debug, Clone)]
pub struct Identity {
    /// SSH public key blob (wire format).
    pub key_blob: Vec<u8>,
    /// Comment associated with the key.
    pub comment: String,
}

/// Parsed agent request (client -> agent).
#[derive(Debug)]
pub enum AgentRequest {
    /// SSH_AGENTC_REQUEST_IDENTITIES: list all identities.
    RequestIdentities,
    /// SSH_AGENTC_SIGN_REQUEST: sign data with a specific key.
    SignRequest {
        /// The key blob identifying which key to use.
        key_blob: Vec<u8>,
        /// The data to sign.
        data: Vec<u8>,
        /// Flags (e.g., for RSA signature algorithm selection).
        flags: u32,
    },
    /// An unrecognized message type.
    Unknown(u8),
}

/// Agent response (agent -> client).
#[derive(Debug)]
pub enum AgentResponse {
    /// SSH_AGENT_IDENTITIES_ANSWER: list of identities.
    IdentitiesAnswer(Vec<Identity>),
    /// SSH_AGENT_SIGN_RESPONSE: signature result.
    SignResponse {
        /// The complete signature blob (including algorithm prefix).
        signature_blob: Vec<u8>,
    },
    /// SSH_AGENT_SUCCESS.
    Success,
    /// SSH_AGENT_FAILURE.
    Failure,
}

/// A raw agent message (either request or response).
#[derive(Debug)]
pub enum AgentMessage {
    Request(AgentRequest),
    Response(AgentResponse),
}

/// Parse a raw message payload into an AgentRequest.
pub fn parse_request(payload: &[u8]) -> Result<AgentRequest> {
    if payload.is_empty() {
        return Err(Error::AgentProtocol("empty payload".into()));
    }

    let msg_type = payload[0];
    let body = &payload[1..];

    match msg_type {
        SSH_AGENTC_REQUEST_IDENTITIES => Ok(AgentRequest::RequestIdentities),
        SSH_AGENTC_SIGN_REQUEST => {
            let mut cursor = Cursor::new(body);
            let key_blob = wire::read_string(&mut cursor)?;
            let data = wire::read_string(&mut cursor)?;
            let flags = wire::read_u32(&mut cursor)?;
            Ok(AgentRequest::SignRequest {
                key_blob,
                data,
                flags,
            })
        }
        other => Ok(AgentRequest::Unknown(other)),
    }
}

/// Serialize an AgentResponse into a message payload.
pub fn serialize_response(response: &AgentResponse) -> Vec<u8> {
    match response {
        AgentResponse::Failure => vec![SSH_AGENT_FAILURE],
        AgentResponse::Success => vec![SSH_AGENT_SUCCESS],
        AgentResponse::IdentitiesAnswer(identities) => {
            let mut buf = Vec::new();
            buf.push(SSH_AGENT_IDENTITIES_ANSWER);
            // uint32 nkeys
            let nkeys = identities.len() as u32;
            buf.extend_from_slice(&nkeys.to_be_bytes());
            for id in identities {
                wire::write_string(&mut buf, &id.key_blob);
                wire::write_string(&mut buf, id.comment.as_bytes());
            }
            buf
        }
        AgentResponse::SignResponse { signature_blob } => {
            let mut buf = Vec::new();
            buf.push(SSH_AGENT_SIGN_RESPONSE);
            wire::write_string(&mut buf, signature_blob);
            buf
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_request_identities() {
        let payload = vec![SSH_AGENTC_REQUEST_IDENTITIES];
        let req = parse_request(&payload).unwrap();
        assert!(matches!(req, AgentRequest::RequestIdentities));
    }

    #[test]
    fn test_parse_sign_request() {
        let mut payload = vec![SSH_AGENTC_SIGN_REQUEST];
        wire::write_string(&mut payload, b"key-blob-data");
        wire::write_string(&mut payload, b"data-to-sign");
        payload.extend_from_slice(&0u32.to_be_bytes()); // flags

        let req = parse_request(&payload).unwrap();
        match req {
            AgentRequest::SignRequest {
                key_blob,
                data,
                flags,
            } => {
                assert_eq!(key_blob, b"key-blob-data");
                assert_eq!(data, b"data-to-sign");
                assert_eq!(flags, 0);
            }
            _ => panic!("expected SignRequest"),
        }
    }

    #[test]
    fn test_parse_unknown_type() {
        let payload = vec![255];
        let req = parse_request(&payload).unwrap();
        assert!(matches!(req, AgentRequest::Unknown(255)));
    }

    #[test]
    fn test_serialize_failure() {
        let payload = serialize_response(&AgentResponse::Failure);
        assert_eq!(payload, vec![SSH_AGENT_FAILURE]);
    }

    #[test]
    fn test_serialize_identities_answer() {
        let identities = vec![
            Identity {
                key_blob: b"blob1".to_vec(),
                comment: "key1".into(),
            },
            Identity {
                key_blob: b"blob2".to_vec(),
                comment: "key2".into(),
            },
        ];
        let payload = serialize_response(&AgentResponse::IdentitiesAnswer(identities));
        assert_eq!(payload[0], SSH_AGENT_IDENTITIES_ANSWER);
        // nkeys = 2
        let nkeys = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
        assert_eq!(nkeys, 2);
    }

    #[test]
    fn test_serialize_sign_response() {
        let payload = serialize_response(&AgentResponse::SignResponse {
            signature_blob: b"sig-data".to_vec(),
        });
        assert_eq!(payload[0], SSH_AGENT_SIGN_RESPONSE);
    }

    #[test]
    fn test_empty_payload() {
        let result = parse_request(&[]);
        assert!(result.is_err());
    }
}
