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

/// Serialize an AgentRequest into a message payload (client-side).
pub fn serialize_request(request: &AgentRequest) -> Vec<u8> {
    match request {
        AgentRequest::RequestIdentities => vec![SSH_AGENTC_REQUEST_IDENTITIES],
        AgentRequest::SignRequest {
            key_blob,
            data,
            flags,
        } => {
            let mut buf = vec![SSH_AGENTC_SIGN_REQUEST];
            wire::write_string(&mut buf, key_blob);
            wire::write_string(&mut buf, data);
            buf.extend_from_slice(&flags.to_be_bytes());
            buf
        }
        AgentRequest::Unknown(t) => vec![*t],
    }
}

/// Parse a raw message payload into an AgentResponse (client-side).
pub fn parse_response(payload: &[u8]) -> Result<AgentResponse> {
    if payload.is_empty() {
        return Err(Error::AgentProtocol("empty payload".into()));
    }

    let msg_type = payload[0];
    let body = &payload[1..];

    match msg_type {
        SSH_AGENT_FAILURE => Ok(AgentResponse::Failure),
        SSH_AGENT_SUCCESS => Ok(AgentResponse::Success),
        SSH_AGENT_IDENTITIES_ANSWER => {
            if body.len() < 4 {
                return Err(Error::AgentProtocol("identities answer too short".into()));
            }
            let nkeys = u32::from_be_bytes([body[0], body[1], body[2], body[3]]) as usize;
            const MAX_KEYS: usize = 10_000;
            if nkeys > MAX_KEYS {
                return Err(Error::AgentProtocol(format!(
                    "nkeys {nkeys} exceeds maximum {MAX_KEYS}"
                )));
            }
            let mut cursor = Cursor::new(&body[4..]);
            let mut identities = Vec::with_capacity(nkeys);
            for _ in 0..nkeys {
                let key_blob = wire::read_string(&mut cursor)?;
                let comment_bytes = wire::read_string(&mut cursor)?;
                let comment = String::from_utf8_lossy(&comment_bytes).to_string();
                identities.push(Identity { key_blob, comment });
            }
            Ok(AgentResponse::IdentitiesAnswer(identities))
        }
        SSH_AGENT_SIGN_RESPONSE => {
            let mut cursor = Cursor::new(body);
            let signature_blob = wire::read_string(&mut cursor)?;
            Ok(AgentResponse::SignResponse { signature_blob })
        }
        other => Err(Error::AgentProtocol(format!(
            "unexpected response type: {other}"
        ))),
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

    // --- Roundtrip tests: serialize_request -> parse_request ---

    #[test]
    fn test_roundtrip_request_identities() {
        let original = AgentRequest::RequestIdentities;
        let payload = serialize_request(&original);
        let parsed = parse_request(&payload).unwrap();
        assert!(matches!(parsed, AgentRequest::RequestIdentities));
    }

    #[test]
    fn test_roundtrip_sign_request() {
        let key_blob = b"my-key-blob-data".to_vec();
        let data = b"data-to-be-signed".to_vec();
        let flags = 0x02u32;

        let original = AgentRequest::SignRequest {
            key_blob: key_blob.clone(),
            data: data.clone(),
            flags,
        };
        let payload = serialize_request(&original);
        let parsed = parse_request(&payload).unwrap();
        match parsed {
            AgentRequest::SignRequest {
                key_blob: kb,
                data: d,
                flags: f,
            } => {
                assert_eq!(kb, key_blob);
                assert_eq!(d, data);
                assert_eq!(f, flags);
            }
            _ => panic!("expected SignRequest"),
        }
    }

    #[test]
    fn test_roundtrip_sign_request_empty_data() {
        let original = AgentRequest::SignRequest {
            key_blob: vec![],
            data: vec![],
            flags: 0,
        };
        let payload = serialize_request(&original);
        let parsed = parse_request(&payload).unwrap();
        match parsed {
            AgentRequest::SignRequest {
                key_blob,
                data,
                flags,
            } => {
                assert!(key_blob.is_empty());
                assert!(data.is_empty());
                assert_eq!(flags, 0);
            }
            _ => panic!("expected SignRequest"),
        }
    }

    #[test]
    fn test_roundtrip_unknown_request() {
        let original = AgentRequest::Unknown(200);
        let payload = serialize_request(&original);
        let parsed = parse_request(&payload).unwrap();
        assert!(matches!(parsed, AgentRequest::Unknown(200)));
    }

    // --- Roundtrip tests: serialize_response -> parse_response ---

    #[test]
    fn test_roundtrip_identities_answer_empty() {
        let original = AgentResponse::IdentitiesAnswer(vec![]);
        let payload = serialize_response(&original);
        let parsed = parse_response(&payload).unwrap();
        match parsed {
            AgentResponse::IdentitiesAnswer(ids) => assert!(ids.is_empty()),
            _ => panic!("expected IdentitiesAnswer"),
        }
    }

    #[test]
    fn test_roundtrip_identities_answer_multiple() {
        let identities = vec![
            Identity {
                key_blob: b"blob-aaa".to_vec(),
                comment: "first key".into(),
            },
            Identity {
                key_blob: b"blob-bbb".to_vec(),
                comment: "second key".into(),
            },
            Identity {
                key_blob: b"blob-ccc".to_vec(),
                comment: "".into(),
            },
        ];
        let original = AgentResponse::IdentitiesAnswer(identities);
        let payload = serialize_response(&original);
        let parsed = parse_response(&payload).unwrap();
        match parsed {
            AgentResponse::IdentitiesAnswer(ids) => {
                assert_eq!(ids.len(), 3);
                assert_eq!(ids[0].key_blob, b"blob-aaa");
                assert_eq!(ids[0].comment, "first key");
                assert_eq!(ids[1].key_blob, b"blob-bbb");
                assert_eq!(ids[1].comment, "second key");
                assert_eq!(ids[2].key_blob, b"blob-ccc");
                assert_eq!(ids[2].comment, "");
            }
            _ => panic!("expected IdentitiesAnswer"),
        }
    }

    #[test]
    fn test_roundtrip_sign_response() {
        let sig = b"some-signature-bytes".to_vec();
        let original = AgentResponse::SignResponse {
            signature_blob: sig.clone(),
        };
        let payload = serialize_response(&original);
        let parsed = parse_response(&payload).unwrap();
        match parsed {
            AgentResponse::SignResponse { signature_blob } => {
                assert_eq!(signature_blob, sig);
            }
            _ => panic!("expected SignResponse"),
        }
    }

    #[test]
    fn test_roundtrip_failure() {
        let payload = serialize_response(&AgentResponse::Failure);
        let parsed = parse_response(&payload).unwrap();
        assert!(matches!(parsed, AgentResponse::Failure));
    }

    #[test]
    fn test_roundtrip_success() {
        let payload = serialize_response(&AgentResponse::Success);
        let parsed = parse_response(&payload).unwrap();
        assert!(matches!(parsed, AgentResponse::Success));
    }

    #[test]
    fn test_parse_response_empty_payload() {
        let result = parse_response(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_response_unknown_type() {
        let result = parse_response(&[0xFF]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_response_identities_answer_truncated() {
        // Just the type byte, no body for count
        let payload = vec![SSH_AGENT_IDENTITIES_ANSWER];
        let result = parse_response(&payload);
        assert!(result.is_err());
    }
}
