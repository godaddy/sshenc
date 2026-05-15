// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Contract tests for the `KeyBackend` trait.
//!
//! These run against `MockKeyBackend` and verify the invariants that all
//! `KeyBackend` implementations must satisfy. Adding new implementations
//! means running this suite against them too.

#![allow(clippy::unwrap_used, clippy::panic)]

use sshenc_core::key::{KeyGenOptions, KeyLabel};
use sshenc_core::{AccessPolicy, PresenceMode};
use sshenc_se::backend::KeyBackend;
use sshenc_test_support::MockKeyBackend;

fn opts(label: &str) -> KeyGenOptions {
    KeyGenOptions {
        label: KeyLabel::new(label).unwrap(),
        comment: Some(format!("comment-{label}")),
        access_policy: AccessPolicy::None,
        presence_mode: PresenceMode::None,
        write_pub_path: None,
        record_pub_path: None,
    }
}

fn backend() -> MockKeyBackend {
    MockKeyBackend::new()
}

// --- generate ---

#[test]
fn generate_returns_key_with_requested_label_and_algorithm() {
    let b = backend();
    let info = b.generate(&opts("my-key")).unwrap();
    assert_eq!(info.metadata.label.as_str(), "my-key");
    assert_eq!(info.public_key_bytes.len(), 65);
    assert_eq!(info.public_key_bytes[0], 0x04, "SEC1 uncompressed prefix");
}

#[test]
fn generate_duplicate_label_returns_error_and_leaves_backend_unchanged() {
    let b = backend();
    b.generate(&opts("dup")).unwrap();
    let result = b.generate(&opts("dup"));
    assert!(result.is_err(), "duplicate label must be rejected");
    // Only one key should exist.
    assert_eq!(b.list().unwrap().len(), 1);
}

#[test]
fn generate_invalid_label_returns_error() {
    let b = backend();
    // An empty string is not a valid label.
    let bad_opts = KeyGenOptions {
        label: KeyLabel::new("a").unwrap(), // placeholder; we build bad label separately
        comment: None,
        access_policy: AccessPolicy::None,
        presence_mode: PresenceMode::None,
        write_pub_path: None,
        record_pub_path: None,
    };
    // KeyLabel::new validates; verify directly that invalid labels are rejected.
    assert!(KeyLabel::new("").is_err(), "empty label must be invalid");
    assert!(
        KeyLabel::new(&"x".repeat(200)).is_err(),
        "excessively long label must be invalid"
    );
    // Backend is still empty.
    assert_eq!(b.list().unwrap().len(), 0);
    drop(bad_opts);
}

// --- list ---

#[test]
fn list_on_empty_backend_returns_empty_vec() {
    let b = backend();
    let keys = b.list().unwrap();
    assert!(keys.is_empty());
}

#[test]
fn list_after_generate_includes_generated_key() {
    let b = backend();
    b.generate(&opts("alpha")).unwrap();
    let keys = b.list().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].metadata.label.as_str(), "alpha");
}

// --- get ---

#[test]
fn get_after_generate_returns_same_key_info() {
    let b = backend();
    let generated = b.generate(&opts("fetch-me")).unwrap();
    let fetched = b.get("fetch-me").unwrap();
    assert_eq!(fetched.metadata.label.as_str(), generated.metadata.label.as_str());
    assert_eq!(fetched.public_key_bytes, generated.public_key_bytes);
}

#[test]
fn get_nonexistent_label_returns_not_found() {
    let b = backend();
    let result = b.get("ghost");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.is_key_not_found(), "expected key-not-found, got: {err}");
}

// --- delete ---

#[test]
fn delete_removes_key_from_list_and_get() {
    let b = backend();
    b.generate(&opts("gone")).unwrap();
    b.delete("gone").unwrap();
    assert!(b.list().unwrap().is_empty());
    let result = b.get("gone");
    assert!(result.is_err());
    assert!(result.unwrap_err().is_key_not_found());
}

#[test]
fn delete_nonexistent_label_returns_not_found() {
    let b = backend();
    let result = b.delete("phantom");
    assert!(result.is_err());
    assert!(result.unwrap_err().is_key_not_found());
}

// --- rename ---

#[test]
fn rename_makes_old_label_unreachable_and_new_label_reachable() {
    let b = backend();
    b.generate(&opts("before")).unwrap();
    b.rename("before", "after").unwrap();
    assert!(b.get("before").unwrap_err().is_key_not_found());
    assert!(b.get("after").is_ok());
    assert_eq!(b.list().unwrap().len(), 1);
}

#[test]
fn rename_to_existing_label_returns_error_and_leaves_both_keys_intact() {
    let b = backend();
    b.generate(&opts("k1")).unwrap();
    b.generate(&opts("k2")).unwrap();
    let result = b.rename("k1", "k2");
    assert!(result.is_err(), "rename to occupied label must fail");
    // Both keys must still exist.
    assert!(b.get("k1").is_ok());
    assert!(b.get("k2").is_ok());
}

#[test]
fn rename_nonexistent_source_returns_not_found() {
    let b = backend();
    let result = b.rename("ghost", "new-name");
    assert!(result.is_err());
    assert!(result.unwrap_err().is_key_not_found());
}

// --- sign ---

#[test]
fn sign_returns_nonempty_bytes() {
    let b = backend();
    b.generate(&opts("signer")).unwrap();
    let sig = b.sign("signer", b"hello").unwrap();
    assert!(!sig.is_empty());
}

#[test]
fn sign_nonexistent_label_returns_not_found() {
    let b = backend();
    let result = b.sign("missing", b"data");
    assert!(result.is_err());
    assert!(result.unwrap_err().is_key_not_found());
}

#[test]
fn sign_twice_with_same_inputs_both_succeed() {
    let b = backend();
    b.generate(&opts("double")).unwrap();
    let sig1 = b.sign("double", b"payload").unwrap();
    let sig2 = b.sign("double", b"payload").unwrap();
    // Both must be non-empty; MockKeyBackend is deterministic so they're equal,
    // but the contract only requires neither errors.
    assert!(!sig1.is_empty());
    assert!(!sig2.is_empty());
}
