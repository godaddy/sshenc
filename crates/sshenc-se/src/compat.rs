// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Backward-compatible metadata loading for sshenc.
//!
//! Handles both the old sshenc metadata format (pre-libenclaveapp) and the
//! new libenclaveapp format.

use enclaveapp_core::types::{AccessPolicy, KeyType};
use std::path::Path;

/// Load sshenc key metadata, handling both old and new formats.
///
/// Old format (pre-libenclaveapp):
///   `{ "label", "comment", "auth_policy" (int), "git_name", "git_email", "created" }`
///
/// New format (libenclaveapp):
///   `{ "label", "key_type", "access_policy" (string), "created", "app_specific": { ... } }`
pub fn load_sshenc_meta(
    keys_dir: &Path,
    label: &str,
) -> std::result::Result<enclaveapp_core::KeyMeta, enclaveapp_core::Error> {
    let meta_path = keys_dir.join(format!("{label}.meta"));
    if !meta_path.exists() {
        return Ok(enclaveapp_core::KeyMeta::new(
            label,
            KeyType::Signing,
            AccessPolicy::None,
        ));
    }

    let content = std::fs::read_to_string(&meta_path)?;
    let raw: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| enclaveapp_core::Error::Serialization(e.to_string()))?;

    // Detect old format: has "comment" or "auth_policy" at top level but no "key_type"
    if raw.get("key_type").is_none()
        && (raw.get("comment").is_some() || raw.get("auth_policy").is_some())
    {
        let auth_policy_int = raw
            .get("auth_policy")
            .and_then(|v| v.as_i64())
            .unwrap_or(0) as i32;
        let access_policy = AccessPolicy::from_ffi_value(auth_policy_int);
        let created = raw
            .get("created")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let mut meta = enclaveapp_core::KeyMeta {
            label: label.to_string(),
            key_type: KeyType::Signing,
            access_policy,
            created,
            app_specific: serde_json::Value::Null,
        };
        if let Some(comment) = raw.get("comment").and_then(|v| v.as_str()) {
            meta.set_app_field("comment", comment);
        }
        if let Some(git_name) = raw.get("git_name").and_then(|v| v.as_str()) {
            meta.set_app_field("git_name", git_name);
        }
        if let Some(git_email) = raw.get("git_email").and_then(|v| v.as_str()) {
            meta.set_app_field("git_email", git_email);
        }
        return Ok(meta);
    }

    // New format
    serde_json::from_str(&content)
        .map_err(|e| enclaveapp_core::Error::Serialization(e.to_string()))
}
