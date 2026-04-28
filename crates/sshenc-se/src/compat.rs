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
) -> Result<enclaveapp_core::KeyMeta, enclaveapp_core::Error> {
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
        let auth_policy_int = match raw.get("auth_policy") {
            None => 0i32,
            Some(v) => {
                let n = v.as_i64().ok_or_else(|| {
                    enclaveapp_core::Error::Serialization(format!(
                        "auth_policy in '{label}.meta' is not an integer: {v}"
                    ))
                })?;
                n as i32
            }
        };
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
    serde_json::from_str(&content).map_err(|e| enclaveapp_core::Error::Serialization(e.to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use enclaveapp_core::types::{AccessPolicy, KeyType};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_dir() -> std::path::PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("sshenc-se-compat-test-{pid}-{id}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn load_old_format_basic_fields() {
        let dir = test_dir();
        let json = serde_json::json!({
            "label": "mykey",
            "comment": "user@host",
            "auth_policy": 1,
            "git_name": "Jay Gowdy",
            "git_email": "jay@example.com",
            "created": "1700000000"
        });
        std::fs::write(dir.join("mykey.meta"), json.to_string()).unwrap();

        let meta = load_sshenc_meta(&dir, "mykey").unwrap();
        assert_eq!(meta.label, "mykey");
        assert_eq!(meta.key_type, KeyType::Signing);
        assert_eq!(meta.access_policy, AccessPolicy::Any);
        assert_eq!(meta.created, "1700000000");
        assert_eq!(meta.get_app_field("comment"), Some("user@host"));
        assert_eq!(meta.get_app_field("git_name"), Some("Jay Gowdy"));
        assert_eq!(meta.get_app_field("git_email"), Some("jay@example.com"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_new_format_basic_fields() {
        let dir = test_dir();
        let json = serde_json::json!({
            "label": "newkey",
            "key_type": "signing",
            "access_policy": "any",
            "created": "1700000001",
            "app_specific": {
                "comment": "new comment",
                "git_name": "New Name"
            }
        });
        std::fs::write(dir.join("newkey.meta"), json.to_string()).unwrap();

        let meta = load_sshenc_meta(&dir, "newkey").unwrap();
        assert_eq!(meta.label, "newkey");
        assert_eq!(meta.key_type, KeyType::Signing);
        assert_eq!(meta.access_policy, AccessPolicy::Any);
        assert_eq!(meta.created, "1700000001");
        assert_eq!(meta.get_app_field("comment"), Some("new comment"));
        assert_eq!(meta.get_app_field("git_name"), Some("New Name"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_missing_file_returns_default() {
        let dir = test_dir();

        let meta = load_sshenc_meta(&dir, "nonexistent").unwrap();
        assert_eq!(meta.label, "nonexistent");
        assert_eq!(meta.key_type, KeyType::Signing);
        assert_eq!(meta.access_policy, AccessPolicy::None);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn old_format_auth_policy_0_maps_to_none() {
        let dir = test_dir();
        let json = serde_json::json!({
            "label": "k",
            "auth_policy": 0
        });
        std::fs::write(dir.join("k.meta"), json.to_string()).unwrap();

        let meta = load_sshenc_meta(&dir, "k").unwrap();
        assert_eq!(meta.access_policy, AccessPolicy::None);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn old_format_auth_policy_1_maps_to_any() {
        let dir = test_dir();
        let json = serde_json::json!({
            "label": "k",
            "auth_policy": 1
        });
        std::fs::write(dir.join("k.meta"), json.to_string()).unwrap();

        let meta = load_sshenc_meta(&dir, "k").unwrap();
        assert_eq!(meta.access_policy, AccessPolicy::Any);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn old_format_auth_policy_2_maps_to_biometric() {
        let dir = test_dir();
        let json = serde_json::json!({
            "label": "k",
            "auth_policy": 2
        });
        std::fs::write(dir.join("k.meta"), json.to_string()).unwrap();

        let meta = load_sshenc_meta(&dir, "k").unwrap();
        assert_eq!(meta.access_policy, AccessPolicy::BiometricOnly);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn old_format_auth_policy_3_maps_to_password() {
        let dir = test_dir();
        let json = serde_json::json!({
            "label": "k",
            "auth_policy": 3
        });
        std::fs::write(dir.join("k.meta"), json.to_string()).unwrap();

        let meta = load_sshenc_meta(&dir, "k").unwrap();
        assert_eq!(meta.access_policy, AccessPolicy::PasswordOnly);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn old_format_missing_auth_policy_defaults_to_none() {
        let dir = test_dir();
        let json = serde_json::json!({
            "label": "k",
            "comment": "just a comment"
        });
        std::fs::write(dir.join("k.meta"), json.to_string()).unwrap();

        let meta = load_sshenc_meta(&dir, "k").unwrap();
        assert_eq!(meta.access_policy, AccessPolicy::None);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn old_format_git_fields_migrate_to_app_specific() {
        let dir = test_dir();
        let json = serde_json::json!({
            "label": "k",
            "comment": "my key",
            "git_name": "Alice",
            "git_email": "alice@example.com"
        });
        std::fs::write(dir.join("k.meta"), json.to_string()).unwrap();

        let meta = load_sshenc_meta(&dir, "k").unwrap();
        // git_name and git_email should be in app_specific
        assert!(meta.app_specific.is_object());
        assert_eq!(meta.get_app_field("git_name"), Some("Alice"));
        assert_eq!(meta.get_app_field("git_email"), Some("alice@example.com"));
        assert_eq!(meta.get_app_field("comment"), Some("my key"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn old_format_without_optional_fields() {
        let dir = test_dir();
        // Minimal old format: just auth_policy, no comment/git fields
        let json = serde_json::json!({
            "label": "k",
            "auth_policy": 0
        });
        std::fs::write(dir.join("k.meta"), json.to_string()).unwrap();

        let meta = load_sshenc_meta(&dir, "k").unwrap();
        assert_eq!(meta.access_policy, AccessPolicy::None);
        assert!(meta.get_app_field("comment").is_none());
        assert!(meta.get_app_field("git_name").is_none());
        assert!(meta.get_app_field("git_email").is_none());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn old_format_missing_created_defaults_to_empty() {
        let dir = test_dir();
        let json = serde_json::json!({
            "label": "k",
            "comment": "c"
        });
        std::fs::write(dir.join("k.meta"), json.to_string()).unwrap();

        let meta = load_sshenc_meta(&dir, "k").unwrap();
        assert_eq!(meta.created, "");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn new_format_encryption_key_type() {
        let dir = test_dir();
        let json = serde_json::json!({
            "label": "enckey",
            "key_type": "encryption",
            "access_policy": "biometric_only",
            "created": "1700000002",
            "app_specific": null
        });
        std::fs::write(dir.join("enckey.meta"), json.to_string()).unwrap();

        let meta = load_sshenc_meta(&dir, "enckey").unwrap();
        assert_eq!(meta.key_type, KeyType::Encryption);
        assert_eq!(meta.access_policy, AccessPolicy::BiometricOnly);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn new_format_with_empty_app_specific() {
        let dir = test_dir();
        let json = serde_json::json!({
            "label": "bare",
            "key_type": "signing",
            "access_policy": "none",
            "created": "1700000003",
            "app_specific": {}
        });
        std::fs::write(dir.join("bare.meta"), json.to_string()).unwrap();

        let meta = load_sshenc_meta(&dir, "bare").unwrap();
        assert_eq!(meta.label, "bare");
        assert_eq!(meta.access_policy, AccessPolicy::None);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn invalid_json_returns_error() {
        let dir = test_dir();
        std::fs::write(dir.join("bad.meta"), "not json at all").unwrap();

        let result = load_sshenc_meta(&dir, "bad");
        assert!(result.is_err());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn old_format_auth_policy_string_returns_error() {
        // A string where an integer is expected should fail, not silently
        // default to AccessPolicy::None.
        let dir = test_dir();
        let json = serde_json::json!({
            "label": "k",
            "auth_policy": "corrupted"
        });
        std::fs::write(dir.join("k.meta"), json.to_string()).unwrap();

        let result = load_sshenc_meta(&dir, "k");
        assert!(result.is_err(), "non-integer auth_policy should return an error");
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("auth_policy"), "error should name the field: {msg}");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn old_format_auth_policy_null_returns_error() {
        // Explicit null is also not a valid integer and should fail.
        let dir = test_dir();
        let json = serde_json::json!({
            "label": "k",
            "auth_policy": null
        });
        std::fs::write(dir.join("k.meta"), json.to_string()).unwrap();

        let result = load_sshenc_meta(&dir, "k");
        assert!(result.is_err(), "null auth_policy should return an error");

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
