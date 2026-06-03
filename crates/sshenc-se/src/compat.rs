// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Backward-compatible metadata loading for sshenc.
//!
//! Handles both the old sshenc metadata format (pre-libenclaveapp) and the
//! new libenclaveapp format.
//!
//! Also defines `KeyMeta` — a local mirror of the on-disk `.meta` JSON
//! schema. This was previously sourced from `enclaveapp_core`; it is now
//! defined here so `sshenc-se` can depend solely on `hardware-enclave`.

use hardware_enclave::{AccessPolicy, KeyType};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Local error type for metadata operations.
#[derive(Debug)]
pub enum MetaError {
    Io(std::io::Error),
    Serialization(String),
}

impl std::fmt::Display for MetaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MetaError::Io(e) => write!(f, "I/O error: {e}"),
            MetaError::Serialization(s) => write!(f, "serialization error: {s}"),
        }
    }
}

impl From<std::io::Error> for MetaError {
    fn from(e: std::io::Error) -> Self {
        MetaError::Io(e)
    }
}

/// Mirror of the on-disk `.meta` JSON structure (formerly `enclaveapp_core::KeyMeta`).
///
/// The JSON schema is stable: `warning`, `label`, `key_type`, `access_policy`,
/// `created`, `app_specific`. This struct must match it exactly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMeta {
    pub warning: String,
    pub label: String,
    #[serde(with = "key_type_serde")]
    pub key_type: KeyType,
    #[serde(with = "access_policy_serde")]
    pub access_policy: AccessPolicy,
    pub created: String,
    #[serde(default)]
    pub app_specific: serde_json::Value,
}

impl KeyMeta {
    pub fn new(label: &str, key_type: KeyType, access_policy: AccessPolicy) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs().to_string())
            .unwrap_or_default();
        Self {
            warning: meta_warning_default(),
            label: label.to_string(),
            key_type,
            access_policy,
            created: now,
            app_specific: serde_json::Value::Null,
        }
    }

    pub fn set_app_field(&mut self, key: &str, value: impl Into<serde_json::Value>) {
        if self.app_specific.is_null() {
            self.app_specific = serde_json::Value::Object(serde_json::Map::new());
        }
        if let Some(obj) = self.app_specific.as_object_mut() {
            obj.insert(key.to_string(), value.into());
        }
    }

    pub fn get_app_field(&self, key: &str) -> Option<&str> {
        self.app_specific.get(key)?.as_str()
    }
}

/// Save a `KeyMeta` to `<keys_dir>/<label>.meta` atomically.
pub fn save_meta(keys_dir: &Path, label: &str, meta: &KeyMeta) -> Result<(), MetaError> {
    let json =
        serde_json::to_vec_pretty(meta).map_err(|e| MetaError::Serialization(e.to_string()))?;
    let path = keys_dir.join(format!("{label}.meta"));
    hardware_enclave::fs::atomic_write(&path, &json)
        .map_err(|e| MetaError::Io(std::io::Error::other(e.to_string())))
}

/// Load a raw public key from `<keys_dir>/<label>.pub`.
pub fn load_pub_key(keys_dir: &Path, label: &str) -> Result<Vec<u8>, MetaError> {
    let path = keys_dir.join(format!("{label}.pub"));
    hardware_enclave::fs::read_no_follow(&path)
        .map_err(|e| MetaError::Io(std::io::Error::other(e.to_string())))
}

/// Save a raw public key to `<keys_dir>/<label>.pub` atomically.
pub fn save_pub_key(keys_dir: &Path, label: &str, pub_key: &[u8]) -> Result<(), MetaError> {
    let path = keys_dir.join(format!("{label}.pub"));
    hardware_enclave::fs::atomic_write(&path, pub_key)
        .map_err(|e| MetaError::Io(std::io::Error::other(e.to_string())))
}

/// The standard warning string embedded in `.meta` files.
pub fn meta_warning_default() -> String {
    "This file is managed by sshenc. Do not edit manually.".to_string()
}

// ── Serde helpers for KeyType and AccessPolicy ──────────────────────────────

mod key_type_serde {
    use hardware_enclave::KeyType;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &KeyType, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(match v {
            KeyType::Signing => "signing",
            KeyType::Encryption => "encryption",
        })
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<KeyType, D::Error> {
        let s = String::deserialize(d)?;
        match s.as_str() {
            "signing" => Ok(KeyType::Signing),
            "encryption" => Ok(KeyType::Encryption),
            other => Err(serde::de::Error::unknown_variant(
                other,
                &["signing", "encryption"],
            )),
        }
    }
}

mod access_policy_serde {
    use hardware_enclave::AccessPolicy;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &AccessPolicy, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(match v {
            AccessPolicy::None => "none",
            AccessPolicy::Any => "any",
            AccessPolicy::BiometricOnly => "biometric_only",
            AccessPolicy::PasswordOnly => "password_only",
        })
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<AccessPolicy, D::Error> {
        let s = String::deserialize(d)?;
        match s.as_str() {
            "none" => Ok(AccessPolicy::None),
            "any" => Ok(AccessPolicy::Any),
            "biometric_only" => Ok(AccessPolicy::BiometricOnly),
            "password_only" => Ok(AccessPolicy::PasswordOnly),
            other => Err(serde::de::Error::unknown_variant(
                other,
                &["none", "any", "biometric_only", "password_only"],
            )),
        }
    }
}

/// Ensure `dir` exists, creating it and all parents if needed.
pub fn ensure_dir(dir: &Path) -> Result<(), MetaError> {
    hardware_enclave::fs::ensure_dir(dir)
        .map_err(|e| MetaError::Io(std::io::Error::other(e.to_string())))
}

/// List all key labels in the keys directory (files with `.pub` extension, without the extension).
pub fn list_labels(keys_dir: &Path) -> Result<Vec<String>, MetaError> {
    let read = match std::fs::read_dir(keys_dir) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(MetaError::Io(e)),
    };
    let mut labels: Vec<String> = Vec::new();
    for entry in read.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("pub") {
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                labels.push(stem.to_string());
            }
        }
    }
    labels.sort();
    Ok(labels)
}

/// Rename key files (meta, pub, handle) from `old_label` to `new_label`.
/// The `_hmac_key` parameter is accepted for API compatibility but is unused in
/// this simplified implementation (HMAC sidecar is left for `TamperEvidentHandle`
/// to update).
pub fn rename_key_files(
    dir: &Path,
    old_label: &str,
    new_label: &str,
    _hmac_key: Option<&[u8]>,
) -> Result<(), MetaError> {
    let extensions = ["meta", "meta.hmac", "pub", "handle"];
    for ext in &extensions {
        let old_path = dir.join(format!("{old_label}.{ext}"));
        let new_path = dir.join(format!("{new_label}.{ext}"));
        if old_path.exists() {
            std::fs::rename(&old_path, &new_path).map_err(MetaError::Io)?;
        }
    }
    // Update the label field inside the .meta file if it exists.
    let meta_path = dir.join(format!("{new_label}.meta"));
    if meta_path.exists() {
        if let Ok(mut meta) = load_sshenc_meta(dir, new_label) {
            meta.label = new_label.to_string();
            drop(save_meta(dir, new_label, &meta));
        }
    }
    Ok(())
}

/// Load sshenc key metadata, handling both old and new formats.
///
/// Old format (pre-libenclaveapp):
///   `{ "label", "comment", "auth_policy" (int), "git_name", "git_email", "created" }`
///
/// New format (libenclaveapp):
///   `{ "label", "key_type", "access_policy" (string), "created", "app_specific": { ... } }`
pub fn load_sshenc_meta(keys_dir: &Path, label: &str) -> Result<KeyMeta, MetaError> {
    let meta_path = keys_dir.join(format!("{label}.meta"));
    if !meta_path.exists() {
        return Ok(KeyMeta::new(label, KeyType::Signing, AccessPolicy::None));
    }

    let content = std::fs::read_to_string(&meta_path)?;
    let raw: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| MetaError::Serialization(e.to_string()))?;

    // Detect old format: has "comment" or "auth_policy" at top level but no "key_type"
    if raw.get("key_type").is_none()
        && (raw.get("comment").is_some() || raw.get("auth_policy").is_some())
    {
        let auth_policy_int = match raw.get("auth_policy") {
            None => 0_i32,
            Some(v) => {
                let n = v.as_i64().ok_or_else(|| {
                    MetaError::Serialization(format!(
                        "auth_policy in '{label}.meta' is not an integer: {v}"
                    ))
                })?;
                n as i32
            }
        };
        let access_policy = access_policy_from_ffi(auth_policy_int);
        let created = raw
            .get("created")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let mut meta = KeyMeta {
            warning: meta_warning_default(),
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
    serde_json::from_str(&content).map_err(|e| MetaError::Serialization(e.to_string()))
}

/// Map the old integer `auth_policy` field to `AccessPolicy`.
fn access_policy_from_ffi(n: i32) -> AccessPolicy {
    match n {
        1 => AccessPolicy::Any,
        2 => AccessPolicy::BiometricOnly,
        3 => AccessPolicy::PasswordOnly,
        _ => AccessPolicy::None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
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
            "warning": "do not edit",
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
        assert!(meta.app_specific.is_object());
        assert_eq!(meta.get_app_field("git_name"), Some("Alice"));
        assert_eq!(meta.get_app_field("git_email"), Some("alice@example.com"));
        assert_eq!(meta.get_app_field("comment"), Some("my key"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn old_format_without_optional_fields() {
        let dir = test_dir();
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
            "warning": "do not edit",
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
            "warning": "do not edit",
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
        let dir = test_dir();
        let json = serde_json::json!({
            "label": "k",
            "auth_policy": "corrupted"
        });
        std::fs::write(dir.join("k.meta"), json.to_string()).unwrap();

        let result = load_sshenc_meta(&dir, "k");
        assert!(
            result.is_err(),
            "non-integer auth_policy should return an error"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("auth_policy"),
            "error should name the field: {msg}"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn old_format_auth_policy_null_returns_error() {
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

    #[test]
    fn old_format_unrecognized_auth_policy_integer_falls_back_to_none() {
        let dir = test_dir();
        let json = serde_json::json!({
            "label": "k",
            "auth_policy": 999
        });
        std::fs::write(dir.join("k.meta"), json.to_string()).unwrap();

        let meta = load_sshenc_meta(&dir, "k").expect("unknown int auth_policy should not error");
        assert_eq!(
            meta.access_policy,
            AccessPolicy::None,
            "unrecognized integer must fall back to None"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn new_format_missing_required_field_returns_error() {
        let dir = test_dir();
        let json = serde_json::json!({
            "key_type": "signing",
            "access_policy": "none",
            "created": "0",
            "app_specific": null
        });
        std::fs::write(dir.join("missing-label.meta"), json.to_string()).unwrap();

        let result = load_sshenc_meta(&dir, "missing-label");
        assert!(
            result.is_err(),
            "new-format meta with missing required field must return Err"
        );
        let msg = result.unwrap_err().to_string();
        assert!(!msg.is_empty(), "error message must be non-empty");

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
