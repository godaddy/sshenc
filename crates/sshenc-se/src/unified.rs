// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Unified backend implementation using `enclaveapp-app-storage`.
//!
//! Replaces the per-platform macos.rs, windows.rs, linux.rs with a single
//! implementation that delegates platform detection to `AppSigningBackend`.

use crate::backend::KeyBackend;
use crate::compat;
use enclaveapp_app_storage::{
    AccessPolicy, AppSigningBackend, BackendKind, EnclaveKeyManager, EnclaveSigner, StorageConfig,
};
use enclaveapp_core::metadata;
use enclaveapp_core::types::{KeyType, PresenceMode};
use sshenc_core::error::{Error, Result};
use sshenc_core::fingerprint;
use sshenc_core::key::{KeyGenOptions, KeyInfo, KeyLabel, KeyMetadata};
use sshenc_core::pubkey::SshPublicKey;
use std::path::PathBuf;

/// Environment variable that opts into the software signing backend.
///
/// Only honored when sshenc-se is compiled with the `force-software`
/// feature. Otherwise ignored. Exists so the e2e suite can exercise the
/// software code path on any developer machine without needing Linux +
/// TPM-absent conditions to flip auto-detection.
#[cfg(feature = "force-software")]
pub const FORCE_SOFTWARE_ENV: &str = "SSHENC_FORCE_SOFTWARE";

#[cfg(feature = "force-software")]
#[derive(Debug)]
enum BackendImpl {
    Platform(AppSigningBackend),
    Software(enclaveapp_test_software::SoftwareSigner),
}

#[cfg(not(feature = "force-software"))]
#[derive(Debug)]
enum BackendImpl {
    Platform(AppSigningBackend),
}

/// Unified sshenc backend using `AppSigningBackend` for platform dispatch.
///
/// Handles SSH-specific concerns (pub file writing, fingerprinting, metadata
/// with comments and git identity) on top of the shared signing backend.
#[derive(Debug)]
pub struct SshencBackend {
    /// Directory where SSH .pub files are written (typically ~/.ssh).
    pub_dir: PathBuf,
    /// Keys directory (typically ~/.sshenc/keys/).
    keys_dir: PathBuf,
    /// The platform-detected signing backend, or the test-software
    /// backend when `SSHENC_FORCE_SOFTWARE` is set and the
    /// `force-software` feature is compiled in.
    backend: BackendImpl,
    /// Wrapping-key cache TTL, plumbed through to
    /// [`EnclaveSigner::sign_with_presence`] so the macOS LAContext
    /// reuse window stays aligned with the wrapping-key cache. `0`
    /// disables caching at every layer (per-sign prompts).
    cache_ttl: std::time::Duration,
}

/// Resolve the effective wrapping-key cache TTL, honoring the
/// `SSHENC_WRAPPING_KEY_CACHE_TTL_SECS` env override when set.
/// Returns 4 hours if neither the env var nor a caller supplies a
/// value.
///
/// Kept in sync with `sshenc_core::config::default_wrapping_key_cache_ttl_secs`
/// -- both must agree so a CLI sign that goes through `SshencBackend::new`
/// (no config file) honors the same wrapping-key reuse window the
/// agent advertises when it loads the same config.
pub fn default_wrapping_key_cache_ttl() -> std::time::Duration {
    if let Some(value) = std::env::var_os("SSHENC_WRAPPING_KEY_CACHE_TTL_SECS") {
        if let Ok(secs) = value.to_string_lossy().parse::<u64>() {
            return std::time::Duration::from_secs(secs);
        }
    }
    std::time::Duration::from_secs(14400)
}

/// Return the sshenc keys directory (~/.sshenc/keys/).
///
/// Respects the `SSHENC_KEYS_DIR` environment variable if set. That override
/// exists to let e2e tests share one persistent SE key across runs instead
/// of creating a fresh one per-run — on macOS each new SE key gets its own
/// keychain ACL, so per-run keys produce per-run "Always Allow" prompts.
#[cfg(feature = "force-software")]
fn force_software_selected() -> bool {
    std::env::var_os(FORCE_SOFTWARE_ENV).is_some_and(|v| !v.is_empty() && v != "0")
}

pub fn sshenc_keys_dir() -> PathBuf {
    if let Some(override_path) = std::env::var_os("SSHENC_KEYS_DIR") {
        return PathBuf::from(override_path);
    }
    // sshenc uses ~/.sshenc/keys/ on Unix, %APPDATA%\sshenc\keys\ on Windows.
    #[cfg(windows)]
    {
        dirs::data_dir()
            .or_else(dirs::home_dir)
            .unwrap_or_else(std::env::temp_dir)
            .join("sshenc")
            .join("keys")
    }
    #[cfg(not(windows))]
    {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join(".sshenc")
            .join("keys")
    }
}

impl SshencBackend {
    /// Create a new sshenc backend with automatic platform detection.
    ///
    /// Uses `macOS` keychain wrapping-key user-presence (biometric or
    /// device passcode) with the 5-minute default cache TTL. Callers
    /// that need a different TTL (notably the agent, which reads the
    /// sshenc config) should call [`SshencBackend::with_cache_ttl`].
    ///
    /// If the `force-software` feature is compiled in and
    /// `SSHENC_FORCE_SOFTWARE=1` is set at runtime, constructs the
    /// test-only software backend instead. The env var is only consulted
    /// when the feature is enabled; production builds never see it.
    pub fn new(
        pub_dir: PathBuf,
        force_keyring: bool,
    ) -> std::result::Result<Self, enclaveapp_app_storage::StorageError> {
        Self::with_cache_ttl(pub_dir, force_keyring, default_wrapping_key_cache_ttl())
    }

    /// Create a backend with an explicit wrapping-key cache TTL. On
    /// macOS this also sets the keychain-item access control to
    /// `.userPresence` so the authentication mechanism is tied to the
    /// user (Touch ID or passcode) rather than to the binary's
    /// ad-hoc signature.
    pub fn with_cache_ttl(
        pub_dir: PathBuf,
        force_keyring: bool,
        cache_ttl: std::time::Duration,
    ) -> std::result::Result<Self, enclaveapp_app_storage::StorageError> {
        let keys_dir = sshenc_keys_dir();

        #[cfg(feature = "force-software")]
        {
            if force_software_selected() {
                metadata::ensure_dir(&keys_dir).map_err(|e| {
                    enclaveapp_app_storage::StorageError::KeyInitFailed(format!(
                        "prepare keys_dir for force-software: {e}"
                    ))
                })?;
                let signer = enclaveapp_test_software::SoftwareSigner::with_keys_dir(
                    "sshenc",
                    keys_dir.clone(),
                );
                tracing::debug!(
                    keys_dir = %keys_dir.display(),
                    "sshenc using test-software signing backend (SSHENC_FORCE_SOFTWARE)"
                );
                return Ok(Self {
                    pub_dir,
                    keys_dir,
                    backend: BackendImpl::Software(signer),
                    cache_ttl,
                });
            }
        }

        let backend = AppSigningBackend::init(StorageConfig {
            app_name: "sshenc".into(),
            key_label: String::new(), // sshenc manages multiple keys, no single label
            access_policy: AccessPolicy::None, // per-key policy, not global
            extra_bridge_paths: vec![],
            keys_dir: Some(keys_dir.clone()),
            force_keyring,
            wrapping_key_user_presence: true,
            wrapping_key_cache_ttl: cache_ttl,
            // Data Protection keychain access group. Released sshenc
            // ships as a `.app` bundle (`com.godaddy.sshenc`) signed
            // with the GoDaddy team's Developer ID Application
            // identity and an embedded provisioning profile that
            // entitles `7UMADG39Z9.*` keychain access groups, so
            // SecItemAdd accepts `kSecUseDataProtectionKeychain: true`
            // + `kSecAttrAccessGroup` and the wrapping-key
            // `.userPresence` ACL actually fires.
            //
            // Ad-hoc / unsigned local builds fall back to the legacy
            // keychain via the bridge's `errSecMissingEntitlement`
            // handler — same UX as before this opt-in. See
            // `libenclaveapp/docs/macos-app-bundle-distribution.md`
            // for the full pattern and `docs/macos-unsigned-ux.md` for
            // why CLI distribution can't reach the DP keychain
            // without the .app-bundle pattern.
            keychain_access_group: Some("7UMADG39Z9.com.godaddy.sshenc".into()),
            // sshenc doesn't use libenclaveapp's Windows encryption path —
            // its Hello UX on Windows comes from the SK/WebAuthn signing
            // path. Keep the soft-Hello-UX opt-in off for the signing
            // backend; it's a no-op on macOS/Linux regardless.
            prefer_windows_hello_ux: false,
        })?;

        Ok(Self {
            pub_dir,
            keys_dir,
            backend: BackendImpl::Platform(backend),
            cache_ttl,
        })
    }

    /// Which platform backend is in use.
    pub fn backend_kind(&self) -> BackendKind {
        match &self.backend {
            BackendImpl::Platform(b) => b.backend_kind(),
            #[cfg(feature = "force-software")]
            BackendImpl::Software(_) => BackendKind::Keyring,
        }
    }

    fn signer(&self) -> &dyn EnclaveSigner {
        match &self.backend {
            BackendImpl::Platform(b) => b.signer(),
            #[cfg(feature = "force-software")]
            BackendImpl::Software(s) => s,
        }
    }

    fn key_manager(&self) -> &dyn EnclaveKeyManager {
        match &self.backend {
            BackendImpl::Platform(b) => b.key_manager(),
            #[cfg(feature = "force-software")]
            BackendImpl::Software(s) => s,
        }
    }

    fn find_pub_file(&self, label: &str) -> Option<PathBuf> {
        let path = if label == "default" {
            self.pub_dir.join("id_ecdsa.pub")
        } else {
            self.pub_dir.join(format!("{label}.pub"))
        };
        if path.exists() {
            Some(path)
        } else {
            None
        }
    }

    /// Disk-only counterpart to `KeyBackend::get`. Reads `.meta` and
    /// `.pub` straight from `keys_dir` without touching the key
    /// manager (which on macOS would slow-path through `load_handle`
    /// → biometric on a missing `.pub` cache). Used by `list` so
    /// bulk enumeration never prompts; single-key `get` keeps its
    /// self-healing decrypt path because the prompt is in-context
    /// for that call.
    fn get_disk_only(&self, label: &str) -> Result<KeyInfo> {
        let owned_label = KeyLabel::new(label)?;
        let meta =
            compat::load_sshenc_meta(&self.keys_dir, label).map_err(|e| map_err("load_meta", e))?;
        let comment = meta.get_app_field("comment").map(|s| s.to_string());
        let public_bytes = metadata::load_pub_key(&self.keys_dir, label)
            .map_err(|e| map_err("load_pub_key", e))?;
        let ssh_pubkey = SshPublicKey::from_sec1_bytes(&public_bytes, comment.clone())?;
        let (fp_sha256, fp_md5) = fingerprint::fingerprints(&ssh_pubkey);
        let pub_file_path = self.persisted_pub_file_path(&meta, label);
        let presence_mode = crate::proxy::presence_mode_from_app_specific(&meta.app_specific);

        Ok(KeyInfo {
            metadata: KeyMetadata::with_presence_mode(
                owned_label,
                meta.access_policy,
                presence_mode,
                comment,
            ),
            public_key_bytes: public_bytes,
            fingerprint_sha256: fp_sha256,
            fingerprint_md5: fp_md5,
            pub_file_path,
        })
    }

    #[allow(clippy::match_same_arms)] // arms kept separate for intent documentation
    fn persisted_pub_file_path(&self, meta: &metadata::KeyMeta, label: &str) -> Option<PathBuf> {
        match meta.app_specific.get("pub_file_path") {
            // Explicit path recorded — use it
            Some(value) if value.is_string() => value.as_str().map(PathBuf::from),
            // Field present but null — key was generated without a pub file.
            // Fall through to filesystem discovery in case one was created later.
            Some(_) => self.find_pub_file(label),
            // Field absent (legacy metadata) — discover from filesystem
            None => self.find_pub_file(label),
        }
    }

    /// Generate an SK (FIDO2 / WebAuthn) key. See [`crate::sk`] for
    /// the full design notes. This is an inherent method because
    /// `KeyBackend::generate` takes the legacy `KeyGenOptions` and
    /// extending the trait would touch every implementor / mock.
    /// Persists app-specific metadata (`algorithm`, `credential_id`,
    /// `rp_id`) alongside the standard fields so subsequent
    /// `sk_sign`/`sk_get`/`sk_delete` calls can pick the SK path
    /// up by just loading `.meta`.
    #[cfg(feature = "webauthn-sk")]
    pub fn sk_generate(&self, opts: &sshenc_core::key::SkKeyGenOptions) -> Result<KeyInfo> {
        let label_str = opts.label.as_str();

        if std::fs::metadata(self.keys_dir.join(format!("{label_str}.meta"))).is_ok() {
            return Err(Error::DuplicateLabel {
                label: label_str.to_string(),
            });
        }

        let info = crate::sk::generate(opts)?;

        // Persist as `enclaveapp_core::KeyMeta` with SK-specific
        // app_specific fields. Old loaders see `algorithm` as a
        // string they don't understand and fall through to legacy
        // assumptions; new loaders pivot on it. base64 the
        // credential_id for a human-inspectable .meta file.
        let mut meta = metadata::KeyMeta::new(label_str, KeyType::Signing, AccessPolicy::Any);
        meta.set_app_field("algorithm", "sk-ecdsa-sha2-nistp256");
        if let Some(ref cid) = info.metadata.credential_id {
            use base64::engine::general_purpose::STANDARD;
            use base64::Engine;
            meta.set_app_field("credential_id_b64", STANDARD.encode(cid));
        }
        if let Some(ref rp) = info.metadata.rp_id {
            meta.set_app_field("rp_id", rp.clone());
        }
        if let Some(ref c) = opts.comment {
            meta.set_app_field("comment", c.clone());
        }
        // SK keys take a separate `SkKeyGenOptions` (no
        // `record_pub_path`); the SK keygen RPC isn't routed through
        // the agent's `GenerateKey` handler today, so the
        // record-only path doesn't apply here.
        match opts.write_pub_path.as_ref() {
            Some(path) => meta.set_app_field(
                "pub_file_path",
                path.as_os_str().to_string_lossy().to_string(),
            ),
            None => meta.set_app_field("pub_file_path", serde_json::Value::Null),
        }
        metadata::save_meta(&self.keys_dir, label_str, &meta)
            .map_err(|e| map_err("save_meta", e))?;

        // Stamp the per-key trust-anchor tag against the SK
        // `.meta` we just wrote. The legacy ECDSA path gets this
        // for free via the platform-backend's inline stamp inside
        // `key_manager().generate(...)` plus a SshencBackend
        // re-stamp; SK keygen skips both layers (it goes directly
        // through `crate::sk::generate` → WebAuthn). Without this
        // stamp the very first `sk_sign` after keygen would observe
        // `Legacy` from `check_meta_integrity` and refuse — exactly
        // the regression the trust-anchor's gentle-cutover migration
        // path exists to handle, but during normal keygen we should
        // produce a valid tag immediately.
        //
        // Best-effort on a meta-HMAC-key load failure (rare): the
        // SK key is still usable on this install, but `sk_sign`
        // will fail with `Legacy` until the user runs
        // `sshenc migrate-meta`. Same posture as the legacy keygen
        // path's fallback.
        const SSHENC_APP_NAME: &str = "sshenc";
        #[cfg(target_os = "macos")]
        {
            if let Ok(Some(hk)) = enclaveapp_apple::meta_hmac::load_existing(SSHENC_APP_NAME) {
                let meta_path = self.keys_dir.join(format!("{label_str}.meta"));
                if let Ok(meta_bytes) = std::fs::read(&meta_path) {
                    let tag = metadata::compute_meta_hmac_bytes(hk.as_slice(), &meta_bytes);
                    if let Err(e) =
                        enclaveapp_apple::meta_tag::store(SSHENC_APP_NAME, label_str, &tag)
                    {
                        tracing::warn!(
                            label = label_str,
                            error = %e,
                            "post-sk-keygen meta-tag stamp failed; \
                             first sk_sign will refuse with Legacy until \
                             user runs `sshenc migrate-meta`"
                        );
                    }
                }
            }
        }
        #[cfg(target_os = "windows")]
        {
            if let Ok(Some(hk)) = enclaveapp_windows::meta_hmac::load_or_create(SSHENC_APP_NAME) {
                if let Err(e) = enclaveapp_windows::meta_tag::stamp_from_disk(
                    SSHENC_APP_NAME,
                    label_str,
                    &self.keys_dir,
                    hk.as_slice(),
                ) {
                    tracing::warn!(
                        label = label_str,
                        error = %e,
                        "post-sk-keygen meta-tag stamp failed; \
                         first sk_sign will refuse with Legacy until \
                         user runs `sshenc migrate-meta`"
                    );
                }
            }
        }
        #[cfg(target_os = "linux")]
        {
            if let Ok(Some(hk)) = enclaveapp_keyring::meta_hmac_key_existing(SSHENC_APP_NAME) {
                if let Err(e) = enclaveapp_keyring::meta_tag::stamp_from_disk(
                    SSHENC_APP_NAME,
                    label_str,
                    &self.keys_dir,
                    hk.as_slice(),
                ) {
                    tracing::warn!(
                        label = label_str,
                        error = %e,
                        "post-sk-keygen meta-tag stamp failed; \
                         first sk_sign will refuse with Legacy until \
                         user runs `sshenc migrate-meta`"
                    );
                }
            }
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        let _ = SSHENC_APP_NAME;

        Ok(info)
    }

    /// True if `label` resolves to an SK key (peeked from the
    /// stored metadata's `algorithm` app_specific field). Returns
    /// false for legacy keys and for missing metadata.
    ///
    /// This is the inherent implementation -- the same-named trait
    /// method (`KeyBackend::is_sk_label`) delegates here. The
    /// `same_name_method` clippy lint complains about the name
    /// collision, but the duplication is intentional: it lets
    /// concrete-type callers (`SshencBackend::is_sk_label(...)`)
    /// avoid trait-object dispatch on a hot path.
    #[cfg(feature = "webauthn-sk")]
    #[allow(clippy::same_name_method)]
    pub fn is_sk_label(&self, label: &str) -> bool {
        match compat::load_sshenc_meta(&self.keys_dir, label) {
            Ok(m) => m.get_app_field("algorithm") == Some("sk-ecdsa-sha2-nistp256"),
            Err(_) => false,
        }
    }

    /// Load full key info for an SK key. Returns `Err` if the
    /// label is not an SK key.
    #[cfg(feature = "webauthn-sk")]
    #[allow(clippy::same_name_method)]
    pub fn sk_get(&self, label: &str) -> Result<KeyInfo> {
        drop(KeyLabel::new(label)?);
        let meta =
            compat::load_sshenc_meta(&self.keys_dir, label).map_err(|e| map_err("load_meta", e))?;
        if meta.get_app_field("algorithm") != Some("sk-ecdsa-sha2-nistp256") {
            return Err(Error::Other(format!("key '{label}' is not an SK key")));
        }

        let credential_id = meta
            .get_app_field("credential_id_b64")
            .ok_or_else(|| Error::Other(format!("SK key '{label}' missing credential_id")))?;
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        let credential_id = STANDARD.decode(credential_id).map_err(Error::Base64)?;
        let rp_id = meta
            .get_app_field("rp_id")
            .ok_or_else(|| Error::Other(format!("SK key '{label}' missing rp_id")))?
            .to_string();
        let comment = meta.get_app_field("comment").map(|s| s.to_string());

        // For the public-key bytes we read the .pub file the keygen
        // step wrote (the SK pub line embeds the SEC1 point). If
        // the user deleted the .pub file we can't reconstruct -- SK
        // keys, unlike CNG keys, have no provider-side enumeration
        // to fall back on.
        let pub_file = self.persisted_pub_file_path(&meta, label);
        let ssh_line = pub_file
            .as_ref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .ok_or_else(|| {
                Error::Other(format!(
                    "SK key '{label}' .pub file missing -- cannot reconstruct public key bytes"
                ))
            })?;
        let parsed_line = ssh_line.trim().splitn(3, ' ').collect::<Vec<_>>();
        if parsed_line.len() < 2 {
            return Err(Error::InvalidPublicKey(format!(
                "SK key '{label}' .pub file is malformed"
            )));
        }
        let blob = STANDARD.decode(parsed_line[1]).map_err(Error::Base64)?;
        // Wire format: string(type) string(curve) string(Q) string(application)
        let (key_type, rest) = sshenc_core::pubkey::read_ssh_string(&blob)?;
        if key_type != b"sk-ecdsa-sha2-nistp256@openssh.com" {
            return Err(Error::InvalidPublicKey(format!(
                "SK key '{label}' .pub file has wrong key type: {:?}",
                std::str::from_utf8(key_type)
            )));
        }
        let (_curve, rest) = sshenc_core::pubkey::read_ssh_string(rest)?;
        let (q, _rest) = sshenc_core::pubkey::read_ssh_string(rest)?;
        let public_key_bytes = q.to_vec();

        let pubkey = sshenc_core::pubkey::SshSkPublicKey::from_sec1_bytes(
            &public_key_bytes,
            rp_id.clone(),
            comment.clone(),
        )?;
        let (fp_sha256, fp_md5) = fingerprint::sk_fingerprints(&pubkey);

        let metadata_out = KeyMetadata::for_sk(
            KeyLabel::new(label)?,
            AccessPolicy::Any,
            Some(PresenceMode::Strict),
            comment,
            credential_id,
            rp_id,
        );

        Ok(KeyInfo {
            metadata: metadata_out,
            public_key_bytes,
            fingerprint_sha256: fp_sha256,
            fingerprint_md5: fp_md5,
            pub_file_path: pub_file,
        })
    }

    /// Sign with an SK key. The `data` bytes go straight into
    /// WebAuthn as `pbClientDataJSON`; the OS hashes them with
    /// SHA-256, the TPM signs `authenticator_data || that_hash`,
    /// and we wrap the result in the OpenSSH SK signature blob.
    #[cfg(feature = "webauthn-sk")]
    #[allow(clippy::same_name_method)]
    pub fn sk_sign(&self, label: &str, data: &[u8]) -> Result<Vec<u8>> {
        drop(KeyLabel::new(label)?);

        // Per-op trust-anchor check before reading anything from
        // the SK key's `.meta`. The SK sign path consumes
        // `credential_id_b64` (chooses which authenticator credential
        // to sign with) and `rp_id` (relying-party identifier) out
        // of `app_specific`; both are security-critical. A same-UID
        // attacker who swaps `credential_id_b64` to an attacker-
        // minted credential would otherwise get the agent to sign
        // with the wrong credential under the user's name. The
        // legacy ECDSA path goes through `key_manager().sign()`
        // which fires `ensure_meta_integrity` inside the platform
        // backend; the SK path skips that platform layer (it goes
        // directly to WebAuthn / FIDO2), so the verify has to live
        // here at the dispatcher.
        //
        // `check_meta_integrity` is platform-dispatching (macOS
        // Keychain, Windows Credential Manager, Linux Secret
        // Service) and read-only on every backend.
        const SSHENC_APP_NAME: &str = "sshenc";
        if let Err(e) = enclaveapp_app_storage::platform::check_meta_integrity(
            SSHENC_APP_NAME,
            label,
            &self.keys_dir,
        ) {
            return Err(Error::Other(format!("sk_sign: {e}")));
        }

        let meta =
            compat::load_sshenc_meta(&self.keys_dir, label).map_err(|e| map_err("load_meta", e))?;
        if meta.get_app_field("algorithm") != Some("sk-ecdsa-sha2-nistp256") {
            return Err(Error::Other(format!("key '{label}' is not an SK key")));
        }
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        let credential_id = meta
            .get_app_field("credential_id_b64")
            .ok_or_else(|| Error::Other(format!("SK key '{label}' missing credential_id")))?;
        let credential_id = STANDARD.decode(credential_id).map_err(Error::Base64)?;
        let rp_id = meta
            .get_app_field("rp_id")
            .ok_or_else(|| Error::Other(format!("SK key '{label}' missing rp_id")))?;

        crate::sk::sign(&credential_id, rp_id, data)
    }

    /// Delete an SK key: remove the persisted `.meta` and `.pub`
    /// files, AND ask Windows to remove the platform credential
    /// from the user's passkey list (so the chooser scope shrinks).
    #[allow(clippy::same_name_method)]
    #[cfg(feature = "webauthn-sk")]
    pub fn sk_delete(&self, label: &str) -> Result<()> {
        drop(KeyLabel::new(label)?);
        let meta =
            compat::load_sshenc_meta(&self.keys_dir, label).map_err(|e| map_err("load_meta", e))?;
        if meta.get_app_field("algorithm") != Some("sk-ecdsa-sha2-nistp256") {
            return Err(Error::Other(format!("key '{label}' is not an SK key")));
        }

        // Best-effort platform-credential cleanup; if the user
        // already deleted it via Settings -> Passkeys, just move on.
        if let Some(cred_b64) = meta.get_app_field("credential_id_b64") {
            use base64::engine::general_purpose::STANDARD;
            use base64::Engine;
            if let Ok(cred_id) = STANDARD.decode(cred_b64) {
                drop(crate::sk::delete_platform_credential(&cred_id));
            }
        }

        // Remove .meta and .pub side-state.
        let meta_path = self.keys_dir.join(format!("{label}.meta"));
        drop(std::fs::remove_file(&meta_path));
        if let Some(pub_path) = self.persisted_pub_file_path(&meta, label) {
            drop(std::fs::remove_file(pub_path));
        }
        Ok(())
    }

    /// List all SK key labels by scanning `.meta` files in the
    /// keys directory and filtering for the SK algorithm marker.
    /// Distinct from the trait `list()` (which enumerates legacy
    #[allow(clippy::same_name_method)]
    /// keys via the platform key manager).
    #[cfg(feature = "webauthn-sk")]
    pub fn sk_list_labels(&self) -> Result<Vec<String>> {
        let read = match std::fs::read_dir(&self.keys_dir) {
            Ok(r) => r,
            Err(_) => return Ok(Vec::new()), // dir missing == no keys
        };
        let mut out = Vec::new();
        for entry in read.flatten() {
            let path = entry.path();
            let label = match path.file_stem().and_then(|s| s.to_str()) {
                Some(s) => s.to_string(),
                None => continue,
            };
            if path.extension().and_then(|s| s.to_str()) != Some("meta") {
                continue;
            }
            if self.is_sk_label(&label) {
                out.push(label);
            }
        }
        out.sort();
        Ok(out)
    }
}

/// Map an enclaveapp_core error to an sshenc_core error.
fn map_err(operation: &str, e: enclaveapp_core::Error) -> Error {
    Error::SecureEnclave {
        operation: operation.into(),
        detail: e.to_string(),
    }
}

impl KeyBackend for SshencBackend {
    fn generate(&self, opts: &KeyGenOptions) -> Result<KeyInfo> {
        let label_str = opts.label.as_str();

        // Check for duplicates. Must use `key_exists`, not
        // `public_key().is_ok()`: on the WSL bridge, `public_key` invokes
        // `init_signing` which creates the key as a side effect, so using
        // it for the check would both falsely report "duplicate" and
        // leave behind a TPM key.
        if self
            .key_manager()
            .key_exists(label_str)
            .map_err(|e| map_err("key_exists", e))?
        {
            return Err(Error::DuplicateLabel {
                label: label_str.to_string(),
            });
        }

        // Generate key via platform backend
        let public_bytes = self
            .key_manager()
            .generate(label_str, KeyType::Signing, opts.access_policy)
            .map_err(|e| map_err("generate", e))?;

        // Save app-specific metadata (comment, git_name, git_email,
        // presence_mode)
        let mut meta = compat::load_sshenc_meta(&self.keys_dir, label_str)
            .map_err(|e| map_err("load_meta", e))?;
        if let Some(ref comment) = opts.comment {
            meta.set_app_field("comment", comment.clone());
        }
        // Prefer `write_pub_path` (we're about to write this file) but
        // fall back to `record_pub_path` (the agent's case: the CLI
        // will write the file, we just record the path so the
        // trust-anchor tag stamps the correct meta). See
        // `KeyGenOptions::record_pub_path`.
        match opts
            .write_pub_path
            .as_ref()
            .or(opts.record_pub_path.as_ref())
        {
            Some(path) => meta.set_app_field(
                "pub_file_path",
                path.as_os_str().to_string_lossy().to_string(),
            ),
            None => meta.set_app_field("pub_file_path", serde_json::Value::Null),
        }
        meta.set_app_field(
            "presence_mode",
            crate::proxy::presence_mode_to_app_specific_str(opts.presence_mode),
        );
        metadata::save_meta(&self.keys_dir, label_str, &meta)
            .map_err(|e| map_err("save_meta", e))?;

        // Re-stamp the per-key meta-integrity tag against the FINAL
        // on-disk meta. The platform backend (`TpmSigner::generate` /
        // `Apple::generate_and_save_key`) already stamped a tag at
        // the end of `key_manager().generate(...)` above, but those
        // saw a meta WITHOUT the `app_specific` fields appended just
        // now — the platform backend goes through the
        // `EnclaveKeyManager` trait which only carries label /
        // key_type / access_policy, never `comment` /
        // `presence_mode` / `pub_file_path`. The platform tag is
        // therefore stale by the time keygen completes; without this
        // re-stamp the first sign-time `meta_tag::verify` would
        // observe a tamper-style mismatch on a freshly-created key.
        //
        // Both Credential Manager (Windows) and the macOS legacy
        // Keychain make the underlying secure-store write idempotent
        // on overwrite, so a re-stamp is cheap. Best-effort on a
        // meta-HMAC-key load failure: the platform-backend's inline
        // stamp survives as a fallback and the user can recover by
        // running `sshenc migrate-meta` once.
        //
        // SshencBackend hardcodes the "sshenc" app namespace (see
        // `SshencBackend::new` / test fixture); the platform
        // secure-store paths share that namespace.
        const SSHENC_APP_NAME: &str = "sshenc";
        #[cfg(target_os = "windows")]
        {
            if let Ok(Some(hk)) = enclaveapp_windows::meta_hmac::load_or_create(SSHENC_APP_NAME) {
                if let Err(e) = enclaveapp_windows::meta_tag::stamp_from_disk(
                    SSHENC_APP_NAME,
                    label_str,
                    &self.keys_dir,
                    hk.as_slice(),
                ) {
                    tracing::warn!(
                        label = label_str,
                        error = %e,
                        "post-app-specific meta-tag re-stamp failed; \
                         platform-backend inline tag remains as fallback — \
                         user should run `sshenc migrate-meta` to recover"
                    );
                }
            }
        }
        #[cfg(target_os = "macos")]
        {
            if let Ok(Some(hk)) = enclaveapp_apple::meta_hmac::load_existing(SSHENC_APP_NAME) {
                let meta_path = self.keys_dir.join(format!("{label_str}.meta"));
                if let Ok(meta_bytes) = std::fs::read(&meta_path) {
                    let tag = metadata::compute_meta_hmac_bytes(hk.as_slice(), &meta_bytes);
                    if let Err(e) =
                        enclaveapp_apple::meta_tag::store(SSHENC_APP_NAME, label_str, &tag)
                    {
                        tracing::warn!(
                            label = label_str,
                            error = %e,
                            "post-app-specific meta-tag re-stamp failed; \
                             platform-backend inline tag remains as fallback — \
                             user should run `sshenc migrate-meta` to recover"
                        );
                    }
                }
            }
        }
        #[cfg(target_os = "linux")]
        {
            if let Ok(Some(hk)) = enclaveapp_keyring::meta_hmac_key_existing(SSHENC_APP_NAME) {
                if let Err(e) = enclaveapp_keyring::meta_tag::stamp_from_disk(
                    SSHENC_APP_NAME,
                    label_str,
                    &self.keys_dir,
                    hk.as_slice(),
                ) {
                    tracing::warn!(
                        label = label_str,
                        error = %e,
                        "post-app-specific meta-tag re-stamp failed; \
                         platform-backend inline tag remains as fallback — \
                         user should run `sshenc migrate-meta` to recover"
                    );
                }
            }
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        let _ = SSHENC_APP_NAME;

        let ssh_pubkey = SshPublicKey::from_sec1_bytes(&public_bytes, opts.comment.clone())?;
        let (fp_sha256, fp_md5) = fingerprint::fingerprints(&ssh_pubkey);

        // Write SSH .pub file if requested
        let pub_file_path = if let Some(ref path) = opts.write_pub_path {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let line = ssh_pubkey.to_openssh_line();
            std::fs::write(path, format!("{line}\n"))?;
            Some(path.clone())
        } else {
            None
        };

        Ok(KeyInfo {
            metadata: KeyMetadata::with_presence_mode(
                opts.label.clone(),
                opts.access_policy,
                Some(opts.presence_mode),
                opts.comment.clone(),
            ),
            public_key_bytes: public_bytes,
            fingerprint_sha256: fp_sha256,
            fingerprint_md5: fp_md5,
            pub_file_path,
        })
    }

    /// Enumerate keys by walking `.meta` and `.pub` files on disk.
    /// Never calls `key_manager().public_key()` -- that path on macOS
    /// falls back to `load_handle` (decrypts the handle blob via the
    /// user-presence-protected wrapping key) if the `.pub` cache is
    /// missing or malformed, which surfaces a Touch ID prompt during
    /// what should be a silent enumeration.
    ///
    /// Public keys are public; reading them must never gate on
    /// biometric. If a key's `.pub` cache is missing we log+skip
    /// rather than self-heal via decrypt -- self-heal is appropriate
    /// for an explicit single-key `get`/`sign` (the user is asking
    /// for that specific key, so prompting is in-context), but never
    /// during a bulk `list` triggered by `RequestIdentities` from a
    /// passing SSH client or by the agent's startup warmup.
    fn list(&self) -> Result<Vec<KeyInfo>> {
        let labels = self
            .key_manager()
            .list_keys()
            .map_err(|e| map_err("list_keys", e))?;

        let mut keys = Vec::new();
        for label_str in labels {
            match self.get_disk_only(&label_str) {
                Ok(info) => keys.push(info),
                Err(e) => {
                    tracing::warn!("skipping key {label_str}: {e}");
                }
            }
        }
        Ok(keys)
    }

    fn get(&self, label: &str) -> Result<KeyInfo> {
        drop(KeyLabel::new(label)?);

        let public_bytes = self
            .key_manager()
            .public_key(label)
            .map_err(|e| map_err("load_pub_key", e))?;

        // Load persisted metadata (handles old and new format)
        let meta =
            compat::load_sshenc_meta(&self.keys_dir, label).map_err(|e| map_err("load_meta", e))?;

        let comment = meta.get_app_field("comment").map(|s| s.to_string());
        let ssh_pubkey = SshPublicKey::from_sec1_bytes(&public_bytes, comment.clone())?;
        let (fp_sha256, fp_md5) = fingerprint::fingerprints(&ssh_pubkey);
        let pub_file = self.persisted_pub_file_path(&meta, label);
        let presence_mode = crate::proxy::presence_mode_from_app_specific(&meta.app_specific);

        Ok(KeyInfo {
            metadata: KeyMetadata::with_presence_mode(
                KeyLabel::new(label)?,
                meta.access_policy,
                presence_mode,
                comment,
            ),
            public_key_bytes: public_bytes,
            fingerprint_sha256: fp_sha256,
            fingerprint_md5: fp_md5,
            pub_file_path: pub_file,
        })
    }

    fn delete(&self, label: &str) -> Result<()> {
        drop(KeyLabel::new(label)?);
        self.key_manager()
            .delete_key(label)
            .map_err(|e| map_err("delete_key", e))
    }

    fn rename(&self, old_label: &str, new_label: &str) -> Result<()> {
        drop(KeyLabel::new(old_label)?);
        drop(KeyLabel::new(new_label)?);
        self.key_manager()
            .rename_key(old_label, new_label)
            .map_err(|e| map_err("rename_key", e))
    }

    fn sign(&self, label: &str, data: &[u8]) -> Result<Vec<u8>> {
        drop(KeyLabel::new(label)?);
        self.signer()
            .sign(label, data)
            .map_err(|e| map_err("sign", e))
    }

    fn sign_with_presence(
        &self,
        label: &str,
        data: &[u8],
        mode: PresenceMode,
        cache_ttl_secs: u64,
        reason: &str,
    ) -> Result<Vec<u8>> {
        drop(KeyLabel::new(label)?);
        // Prefer the caller-supplied TTL when non-zero, otherwise
        // fall back to the backend's own configured TTL. The agent
        // always passes its config-derived TTL, but other callers
        // (CLI subcommands signing locally) pick up the default.
        let effective_ttl = if cache_ttl_secs == 0 {
            self.cache_ttl.as_secs()
        } else {
            cache_ttl_secs
        };
        self.signer()
            .sign_with_presence(label, data, mode, effective_ttl, reason)
            .map_err(|e| map_err("sign_with_presence", e))
    }

    fn is_available(&self) -> bool {
        self.key_manager().is_available()
    }

    // SK trait method overrides delegate to the inherent methods of
    // the same name. `Self::method(self, ...)` resolves to the
    // inherent (preferred over trait method when both exist).

    #[cfg(feature = "webauthn-sk")]
    fn is_sk_label(&self, label: &str) -> bool {
        Self::is_sk_label(self, label)
    }

    #[cfg(feature = "webauthn-sk")]
    fn sk_list_labels(&self) -> Result<Vec<String>> {
        Self::sk_list_labels(self)
    }

    #[cfg(feature = "webauthn-sk")]
    fn sk_get(&self, label: &str) -> Result<KeyInfo> {
        Self::sk_get(self, label)
    }

    #[cfg(feature = "webauthn-sk")]
    fn sk_sign(&self, label: &str, data: &[u8]) -> Result<Vec<u8>> {
        Self::sk_sign(self, label, data)
    }

    #[cfg(feature = "webauthn-sk")]
    fn sk_delete(&self, label: &str) -> Result<()> {
        Self::sk_delete(self, label)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_pub_dir() -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("sshenc-se-unified-test-{pid}-{id}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Try to create a test backend. Returns None if hardware is unavailable
    /// (e.g., no TPM on Windows CI, no SE on macOS CI).
    fn try_test_backend(pub_dir: PathBuf) -> Option<SshencBackend> {
        let backend = AppSigningBackend::init(StorageConfig {
            app_name: "sshenc-test".into(),
            key_label: String::new(),
            access_policy: AccessPolicy::None,
            extra_bridge_paths: vec![],
            keys_dir: None,
            force_keyring: false,
            wrapping_key_user_presence: false,
            wrapping_key_cache_ttl: std::time::Duration::ZERO,
            keychain_access_group: None,
            prefer_windows_hello_ux: false,
        })
        .ok()?;
        Some(SshencBackend {
            pub_dir,
            keys_dir: sshenc_keys_dir(),
            backend: BackendImpl::Platform(backend),
            cache_ttl: std::time::Duration::ZERO,
        })
    }

    #[test]
    fn sshenc_keys_dir_is_absolute() {
        let dir = sshenc_keys_dir();
        assert!(dir.is_absolute());
        assert!(dir.to_string_lossy().contains("sshenc"));
        assert!(dir.to_string_lossy().contains("keys"));
    }

    #[test]
    fn find_pub_file_default_label_uses_id_ecdsa() {
        let pub_dir = test_pub_dir();
        std::fs::write(pub_dir.join("id_ecdsa.pub"), "key content").unwrap();

        let Some(backend) = try_test_backend(pub_dir.clone()) else {
            std::fs::remove_dir_all(&pub_dir).unwrap();
            return; // hardware not available in CI
        };
        let path = backend.find_pub_file("default");
        assert!(path.is_some());
        assert!(path.unwrap().ends_with("id_ecdsa.pub"));

        std::fs::remove_dir_all(&pub_dir).unwrap();
    }

    #[test]
    fn find_pub_file_custom_label() {
        let pub_dir = test_pub_dir();
        std::fs::write(pub_dir.join("github-work.pub"), "key content").unwrap();

        let Some(backend) = try_test_backend(pub_dir.clone()) else {
            std::fs::remove_dir_all(&pub_dir).unwrap();
            return;
        };
        let path = backend.find_pub_file("github-work");
        assert!(path.is_some());
        assert!(path.unwrap().ends_with("github-work.pub"));

        std::fs::remove_dir_all(&pub_dir).unwrap();
    }

    #[test]
    fn find_pub_file_returns_none_when_missing() {
        let pub_dir = test_pub_dir();

        let Some(backend) = try_test_backend(pub_dir.clone()) else {
            std::fs::remove_dir_all(&pub_dir).unwrap();
            return;
        };
        let path = backend.find_pub_file("nonexistent");
        assert!(path.is_none());

        std::fs::remove_dir_all(&pub_dir).unwrap();
    }

    fn test_backend(pub_dir: &Path) -> Option<SshencBackend> {
        try_test_backend(pub_dir.to_path_buf())
    }

    #[test]
    fn persisted_pub_file_path_uses_recorded_string() {
        let pub_dir = test_pub_dir();
        let Some(backend) = test_backend(&pub_dir) else {
            std::fs::remove_dir_all(&pub_dir).unwrap();
            return;
        };

        let mut meta = metadata::KeyMeta::new("test-key", KeyType::Signing, AccessPolicy::None);
        meta.set_app_field("pub_file_path", "/custom/path/test-key.pub");

        let result = backend.persisted_pub_file_path(&meta, "test-key");
        assert_eq!(result, Some(PathBuf::from("/custom/path/test-key.pub")));

        std::fs::remove_dir_all(&pub_dir).unwrap();
    }

    #[test]
    fn persisted_pub_file_path_null_falls_through_to_filesystem() {
        let pub_dir = test_pub_dir();
        std::fs::write(pub_dir.join("test-key.pub"), "key content").unwrap();
        let Some(backend) = test_backend(&pub_dir) else {
            std::fs::remove_dir_all(&pub_dir).unwrap();
            return;
        };

        let mut meta = metadata::KeyMeta::new("test-key", KeyType::Signing, AccessPolicy::None);
        meta.set_app_field("pub_file_path", serde_json::Value::Null);

        let result = backend.persisted_pub_file_path(&meta, "test-key");
        assert!(result.is_some());
        assert!(result.unwrap().ends_with("test-key.pub"));

        std::fs::remove_dir_all(&pub_dir).unwrap();
    }

    #[test]
    fn persisted_pub_file_path_absent_field_falls_through_to_filesystem() {
        let pub_dir = test_pub_dir();
        std::fs::write(pub_dir.join("legacy.pub"), "key content").unwrap();
        let Some(backend) = test_backend(&pub_dir) else {
            std::fs::remove_dir_all(&pub_dir).unwrap();
            return;
        };

        // Legacy metadata has no pub_file_path field at all
        let meta = metadata::KeyMeta::new("legacy", KeyType::Signing, AccessPolicy::None);

        let result = backend.persisted_pub_file_path(&meta, "legacy");
        assert!(result.is_some());
        assert!(result.unwrap().ends_with("legacy.pub"));

        std::fs::remove_dir_all(&pub_dir).unwrap();
    }

    #[test]
    fn persisted_pub_file_path_null_no_filesystem_returns_none() {
        let pub_dir = test_pub_dir();
        let Some(backend) = test_backend(&pub_dir) else {
            std::fs::remove_dir_all(&pub_dir).unwrap();
            return;
        };

        let mut meta = metadata::KeyMeta::new("no-pub", KeyType::Signing, AccessPolicy::None);
        meta.set_app_field("pub_file_path", serde_json::Value::Null);

        let result = backend.persisted_pub_file_path(&meta, "no-pub");
        assert!(result.is_none());

        std::fs::remove_dir_all(&pub_dir).unwrap();
    }

    /// `get_disk_only` must NOT touch the key manager. We construct
    /// a backend with a tempdir keys_dir, write a hand-rolled `.pub`
    /// and `.meta` into it, and verify `get_disk_only` returns the
    /// key without going through any of the keychain-backed paths.
    /// The corollary -- that `list` only ever calls this and never
    /// `get` -- is what protects bulk enumeration from prompting on
    /// macOS when a key's `.pub` cache is missing.
    #[test]
    fn get_disk_only_reads_pub_and_meta_without_key_manager() {
        let pub_dir = test_pub_dir();
        let keys_dir = std::env::temp_dir().join(format!(
            "sshenc-se-disk-only-{}-{}",
            std::process::id(),
            TEST_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&keys_dir).unwrap();

        // 65-byte SEC1-shaped buffer. `validate_p256_point` and
        // `SshPublicKey::from_sec1_bytes` only check length + 0x04
        // prefix; no curve math. Good enough for the disk-only path
        // test which doesn't sign or verify.
        let mut public = vec![0x04];
        public.extend_from_slice(&[0xAA; 64]);

        let label = "disk-only-test";
        metadata::save_pub_key(&keys_dir, label, &public).unwrap();
        let mut meta = metadata::KeyMeta::new(label, KeyType::Signing, AccessPolicy::None);
        meta.set_app_field("comment", "disk-only-test-comment");
        metadata::save_meta(&keys_dir, label, &meta).unwrap();

        // Build a SshencBackend WITHOUT going through `with_cache_ttl`
        // (which would require either real keychain or the
        // force-software feature). We bypass platform init by using
        // try_test_backend on hosts where it succeeds; on hosts
        // where it doesn't, the test exits early -- the disk-only
        // path is identical either way.
        let Some(mut backend) = try_test_backend(pub_dir.clone()) else {
            std::fs::remove_dir_all(&pub_dir).unwrap();
            std::fs::remove_dir_all(&keys_dir).unwrap();
            return;
        };
        backend.keys_dir = keys_dir.clone();

        let info = backend.get_disk_only(label).unwrap();
        assert_eq!(info.metadata.label.as_str(), label);
        assert_eq!(
            info.metadata.comment.as_deref(),
            Some("disk-only-test-comment")
        );
        assert_eq!(info.public_key_bytes, public);

        std::fs::remove_dir_all(&pub_dir).unwrap();
        std::fs::remove_dir_all(&keys_dir).unwrap();
    }

    /// If the `.pub` cache is missing for a label that has a `.meta`,
    /// `get_disk_only` must error rather than fall through to a
    /// keychain decrypt. `list` swallows the error and skips the
    /// key, which is the prompt-free behaviour we want.
    #[test]
    fn get_disk_only_errors_when_pub_cache_missing() {
        let pub_dir = test_pub_dir();
        let keys_dir = std::env::temp_dir().join(format!(
            "sshenc-se-disk-only-miss-{}-{}",
            std::process::id(),
            TEST_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&keys_dir).unwrap();

        // .meta only, no .pub
        let label = "missing-pub";
        let meta = metadata::KeyMeta::new(label, KeyType::Signing, AccessPolicy::None);
        metadata::save_meta(&keys_dir, label, &meta).unwrap();

        let Some(mut backend) = try_test_backend(pub_dir.clone()) else {
            std::fs::remove_dir_all(&pub_dir).unwrap();
            std::fs::remove_dir_all(&keys_dir).unwrap();
            return;
        };
        backend.keys_dir = keys_dir.clone();

        let result = backend.get_disk_only(label);
        assert!(result.is_err(), "expected error when .pub cache is missing");

        std::fs::remove_dir_all(&pub_dir).unwrap();
        std::fs::remove_dir_all(&keys_dir).unwrap();
    }
}
