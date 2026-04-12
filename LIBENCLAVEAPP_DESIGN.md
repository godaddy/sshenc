# libenclaveapp Design Document

## Goal

Extract duplicated hardware-security infrastructure from `sshenc`, `awsenc`, and `sso-jwt` into a shared Rust crate. Normalize all three apps onto **CryptoKit** (macOS) and **CNG** (Windows) so the platform FFI layer is written once.

## Current State

| | sshenc | awsenc | sso-jwt |
|---|---|---|---|
| macOS FFI | CryptoKit (Swift bridge) | Security.framework (direct) | Security.framework (direct) |
| Crypto op | ECDSA signing | ECIES encrypt/decrypt | ECIES encrypt/decrypt |
| Windows FFI | CNG NCrypt (signing) | CNG NCrypt+BCrypt (ECIES) | CNG NCrypt (encrypt/decrypt) |
| WSL | socat+npiperelay to agent pipe | JSON-RPC bridge | JSON-RPC bridge |
| Key storage | `.handle` + `.pub` + `.meta` | Keychain only (no files) | Keychain only (no files) |

### Problem with Security.framework

awsenc and sso-jwt use `SecKeyCreateRandomKey` / `SecKeyCreateEncryptedData` / `SecKeyCreateDecryptedData` from Security.framework. This works but:

1. Requires careful Keychain entitlements on macOS (hit this wall with sshenc)
2. Security.framework's Keychain API is finicky (query semantics, duplicate detection)
3. CryptoKit is Apple's modern replacement — cleaner API, works with ad-hoc code signing

### CryptoKit Capabilities

CryptoKit's Secure Enclave support provides two key types:

- **`SecureEnclave.P256.Signing.PrivateKey`** — ECDSA signing (used by sshenc today)
- **`SecureEnclave.P256.KeyAgreement.PrivateKey`** — ECDH key agreement (needed for ECIES)

ECIES via CryptoKit key agreement:
1. Generate ephemeral `P256.KeyAgreement.PrivateKey` (in software)
2. Derive shared secret via ECDH with the SE-bound key's public key
3. Derive symmetric key via X9.63 KDF or HKDF
4. Encrypt with AES-GCM

This is functionally equivalent to Security.framework's `eciesEncryptionCofactorX963SHA256AESGCM` algorithm, but without Keychain entitlement issues.

## Proposed Architecture

```
libenclaveapp/
├── Cargo.toml                        # Workspace
├── crates/
│   ├── enclaveapp-core/              # Platform-agnostic types & traits
│   ├── enclaveapp-apple/             # macOS Secure Enclave (CryptoKit)
│   ├── enclaveapp-windows/           # Windows TPM 2.0 (CNG)
│   ├── enclaveapp-wsl/               # WSL detection & shell config
│   ├── enclaveapp-bridge/            # TPM bridge binary (Windows→WSL)
│   └── enclaveapp-test-support/      # Mock backend for testing
```

### enclaveapp-core

Platform-agnostic abstractions. No FFI, no platform-specific code.

```rust
/// Key type determines what crypto operations are available.
pub enum KeyType {
    /// ECDSA P-256 signing key (SSH, git signing)
    Signing,
    /// ECDH P-256 key agreement key (ECIES encryption)
    Encryption,
}

/// Access control policy for key usage.
pub enum AccessPolicy {
    None,             // No user interaction required
    Any,              // Touch ID or password/PIN
    BiometricOnly,    // Touch ID / fingerprint only
    PasswordOnly,     // Password / PIN only
}

/// Metadata stored alongside a key.
#[derive(Serialize, Deserialize)]
pub struct KeyMeta {
    pub label: String,
    pub key_type: KeyType,
    pub access_policy: AccessPolicy,
    pub created: String,                  // Unix timestamp
    pub app_specific: serde_json::Value,  // App-defined extra fields
}

/// Core key management operations — every platform implements this.
pub trait EnclaveKeyManager: Send + Sync {
    /// Generate a new hardware-bound key. Returns the 65-byte SEC1 public key.
    fn generate(&self, label: &str, key_type: KeyType, policy: AccessPolicy)
        -> Result<Vec<u8>>;

    /// Get the public key for an existing key.
    fn public_key(&self, label: &str) -> Result<Vec<u8>>;

    /// List all key labels managed by this app.
    fn list_keys(&self) -> Result<Vec<String>>;

    /// Delete a key and its metadata.
    fn delete_key(&self, label: &str) -> Result<()>;

    /// Check if the hardware backend is available.
    fn is_available(&self) -> bool;

    /// Save metadata for a key.
    fn save_meta(&self, label: &str, meta: &KeyMeta) -> Result<()>;

    /// Load metadata for a key.
    fn load_meta(&self, label: &str) -> Result<KeyMeta>;
}

/// Signing operations (sshenc).
pub trait EnclaveSigner: EnclaveKeyManager {
    /// Sign a message. The backend hashes internally (CryptoKit)
    /// or pre-hashes (CNG). Returns DER-encoded ECDSA signature.
    fn sign(&self, label: &str, data: &[u8]) -> Result<Vec<u8>>;
}

/// Encryption operations (awsenc, sso-jwt).
pub trait EnclaveEncryptor: EnclaveKeyManager {
    /// Encrypt plaintext using the key's public key (ECIES).
    fn encrypt(&self, label: &str, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt ciphertext using the hardware-bound private key.
    fn decrypt(&self, label: &str, ciphertext: &[u8]) -> Result<Vec<u8>>;
}
```

Utilities:
```rust
/// Atomic file write: write to .tmp, rename into place.
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()>;

/// Directory lock (flock on Unix, LockFile on Windows).
pub struct DirLock { ... }
impl DirLock {
    pub fn acquire(dir: &Path) -> Result<Self>;
}

/// Standard app data directory.
/// Unix: ~/.config/<app_name>/keys/
/// Windows: %APPDATA%/<app_name>/keys/
pub fn keys_dir(app_name: &str) -> PathBuf;

/// Config directory.
/// Unix: ~/.config/<app_name>/
/// Windows: %APPDATA%/<app_name>/
pub fn config_dir(app_name: &str) -> PathBuf;

/// TOML config load with silent defaults for missing file.
pub fn load_toml<T: DeserializeOwned + Default>(path: &Path) -> Result<T>;

/// TOML config save with parent directory creation.
pub fn save_toml<T: Serialize>(path: &Path, value: &T) -> Result<()>;

/// SEC1 uncompressed P-256 point validation.
pub fn validate_p256_point(bytes: &[u8]) -> Result<()>;
```

### enclaveapp-apple

Unified CryptoKit Swift bridge exposing both signing and encryption.

**Swift bridge (`bridge.swift`):**

```swift
// Key lifecycle — shared between signing and encryption keys

@_cdecl("enclaveapp_available")
public func enclaveapp_available() -> Int32

@_cdecl("enclaveapp_generate_signing_key")
public func enclaveapp_generate_signing_key(
    pubKeyOut: UnsafeMutablePointer<UInt8>,
    pubKeyLen: UnsafeMutablePointer<Int32>,
    dataRepOut: UnsafeMutablePointer<UInt8>,
    dataRepLen: UnsafeMutablePointer<Int32>,
    authPolicy: Int32
) -> Int32

@_cdecl("enclaveapp_generate_encryption_key")
public func enclaveapp_generate_encryption_key(
    pubKeyOut: UnsafeMutablePointer<UInt8>,
    pubKeyLen: UnsafeMutablePointer<Int32>,
    dataRepOut: UnsafeMutablePointer<UInt8>,
    dataRepLen: UnsafeMutablePointer<Int32>,
    authPolicy: Int32
) -> Int32

@_cdecl("enclaveapp_signing_public_key")
public func enclaveapp_signing_public_key(
    dataRep: UnsafePointer<UInt8>, dataRepLen: Int32,
    pubKeyOut: UnsafeMutablePointer<UInt8>, pubKeyLen: UnsafeMutablePointer<Int32>
) -> Int32

@_cdecl("enclaveapp_encryption_public_key")
public func enclaveapp_encryption_public_key(
    dataRep: UnsafePointer<UInt8>, dataRepLen: Int32,
    pubKeyOut: UnsafeMutablePointer<UInt8>, pubKeyLen: UnsafeMutablePointer<Int32>
) -> Int32

// Signing (sshenc)

@_cdecl("enclaveapp_sign")
public func enclaveapp_sign(
    dataRep: UnsafePointer<UInt8>, dataRepLen: Int32,
    message: UnsafePointer<UInt8>, messageLen: Int32,
    sigOut: UnsafeMutablePointer<UInt8>, sigLen: UnsafeMutablePointer<Int32>
) -> Int32

// ECIES encryption (awsenc, sso-jwt)
// Encrypt doesn't need the private key — only the public key.
// The ciphertext format is:
//   [65-byte ephemeral public key] [12-byte nonce] [ciphertext] [16-byte tag]

@_cdecl("enclaveapp_encrypt")
public func enclaveapp_encrypt(
    pubKeyDataRep: UnsafePointer<UInt8>, pubKeyDataRepLen: Int32,
    plaintext: UnsafePointer<UInt8>, plaintextLen: Int32,
    ciphertextOut: UnsafeMutablePointer<UInt8>, ciphertextLen: UnsafeMutablePointer<Int32>
) -> Int32

@_cdecl("enclaveapp_decrypt")
public func enclaveapp_decrypt(
    dataRep: UnsafePointer<UInt8>, dataRepLen: Int32,
    ciphertext: UnsafePointer<UInt8>, ciphertextLen: Int32,
    plaintextOut: UnsafeMutablePointer<UInt8>, plaintextLen: UnsafeMutablePointer<Int32>
) -> Int32
```

**ECIES implementation in Swift (CryptoKit):**

```swift
func eciesEncrypt(publicKey: P256.KeyAgreement.PublicKey, plaintext: Data) -> Data {
    // 1. Generate ephemeral key pair
    let ephemeral = P256.KeyAgreement.PrivateKey()

    // 2. ECDH shared secret
    let shared = try ephemeral.sharedSecretFromKeyAgreement(with: publicKey)

    // 3. Derive symmetric key via X9.63 KDF (matches Security.framework behavior)
    let symKey = shared.x963DerivedSymmetricKey(
        using: SHA256.self,
        sharedInfo: ephemeral.publicKey.x963Representation,
        outputByteCount: 32
    )

    // 4. AES-GCM encrypt
    let sealed = try AES.GCM.seal(plaintext, using: symKey)

    // 5. Pack: ephemeral_pub (65) || nonce (12) || ciphertext || tag (16)
    return ephemeral.publicKey.x963Representation
         + sealed.nonce
         + sealed.ciphertext
         + sealed.tag
}

func eciesDecrypt(privateKey: SecureEnclave.P256.KeyAgreement.PrivateKey,
                  ciphertext: Data) -> Data {
    // 1. Unpack
    let ephemeralPub = try P256.KeyAgreement.PublicKey(x963Representation: ciphertext[0..<65])
    let nonce = try AES.GCM.Nonce(data: ciphertext[65..<77])
    let encrypted = ciphertext[77..<(ciphertext.count - 16)]
    let tag = ciphertext[(ciphertext.count - 16)...]

    // 2. ECDH with SE-bound private key
    let shared = try privateKey.sharedSecretFromKeyAgreement(with: ephemeralPub)

    // 3. Derive same symmetric key
    let symKey = shared.x963DerivedSymmetricKey(
        using: SHA256.self,
        sharedInfo: ephemeralPub.x963Representation,
        outputByteCount: 32
    )

    // 4. AES-GCM decrypt
    let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: encrypted, tag: tag)
    return try AES.GCM.open(sealedBox, using: symKey)
}
```

**Rust side (`src/lib.rs`):**

```rust
// Feature-gated modules
#[cfg(feature = "signing")]
pub mod sign;       // EnclaveSigner impl

#[cfg(feature = "encryption")]
pub mod encrypt;    // EnclaveEncryptor impl

pub mod keychain;   // Key lifecycle (always available)
```

**build.rs** — same pattern as sshenc: compile Swift to static library, link.

### enclaveapp-windows

Unified CNG layer supporting both signing and ECIES.

```rust
pub mod provider;   // NCrypt provider open, RAII handle wrapper
pub mod key;        // Key create/open/delete/enumerate (shared)
pub mod ui_policy;  // Windows Hello policy setup
pub mod export;     // ECCPUBLIC_BLOB → SEC1 conversion

#[cfg(feature = "signing")]
pub mod sign;       // NCryptSignHash + P1363→DER

#[cfg(feature = "encryption")]
pub mod encrypt;    // ECDH + AES-GCM (BCrypt)
```

Key differences from current code:
- **sshenc** uses `BCRYPT_ECDSA_P256_ALGORITHM` for signing
- **awsenc/sso-jwt** use `BCRYPT_ECDH_P256_ALGORITHM` for key agreement

Both go through the same provider, same key lifecycle, same UI policy. The algorithm choice is parameterized by `KeyType`.

### enclaveapp-wsl

Generic WSL integration, parameterized by app name.

```rust
pub struct WslConfig {
    pub app_name: String,           // "sshenc", "awsenc", "sso-jwt"
    pub begin_marker: String,       // auto-generated from app_name
    pub end_marker: String,
    pub block_content: String,      // App provides the shell script body
    pub deps: Vec<WslDependency>,   // What to install (socat, bridge binary, etc.)
}

pub fn is_wsl() -> bool;
pub fn detect_distros() -> Vec<WslDistro>;
pub fn configure_distro(distro: &WslDistro, config: &WslConfig) -> Result<()>;
pub fn unconfigure_distro(distro: &WslDistro, config: &WslConfig) -> Result<()>;
pub fn syntax_check_shell(distro: &WslDistro, shell: &str, content: &[u8]) -> Result<()>;
```

### enclaveapp-bridge

Generic TPM bridge binary. Currently awsenc and sso-jwt each build their own — this becomes one binary parameterized by key name.

```rust
// Server side (Windows binary)
pub fn run_bridge_server(key_name: &str) -> Result<()>;

// Client side (WSL/Linux)
pub fn find_bridge(app_name: &str) -> Option<PathBuf>;
pub fn call_bridge(bridge_path: &Path, method: &str, data: &[u8]) -> Result<Vec<u8>>;
```

The bridge protocol stays JSON-RPC over stdin/stdout. The key name (`"awsenc-tpm-key"`, `"sso-jwt-cache-key"`) is the only app-specific parameter.

Alternatively, a single `enclaveapp-bridge.exe` binary could manage keys for all three apps, selected by a `--app` flag or key name prefix.

## ECIES Ciphertext Format

To ensure awsenc and sso-jwt can migrate without breaking existing caches, the ECIES format must match what Security.framework produces — or we define a new format and provide a migration path.

**Option A: Match Security.framework format**

Security.framework's `eciesEncryptionCofactorX963SHA256AESGCM` produces:
```
[65-byte ephemeral EC point] [ciphertext + 16-byte GCM tag]
```
The nonce is derived from the shared secret (not stored). This is harder to reproduce exactly in CryptoKit.

**Option B: New CryptoKit-native format (recommended)**

```
[1-byte version = 0x01]
[65-byte ephemeral EC point]
[12-byte AES-GCM nonce]
[N-byte ciphertext]
[16-byte GCM tag]
```

Explicit nonce is more robust and auditable. The version byte allows future format evolution.

**Migration:** On first decrypt, try old Security.framework format. If that fails (version byte present), use new format. On encrypt, always use new format. After one successful decrypt+re-encrypt cycle, the cache is migrated.

## Feature Flags

Each consuming app only pulls in what it needs:

```toml
# sshenc — needs signing only
enclaveapp-apple = { version = "0.1", features = ["signing"] }
enclaveapp-windows = { version = "0.1", features = ["signing"] }

# awsenc — needs encryption only
enclaveapp-apple = { version = "0.1", features = ["encryption"] }
enclaveapp-windows = { version = "0.1", features = ["encryption"] }
enclaveapp-bridge = { version = "0.1" }

# sso-jwt — needs encryption only
enclaveapp-apple = { version = "0.1", features = ["encryption"] }
enclaveapp-windows = { version = "0.1", features = ["encryption"] }
enclaveapp-bridge = { version = "0.1" }
```

## Migration Plan

### Phase 1: Build libenclaveapp from sshenc internals

1. Create `libenclaveapp` repo
2. Extract `enclaveapp-core` from sshenc-core (atomic writes, dir locking, config helpers, key metadata, error types)
3. Extract `enclaveapp-apple` from sshenc-ffi-apple (Swift bridge, signing path)
4. Extract `enclaveapp-windows` from sshenc-ffi-windows (CNG signing path)
5. Extract `enclaveapp-wsl` from sshenc-cli/wsl.rs
6. Write tests against mock + real hardware
7. Make sshenc depend on libenclaveapp, delete extracted code, verify all tests pass

### Phase 2: Add encryption support

1. Add `SecureEnclave.P256.KeyAgreement` support to Swift bridge
2. Add ECIES encrypt/decrypt to Swift bridge
3. Add ECDH + AES-GCM to enclaveapp-windows (from awsenc-tpm-bridge/tpm.rs)
4. Implement `EnclaveEncryptor` trait on both platforms
5. Extract `enclaveapp-bridge` from sso-jwt-tpm-bridge (or awsenc-tpm-bridge — they're nearly identical)
6. Test encryption roundtrip on macOS + Windows

### Phase 3: Migrate awsenc

1. Replace `awsenc-secure-storage` macOS impl with `enclaveapp-apple` (encryption feature)
2. Replace `awsenc-tpm-bridge` with `enclaveapp-bridge`
3. Replace WSL detection with `enclaveapp-wsl`
4. Add cache format migration (Security.framework → CryptoKit ECIES)
5. Delete awsenc-secure-storage/macos.rs, awsenc-tpm-bridge/tpm.rs, awsenc WSL code
6. Run full test suite, verify Okta flow still works

### Phase 4: Migrate sso-jwt

1. Same as Phase 3 but for sso-jwt
2. Replace sso-jwt-lib/secure_storage/* with enclaveapp crates
3. Replace sso-jwt-tpm-bridge with enclaveapp-bridge
4. Add cache format migration
5. Delete replaced code, verify OAuth flow still works

### Phase 5: Shared CI/CD

1. Create reusable GitHub Actions workflows in libenclaveapp
2. Standardize release packaging (tar.gz, zip, MSI, Homebrew, Scoop, winget)
3. Each app's release.yml becomes a thin wrapper calling shared workflows

## Risks

1. **ECIES format compatibility** — old caches encrypted with Security.framework need to decrypt under CryptoKit. The KDF and nonce derivation must match exactly, or we need the migration path described above.

2. **CryptoKit availability** — CryptoKit requires macOS 10.15+. Security.framework works on older versions. Acceptable tradeoff since macOS 10.15 is the practical minimum anyway.

3. **Swift bridge compilation** — The build.rs Swift compilation adds ~2s to clean builds. Now three apps pay this cost. Mitigation: the static library is cached by cargo, so incremental builds are unaffected.

4. **Breaking changes in shared library** — A bug fix in libenclaveapp ships to all three apps simultaneously. This is mostly a feature (fix once) but needs careful versioning. Use semver strictly.

## Non-Goals

- Abstracting over key algorithms (only P-256 is hardware-backed on both platforms)
- Supporting non-Apple/non-Windows platforms in the hardware layer (Linux stays software-only, per app)
- Merging the three apps into one binary
- Sharing app-specific logic (SSH agent protocol, Okta auth, OAuth device flow)
