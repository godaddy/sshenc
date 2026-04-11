# Architecture

## Workspace Layout

```
sshenc/
  Cargo.toml                    # Workspace root
  crates/
    sshenc-core/                # Domain models, SSH encoding, config, errors
    sshenc-se/                  # Secure Enclave backend (trait + macOS impl)
    sshenc-agent-proto/         # SSH agent protocol types and wire format
    sshenc-agent/               # SSH agent daemon (binary + library)
    sshenc-cli/                 # Main CLI binary (sshenc)
    sshenc-keygen-cli/          # Standalone keygen binary (sshenc-keygen)
    sshenc-pkcs11/              # PKCS#11 provider (cdylib)
    sshenc-ffi-apple/           # Apple Security.framework bridge
    sshenc-test-support/        # Mock backend and test fixtures
```

## Crate Responsibilities

### sshenc-core

Platform-independent foundation. Contains:

- **Key domain models** (`key.rs`): `KeyLabel` (validated label type), `KeyMetadata`,
  `KeyInfo`, `KeyAlgorithm`, `KeyGenOptions`. Labels are validated to be non-empty,
  ASCII alphanumeric plus hyphens/underscores, max 64 characters.
- **SSH public key encoding** (`pubkey.rs`): `SshPublicKey` type with SEC1 byte input,
  SSH wire format encoding per RFC 5656, OpenSSH line formatting, and parsing.
  Provides `write_ssh_string` and `read_ssh_string` for the SSH string primitive.
- **Fingerprints** (`fingerprint.rs`): SHA-256 (base64, no padding) and MD5
  (colon-separated hex) fingerprint generation from SSH wire-format blobs.
- **Config** (`config.rs`): `Config` struct with TOML serialization/deserialization.
  Covers socket path, allowed labels, prompt policy, pub directory, log level,
  and host-specific identity preferences.
- **Errors** (`error.rs`): `Error` enum covering all failure modes across the project.
  All crates use `sshenc_core::error::Result<T>`.

### sshenc-se

Trait-based key backend abstraction with a real macOS implementation.

- **`KeyBackend` trait** (`backend.rs`): `generate`, `list`, `get`, `delete`, `sign`,
  `is_available`. All operations are synchronous. The trait is `Send + Sync` so it can
  be shared across async tasks.
- **`SecureEnclaveBackend`** (`macos.rs`): Real implementation using `sshenc-ffi-apple`.
  Handles key lifecycle through Apple APIs, `.pub` file management, and fingerprint
  computation. Behind `#[cfg(target_os = "macos")]`.

### sshenc-ffi-apple

Direct Apple Security.framework calls, isolated from the rest of the codebase.

- **`keychain` module**: Wraps `SecKeyCreateRandomKey`, `SecItemCopyMatching`,
  `SecItemDelete`, `SecKeyCopyPublicKey`, `SecKeyCopyExternalRepresentation`,
  `SecKeyCreateSignature`, and `SecAccessControlCreateWithFlags`.
- Non-macOS builds get a stub module that returns `false` for availability checks.

### sshenc-agent-proto

SSH agent protocol implementation (subset needed for OpenSSH interop).

- **Messages** (`message.rs`): `AgentRequest` and `AgentResponse` enums.
  Supports `SSH_AGENTC_REQUEST_IDENTITIES`, `SSH_AGENTC_SIGN_REQUEST`,
  `SSH_AGENT_IDENTITIES_ANSWER`, `SSH_AGENT_SIGN_RESPONSE`, and `SSH_AGENT_FAILURE`.
- **Signatures** (`signature.rs`): DER-to-SSH signature conversion. The Secure Enclave
  returns DER-encoded ECDSA signatures; OpenSSH expects
  `string("ecdsa-sha2-nistp256") || string(mpint(r) || mpint(s))`.
- **Wire format** (`wire.rs`): Message framing (`uint32(length) || payload`),
  SSH string read/write, 256 KB message size limit.

### sshenc-agent

Async Unix socket server using tokio.

- Listens on a configurable Unix socket path
- Sets socket permissions to 0600
- Handles concurrent connections via `tokio::spawn`
- For `RequestIdentities`: lists keys from backend, filters by allowed labels,
  returns SSH public key blobs
- For `SignRequest`: matches key blob to a backend key, signs data, converts
  DER signature to SSH wire format
- Cleans up the socket file on shutdown (SIGINT)

### sshenc-cli

Main CLI (`sshenc` binary) built with clap derive macros. Subcommands:

- `keygen`: Generate key, optionally write `.pub` file, print public key
- `list`: List all managed keys (text or JSON)
- `inspect`: Detailed key info by label
- `delete`: Delete keys with confirmation prompt (`--yes` to skip)
- `export-pub`: Export public key, fingerprint, or authorized_keys line
- `agent`: Start the SSH agent daemon (delegates to `sshenc-agent`)
- `config init|path|show`: Config file management
- `openssh print-config`: Generate SSH config snippets

### sshenc-keygen-cli

Standalone `sshenc-keygen` binary. Thin wrapper that directly calls into
`sshenc-se` for key generation and outputs the public key. Supports `--auto-pub`
for automatic `~/.ssh/<label>.pub` creation.

### sshenc-pkcs11

PKCS#11 provider as a `cdylib`. Single-slot, single-token model mapping the
Secure Enclave as the hardware token.

Currently implemented: `C_Initialize`, `C_Finalize`, `C_GetInfo`, `C_GetSlotList`,
`C_GetSlotInfo`, `C_GetTokenInfo`, `C_OpenSession`, `C_CloseSession`,
`C_CloseAllSessions`.

Returns `CKR_FUNCTION_NOT_SUPPORTED` for: `C_FindObjectsInit`, `C_FindObjects`,
`C_FindObjectsFinal`, `C_GetAttributeValue`, `C_SignInit`, `C_Sign`.

Session management uses a simple handle allocator (1-based handles, max 16 sessions).

### sshenc-test-support

- **`MockKeyBackend`**: In-memory `KeyBackend` implementation. Generates deterministic
  fake EC points and DER signatures from seed values. Supports all `KeyBackend` operations.
- **Test helpers**: `test_ec_point(seed)` and `test_signature(data, seed)` for generating
  structurally valid (but cryptographically meaningless) test data.

## Dependency Graph

```
sshenc-cli ──> sshenc-agent ──> sshenc-agent-proto ──> sshenc-core
     |              |
     └──> sshenc-se ├──> sshenc-ffi-apple
              |
              └──> sshenc-core

sshenc-keygen-cli ──> sshenc-se ──> sshenc-core

sshenc-pkcs11 ──> sshenc-se ──> sshenc-core

sshenc-test-support ──> sshenc-se ──> sshenc-core
```

## Data Flow

### Key Generation

1. User runs `sshenc keygen --label my-key`
2. `sshenc-cli` validates the label via `KeyLabel::new()`
3. `sshenc-cli` calls `SecureEnclaveBackend::generate()`
4. `sshenc-se` checks for duplicate tags via `keychain::find_key_by_tag()`
5. `sshenc-ffi-apple` calls `SecKeyCreateRandomKey` with:
   - Key type: `kSecAttrKeyTypeECSECPrimeRandom` (P-256)
   - Token: `kSecAttrTokenIDSecureEnclave`
   - Application tag: `com.sshenc.key.<label>` (raw bytes)
   - Label: `sshenc:<label>`
   - Access control: `kSecAccessControlPrivateKeyUsage` (plus `kSecAccessControlUserPresence` if requested)
   - Protection: `AccessibleWhenPasscodeSetThisDeviceOnly`
6. `sshenc-ffi-apple` extracts the public key via `SecKeyCopyPublicKey` + `SecKeyCopyExternalRepresentation` (65-byte uncompressed SEC1)
7. `sshenc-core` formats the SSH public key line and computes fingerprints
8. The `.pub` file is written if `--write-pub` was specified
9. `KeyInfo` is returned to the CLI for display

### Signing (Agent)

1. OpenSSH sends `SSH_AGENTC_SIGN_REQUEST` over the Unix socket
2. `sshenc-agent` reads the framed message, parses via `sshenc-agent-proto`
3. The key blob in the request is matched against known keys by listing all
   backend keys and comparing wire-format public key blobs
4. The matched key's label is used to call `backend.sign(label, data)`
5. `sshenc-se` calls `keychain::find_key_by_tag()` to get the `SecKey` reference
6. `sshenc-ffi-apple` calls `SecKeyCreateSignature` with
   `ECDSASignatureMessageX962SHA256`
7. The DER-encoded signature is converted to SSH wire format by
   `sshenc-agent-proto::signature::der_to_ssh_signature()`
8. The agent sends `SSH_AGENT_SIGN_RESPONSE` back to OpenSSH

### Identity Enumeration (Agent)

1. OpenSSH sends `SSH_AGENTC_REQUEST_IDENTITIES`
2. Agent lists all keys from backend, filters by `allowed_labels` config
3. Each key's public bytes are converted to SSH wire-format blobs
4. Agent sends `SSH_AGENT_IDENTITIES_ANSWER` with the list

## Apple API Mapping

| Operation | Apple API | Notes |
|---|---|---|
| Generate key | `SecKeyCreateRandomKey` | P-256, Secure Enclave token, access control flags |
| Find key by tag | `SecItemCopyMatching` | Query by `kSecAttrApplicationTag` + `kSecAttrKeyClassPrivate` |
| List all keys | `SecItemCopyMatching` | `kSecMatchLimitAll`, filter by `sshenc:` label prefix |
| Delete key | `SecItemDelete` | By application tag |
| Get public key | `SecKeyCopyPublicKey` | From private key reference |
| Export public bytes | `SecKeyCopyExternalRepresentation` | Public key only, 65-byte SEC1 |
| Sign data | `SecKeyCreateSignature` | `ECDSASignatureMessageX962SHA256`, returns DER |
| Access control | `SecAccessControlCreateWithFlags` | `PrivateKeyUsage`, optional `UserPresence` |

## Key Tagging Strategy

Each key has two identifiers in the Keychain:

- **Application tag** (`kSecAttrApplicationTag`): `com.sshenc.key.<label>` stored as
  raw bytes. Used for precise single-key lookup. Reverse-DNS format avoids collision
  with other applications.
- **Keychain label** (`kSecAttrLabel`): `sshenc:<label>` as a string. Used for
  prefix-based enumeration (list all keys). The `sshenc:` prefix allows filtering
  without touching unrelated Keychain items.

Key enumeration works by querying all EC private keys with `kSecMatchLimitAll`,
returning attributes, and filtering client-side for items whose label starts
with `sshenc:`. This is necessary because `SecItemCopyMatching` does not support
prefix matching on string attributes.

## Security Boundaries

1. **Secure Enclave hardware**: Private key material is generated and stored here.
   It never exists in application memory.
2. **Keychain access control**: Keys are created with
   `AccessibleWhenPasscodeSetThisDeviceOnly`, meaning they require the device
   passcode to be set and are not included in backups or synced via iCloud Keychain.
3. **Application tag namespace**: Only keys tagged with `com.sshenc.key.*` are
   operated on. sshenc never modifies unrelated Keychain items.
4. **Agent socket permissions**: Set to 0600 (owner-only). Only the launching user
   can connect.
5. **Label allowlist**: The agent can be configured to expose only specific keys,
   limiting which keys are available for signing.
6. **No private key export**: The `SecKeyCopyExternalRepresentation` call is used
   only on the public key obtained via `SecKeyCopyPublicKey`. The Secure Enclave
   would refuse this call on the private key itself.
