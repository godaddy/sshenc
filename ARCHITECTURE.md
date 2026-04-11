# Architecture

## Workspace Layout

```
sshenc/
  Cargo.toml                    # Workspace root
  crates/
    sshenc-core/                # Domain models, SSH encoding, ssh_config, errors
    sshenc-se/                  # Secure Enclave backend (trait + macOS impl)
    sshenc-agent-proto/         # SSH agent protocol types and wire format
    sshenc-agent/               # SSH agent daemon (binary + library)
    sshenc-cli/                 # Main CLI binary (sshenc)
    sshenc-keygen-cli/          # Standalone keygen binary (sshenc-keygen)
    sshenc-pkcs11/              # PKCS#11 agent launcher (cdylib)
    sshenc-ffi-apple/           # CryptoKit Secure Enclave bridge (Swift static lib + Rust FFI)
    sshenc-gitenc/              # Git wrapper binary (gitenc)
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
- **SSH config management** (`ssh_config.rs`): Install/uninstall of a managed block
  in `~/.ssh/config`. The block sets `IdentityAgent` and optionally `PKCS11Provider`
  under `Host *`. Uses comment-delimited markers for idempotent edits.
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
  Stores key handles and public key caches in `~/.sshenc/keys/`. Loads persisted
  metadata (auth policy, comment, creation time) from `.meta` files. Behind
  `#[cfg(target_os = "macos")]`.

### sshenc-ffi-apple

CryptoKit Secure Enclave bridge, isolated from the rest of the codebase.

- **Swift static library** (`swift/sshenc_se_bridge.swift`): Compiled by `build.rs`
  via `swiftc` into a static library (`libsshenc_se_bridge.a`). Links CryptoKit,
  Security, and LocalAuthentication frameworks. Exposes `@_cdecl` C functions:
  - `sshenc_se_available` -- checks `SecureEnclave.isAvailable`
  - `sshenc_se_generate` -- creates `SecureEnclave.P256.Signing.PrivateKey`, returns
    `dataRepresentation` (opaque SE handle) and 65-byte uncompressed public key
  - `sshenc_se_public_key` -- reconstructs public key from a data representation
  - `sshenc_se_sign` -- loads key from data representation, signs message (CryptoKit
    hashes with SHA-256 internally), returns DER-encoded ECDSA signature
- **Rust FFI layer** (`src/se.rs`): Declares `extern "C"` bindings to the Swift
  functions. Provides safe wrappers: `generate()`, `public_key_from_data_rep()`,
  `sign()`. Handles file-based key storage: `save_key()`, `load_key()`,
  `load_pub_key()`, `delete_key()`, `list_key_labels()`, `load_meta()`.
  Also includes `KeyMeta` (serde), `AuthPolicy` enum, SSH public key formatting,
  and base64 encoding.
- **`build.rs`**: Compiles `sshenc_se_bridge.swift` to an object file, archives it
  into a static library, and emits linker directives for `swiftCore`, `swiftFoundation`,
  `CryptoKit`, `Security`, and `LocalAuthentication` frameworks. macOS-only; non-macOS
  builds get a stub returning `false` for availability.
- No Apple Developer certificate or code signing required. CryptoKit works with the
  standard ad-hoc linker signature that `ld` applies.

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

Async Unix socket server using tokio. Serves only Secure Enclave keys; legacy
`~/.ssh` keys are handled by SSH natively.

- Listens on a configurable Unix socket path (default `~/.sshenc/agent.sock`)
- Sets socket permissions to 0600
- Handles concurrent connections via `tokio::spawn`
- For `RequestIdentities`: lists keys from backend, filters by allowed labels,
  returns SSH public key blobs
- For `SignRequest`: matches key blob to a backend key, signs data, converts
  DER signature to SSH wire format
- Cleans up the socket file on shutdown (SIGINT)

### sshenc-cli

Main CLI (`sshenc` binary) built with clap derive macros. Subcommands:

- `keygen`: Generate key with `--label`, `--comment`, `--auth-policy`, `--require-user-presence`.
  Optionally writes `.pub` file to `~/.ssh/`. Supports JSON output.
- `list`: List all managed keys (text or JSON)
- `inspect`: Detailed key info by label (with optional `--show-pub`)
- `delete`: Delete keys with confirmation prompt (`--yes` to skip, `--delete-pub` to
  remove associated `.pub` files)
- `export-pub`: Export public key, fingerprint, or authorized_keys line
- `agent`: Start the SSH agent daemon (delegates to `sshenc-agent`)
- `config init|path|show`: Config file management
- `openssh print-config`: Generate SSH config snippets (agent or PKCS#11 mode)
- `install`: Add `IdentityAgent` and `PKCS11Provider` to `~/.ssh/config` under `Host *`
- `uninstall`: Remove the managed block from `~/.ssh/config`
- `ssh`: Run ssh using a specific sshenc key (`-o IdentityAgent`, `-o IdentityFile`)
- `completions`: Generate shell completions (bash, zsh, fish)

### sshenc-keygen-cli

Standalone `sshenc-keygen` binary. Thin wrapper that directly calls into
`sshenc-se` for key generation and outputs the public key. Supports `--auto-pub`
for automatic `~/.ssh/<label>.pub` creation.

### sshenc-pkcs11

PKCS#11 provider as a `cdylib`. This is a thin agent launcher, not a key provider.

On `C_Initialize`, it starts the sshenc-agent if not already running (via
`agent_client::ensure_agent_running()`). `C_GetSlotList` reports 0 slots.
All key serving and signing happens through the agent via `IdentityAgent`.

OpenSSH loads the dylib (triggering agent startup), then talks to the agent
socket for authentication. The dylib implements only `C_Initialize`, `C_Finalize`,
`C_GetInfo`, `C_GetSlotList`, and `C_GetFunctionList`; all remaining function
pointers are NULL.

### sshenc-gitenc

Git wrapper binary (`gitenc`) for sshenc identity selection.

- `gitenc --label NAME [git args...]` -- sets `GIT_SSH_COMMAND="sshenc ssh --label NAME --"`
  and execs `git`
- `gitenc [git args...]` -- uses default agent key selection
- `gitenc --config NAME` -- sets `core.sshCommand` in the current repo's git config

### sshenc-test-support

- **`MockKeyBackend`**: In-memory `KeyBackend` implementation. Generates deterministic
  fake EC points and DER signatures from seed values. Supports all `KeyBackend` operations.
- **Test helpers**: `test_ec_point(seed)` and `test_signature(data, seed)` for generating
  structurally valid (but cryptographically meaningless) test data.

## Dependency Graph

```
sshenc-cli ──> sshenc-agent ──> sshenc-agent-proto ──> sshenc-core
     |              |
     └──> sshenc-se ├──> sshenc-ffi-apple (Swift static lib + CryptoKit)
              |
              └──> sshenc-core

sshenc-keygen-cli ──> sshenc-se ──> sshenc-core

sshenc-pkcs11 (agent launcher, no key serving)

sshenc-gitenc (standalone, execs git + sshenc)

sshenc-test-support ──> sshenc-se ──> sshenc-core
```

## Key Storage

Keys are stored as files in `~/.sshenc/keys/` (directory mode 0700). For each key
with label `<label>`:

| File | Contents | Mode |
|---|---|---|
| `<label>.handle` | CryptoKit `dataRepresentation` -- opaque reference to the SE key | 0600 |
| `<label>.pub` | Raw 65-byte uncompressed EC point (0x04 &#124;&#124; X &#124;&#124; Y), cached for fast enumeration | default |
| `<label>.ssh.pub` | OpenSSH-formatted public key line (`ecdsa-sha2-nistp256 <base64> <comment>`) | 0600 |
| `<label>.meta` | JSON: `{ label, comment, auth_policy, created }` | default |

The `.handle` file contains only an opaque SE handle. Private key material never
leaves the Secure Enclave. Key enumeration scans for `.handle` files and reads
the cached `.pub` alongside them.

All writes use atomic temp-file-then-rename to prevent partial files.

## Data Flow

### Key Generation

1. User runs `sshenc keygen --label my-key`
2. `sshenc-cli` validates the label via `KeyLabel::new()`
3. `sshenc-cli` calls `SecureEnclaveBackend::generate()`
4. `sshenc-se` checks for duplicates by attempting `se::load_key()`
5. `sshenc-ffi-apple` FFI calls `sshenc_se_generate()` in the Swift bridge:
   - Creates `SecureEnclave.P256.Signing.PrivateKey`
   - If `auth_policy != 0`, creates `SecAccessControl` with appropriate flags
     (`userPresence`, `biometryAny`, or `devicePasscode`) plus `.privateKeyUsage`
   - Extracts `key.publicKey.rawRepresentation` (64 bytes), prepends 0x04
   - Extracts `key.dataRepresentation` (opaque handle blob)
6. `sshenc-ffi-apple` saves `.handle`, `.pub`, `.ssh.pub`, and `.meta` files
7. `sshenc-core` computes fingerprints from the SSH wire-format blob
8. If `--write-pub` or default, writes `~/.ssh/<label>.pub`
9. `KeyInfo` is returned to the CLI for display

### Signing (Agent)

1. OpenSSH sends `SSH_AGENTC_SIGN_REQUEST` over the Unix socket
2. `sshenc-agent` reads the framed message, parses via `sshenc-agent-proto`
3. The key blob in the request is matched against known keys by listing all
   backend keys and comparing wire-format public key blobs
4. The matched key's label is used to call `backend.sign(label, data)`
5. `sshenc-se` loads the `.handle` file and calls `se::sign(data_rep, data)`
6. The Swift bridge loads the key from `dataRepresentation`, calls
   `key.signature(for: message)` (CryptoKit hashes with SHA-256 internally)
7. The DER-encoded signature is converted to SSH wire format by
   `sshenc-agent-proto::signature::der_to_ssh_signature()`
8. The agent sends `SSH_AGENT_SIGN_RESPONSE` back to OpenSSH

### Identity Enumeration (Agent)

1. OpenSSH sends `SSH_AGENTC_REQUEST_IDENTITIES`
2. Agent lists all keys from backend (scans `~/.sshenc/keys/*.handle`),
   filters by `allowed_labels` config
3. Each key's cached public bytes are converted to SSH wire-format blobs
4. Agent sends `SSH_AGENT_IDENTITIES_ANSWER` with the list

### SSH Config Install

`sshenc install` adds a managed block to `~/.ssh/config`:

```
# BEGIN sshenc managed block -- do not edit
Host *
    IdentityAgent ~/.sshenc/agent.sock
    PKCS11Provider /path/to/libsshenc_pkcs11.dylib
# END sshenc managed block
```

- `IdentityAgent` directs SSH authentication to the sshenc agent
- `PKCS11Provider` causes SSH to load the dylib on startup, which auto-starts
  the agent if it's not running (boot hook)
- The block is idempotent; `sshenc uninstall` removes it cleanly

## CryptoKit API Mapping

| Operation | CryptoKit / Swift API | Notes |
|---|---|---|
| Check availability | `SecureEnclave.isAvailable` | |
| Generate key | `SecureEnclave.P256.Signing.PrivateKey()` | With optional `accessControl:` parameter |
| Access control | `SecAccessControlCreateWithFlags` | `.privateKeyUsage` + optional `.userPresence` / `.biometryAny` / `.devicePasscode` |
| Persist key | `key.dataRepresentation` | Opaque blob containing SE handle; saved to `.handle` file |
| Load key | `SecureEnclave.P256.Signing.PrivateKey(dataRepresentation:)` | From `.handle` file bytes |
| Get public key | `key.publicKey.rawRepresentation` | 64-byte raw X &#124;&#124; Y; caller prepends 0x04 |
| Sign data | `key.signature(for:)` | SHA-256 hashing done internally by CryptoKit; returns DER |

## User Presence / Auth Policy

The `auth_policy` field controls whether Touch ID or password prompts are required
for signing operations. Values:

| Value | Policy | SecAccessControlCreateFlags |
|---|---|---|
| 0 | None (default) | `.privateKeyUsage` only |
| 1 | Any (Touch ID or password) | `.privateKeyUsage` + `.userPresence` |
| 2 | Biometric only | `.privateKeyUsage` + `.biometryAny` |
| 3 | Password only | `.privateKeyUsage` + `.devicePasscode` |

The policy is set at key generation time and persisted in the `.meta` file.
CryptoKit enforces it at the SE level on every `signature(for:)` call.

## Security Boundaries

1. **Secure Enclave hardware**: Private key material is generated inside the SE
   and never exists in application memory. The `.handle` file is an opaque
   reference, not key material.
2. **File permissions**: `~/.sshenc/keys/` is 0700; `.handle` and `.ssh.pub` files
   are 0600. Atomic writes prevent partial file exposure.
3. **Agent socket permissions**: Set to 0600 (owner-only). Only the launching user
   can connect.
4. **Label allowlist**: The agent can be configured to expose only specific keys,
   limiting which keys are available for signing.
5. **No private key export**: CryptoKit's `SecureEnclave.P256.Signing.PrivateKey`
   does not support extracting private key bytes. Only the public key and opaque
   data representation are accessible.
6. **No code signing required**: CryptoKit Secure Enclave operations work with
   the standard ad-hoc signature applied by the linker. No Apple Developer
   certificate or entitlements needed.
7. **SE-only agent**: The agent serves only Secure Enclave keys. Legacy `~/.ssh`
   keys are handled by SSH natively and are not touched.
