# Testing Strategy

## Overview

Tests are split into categories based on what they require to run:

| Category | Requires hardware | Crates | Run with |
|---|---|---|---|
| Unit tests | No | All | `cargo test` |
| Mock backend tests | No | `sshenc-test-support` | `cargo test -p sshenc-test-support` |
| Protocol tests | No | `sshenc-agent-proto` | `cargo test -p sshenc-agent-proto` |
| SSH encoding tests | No | `sshenc-core` | `cargo test -p sshenc-core` |
| PKCS#11 session tests | No | `sshenc-pkcs11` | `cargo test -p sshenc-pkcs11` |
| Hardware integration | Yes | `sshenc-se`, `sshenc-ffi-apple` | `cargo test -p sshenc-se` |

## Unit Tests

Each crate contains unit tests in `#[cfg(test)] mod tests` blocks colocated
with the implementation.

### sshenc-core

- **pubkey.rs**: SEC1 byte validation (length, prefix), wire format
  encoding/decoding roundtrip, OpenSSH line formatting and parsing, wire
  format structure verification.
- **fingerprint.rs**: SHA-256 format (`SHA256:` prefix, base64 no padding),
  MD5 format (`MD5:` prefix, 16 colon-separated hex pairs), deterministic
  output.
- **key.rs**: `KeyLabel` validation (empty, too long, invalid characters),
  `app_tag()` generation.
- **config.rs**: Default config values, TOML roundtrip serialization, file
  save/load, missing file returns default.

### sshenc-agent-proto

- **message.rs**: Parse `REQUEST_IDENTITIES`, parse `SIGN_REQUEST` with
  key blob / data / flags, parse unknown message types, serialize
  `FAILURE` / `IDENTITIES_ANSWER` / `SIGN_RESPONSE`, empty payload
  rejection.
- **wire.rs**: Message frame read/write roundtrip, SSH string roundtrip,
  empty message rejection, oversized message rejection (>256 KB).
- **signature.rs**: DER-to-SSH signature conversion, handling of leading
  zeros in integer components, invalid DER rejection (wrong tags, truncated
  data).

### sshenc-pkcs11

- **session.rs**: Session handle allocation (1-based), open/close lifecycle,
  close-all, max session capacity, invalid handle rejection, slot reuse
  after close.

## Mock Backend Tests

`sshenc-test-support/src/mock.rs` tests the `MockKeyBackend` which
implements `KeyBackend` in memory:

- Generate and retrieve a key
- Duplicate label rejection
- List multiple keys
- Delete a key and verify count
- Delete nonexistent key returns error
- Sign produces structurally valid DER
- Sign is deterministic for same input
- Sign for missing key returns error

These tests validate the `KeyBackend` trait contract without hardware.
The same contract is expected of the real `SecureEnclaveBackend`.

## Hardware Integration Tests

Located in `sshenc-se` and `sshenc-ffi-apple`. These tests:

- Create real Secure Enclave keys
- Extract public key bytes and verify format (65 bytes, 0x04 prefix)
- Sign data and verify DER structure
- Delete keys and verify removal
- Exercise the full `SecureEnclaveBackend` implementation

These tests are behind `#[cfg(target_os = "macos")]` and require a Mac
with Secure Enclave hardware. They may trigger biometric prompts.

## Agent Protocol Tests

The tests in `sshenc-agent-proto` verify protocol correctness independently
of any key backend:

- Message framing (length prefix encoding)
- Request parsing (identity enumeration, sign request, unknown types)
- Response serialization (identity list, signature, failure)
- Signature format conversion (DER to SSH wire format)

## What Is Tested Where

| Behavior | Test location |
|---|---|
| SSH public key wire format | `sshenc-core/src/pubkey.rs` |
| SSH public key line format | `sshenc-core/src/pubkey.rs` |
| Fingerprint computation | `sshenc-core/src/fingerprint.rs` |
| Key label validation | `sshenc-core/src/key.rs` |
| Config serialization | `sshenc-core/src/config.rs` |
| Agent message parsing | `sshenc-agent-proto/src/message.rs` |
| Agent wire framing | `sshenc-agent-proto/src/wire.rs` |
| DER to SSH signature | `sshenc-agent-proto/src/signature.rs` |
| PKCS#11 sessions | `sshenc-pkcs11/src/session.rs` |
| KeyBackend contract | `sshenc-test-support/src/mock.rs` |
| Real Secure Enclave ops | `sshenc-se/src/macos.rs` (hardware) |
| Apple Keychain FFI | `sshenc-ffi-apple/src/keychain.rs` (hardware) |

## Running the Full Test Suite

```sh
# All tests (unit + mock + protocol)
cargo test

# With verbose output
cargo test -- --nocapture

# Only tests matching a pattern
cargo test fingerprint
cargo test -p sshenc-agent-proto sign

# Excluding hardware tests (they're cfg-gated, but for clarity)
cargo test -p sshenc-core -p sshenc-agent-proto -p sshenc-test-support -p sshenc-pkcs11
```
