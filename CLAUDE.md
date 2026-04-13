# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`sshenc` (SSH Secure Enclave) is a cross-platform Rust project that provides hardware-backed SSH key management. It creates, manages, and uses ECDSA P-256 keys for OpenSSH and git+ssh workflows. On macOS keys are stored in the Secure Enclave, on Windows in TPM 2.0, and on Linux as software-backed keys on disk. Licensed under MIT.

## Build & Development

Rust workspace. Requires macOS, Windows, or Linux with Rust 1.75+.

```bash
cargo build --workspace            # build all crates
cargo build -p sshenc-core         # build a single crate
cargo test --workspace             # run all tests
cargo test -p sshenc-core          # test a single crate
cargo test test_name               # run a specific test
cargo clippy --workspace --all-targets -- -D warnings  # lint (must pass clean)
cargo fmt --all -- --check         # check formatting
cargo fmt --all                    # auto-format
```

## Architecture

Rust workspace under `crates/`:

- **sshenc-core** — Domain models, SSH public key encoding (ecdsa-sha2-nistp256), fingerprints (SHA-256/MD5), config model, shared error types. No platform-specific code.
- **sshenc-ffi-apple** — Apple Security.framework bridge. All raw Apple API calls isolated here. Defines `kSecAttrApplicationTag` via extern link since it's missing from `security-framework-sys`. Keys tagged with `sshenc:<label>` Keychain label and `com.sshenc.key.<label>` application tag.
- **sshenc-se** — High-level key operations via `KeyBackend` trait. Unified `SshencBackend` uses `enclaveapp-app-storage::AppSigningBackend` for automatic platform detection (Secure Enclave, TPM, software). SSH-specific logic (pub file management, fingerprinting, metadata) stays in this crate. The trait enables mock backends for testing.
- **sshenc-agent-proto** — SSH agent protocol: message parsing/serialization, DER-to-SSH signature conversion. Implements identity enumeration and sign request/response.
- **sshenc-agent** — SSH agent daemon (tokio async). Unix socket server, key selection by label allowlist. Both a library (`sshenc_agent::server`) and binary (`sshenc-agent`).
- **sshenc-cli** — Main CLI (`sshenc`). Subcommands: keygen, list, inspect, delete, export-pub, agent, config, openssh. Uses sshenc-agent library for embedded agent mode.
- **sshenc-keygen-cli** — Standalone `sshenc-keygen` binary.
- **sshenc-pkcs11** — PKCS#11 provider (cdylib). Session management and info functions implemented. Crypto operations (`C_FindObjects`, `C_Sign`, etc.) return `CKR_FUNCTION_NOT_SUPPORTED` — scaffold for future implementation.
- **sshenc-test-support** — `MockKeyBackend` for testing without Secure Enclave hardware. Deterministic key generation and signature production.

### Key Patterns

- `KeyBackend` trait (`sshenc-se/src/backend.rs`) is the central abstraction. Real SE backend and mock backend both implement it.
- SSH wire format helpers (`write_ssh_string`, `read_ssh_string`) are in `sshenc-core/src/pubkey.rs` and reused by agent-proto.
- DER-to-SSH signature conversion in `sshenc-agent-proto/src/signature.rs` handles the Secure Enclave's DER output → OpenSSH's mpint format.
- PKCS#11 types in `sshenc-pkcs11/src/types.rs` are `#[repr(C)]` structs matching the PKCS#11 v2.40 C header.

### Binaries

1. `sshenc` — umbrella CLI with all subcommands
2. `sshenc-keygen` — convenience keygen binary
3. `sshenc-agent` — ssh-agent-compatible daemon
4. `libsshenc_pkcs11.dylib` — PKCS#11 provider (cdylib)

## Testing

41 unit tests across sshenc-core (15), sshenc-agent-proto (14), sshenc-pkcs11 (4), sshenc-test-support (8). Tests cover:
- SSH public key wire format encoding/decoding roundtrips
- OpenSSH line format parsing
- Fingerprint generation (SHA-256/MD5)
- Config serialization roundtrips
- Agent protocol message parsing/serialization
- DER signature parsing
- PKCS#11 session management
- Mock backend key lifecycle (generate/list/get/delete/sign)

Real Secure Enclave integration tests require macOS hardware and are not yet gated behind cfg flags (future work).

## Platform

Supports macOS, Windows, and Linux:
- **macOS**: Uses Apple Secure Enclave via Security.framework. The `sshenc-ffi-apple` crate links against the Security framework at build time.
- **Windows**: Uses TPM 2.0 via Windows CNG.
- **Linux**: Uses software-backed ECDSA P-256 keys via `enclaveapp-software`. Keys are stored on disk in `~/.sshenc/keys/` and are NOT hardware-protected.
