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

- **sshenc-core** — Domain models, SSH public key encoding (ecdsa-sha2-nistp256), fingerprints (SHA-256/MD5), config model (`AccessPolicy`, `PromptPolicy`), shared error types, `backup.rs` (transactional key material backup/rollback), and `bin_discovery.rs` (trusted binary discovery without PATH lookup). Note: `bin_discovery.rs` and `ssh_config.rs` contain platform-specific code (`#[cfg(windows)]` / `#[cfg(unix)]`).
- **sshenc-se** — High-level key operations via `KeyBackend` trait. Unified `SshencBackend` uses `enclaveapp-app-storage::AppSigningBackend` for automatic platform detection (Secure Enclave, TPM, software). SSH-specific logic (pub file management, fingerprinting, metadata) stays in this crate. The trait enables mock backends for testing. Note: platform backends (Secure Enclave, TPM, software) are provided by the `enclaveapp-*` crate family via `enclaveapp-app-storage`; the old `sshenc-ffi-apple` crate has been removed.
- **sshenc-agent-proto** — SSH agent protocol: message parsing/serialization, DER-to-SSH signature conversion. Implements identity enumeration and sign request/response.
- **sshenc-agent** — SSH agent daemon (tokio async). Unix socket server, key selection by label allowlist. Both a library (`sshenc_agent::server`) and binary (`sshenc-agent`).
- **sshenc-cli** — Main CLI (`sshenc`). Subcommands: keygen, list, inspect, delete, export-pub, agent, config, openssh. Uses sshenc-agent library for embedded agent mode.
- **sshenc-gitenc** — Git wrapper binary (`gitenc`). Selects Secure Enclave identities for git operations, configures repos for SSH auth and commit signing.
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
4. `gitenc` — git wrapper for Secure Enclave identity selection and repo config
5. `libsshenc_pkcs11.dylib` — PKCS#11 provider (cdylib)

## Testing

90+ unit tests across the workspace. Tests cover:
- SSH public key wire format encoding/decoding roundtrips
- OpenSSH line format parsing
- Fingerprint generation (SHA-256/MD5)
- Config serialization roundtrips
- Agent protocol message parsing/serialization
- DER signature parsing
- PKCS#11 session management
- Mock backend key lifecycle (generate/list/get/delete/sign)
- Trusted binary discovery and SSH config generation
- Transactional backup/rollback of key material
- AccessPolicy and PromptPolicy configuration

Real Secure Enclave integration tests require macOS hardware and are not yet gated behind cfg flags (future work).

## Platform

Supports macOS, Windows, and Linux:
- **macOS**: Uses Apple Secure Enclave via CryptoKit. Platform backend provided by `enclaveapp-app-storage`.
- **Windows**: Uses TPM 2.0 via Windows CNG.
- **Linux**: Uses software-backed ECDSA P-256 keys via `enclaveapp-software`. Keys are stored on disk in `~/.sshenc/keys/` and are NOT hardware-protected.
