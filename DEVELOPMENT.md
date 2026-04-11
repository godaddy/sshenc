# Development Guide

## Prerequisites

- **Rust 1.75+** (check with `rustc --version`)
- **macOS** (the project links against Apple Security.framework)
- **Secure Enclave hardware** for integration tests (Apple Silicon or T2 chip)
- **Xcode Command Line Tools** (`xcode-select --install`)

Unit tests and tests using the mock backend run on any macOS machine.
Integration tests that create real Secure Enclave keys require hardware
with a Secure Enclave.

## Building

```sh
# Build all crates
cargo build

# Build a single crate
cargo build -p sshenc-core

# Build in release mode
cargo build --release

# Build the PKCS#11 dynamic library
cargo build --release -p sshenc-pkcs11
```

## Testing

### Run all tests

```sh
cargo test
```

This runs unit tests and platform-independent integration tests. Tests that
require Secure Enclave hardware are behind `#[cfg]` gates and will be
conditionally compiled only on macOS.

### Run tests for a single crate

```sh
cargo test -p sshenc-core
cargo test -p sshenc-agent-proto
cargo test -p sshenc-test-support
cargo test -p sshenc-pkcs11
```

### Run a specific test

```sh
cargo test test_wire_format_roundtrip
cargo test -p sshenc-core test_openssh_line_format
```

### Test with the mock backend

The `sshenc-test-support` crate provides `MockKeyBackend`, an in-memory
implementation of `KeyBackend`. Tests in other crates use it to verify
behavior without hardware:

```sh
cargo test -p sshenc-test-support
```

### Run hardware integration tests

Hardware tests interact with the real Secure Enclave and Keychain. They
create and delete actual keys. Run them on a machine with Secure Enclave
access:

```sh
cargo test -p sshenc-se
cargo test -p sshenc-ffi-apple
```

These tests may trigger Touch ID or password prompts depending on key
access control settings.

## Linting

```sh
# Run clippy on all crates
cargo clippy --workspace

# Check formatting
cargo fmt --all -- --check

# Auto-format
cargo fmt --all
```

## Documentation

```sh
# Build API docs for all crates
cargo doc --workspace --no-deps

# Open in browser
cargo doc --workspace --no-deps --open
```

## Adding a New Feature

1. Identify which crate(s) the change belongs in. Domain types go in
   `sshenc-core`. Apple API calls go in `sshenc-ffi-apple`. Backend logic
   goes in `sshenc-se`. Protocol changes go in `sshenc-agent-proto`.
   CLI changes go in `sshenc-cli`.

2. If the change requires a new `KeyBackend` method, add it to the trait
   in `sshenc-se/src/backend.rs`, then implement it in both
   `sshenc-se/src/macos.rs` and `sshenc-test-support/src/mock.rs`.

3. Write unit tests in the same file as the implementation.

4. Write integration tests that exercise the feature through the mock backend.

5. Run `cargo clippy --workspace` and `cargo fmt --all -- --check` before
   submitting.

6. Run `cargo test` to verify nothing is broken.

## Project Structure Conventions

- All source files carry the MIT SPDX header.
- Error types are centralized in `sshenc-core/src/error.rs`.
- All Apple framework calls are isolated in `sshenc-ffi-apple`.
- The `KeyBackend` trait is the boundary between platform-specific code
  and the rest of the application. All code above `sshenc-se` is
  platform-independent.
- CLI output supports `--json` for machine-readable formats.
- Key labels are validated at construction (`KeyLabel::new()`), not at
  use sites.
