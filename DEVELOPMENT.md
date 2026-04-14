# Development Guide

## Prerequisites

- Rust 1.75+
- one of:
  - macOS with Xcode command line tools
  - Windows with Visual Studio Build Tools
  - Linux with standard build tooling
- for Linux TPM work: `tpm2-tss` development libraries

Hardware-backed integration work is easiest on the platform you are targeting, but the software fallback and mock backend keep most of the workspace testable on any development machine.

## Build

```sh
# Entire workspace
cargo build

# Release build
cargo build --release

# Individual crates
cargo build -p sshenc-cli
cargo build -p sshenc-agent
cargo build -p sshenc-pkcs11
```

## Test

```sh
# All workspace tests
cargo test

# Lint + format check
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

Useful focused runs:

```sh
cargo test -p sshenc-core
cargo test -p sshenc-agent-proto
cargo test -p sshenc-test-support
cargo test -p sshenc-se
```

## Cross-platform expectations

- `sshenc-se` is where hardware backend integration lives
- `sshenc-core` should stay platform-agnostic
- CLI changes usually land in `sshenc-cli`
- agent protocol changes belong in `sshenc-agent-proto`
- actual agent behavior belongs in `sshenc-agent`

If a change requires new key-management behavior, update both:

- the real backend in `sshenc-se`
- the mock backend in `sshenc-test-support`

## Hardware-specific work

The workspace supports:

- macOS Secure Enclave
- Windows TPM 2.0
- Linux TPM 2.0
- Linux software fallback

When you touch platform behavior, test on the real platform when possible. The mock backend is useful for control-flow coverage, but it does not validate platform prompts, OS policy handling, or actual hardware persistence.

## Documentation and CLI validation

Before landing CLI changes, verify:

```sh
cargo run -q -p sshenc-cli -- --help
cargo run -q -p sshenc-cli -- help config
cargo run -q -p sshenc-cli -- help openssh
```

This catches drift between implementation and the user-facing docs.
