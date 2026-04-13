# Contributing

## Development Setup

1. Install Rust 1.75+ via [rustup](https://rustup.rs/).
2. Clone the repository:
   ```sh
   git clone https://github.com/godaddy/sshenc.git
   cd sshenc
   ```
3. Build and run tests:
   ```sh
   cargo build
   cargo test
   ```

See [DEVELOPMENT.md](DEVELOPMENT.md) for detailed build and test instructions.

## Pull Request Process

1. Fork the repository and create a branch from `main`.
2. Make your changes. Write tests for new functionality.
3. Run the full check suite:
   ```sh
   cargo fmt --all -- --check
   cargo clippy --workspace
   cargo test
   ```
4. All three commands must pass with no errors or warnings.
5. Open a pull request against `main` with a clear description of what
   changed and why.
6. PRs require review before merge.

## Coding Standards

- Follow existing code style. Run `cargo fmt --all` before committing.
- All public items must have doc comments.
- All source files must carry the MIT SPDX header:
  ```rust
  // Copyright 2024 Jay Gowdy
  // SPDX-License-Identifier: MIT
  ```
- Use `thiserror` for error types. All errors go through `sshenc_core::error::Error`.
- No `unsafe` unless strictly necessary. If used, document why it is
  sound in a `// SAFETY:` comment.
- Keep Apple framework calls in `sshenc-ffi-apple`. Do not add Apple
  imports to other crates.
- Use the `KeyBackend` trait for anything that touches key storage.
  Implement the mock in `sshenc-test-support` alongside any real backend
  changes.

## Testing Requirements

- New features must include tests.
- Bug fixes must include a regression test.
- Tests that require Secure Enclave hardware must be behind
  `#[cfg(target_os = "macos")]` and documented in [TESTING.md](TESTING.md).
- Use `MockKeyBackend` from `sshenc-test-support` for tests that exercise
  key operations without hardware.
- All existing tests must continue to pass.

## Commit Messages

- Use clear, descriptive commit messages.
- First line: imperative mood, under 72 characters (e.g., "Add host-specific
  identity selection to agent").
- Body: explain the motivation and approach if the change is non-trivial.

## Scope

Contributions welcome for:

- Bug fixes
- Test coverage improvements
- Documentation improvements
- PKCS#11 provider implementation
- Performance improvements
- New CLI features that fit the project scope

For large changes or new features, open an issue first to discuss the
approach before investing significant effort.
