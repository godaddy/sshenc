# Testing Strategy

## Test categories

| Category | Purpose | Typical crates |
|---|---|---|
| unit tests | pure logic and serialization | `sshenc-core`, `sshenc-agent-proto`, `sshenc-cli` |
| mock-backend tests | key-management behavior without hardware | `sshenc-test-support`, callers of `KeyBackend` |
| integration tests | CLI and workflow coverage | `sshenc-cli`, `sshenc-gitenc`, selected workspace tests |
| platform tests | real backend behavior on target OS | `sshenc-se`, `sshenc-agent` |

## Core expectations

Every change should preserve:

- valid SSH public-key encoding
- stable fingerprint formatting
- correct SSH agent protocol framing
- correct key metadata persistence
- consistent default-key behavior
- safe install and uninstall of managed SSH config blocks

## Recommended commands

```sh
# broad regression run
cargo test

# focused protocol and encoding validation
cargo test -p sshenc-core
cargo test -p sshenc-agent-proto

# mock backend behavior
cargo test -p sshenc-test-support

# backend integration
cargo test -p sshenc-se
```

## What the mock backend covers

`sshenc-test-support` is for:

- trait-contract coverage
- deterministic signatures and public keys
- duplicate/delete/list behavior
- calling code that should not require real hardware

It is not a substitute for validating:

- Secure Enclave / TPM availability
- OS prompt behavior
- real backend persistence formats
- WSL and Windows agent compatibility

## Platform-specific validation

When a change touches platform behavior, validate the affected path directly:

- macOS: key creation, signing, install flow, OpenSSH use
- Windows: named pipe path, Git Bash compatibility, install/uninstall behavior
- Linux TPM: backend availability and key persistence
- Linux fallback: software backend behavior and warning paths

## CLI/doc sync checks

The docs in this repo are expected to match the live CLI. Re-run:

```sh
cargo run -q -p sshenc-cli -- --help
cargo run -q -p sshenc-cli -- help openssh
cargo run -q -p sshenc-cli -- help config
```

after changing commands, flags, or examples.
