# Current Test Plan

This plan tracks the current `sshenc` workspace rather than the older pre-refactor crate layout.

## Priority areas

1. Key lifecycle
   - generate, inspect, list, delete
   - default-key promotion
   - metadata persistence and compatibility handling

2. SSH wire compatibility
   - OpenSSH public-key formatting
   - DER to SSH signature conversion
   - agent protocol framing and bounds checking

3. Agent behavior
   - identity ordering
   - label filtering
   - Unix socket and Windows named-pipe handling

4. Installation flows
   - managed block install/uninstall in `~/.ssh/config`
   - OpenSSH snippet generation
   - WSL configuration on Windows hosts

5. Git integration
   - `gitenc --config`
   - SSH signing via `ssh-keygen -Y sign`
   - default-key and labeled-key workflows

6. Platform backends
   - macOS Secure Enclave
   - Windows TPM
   - Linux TPM
   - Linux software fallback

## Minimum regression command set

```sh
cargo test
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Extra validation when touching specific areas

- protocol changes: `cargo test -p sshenc-agent-proto`
- backend changes: `cargo test -p sshenc-se`
- config or metadata changes: `cargo test -p sshenc-core -p sshenc-test-support`
- CLI changes: verify `sshenc --help`, `sshenc help openssh`, and `sshenc help config`
