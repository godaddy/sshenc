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

## Per-Crate Test Inventory

- **sshenc-core** (~20 tests): SSH public key wire format encoding/decoding roundtrips, OpenSSH line format parsing, fingerprint generation (SHA-256/MD5), config serialization roundtrips, SSH config install/uninstall/idempotency, backup/rollback transactional safety, binary discovery candidate selection
- **sshenc-agent-proto** (~14 tests): Agent protocol message parsing/serialization, DER-to-SSH signature conversion, identity enumeration encoding
- **sshenc-agent** (~15 tests): PID file management, readiness protocol (ready/error/timeout), socket path preparation (stale socket cleanup, live socket rejection), prompt policy enforcement, handle_request for identity and sign requests
- **sshenc-cli** (~40 tests): keygen lifecycle (create/duplicate/invalid label/comment/pub file/user presence/json), list (empty/populated/json), inspect (existing/missing/json/pub), delete (single/multiple/pub cleanup/empty labels/verification), export-pub (stdout/file/nested dir/fingerprint/json/authorized_keys), agent launcher (spawn/already running/error propagation), Windows install state (prepare/finalize/restore/service parsing/registry parsing), promote-to-default (rename/rollback/overwrite), ssh wrapper invocation, ssh-keygen sign args parsing, SSH signature file creation, base64 wrapping, openssh config printing
- **sshenc-gitenc** (~15 tests): Arg parsing (label/config/short flags/empty/passthrough), build_ssh_command validation, configure_repo_entries (default/named label/recorded pub path/missing pub path), git key metadata parsing (app_specific/legacy), signing_key_path validation
- **sshenc-pkcs11** (~4 tests): Session management, slot/token info
- **sshenc-test-support** (~8 tests): Mock backend key lifecycle (generate/list/get/delete/sign), deterministic key generation, pub file write, comment handling
- **sshenc-e2e** (6 scenarios, `#[ignore]` by default): drop-in compatibility
  against a real OpenSSH server in a Docker container. Covers on-disk-only,
  empty-agent fallback, both-keys-unlabeled (on-disk and enclave variants),
  `--label` enclave-only restriction, and plain `ssh` with `IdentityAgent`.
  Run with `make e2e` or `cargo test -p sshenc-e2e -- --ignored --test-threads=1`.
  See `docs/e2e-design.md` for design and the shared-enclave-key rationale
  (minimizes macOS keychain prompts to one-per-binary-per-rebuild).

## Fuzz Targets

Run with: `cd fuzz && cargo +nightly fuzz run <target>`

- `read_ssh_string` — fuzzes `sshenc_core::pubkey::read_ssh_string` with arbitrary byte input
- `parse_request` — fuzzes `sshenc_agent_proto::message::parse_request` with arbitrary byte input
- `parse_der_signature` — fuzzes `sshenc_agent_proto::signature::der_to_ssh_signature` with arbitrary byte input

## Future Testing Roadmap

- **Miri**: run `cargo +nightly miri test` on `sshenc-core` and `sshenc-agent-proto` (pure Rust, no FFI). Several tests are already `#[cfg_attr(miri, ignore)]` for file I/O.
- **Hardware integration**: gate real Secure Enclave / TPM tests behind `#[cfg(feature = "hardware-tests")]` and a CI runner with hardware access.
- **Property-based testing**: consider `proptest` for SSH wire format roundtrip properties.
