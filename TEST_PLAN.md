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
- **sshenc-e2e** (36 scenarios total, `#[ignore]` by default): sshenc
  and gitenc against a real OpenSSH server in a Docker container.
  Covers:
  - **drop-in compatibility** (`tests/drop_in.rs`, 6 scenarios):
    `sshenc install` + plain ssh, empty-agent fallback, both-keys-unlabeled
    (on-disk and enclave variants), `--label` enclave-only restriction,
    and plain `ssh` with `IdentityAgent`.
  - **ssh function coverage** (`tests/ssh_functions.rs`, 14 scenarios):
    scp/sftp/rsync data transfer, `ssh -L` / `-A` forwarding, `ssh-add -l`
    enumeration, `sshenc -Y sign` + verify, concurrent signing, legacy
    on-disk RSA + ECDSA keys, exit-code propagation, binary stdin/stdout
    roundtrip, `ssh -tt` pty allocation, and `ssh-copy-id` key deposit.
  - **gitenc** (`tests/gitenc.rs`, 5 scenarios): push + clone roundtrip
    via enclave agent, `--label` forces the named key, `--config`
    writes expected git config, `--config` + `git commit -S` produces
    an ssh signature that `git log --show-signature` accepts, and
    fallback to on-disk keys with an empty agent.
  - **CLI lifecycle / config surface** (`tests/lifecycle.rs`, 9 scenarios):
    `list` (text + JSON), `inspect` (+ `--show-pub`), `delete`, `install`
    idempotency, install+uninstall round-trip preserving other config,
    the standalone `sshenc-keygen` binary, `openssh print-config`,
    `config init`/`path`/`show`, and the agent's `allowed_labels`
    filtering.
  - **extended** (`tests/extended.rs`, 2 scenarios, gated behind
    `SSHENC_E2E_EXTENDED=1`): multi-label enclave-key selection and
    `sshenc default` promotion. Gated because each extra SE key on macOS
    adds one keychain ACL prompt per binary per rebuild.

  **Dual-mode verification.** The full 36-scenario suite runs and passes
  in two modes:
  - Default (Secure Enclave on macOS): `SSHENC_E2E_EXTENDED=1 make e2e`.
  - Software backend: `SSHENC_E2E_SOFTWARE=1 SSHENC_E2E_EXTENDED=1 make e2e`.
    Builds the sshenc binaries with the `force-software` Cargo feature
    and sets `SSHENC_FORCE_SOFTWARE=1` at runtime so `SshencBackend::new`
    constructs `enclaveapp-test-software::SoftwareSigner` instead of the
    platform backend. Zero keychain prompts; also the path exercised by
    Linux CI where SE/TPM isn't available.

  Run with:
  ```sh
  make e2e                                                        # baseline 13 scenarios
  SSHENC_E2E_EXTENDED=1 cargo test -p sshenc-e2e -- --ignored --test-threads=1  # all 15
  ```

  **Backend coverage.** The suite is backend-agnostic: assertions are on
  observable SSH behavior, not on which backend signed. On developer
  macOS machines the Secure Enclave backend runs; on Linux CI runners
  without TPM, the software keyring backend runs. Both paths pass the
  same scenarios.

  **macOS prompt budget.** Per rebuild of either `sshenc` or
  `sshenc-agent`, each persistent enclave key prompts once for keychain
  ACL. Baseline mode uses one shared key → 2 prompts per rebuild (one
  per binary). Extended mode uses three keys → up to 6 prompts per
  rebuild. After Always Allow, subsequent test runs against the same
  binaries are silent. See `docs/e2e-design.md` for design.

## Fuzz Targets

Run with: `cd fuzz && cargo +nightly fuzz run <target>`

- `read_ssh_string` — fuzzes `sshenc_core::pubkey::read_ssh_string` with arbitrary byte input
- `parse_request` — fuzzes `sshenc_agent_proto::message::parse_request` with arbitrary byte input
- `parse_der_signature` — fuzzes `sshenc_agent_proto::signature::der_to_ssh_signature` with arbitrary byte input

## Future Testing Roadmap

- **Miri**: run `cargo +nightly miri test` on `sshenc-core` and `sshenc-agent-proto` (pure Rust, no FFI). Several tests are already `#[cfg_attr(miri, ignore)]` for file I/O.
- **Hardware integration**: gate real Secure Enclave / TPM tests behind `#[cfg(feature = "hardware-tests")]` and a CI runner with hardware access.
- **Property-based testing**: consider `proptest` for SSH wire format roundtrip properties.
