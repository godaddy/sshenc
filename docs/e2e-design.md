# End-to-End Testing Design

Status: draft — April 24, 2026
Scope: test-only; no change to sshenc production code.

## Goal

Prove that `sshenc` is a drop-in replacement for `ssh`/`ssh-agent` against a real
OpenSSH server:

1. On-disk keys in `~/.ssh/id_*` continue to work when sshenc is installed,
   whether or not any enclave keys exist.
2. Enclave keys added via `sshenc keygen` work through both the agent socket
   and the `sshenc ssh --label …` wrapper.
3. `sshenc ssh --label …` correctly restricts identity selection to the named
   enclave key (forces `IdentitiesOnly yes`).
4. On-disk fallback continues to work even when `sshenc-agent` is running
   with zero enclave keys.

## Non-goals

- Windows e2e coverage. Spinning up sshd on Windows in a test harness is a
  separate problem and is deferred.
- Testing the Docker image contents. The image is a reproducibility aid, not
  a unit under test.
- Proving git-over-SSH workflows end-to-end. `gitenc` uses the same
  `sshenc ssh` machinery, so SSH auth coverage transitively validates the
  SSH side of gitenc. A dedicated gitenc scenario is a follow-up.

## Why Docker

Earlier alternatives (spawn a local `sshd` on a random port, or only test the
agent protocol in-process) were rejected for these reasons:

- **Local `sshd`**: requires `/usr/sbin/sshd` installed and privilege-sensitive
  config; fails differently on macOS vs Linux runners; mutates host state
  (auth logs, privsep dir).
- **In-process agent tests**: validate parsing, not authentication against a
  real SSH implementation. Cannot catch wire-format regressions that survive
  a round-trip with the sshenc implementation but fail against OpenSSH.

A container built from a small Dockerfile gives a reproducible OpenSSH server
that is identical on every developer machine and CI runner, owns its own
host keys and user database, and tears down cleanly.

## Backend selection

`SshencBackend::new` calls `AppSigningBackend::init`, which auto-detects the
best available platform backend (Secure Enclave on macOS, TPM on
Linux/Windows with a TPM, falling back to on-disk ECDSA via
`enclaveapp-software`). The e2e tests do **not** force a specific backend;
they let the auto-detection run and exercise whichever backend is present.

- On a developer laptop with SE/TPM, tests exercise the real hardware path.
- On CI runners without SE/TPM (typical), tests exercise the software path.

Tests assert on observable SSH behavior (the server authenticated us or it
didn't). That invariant holds regardless of backend, so no per-backend
branches are needed.

## Prerequisites

- `docker` binary in `PATH` and `docker info` succeeds. Tests that cannot
  reach the Docker daemon print a skip message and exit 0.
- A supported platform. Linux and macOS only in v1.
- Standard OpenSSH client (`ssh`, `ssh-keygen`) on the host — already a hard
  runtime dependency of `sshenc` itself, so no new requirement.

## Crate layout

```
crates/sshenc-e2e/
├── Cargo.toml                 # test-only crate, no library output
├── build.rs                   # fingerprints Docker assets for cache busting
├── docker/
│   ├── Dockerfile             # OpenSSH test server (alpine-based)
│   └── entrypoint.sh          # host-key gen, authorized_keys injection
├── src/
│   └── lib.rs                 # SshdContainer, SshencEnv, helpers
└── tests/
    └── drop_in.rs             # six scenarios, all #[ignore] by default
```

The crate is a workspace member but produces no published artifacts. All
tests are gated with `#[ignore]` so `cargo test --workspace` stays fast.

## Docker image

Built locally from `crates/sshenc-e2e/docker/Dockerfile`:

- Base: `alpine:3`
- Packages: `openssh-server`, `bash`
- Creates user `sshtest` with no password; locks the password entry.
- `/etc/ssh/sshd_config`: pubkey auth only, no password, no root login, no
  PAM, no challenge-response. Host keys generated fresh at container start
  via `ssh-keygen -A`.
- Entry point reads authorized keys from either:
  - `/authorized_keys` (mounted file), or
  - `$AUTHORIZED_KEYS` (newline-separated pubkeys).

Tagged `sshenc-e2e-sshd:latest`. The image is built once per `cargo test`
invocation by a `OnceLock` in the harness. `docker build` with an unchanged
Dockerfile is a near-instant cache hit.

## `SshdContainer` fixture

```rust
pub struct SshdContainer {
    container_id: String,
    pub host_port: u16,
    pub host_ip: &'static str, // always "127.0.0.1"
}

impl SshdContainer {
    pub fn start(authorized_keys: &[&str]) -> io::Result<Self>;
    pub fn skip_reason() -> Option<String>; // returns Some if Docker unavailable
}

impl Drop for SshdContainer {
    // docker kill + docker rm (best-effort)
}
```

- `start()` writes `authorized_keys` to a tempfile and runs:
  ```
  docker run --rm -d -p 127.0.0.1:0:22 -v <tempfile>:/authorized_keys:ro sshenc-e2e-sshd:latest
  ```
- The harness then invokes `docker port <id> 22/tcp` to learn the
  host-side port.
- It polls `TcpStream::connect` until the port answers (with timeout).
- `Drop` runs `docker kill <id>` synchronously; `--rm` handles removal.

## `SshencEnv` fixture

```rust
pub struct SshencEnv {
    pub home: PathBuf,      // tempdir, HOME for all child processes
    pub socket: PathBuf,    // <home>/.sshenc/agent.sock
    agent: Option<Child>,
}

impl SshencEnv {
    pub fn new() -> Self;
    pub fn start_agent(&mut self) -> io::Result<()>;
    pub fn stop_agent(&mut self);
    pub fn sshenc_cmd(&self) -> Command;    // sshenc binary, HOME=<home>
    pub fn ssh_cmd(&self) -> Command;       // system ssh, HOME=<home>
}

impl Drop for SshencEnv { /* stop_agent, rm_rf home */ }
```

- `HOME` is set to a per-test tempdir so the default `Config::load_default`
  paths (`~/.sshenc/agent.sock`, `~/.ssh/`) resolve inside the sandbox.
- `SSH_AUTH_SOCK` is explicitly unset to prevent leakage from the host's
  agent.
- Binaries are located via `env!("CARGO_BIN_EXE_sshenc")` and
  `env!("CARGO_BIN_EXE_sshenc-agent")`, which Cargo defines for integration
  tests that depend on the binaries' crates.
- The agent is started in foreground mode (`--foreground --socket …`) as a
  child process. The harness polls the socket until it accepts connections.
- A small known_hosts file is written into the tempdir; the harness does not
  use `-o StrictHostKeyChecking=no` for the main ssh invocation (it accepts
  the container host key on first connect with `-o StrictHostKeyChecking=accept-new`
  and a tempdir `UserKnownHostsFile`).

## Scenarios (six, in `tests/drop_in.rs`)

Each test names what it proves. Every test runs in a fresh `SshencEnv` and
its own `SshdContainer` (parallel-safe: random ports, disjoint tempdirs).

1. `sshenc_install_preserves_plain_ssh_with_on_disk_keys`
   - No enclave keys (ephemeral keys dir). On-disk `id_ed25519` generated
     in `$HOME/.ssh/`.
   - Run `sshenc install`, which writes the managed `Host *` block with
     `IdentityAgent` into `$HOME/.ssh/config` and daemonizes the agent.
   - Verify the config file actually contains `IdentityAgent` and the
     isolated socket path.
   - Container `authorized_keys` trusts the on-disk pubkey.
   - Expect: plain `ssh -F <written-config> -i <on-disk> sshtest@…` exits 0.
   - Proves the real install flow (not just the `sshenc ssh` wrapper) is
     drop-in for users with existing on-disk keys.

2. `agent_running_zero_enclave_keys`
   - Same as 1, but `sshenc-agent` is running with an empty backend.
   - Expect: success.
   - Proves the agent doesn't break on-disk fallback when it has nothing to
     offer.

3. `both_present_unlabeled_accepts_on_disk`
   - Enclave key created via `sshenc keygen`. On-disk key also present.
   - Container trusts only the on-disk pubkey.
   - Expect: `sshenc ssh -- sshtest@127.0.0.1 -p <port> true` succeeds
     (agent tries enclave, sshd rejects, ssh falls back to on-disk).

4. `both_present_unlabeled_accepts_enclave`
   - Same setup as 3, but the container trusts the enclave pubkey only.
   - Expect: `sshenc ssh` succeeds (agent provides enclave identity).

5. `label_forces_enclave_and_fails_against_on_disk_only`
   - Enclave and on-disk keys both present; container trusts on-disk only.
   - Run `sshenc ssh --label <name> -- sshtest@127.0.0.1 -p <port> true`.
   - Expect: **failure**. `IdentitiesOnly yes` + enclave-only IdentityFile
     means ssh must not fall back to on-disk.
   - Asserts exit code is non-zero and that authentication failed (not a
     transport error).

6. `plain_ssh_with_identity_agent_uses_both`
   - Invoke system `ssh` directly (not the `sshenc ssh` wrapper) with
     `-o IdentityAgent=<sshenc-sock>`. Enclave and on-disk keys both
     present; container trusts either variant, run once per variant.
   - Expect: success in both variants.
   - Proves agent-only installation (`~/.ssh/config` `IdentityAgent`
     directive) preserves drop-in semantics.

## Running

```
# Runs all non-ignored tests (fast path, no Docker).
cargo test --workspace

# Runs the ignored e2e tests. Requires Docker.
cargo test -p sshenc-e2e -- --ignored

# Makefile convenience.
make e2e
```

CI tier: `cargo test --workspace` stays on PRs; the e2e suite runs in a
separate job that provides Docker. Failures in the e2e job should block merge.

## Scenario inventory

### `tests/drop_in.rs` — six drop-in scenarios (baseline)

1. `sshenc_install_preserves_plain_ssh_with_on_disk_keys`
2. `agent_running_zero_enclave_keys_still_authenticates_on_disk`
3. `both_present_unlabeled_falls_back_to_on_disk`
4. `both_present_unlabeled_uses_enclave_via_agent`
5. `label_forces_enclave_and_refuses_on_disk_fallback`
6. `plain_ssh_with_identity_agent_accepts_both_key_paths`

### `tests/ssh_functions.rs` — fourteen function-coverage scenarios (baseline)

 1. `scp_roundtrips_file_via_enclave_agent` — scp upload + download + byte
    comparison.
 2. `sftp_lists_remote_directory_via_enclave_agent` — sftp batch-mode
    `ls` sees files placed via scp.
 3. `ssh_local_port_forward_through_enclave_agent` — `ssh -L` forwards
    to container sshd; local connect reads `SSH-2.0` banner.
 4. `ssh_a_forwards_sshenc_agent_to_remote` — `ssh -A`; running
    `ssh-add -l` in the container enumerates forwarded identities.
 5. `ssh_add_l_enumerates_sshenc_agent` — direct `SSH_AUTH_SOCK=<sock>
    ssh-add -l` lists enclave identities.
 6. `sshenc_y_sign_produces_valid_signature` — `sshenc -Y sign` →
    `ssh-keygen -Y verify` with an allowed_signers file.
 7. `concurrent_ssh_invocations_via_enclave_agent` — four parallel ssh
    runs against the same agent all succeed.
 8. `rsync_over_ssh_via_enclave_agent` — `rsync -e ssh` uploads and
    downloads a directory tree authenticated through the agent; file
    contents byte-compared.
 9. `on_disk_rsa_key_still_works_with_sshenc_agent` — legacy on-disk
    RSA key authenticates when sshenc-agent is running.
10. `on_disk_ecdsa_key_still_works_with_sshenc_agent` — same for ECDSA.
11. `exit_code_propagates_through_sshenc_ssh` — remote exit codes
    (0, 1, 17, 42, 127) reach the local caller through the wrapper.
12. `stdin_stdout_binary_roundtrip_via_sshenc_ssh` — 16 KiB of
    full-range bytes (including NUL/CR/LF) piped through `ssh host cat`
    and byte-compared.
13. `ssh_tt_allocates_pty_through_sshenc_agent` — `ssh -tt` produces a
    working pty on the remote (critical for sudo-over-ssh, curses apps).
14. `ssh_copy_id_authorizes_new_key_via_existing_credentials` — user
    with an on-disk key runs `ssh-copy-id` to authorize their enclave
    pubkey; the enclave key works afterward.

### `tests/gitenc.rs` — five scenarios (baseline)

1. `gitenc_push_and_clone_roundtrip_via_enclave_agent` — make a commit,
   push via `gitenc`, re-clone, verify file content matches.
2. `gitenc_label_forces_named_enclave_key` — `--label e2e-shared` pushes
   succeed against a server trusting the enclave; a bogus label fails.
3. `gitenc_config_writes_expected_git_config` — `gitenc --config <label>`
   sets `core.sshCommand`, `gpg.format`, `user.signingkey`,
   `commit.gpgsign`, `gpg.ssh.program` to the expected values.
4. `gitenc_config_signs_commit_and_verifies` — full chain:
   `sshenc identity`, `gitenc --config`, `git commit -S`,
   `git log --show-signature` accepts the signature.
5. `gitenc_falls_back_to_on_disk_when_agent_is_empty` — proves gitenc
   inherits the same ssh-level drop-in compatibility: user with
   only an on-disk key can still use gitenc.

### `tests/extended.rs` — two scenarios gated behind `SSHENC_E2E_EXTENDED=1`

1. `sshenc_ssh_selects_among_multiple_enclave_keys_by_label`
2. `sshenc_default_promotion_writes_id_ecdsa_pub_and_authenticates`

## Backend rename support

`sshenc default <label>` renames a label to `default`. Pre-existing on
macOS the metadata rename was disk-only and left the Keychain
wrapping-key entry orphaned, so the newly-promoted `default` could not
be unwrapped. This was found by the promotion e2e scenario and fixed in
`libenclaveapp` by adding `EnclaveKeyManager::rename_key` with per-backend
overrides:

- **Apple Secure Enclave**: moves the keychain wrapping-key entry +
  renames disk metadata atomically, with rollback on failure.
- **Linux keyring**: decrypts under old label, re-encrypts under new
  label (new KEK in keyring), renames disk files, deletes old keyring
  entry.
- **Linux TPM**: renames `.tpm_pub` / `.tpm_priv` blobs + disk metadata.
- **Software (test)**: renames disk files only.
- **Windows TPM**: returns error — CNG persisted keys are immutable by
  name. A UUID-indirection refactor (label ↔ UUID mapping in metadata)
  would unblock this on Windows; tracked as a follow-up in libenclaveapp.

## Open risks / follow-ups

- Alpine's `openssh-server` vs Debian's: we pin the Alpine version; future
  bumps require re-validating the sshd_config directive set.
- If Docker Desktop is paused on macOS, `docker info` still exits 0 in some
  versions. The container-start timeout will catch it, but the failure mode
  is a timeout, not a skip. Acceptable for now.
- A gitenc e2e scenario (push to a bare repo inside the container) is
  tracked as a follow-up; not required for the drop-in claim.
- Windows `sshenc default` is still unsupported pending the UUID
  indirection redesign in libenclaveapp.
- Concurrent `cargo test -- --test-threads=N` is safe because containers
  bind ephemeral ports and tempdirs are disjoint, but image builds race on
  the first run; a `OnceLock` guards this.
