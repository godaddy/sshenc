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

## Open risks / follow-ups

- Alpine's `openssh-server` vs Debian's: we pin the Alpine version; future
  bumps require re-validating the sshd_config directive set.
- If Docker Desktop is paused on macOS, `docker info` still exits 0 in some
  versions. The container-start timeout will catch it, but the failure mode
  is a timeout, not a skip. Acceptable for now.
- A gitenc e2e scenario (push to a bare repo inside the container) is
  tracked as a follow-up; not required for the drop-in claim.
- Concurrent `cargo test -- --test-threads=N` is safe because containers
  bind ephemeral ports and tempdirs are disjoint, but image builds race on
  the first run; a `OnceLock` guards this.
