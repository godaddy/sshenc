# Architecture

## Workspace layout

`sshenc` is a 9-crate workspace:

| Crate | Purpose |
|---|---|
| `sshenc-core` | domain types, SSH encoding, config, fingerprints, ssh config edits |
| `sshenc-se` | hardware-backed signing backend built on `libenclaveapp` |
| `sshenc-agent-proto` | SSH agent wire protocol |
| `sshenc-agent` | agent daemon for Unix sockets and Windows named pipes |
| `sshenc-cli` | main `sshenc` CLI |
| `sshenc-keygen-cli` | standalone `sshenc-keygen` helper |
| `sshenc-pkcs11` | PKCS#11 launcher for OpenSSH integration |
| `sshenc-gitenc` | git wrapper and SSH signing helper |
| `sshenc-test-support` | mock backend and test fixtures |

## High-level flow

```
sshenc-cli / sshenc-keygen-cli / gitenc
            |
            |  (AgentProxyBackend — disk reads + RPC)
            |
            |  Unix socket (macOS/Linux)  or
            |  Windows named pipe
            v
        sshenc-agent
            |
            v
        sshenc-se (SshencBackend)
            |
            v
  enclaveapp-app-storage + enclaveapp-core
            |
   +--------+---------+---------+
   |                  |         |
   v                  v         v
macOS SE         Windows TPM   Linux TPM / software fallback
```

**`sshenc-agent` is the only process that ever calls into the platform crypto store.** The CLI binaries (`sshenc`, `sshenc-keygen`, `gitenc`) go through `sshenc-se::AgentProxyBackend`, which:

- serves read-only ops (`list`, `get`, `is_available`) by reading `<label>.pub` / `<label>.meta` files directly from disk — no keychain / TPM / keyring touch;
- forwards every write-side op (`generate`, `sign`, `delete`, `rename`) over the agent's local IPC endpoint (Unix socket on macOS/Linux, named pipe on Windows).

This keeps the CLI binary's code signature off every `SecItemAdd` / `SecKeyCreateSignature` / CNG / keyring call — which on unsigned macOS builds prevents the legacy keychain's cross-binary ACL prompt from firing between creator (CLI) and reader (agent).

`sshenc-se` is the backend boundary *inside* the agent process. It uses `enclaveapp-app-storage` for platform detection and backend initialization, then layers SSH-specific behavior on top:

- public key file placement
- metadata with comments and git identity
- default-key handling
- OpenSSH formatting and fingerprints

## Main binaries

### `sshenc`

Primary CLI. Current command surface includes:

- `keygen`
- `list`
- `inspect`
- `delete`
- `export-pub`
- `agent`
- `config`
- `openssh`
- `install`
- `identity`
- `uninstall`
- `default`
- `ssh`
- `completions`

It also intercepts `ssh-keygen -Y sign` compatibility mode for SSH signing workflows.

### `sshenc-agent`

Runs the actual SSH agent service:

- Unix socket on macOS/Linux
- named pipe plus Unix-socket compatibility path on Windows
- key enumeration and signing over the standard SSH agent protocol

### `gitenc`

Wraps git commands and configures repo-local SSH signing and SSH command selection. It is the bridge between a chosen `sshenc` key and ordinary git workflows.

### `sshenc-pkcs11`

Acts as an OpenSSH launcher shim. It does not hold keys itself. It ensures the agent is available so OpenSSH can talk to the agent for actual signing.

## Key storage model

`sshenc` keeps its application state in `~/.sshenc/keys/` by default. The hardware key material stays in the platform backend. `sshenc` stores only the application-side files it needs for lookup and UX:

- metadata
- cached public key bytes
- OpenSSH-formatted public key files
- platform handle/blob files where required by the backend

The exact on-disk representation depends on the selected backend, but the invariant is the same: private keys do not become exportable application files.

## Platform model

| Platform | Backend path |
|---|---|
| macOS | Secure Enclave via `enclaveapp-apple` |
| Windows | TPM 2.0 via `enclaveapp-windows` |
| Linux with TPM | TPM 2.0 via `enclaveapp-linux-tpm` |
| Linux without TPM | software fallback via `enclaveapp-software` |
| WSL | Windows-hosted agent / WSL install helpers |

## Configuration

`sshenc-core` owns the durable config format. The current config covers:

- socket path
- allowed labels
- prompt policy
- public-key output directory
- log level
- host-specific identity preferences

The `sshenc config init|path|show` commands are thin wrappers around that shared config layer.

## Key storage file layout

All application-side files live in `~/.sshenc/keys/` (Unix) or `%APPDATA%\sshenc\keys\` (Windows). For a key with label `<label>`:

- **`<label>.pub`** — SEC1 uncompressed public key bytes (65 bytes: `0x04 || x || y`). Written by the platform backend during key generation.
- **`<label>.meta`** — JSON metadata. New-format fields: `label`, `key_type` (`signing`), `access_policy` (`none`/`any`/`biometric_only`/`password_only`), `created` (timestamp), `app_specific` object containing `comment`, `git_name`, `git_email`, and `pub_file_path`. Legacy (pre-libenclaveapp) metadata is auto-migrated on read by `sshenc-se/src/compat.rs`.
- **`<label>.handle`** — Platform-specific key handle. On macOS: Keychain persistent reference. On Windows: CNG key name. On Linux (software backend): encrypted private key material stored on disk.
- **`<label>.ssh.pub`** — Optional OpenSSH-format public key line (`ecdsa-sha2-nistp256 AAAA... comment`). Written to `~/.ssh/` (or the configured `pub_dir`) when `--write-pub` is used during keygen. The path is recorded in `app_specific.pub_file_path` in the metadata.

Private keys never appear as application-accessible files. On macOS and Windows, the private key stays in the Secure Enclave or TPM respectively. On Linux, the software backend stores an encrypted private key in the handle file, but this is managed entirely by the `enclaveapp-software` crate.

## Data flow: key generation (`sshenc keygen`)

```
CLI validates label (KeyLabel::new)
  → AgentProxyBackend::generate()
    → ensure_agent_ready() — spawns sshenc-agent on Unix if not
      already listening at config.socket_path; probes the named
      pipe on Windows
    → try_generate_via_socket() sends SSH_AGENTC_SSHENC_GENERATE_KEY
      framed over the IPC endpoint
  → AGENT PROCESS receives the RPC
    → SshencBackend::generate() runs here
      → EnclaveKeyManager::generate() via AppSigningBackend
      → platform backend creates key (SE / TPM / software)
      → sshenc-se saves `.meta` / `.pub` / `.handle` to keys_dir
    → responds with SSH_AGENT_SSHENC_GENERATE_RESPONSE carrying
      SEC1 public-key bytes
  → CLI reconstructs KeyInfo client-side (fingerprints, the
    optional `~/.ssh/<label>.pub` write), prints output
```

The CLI process never touches the platform crypto store. `backend.get` / `backend.list` on the CLI side read `.pub` / `.meta` from disk directly — no `load_handle` fallback, so a missing `.pub` surfaces as `KeyNotFound` rather than triggering a keychain read.

## Data flow: signing (agent)

```
SSH client connects to agent socket (Unix) or named pipe (Windows)
  → agent reads framed message (u32 length + payload)
    → sshenc-agent-proto parses SSH agent protocol message
    → RequestIdentities: lists keys via SshencBackend::list(),
        filters by allowed_labels, returns wire-format blobs
    → SignRequest: matches key_blob against stored keys
        → checks allowed_labels filter
        → evaluates PromptPolicy vs key's AccessPolicy
        → calls SshencBackend::sign(label, data)
          → platform backend signs:
              macOS SE: triggers Touch ID/password if access_policy requires it
              Windows TPM: triggers Windows Hello
              Linux software: signs directly (no hardware enforcement)
        → sshenc-agent-proto converts DER signature to SSH format
            (DER → extract r,s integers → pad to 32 bytes → SSH mpint encoding)
        → returns framed SignResponse
```

## Data flow: git commit signing (`sshenc -Y sign`)

```
git calls: sshenc -Y sign -n git -f <pubkey_path> <data_file>
  → CLI intercepts -Y sign before clap parsing
    → reads <pubkey_path> to get the target pubkey wire blob
    → builds SSHSIG pre-sign bytes (magic + namespace + sha256(file))
    → ensure_agent_ready() — starts sshenc-agent if needed
    → try_sign_via_socket() sends standard
      SSH_AGENTC_SIGN_REQUEST to the agent over the configured
      socket (NOT `SSH_AUTH_SOCK` — sshenc's CLI always talks to
      its own agent)
  → AGENT PROCESS signs via SshencBackend and returns the
    ssh-format signature (string(algo) || string(r || s))
  → CLI builds the SSHSIG v1 envelope and writes the
    PEM-armored signature to <data_file>.sig
```

Same agent, same IPC endpoint as SSH authentication — `sshenc-agent` is a drop-in `ssh-agent` with sshenc-specific extensions layered on top (opcodes `0xF0`/`0xF1`/`0xF2`/`0xF3` for DeleteKey / GenerateKey / GenerateResponse / RenameKey).

`gitenc --config <label>` sets up the repo with `gpg.format=ssh`, `gpg.ssh.program=sshenc`, `user.signingkey=<pub_path>`, and `commit.gpgsign=true`. It also reads `git_name`/`git_email` from the key's metadata to set `user.name`/`user.email`.

## Access policy

| Policy | macOS | Windows | Linux |
|---|---|---|---|
| `None` | No prompt | No prompt | No prompt |
| `Any` | Touch ID or system password | Windows Hello | Terminal confirmation (CLI only) |
| `BiometricOnly` | Touch ID only | Windows Hello biometric | Not enforced (software backend) |
| `PasswordOnly` | System password | Windows Hello PIN | Not enforced (software backend) |

On macOS and Windows, access policy is enforced at the hardware level during the sign operation. On Linux, the software backend has no hardware to enforce policy. In CLI mode (`sshenc -Y sign`), `Any` triggers a stderr confirmation prompt; in agent mode, a warning is logged but signing proceeds because the agent has no terminal.

The agent's `PromptPolicy` config (`always`/`never`/`keydefault`) controls whether user-presence checks are applied:
- `always` — verify for every sign, regardless of key policy
- `never` — skip verification entirely
- `keydefault` — verify only if the key's `access_policy` is not `None`

## Security boundaries

- **Private key isolation.** On macOS, private keys live in the Secure Enclave and are never exportable. On Windows, private keys are held in the TPM 2.0. On Linux, the software backend stores keys encrypted on disk in `~/.sshenc/keys/` — these ARE extractable and not hardware-protected.
- **Sole crypto-store toucher.** `sshenc-agent` is the only process that calls into the platform crypto FFI (`SecItem*` / `SecKey*` on macOS, CNG on Windows, `keyutils`-family on Linux). The CLI binaries construct `AgentProxyBackend`, which performs `KeyBackend`-trait reads by reading disk files directly and forwards every write through the agent. On unsigned macOS builds this prevents the legacy keychain's cross-binary ACL prompt from firing between the CLI (as creator) and the agent (as reader); on signed builds it keeps the Always-Allow surface reduced to a single binary.
- **Agent socket permissions.** Unix sockets are created with mode `0600`, restricting access to the owning user. On Windows, a per-user named pipe is used; its DACL grants access only to the creating user and SYSTEM.
- **Trusted binary discovery.** `enclaveapp_core::bin_discovery` searches a fixed set of install directories (current exe sibling, `~/.local/bin`, `~/.cargo/bin`, `/opt/homebrew/bin`, `/usr/local/bin`, `/usr/bin` on Unix; `%LOCALAPPDATA%\sshenc\bin`, `%ProgramFiles%\sshenc` etc. on Windows, parameterized by `app_name`). It never consults `$PATH`, preventing binary-planting attacks. Every consumer of the enclaveapp helpers (sshenc today; awsenc etc. next) shares the same search logic.
- **Atomic file writes.** SSH config modifications and config saves use `atomic_write` (write to temp file, then rename) to prevent partial writes from corrupting state.
- **Key material backup.** `backup.rs` provides transactional backup/rollback for key file overwrites. Existing `.pub` and private key files are renamed to `.bak` before overwrite and restored on failure. Backup files are cleaned up on success to avoid stale key material persisting on disk.
- **Human-time crypto-op detection.** `enclaveapp-apple`'s Swift bridge wraps every Apple FFI call with a shippable warning that logs to stderr when an op exceeds 1000 ms (the threshold below which a macOS prompt sheet almost never completes). If a cross-binary or userPresence prompt ever slips back in, the warning line names the exact `SecItem*` / `SecKey*` call and the elapsed milliseconds, so regressions self-identify in CI and field use. Opt into per-call detail with `ENCLAVEAPP_KEYCHAIN_TRACE=1`; override the threshold with `ENCLAVEAPP_SLOW_OP_THRESHOLD_MS`.
