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
sshenc-cli / gitenc / sshenc-agent
            |
            v
        sshenc-se
            |
            v
  enclaveapp-app-storage + enclaveapp-core
            |
   +--------+---------+---------+
   |                  |         |
   v                  v         v
macOS SE         Windows TPM   Linux TPM / software fallback
```

`sshenc-se` is the key boundary. It uses `enclaveapp-app-storage` for platform detection and backend initialization, then layers SSH-specific behavior on top:

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

## Data flow: key generation

```
CLI validates label (KeyLabel::new)
  → KeyBackend::generate()
    → SshencBackend checks for duplicates
      → EnclaveKeyManager::generate() via AppSigningBackend
        → platform backend creates key (SE / TPM / software)
        → returns SEC1 public key bytes
      → sshenc-se saves app_specific metadata (.meta file)
      → optional: writes OpenSSH .pub file to pub_dir
    → returns KeyInfo with fingerprints
  → CLI prints fingerprint and key info
```

## Data flow: signing (agent)

```
SSH client connects to agent socket (Unix) or named pipe (Windows)
  → agent reads framed message (u32 length + payload)
    → sshenc-agent-proto parses SSH agent protocol message
    → RequestIdentities: lists keys via KeyBackend::list(),
        filters by allowed_labels, returns wire-format blobs
    → SignRequest: matches key_blob against stored keys
        → checks allowed_labels filter
        → evaluates PromptPolicy vs key's AccessPolicy
        → calls KeyBackend::sign(label, data)
          → platform backend signs:
              macOS SE: triggers Touch ID/password if access_policy requires it
              Windows TPM: triggers Windows Hello
              Linux software: signs directly (no hardware enforcement)
        → sshenc-agent-proto converts DER signature to SSH format
            (DER → extract r,s integers → pad to 32 bytes → SSH mpint encoding)
        → returns framed SignResponse
```

## Data flow: git commit signing

```
git calls: sshenc -Y sign -n git -f <pubkey_path> <data_file>
  → CLI intercepts -Y sign before clap parsing
    → loads SshencBackend
    → resolves signing label by matching <pubkey_path> content to stored keys
    → evaluates PromptPolicy (on non-macOS, may prompt on stderr)
    → hashes file data with SHA-256
    → constructs SSHSIG signed-data blob (magic + namespace + hash)
    → calls KeyBackend::sign(label, signed_data)
    → builds SSH signature envelope (SSHSIG v1 + pubkey + namespace + sig)
    → writes PEM-armored signature to <data_file>.sig
```

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
- **Agent socket permissions.** Unix sockets are created with mode `0600`, restricting access to the owning user. On Windows, a per-user named pipe is used, with an additional AF_UNIX socket for Git Bash/MINGW compatibility.
- **Trusted binary discovery.** `bin_discovery.rs` searches only a fixed set of trusted directories (current exe sibling, `~/.local/bin`, `~/.cargo/bin`, `/opt/homebrew/bin`, `/usr/local/bin`, `/usr/bin` on Unix; `%LOCALAPPDATA%\sshenc\bin`, `%ProgramFiles%\sshenc` on Windows). It never searches `$PATH`, preventing binary planting attacks.
- **Atomic file writes.** SSH config modifications and config saves use `atomic_write` (write to temp file, then rename) to prevent partial writes from corrupting state.
- **Key material backup.** `backup.rs` provides transactional backup/rollback for key file overwrites. Existing `.pub` and private key files are renamed to `.bak` before overwrite and restored on failure. Backup files are cleaned up on success to avoid stale key material persisting on disk.
