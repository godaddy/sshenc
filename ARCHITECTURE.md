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
