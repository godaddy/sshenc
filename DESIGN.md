# sshenc Design Document

## Overview

sshenc provides Secure Enclave / TPM-backed SSH key management. It generates
hardware-bound ECDSA P-256 keys and serves them via a standard SSH agent.
Private key material never leaves the hardware security module.

## Architecture

Rust workspace with 10 crates under `crates/`:

| Crate | Purpose |
|---|---|
| `sshenc-core` | Domain models, SSH public key encoding, fingerprints, config, transactional backup/rollback |
| `sshenc-se` | `KeyBackend` trait and two impls: `SshencBackend` (the agent's direct backend) and `AgentProxyBackend` (the CLI's agent-routing backend) |
| `sshenc-agent-proto` | SSH agent protocol + sshenc extensions, plus the client helpers that CLIs use to reach the agent (Unix socket and Windows named pipe) |
| `sshenc-agent` | Async SSH agent daemon (tokio), Unix socket / named pipe server |
| `sshenc-cli` | Main CLI (`sshenc`): keygen, list, inspect, delete, export-pub, agent, config, openssh, install, uninstall, identity, default, ssh, completions |
| `sshenc-keygen-cli` | Standalone `sshenc-keygen` binary |
| `sshenc-gitenc` | `gitenc` binary for git+SSH with per-key identity selection and commit signing |
| `sshenc-pkcs11` | PKCS#11 provider (cdylib) for agent auto-start via SSH's PKCS11Provider |
| `sshenc-tpm-bridge` | Windows-side JSON-RPC bridge that serves TPM operations to the WSL agent |
| `sshenc-test-support` | Mock key backend for testing without hardware |

### Platform Backends

All platform-specific crypto is delegated to
[libenclaveapp](https://github.com/godaddy/libenclaveapp). sshenc depends on
the `signing` feature of each platform crate:

| Platform | Backend | Hardware |
|---|---|---|
| macOS | `enclaveapp-apple` | Secure Enclave (CryptoKit) |
| Windows | `enclaveapp-windows` | TPM 2.0 (CNG) |
| Linux | `enclaveapp-linux-tpm` | TPM 2.0 (tss-esapi) |
| Linux (no TPM) | `enclaveapp-software` + `enclaveapp-keyring` | Software P-256 wrapped by an OS keyring key |
| WSL | `enclaveapp-wsl` + `sshenc-tpm-bridge` | Windows TPM via JSON-RPC over stdio |

The `KeyBackend` trait in `sshenc-se` wraps libenclaveapp's `EnclaveSigner`
into sshenc's domain model. Platform selection happens at runtime based on
OS detection and hardware availability.

### Key Storage

Keys are stored as opaque references alongside cached public keys:

```
~/.sshenc/keys/
  <label>.handle     # platform key reference (CryptoKit data rep, or TPM blob)
  <label>.pub        # cached SEC1 public key bytes
  <label>.ssh.pub    # SSH-formatted public key (for identity selection)
  <label>.meta       # metadata (label, comment, auth policy, timestamp)
```

The `.handle` file is useless on another device -- the actual key is bound
to the local hardware security module.

### SSH Agent

The agent listens on a Unix socket (macOS/Linux) or Windows named pipe. It
implements the SSH agent protocol for identity enumeration and signing. The
PKCS#11 provider acts as a lightweight launcher -- if SSH loads it and the
agent isn't running, it starts the agent automatically.

On Windows the named pipe is created with an explicit DACL
(`D:P(A;;GA;;;OW)(A;;GA;;;SY)`) via
`ConvertStringSecurityDescriptorToSecurityDescriptorW` so that only the pipe
owner and SYSTEM can open it. On Unix the socket directory is restricted to
`0700` and the socket to `0600`.

`sshenc install` configures `~/.ssh/config` with `IdentityAgent` and
`PKCS11Provider` directives. `sshenc uninstall` removes them.

### WSL Bridge

On WSL, the agent cannot talk to the Windows TPM directly. Instead, the Linux
side spawns `sshenc-tpm-bridge.exe` (installed on the Windows host) and
communicates with it over stdin/stdout using the JSON-RPC protocol defined in
`enclaveapp-tpm-bridge`. The bridge binary is discovered via a fixed allowlist
of installation directories (no `$PATH` lookup).

### Git Integration

`gitenc` wraps git commands with per-key SSH identity selection. It also
configures SSH-based commit signing (`gpg.format = ssh`) so commits are
signed with the hardware-bound key.

## Security Model

- Private keys never leave the hardware security module
- Keys are ECDSA P-256 (the only curve with hardware support on all platforms)
- Keys are device-bound and non-exportable
- Optional per-key Touch ID / Windows Hello / password for each signing operation
- Agent socket restricted to owner-only permissions (0600 on Unix; per-user DACL on Windows named pipe)
- **`sshenc-agent` is the sole process that calls into the platform crypto FFI.** The CLI binaries (`sshenc`, `sshenc-keygen`, `gitenc`) construct `AgentProxyBackend`, which reads `.pub` / `.meta` from disk directly for read-side ops and forwards every write-side op (`generate`, `sign`, `delete`, `rename`) to the agent over its local IPC endpoint (Unix socket on macOS/Linux/WSLv2, Windows named pipe for PowerShell / cmd.exe / Git Bash). This keeps the CLI binary's code signature off every `SecItem*` / `SecKey*` / CNG / keyring call, which on unsigned macOS builds eliminates the legacy-keychain cross-binary approval prompt.
- No Keychain entitlements required on macOS (CryptoKit for SE keys, Security.framework `SecItem*` for wrapping keys — both accept unsigned callers via the legacy keychain path).

See [THREAT_MODEL.md](THREAT_MODEL.md) for detailed analysis.

## Platform Support

| Platform | Status | Notes |
|---|---|---|
| macOS (Apple Silicon / T2) | Full support | CryptoKit Secure Enclave |
| Windows (native) | Full support | TPM 2.0 via CNG, named pipe agent |
| Windows (Git Bash) | Full support | GIT_SSH_COMMAND bypass for MINGW SSH |
| WSL | Full support | JSON-RPC bridge (`sshenc-tpm-bridge.exe`) to Windows TPM |
| Linux (with TPM) | Full support | TPM 2.0 via tss-esapi |
| Linux (no TPM) | Software fallback | P-256 keys on disk, wrapped by OS keyring key via `enclaveapp-keyring` |

## Binaries

1. `sshenc` -- umbrella CLI with all subcommands
2. `sshenc-keygen` -- convenience keygen binary
3. `sshenc-agent` -- ssh-agent-compatible daemon
4. `gitenc` -- git wrapper with per-key identity and commit signing
5. `libsshenc_pkcs11.dylib` -- PKCS#11 provider (agent auto-start)
6. `sshenc-tpm-bridge` -- Windows-side JSON-RPC bridge invoked by the WSL agent
