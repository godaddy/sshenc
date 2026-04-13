# sshenc Design Document

## Overview

sshenc provides Secure Enclave / TPM-backed SSH key management. It generates
hardware-bound ECDSA P-256 keys and serves them via a standard SSH agent.
Private key material never leaves the hardware security module.

## Architecture

Rust workspace with 9 crates under `crates/`:

| Crate | Purpose |
|---|---|
| `sshenc-core` | Domain models, SSH public key encoding, fingerprints, config |
| `sshenc-se` | Hardware key backend via `KeyBackend` trait (macOS, Windows, Linux) |
| `sshenc-agent-proto` | SSH agent protocol: message parsing, DER-to-SSH signature conversion |
| `sshenc-agent` | Async SSH agent daemon (tokio), Unix socket / named pipe server |
| `sshenc-cli` | Main CLI (`sshenc`): keygen, list, inspect, delete, export-pub, agent, install |
| `sshenc-keygen-cli` | Standalone `sshenc-keygen` binary |
| `sshenc-gitenc` | `gitenc` binary for git+SSH with per-key identity selection and commit signing |
| `sshenc-pkcs11` | PKCS#11 provider (cdylib) for agent auto-start via SSH's PKCS11Provider |
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
| Linux (no TPM) | `enclaveapp-software` | Software P-256 (fallback) |
| WSL | `enclaveapp-wsl` + bridge | Windows TPM via socat/npiperelay |

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

`sshenc install` configures `~/.ssh/config` with `IdentityAgent` and
`PKCS11Provider` directives.

### Git Integration

`gitenc` wraps git commands with per-key SSH identity selection. It also
configures SSH-based commit signing (`gpg.format = ssh`) so commits are
signed with the hardware-bound key.

## Security Model

- Private keys never leave the hardware security module
- Keys are ECDSA P-256 (the only curve with hardware support on all platforms)
- Keys are device-bound and non-exportable
- Optional per-key Touch ID / Windows Hello / password for each signing operation
- Agent socket restricted to owner-only permissions (0600)
- No Keychain entitlements required on macOS (CryptoKit, not Security.framework)

See [THREAT_MODEL.md](THREAT_MODEL.md) for detailed analysis.

## Platform Support

| Platform | Status | Notes |
|---|---|---|
| macOS (Apple Silicon / T2) | Full support | CryptoKit Secure Enclave |
| Windows (native) | Full support | TPM 2.0 via CNG, named pipe agent |
| Windows (Git Bash) | Full support | GIT_SSH_COMMAND bypass for MINGW SSH |
| WSL | Full support | socat + npiperelay bridge to Windows agent |
| Linux (with TPM) | Full support | TPM 2.0 via tss-esapi |
| Linux (no TPM) | Software fallback | P-256 keys on disk, one-time warning |

## Binaries

1. `sshenc` -- umbrella CLI with all subcommands
2. `sshenc-keygen` -- convenience keygen binary
3. `sshenc-agent` -- ssh-agent-compatible daemon
4. `gitenc` -- git wrapper with per-key identity and commit signing
5. `libsshenc_pkcs11.dylib` -- PKCS#11 provider (agent auto-start)
