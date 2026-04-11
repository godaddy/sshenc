# sshenc

macOS Secure Enclave-backed SSH key management.

`sshenc` lets you generate SSH keys inside the macOS Secure Enclave and use them
with standard OpenSSH. Private key material never leaves the hardware. It also
serves your existing `~/.ssh` keys, so you can switch without breaking anything.

## How it works

sshenc provides a PKCS#11 dynamic library (`libsshenc_pkcs11.dylib`) that
OpenSSH loads on demand. When SSH needs to authenticate, it calls into the
library, which signs using the Secure Enclave or your existing private keys.
No running daemon or agent is required.

After installing, run `sshenc install` and SSH works exactly as before -- your
existing keys keep working, and any new Secure Enclave keys you create are
available immediately.

## Installation

### Homebrew (recommended)

```sh
brew tap jgowdy/sshenc https://github.com/jgowdy/sshenc
brew install sshenc
```

### From source

Requires Rust 1.75+ and macOS (Apple Silicon or T2 Mac).

```sh
git clone https://github.com/jgowdy/sshenc.git
cd sshenc
make install
```

This installs to `/usr/local/bin` and `/usr/local/lib`. To change the prefix:

```sh
make install PREFIX=/opt/sshenc
```

To uninstall:

```sh
make uninstall
```

## Quick start

### 1. Configure SSH

```sh
sshenc install
```

This adds a single line to `~/.ssh/config` that tells SSH to use the sshenc
PKCS#11 provider for all hosts. Your existing SSH keys continue to work.

### 2. Verify it works

```sh
ssh -T git@github.com
```

If you had working SSH keys before, they still work. Nothing changes for
existing connections.

### 3. Generate a Secure Enclave key

```sh
sshenc keygen --label github -C "you@host" --write-pub ~/.ssh/github.pub
```

This creates a hardware-bound P-256 key in the Secure Enclave and writes the
public key to `~/.ssh/github.pub`.

### 4. Add the public key to GitHub/GitLab

```sh
sshenc export-pub github | pbcopy
```

Paste into your GitHub/GitLab SSH keys settings.

### 5. Test

```sh
ssh -T git@github.com
git clone git@github.com:you/repo.git
```

## Commands

### Key management

```sh
sshenc keygen --label NAME [-C COMMENT] [--write-pub PATH] [--require-user-presence]
sshenc list [--json]
sshenc inspect NAME [--json] [--show-pub]
sshenc export-pub NAME [-o FILE] [--fingerprint] [--json]
sshenc delete NAME [--delete-pub] [-y]
```

`--require-user-presence` makes the key require Touch ID or password for every
signing operation. Without it, the key can be used by any process running as
your user.

### SSH configuration

```sh
sshenc install        # add PKCS11Provider to ~/.ssh/config for all hosts
sshenc uninstall      # remove it
```

`sshenc install` is idempotent. Running it twice is safe.

### Per-host config snippets

```sh
sshenc openssh print-config --label github --host github.com
```

Generates a host-specific SSH config block you can paste into `~/.ssh/config`
if you want fine-grained control.

### SSH agent (alternative to PKCS#11)

The PKCS#11 provider is the recommended integration, but sshenc also includes
a standalone SSH agent:

```sh
sshenc agent [--socket PATH] [--labels key1,key2] [--debug]
```

The agent serves both Secure Enclave keys and legacy keys from `~/.ssh/`.

### Convenience keygen

```sh
sshenc-keygen --label NAME [-C COMMENT] [--auto-pub] [--require-user-presence]
```

Same as `sshenc keygen` but as a standalone binary.

### Configuration

```sh
sshenc config init    # create default config file
sshenc config path    # show config file location
sshenc config show    # print current config
```

Config file location: `~/Library/Application Support/sshenc/config.toml`

## Legacy key support

sshenc automatically discovers and serves existing SSH keys from `~/.ssh/`:

- Well-known key files: `id_rsa`, `id_ed25519`, `id_ecdsa`, `id_dsa`
- Any file that has a corresponding `.pub` file (custom-named keys)

Encrypted keys are skipped. This applies to both the PKCS#11 provider and the
SSH agent.

After `sshenc install`, your existing SSH setup keeps working exactly as before.
You can then gradually create Secure Enclave keys for hosts you want to protect.

## Security model

- Private keys are generated inside and never leave the Secure Enclave
- Keys are ECDSA P-256 (the only curve the Secure Enclave supports)
- Keys are device-bound and non-exportable -- they cannot be backed up or cloned
- Optional per-key user-presence requirement (Touch ID / password) for signing
- The PKCS#11 provider runs in-process with SSH -- no daemon, no socket to abuse
- Keys are namespaced in the Keychain (`com.sshenc.key.*`) to avoid collisions

See [THREAT_MODEL.md](THREAT_MODEL.md) for detailed threat analysis.

## Limitations

- **macOS only.** Requires Apple Silicon or T2 Mac (Secure Enclave hardware).
- **P-256 only.** Ed25519 and RSA keys cannot be created in the Secure Enclave.
  Existing Ed25519/RSA keys from `~/.ssh/` still work through legacy key support.
- **Non-exportable.** Secure Enclave keys cannot be backed up, migrated, or
  shared between devices. Losing the device means losing those keys.
- **Encrypted legacy keys are skipped.** Keys protected with a passphrase in
  `~/.ssh/` are not loaded. Use `ssh-add` with the system agent for those, or
  remove the passphrase.

## Project structure

| Crate | Purpose |
|---|---|
| `sshenc-core` | Domain models, SSH public key encoding, fingerprints, config |
| `sshenc-se` | Secure Enclave / Keychain integration via Security.framework |
| `sshenc-agent-proto` | SSH agent protocol types and wire encoding |
| `sshenc-agent` | SSH agent daemon (alternative to PKCS#11 mode) |
| `sshenc-cli` | Main `sshenc` binary with all subcommands |
| `sshenc-keygen-cli` | Standalone `sshenc-keygen` binary |
| `sshenc-pkcs11` | PKCS#11 provider loaded by OpenSSH on demand |
| `sshenc-ffi-apple` | Apple Security.framework bridge layer |
| `sshenc-test-support` | Mock key backend for testing without hardware |

See [ARCHITECTURE.md](ARCHITECTURE.md) for design details.

## Development

```sh
cargo build --workspace            # build everything
cargo test --workspace             # run tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

See [DEVELOPMENT.md](DEVELOPMENT.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT License. See [LICENSE](LICENSE).
