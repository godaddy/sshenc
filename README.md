# sshenc

macOS Secure Enclave-backed SSH key management.

`sshenc` generates SSH keys inside the macOS Secure Enclave and serves them
via a standard SSH agent. Private key material never leaves the hardware.
Your existing `~/.ssh` keys continue to work — SSH tries them as a fallback
after the Secure Enclave keys.

## How it works

`sshenc install` adds an `IdentityAgent` entry to `~/.ssh/config` that points
SSH at the sshenc agent. The agent serves Secure Enclave keys for authentication.
Your existing `~/.ssh` keys are unaffected — SSH handles them natively as
a fallback if no SE key matches.

Keys are stored in `~/.sshenc/keys/` as CryptoKit data representations — opaque
handles that reference the Secure Enclave key. The private key material is
inside the SE hardware and cannot be extracted, backed up, or cloned.

No code signing certificates or Apple Developer accounts are required.
Homebrew downloads pre-built binaries that are compiled and linker-signed on
GitHub Actions. When building from source, `cargo build` produces binaries
with an ad-hoc linker signature that macOS accepts for CryptoKit Secure Enclave
access — no manual signing step needed.

## Installation

### Homebrew

```sh
brew tap jgowdy/sshenc https://github.com/jgowdy/sshenc
brew install sshenc
```

Pre-built binaries for Apple Silicon and Intel. No Rust toolchain needed.

### From source

Requires Rust 1.75+, Xcode command line tools, and macOS on Apple Silicon or
T2 Mac.

```sh
git clone https://github.com/jgowdy/sshenc.git
cd sshenc
make install
```

Installs to `/usr/local`. Override with `make install PREFIX=/opt/sshenc`.

The build compiles a small Swift static library (CryptoKit bridge) and links
it into the Rust binaries. The resulting binaries work immediately — macOS
trusts the linker-signed ad-hoc signature for CryptoKit Secure Enclave access.

## Quick start

### 1. Set up SSH

```sh
sshenc install
```

Configures SSH to use the sshenc agent and starts it as a background daemon.
Your existing SSH keys continue to work as fallback.

### 2. Generate a Secure Enclave key

```sh
sshenc keygen --label github
```

Creates a hardware-bound P-256 key and writes the public key to
`~/.ssh/github.pub`. The comment defaults to `user@hostname`.

### 3. Add to GitHub / GitLab

```sh
sshenc export-pub github | pbcopy
```

Paste into your account's SSH key settings.

### 4. Test

```sh
ssh -T git@github.com
```

## Commands

### Key management

```sh
sshenc keygen --label NAME [-C COMMENT] [--write-pub PATH] [--no-pub-file] [--require-user-presence]
sshenc list [--json]
sshenc inspect NAME [--json] [--show-pub]
sshenc export-pub NAME [-o FILE] [--fingerprint] [--json]
sshenc delete NAME [--delete-pub] [-y]
```

`--require-user-presence` makes the key require Touch ID or password for each
signing operation.

### SSH integration

```sh
sshenc install              # configure SSH + start agent daemon
sshenc uninstall            # revert SSH config + stop agent
```

### Key-specific SSH sessions

Use a specific Secure Enclave key for a single SSH connection:

```sh
sshenc ssh --label jgowdy-godaddy -T git@github.com
```

Works with `GIT_SSH_COMMAND` for per-repo identity selection:

```sh
GIT_SSH_COMMAND="sshenc ssh --label jgowdy-godaddy --" git push
```

Or set it permanently on a repo:

```sh
git config core.sshCommand "sshenc ssh --label jgowdy-godaddy --"
```

### SSH agent

The agent runs as a background daemon and is started automatically by
`sshenc install`. You can also run it manually:

```sh
sshenc agent                            # daemonize (default)
sshenc agent --foreground               # stay in terminal
sshenc agent --socket /tmp/my.sock      # custom socket path
sshenc agent --labels key1,key2         # only expose specific keys
sshenc agent --debug                    # verbose logging
```

The agent serves only Secure Enclave keys. Legacy `~/.ssh` keys are handled
by OpenSSH directly and don't go through the agent.

### Per-host config snippets

```sh
sshenc openssh print-config --label github --host github.com
```

Generates an SSH config block for a specific host/key combination.

### Shell completions

```sh
sshenc completions bash > /usr/local/etc/bash_completion.d/sshenc
sshenc completions zsh > /usr/local/share/zsh/site-functions/_sshenc
sshenc completions fish > ~/.config/fish/completions/sshenc.fish
```

### Configuration

```sh
sshenc config init    # create default config file
sshenc config path    # show config file location
sshenc config show    # print current config
```

Config file: `~/Library/Application Support/sshenc/config.toml`

## Multiple GitHub accounts

If you have multiple GitHub accounts (e.g., personal and work), create a key
for each:

```sh
sshenc keygen --label github-personal
sshenc keygen --label github-work
```

Add each public key to the corresponding GitHub account. Then use `sshenc ssh`
to select which identity to use:

```sh
# Personal repos
GIT_SSH_COMMAND="sshenc ssh --label github-personal --" git clone git@github.com:you/personal-repo.git

# Work repos
GIT_SSH_COMMAND="sshenc ssh --label github-work --" git clone git@github.com:org/work-repo.git
```

Set it per-repo so you don't have to think about it:

```sh
cd work-repo
git config core.sshCommand "sshenc ssh --label github-work --"
```

## How keys are stored

Secure Enclave keys are stored in `~/.sshenc/keys/`:

```
~/.sshenc/keys/
  github-personal.key      # CryptoKit data representation (SE key handle)
  github-personal.pub      # raw EC point bytes (cached)
  github-personal.ssh.pub  # SSH-formatted public key (for IdentityFile)
```

The `.key` file is an opaque handle — it references the SE key but contains
no secret material. Copying it to another device won't work (device-bound).
The directory is restricted to owner-only permissions (0700), and `.key` files
are 0600.

## Security model

- Private keys are generated inside and never leave the Secure Enclave
- Keys are ECDSA P-256 (the only curve the Secure Enclave supports)
- Keys are device-bound and non-exportable — cannot be backed up or cloned
- Optional per-key user-presence requirement (Touch ID / password) for signing
- Agent socket at `~/.sshenc/agent.sock` restricted to owner-only (0600)
- Key files in `~/.sshenc/keys/` restricted to owner-only (0700/0600)
- No Keychain entitlements required — uses CryptoKit which works with
  standard linker-signed binaries

See [THREAT_MODEL.md](THREAT_MODEL.md) for detailed threat analysis.

## Limitations

- **macOS only.** Requires Apple Silicon or T2 Mac (Secure Enclave hardware).
- **P-256 only.** Ed25519 and RSA keys cannot be created in the Secure Enclave.
  Existing Ed25519/RSA keys from `~/.ssh/` still work — SSH handles them
  natively as a fallback.
- **Non-exportable.** Secure Enclave keys cannot be backed up, migrated, or
  shared between devices. Losing the device means losing those keys.
- **Agent required.** The sshenc agent must be running for SE key authentication.
  `sshenc install` starts it automatically and it persists across SSH sessions.

## Architecture

The project uses CryptoKit (via a Swift static library) for Secure Enclave
operations, avoiding the keychain-access-groups entitlement that
Security.framework requires. This means no Apple Developer certificate is
needed — standard `cargo build` output works.

| Crate | Purpose |
|---|---|
| `sshenc-core` | Domain models, SSH public key encoding, fingerprints, config |
| `sshenc-se` | Secure Enclave backend (KeyBackend trait + CryptoKit implementation) |
| `sshenc-ffi-apple` | Swift/CryptoKit bridge: key generation, signing, persistence |
| `sshenc-agent-proto` | SSH agent protocol types and wire encoding |
| `sshenc-agent` | SSH agent daemon serving Secure Enclave keys |
| `sshenc-cli` | Main `sshenc` binary with all subcommands |
| `sshenc-keygen-cli` | Standalone `sshenc-keygen` binary |
| `sshenc-pkcs11` | PKCS#11 provider (key discovery; signing not supported due to CryptoKit hashing) |
| `sshenc-test-support` | Mock key backend for testing without hardware |

See [ARCHITECTURE.md](ARCHITECTURE.md) for design details.

## Development

```sh
cargo build --workspace            # build everything (includes Swift bridge)
cargo test --workspace             # run 93 tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
make install                       # build release + install
```

Requires Xcode command line tools (for `swiftc`).

See [DEVELOPMENT.md](DEVELOPMENT.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT License. See [LICENSE](LICENSE).
