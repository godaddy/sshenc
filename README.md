# sshenc

macOS Secure Enclave-backed SSH key management.

`sshenc` lets you generate SSH keys inside the macOS Secure Enclave and use them
with standard OpenSSH. Private key material never leaves the hardware. It also
serves your existing `~/.ssh` keys — including encrypted ones — so you can
switch without breaking anything.

## How it works

sshenc provides a PKCS#11 dynamic library that OpenSSH loads on demand via
`~/.ssh/config`. The first time SSH needs a key, the library starts the
sshenc-agent in the background. The agent loads your Secure Enclave keys and
legacy SSH keys (prompting for passphrases as needed), then stays running so
you only enter each passphrase once.

```
SSH  →  loads libsshenc_pkcs11.dylib  →  connects to sshenc-agent (starts it if needed)
                                                ↓
                                         agent holds all keys:
                                         • Secure Enclave keys (hardware-bound)
                                         • Legacy ~/.ssh keys (decrypted once)
                                                ↓
                                         persists across SSH sessions
```

After installing, run `sshenc install` and SSH works exactly as before — your
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

To uninstall the binaries:

```sh
make uninstall
```

## Quick start

### 1. Configure SSH

```sh
sshenc install
```

This adds a `PKCS11Provider` line to `~/.ssh/config` for all hosts. Your
existing SSH keys continue to work — the agent loads them automatically.

### 2. Verify it works

```sh
ssh -T git@github.com
```

If you had working SSH keys before, they still work. The agent starts
automatically on first use and prompts for any encrypted key passphrases.

### 3. Generate a Secure Enclave key

```sh
sshenc keygen --label github
```

This creates a hardware-bound P-256 key in the Secure Enclave and writes the
public key to `~/.ssh/github.pub`. The comment defaults to `user@hostname`
(like `ssh-keygen`). Use `-C` to override it.

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
sshenc keygen --label NAME [-C COMMENT] [--write-pub PATH] [--no-pub-file] [--require-user-presence]
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

### SSH agent

The agent runs as a background daemon by default. It's started automatically
by the PKCS#11 provider, but you can also run it manually:

```sh
sshenc agent                            # daemonize (default)
sshenc agent --foreground               # stay in terminal
sshenc agent --socket /tmp/my.sock      # custom socket path
sshenc agent --labels key1,key2         # only expose specific SE keys
sshenc agent --debug                    # verbose logging
```

The agent serves both Secure Enclave keys and legacy keys from `~/.ssh/`.
Encrypted keys are decrypted on startup with a terminal passphrase prompt.
Passphrases are only asked once per agent lifetime.

### Shell completions

```sh
sshenc completions bash > /usr/local/etc/bash_completion.d/sshenc
sshenc completions zsh > /usr/local/share/zsh/site-functions/_sshenc
sshenc completions fish > ~/.config/fish/completions/sshenc.fish
```

### Convenience keygen

```sh
sshenc-keygen --label NAME [-C COMMENT] [--write-pub PATH] [--no-pub-file] [--require-user-presence]
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
- Encrypted keys prompt for their passphrase on the terminal at agent startup

Passphrases are entered once when the agent starts and held in memory for the
agent's lifetime. Subsequent SSH sessions reuse the already-running agent
without re-prompting.

After `sshenc install`, your existing SSH setup keeps working exactly as before.
You can then gradually create Secure Enclave keys for hosts you want to protect.

## Security model

- Private keys are generated inside and never leave the Secure Enclave
- Keys are ECDSA P-256 (the only curve the Secure Enclave supports)
- Keys are device-bound and non-exportable — they cannot be backed up or cloned
- Optional per-key user-presence requirement (Touch ID / password) for signing
- Agent socket is restricted to owner-only permissions (0600)
- Keys are namespaced in the Keychain (`com.sshenc.key.*`) to avoid collisions
- Agent protocol between the PKCS#11 dylib and agent uses the same Unix socket
  security model as `ssh-agent` (file permissions, not encryption)

See [THREAT_MODEL.md](THREAT_MODEL.md) for detailed threat analysis.

## Limitations

- **macOS only.** Requires Apple Silicon or T2 Mac (Secure Enclave hardware).
- **P-256 only.** Ed25519 and RSA keys cannot be created in the Secure Enclave.
  Existing Ed25519/RSA keys from `~/.ssh/` still work through legacy key support.
- **Non-exportable.** Secure Enclave keys cannot be backed up, migrated, or
  shared between devices. Losing the device means losing those keys.

## Project structure

| Crate | Purpose |
|---|---|
| `sshenc-core` | Domain models, SSH public key encoding, fingerprints, config |
| `sshenc-se` | Secure Enclave / Keychain integration via Security.framework |
| `sshenc-agent-proto` | SSH agent protocol types and wire encoding |
| `sshenc-agent` | SSH agent daemon (serves SE + legacy keys, auto-started by dylib) |
| `sshenc-cli` | Main `sshenc` binary with all subcommands |
| `sshenc-keygen-cli` | Standalone `sshenc-keygen` binary |
| `sshenc-pkcs11` | PKCS#11 dylib — thin agent client loaded by OpenSSH on demand |
| `sshenc-ffi-apple` | Apple Security.framework bridge layer |
| `sshenc-test-support` | Mock key backend for testing without hardware |

See [ARCHITECTURE.md](ARCHITECTURE.md) for design details.

## Development

```sh
cargo build --workspace            # build everything
cargo test --workspace             # run 93 tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
make install                       # build release + install
```

See [DEVELOPMENT.md](DEVELOPMENT.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT License. See [LICENSE](LICENSE).
