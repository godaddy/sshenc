# sshenc

macOS Secure Enclave-backed SSH key management.

`sshenc` generates SSH keys inside the macOS Secure Enclave and serves them
via a standard SSH agent. Private key material never leaves the hardware —
it can't be exported, copied, or stolen from disk.

Your existing SSH keys in `~/.ssh` continue to work alongside Secure Enclave
keys. Nothing breaks when you install sshenc.

## Installation

### Homebrew

```sh
brew tap jgowdy/sshenc https://github.com/jgowdy/sshenc
brew install sshenc
```

Pre-built binaries for Apple Silicon and Intel. No Rust toolchain or Apple
Developer account needed.

### From source

Requires Rust 1.75+, Xcode command line tools, and macOS (Apple Silicon or
T2 Mac).

```sh
git clone https://github.com/jgowdy/sshenc.git
cd sshenc
make install
```

No code signing is required. `cargo build` produces linker-signed binaries
that macOS trusts for CryptoKit Secure Enclave access out of the box.

## Quick start

### 1. Set up

```sh
sshenc install
```

This configures SSH to use the sshenc agent and starts it in the background.
If the agent ever stops, it restarts automatically the next time you use SSH.

### 2. Create a key

```sh
sshenc keygen --label github
```

This creates a hardware-bound P-256 key in the Secure Enclave. The public
key is written to `~/.ssh/github.pub` automatically.

### 3. Add to GitHub

```sh
sshenc export-pub github | pbcopy
```

Paste into GitHub → Settings → SSH keys → New SSH key.

### 4. Done

```sh
ssh -T git@github.com
git clone git@github.com:you/repo.git
```

Everything works. SSH, git, scp, sftp — anything that reads `~/.ssh/config`
uses the sshenc agent automatically.

## Common use cases

### Single key (most people)

If you only need one Secure Enclave key, the quick start above is all you
need. After `sshenc install`, SSH picks up your SE key automatically for
all connections. Your old `~/.ssh` keys still work as fallback.

```sh
ssh user@server              # uses SE key, falls back to ~/.ssh keys
git push                     # same — just works
scp file.txt user@server:    # same
```

### Multiple keys (multiple GitHub accounts, work vs personal)

If you have separate GitHub accounts (or different keys for different
servers), create a key for each:

```sh
sshenc keygen --label github-personal
sshenc keygen --label github-work
sshenc keygen --label servers
```

Add each public key to the appropriate account (`sshenc export-pub NAME | pbcopy`).

#### Using git

Use `gitenc` to tell git which key to use:

```sh
# Clone with a specific identity
gitenc --label github-work clone git@github.com:mycompany/repo.git
gitenc --label github-personal clone git@github.com:me/my-repo.git

# Day-to-day git — set the identity per-repo once
cd mycompany-repo
git config core.sshCommand "sshenc ssh --label github-work --"

cd my-personal-repo
git config core.sshCommand "sshenc ssh --label github-personal --"

# After that, regular git commands use the right key automatically
git pull
git push
```

Without `--label`, `gitenc` uses whatever key the agent offers first:

```sh
gitenc pull    # default key, same as regular git
```

#### Using ssh directly

```sh
# Specific key
sshenc ssh --label servers user@myserver.com

# Default (agent picks)
ssh user@myserver.com
```

#### Using scp / sftp

These read `~/.ssh/config` automatically, so they just work:

```sh
scp file.txt user@server:          # uses sshenc agent
sftp user@server                   # uses sshenc agent
```

To use a specific key with scp/sftp, use the SSH config approach:

```sh
sshenc openssh print-config --label servers --host myserver.com
```

This prints a config block you can add to `~/.ssh/config`:

```
Host myserver.com
  IdentityAgent ~/.sshenc/agent.sock
  IdentityFile ~/.ssh/servers.pub
  IdentitiesOnly yes
```

## How it works

sshenc runs a background SSH agent that serves your Secure Enclave keys.
`sshenc install` adds two lines to `~/.ssh/config`:

```
Host *
    IdentityAgent ~/.sshenc/agent.sock
    PKCS11Provider /opt/homebrew/lib/libsshenc_pkcs11.dylib
```

`IdentityAgent` tells SSH to talk to the sshenc agent for key operations.
`PKCS11Provider` is a lightweight launcher — if the agent isn't running,
SSH loads this library which starts the agent automatically.

Keys are stored in `~/.sshenc/keys/` as CryptoKit data representations.
These are opaque handles that reference the Secure Enclave key — the actual
private key material is inside the SE hardware and can't be read.

```
~/.sshenc/keys/
  github.key        # SE key handle (opaque, device-bound)
  github.pub        # cached public key bytes
  github.ssh.pub    # SSH-formatted public key (for identity selection)
```

No Apple Developer certificate or code signing is required. The project
uses CryptoKit (via a Swift static library), which works with the standard
ad-hoc linker signature that `cargo build` produces.

## Commands

### Key management

```sh
sshenc keygen --label NAME      # create a new SE key (pub key → ~/.ssh/NAME.pub)
sshenc list                     # list all SE keys
sshenc list --json              # machine-readable output
sshenc inspect NAME             # detailed info for one key
sshenc export-pub NAME          # print public key to stdout
sshenc export-pub NAME | pbcopy # copy to clipboard
sshenc delete NAME              # delete a key
sshenc delete NAME --delete-pub # also remove the .pub files
```

Options for `keygen`:
- `-C "comment"` — custom comment (default: user@hostname)
- `--write-pub PATH` — write public key to a custom path
- `--no-pub-file` — don't write a .pub file at all
- `--require-user-presence` — require Touch ID / password for every sign

### SSH and git wrappers

```sh
sshenc ssh --label NAME [ssh args...]    # ssh with a specific SE key
sshenc ssh [ssh args...]                 # ssh with default agent keys
gitenc --label NAME [git args...]        # git with a specific SE key
gitenc [git args...]                     # git with default agent keys
```

### Setup

```sh
sshenc install       # configure SSH + start agent
sshenc uninstall     # revert SSH config
```

### Agent

```sh
sshenc agent                  # start as daemon (default)
sshenc agent --foreground     # stay in terminal
sshenc agent --debug          # verbose logging
```

The agent starts automatically via `sshenc install`. You rarely need to
run it manually.

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

## Security model

- Private keys are generated inside and never leave the Secure Enclave
- Keys are ECDSA P-256 — the only curve the Secure Enclave supports
- Keys are device-bound and non-exportable — cannot be backed up or cloned
- Optional per-key Touch ID / password requirement for each signing operation
- Agent socket restricted to owner-only permissions (0600)
- Key files in `~/.sshenc/keys/` restricted to owner-only (0700/0600)
- No Keychain entitlements required — uses CryptoKit, not Security.framework

See [THREAT_MODEL.md](THREAT_MODEL.md) for detailed analysis.

## Limitations

- **macOS only** — requires Apple Silicon or T2 Mac (Secure Enclave)
- **P-256 only** — Ed25519 and RSA can't be created in the SE, but existing
  keys in `~/.ssh` still work as SSH handles them natively
- **Non-exportable** — losing the device means losing the SE keys
- **Agent required** — the agent must be running for SE key auth; it starts
  automatically via `sshenc install` and auto-restarts if killed

## Development

```sh
cargo build --workspace
cargo test --workspace             # 157 tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

Requires Xcode command line tools (for `swiftc`).

See [ARCHITECTURE.md](ARCHITECTURE.md), [DEVELOPMENT.md](DEVELOPMENT.md),
and [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT License. See [LICENSE](LICENSE).
