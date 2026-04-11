# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in sshenc, report it privately.

**Do not open a public GitHub issue for security vulnerabilities.**

Email: Report via GitHub's private vulnerability reporting feature on the
[sshenc repository](https://github.com/jgowdy/sshenc/security/advisories/new),
or contact the maintainer directly.

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

You will receive an acknowledgment within 72 hours. A fix will be developed
and released as quickly as possible, with credit given to the reporter
(unless anonymity is requested).

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |

Only the latest release receives security fixes.

## Security Model Summary

sshenc relies on the macOS Secure Enclave for private key protection:

- **Private keys never leave the Secure Enclave.** There is no export path.
  `SecKeyCopyExternalRepresentation` is called only on the public key.
- **Keys are device-bound.** They are created with
  `AccessibleWhenPasscodeSetThisDeviceOnly` and are not included in backups
  or iCloud Keychain sync.
- **User-presence is optional per key.** Keys can require Touch ID or
  password for each signing operation. This is configured at key generation
  time and cannot be changed afterward.
- **Agent socket is restricted.** Permissions are set to 0600 (owner-only).
- **Key namespace isolation.** sshenc only operates on Keychain items tagged
  with `com.sshenc.key.*` and labeled with the `sshenc:` prefix.

### What sshenc does NOT protect against

- Root compromise (root can bypass socket permissions and Keychain ACLs)
- macOS kernel exploits
- Physical attacks on the Secure Enclave hardware
- Signing abuse by processes running as the same user (without user-presence)

See [THREAT_MODEL.md](THREAT_MODEL.md) for a detailed analysis.

## Dependencies

sshenc uses a conservative set of dependencies. Key external crates:

- `security-framework` / `security-framework-sys`: Rust bindings for Apple
  Security.framework
- `core-foundation` / `core-foundation-sys`: Rust bindings for Apple
  Core Foundation
- `clap`: CLI argument parsing
- `tokio`: Async runtime for the agent daemon
- `sha2`, `md-5`: Hash functions for fingerprints
- `base64`, `byteorder`: Encoding primitives

All dependencies are published on crates.io and are widely used in the
Rust ecosystem.
