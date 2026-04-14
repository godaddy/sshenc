# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in sshenc, report it privately.

**Do not open a public GitHub issue for security vulnerabilities.**

Email: Report via GitHub's private vulnerability reporting feature on the
[sshenc repository](https://github.com/godaddy/sshenc/security/advisories/new),
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
| 0.6.x | Yes |

Only the latest release receives security fixes.

## Security Model Summary

sshenc relies on hardware security modules for private key protection:

- **Private keys never leave the hardware.** Secure Enclave (macOS),
  TPM 2.0 (Windows/Linux) keys are non-exportable. The software fallback
  on Linux stores keys on disk with restrictive permissions but does not
  provide hardware isolation.
- **Keys are device-bound.** They cannot be backed up, cloned, or
  transferred to another machine.
- **User-presence is optional per key.** Keys can require Touch ID,
  Windows Hello, or password for each signing operation. This is
  configured at key generation time.
- **Agent socket is restricted.** Permissions are set to 0600 (owner-only).
- **Key namespace isolation.** sshenc only operates on keys it created,
  identified by label prefix and stored in `~/.sshenc/keys/`.

### What sshenc does NOT protect against

- Root compromise (root can bypass socket permissions and access hardware APIs)
- Kernel exploits on any platform
- Physical attacks on the Secure Enclave or TPM hardware
- Signing abuse by processes running as the same user (without user-presence)
- Software fallback key theft on Linux without TPM

See [THREAT_MODEL.md](THREAT_MODEL.md) for a detailed analysis.

## Dependencies

sshenc uses a conservative set of dependencies. Key external crates:

- `enclaveapp-*`: Shared hardware-backed key management (libenclaveapp)
- `clap`: CLI argument parsing
- `tokio`: Async runtime for the agent daemon
- `sha2`, `md-5`: Hash functions for fingerprints
- `base64`, `byteorder`: Encoding primitives

All dependencies are published on crates.io and are widely used in the
Rust ecosystem.
