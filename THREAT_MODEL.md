# Threat Model

This document describes the threats sshenc is designed to resist, partially
resist, or explicitly not resist.

## Threat: Malware on Host

**Scenario**: Malicious software running as the current user.

**Mitigations**:
- Private keys cannot be exported from the Secure Enclave, even by processes
  with full user-level access. Malware cannot steal the key material itself.
- With user-presence enabled keys, each signing operation requires Touch ID or
  password confirmation. Malware cannot silently sign authentication challenges.

**Residual risk**:
- Without user-presence, malware running as the same user can connect to the
  agent socket and issue signing requests. The agent cannot distinguish
  legitimate SSH clients from malicious ones.
- Malware could intercept or replace the public key shown to the user.
- Malware could substitute its own agent socket via environment manipulation.

## Threat: Root Compromise

**Scenario**: Attacker gains root access to the machine.

**Mitigations**:
- The Secure Enclave (macOS) and TPM (Windows/Linux) are separate hardware
  processors. Root access does not grant the ability to extract private key
  material from the hardware.
- With user-presence keys, signing still requires biometric or password input.

**Residual risk**:
- Root can read/write any Unix socket and can impersonate any user.
- Root can inject code into running processes or replace binaries.
- Root can manipulate key metadata (though not extract hardware key material).
- Root can suppress or fake user-presence prompts in some scenarios.
- On Linux with the software fallback, root can read key files directly.

## Threat: Phishing / Remote Theft

**Scenario**: Attacker attempts to steal the SSH private key over the network.

**Mitigations**:
- On hardware backends, the private key physically cannot leave the Secure
  Enclave or TPM. There is no export mechanism, no file to steal, and no
  memory to dump that contains the key material.
- This is the primary advantage over file-based SSH keys.

**Residual risk**:
- An attacker who compromises the machine can use the key (via the agent) while
  they maintain access, even if they cannot steal it for offline use.

## Threat: Public Key Substitution

**Scenario**: Attacker replaces the `.pub` file or intercepts the public key
during export, substituting their own public key.

**Mitigations**:
- The `sshenc inspect` and `sshenc export-pub --fingerprint` commands allow
  the user to verify the fingerprint of a key independently of the `.pub` file.
- The agent returns public key blobs directly from the Secure Enclave, not
  from `.pub` files.

**Residual risk**:
- If a user copies a substituted public key to a remote service (GitHub, etc.),
  the attacker's key will be authorized instead of the legitimate one. sshenc
  cannot prevent this if the substitution happens before the user uploads the key.
- Users must verify fingerprints out-of-band if the host is potentially
  compromised.

## Threat: Agent Socket Abuse

**Scenario**: Another local user or process connects to the agent's Unix socket
to make unauthorized signing requests.

**Mitigations**:
- The socket is created with mode 0600 (owner-only read/write).
- The socket's parent directory is enforced to mode 0700 (`sshenc-agent/src/server.rs` `prepare_socket_path`).
- Each accepted connection is verified against the peer UID via `SO_PEERCRED` / `getpeereid`; connections from other UIDs are rejected.
- A per-connection rate limiter (`server.rs`) throttles signing-request floods.
- The peer process binary is checked against an allowlist of trusted `sshenc` install paths (`server.rs`), limiting which local binaries can drive the agent.
- The agent supports an allowlist (`allowed_labels`) to limit which keys are exposed through the socket.
- `Config::default()` and the agent fall back to `$TMPDIR/sshenc` when `$HOME` is unset. This is a narrower fallback than the historical `/tmp` — the subdirectory is created at 0700 — but `$TMPDIR` / `/tmp` on shared systems is still a less isolated location than the home directory.

**Residual risk**:
- Root can bypass socket permissions.
- A same-UID attacker process can pass all UID / allowlist / rate-limit checks and drive the agent normally. Hardware user-presence (Touch ID / Windows Hello) is the only defense against this case.
- If `$HOME` is unset and `$TMPDIR` is shared with other users, the parent-dir-0700 hardening holds only while nothing else in `$TMPDIR` is adversarial.

## Threat: Malicious Local Processes

**Scenario**: A process running as the same user abuses the signing capability.

**Mitigations**:
- User-presence keys require Touch ID / password for each signature. The user
  sees a system prompt and can deny unexpected requests.
- The agent logs signing requests (in debug mode) for forensic review.

**Residual risk**:
- Without user-presence, any process running as the user can sign through the
  agent without any prompt. This is identical to the threat model of standard
  `ssh-agent` with unencrypted keys loaded.
- With user-presence, prompt fatigue (see below) can lead users to approve
  requests reflexively.

## Threat: Software Key Ambiguity

**Scenario**: A user has both hardware-backed keys (via sshenc) and
traditional file-based SSH keys. They mistakenly believe a file-based key
is hardware-protected.

**Mitigations**:
- sshenc keys are stored in `~/.sshenc/keys/` with distinct metadata files.
  They are separate from any file-based keys in `~/.ssh/`.
- `sshenc list` and `sshenc inspect` clearly identify hardware-backed keys
  and show which backend is in use.
- The agent only serves keys managed by sshenc.
- OpenSSH config snippets generated by `sshenc openssh print-config` use
  `IdentitiesOnly yes` to prevent fallback to file-based keys.

**Residual risk**:
- If the user's SSH config does not use `IdentitiesOnly yes`, OpenSSH may
  offer file-based keys alongside or instead of hardware-backed keys.
- The `.pub` file looks identical to any other ECDSA P-256 public key.
  There is no marker in the public key itself indicating hardware origin.
- On Linux with the software fallback, the key is functionally equivalent
  to a file-based key (no hardware isolation).

## Threat: User-Presence Prompt Fatigue

**Scenario**: Frequent Touch ID prompts desensitize users, leading them to
approve signing requests without verifying the context.

**Mitigations**:
- The prompt policy is configurable (`Always`, `Never`, `KeyDefault`).
  `KeyDefault` follows the key's own `AccessPolicy`.
- Keys can be created with or without user-presence requirements.
  Different keys can have different policies (e.g., user-presence for
  production servers, none for personal GitHub).

**Residual risk**:
- macOS user-presence prompts are generic. They indicate that an application
  wants to use a Keychain item but do not show which SSH host is being
  authenticated to or what specific operation is requested.
- Users who enable user-presence and then approve every prompt without
  thought get no security benefit from the feature.
- **Important:** `PromptPolicy` is advisory. The real user-presence
  enforcement lives in the hardware — the Secure Enclave triggers Touch ID
  inside `SecKeyCreateSignature` when the key was created with a non-`None`
  access policy, and Windows CNG triggers Windows Hello via
  `NCRYPT_UI_POLICY` at key creation time. `sshenc`'s in-process
  `maybe_verify_user_presence` path is a no-op on macOS and Windows (it
  relies on the hardware to enforce) and a stderr confirmation prompt on
  Linux software backend. A key created with `AccessPolicy::None` **will
  never prompt**, even with `PromptPolicy::Always`, because the hardware
  was not told to require presence.
- The Windows NCRYPT UI policy is set only at key-create time (see the
  libenclaveapp threat model on CNG policy verification); `sshenc` does
  not re-read the policy before signing, so an attacker-planted TPM key
  with the expected CNG name would bypass presence. Integration testing
  against real Windows TPM hardware is a known gap.

## Threat: Backup and Migration Limitations

**Scenario**: User loses their device or migrates to a new machine and
expects to retain access to their SSH keys.

**Mitigations**:
- This is a known trade-off, not a bug. Non-exportability is the core
  security property.
- Documentation clearly states that keys are device-bound and non-exportable.

**Residual risk**:
- Users who do not register backup keys on remote services will be locked
  out if they lose their device.
- There is no key recovery mechanism. Neither the Secure Enclave nor TPM
  supports key escrow.
- Organizations should plan for key rotation and multi-device registration.

## Threat: Software Fallback Weakness (Linux)

**Scenario**: On Linux without TPM, sshenc uses a software P-256 backend.
The private key exists on disk and in process memory.

**Mitigations**:
- A one-time warning is printed when the software backend is used.
- Key files are stored with 0600 permissions (owner-only).
- This backend is documented as providing no hardware isolation.

**Residual risk**: Any process running as the same user can read the key
file. This is a known limitation of Linux environments without TPM.

## Threat: SSH Agent Forwarding

**Scenario**: The user runs `ssh -A` or has `ForwardAgent yes` in their SSH
config. Agent requests are forwarded to the remote host. Any user with the
forwarded socket on the remote host — including root on that host — can sign
authentication challenges using the user's hardware-backed key.

**Mitigations**:
- `sshenc openssh print-config` emits `IdentitiesOnly yes` but does not
  disable `ForwardAgent`. `ForwardAgent` is a user-facing SSH decision.
- Documentation should recommend `IdentitiesOnly yes` and explicit per-host
  `ForwardAgent no`.

**Residual risk**:
- Forwarding remains a user-controlled feature. `sshenc` cannot prevent
  keys from being used for authentication while a forwarded connection is
  live. Users who forward agents to untrusted hosts give those hosts the
  ability to log into anything the key can reach.

## Threat: Key Enumeration via `SSH_AGENTC_REQUEST_IDENTITIES`

**Scenario**: Any process that passes the agent's peer-UID and
allowlist checks can issue `SSH_AGENTC_REQUEST_IDENTITIES` and receive the
full list of enrolled keys — public key blob plus comment — regardless of
`AccessPolicy`. The listing is unauthenticated per request.

**Mitigations**:
- The agent's peer-UID and binary allowlist (see "Agent Socket Abuse")
  reject non-user or non-trusted callers.
- Labels and comments should not themselves contain secrets.

**Residual risk**:
- A same-UID attacker that reaches the socket learns exactly which
  services the user has SSH keys for (from fingerprints and comments).
  This is an information-disclosure threat even for keys that require
  Touch ID / Windows Hello to sign.

## Threat: Windows Named-Pipe Hijack

**Scenario**: `sshenc-agent` reuses Microsoft OpenSSH's named pipe
(`\\.\pipe\openssh-ssh-agent`) so existing SSH clients connect
transparently. If Microsoft's OpenSSH `ssh-agent` service is running when
`sshenc-agent` starts, `sshenc-agent` fails to bind. Conversely, an
attacker process that creates the pipe first (with a malicious security
descriptor) can accept SSH clients' signing requests.

**Mitigations**:
- `sshenc install` stops and disables the Windows `ssh-agent` service
  before starting `sshenc-agent`, so clients connect to `sshenc`.
- `sshenc-agent` uses `ServerOptions::first_pipe_instance(true)` and
  refuses to attach to an existing pipe.
- The named pipe is created with an explicit DACL
  (`ConvertStringSecurityDescriptorToSecurityDescriptorW`) that grants
  full control only to the creator-owner (the current user) and
  `SYSTEM`, cutting off `Administrators` and `Everyone` who would
  otherwise have default read/write access (`sshenc-agent/src/server.rs`
  `SecurityDescriptor`).
- The CLI surfaces an actionable error when the pipe is in use.

**Residual risk**:
- An attacker with admin rights can always create the pipe first; admin
  rights on Windows already implies full control over the TPM.

## Threat: Metadata File Tamper (`.meta`)

**Scenario**: A same-UID attacker edits `~/.sshenc/keys/<label>.meta` to
change the stored `AccessPolicy` (e.g. `BiometricOnly` → `None`) or other
fields.

**Mitigations**:
- The hardware key's real access policy is fixed at **key creation time**
  on macOS Secure Enclave and Windows CNG. Editing `.meta` cannot relax
  the hardware's enforcement — Touch ID / Windows Hello still fires on
  sign regardless of what the metadata file claims.
- Metadata files are written 0600 via `atomic_write`.
- On the Linux keyring / software backend, `.meta` now has an HMAC
  sidecar `<label>.meta.hmac` generated at key-creation time. The
  HMAC key is a random per-app 32-byte value stored in the system
  keyring (`enclaveapp-keyring::meta_hmac_key`). `enclaveapp-app-storage`
  verifies the sidecar on load and rejects HMAC-mismatched reads with
  a hard error (`meta_hmac_verify`). An attacker who rewrites `.meta`
  without also having keyring access is caught.

**Residual risk**:
- UI and library-level policy checks (`sshenc list`, `sshenc inspect`,
  `PromptPolicy::KeyDefault`) still trust the metadata file on
  hardware backends, where the sidecar is not written (hardware-side
  enforcement makes the check redundant). An attacker who rewrites
  `.meta` on a hardware backend can still **mislead** the user into
  believing a key is unprotected — but signing will still prompt.
- On the keyring / software backend, a same-UID attacker who also has
  keyring access can still rewrite both `.meta` and the sidecar. This
  is the same threshold as decrypting the key material itself, so no
  net loss of protection.
- The migration from the legacy `biometric: bool` field to `AccessPolicy`
  is handled by compatibility code; a missing `access_policy` field is
  treated per the legacy bool. A same-UID attacker who strips the new
  field from `.meta` can rely on the legacy-compat path behaving
  intuitively but should not gain anything the hardware does not already
  allow (and on the keyring backend the HMAC check catches the edit).

## Threat: `SSH_AUTH_SOCK` / `IdentityAgent` Trust

**Scenario**: The user's shell profile, an attacker-modified dotfile, or a
supply-chain compromise sets `SSH_AUTH_SOCK` (or `IdentityAgent` in
`~/.ssh/config`) to point at an attacker-controlled socket. SSH clients
trust whatever signs, so all authentications happen against the attacker's
agent — the hardware-backed guarantee is silently bypassed.

**Mitigations**:
- `sshenc openssh print-config` emits an explicit `IdentityAgent` line
  that points at the managed socket path.
- Documentation should call out that a user's `.bashrc` / `.zshrc` is a
  credential-sensitive file.

**Residual risk**:
- This is a user-environment-trust threat that `sshenc` cannot fully
  close. If the attacker has write access to shell startup files, they
  can redirect agent traffic at will.

## Threat: `AccessPolicy::None` Keys Are Hardware-Non-Exportable but Present-less

**Scenario**: The user creates a key with `AccessPolicy::None` (the default
for `sshenc keygen` when `--require-user-presence` is not set) expecting
some protection from hardware backing.

**Mitigations**:
- Non-exportability still holds: the private key material cannot be read
  out of the Secure Enclave or TPM.
- `sshenc list` / `inspect` clearly display whether user presence is
  required.

**Residual risk**:
- Any same-UID process can sign with the key at any time without a
  prompt. Functionally equivalent to a loaded `ssh-agent` with a password-
  less file key, with the single added benefit that the key itself cannot
  be exfiltrated.
- Users who want Touch ID / Windows Hello prompts must explicitly create
  keys with `--access-policy any` (or `biometric` / `password`) at keygen
  time.

## Threat: Git Signing Configuration Tamper (`gitenc`)

**Scenario**: `gitenc --config` writes:
- `gpg.format = ssh`
- `gpg.ssh.program = /path/to/sshenc`
- `user.signingkey = ...`
- `gpg.ssh.allowedSignersFile` pointing at `~/.ssh/allowed_signers`

All four values live in user-writable files (`~/.gitconfig` and the
allowed-signers file). Malware running as the user can redirect
`gpg.ssh.program` to its own binary, swap the signing key, or authorise
the attacker's own keys for commit verification.

**Mitigations**:
- `gitenc` validates label and email inputs before writing.
- File locations are standard git / OpenSSH paths so they are not
  themselves surprising.

**Residual risk**:
- A same-UID attacker with write access to `~/.gitconfig` or
  `~/.ssh/allowed_signers` can defeat the integrity of `git log --show-signature`
  and `ssh-keygen -Y sign` / `-Y verify` end-to-end. This is a user-side
  dotfile-integrity threat that `sshenc` cannot fully mitigate from inside
  its own process.

## Threat: Cross-Binary Keychain ACL Prompt / Fatigue

**Scenario**: The macOS legacy keychain keys its per-item ACL to
the *creating binary's* code signature. On unsigned sshenc builds
(cargo, Homebrew, pre-signing), every new binary hash is a fresh
ACL identity. If the CLI (`sshenc` / `sshenc-keygen`) creates a
wrapping-key entry and the agent (`sshenc-agent`) later tries to
read it, macOS fires an approval sheet for the cross-binary
access. Without careful design this cascades into a prompt per
rebuild per binary per key, fatiguing the user into clicking
"Always Allow" on everything.

**Mitigations**:
- `sshenc-agent` is the *sole* process that calls into the
  platform crypto FFI. The CLI binaries construct
  `sshenc-se::AgentProxyBackend`, which reads `.pub` / `.meta`
  from disk directly for read-side ops and forwards every write
  (`generate` / `sign` / `delete` / `rename`) over the agent's
  local IPC endpoint. Creator and reader of every keychain item
  are the same binary — no cross-binary ACL prompt.
- The invariant is platform-uniform: Unix socket on
  macOS/Linux/WSLv2, Windows named pipe on native/PowerShell/Git
  Bash/cmd.exe. The CLI binary never links the platform FFI into
  a path that would call it.
- The Swift bridge in `enclaveapp-apple` emits a shippable stderr
  warning whenever a single crypto op exceeds ~1 s — any cross-
  binary prompt that ever slips back in self-identifies with the
  exact `SecItem*` call and its elapsed time.

**Residual risk**:
- Rebuilding `sshenc-agent` still changes its code signature, so
  a rebuild still costs one Always-Allow approval per existing
  wrapping-key item. That's one prompt per key, not one per key
  per binary per rebuild — a linear improvement.
- On Windows, CNG's ACL model isn't code-signature-based, so the
  prompt class doesn't apply there; the centralization is kept
  anyway for architectural uniformity.

## Threat: PKCS#11 Dylib / Agent Binary Tamper

**Scenario**: `sshenc-pkcs11` is installed to a user-writable location
(e.g. `%LOCALAPPDATA%\sshenc\bin\` on Windows, or the user's
`~/.cargo/bin` / `~/.local/bin` on Unix). Same-user malware replaces the
dylib with a lookalike that signs with its own key or exfiltrates signing
requests.

**Mitigations**:
- `enclaveapp_core::bin_discovery::find_trusted_binary` canonicalizes
  paths and restricts lookups to a trusted install-directory list,
  preventing PATH-based planting of the sshenc CLI itself. The same
  helper is shared across every enclaveapp consumer (sshenc today;
  awsenc next) so the search-path invariant stays consistent.
- The PKCS#11 provider path in `~/.ssh/config` is written as an absolute
  path, so planting a lookalike requires write access to that exact path.
- Distribution via signed Homebrew bottles / MSI installers is the
  recommended channel; code-signing status applies end-to-end.

**Residual risk**:
- If the PKCS#11 dylib or the `sshenc-agent` binary is installed into a
  user-writable directory (common for per-user installs), same-user
  malware can replace it. This is a subset of the generic "malware-as-
  user" threat but worth naming because SSH loads the PKCS#11 provider
  implicitly on every session.

## Threat: Ready-File Symlink in `$TMPDIR`

**Scenario**: `sshenc-agent` writes a ready-file in `$TMPDIR`
(`sshenc-agent-ready-<pid>-<nanos>.tmp`, 0600) as part of the daemonize
handshake. On a shared `/tmp`, an attacker can pre-create a symlink at
that path to redirect the "ready" write.

**Mitigations**:
- The filename includes PID and nanosecond timestamp so collisions are
  unlikely.
- `signal_ready` opens the file with
  `OpenOptions::new().write(true).create_new(true).custom_flags(libc::O_NOFOLLOW).mode(0o600)`
  (`sshenc-agent/src/server.rs`). `create_new` atomically fails with
  `EEXIST` if anything already exists at the path (file, symlink,
  directory); `O_NOFOLLOW` additionally refuses to dereference a
  pre-planted symlink and fails with `ELOOP`. Either way the write
  never lands on an attacker-chosen target, and the error is surfaced
  to the parent process via the daemonize handshake instead of being
  silently followed.
- `mode(0o600)` at open time (load-bearing on umask-permissive
  systems) + an explicit `set_permissions(0o600)` for belt-and-
  suspenders.
- A `signal_ready_refuses_preplanted_symlink` unit test locks in the
  symlink-refusal semantics.

**Residual risk**:
- None for the symlink-redirect vector. An attacker who can predict
  the path and win a TOCTOU between our `remove_file` (performed by
  the parent before spawn) and our `create_new` (in the child) still
  loses — the attacker's file is created, then our `create_new` fails
  with `EEXIST`, and the parent daemonize handshake surfaces the
  failure.

## Threat: MSI Uninstall Resilience

**Scenario**: If `sshenc uninstall` exited non-zero during MSI removal
(agent still running, file locked, registry error), a pedantic
`Return="check"` custom action would fail the entire MSI uninstall and
roll it back — leaving the user unable to remove the software.

**Mitigations**:
- The uninstall custom action in `installer/sshenc.wxs` uses
  `Return="ignore"` so MSI uninstall always completes even if
  `sshenc uninstall` reports an error.
- The install custom action uses `Return="check"` so users learn about
  installer failures up front.

**Residual risk**:
- `sshenc uninstall` is designed to be resilient, but residual non-fatal
  errors may leave stale registry / service state. The `Return="ignore"`
  posture is deliberate: a broken installer that cannot be removed is
  worse than stale uninstall artefacts.

## Out of Scope

The following are explicitly outside sshenc's threat model:

- **Physical attacks on the Secure Enclave or TPM**: We rely on Apple's
  and Microsoft's hardware security guarantees.
- **Kernel exploits on any platform**: A kernel-level compromise can bypass
  all software protections.
- **Supply chain attacks on sshenc itself**: Standard open-source mitigation
  (reproducible builds, signed releases) applies.
- **SSH protocol weaknesses**: sshenc implements key management, not the
  SSH protocol itself.
- **Denial of service**: An attacker who can delete key files can destroy
  keys. This requires local access.
