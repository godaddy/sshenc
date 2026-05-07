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

**Scenario**: Another local user or process connects to the agent's
local IPC endpoint (Unix socket or Windows named pipe) to make
unauthorized signing requests.

The defenses differ by platform — they are listed separately below
because the threat model previously misrepresented them as uniform.
On Unix the agent runs three checks per connection (peer UID, rate
limit, peer-binary heuristic); on Windows the named pipe relies on
its DACL and the AF_UNIX compatibility socket relies on NTFS
directory ownership. The Windows code paths do **not** currently
run a peer-SID check, the rate limiter, or the binary heuristic.

**Mitigations (Unix — macOS, Linux, WSLv2)**:
- The socket is created with mode 0600 (owner-only read/write).
- The socket's parent directory is enforced to mode 0700
  (`sshenc-agent/src/server.rs` `prepare_socket_path`).
- Each accepted connection is verified against the peer UID via
  `SO_PEERCRED` / `getpeereid`; connections from other UIDs are
  rejected (`verify_peer_uid` in `server.rs`).
- A per-connection rate limiter (`RateLimiter::check` in `server.rs`)
  throttles signing-request floods on the Unix path.
- A best-effort peer-binary check (`verify_peer_binary`) attempts to
  log the peer's exe path and basename. **This is not a trust
  boundary**; see "Peer-binary heuristic" below.
- The agent supports an allowlist (`allowed_labels`) to limit which
  keys are exposed through the socket.
- `Config::default()` and the agent fall back to `$TMPDIR/sshenc`
  when `$HOME` is unset. This is a narrower fallback than the
  historical `/tmp` — the subdirectory is created at 0700 — but
  `$TMPDIR` / `/tmp` on shared systems is still a less isolated
  location than the home directory.

**Mitigations (Windows native — named pipe + AF_UNIX bridge)**:
- The primary endpoint is the named pipe
  (`\\.\pipe\openssh-ssh-agent`). Its DACL is built explicitly via
  `ConvertStringSecurityDescriptorToSecurityDescriptorW`
  (`PipeSecurityAttributes::restricted` in `server.rs`) to grant
  full control only to the **creator-owner** (the current user) and
  `SYSTEM`, cutting off `Administrators` and `Everyone` who would
  otherwise have default read/write access.
- `ServerOptions::first_pipe_instance(true)` is set on initial
  pipe creation so an attacker process that races for the well-known
  pipe name causes a clear error rather than a silent hijack.
- A secondary AF_UNIX socket (`~/.sshenc/agent.sock`) is exposed
  for Git Bash / MINGW SSH compatibility. It relies on the parent
  directory's NTFS ACL (the user's profile directory is
  user-owned), so same-UID is the trust boundary by file-system
  ownership.
- The agent supports the `allowed_labels` allowlist on Windows too.
- The Windows accept loop does **not** run a peer-SID check, the
  per-connection rate limiter, or the peer-binary heuristic.
  Tightening this would use `GetNamedPipeClientProcessId` →
  `OpenProcessToken` to compare SIDs; tracked in DEEP_REVIEW B3.

**Peer-binary heuristic (Unix only)**:

`verify_peer_binary` resolves the peer's exe via
`SO_PEERCRED → /proc/<pid>/exe` (Linux) or `LIBPROC_PIDPATHINFO_MAXSIZE`
(macOS), then matches the basename against this allowlist:

```
ssh, ssh-add, ssh-agent, ssh-keygen, ssh-keyscan, scp, sftp,
rsync, git, git-remote-ssh, sshenc, sshenc-agent, gitenc,
code (VS Code remote SSH), cursor (Cursor editor)
```

This is a best-effort heuristic, not a trust boundary:
1. Resolution failures (kernel thread, EPERM on `/proc`,
   PID-recycled race) are treated as **allow**.
2. The match is by basename, not canonicalized install path. A
   same-UID attacker who renames their binary to any allowlisted
   name (`ssh`, `git`, etc.) passes.
3. The list deliberately includes generic tools (`git`, `code`,
   `cursor`) so legitimate workflows are not broken; that
   permissiveness is the point.

Treat `verify_peer_binary` as a tripwire (it logs the unexpected
basename) and as friction against casual misuse — not as a defense
against motivated same-UID malware. The hardware user-presence
gate (Touch ID / Windows Hello) is the actual defense for that
case.

**Residual risk**:
- Root can bypass socket permissions on Unix; admin can recreate
  the named pipe on Windows.
- A same-UID attacker process passes UID/allowlist/rate-limit
  checks (Unix) or DACL/NTFS ownership (Windows) and drives the
  agent normally. Hardware user-presence (Touch ID / Windows
  Hello) is the only defense against this case.
- If `$HOME` is unset and `$TMPDIR` is shared with other users on
  Unix, the parent-dir-0700 hardening holds only while nothing
  else in `$TMPDIR` is adversarial.
- Windows: with no peer-SID enforcement in the accept loop, the
  named pipe's DACL is the only thing keeping cross-user
  connections out. That DACL is correctly restrictive, but the
  defense in depth that the Unix path has (UID + DACL + rate
  limiter + binary heuristic) is reduced to one layer on Windows.

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
- On Windows every consent gate is hardware-enforced as of the
  libenclaveapp soft-consent removal: the legacy Platform-KSP path
  always sets `NCRYPT_UI_PROTECT_KEY_FLAG`, and the SK path goes
  through WebAuthn / NGC. An attacker with code execution as the
  user cannot hook a Boolean to bypass either -- the only consent
  UI fires from the OS itself before the TPM releases the key. See
  "Threat: Windows consent-path selection" below for the matrix
  and UX trade-offs.

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
- **Important:** `PromptPolicy` is advisory. The actual user-presence
  enforcement is platform-specific and uniformly hardware-enforced
  on the supported hardware backends. **macOS** triggers Touch ID
  inside `SecKeyCreateSignature` when the key was created with a
  non-`None` access policy -- the gate is enforced inside the
  Secure Enclave. **Windows on the SK / WebAuthn path** (the
  default when Hello is enrolled) triggers Hello via
  `WebAuthNAuthenticatorGetAssertion`; the TPM/OS will not produce
  a signature without an OS-mediated Hello gesture. **Windows on
  the legacy Platform-KSP path** sets `NCRYPT_UI_PROTECT_KEY_FLAG`
  on every non-`None` access-policy key, so the TPM enforces the
  gate via the legacy CryptUI password dialog; the library does
  not (and has never since the soft-consent removal in libenclaveapp's
  follow-up to #105) issue any user-mode Boolean check between the
  agent and the hardware ack. **Linux software backend** issues a
  stderr confirmation prompt; **Linux TPM backend** does not
  currently enforce presence at sign time (see libenclaveapp
  threat model).
- A key created with `AccessPolicy::None` **will never prompt** on
  any backend, even with `PromptPolicy::Always`, because the hardware
  / OS was not told to require presence.

## Threat: Windows consent-path selection

**Scenario**: A Windows user wants hardware-enforced consent for SSH
signing operations, comparable to macOS's Secure Enclave.

**Background**: On Windows, sshenc creates ECDSA P-256 keys via one
of two paths. Both gate signing on a hardware-enforced UI ack -- the
choice between them is purely about *which* UI fires, not whether
the gate is real:

| Path | Backend | UI surface | Default? |
|------|---------|------------|:--------:|
| **SK / WebAuthn** | `WebAuthNAuthenticatorGetAssertion` (TPM via NGC) | Windows Hello biometric / PIN, fronted by a one-entry passkey chooser interstitial. | **Yes**, when Hello is enrolled. |
| **Legacy Platform KSP** | `NCryptSignHash` with `NCRYPT_UI_PROTECT_KEY_FLAG` set on the key | Legacy CryptUI password protector dialog. | Yes, when Hello is not enrolled, when `--legacy` is passed, or when the user pinned a legacy-only flag (`--strict`, `--no-user-presence`, `--auth-policy`). |

The agent never sees a user-mode "did the user agree?" Boolean -- it
issues the TPM call, the OS interposes its UI, and the TPM only
returns a signature after the OS confirms the ack. There is no soft
consent gate anywhere in the sshenc stack on Windows.

**Mitigations**:
- `sshenc keygen` autodetects Hello availability via
  `WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable` and
  selects the SK path by default when present. Users who never
  pass a flag get the better UX (Hello biometric) automatically.
- `--strong` forces the SK path and exits with a clear error if
  Hello isn't reachable, so a script that requires the
  Hello-style UX can fail closed rather than silently fall back to
  the password dialog.
- `--legacy` opts into the legacy CryptUI password dialog. The
  consent gate is still hardware-enforced; the user is choosing UX
  (no passkey chooser, password dialog instead of biometric).
- The SK path uses a unique-per-key Relying Party ID
  (`sshenc-<keyhash>.local`) so the Win11 26200+ passkey chooser
  scope is exactly one credential per RP, even when the user has
  many SK-backed sshenc keys.
- The SK signature wire format (`sk-ecdsa-sha2-nistp256@openssh.com`)
  is the standard OpenSSH 8.2+ FIDO2 format. Stock sshd and GitHub
  verify it natively -- there is no sshenc-specific verifier in
  the trust path.
- `verify_ui_policy_matches` re-reads the legacy key's actual
  `NCRYPT_UI_POLICY` flag at sign time and refuses keys whose flag
  doesn't match metadata, catching attacker-planted CNG keys with
  a missing or wrong UI flag.

**Residual risk**:
- **Pre-soft-consent-removal keys.** Legacy Windows keys created
  by sshenc versions that ran the (now-removed) `UserConsentVerifier`
  path on Hello-enrolled hosts have no `NCRYPT_UI_PROTECT_KEY_FLAG`
  set on the TPM key -- the flag can't be added retroactively. The
  agent now refuses to sign with such keys (per
  `verify_ui_policy_matches`), forcing regeneration. This was an
  explicit pre-release choice: leaving those keys signable would
  preserve a soft-consent path the rest of the stack no longer
  carries. Regenerate via `sshenc keygen` (auto-picks SK on
  Hello-enrolled hosts) or `sshenc keygen --legacy`.
- **WebAuthn `clientDataJSON` brittleness.** The SK path passes
  the raw SSH sign payload as `pbClientDataJSON` to `WebAuthn.dll`,
  relying on the documented Win32 contract that the bytes are not
  validated as JSON. If a future Windows update tightens this,
  every existing SK key breaks (signs would fail at the wire).
  The `tavrez/openssh-sk-winhello` plugin uses the same trick, so
  any tightening would break the broader FIDO2-on-Windows ecosystem
  at the same time. The pre-release smoke test
  (`Test-EnclaveApps.ps1 -StrongSk`) verifies the wire format
  end-to-end against a stock OpenSSH server in Docker; running it
  before each release detects this drift before users do.
- **No back-migration.** There is no in-place upgrade from a legacy
  key to an SK key — the credential identifiers are different at the
  hardware layer. Users who want hardware-enforced consent for an
  existing key must `sshenc keygen --strong` to a new label and
  re-deploy the pubkey.

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
change the stored `AccessPolicy` (e.g. `BiometricOnly` → `None`),
`presence_mode`, the SK `credential_id_b64`, or other fields. Defense
goes further than just hardware enforcement: even when the chip's
behavior is fixed, `.meta` is what the agent shows the user, what
gates which credential the agent uses, and what tells `sshenc inspect`
whether a key is biometric-locked.

**Mitigations**:
- The hardware key's real access policy is fixed at **key creation
  time** on macOS Secure Enclave and Windows CNG. Editing `.meta`
  cannot relax the hardware's enforcement — Touch ID / Windows Hello
  still fires on sign regardless of what `access_policy` in the
  metadata file claims.
- Metadata files are written 0600 via `atomic_write`.
- The agent never auto-migrates a missing sidecar in the per-op
  hot path. The earlier design did, and a same-UID attacker who
  could `rm` the sidecar got the tampered `.meta` blessed silently.
  The hot path now refuses missing-tag loads outright; the user runs
  an explicit `sshenc migrate-meta` once per install to bless on-
  disk state after a confirmation prompt that prints each key's
  policy fields and meta-JSON SHA-256 fingerprint.

### Trust anchor: per-key secure-store-backed HMAC tag (macOS + Windows)

For each key `<label>`, the agent stores a 32-byte HMAC-SHA256 tag
of `<label>.meta` in a per-key secure-store item:

- **macOS**: legacy Keychain entry under service
  `com.godaddy.<app>.meta-tag`, account `<label>`. The item shares
  the same code-signature ACL as the per-key wrapping key — an
  attacker without our entitled signed binary can neither read nor
  write either.
- **Windows**: per-key Credential Manager entry under target
  `com.godaddy.<app>.meta-tag.<label>`, `CRED_TYPE_GENERIC`,
  `CRED_PERSIST_LOCAL_MACHINE`. Credential Manager binds to the
  current user's profile (DPAPI under the hood). A same-UID
  attacker without the user's Windows credentials cannot decrypt
  or rewrite. Same-user processes can `CredDelete`, but that
  surfaces as `Legacy` on next op — and after `migrate-meta` runs
  once, the marker switches the agent's error to the strong-tamper
  variant. The first attempt at this layer used `NCryptSetProperty`
  with a custom property name on the TPM-backed key handle, but
  Microsoft Platform Crypto Provider rejects custom property names
  (`NTE_NOT_SUPPORTED 0x80090029`) — Credential Manager was the
  porting doc's documented fallback and is what shipped.
- **Linux** (keyring + TPM backends): per-key Secret Service entry
  under service `<app>`, account `__meta_tag_<label>__`, via the
  `keyring` crate over `org.freedesktop.secrets`. Same Secret
  Service backend that already holds the per-app meta-HMAC key.
  Bound to the user's unlocked session keyring; same-UID
  attackers without an unlocked session cannot read or write.
  Same-user processes within an unlocked session can call
  `delete_credential`; surfaces as `Legacy`, gated by the
  migration marker like the other platforms. **On Linux the trust
  anchor is the entire defense for `.meta` policy fields**:
  neither the keyring backend nor the Linux TPM backend (per its
  design caveat) enforces `AccessPolicy` at sign time. macOS and
  Windows have hardware-enforced policy bits at the chip layer
  that catch some bypasses even if the trust anchor is defeated;
  Linux does not.

The on-disk `<label>.meta.hmac` sidecar is kept as a derivable
cache: the secure-store tag is the authority. Deleting the sidecar
does not change the verification outcome; the agent rebuilds it
from the secure-store tag on next op.

At every per-op load (macOS `load_handle_with_context` /
`load_pub_key` via `enclaveapp-apple::keychain::ensure_meta_integrity`;
Windows `TpmSigner::sign` via
`enclaveapp-windows::sign::ensure_meta_integrity`):

- **Tag matches recomputed HMAC of `.meta`** → operation proceeds.
- **Tag mismatch** → hard error
  `meta_tag_verify`. Refuse the operation. Recommendation:
  regenerate the key.
- **No tag in keychain** → hard error `meta_tag_legacy`. The error
  message is one of two variants depending on the migration marker
  (see below):
  - **Marker not set** (gentle, one-time-cutover): "This is a one-
    time migration required by upgrading to a build that introduces
    meta integrity tags. Run `sshenc migrate-meta` after verifying
    the policy fields look correct."
  - **Marker present** (strong, tamper signal):
    "`sshenc migrate-meta` has already completed on this install,
    so this should not have recurred. Regenerate the affected key
    instead. Do NOT run migrate-meta again."

The HMAC key used to compute the per-key tag is the same per-app
random 32-byte value that authenticates the on-disk sidecar. On
macOS it lives in the legacy Keychain under
`com.godaddy.<app>.meta-hmac` / `__meta_hmac_key__`, no user-
presence ACL; on Windows it lives in a DPAPI-encrypted blob at
`%APPDATA%\<app>\.meta-hmac.dpapi`, bound to the current user's
master key; on Linux it lives in a Secret Service entry under
service `<app>` / account `__meta_hmac_key__`, bound to the user's
unlocked session keyring. The verify path uses a strictly
read-only companion on every platform (`meta_hmac::load_existing`
on macOS / Windows, `meta_hmac_key_existing` on Linux) — the
create-on-first-call form is reserved for the keygen path so a
verify can never trigger a `SecItemAdd` (macOS),
`CryptProtectData` (Windows), or `set_secret` (Linux) on a
locked secure store.

### Migration: explicit, user-confirmed, one-shot

Pre-upgrade keys do not have a keychain tag yet. The user runs
`sshenc migrate-meta` once after upgrade. Behavior:

1. Enumerate `<keys_dir>/*.meta`, parse each, print
   policy + SHA-256 fingerprint table. Keys with
   `presence_mode: none` or `access_policy: None` are highlighted
   with `POLICY=NONE !!` and an explanatory annotation so the user
   has to look at them.
2. Require typing `yes` (full word). `--yes` exists for scripted
   environments and is documented as bypassing the human-review
   step.
3. For each label, the CLI sends `SSH_AGENTC_SSHENC_MIGRATE_META`
   to the agent over IPC. The agent — the only binary that should
   ever write a meta-tag item — computes the tag from the on-disk
   `.meta` and writes it to the per-key keychain item. The CLI
   never touches the meta-tag keychain item directly, preserving
   the cross-binary ACL invariant.
4. After all keys migrate, the CLI sends
   `SSH_AGENTC_SSHENC_SET_MIGRATION_MARKER`. The marker lives in a
   per-platform secure store — macOS Keychain under
   `com.godaddy.<app>.migrate-marker` / `__completed__`, Windows
   Credential Manager target `com.godaddy.<app>.migrate-marker`
   with `CRED_PERSIST_LOCAL_MACHINE`, Linux Secret Service entry
   under service `<app>` / account `__meta_migration_marker__`
   (NOT a file — a file marker is a trivial deletion primitive
   that re-opens the auto-migrate hole). After the marker is set,
   the agent's `legacy_meta` error variant switches to the
   strong-tamper-warning form, and the CLI refuses repeat
   invocation without `--force-rerun-i-understand`.

### Per-field tamper coverage

The tag authenticates the full `.meta` JSON body, so every field —
`access_policy`, `app_specific.presence_mode`,
`app_specific.credential_id_b64` + `rp_id` for SK keys,
`pub_file_path`, `git_email`, `git_name`, `comment`, etc. — is in
scope. The most consequential of these is the SK
`credential_id_b64` substitution: planting an attacker-minted TPM
credential ID into another label's `.meta` would otherwise let the
agent sign with the attacker's key while the user thinks they're
using their own. The trust anchor closes that.

### Agent-only access invariant

The macOS meta-tag, meta-HMAC key, and migrate-marker modules are
called only from `sshenc-agent` (and the equivalent agent for
awsenc / sso-jwt / npmenc), never the CLI binaries. CLI binaries
reach `AgentProxyBackend` for write ops and read disk-only
artifacts (`.pub`, `.meta`) for read ops; the cross-platform
helper `enclaveapp-app-storage::platform::check_meta_integrity`
also uses `meta_hmac::load_existing` to stay read-only. This
preserves the "agent-only Keychain reads" invariant documented in
*Cross-Binary Keychain ACL Prompt / Fatigue*.

### Verification is gated by `.meta` existence

The `meta_path.exists()` check fires before any platform secure-
store query. A synthetic call site (test binary, fresh-install
probe, dev tool, freshly-enrolled label that hasn't been
generated yet) does not trigger any Keychain access or DPAPI
syscall. Without this guard, every cargo test rebuild from an
unsigned binary would prompt for ACL grants on the meta-HMAC
keychain item.

**Residual risk**:

- **Repeat-migration social engineering.** A same-UID attacker
  could in principle tamper `.meta` then trick the user into
  running `sshenc migrate-meta --force-rerun-i-understand`. This
  requires either deceiving the user about the policy-field
  display (the migrate-meta UI shows each key's current
  fingerprint and policy fields) or the user dismissing the
  prompt without reading. The
  `--force-rerun-i-understand` flag's deliberately awkward name
  exists to make this hard to do by reflex. The "marker present"
  agent error message is also tuned to discourage repeat-runs.
- **Trust-on-first-use at migrate-meta.** The very first
  migrate-meta run blesses whatever is currently on disk. If a
  same-UID attacker tampered `.meta` BEFORE the user upgraded
  sshenc to a build with the trust anchor AND before the user
  runs migrate-meta, the tampered content is what gets
  authenticated. The recommendation is for users who suspect
  tampering on a pre-upgrade install to regenerate keys
  rather than migrate. The fingerprint/policy display in the
  migrate-meta prompt exists to give a paranoid user a check
  before saying yes.
- **Platform-store-compromise threshold.** A same-UID attacker
  who **also** has access to the macOS legacy Keychain with our
  binary's code-signing ACL granted can rewrite the per-key tag
  to match a tampered `.meta`. This is the same threshold as
  decrypting the wrapping key / KEK that the user's
  authentication state already gates, so no net loss of
  protection beyond what the threat model already accepts at
  that threshold.
- **Approval-sheet cost on macOS dev rebuilds.** The legacy
  Keychain ACL is bound to the creating binary's code signature.
  Each rebuild of `sshenc-agent` from an unsigned cargo build is
  a new signature and costs approval sheets on first access of
  the meta-HMAC key, the per-key meta-tag items, AND the
  migrate-marker — equivalent to the wrapping-key-per-rebuild
  cost already documented in *Cross-Binary Keychain ACL Prompt
  / Fatigue*. Production signed builds (Homebrew bottle, .app
  bundle) do not pay this cost.
- **Backend-without-policy enforcement on Linux.** The keyring
  backend and the Linux TPM backend (per its design caveat) do
  not enforce `AccessPolicy` at sign time — the meta-integrity
  tag is the only defense against same-UID rewriting of policy
  fields in `.meta` on those backends. macOS and Windows have
  hardware-enforced policy bits at the chip layer that catch
  some bypasses even if the trust anchor were defeated; Linux
  does not.
- **DPAPI blob loss on Windows profile reset.** A user-profile
  reset destroys the DPAPI master key and renders the meta-HMAC
  blob unreadable. The next strict-mode load returns
  `meta_hmac_missing` and the migration path writes a fresh
  sidecar; the user is not locked out but loses the integrity
  guarantee for `.meta` content frozen before the reset.
  Equivalent to a TPM hardware reset.
- The migration from the legacy `biometric: bool` field to
  `AccessPolicy` is handled by compatibility code; a missing
  `access_policy` field is treated per the legacy bool. A
  same-UID attacker who strips the new field from `.meta`
  cannot gain anything the hardware does not already allow,
  and the trust anchor / sidecar catches the edit on every
  platform.

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

## Threat: WSL Bridge Response Inflation

**Scenario**: The WSL → Windows bridge protocol passes JSON-RPC
requests/responses over a child process's stdin/stdout. If the
Windows-side bridge (`sshenc-tpm-bridge.exe`) is replaced or
compromised it can return arbitrarily large response lines,
forcing the WSL client to allocate memory until the process is
OOM-killed. There is no authentication on the bridge wire — the
client trusts whatever it spawned.

**Mitigations**:
- The bridge binary is discovered via fixed admin-path locations
  (`/mnt/c/Program Files/<app>/...`,
  `/mnt/c/ProgramData/<app>/...`) or an explicit
  `ENCLAVEAPP_BRIDGE_PATH` env override. PATH-based lookup was
  removed: a user-writable `$PATH` entry on the WSL side could
  substitute a malicious bridge.
- Per-line read uses
  `LineReaderWithTimeout::with_max_line_bytes(stdout, MAX_BRIDGE_RESPONSE_BYTES)`
  (`enclaveapp-bridge::client`). Lines exceeding the
  64 KB cap are aborted with `io::ErrorKind::InvalidData` *during*
  the read, so the worst-case allocation is bounded at 64 KB
  rather than at the bridge's discretion. The bridge child is
  killed and the session ends; subsequent ops will respawn.
- Per-request timeout
  (`ENCLAVEAPP_BRIDGE_TIMEOUT_SECS`, default 120 s) catches the
  trickle case where a malicious peer holds the connection open
  without sending the newline.
- `BUILD_REQUIRES_SIGNED` (compile-time flag) refuses to spawn an
  unsigned bridge binary when set; default is **off** because the
  current release pipeline does not sign bridges.

**Residual risk**:
- An attacker who replaces the bridge binary at one of the fixed
  install paths can return arbitrary signed content within the
  64 KB cap — DoS is bounded but signing semantics are not. This
  is the same trust relationship as any platform-FFI consumer
  with a binary planted in the install path; signed bridges
  (`BUILD_REQUIRES_SIGNED`) close it.
- The bridge spawn is a child process inheriting WSL's
  environment; an attacker controlling environment variables in
  the WSL shell can influence which bridge is found via
  `ENCLAVEAPP_BRIDGE_PATH`.

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
