# Wrapping-key user presence and TTL cache (macOS)

Status: active — added April 24, 2026.
Scope: macOS Secure Enclave keys. Linux and Windows unaffected.

## What the wrapping key does

On macOS, sshenc can't use `kSecAttrTokenIDSecureEnclave` directly
because ad-hoc signed binaries (every unsigned local rebuild) fail
AMFI's provisioning check. The workaround is CryptoKit's
`SecureEnclave.P256.Signing.PrivateKey`, whose `dataRepresentation:
Data` is an opaque blob the same device can later feed back into SE to
rebuild the key for signing.

That blob sits on disk at `~/.sshenc/keys/<label>.handle`. The private
key never leaves the SE, but the blob is a bearer token — any process
that reads it can drive SE signing operations. sshenc wraps the blob
at rest with a per-key AES-256-GCM wrapping key stored in the macOS
login keychain.

## Why the old design produced password prompts on every rebuild

The login-keychain item's access control was bound to the calling
binary's code-signing identity. Ad-hoc signatures (`rustc` / `cargo`
default) change on every rebuild, so macOS prompted for the login
password to add the new signature to the item's ACL. A developer
building sshenc a dozen times a day saw a dozen prompts, and so did
everyone their `brew upgrade` pipeline touched.

## What changed

The wrapping-key item is now stored with a
`SecAccessControlCreateWithFlags(.userPresence)` access control.
Access is gated on Touch ID or the device passcode, tied to the
logged-in user — **not** to the binary's signature. Rebuilding the
binary doesn't invalidate anything.

The price: naïvely, every load of the wrapping key triggers a
LocalAuthentication prompt. That would be one Touch ID per `ssh`, per
`git commit`, per agent sign — unusable.

The price is paid off by a short-lived in-process cache:

- **TTL** (default 300 s / 5 min; configurable): the wrapping key is
  kept in process memory for this long after a successful load and
  reused for subsequent signs without another keychain round-trip.
- **Memory protection**: the cached key lives in
  `Box<Zeroizing<[u8; 32]>>` (stable heap address, cleared on drop);
  `mlock`ed so it can't be swapped to disk; `munlock` + `zeroize` runs
  on TTL expiry and on process exit. The binary already calls
  `enclaveapp_core::process::harden_process()` at startup, which
  disables core dumps on macOS and Linux.

## User-visible behavior

Typical day, with an agent running at login:

- `ssh host1` — Touch ID prompt. Tap.
- `ssh host2`, `scp ...`, `git push` within 5 minutes — silent.
- Coffee break. TTL expires.
- `ssh host3` — Touch ID prompt again.
- Rebuild sshenc-agent and restart it — one Touch ID prompt on next
  sign. (No password prompt, no rebuild-ACL pain.)

## Threat model

Protected against:

- Same-UID attacker that reads the `.handle` file directly — still
  needs the wrapping key, which now requires user presence.
- Same-UID attacker that tries to hit the keychain item directly —
  gets a LocalAuthentication prompt they can't satisfy without the
  user's finger or passcode.
- Swap/disk inspection — cached wrapping key is `mlock`ed.
- Core dump inspection — `RLIMIT_CORE=0` (mac) / `PR_SET_DUMPABLE=0`
  (Linux) from `harden_process()`.

Not protected against:

- Same-UID attacker with `task_for_pid` debug entitlement / ptrace
  privileges — can read live process memory, including the cached
  wrapping key during its TTL window. This attacker also wins against
  any SSH agent; it's inherently outside the scope of an agent
  architecture.
- Offline physical attack on a signed-in, unlocked machine — same
  caveat.

## Configuration

`~/.config/sshenc/config.toml`:

```toml
# Cache a loaded wrapping key for this many seconds before the next
# sign re-prompts for Touch ID. 0 disables the cache (every sign
# prompts). Default: 300 (5 min, matches Apple's
# LATouchIDAuthenticationMaximumAllowableReuseDuration).
wrapping_key_cache_ttl_secs = 300
```

Environment override, useful for testing or strict modes:

```
SSHENC_WRAPPING_KEY_CACHE_TTL_SECS=0   # prompt every sign
SSHENC_WRAPPING_KEY_CACHE_TTL_SECS=900 # cache for 15 min
```

## Interaction with existing keys

Existing keychain items created before this change were stored under
the legacy code-signature ACL and **continue to behave that way**
until they are rotated. A user who does `sshenc delete <label>` +
`sshenc keygen --label <label>` will get a userPresence-protected
wrapping key; otherwise their existing keys still prompt for the
login password on binary rebuilds.

Future follow-up: `sshenc rotate <label>` would migrate an existing
key's wrapping entry from legacy-ACL to userPresence without touching
the SE key material. Not yet implemented.

## Interaction with stable code signing

When sshenc is eventually distributed under a stable Developer ID,
the codesig-based ACL never invalidates either, which would also
eliminate the rebuild prompts for that specific case. This design
removes the dependence on that code signing rolling out — unsigned
and signed builds both behave correctly — which is why it's
preferred over "just sign everything."
