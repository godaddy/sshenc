# macOS unsigned UX

Status: empirical — recorded April 27, 2026 against macOS 26.4.1 on
Apple Silicon, fresh `cargo build --release` of `sshenc-agent`,
`sshenc`, `sshenc-keygen`, and `gitenc`. Apple's only signature is the
linker's ad-hoc one (`Signature=adhoc`, `TeamIdentifier=not set`).

This document is a counterpart to `wrapping-key-cache.md`. That doc
describes how the design is *meant* to behave on macOS. This one
records how the unsigned build actually behaves on real hardware
today, including a gap between the two.

## Test setup

- Isolated `$HOME` sandbox so the user's real keys were untouched.
- One `sshenc-agent` started in foreground on a sandbox socket. No
  startup prompt.
- Two keys generated for the matrix: `uxtest1` with
  `--require-user-presence`, `uxtest_nopresence` without.

## Observed prompt counts and latencies

| Step | Touch ID? | Password dialog? | Latency |
|---|---|---|---|
| `sshenc-agent` startup | no | no | < 50 ms |
| `keygen` (no presence) | no | no | 0.12 s |
| `keygen --require-user-presence` | no | no | 0.56 s; **but** see "wrapping-key ACL fallback" below |
| `list` / `inspect` | no | no | < 50 ms |
| `sign` (no-presence key) | no | no | 13–40 ms |
| `sign` (presence key, cold) | yes | no | 3.0 s |
| `sign` (presence key, warm) | **yes per sign** | no | ~ 1.3 s |
| 12 signs in a row, presence key | **12 fingerprints** | no | ~ 16 s total |
| 5 signs, no-presence key | no | no | ~ 70 ms total |
| First sign after binary rebuild (different cdhash) | no | **yes — login password** | 9.2 s |
| `sshenc delete <label>` after rebuild | no | **yes — login password** | similar |
| Sign after agent restart with same binary | yes | no | 1.9 s; keys persist |

Live-verified by the user during the session: the 12-signs-in-a-row
case prompted Touch ID 12 times, and the post-rebuild sign asked for
the login password (not Touch ID).

## Wrapping-key ACL fallback (the unsigned-only bug)

On every `keygen` (with or without user-presence flag), the agent
logged:

```
enclaveapp: wrapping-key userPresence ACL rejected (OSStatus=-50);
  falling back to non-userPresence storage —
  userPresence gate won't fire for this key
```

`OSStatus=-50` is `errSecParam`. Apple's `kSecAttrAccessControl` with
`.userPresence` requires storing the keychain item in the
**data-protection keychain**. That keychain rejects items from
processes that don't carry the right entitlements (specifically a
`keychain-access-groups` entitlement signed into the binary, which
needs a stable Developer ID + provisioning profile). Linker-adhoc
signatures don't qualify, so the install is rejected and the agent
falls back to the legacy file-based keychain — bound to the calling
binary's code-signing identity, i.e. the ad-hoc cdhash.

Consequences on the unsigned build:

1. The *wrapping-key* protection promised in `wrapping-key-cache.md`
   ("userPresence ACL — tied to the user, not the binary") does **not
   apply**. The wrapping-key item is back to the pre-fix legacy ACL.
2. The *SE private key itself* is unaffected — its access policy is
   enforced by the Secure Enclave Processor in hardware regardless of
   binary signing. `--require-user-presence` keys still prompt Touch
   ID per sign, correctly.
3. Every cdhash change re-triggers the legacy "Allow / Always Allow /
   Deny" + login-password dialog the first time a wrapping key is
   loaded under the new identity. That's the 9-second outlier above.

The CLI still prints `User presence: required` for `uxtest1` after
the fallback. That label is correct for the SE key, misleading for
the wrapping key.

## What the wrapping-key cache actually does today

`wrapping_key_cache_ttl_secs` (default 300) caches the loaded
wrapping key in `mlock`-ed, zeroize-on-drop process memory and reuses
it for subsequent signs without a keychain round-trip.

What it covers:

- Multiple signs of a **no-presence** SE key within the TTL — silent,
  ~15 ms each.
- Avoiding repeated keychain access dialogs *within one process
  lifetime* on rebuild day, after the first dialog has been answered.

What it does **not** cover:

- SE keys with `--require-user-presence`. The SEP-level access
  policy fires every sign, independent of the wrapping-key cache,
  because there is no long-lived `LAContext` passed to CryptoKit's
  `SecureEnclave.P256.Signing.PrivateKey.signature(for:)`. Each sign
  constructs an implicit fresh context and re-prompts. Apple's
  `LATouchIDAuthenticationMaximumAllowableReuseDuration` is documented
  to deduplicate prompts within a window, but only via a reused
  context — there is no such reuse here today.
- The first sign after a binary update. The cache is empty, the
  legacy-ACL load triggers the password dialog regardless.

## User-visible UX, summarised

Convenience-prioritised path (`sshenc keygen <label>`, no flag):

- Generation, list, inspect: silent.
- Signing: silent and fast (~15 ms).
- Binary update: one login-password dialog on first sign after the
  update, then silent again.

Security-prioritised path (`sshenc keygen <label>
--require-user-presence`):

- Generation: silent, but the wrapping-key ACL fallback fires and is
  only visible in `stderr`. The CLI does not surface this to the
  user.
- Signing: **one Touch ID per sign**, no batching. 12 git operations
  in a five-minute window cost 12 fingerprints.
- Binary update: one login-password dialog (legacy keychain ACL),
  then back to one fingerprint per sign.

## What still holds

- SE private key never leaves the SEP. Hardware-enforced regardless
  of binary signing.
- `--require-user-presence` is honoured at the hardware layer for
  every sign — not theatrical.
- Keys persist across `cargo install` / `brew upgrade` /
  `sshenc-agent` restart. No re-pairing needed beyond the one-time
  legacy-ACL re-authorisation.
- Trusted-binary peer check (`sshenc-agent/src/server.rs` ~line 432)
  is logging-only, so binary updates do not break clients there.
- Wrapping key on disk-protected: `mlock`-ed and zeroized on drop.

## Where the convenience cost lives, and what fixes it

Two changes shift the curve substantially.

### 1. Reusable `LAContext` for SE signing

Modify `enclaveapp_se_sign`
(`libenclaveapp/crates/enclaveapp-apple/swift/bridge.swift`) to accept
an `LAContext` whose `touchIDAuthenticationAllowableReuseDuration` is
set to `wrapping_key_cache_ttl_secs`. Pass it to
`SecureEnclave.P256.Signing.PrivateKey(dataRepresentation:authenticationContext:)`.
Authenticate the context once per cache-TTL window. Within that
window, multiple SE signs reuse the same authentication and skip the
prompt — Apple's documented mechanism.

Result: 12 git operations within five minutes = 1 fingerprint, not
12. Same TTL knob already exposed; same threat model already accepted
("same-UID attacker with `task_for_pid` wins anyway, outside agent
scope").

User presence with cached LAContext becomes the **default** at
`keygen` time. Two opt-outs at either end of the spectrum:

```sh
sshenc keygen --label work
# default: user presence required, cached
# → one fingerprint per cache-TTL window (default 5 min)

sshenc keygen --label highvalue --strict
# → one fingerprint per signature, no batching

sshenc keygen --label automation --no-user-presence
# → no fingerprint required at all (not default; explicit opt-out)
```

The flag (default / `--strict` / `--no-user-presence`) is recorded
in the key's `.meta` file so the agent enforces it at sign time
independently of the per-process or global prompt policy. A separate
global override (`prompt_policy = "always"`) remains available to
force strict behaviour for every key on the agent.

This is a breaking change for keygen defaults: the previous default
was no-presence, with `--require-user-presence` as the opt-in. Old
keys keep behaving the way they were created (the policy is in the
`.meta` file). New `keygen` invocations without flags get the new
secure default.

### 2. Stable Developer ID code signing

Solves both unsigned-only problems:

- The wrapping-key `.userPresence` ACL would actually install (no
  more `errSecParam` fallback), restoring the second presence layer
  the design intended.
- The legacy ACL's dependency on cdhash goes away in favour of team
  identity, so the post-update password dialog disappears.

The current architecture comment at
`libenclaveapp/crates/enclaveapp-app-storage/src/lib.rs` ~line 95
frames the userPresence-ACL design as a way to *escape* code-signature
binding. That stops being the right framing once the binary is signed
under a stable Developer ID; signing makes the legacy ACL benign and
re-enables the data-protection-keychain path simultaneously.

## Cleanup notes

The agent-side `sshenc delete <label>` triggers the legacy-keychain
dialog whenever cdhash has changed since the wrapping key was
created. Two ways to clean up orphaned wrapping-key items by hand:

```sh
security delete-generic-password \
  -s "com.sshenc.wrappingkey" -a "com.sshenc.key.<label>"
```

Orphaned SEP keys do not consume meaningful space and are tolerable.
