# Deep Review Action Plan — 2026-05-06

Findings from a multi-pass deep review of `sshenc` and `libenclaveapp`.
Each item lists the affected files, the fix, and acceptance criteria so
the work can be picked up and merged independently.

Severity: **Blocker** = ship-stopper or threat-model contradiction;
**Suggestion** = improvement, not a release gate.

Repos:
- `sshenc/` = `/Users/jgowdy/enclaveapps/sshenc`
- `libenclaveapp/` = `/Users/jgowdy/enclaveapps/libenclaveapp`

## Status (2026-05-06 → 2026-05-06+)

All blockers and suggestions in this document have been addressed
on branch `deep-review-fixes` in both repos. Each item is annotated
inline with **Status** below. Run summary:

| ID | Title                                              | Status   | Commit (sshenc / libenclaveapp)              |
| -- | -------------------------------------------------- | -------- | -------------------------------------------- |
| B1 | Meta HMAC sidecar bypassable by sidecar delete     | **DONE** | libenclaveapp 43ae0b4 + sshenc f9281cc       |
| B2 | Bridge response size cap unenforced                | **DONE** | libenclaveapp 3bf820b                        |
| B3 | Threat model overstates Windows peer enforcement   | **DONE (doc)** | sshenc 613864f                         |
| B4 | Peer-binary allowlist threat-model overstatement   | **DONE (doc)** | sshenc 613864f                         |
| B5 | AgentProxyBackend rename leaks cached artifacts    | **DONE** | sshenc 3ff4f4c                               |
| S1 | `update_allowed_signers` swallows errors           | **DONE** | sshenc 856711c                               |
| S2 | `ssh_sig_to_der` DER length `as u8`                | **DONE** | sshenc c7ab6bd                               |
| S3 | Apple `data_rep` not zeroizing                     | **DONE** | libenclaveapp 47e0f8f                        |
| S4 | Linux TPM silent fallback to keyring               | **DONE** | libenclaveapp fdc2b5a                        |
| S5 | gitenc nudge sentinel write swallows errors        | **DONE** | sshenc c7d847e                               |
| S6 | SSH protocol parser malformed-input test coverage  | **DONE** | sshenc ae52798                               |
| S7 | Bridge fuzz target                                 | **DONE** | sshenc ca20149 + libenclaveapp 4fe6236       |

Test/lint baseline at branch tip:

```
sshenc:        cargo build/test/clippy/fmt all clean
libenclaveapp: cargo build/test/clippy/fmt all clean
fuzz_bridge_response: ~960k iters in 11s, no findings
```

Pre-existing daemon-test flakiness in
`enclaveapp_core::daemon::tests` under high parallelism is
unchanged by this branch — those tests pass in isolation /
serial.

Threat-model edits required (listed below) all landed in sshenc 613864f.

---

## Blockers

### B1. Meta HMAC sidecar can be bypassed by deleting the sidecar — **DONE**

> **Status:** Fixed in libenclaveapp `43ae0b4` (+ sshenc `f9281cc`
> for the propagated rename signature). `MetaIntegrityMode` enum
> added; `load_meta_with_hmac` now defaults to `RequireSidecar` for
> production callers. `migrate_meta_to_hmac` exposed for explicit
> migration. `enclaveapp-app-storage::encryption::ensure_key`
> auto-migrates on first load with a `warn!` log. `rename_key_files`
> grew an `hmac_key: Option<&[u8]>` parameter and recomputes the
> sidecar after relabeling. Tests:
> `meta_hmac_strict_rejects_missing_sidecar`,
> `meta_hmac_legacy_mode_accepts_missing_sidecar`,
> `migrate_meta_to_hmac_writes_sidecar_for_legacy_meta`,
> `migrate_meta_to_hmac_errors_for_missing_meta`,
> `rename_key_files_with_sidecar_recomputes_hmac_under_new_label`,
> `rename_key_files_with_sidecar_requires_hmac_key`. Threat-model
> language updated in sshenc `613864f`.

- **Files:** `libenclaveapp/crates/enclaveapp-core/src/metadata.rs:294-318`
- **Reference:** threat-model claim at `sshenc/THREAT_MODEL.md:360-362`
- **Problem:** `load_meta_with_hmac` accepts `<label>.meta` without
  verification when `<label>.meta.hmac` is missing ("preserves
  migration"). A same-UID attacker just `unlink`s the sidecar, then
  rewrites `.meta`. The threat model claims the attacker is "caught"
  unless they also have keyring access — false.
- **Fix:**
  - Add a `MetaIntegrityMode` argument (`StrictRequireSidecar` |
    `AllowMissingSidecar`).
  - Default callers to `StrictRequireSidecar`. Only the migration path
    (one-time, version-gated) uses `AllowMissingSidecar`, and it must
    immediately re-write a sidecar so subsequent loads are strict.
  - When strict and the sidecar is missing on a backend that should have
    one (keyring available, key was created with HMAC), return
    `Error::KeyOperation { operation: "meta_hmac_verify", … }`.
- **Acceptance:**
  - New unit test: create key with sidecar, delete sidecar, edit
    `.meta`, expect strict load to error.
  - New unit test: legacy meta with no sidecar loads under
    migration mode and a sidecar appears on disk afterward.
  - Threat-model paragraph updated to describe new semantics.

### B2. Bridge response size cap is declared but unenforced — **DONE**

> **Status:** Fixed in libenclaveapp `3bf820b`. Added
> `enclaveapp_core::timeout::LineReaderWithTimeout::with_max_line_bytes`
> backed by a new `read_line_bounded` helper that reads via
> `BufRead::fill_buf` / `consume` and aborts with `InvalidData`
> when the cap is reached before a newline. Bridge client now
> constructs the reader via that constructor with the existing
> `MAX_BRIDGE_RESPONSE_BYTES` constant; the post-read length check
> is removed. Cap-hit errors surface as a typed
> `KeyOperation { operation: "bridge_read", … }` and the child is
> killed before returning. Tests:
> `bounded_line_reader_aborts_when_line_exceeds_cap`,
> `bounded_line_reader_accepts_line_within_cap`. The fuzz target
> in S7 also exercises this path.

- **Files:**
  - `libenclaveapp/crates/enclaveapp-bridge/src/client.rs:17`
    declares `MAX_BRIDGE_RESPONSE_BYTES = 64 * 1024`
  - `libenclaveapp/crates/enclaveapp-core/src/timeout.rs:151-179`
    (`LineReaderWithTimeout` calls `BufReader::read_line` with no cap)
- **Problem:** A compromised Windows-side bridge can return an
  arbitrarily long JSON line; the WSL client allocates and `serde_json`-
  parses it without bound. DoS / heap-exhaustion vector.
- **Fix (pick one):**
  - Add a `read_line_bounded(&mut String, max: usize)` helper to
    `enclaveapp-core::timeout`, swap `LineReaderWithTimeout` to use it,
    plumb `MAX_BRIDGE_RESPONSE_BYTES` through.
  - Return a typed `Error::BridgeResponseTooLarge { read: usize, cap:
    usize }` (or equivalent) and surface a clear log line.
- **Acceptance:**
  - New unit test in `enclaveapp-bridge`: feed a fake reader that emits
    `MAX + 1` bytes before the newline; expect the bounded error and
    no allocation past the cap.
  - The `MAX_BRIDGE_RESPONSE_BYTES` constant must be read from at least
    one production code path (no dead-code warning suppression).

### B3. Threat model overstates Windows peer-identity enforcement — **DONE (doc path)**

> **Status:** Fixed in sshenc `613864f` via the document path —
> the "Agent Socket Abuse" section is now split into "Mitigations
> (Unix)" and "Mitigations (Windows native — named pipe + AF_UNIX
> bridge)" subsections that accurately describe each platform's
> enforcement. The Windows code paths still do **not** run a
> peer-SID check, the rate limiter, or the binary heuristic; that
> implementation gap is now explicit in the residual-risk bullet
> rather than hidden under wording that implied uniformity. The
> "implement" path (peer-SID via `GetNamedPipeClientProcessId` +
> `OpenProcessToken`) remains a follow-up — it touches the agent
> hot path on a platform I can't smoke-test from this
> workstation, and should land as its own change with Windows CI
> green.

- **Files:**
  - `sshenc/THREAT_MODEL.md:72-89` (the "Agent Socket Abuse" section)
  - `sshenc/crates/sshenc-agent/src/server.rs:178-190` (Unix path —
    correct)
  - `sshenc/crates/sshenc-agent/src/server.rs:339-359` (Windows AF_UNIX
    bridge — no peer-UID, no rate limiter, no binary check)
  - `sshenc/crates/sshenc-agent/src/server.rs:362-380` (Windows named
    pipe — no peer-UID, no rate limiter, no binary check)
- **Problem:** Threat model reads as if `SO_PEERCRED`-style checks, the
  rate limiter, and the binary allowlist apply uniformly. None of the
  three apply on the Windows pipe or the Windows AF_UNIX bridge.
- **Fix (pick one):**
  - **Document:** rewrite the section into Unix vs. Windows
    subsections. Spell out that Windows defends via the named-pipe
    DACL (creator-owner + SYSTEM) and NTFS directory ownership for the
    AF_UNIX socket; explicitly call out that the rate limiter and
    binary allowlist do not run on Windows.
  - **Implement:** add `verify_peer_uid` and a rate limiter to both
    Windows code paths. For the named pipe, use
    `GetNamedPipeClientProcessId` → `OpenProcessToken` → SID compare.
    For AF_UNIX on Windows, the cheapest correct thing is to inherit
    the parent-directory ACL invariant and skip the check explicitly
    with a code comment.
- **Acceptance:**
  - Either the threat-model split lands, or both Windows paths gain
    the checks plus a regression test that a connection from a
    different SID is rejected (skipped on non-Windows).
  - Cross-link the threat-model paragraph to the relevant
    `server.rs` line ranges.

### B4. `verify_peer_binary` allowlist is broader than the threat model claims — **DONE (doc path)**

> **Status:** Fixed in sshenc `613864f` via the document path. A
> new "Peer-binary heuristic (Unix only)" subsection enumerates
> the actual basename allowlist (`ssh`, `ssh-add`, …, `git`,
> `code`, `cursor`) and the failure-open semantics, and reframes
> the check as a tripwire / friction layer rather than a trust
> boundary. The "implement" path — narrowing to canonicalized
> install paths via `bin_discovery::find_trusted_binary` —
> remains an option but is intentionally not taken: the broad
> allowlist exists so legitimate workflows (git over ssh from
> editors, `rsync` etc.) don't break. Tightening the heuristic
> would either still need the broad allowlist for those callers
> or risk regressions.

- **Files:**
  - `sshenc/crates/sshenc-agent/src/server.rs:486-519`
  - `sshenc/THREAT_MODEL.md:82`
- **Problem:** Allowlist is by *file basename* (`ssh`, `git`, `code`,
  `cursor`, …) and is failure-open if the exe path can't be resolved.
  Threat model markets it as "checked against an allowlist of trusted
  `sshenc` install paths."
- **Fix (pick one):**
  - **Document:** reword the threat-model bullet to "best-effort
    deterrent against casual misuse, not a trust boundary." Lower its
    emphasis in the mitigation list.
  - **Implement:** narrow the allowlist to canonicalized install paths
    via `enclaveapp_core::bin_discovery::find_trusted_binary` for the
    `sshenc*`/`gitenc` family and accept the SSH/git family by
    basename-only with a code comment that calls out the soft
    semantics.
- **Acceptance:**
  - Threat model and code agree on what the check actually does.
  - If the implement path is taken, add a test for path-based
    rejection.

### B5. `AgentProxyBackend::rename` does not invalidate the local CLI cache — **DONE**

> **Status:** Fixed in sshenc `3ff4f4c`. Two new helpers on
> `AgentProxyBackend`:
> `drop_cached_artifacts(label)` (extracted from `delete`) and
> `rename_cached_artifacts(old, new)` (renames `<old>.{pub,meta,
> meta.hmac}` and rewrites the new `.meta`'s internal `label`
> field). `rename` now invokes the latter after the agent-side
> rename succeeds. Tests:
> `rename_cached_artifacts_moves_pub_meta_and_sidecar`,
> `rename_cached_artifacts_is_noop_when_source_missing`. The
> proxy intentionally does not re-verify the moved `.meta.hmac`
> sidecar — it doesn't hold the per-app keyring HMAC key; the
> agent-side `rename_key_files` recomputes the authoritative
> sidecar against the agent's own keys_dir.

- **Files:**
  - `sshenc/crates/sshenc-se/src/proxy.rs:479-490` (rename — no cache
    cleanup)
  - `sshenc/crates/sshenc-se/src/proxy.rs:466-475` (delete — does
    cleanup; reference behavior)
- **Problem:** After a successful rename in the WSL→Windows scenario,
  `<old>.pub`, `<old>.meta`, and `<old>.meta.hmac` linger in the CLI
  `keys_dir`; `list` then surfaces a ghost identity. The new label
  also has no local `.pub` cache.
- **Fix:** After `try_rename_via_socket` succeeds, mirror what
  `delete` does: rename the three files
  (`<old>.{pub,meta,meta.hmac}` → `<new>.{pub,meta,meta.hmac}`) with
  NotFound-tolerant error handling.
- **Acceptance:**
  - New unit test (mirroring the existing post-delete cache cleanup
    test) that asserts `<old>.*` are gone and `<new>.*` exist after
    `rename`.
  - Test covers the case where the agent shares `keys_dir` with the
    CLI (rename is a no-op locally because the agent already moved
    the files) so it doesn't regress.

---

## Suggestions

### S1. `update_allowed_signers` swallows write errors and is not atomic — **DONE**

> **Status:** Fixed in sshenc `856711c`. `update_allowed_signers`
> returns `std::io::Result<()>` — its caller in
> `configure_repo_entries` propagates the error through the
> existing `Result<…, String>` contract with the path included.
> Adds a local `write_atomic` helper (write to
> `<file>.<pid>.<nanos>.tmp` with `O_CREAT|O_EXCL`, fsync,
> rename) so a crash mid-write leaves the prior allowed_signers
> intact rather than truncated. Tests:
> `update_allowed_signers_creates_missing_parent_dir`,
> `update_allowed_signers_propagates_write_failure`. Concurrency
> is still last-write-wins at the read-modify-write level — the
> doc explicitly notes that.

- **File:** `sshenc/crates/sshenc-gitenc/src/main.rs:484-495`
- **Problem:** `drop(std::fs::write(...))` silently discards write
  failures. Read-modify-write is non-atomic; concurrent
  `gitenc --config` invocations race.
- **Fix:** Switch to `enclaveapp-core::metadata::atomic_write` (or
  `tempfile::NamedTempFile::persist`) and propagate errors via
  `Result`. Update the call site to surface them.
- **Acceptance:** unit test for write failure (use a read-only
  tempdir) returns the error rather than success.

### S2. `ssh_sig_to_der` writes DER lengths via `as u8` — **DONE**

> **Status:** Fixed in sshenc `c7ab6bd`. Both `ssh_sig_to_der` and
> `write_der_integer` now check `len >= 0x80` and return an
> explicit `Error::Other("…long-form…")` instead of emitting a
> truncated single-byte length prefix. Test:
> `write_der_integer_rejects_oversized_content`. Existing
> P-256 round-trip tests still pass.

- **File:** `sshenc/crates/sshenc-se/src/proxy.rs:535, 551`
- **Problem:** Truncation if reused with non-P-256 inputs. Not
  exploitable today.
- **Fix:** `debug_assert!(content_len < 0x80)`; return
  `Error::Backend("DER length out of single-byte range")` for ≥128.
- **Acceptance:** existing `ssh_sig_to_der_round_trips_known_values`
  still passes; add one test feeding a synthetic >127-byte body and
  expect the typed error.

### S3. Apple `data_rep` handle bytes are not zeroizing — **DONE**

> **Status:** Fixed in libenclaveapp `47e0f8f`. `keychain::load_handle`
> and `load_handle_with_context` now return
> `Zeroizing<Vec<u8>>` so the SE-key reference is wiped on drop.
> Source-compatible with all existing call sites (Deref through
> `Zeroizing` makes `.as_ptr()`, `.len()`, and `&[u8]` parameter
> coercion work unchanged); `sign.rs`, `encrypt.rs`, and the
> remaining `keychain.rs` consumers needed no edits. Generate-side
> `data_rep` is intentionally not wrapped — it lives across one
> synchronous wrap call site and is consumed immediately, a
> smaller window than the load path that fires on every
> sign/encrypt/decrypt.

- **Files:**
  - `libenclaveapp/crates/enclaveapp-apple/src/keychain.rs:54, 80-81`
  - `libenclaveapp/crates/enclaveapp-apple/src/sign.rs:56-78`
- **Problem:** The `data_rep` handle (an SE-key reference) is returned
  as a plain `Vec<u8>`. Per
  `references/security-critical-rust.md`, key-material-adjacent
  buffers should zeroize on drop.
- **Fix:** Wrap the returning function signatures in
  `Zeroizing<Vec<u8>>`; update callers (`sign_inner`, encrypt path)
  to consume `Zeroizing` and not re-clone.
- **Acceptance:** `cargo build` passes on macOS; manual review that
  no `.to_vec()` / `.clone()` re-introduces unzeroizing copies.

### S4. Linux TPM→keyring fallback is silent on transient TPM unavailability — **DONE**

> **Status:** Fixed in libenclaveapp `fdc2b5a`. New
> `enclaveapp_app_storage::backend_marker` (Linux-only) records
> the chosen backend in `~/.config/<app>/.backend`.
> `AppSigningBackend::init_linux` now reads that marker and, if
> the prior choice was `Tpm` while the current run sees TPM as
> unavailable, returns a typed `KeyInitFailed` error with
> recovery instructions instead of silently falling back to
> keyring. Successful inits write/refresh the marker. Tests:
> `read_returns_none_when_marker_absent`,
> `write_then_read_roundtrips_each_kind`,
> `read_returns_none_for_unrecognized_kind`,
> `write_overwrites_existing_marker`. The encryption-side
> `init_linux` could adopt the same pattern in a follow-up if
> the bug class shows up there too — out of scope for this PR.

- **Files:**
  - `libenclaveapp/crates/enclaveapp-app-storage/src/signing.rs:226-243`
  - `libenclaveapp/crates/enclaveapp-linux-tpm/src/lib.rs:35-44`
- **Problem:** A key created on TPM, then loaded after the TPM
  becomes transiently unavailable, silently downgrades to keyring.
  Sign then fails with a confusing error.
- **Fix:** Persist the chosen backend (e.g. one-line file
  `~/.config/sshenc/.backend`, or a field in the `.meta` JSON) at
  init time and refuse to fall back on subsequent inits if it
  disagrees. Surface a clear "TPM was used previously but is now
  unavailable" error.
- **Acceptance:** unit test that swaps `is_available` to `false`
  on a second init and expects an explicit error rather than a
  silent backend swap.

### S5. gitenc nudge sentinel write swallows errors — **DONE**

> **Status:** Fixed in sshenc `c7d847e`. `maybe_print_config_hint`
> still drops sentinel-write failures silently in the default
> case (matching the fire-and-forget UX intent), but now emits a
> single `eprintln!` with the path and error when
> `GITENC_DEBUG=1` is set. Lets a power user diagnose why the
> tip is re-printing on every gitenc run without spamming
> normal stderr. No new tests — the path is purely diagnostic
> output and not a contract.

- **File:** `sshenc/crates/sshenc-gitenc/src/main.rs:180`
- **Problem:** `drop(touch_sentinel(&sentinel))`: if the sentinel
  directory is read-only, the nudge prints on every invocation.
  Mild UX; not a defect.
- **Fix:** Log at debug to stderr when the sentinel write fails.
- **Acceptance:** ad-hoc — manual test by chmod'ing the sentinel
  parent.

### S6. Test coverage for SSH protocol parser — **DONE**

> **Status:** Fixed in sshenc `ae52798`. Added 11 malformed-input
> tests against `sshenc_agent_proto::message::parse_request` and
> `parse_response` covering: empty payload (both directions),
> truncated identity-answer count, `nkeys=0` clean-empty path,
> `nkeys > MAX_KEYS` rejection before allocation, truncated body
> after count, short string-length-prefix, missing flags field,
> truncated SIGN_RESPONSE, unknown msg type, etc. The parser
> already returned errors for these — the tests lock the
> contract so future changes can't silently weaken it.

- **Files:** `sshenc/crates/sshenc-agent-proto/src/message.rs`
- **Problem:** No tests for truncated nested SSH strings inside an
  identities answer or sign request, or for `nkeys = 0` edge.
- **Fix:** Add 3-5 unit tests for malformed/truncated/zero-length
  cases. The parser already returns errors; we just need to lock
  the contract.
- **Acceptance:** `cargo test -p sshenc-agent-proto` adds the new
  tests; behavior unchanged.

### S7. Bridge protocol fuzzing — **DONE**

> **Status:** Fixed in sshenc `ca20149` (+ libenclaveapp `4fe6236`
> which made `read_line_bounded` `pub` so the harness can
> exercise it directly). New `fuzz_bridge_response` libfuzzer
> target lives at `sshenc/fuzz/fuzz_targets/bridge_response.rs`,
> wired into `sshenc/fuzz/Cargo.toml`. Pipeline:
> `fuzz_data → BufReader → read_line_bounded(MAX_BRIDGE_RESPONSE_BYTES)
>  → serde_json::from_str::<BridgeResponse>`. Asserts the cap
> invariant on returned line length and that no input panics.
> Verified locally: ~960k iterations in 11s, no findings. Fuzz
> infra `.gitignore` added so `target/`, `corpus/`, `artifacts/`,
> and the generated `Cargo.lock` stay out of the tree.

- **Files:** `libenclaveapp/crates/enclaveapp-bridge/`
- **Problem:** Bridge JSON-RPC has no fuzz target; B2 motivates one.
- **Fix:** Add a `fuzz/` target (or extend `sshenc/fuzz/`) for
  `enclaveapp_bridge::client::parse_response` analogues. Time-box: a
  short corpus run in CI, longer locally.

---

## Threat-model edits required — **DONE (sshenc 613864f)**

In `sshenc/THREAT_MODEL.md`, after B1-B4 land:

1. **Lines 72-89 ("Agent Socket Abuse"):** split into
   "Mitigations (Unix)" and "Mitigations (Windows)" subsections;
   correct that the rate limiter and binary allowlist do not run on
   Windows.
2. **Line 82:** rewrite "trusted `sshenc` install paths" — this
   check is a basename allowlist that includes `git`, `code`, etc.,
   and is failure-open. Either narrow the code or rewrite the
   prose.
3. **Lines 360-362 ("Metadata File Tamper" → Residual risk):**
   replace the "caught unless attacker has keyring access" sentence
   with the actual semantics after B1 lands.
4. **New residual-risk bullet** under WSL/bridge: response size
   cap (B2) and what it does/does-not protect against.
5. **No update needed for** ready-file symlink, MSI uninstall,
   `AccessPolicy::None`, SK key path, soft-consent removal — those
   are accurate.

---

## Test gaps to close (rolled up) — **all addressed**

- ~~Strict-mode meta HMAC sidecar tests (B1).~~ Done (B1).
- ~~Bridge oversize-response test (B2).~~ Done (B2 unit + S7 fuzz).
- Per-platform peer-identity enforcement test (B3, if implement
  path taken). **Skipped** — deliberately not implemented (the
  doc path was taken). When the implement path lands, this test
  needs to live alongside it.
- ~~Rename cache-cleanup regression test (B5).~~ Done (B5).
- ~~`update_allowed_signers` write-failure + concurrency tests
  (S1).~~ Write-failure done (S1). Concurrency is documented as
  last-write-wins; no test added because reproducing the race
  reliably across platforms isn't worth the test's flakiness
  budget.
- ~~Truncated/zero-length SSH protocol frame tests (S6).~~ Done (S6).

---

## Verification baseline (2026-05-06)

```
cargo build  --workspace                                # both repos: OK
cargo test   --workspace                                # sshenc: 175 pass / libenclaveapp: 486 pass
cargo clippy --workspace --all-targets -- -D warnings   # both repos: OK
```

Not run (need platform/hardware):
- `cargo miri test` on FFI-heavy crates.
- macOS Secure Enclave smoke (`Test-EnclaveApps.ps1` equivalents).
- Windows Hello SK end-to-end (`Test-EnclaveApps.ps1 -StrongSk`).
- Linux TPM smoke against real `/dev/tpmrm0`.

These should be added back to the action plan once they're exercised.

---

## Suggested execution order — **followed**

1. ~~B1 (meta HMAC) — security, small surface area, tests obvious.~~
2. ~~B5 (rename cache) — small, removes a real WSL ghost-entry bug.~~
3. ~~B2 (bridge size cap) — small + adds the missing fuzz target (S7).~~
4. ~~B3 + B4 + threat-model edits — bundle as one "threat-model
   reconciliation" PR; pick document-vs-implement per item.~~ Both
   B3 and B4 took the document path; `verify_peer_uid` /
   `RateLimiter` on Windows is queued as follow-up work.
5. ~~S1 (allowed_signers) — small, removes silent-failure footgun.~~
6. ~~S2, S3, S4, S5, S6 — opportunistic.~~ All landed; S7 (fuzz)
   landed last as the final commit on the branch.

## Follow-ups deferred to separate work

- **Windows peer-SID enforcement + rate limiter** in
  `sshenc-agent/src/server.rs` (the "implement" path of B3).
  Touches the agent hot path on a platform that needs Windows CI
  to validate; out of scope for the doc-reconciliation pass.
- **Encryption-side Linux backend marker.** S4 added the marker
  for `AppSigningBackend::init_linux` only. The encryption-side
  `init_linux` has the same silent-fallback shape and could
  adopt `backend_marker` symmetrically. Not done here because
  no consumer of the encryption side has reported the bug class
  yet — encrypt/decrypt against a stale TPM key fails in a more
  visible way than `sign` does.
- **Tightening `verify_peer_binary` to canonicalized install
  paths** (the "implement" path of B4). Intentionally deferred —
  the broad allowlist is load-bearing for `git`, `code`,
  `cursor`, `rsync` etc.
