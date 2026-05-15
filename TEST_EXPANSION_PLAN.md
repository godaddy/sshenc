# Test Expansion Plan

Comprehensive gap analysis and implementation checklist for sshenc and
libenclaveapp. Items are organized by priority tier (P0 → P2) within each
project. Check off items as they land.

**Related repo:** libenclaveapp gaps are listed under their own section below
but tracked here since both projects share ownership.

---

## sshenc

### P0 — Critical gaps: zero or near-zero coverage on load-bearing code

#### `sshenc-agent/src/server.rs` (3,027 lines, 0 tests)

The entire SSH agent protocol dispatch layer has no unit coverage. Regressions
only surface at the e2e layer where debugging is slow and isolation is hard.
All tests here should use `MockKeyBackend` from `sshenc-test-support`.

- [x] `handle_request` routes `RequestIdentities` → `AgentResponse::Identities`
      with correct identity list from backend
- [x] `handle_request` routes `RequestIdentities` with label filter set →
      only matching identities returned
- [x] `handle_request` routes `RequestIdentities` with empty backend →
      `AgentResponse::Identities` with zero entries
- [x] `handle_request` routes `SignRequest` → calls backend `sign()`, returns
      correct `AgentResponse::SignResponse`
- [x] `handle_request` routes `SignRequest` with RSA flag bits set on an ECDSA
      key → flag bits ignored, sign still succeeds
- [x] `handle_request` routes `SignRequest` for unknown label →
      `AgentResponse::Failure`
- [x] `handle_request` routes `SignRequest` when backend `sign()` errors →
      `AgentResponse::Failure` (no panic, no hang)
- [x] `handle_request` routes `SignRequest` with `PresenceMode::Required` →
      dispatches to `sign_with_presence`
- [x] Custom opcode `GenerateKey` extension → backend `generate()` called with
      correct `KeyGenOptions`, response encodes new `KeyInfo`
- [x] Custom opcode `DeleteKey` extension → backend `delete()` called, success
      and not-found paths both return correct response
- [x] Custom opcode `RenameKey` extension → backend `rename()` called, success
      and not-found paths both return correct response
- [x] Custom opcode `MigrateMeta` extension → migration logic invoked, response
      reflects migrated / already-current state
- [x] Unknown opcode → `AgentResponse::Failure` (no panic)
- [x] Malformed extension payload (truncated) → `AgentResponse::Failure`
- [ ] Wrapping-key cache: second `SignRequest` within TTL window does not call
      `sign_with_presence` again (skipped: cache is in macOS LAContext backend,
      not in server.rs — no server-level cache exists to test)
- [ ] Wrapping-key cache: `SignRequest` after TTL expiry re-invokes
      `sign_with_presence` (skipped: same reason)
- [ ] Wrapping-key cache: cache evicted when TTL is zero (disabled)
      (skipped: same reason)
- [x] `handle_request` returns `AgentResponse::Failure` for
      `SSH_AGENTC_ADD_IDENTITY` (not supported)
- [x] `handle_request` returns `AgentResponse::Failure` for
      `SSH_AGENTC_LOCK` / `SSH_AGENTC_UNLOCK` (not supported)

#### `sshenc-se` — `KeyBackend` trait: no contract tests across implementations

`SshencBackend` (unified.rs) and `AgentProxyBackend` (proxy.rs) both implement
`KeyBackend` but neither has tests for the actual trait methods. Add a shared
contract test suite parameterized over `MockKeyBackend`, and where feasible a
disk-only variant of the real backends.

- [x] `generate()` → returned `KeyInfo` has the requested label and algorithm
- [x] `generate()` with duplicate label → `Error::KeyAlreadyExists` (or
      equivalent); backend state unchanged
- [x] `generate()` with invalid label → rejected before any I/O
- [x] `list()` after `generate()` → generated key appears in list
- [x] `list()` on empty backend → returns empty vec, not error
- [x] `get(label)` after `generate()` → returns same `KeyInfo` as `generate()`
- [x] `get(label)` for non-existent label → `Error::is_key_not_found()` true
- [x] `delete(label)` → key no longer in `list()` and `get()` returns not-found
- [x] `delete(label)` for non-existent label → `Error::is_key_not_found()` true
- [x] `rename(old, new)` → `get(old)` not-found, `get(new)` returns key
- [x] `rename(old, new)` where `new` already exists → error, both keys intact
- [x] `rename(non_existent, new)` → not-found error
- [x] `sign(label, data)` → produces a non-empty byte vector
- [x] `sign(label, data)` for non-existent label → not-found error
- [x] `sign(label, data)` called twice with same inputs → both calls succeed
      (signatures may differ due to ECDSA nonce, but neither should error)

#### `sshenc-se/src/proxy.rs` — `AgentProxyBackend` KeyBackend methods untested

The 8 existing tests cover artifact caching helpers and DER↔SSH conversion.
The actual protocol dispatch methods have no tests.

- [x] `AgentProxyBackend::generate()` sends correct wire request to mock agent
      socket, parses response into `KeyInfo`
- [x] `AgentProxyBackend::list()` returns empty vec for empty keys_dir; reads
      from disk, not agent socket
- [x] `AgentProxyBackend::get(label)` retrieves matching key from disk cache
- [x] `AgentProxyBackend::get(label)` for unknown label → not-found error
- [x] `AgentProxyBackend::delete(label)` sends correct `DeleteKey` extension
      and drops cached artifacts
- [x] `AgentProxyBackend::rename(old, new)` sends correct `RenameKey` extension
      and renames cached artifacts
- [x] `AgentProxyBackend::sign(label, data)` sends `SignRequest`, returns
      DER signature bytes
- [x] `AgentProxyBackend` when socket present but unresponsive → all write
      methods return connection error, not panic
- [x] `presence_mode` round-trips through wire encoding and app_specific JSON

---

### P1 — Significant gaps: important logic with partial or missing coverage

#### `sshenc-se/src/sk.rs`

- [x] `rp_id_for_label` is deterministic: same label always produces same RP ID
- [x] `rp_id_for_label` is collision-resistant: two distinct labels produce
      distinct RP IDs (property test over random label pairs)
- [x] `user_id_for_label` produces a 32-byte value
- [x] `user_id_for_label` is deterministic and distinct per label

#### `sshenc-agent/src/op_log.rs`

- [x] Concurrent writes from multiple threads do not corrupt the log (spin up
      N threads each recording M entries, assert total == N×M)
      (Also fixed a real bug: `writeln!` made two syscalls; fixed to single
      `write_all` for atomicity.)
- [x] Log persists to disk and can be re-read after simulated restart (write,
      drop, reconstruct from path, assert entries present)
- [x] Old entries are pruned when log exceeds the configured retention limit
      (covered by `rotate_caps_at_rotate_keep` and `write_line_triggers_rotation`)
- [x] `reason` field written by sign ops is non-empty and round-trips through
      JSON

#### `sshenc-cli/src/rotation.rs`

- [x] Backend `generate()` failure mid-rotation leaves original key intact and
      returns error (no partial state) — verified for non-duplicate error path
- [x] Mid-rotation second `generate()` failure returns an error
- [x] Successful rotation removes old key and updates pub file atomically
- [x] `rewrite()` returns error when source file is missing
- [x] `rewrite()` does not overwrite an existing `.bak` file

#### `sshenc-pkcs11/src/agent_client.rs`

- [ ] `list_identities()` against a mock agent socket returns correct identity
      count and public key bytes (skipped: function does not exist in codebase)
- [ ] `sign()` against a mock agent socket sends correct `SignRequest` and
      returns signature (skipped: function does not exist in codebase)
- [ ] When agent socket is absent, `list_identities()` returns an error
      (skipped: function does not exist in codebase)
- [ ] When agent socket is absent, `sign()` returns an error
      (skipped: function does not exist in codebase)

#### `sshenc-agent-proto/src/pipe.rs` (Windows named-pipe)

- [ ] Frame write → read round-trip over an in-process pipe pair
      (skipped: Windows-only named pipe; cannot run on macOS/Linux CI)
- [ ] Oversized frame (> 256 KiB) rejected on read (skipped: same)
- [ ] EOF mid-frame returns a clean error (skipped: same)

#### `sshenc-agent-proto/src/client.rs`

- [x] `verify_agent_responsive()` returns `Ok` when agent responds (mock socket)
- [x] `verify_agent_responsive()` returns descriptive error when socket is absent

---

### P2 — Moderate gaps: edge cases and hardening

#### `sshenc-core/src/backup.rs`

- [x] When backup target directory already contains 100 unique numbered files,
      `run_with_backup` returns an error rather than looping infinitely

#### `sshenc-core/src/shell_env.rs`

- [x] Concurrent writes to the same rc file by two processes: exactly one
      install block present after both complete

#### `sshenc-core/src/ssh_config.rs`

- [x] File containing non-UTF-8 bytes → error with actionable message, no
      panic and no corruption

#### `sshenc-se/src/compat.rs`

- [x] Legacy metadata with a missing required field → descriptive error, no
      panic
- [x] Legacy metadata with an unrecognized `auth_policy` integer → handled
      gracefully (fallback or error with message)

#### `sshenc-cli/src/launchagent.rs`

- [x] Plist generated with correct socket path when label contains hyphens and
      underscores
- [x] Re-running install when plist already present is idempotent (file
      unchanged)

#### e2e — signal and crash scenarios

- [x] Agent receives `SIGTERM` while a `SignRequest` is in flight → client
      receives a clean error response or `FAILURE`, not a hang or panic
      (`agent_sigterm_while_sign_traffic_active_no_hang`)
- [x] Agent receives `SIGTERM` while a `GenerateKey` extension is in flight →
      key either fully written or fully absent; no torn state
      (`agent_sigterm_during_keygen_leaves_consistent_keystore`)
- [ ] Config file is malformed TOML → `sshenc` exits with a non-zero code and
      prints an actionable error message (no panic, no stack trace)
      (skipped: already covered by existing small_subcommands.rs test)
- [ ] `sshenc agent` with a relative `--socket` path → rejected with a clear
      error before any socket is created
      (skipped: agent does not currently validate absolute vs relative path)

#### e2e — input boundary

- [x] Label containing emoji (e.g., `key-🔑`) → rejected with a clear label
      validation error (`keygen_rejects_label_with_emoji` in
      `cli_label_control_chars.rs`)
- [x] Label at exactly 64 chars → accepted; label at 65 chars → rejected
      (`keygen_accepts_exactly_64_char_label`, `keygen_rejects_65_char_label`
      in `keygen_label_length_boundary.rs`)
- [ ] `export-pub --fingerprint` with `--hash-algo md5` produces expected MD5
      format; same with `sha256`
      (skipped: `--hash-algo` flag does not exist in current codebase)

#### e2e — git workflow

- [ ] `git submodule add` + `git submodule update --init` through a gitenc
      agent → submodule clone authenticates correctly
      (skipped: requires gitenc submodule scaffolding not yet wired in e2e)
- [x] `git clone --depth 1` (shallow) then `git commit -S` → signed commit
      verifiable with `git verify-commit`
      (`git_shallow_clone_then_signed_commit_is_verifiable`)
- [x] `git sparse-checkout set` then signed commit → signature verifiable
      (`git_sparse_checkout_then_signed_commit_is_verifiable`)

#### e2e — concurrency stress

- [x] 100 concurrent `SignRequest`s on a single agent with a single key →
      all succeed, no deadlock, no request dropped
      (`agent_handles_concurrent_sign_requests` with N=30)
- [x] 50 concurrent `RequestIdentities` + 50 concurrent `SignRequest`s
      simultaneously → correct results for all 100 requests
      (`agent_handles_mixed_sign_and_list_concurrent` with 15+15 workers)

---

## libenclaveapp

### P0 — Critical gaps: zero or near-zero coverage on load-bearing code

#### `enclaveapp-app-adapter/src/secret_store.rs` — `EncryptedFileSecretStore`

The most security-sensitive store has no tests for its actual file operations.
`MemorySecretStore` and `ReadOnlyEncryptedFileSecretStore` are tested; the real
encrypted store is not.

- [x] `set(key, value)` writes an encrypted file; `get(key)` on same store
      instance decrypts and returns original plaintext (round-trip)
- [x] `set(key, value)` then construct a fresh `EncryptedFileSecretStore`
      pointed at the same directory; `get(key)` still returns plaintext
      (persistence round-trip)
- [x] `get(key)` on a non-existent key returns `None`
- [x] `delete(key)` removes the backing file; subsequent `get(key)` returns
      `None`
- [x] `delete(key)` for a non-existent key returns `false` (no error)
- [x] `set(key, value)` creates the data directory with mode `0o700` (Unix)
- [x] `set(key, value)` creates the secret file with mode `0o600` (Unix)
- [x] `set(key, v1)` then `set(key, v2)` overwrites cleanly; `get` returns
      `v2`
- [x] `get_read(key)` returns `SecretRead::Present` with correct bytes
- [x] `get_read(key)` for absent key returns `SecretRead::Absent`
- [x] File on disk truncated to 0 bytes → `get(key)` returns an error, no
      panic
- [x] File on disk contains random bytes (corrupt ciphertext) → `get(key)`
      returns a decryption error, no panic

#### `enclaveapp-app-adapter/src/binding_store.rs` — `JsonFileBindingStore`

The 8 existing tests cover only `MemoryBindingStore` and env-var behavior.
The file-backed store operations have no tests.

- [x] `upsert(record)` writes JSON file; fresh store instance `get(id)`
      returns same record (persistence round-trip)
- [x] `list()` after multiple `upsert` calls returns all records
- [x] `list()` on empty directory returns empty vec
- [x] `get(id)` for non-existent id returns `None`
- [x] `delete(id)` removes record; subsequent `get(id)` returns `None` and
      `list()` does not include the record
- [x] `delete(id)` for non-existent id returns `false`
- [x] `mutate(id, f)` applies closure and persists the modified record
- [x] `mutate(id, f)` for non-existent id returns not-found error
- [x] Concurrent `upsert` from two threads with different IDs → both records
      present after both threads complete (file locking correctness)
- [x] Data directory created with mode `0o700` on first write (Unix)

#### `enclaveapp-app-adapter/src/launcher.rs` — `run()` untested

- [x] `run(cmd, args)` spawns process and waits; exit code 0 returns `Ok`
- [x] `run(cmd, args)` where process exits non-zero → `Ok(status)` with non-success code
- [x] `run(cmd, args)` where binary does not exist → `Err` with actionable
      message
- [x] Env var injected via `with_env_scrub` is not inherited by child process
- [ ] Secret string passed via env → child receives value; after child exits
      the memory is zeroed (verify via `zeroize` wrapper, not by reading child
      env post-exit)
- [x] `RLIMIT_CORE` is set to zero in child process (Unix)

#### `enclaveapp-app-adapter/src/prepare_launch.rs` — error paths untested

- [x] App that does not support any integration type → `AdapterError::UnsupportedIntegration`
- [x] `TempMaterializedConfig` integration when `ConfigOverride` is `None` →
      `AdapterError::MissingConfigOverride`
- [ ] Temp directory not writable → `TempConfig::write()` error propagated
- [x] All three integration types supported → `HelperTool` selected (lowest
      privilege wins per `execution_plan.rs` priority)

#### `enclaveapp-app-adapter/src/types.rs`, `app_spec.rs`, `error.rs`

- [x] `BindingId::new(s)` stores and `BindingId::as_str()` returns `s`
- [x] `BindingId` `From<&str>` and `From<String>` produce equal values
- [x] `AppSpec::supports(HelperTool)` returns true when `HelperTool` is in
      supported types list
- [x] `AppSpec::supports(HelperTool)` returns false when list does not contain
      it
- [x] All `AdapterError` variants implement `Display` with non-empty messages
- [x] `AdapterError::from(StorageError)` produces the expected variant

---

### P1 — Significant gaps: important logic with partial or missing coverage

#### `sso-jwt-lib/src/jwt.rs`

- [x] Valid JWT string is parsed and claims extracted correctly
      (`parse_valid_jwt_with_all_claims` — already present)
- [x] Expired token → `parse_claims` does not validate expiry (by design);
      `exp` field is parsed and accessible (`parse_valid_jwt_with_all_claims`)
- [x] Token with no expiry fields is not treated as expired (`minimal_claims`)
- [x] Malformed base64 in JWT payload → parse error, no panic (`reject_invalid_base64`)
- [x] JWT with missing required claim → specific error (`extract_iat_missing`)

#### `sso-jwt-lib/src/oauth.rs`

- [x] Device code request with mocked HTTP returns expected `DeviceCode` struct
      (`get_device_code_posts_to_oauth_url_directly` — already present)
- [x] Polling loop returns token when mocked server responds with success
      (`poll_for_token_uses_token_url_when_provided` — already present)
- [x] Polling loop retries on `authorization_pending` then returns token
      (`poll_for_token_retries_on_authorization_pending_then_succeeds`)
- [x] Polling loop returns `access_denied` error when user declines
      (`poll_for_token_access_denied_returns_error`)
- [x] Polling loop times out when `expires_in=0`
      (`poll_for_token_times_out_when_expires_in_zero`)
      (Also fixed pre-existing StorageConfig missing-fields error in lib.rs and se_roundtrip.rs)

#### `sso-jwt-lib/src/cache.rs` — existing 60 tests are good; add:

- [x] Cache entry past `max_age` → classified as `RefreshWindow` or `Grace`
      (covered by `edge_case_exact_refresh_boundary`, `grace_period_risk_level_2`)
- [x] Concurrent `write_cache` from two threads → file valid after both complete
      (enclaveapp_core::metadata::atomic_write uses rename; concurrent test still useful)

#### `enclaveapp-app-adapter/src/credential_cache.rs`

- [x] `validate_https_url` accepts `https://example.com` and rejects
      `http://example.com`, empty string, and non-URL garbage
- [x] `encode_cache_component` with Unicode input (emoji, CJK) produces a
      filename-safe string
- [x] `cache_file_path` with various (app, url, user) triples produces
      distinct, stable paths
- [x] `clear_cache_files` deletes only the expected cache files, not adjacent
      files in the directory

#### `enclaveapp-app-adapter/src/resolver.rs`

- [ ] `resolve_program` on Windows handles `PATHEXT` extensions (`.exe`,
      `.cmd`) correctly (Windows-only; skipped on macOS/Linux)
- [x] Alias chain longer than the recursion limit returns an error or
      `ProgramNotFound` (no panic or stack-overflow)
- [x] `resolve_program` when `SHELL` env var is absent falls back gracefully
- [x] PATH containing an empty component (leading/trailing colon) does not
      panic

#### `enclaveapp-app-adapter/src/execution_plan.rs`

- [x] Empty supported-types list → `NoSupportedIntegration` error
- [x] Only `TempMaterializedConfig` supported → selected (only option)
- [x] `EnvInterpolation` and `HelperTool` both supported → `HelperTool`
      selected

#### `enclaveapp-app-storage/src/encryption.rs`

- [x] Decryption with a different key returns a decryption error, no panic
- [x] Ciphertext truncated by one byte → error, no panic
- [x] Concurrent writes to the same file from two threads → one write wins,
      file is valid after both complete (added to `secret_store.rs`)

---

### P2 — Moderate gaps: edge cases and hardening

#### `enclaveapp-app-adapter/src/launcher.rs`

- [x] Very large argument list (> 1,000 args) does not panic or silently
      truncate
- [x] `with_env_scrub` with a prefix pattern strips all matching vars, not
      just the first match

#### `enclaveapp-app-adapter/src/binding_store.rs`

- [x] JSON file on disk is corrupt (truncated) → `get` returns a parse error,
      not panic; store recovers on next `upsert`
- [x] Large number of records (1,000+) in `list()` returns correct count within
      a reasonable time bound

#### `enclaveapp-cache/src/lib.rs` — existing 44 tests are good; add:

- [x] Atomic overwrite: old reader holds a file descriptor open while writer
      atomically replaces the file → reader still sees old content, new reader
      sees new content (Unix rename-over semantics)

#### `sso-jwt/tests/integration.rs`

- [ ] `sso-jwt exec -- env` with a mocked JWT cache file → correct `SSO_JWT`
      env var injected into child process
- [ ] `sso-jwt exec` with an expired cache → invokes refresh path (mocked) and
      executes with fresh token
- [ ] `sso-jwt exec` when OAuth returns `AccessDenied` → exits non-zero with
      actionable message

---

## Cross-cutting: property-based and fuzz testing

The fuzz directory already covers `read_ssh_string`, `parse_request`, and
`parse_der_signature`. These additions target areas where structured fuzzing
has the most leverage.

- [ ] **proptest**: `KeyLabel::new(s)` for arbitrary strings — verify that
      validation is complete and consistent with the regex used in `key.rs`
- [ ] **proptest**: SSH wire format round-trip for `SshPublicKey` — encode then
      decode should produce the original value for any valid key
- [ ] **proptest**: `credential_cache::classify_credential` for arbitrary
      `(created_at, now, max_age, refresh_window, grace_period)` tuples —
      verify state machine covers all regions without panic
- [ ] **fuzz**: `enclaveapp_cache::decode` with arbitrary byte input — the
      existing in-repo fuzz crate is a natural place for this target
- [ ] **fuzz**: `sso_jwt_lib::jwt::parse` with arbitrary byte input

---

## Implementation notes

- All new unit tests that require a `KeyBackend` should use `MockKeyBackend`
  from `sshenc-test-support` rather than spawning a real agent.
- Tests that exercise `EncryptedFileSecretStore` or `JsonFileBindingStore`
  should use `tempfile::TempDir` to avoid polluting the developer's data
  directory and to ensure cleanup on test failure.
- Tests marked `#[ignore]` in the e2e suite require a running OpenSSH server
  and the software-backend build; they should remain ignorable for offline
  development.
- For concurrency tests, prefer `std::thread::spawn` + `join` over
  `tokio::spawn` unless the code under test is already async, to keep the
  test runtime dependency minimal.
- Signal tests (`SIGTERM` during in-flight request) require Unix and should be
  gated with `#[cfg(unix)]`.
