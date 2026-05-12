# Fix Plan: Agent Runtime Blocking Issue

## Problem
Agent becomes unresponsive after ~17 rapid sequential sign requests during git rebase.

## Root Cause
Synchronous backend operations (list(), sign_with_presence(), etc.) block tokio runtime worker threads. After ~17 concurrent connections, all worker threads are blocked and the agent can't accept new connections.

## Solution
Wrap ALL blocking backend method calls in `tokio::spawn_blocking()` to move them off the async runtime onto a dedicated blocking threadpool.

## Files to Modify

### 1. crates/sshenc-agent/src/op_log.rs
- Add `error: Option<&str>` parameter to `record()` and `record_to()`
- Include error message in JSON output when present
- ALREADY IMPLEMENTED (in stash)

### 2. crates/sshenc-agent/src/server.rs

#### handle_connection signature change:
- Change `backend: &dyn KeyBackend` to `backend: Arc<dyn KeyBackend>`
- Change `allowed_labels: &HashSet<String>` to `allowed_labels: Arc<HashSet<String>>`
- Update call site in run_agent to pass Arc instead of &

#### handle_request signature change:
- Make function async
- Change `backend: &dyn KeyBackend` to `backend: Arc<dyn KeyBackend>`
- Change `allowed_labels: &HashSet<String>` to `allowed_labels: Arc<HashSet<String>>`
- Update call site in handle_connection to await

#### Backend calls to wrap in spawn_blocking:

**RequestIdentities handler:**
- backend.list() (line ~910)
- backend.sk_list_labels() (line ~953)
- backend.sk_get() (line ~958) - in loop

**SignRequest handler:**
- backend.list() (line ~1034) - cache rebuild
- backend.sk_list_labels() (line ~1054) - cache rebuild
- backend.sk_get() (line ~1056) - cache rebuild loop
- backend.is_sk_label() (line ~1098)
- backend.sk_sign() (line ~1101)
- backend.get() (line ~1134)
- backend.sign_with_presence() (line ~1187) **MOST CRITICAL**

**GenerateKey handler:**
- backend.generate() (line ~1403)

**RenameKey handler:**
- backend.rename() (line ~1471)

**DeleteKey handler:**
- backend.is_sk_label() (line ~1533)
- backend.sk_delete() (line ~1535)
- backend.delete() (line ~1537)

#### Tests to fix:
- Convert all `#[test]` to `#[tokio::test]`
- Make all test functions async
- Update handle_request calls to wrap backend in Arc::new() and await
- Update handle_connection calls to pass Arc instead of &

## Testing Steps
1. Build and run unit tests: `cargo test -p sshenc-agent`
2. Build release: `cargo build --workspace --release`
3. Commit and push to trigger CI
4. CI builds signed release
5. Install via Homebrew test channel
6. Run reproduce script with 30 sequential signs
7. Verify all signs complete successfully
8. Check enclave-events.log for any errors

## Success Criteria
- All 30 sequential sign operations complete without "agent refused" or "not reachable" errors
- Agent remains responsive throughout
- Unit tests pass
- CI build succeeds
