# AGENTS.md

Instructions for AI agents (Claude Code, Copilot, Cursor, etc.) working with sshenc.

## CRITICAL: Never Run Unsigned Binaries

**DO NOT** run binaries from development builds (`cargo build`, `cargo run`, `~/.cargo/bin/*`) in production contexts or when they could access hardware security modules (Secure Enclave, TPM).

### Why This Matters

sshenc accesses hardware-backed cryptographic storage (macOS Secure Enclave, Windows TPM, Linux software keys). Running unsigned development builds as agents can:

1. **Poison the keychain** — unsigned agents create keychain entries that conflict with production agents
2. **Trigger unexpected auth prompts** — users see Touch ID/password prompts from the wrong binary
3. **Break signing** — the wrong agent binary services signing requests, causing failures
4. **Leave stale processes** — development agents don't clean up properly when killed

### Safe vs Unsafe Operations

**SAFE:**
- `cargo test` — tests use mock backends, not real hardware
- `cargo build` — compiling is fine, just don't run the output as a daemon
- `cargo clippy`, `cargo fmt` — static analysis tools
- Reading source code and documentation

**UNSAFE:**
- `cargo run --bin sshenc-agent` — spawns unsigned agent that can access Secure Enclave
- `~/.cargo/bin/sshenc agent` — same issue
- `sshenc agent` when `~/.cargo/bin` is early in PATH — resolves to unsigned binary
- Any operation that calls `sshenc -Y sign` or `git commit -S` when an unsigned agent is running

### How to Develop Safely

1. **Always use the production agent:** Ensure only the signed production agent (`/opt/homebrew/bin/sshenc-agent` on macOS) is running before testing signing operations
2. **Kill development agents immediately:** If you accidentally spawn `~/.cargo/bin/sshenc-agent`, kill it: `pkill -f ~/.cargo/bin/sshenc-agent`
3. **Check which agent is running:**
   ```bash
   ps aux | grep sshenc-agent | grep -v grep
   # Should show /opt/homebrew/bin/sshenc-agent, NOT ~/.cargo/bin/sshenc-agent
   ```
4. **Verify the PID file points to the right binary:**
   ```bash
   cat ~/.sshenc/agent.pid
   ps -p $(cat ~/.sshenc/agent.pid) -o command=
   ```

### Self-Healing Gaps (TO BE FIXED)

The current implementation has these weaknesses:

1. **No validation that running agent is signed/trusted** — PID file doesn't verify binary path
2. **~/.cargo/bin is in trusted binary search** — `find_trusted_binary()` will find development builds
3. **No automatic cleanup of unsigned agents** — user must manually kill them
4. **No warning when unsigned binary tries to act as agent** — should log/reject unsigned spawns

### When Things Go Wrong

If you've accidentally run an unsigned agent and signing is broken:

1. **Kill all agents:**
   ```bash
   pkill -9 sshenc-agent
   ```

2. **Verify clean state:**
   ```bash
   ps aux | grep sshenc-agent | grep -v grep  # should be empty
   ls ~/.sshenc/agent.sock  # should not exist
   ```

3. **Restart production agent:**
   ```bash
   /opt/homebrew/bin/sshenc agent
   ```

4. **Verify it's the right one:**
   ```bash
   ps aux | grep sshenc-agent | grep -v grep
   # Should show /opt/homebrew/bin/sshenc-agent
   ```

5. **If keychain is still broken, verify keys exist:**
   ```bash
   sshenc list
   ```

6. **Test signing (will prompt for Touch ID):**
   ```bash
   echo "test" > /tmp/test-sign.txt
   sshenc -Y sign -f /tmp/test-sign.txt
   ```

## Build Commands

When working on sshenc code changes:

```bash
# Build and test safely
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all

# DO NOT run the built binaries as daemons
# DO NOT run: cargo run --bin sshenc-agent
# DO NOT run: ~/.cargo/bin/sshenc agent

# To test agent changes, install via homebrew first:
cargo build --release
# ... create PR, merge, release via CI ...
brew upgrade sshenc
# NOW it's safe to test agent functionality
```

## Commit Signing

**Before committing:** Ensure only the production agent is running.

```bash
# Check agent
ps aux | grep sshenc-agent | grep -v grep

# If it's ~/.cargo/bin/sshenc-agent, kill it and restart production agent:
pkill -f ~/.cargo/bin/sshenc-agent
/opt/homebrew/bin/sshenc agent

# Then commit
git commit -S -m "your message"
```

## Summary

- ✅ Build and test code with `cargo`
- ✅ Use production agents from `/opt/homebrew/bin`
- ❌ Don't run `~/.cargo/bin/sshenc-agent` as a daemon
- ❌ Don't test signing with development builds
- 🔍 Always verify which agent binary is running before signing operations
