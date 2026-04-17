# sshenc — Open Findings

Snapshot of findings still live in the current tree after the 2026-04 audit sweep.
Findings marked FIXED/WONTFIX have been removed; this file now tracks only work
that is still outstanding.

## Medium

### M8. `install()` has duplicated Windows rollback blocks

**File:** `sshenc-cli/src/commands.rs:780-933`

`install()` contains two near-identical rollback sequences (around lines 848-866 and
893-913) that combine Windows state restoration with SSH config uninstall. Every new
failure point needs the same rollback repeated, expanding audit surface.

**Remediation:** Introduce an `InstallGuard` RAII struct that tracks what's been
applied and rolls back on `Drop` unless `committed = true` is set at the end of
`install()`. Each step sets a flag on the guard; rollback becomes linear.

## Low

### L11. Mixed `cfg(target_os = "windows")` vs `cfg(windows)` in workspace deps

The remaining inconsistency is in `libenclaveapp`'s workspace (its crates still mix
both forms). The sshenc tree has been normalized to `cfg(windows)` / `cfg(unix)`,
but consuming apps should follow suit.

### R2. Backup messages no longer include file paths

**File:** `sshenc-keygen-cli/src/main.rs:113` and `sshenc-cli/src/main.rs`

After M3's `BackupPlan::cleanup()` addition, `.bak` files are cleaned on success, so
paths are only meaningful on failure. The user-facing message currently says
"Existing SSH key pair will be backed up before generation" with no indication of
where the backup landed. If the operation fails mid-way, the user has no easy way
to locate the backup (PID + nanosecond timestamped filenames).

**Remediation:** Change `with_existing_key_material_backup` to return the
`BackupPlan` alongside the operation result; on failure, print the backup paths
from `plan.entries()`.

## Documentation follow-ups

### D2. CLAUDE.md architecture staleness

`CLAUDE.md` describes the `enclaveapp-*` delegation model correctly, but the old
audit flagged references to removed crates and missing mentions of `sshenc-gitenc`.
Verify the file still matches the actual crate graph before the next release.

### D4/D5. Restore technical sections to ARCHITECTURE.md / TEST_PLAN.md

The 2026-04 doc refresh stripped the detailed key-storage file layout, data-flow
sequences, auth policy table, and per-crate test checklists. The new docs are
concise but lost content that was useful for security review and onboarding.
Consider restoring those sections with updated content reflecting the current
`enclaveapp-*` architecture.

### I1. `Return="check"` on uninstall custom action

**File:** `installer/sshenc.wxs:83`

Keeping `Return="check"` on the uninstall action risks blocking MSI removal if
`sshenc uninstall` ever returns non-zero (agent still running, file locked, etc.).
Switch uninstall to `Return="ignore"` so users can always remove the package;
harden `sshenc uninstall` to be best-effort internally.

---

*All prior H/M/L findings not listed above were either fixed or were transient
commit-cadence commentary; removed from this report on 2026-04-16.*
