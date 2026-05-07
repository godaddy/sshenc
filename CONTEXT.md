# Handoff context — Track 4: fish + PowerShell shell-rc support

> **DELETE THIS FILE BEFORE THE PR IS MERGED.** This is per-branch
> handoff context, not a permanent doc. The "Definition of done"
> section below repeats the reminder. `git rm CONTEXT.md` as part
> of your final commit. The substantive porting guide lives in
> `docs/PORTING-shell-rc.md` and stays committed.

You are picking up Track 4 of the cross-platform shell-rc work.
This branch has been pre-loaded with everything you need.

## What you do next

1. Read **`docs/PORTING-shell-rc.md`** in full — that is the
   implementation plan: file paths, syntax differences across shells,
   the Windows OpenSSH `SSH_AUTH_SOCK` semantics caveat, the test
   plan.
2. Read the existing **`crates/sshenc-core/src/shell_env.rs`** —
   already on this branch. It implements zsh + bash; you extend
   the `Shell` enum, add per-shell `rc_path_for`, and add per-shell
   `snippet_body`. The existing zsh/bash arms are the reference
   template.
3. Read the install/uninstall hookup in
   **`crates/sshenc-cli/src/commands.rs::install`** and
   **`uninstall`** — these dispatch through
   `shell_env::install_for_detected_shell` /
   `uninstall_for_detected_shell`. The dispatch already handles
   `Shell::Unknown` gracefully; you add new variants and the
   dispatch picks them up.

## What's in scope

- **fish** (`~/.config/fish/config.fish`). POSIX-incompatible
  syntax (`set -gx VAR VALUE` instead of `export VAR=VALUE`,
  `test -S` instead of `[ -S ]`, no `if then fi`).
- **PowerShell 7** (`$PROFILE`, typically
  `~/Documents/PowerShell/Microsoft.PowerShell_profile.ps1`).
  Different syntax (`if (Test-Path) { $env:VAR = ... }`).
- **Windows PowerShell 5.1** legacy profile path (different
  directory). Probably treat as PowerShell 7's twin.
- **cmd.exe** — no rc file. Use `setx VAR VALUE` for persistent
  user env, plus a transient `set` for the current session.
  Document this is "user-level env var only" — there's no
  per-session script.

## What's NOT in scope (defer to follow-ups)

- Generalizing the agent's RPC handlers to multiple apps. That's
  Track 5 (cross-app coverage for awsenc / sso-jwt / npmenc).
- Anything related to the meta-HMAC trust anchor on platforms
  other than what already shipped — that work is done.

## Why this branch and not `main`

The existing shell_env.rs (zsh + bash) is on `main` already. You
are extending it. Branching from `main` is correct here — there is
no in-progress dependency to stack on.

## Required environment

- A machine with each shell you implement installed. fish on
  macOS / Linux. PowerShell on Windows (or PowerShell Core / `pwsh`
  on macOS / Linux for development).
- Rust 1.75+.

## Testing notes

The existing shell_env test suite has 8 unit tests covering
install / repair / idempotent / uninstall / missing-file /
foreign-content cases for the markers-and-rc-write logic. Reuse
that pattern — each new shell variant gets the same coverage.

For PowerShell on Windows specifically, the tricky part is
`SSH_AUTH_SOCK` semantics: native Windows OpenSSH expects a
named-pipe path, not a Unix socket path. **Confirm the actual
agent socket / pipe path used on Windows BEFORE writing the
PowerShell snippet.** Look at how sshenc-agent's pipe path is
configured — it's a `\\.\pipe\sshenc-agent` named pipe, not
`~/.sshenc/agent.sock`.

## Definition of done

- `Shell::Fish`, `Shell::PowerShell` variants in the enum.
- `detect_shell_from_env` recognizes `fish`, `pwsh`,
  `powershell` (Windows native).
- `rc_path_for` and `snippet_body` cover both new shells with
  shell-specific syntax.
- Per-shell unit tests, mirroring the existing zsh/bash tests.
- `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace` all pass.
- Manual smoke test of `sshenc install` on a fish shell on macOS
  / Linux, and on PowerShell on Windows.
- PR opened against `main`.
- **`git rm CONTEXT.md`** before the PR merges — this file is
  branch-only handoff scaffolding and must not land on `main`.
  The porting guide at `docs/PORTING-shell-rc.md` stays.

Good luck.
