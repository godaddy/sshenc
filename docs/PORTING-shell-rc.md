# Porting guide: fish + PowerShell + cmd.exe shell-rc support

**Branch:** `shell-rc-fish-powershell`
**Repo:** sshenc
**Status:** Bootstrap doc — implementation not started.
**Audience:** A fresh Claude Code session on a Unix machine (for
fish work) or a Windows host (for PowerShell / cmd.exe work). May
need both for the full PR; the work is naturally splittable into
two sub-PRs if needed.

## What this is

`sshenc install` writes a guarded snippet to the user's shell rc
file that points `SSH_AUTH_SOCK` at the sshenc-agent socket so
`git commit -S` (which calls `ssh-keygen -Y sign`) talks to the
right agent. Today the snippet is written for zsh (`~/.zshrc`)
and bash (`~/.bash_profile` on macOS, `~/.bashrc` elsewhere).

This PR extends coverage to:

- **fish** (`~/.config/fish/config.fish`)
- **PowerShell 7+** (`$PROFILE`)
- **Windows PowerShell 5.1** (different profile path)
- **cmd.exe** (`setx` for persistent user env)

## Read first

In this order:

1. **`crates/sshenc-core/src/shell_env.rs`** — the existing module
   you extend. zsh + bash patterns are the reference. Look at the
   `Shell` enum, `detect_shell_from_env`, `rc_path_for`,
   `snippet_body`, `install_block`, `uninstall_block`, plus the
   8 unit tests at the bottom.
2. **`crates/sshenc-cli/src/commands.rs::install`** and `uninstall`
   — the dispatch to `install_for_detected_shell` /
   `uninstall_for_detected_shell`. Already handles the
   `Shell::Unknown` and `Shell::NoHome` cases gracefully.

## Implementation plan

Five logical commits, each independently reviewable.

### 1. fish support

Extend `Shell` enum with `Fish`. Update `detect_shell_from_env`
to recognize `fish`. Update `rc_path_for(Shell::Fish, home)` to
return `home/.config/fish/config.fish`. Note: fish's config dir
respects `XDG_CONFIG_HOME` if set; the simplest implementation
honors that, falling back to `~/.config/fish/`.

Fish snippet syntax:

```fish
# >>> sshenc-managed (do not edit between markers)
# Route SSH_AUTH_SOCK at sshenc-agent so git commit signing
# (ssh-keygen -Y sign) talks to the right agent.
if test -S "$HOME/.sshenc/agent.sock"
    set -gx SSH_AUTH_SOCK "$HOME/.sshenc/agent.sock"
end
# <<< sshenc-managed
```

Differences from POSIX:

- `set -gx VAR VALUE` instead of `export VAR=VALUE`. `-g` is global
  scope; `-x` exports to subprocesses.
- `test -S` instead of `[ -S ]` (fish builtin, same semantics).
- `if test ...; ... end` block syntax (no `[`/`]`/`then`/`fi`).
- `#` comment is the same.

Reuse the existing `BlockMarkers::standard("sshenc")` —
fish accepts `#` comments, so the markers work as-is.

### 2. PowerShell 7 support (cross-platform)

Extend `Shell` enum with `PowerShell`. Detection: `$SHELL` ending
in `pwsh` (PowerShell Core / 7) or `powershell.exe` (Windows
native). Note that on Windows `$SHELL` is often unset — the
detection should fall back to checking for the existence of
`pwsh.exe` on PATH, or accepting an explicit override.

`rc_path_for`: PowerShell's `$PROFILE` is per-user-per-host. The
canonical location is documented as `$HOME\Documents\PowerShell\Microsoft.PowerShell_profile.ps1`
on PowerShell 7, `$HOME\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1`
on Windows PowerShell 5.1. Detect which by inspecting the
PowerShell version on the executable, or just write the 7 profile
and document that 5.1 users need an extra step.

PowerShell snippet syntax:

```powershell
# >>> sshenc-managed (do not edit between markers)
# Route SSH_AUTH_SOCK at sshenc-agent so git commit signing
# (ssh-keygen -Y sign) talks to the right agent.
if (Test-Path "$env:USERPROFILE\.sshenc\agent.sock") {
    $env:SSH_AUTH_SOCK = "$env:USERPROFILE\.sshenc\agent.sock"
}
# <<< sshenc-managed
```

PowerShell uses `#` for line comments — markers work.

**CRITICAL Windows OpenSSH caveat:** native Windows OpenSSH does
not use a Unix socket path for `SSH_AUTH_SOCK`. It uses a named
pipe: `\\.\pipe\openssh-ssh-agent` by default. sshenc-agent on
Windows binds to a different named pipe. **Before writing the
snippet on Windows, find the correct pipe path** — look at
`crates/sshenc-agent/src/main.rs` or the install code for what
pipe name sshenc-agent actually uses. The snippet on Windows
should set `SSH_AUTH_SOCK` to that pipe path, not a Unix socket
path.

For cross-platform PowerShell (pwsh on macOS / Linux), the socket
path stays as the Unix socket — matches the bash/zsh snippet.

### 3. Windows PowerShell 5.1 support

Same syntax as PowerShell 7; different profile path. May or may
not be worth supporting — modern setups use PowerShell 7. Decision
point: implement now, or leave a clear "not supported, run
PowerShell 7" message?

Recommendation: implement. The path difference is one match-arm.
Detection: if the user's `$PSVersionTable.PSVersion.Major < 6`,
they're on 5.1. From the install side, this is hard to detect
(you're a Rust process, not running in PowerShell). Heuristic:
if `$PROFILE` directory exists at the 7 path → write 7;
else if 5.1 path exists → write 5.1; else write 7 (default).

### 4. cmd.exe support

cmd.exe has no rc file. Persistent user env is set via `setx`.

Mechanism: invoke `setx SSH_AUTH_SOCK <path>` on Windows during
`sshenc install`. Document that cmd.exe users see the new env var
in NEW shells (existing shells need a manual `set` or restart).

`sshenc uninstall` on Windows removes via `reg delete`:

```cmd
reg delete "HKEY_CURRENT_USER\Environment" /v SSH_AUTH_SOCK /f
```

This is fundamentally different from the rc-file pattern (no guard
markers, no idempotent block). The uninstall is destructive — if
the user had `SSH_AUTH_SOCK` set for some other reason, sshenc
uninstall will blow it away. Document this. Or: only remove if
the value matches the sshenc pipe path.

Recommended: on `setx`, record the prior value via `reg query`
into a Windows-side `.uninstall-state` file (similar pattern to
`load_windows_install_state` in `commands.rs`). On uninstall,
restore the prior value, falling back to delete if nothing was
recorded.

### 5. Test coverage

Mirror the existing `shell_env::tests` for zsh/bash — 8 unit tests
per shell. Tempdir, write rc, install, assert content, repeat
install (`AlreadyPresent`), repeat with different socket
(`Repaired`), uninstall, uninstall on missing file
(`NotPresent`), uninstall on file without our markers
(`NotPresent`).

PowerShell-specific tests should additionally verify the
`Test-Path` / `$env:` syntax is correct in the rendered snippet.
Easiest: snapshot test against an expected string.

## Test environment

- fish work: any Unix host with fish installed (`brew install fish`
  on macOS, `apt install fish` on Linux).
- PowerShell work: a Windows host. PowerShell 7 install (also
  available cross-platform: `brew install powershell` on macOS).
- cmd.exe: Windows host required for live verification. Static
  unit tests (snapshot of `setx` invocation builder) can run
  anywhere.

CI on stock GitHub `windows-latest` already has PowerShell 7 and
cmd.exe pre-installed. fish needs to be installed in the CI
ubuntu / macOS jobs if you want the live-shell tests there;
otherwise gate them behind a feature flag and run manually.

## What does NOT change

- The existing zsh / bash code stays as-is.
- The agent's RPC protocol — no new RPCs needed; this is purely
  client-side rc-file management.
- The trust-anchor / migrate-meta logic — independent.

## When you're done

Push the branch, open a PR against `main`. Update:

- `README.md` if it mentions which shells are supported
- `docs/` index if there's one

Don't bother updating the threat model — this is install-time UX
plumbing, not a security boundary change.
