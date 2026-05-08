// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! gitenc: Git wrapper that selects sshenc Secure Enclave identities.
//!
//! Usage:
//!   gitenc --label NAME [git args...]         # use a specific SE key
//!   gitenc [git args...]                      # use default (agent picks)
//!   gitenc --config NAME                      # set this repo to always use NAME
//!   gitenc --config                           # set this repo to use default agent
//!
//! Examples:
//!   gitenc --label github-work clone git@github.com:org/repo.git
//!   gitenc --label github-personal push origin main
//!   gitenc --config github-work               # configure current repo
//!   gitenc pull                               # uses configured key
//!
//! ## Transport
//!
//! gitenc is **agent-only**. Both the SSH side (set via
//! `core.sshCommand = sshenc ssh --label X --`) and the
//! commit-signing side (`gpg.ssh.program = sshenc`) talk to
//! `sshenc-agent` via the same Unix socket. There is no PKCS#11
//! mode for gitenc — PKCS#11 is OpenSSH's plug-in interface for
//! crypto providers and is only used by `sshenc install` to wire
//! up the agent boot-hook in `~/.ssh/config`. From git's
//! perspective every operation goes through `sshenc ssh` →
//! `AgentProxyBackend` → the agent. If you need to disable the
//! agent path entirely, fall back to a non-sshenc SSH key and
//! configure git to use the system ssh directly; gitenc itself
//! does not expose an alternative.

use clap::Parser;
use enclaveapp_core::types::validate_label;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Parser, Debug)]
#[command(
    name = "gitenc",
    about = "Git wrapper that selects sshenc Secure Enclave identities for SSH transport and commit signing",
    long_about = "gitenc runs git with GIT_SSH_COMMAND set so SSH transport goes through an \
                  sshenc-managed Secure Enclave (or TPM / software-backed) key. With --config, \
                  it instead writes the current repository's git config so future plain `git` \
                  invocations use the chosen sshenc identity for both SSH and commit signing.\n\n\
                  Without --label, gitenc uses the sshenc agent's default identity. All arguments \
                  after the gitenc options are passed verbatim to git; use `gitenc <cmd> --help` \
                  or `gitenc -- --help` to read git's own help.",
    version,
    disable_help_subcommand = true
)]
struct Cli {
    /// Use the sshenc key with this label for SSH transport and commit signing.
    #[arg(long, short = 'l', value_name = "LABEL")]
    label: Option<String>,

    /// Configure the current git repo (via `git config`) to use the chosen
    /// sshenc key. With no label, the repo is configured to use the agent's
    /// default key. Sets core.sshCommand, gpg.format, gpg.ssh.program,
    /// user.signingkey, commit.gpgsign, and gpg.ssh.allowedSignersFile.
    #[arg(long)]
    config: bool,

    /// In normal mode: arguments passed verbatim to git.
    /// In --config mode: optional positional key label (alternative to --label).
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

fn main() {
    enclaveapp_core::process::harden_process();

    let cli = Cli::parse();

    if cli.config {
        let label = match resolve_config_label(cli.label.as_deref(), &cli.args) {
            Ok(l) => l,
            Err(err) => exit_arg_error(&err),
        };
        configure_repo(label.as_deref());
    } else {
        run_git(cli.label.as_deref(), &cli.args);
    }
}

fn resolve_config_label(
    label_flag: Option<&str>,
    positional: &[String],
) -> Result<Option<String>, String> {
    match (label_flag, positional) {
        (Some(_), rest) if !rest.is_empty() => {
            Err("--config takes either --label NAME or one positional NAME, not both".into())
        }
        (Some(l), _) => Ok(Some(l.to_string())),
        (None, []) => Ok(None),
        (None, [single]) => Ok(Some(single.clone())),
        (None, _) => Err("--config takes at most one positional argument".into()),
    }
}

#[allow(clippy::exit, clippy::print_stderr)]
fn run_git(label: Option<&str>, git_args: &[String]) -> ! {
    let ssh_command = build_ssh_command(label).unwrap_or_else(|err| exit_invalid_label(&err));

    let mut cmd = Command::new("git");

    // For unconfigured repos, inject signing config inline via
    // `git -c key=value` so `gitenc git commit -S` / `gitenc git tag -s`
    // sign with sshenc's default identity (or the explicit --label
    // when given) — without requiring the user to have run
    // `gitenc --config` first. We DON'T set commit.gpgsign=true:
    // surprising users with auto-signing on every commit isn't
    // right; users opt in by passing `-S`. Setting just the
    // gpg.format/program/signingkey/allowedSignersFile shape makes
    // `-S` use sshenc when the user asks for it.
    //
    // Skipped if the repo is already configured (via
    // `gitenc --config` or hand-edited gitconfig) so we don't
    // override an explicit operator choice.
    let inline_signing_args = inline_signing_args_if_unconfigured(label);
    for arg in &inline_signing_args {
        cmd.arg("-c").arg(arg);
    }

    // Spawn-and-wait (rather than exec on Unix) so we can run the
    // post-success nudge that points users at `gitenc --config` when
    // they're in a repo that hasn't opted into persistent sshenc
    // config. The cost vs. exec is one extra alive process during
    // the git operation; signals propagate naturally (the shell
    // sends SIGINT to the whole process group), and the exit code
    // is forwarded faithfully.
    let status = cmd
        .args(git_args)
        .env("GIT_SSH_COMMAND", &ssh_command)
        .status();

    match status {
        Ok(s) => {
            if s.success() {
                maybe_print_config_hint();
            }
            std::process::exit(s.code().unwrap_or(1));
        }
        Err(e) => {
            eprintln!("gitenc: failed to run git: {e}");
            std::process::exit(1);
        }
    }
}

/// Build the `key=value` pairs to pass via `git -c` so an
/// unconfigured repo still uses sshenc's default identity (or the
/// explicit `--label`) for `git commit -S` / `git tag -s`.
///
/// Returns an empty Vec if any of these is true:
/// - We can't resolve `$HOME` (so we can't compute `.pub` paths).
/// - We can't find the trusted sshenc binary (so the
///   `gpg.ssh.program` we'd advertise wouldn't run).
/// - The default `.pub` file doesn't exist on disk (so signing
///   would fail anyway — falling through to git's default config
///   surfaces a clearer error than "sshenc -Y sign: file missing").
/// - The repo's `core.sshCommand` already routes through sshenc
///   (the operator ran `gitenc --config` — their explicit settings
///   should win, including any custom `user.signingkey`).
///
/// The empty-Vec returns are intentional silent fall-throughs:
/// `gitenc git push` on a host without any sshenc keys configured
/// should still work — it just won't auto-enable signing.
fn inline_signing_args_if_unconfigured(label: Option<&str>) -> Vec<String> {
    let Some(home_os) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) else {
        return Vec::new();
    };
    let Some(home) = home_os.to_str() else {
        return Vec::new();
    };

    // Resolved label that signing_key_path() / load_git_key_metadata()
    // expect. Mirrors the same `label.unwrap_or("default")` choice
    // configure_repo() makes.
    let signing_label = label.unwrap_or("default");
    let signing_key = match signing_key_path(home, signing_label) {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };
    if !Path::new(&signing_key).exists() {
        return Vec::new();
    }

    // Skip the inline shape if the repo is already configured
    // (operator's explicit choice should win).
    if let Some(repo_root) = git_repo_root() {
        if repo_already_configured(&repo_root) {
            return Vec::new();
        }
    }

    let binary_name = if cfg!(windows) {
        "sshenc.exe"
    } else {
        "sshenc"
    };
    let Some(sshenc_bin) =
        enclaveapp_core::bin_discovery::find_trusted_binary(binary_name, "sshenc")
    else {
        return Vec::new();
    };

    inline_signing_args_pure(home, &sshenc_bin.display().to_string(), &signing_key)
}

/// Pure helper extracted for unit testing — produces the
/// `key=value` pairs given fully-resolved inputs. The caller
/// (`inline_signing_args_if_unconfigured`) is responsible for the
/// gating: HOME resolved, key file exists, repo not already
/// configured, sshenc binary discovered. This function just
/// formats; no I/O, no env, no process state.
fn inline_signing_args_pure(home: &str, sshenc_bin: &str, signing_key: &str) -> Vec<String> {
    let allowed_signers = Path::new(home).join(".ssh").join("allowed_signers");
    vec![
        "gpg.format=ssh".to_string(),
        format!("gpg.ssh.program={sshenc_bin}"),
        format!("user.signingkey={signing_key}"),
        format!("gpg.ssh.allowedSignersFile={}", allowed_signers.display()),
    ]
}

/// One-shot duration after which the "configure this repo" nudge can
/// re-appear. Long enough that a user who saw the tip last week and
/// got distracted gets a second reminder; short enough not to feel
/// stale when the user comes back to a fresh repo.
const HINT_REPRINT_AFTER: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Fire-and-forget UX nudge for users who haven't run `gitenc --config`
/// in this repo. Prints a single line on stdout pointing at the
/// command, then drops a sentinel file so the same shell session (and
/// subsequent invocations within `HINT_REPRINT_AFTER`) stay quiet.
///
/// All conditions must hold:
///   - stdout AND stdin are TTYs (don't pollute pipelines, CI, or
///     git-over-stdio scripts).
///   - cwd resolves to a git repo via `git rev-parse --show-toplevel`
///     (no nudge for `gitenc --version` outside any repo).
///   - the repo's `core.sshCommand` does NOT already contain "sshenc"
///     (i.e. the user hasn't already configured this repo, manually
///     or via `gitenc --config`).
///   - the sentinel file is missing or older than `HINT_REPRINT_AFTER`.
///
/// Failures along the way are silent — we never want a missing HOME,
/// a denied write to the sentinel directory, or git not on PATH to
/// surface as an error from a normal `gitenc fetch`.
#[allow(clippy::print_stdout)]
fn maybe_print_config_hint() {
    if !std::io::stdout().is_terminal() || !std::io::stdin().is_terminal() {
        return;
    }
    let Some(repo_root) = git_repo_root() else {
        return;
    };
    if repo_already_configured(&repo_root) {
        return;
    }
    let Some(sentinel) = sentinel_path() else {
        return;
    };
    if recently_shown(&sentinel, SystemTime::now(), HINT_REPRINT_AFTER) {
        return;
    }

    println!(
        "\ngitenc: tip — run `gitenc --config` in this repo so plain `git` \
         commands also use sshenc for SSH and commit signing. \
         Pass `--label NAME` to bind a specific identity."
    );
    // The sentinel write debounces this nudge for HINT_REPRINT_AFTER.
    // If it fails (read-only XDG dir, ENOSPC, etc.) the user will see
    // the tip on every successful `gitenc` run instead of once a week,
    // which is annoying but not broken. Surface the failure under
    // `GITENC_DEBUG=1` so a power user diagnosing the noise can see
    // why; stay silent in the default case.
    if let Err(e) = touch_sentinel(&sentinel) {
        if std::env::var_os("GITENC_DEBUG").is_some() {
            #[allow(clippy::print_stderr)]
            {
                eprintln!(
                    "gitenc: debug: failed to write hint sentinel at {}: {e}",
                    sentinel.display()
                );
            }
        }
    }
}

/// Find the toplevel of the current git working tree, or `None` if
/// we're not in a repo. Shells out to `git` rather than walking the
/// filesystem because git's own answer accounts for `GIT_DIR`,
/// `GIT_WORK_TREE`, and submodule conventions that a naive walk
/// wouldn't.
fn git_repo_root() -> Option<PathBuf> {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let raw = String::from_utf8(output.stdout).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(PathBuf::from(trimmed))
    }
}

/// True if the repo's `core.sshCommand` already routes through
/// sshenc. Ignores the literal substring case: any value containing
/// "sshenc" (e.g. `sshenc ssh`, `/opt/homebrew/bin/sshenc ssh ...`,
/// or a future `sshenc-something`) is taken as configured. False on
/// any git error or missing config — the conservative read for a
/// nudge that errs toward silence.
fn repo_already_configured(repo_root: &Path) -> bool {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["config", "--local", "--get", "core.sshCommand"])
        .output();
    match output {
        Ok(o) if o.status.success() => {
            let value = String::from_utf8_lossy(&o.stdout);
            value.contains("sshenc")
        }
        _ => false,
    }
}

/// Path to the sentinel file. Lives next to the agent socket so it
/// shares the `~/.sshenc/` directory's permissions and lifecycle.
fn sentinel_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
    Some(
        PathBuf::from(home)
            .join(".sshenc")
            .join(".gitenc-config-hint-shown"),
    )
}

/// True if the sentinel file's mtime is within `window` of `now`.
/// A missing file or any IO error returns false (we'll show the
/// nudge and try to write the sentinel).
fn recently_shown(sentinel: &Path, now: SystemTime, window: Duration) -> bool {
    let Ok(meta) = std::fs::metadata(sentinel) else {
        return false;
    };
    let Ok(mtime) = meta.modified() else {
        return false;
    };
    match now.duration_since(mtime) {
        Ok(elapsed) => elapsed < window,
        // mtime is in the future (clock skew / restored backup).
        // Treat as recent so we don't spam on a misbehaving clock.
        Err(_) => true,
    }
}

/// Create or `mtime`-bump the sentinel file. Best effort -- the
/// directory might not exist, or the FS might be read-only. Failure
/// is silent.
fn touch_sentinel(sentinel: &Path) -> std::io::Result<()> {
    if let Some(parent) = sentinel.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Re-create on every touch so mtime always advances, even on
    // filesystems where setting mtime on an existing file is fiddly.
    std::fs::write(sentinel, b"")
}

#[allow(clippy::print_stdout, clippy::print_stderr, clippy::exit)]
fn configure_repo(label: Option<&str>) {
    if let Err(err) = build_ssh_command(label) {
        exit_invalid_label(&err);
    }

    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| "/tmp".into());

    // Find sshenc binary (same directory as gitenc, or in PATH)
    let sshenc_bin = {
        #[cfg(windows)]
        let binary_name = "sshenc.exe";
        #[cfg(not(windows))]
        let binary_name = "sshenc";
        enclaveapp_core::bin_discovery::find_trusted_binary(binary_name, "sshenc")
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| {
                eprintln!("gitenc: trusted sshenc binary not found");
                std::process::exit(1);
            })
    };

    let signing_label = label.unwrap_or("default");
    let metadata = load_git_key_metadata(signing_label);
    let configs = configure_repo_entries(label, &home, &sshenc_bin, metadata.as_ref())
        .unwrap_or_else(|err| exit_invalid_label(&err));

    for (key, value) in &configs {
        let status = Command::new("git").args(["config", key, value]).status();
        match status {
            Ok(s) if s.success() => {}
            Ok(s) => {
                eprintln!(
                    "git config {key} failed (exit {}). Are you in a git repo?",
                    s.code().unwrap_or(-1)
                );
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("gitenc: failed to run git: {e}");
                std::process::exit(1);
            }
        }
    }

    match label {
        Some(effective_label) => {
            let signing_key = configs
                .iter()
                .find(|(key, _)| key == "user.signingkey")
                .map(|(_, value)| value.as_str())
                .unwrap_or("");
            println!("Configured this repo to use sshenc key: {effective_label}");
            println!("  SSH auth:       sshenc ssh --label {effective_label}");
            println!("  Commit signing: {signing_key}");
            if let Some(ref meta) = metadata {
                if let Some(ref name) = meta.git_name {
                    println!("  Author:         {name}");
                }
                if let Some(ref email) = meta.git_email {
                    println!("  Email:          {email}");
                }
                if meta.git_name.is_none() && meta.git_email.is_none() {
                    println!("  (no git identity set — use 'sshenc identity {effective_label} --name \"...\" --email \"...\"' to configure)");
                }
            } else {
                println!("  (no git identity set — use 'sshenc identity {effective_label} --name \"...\" --email \"...\"' to configure)");
            }
        }
        None => {
            let signing_key = configs
                .iter()
                .find(|(key, _)| key == "user.signingkey")
                .map(|(_, value)| value.as_str())
                .unwrap_or("");
            println!("Configured this repo to use sshenc agent-default SSH authentication.");
            println!("  SSH auth: sshenc ssh --");
            println!("  Commit signing: {signing_key}");
            if let Some(ref meta) = metadata {
                if let Some(ref name) = meta.git_name {
                    println!("  Author:         {name}");
                }
                if let Some(ref email) = meta.git_email {
                    println!("  Email:          {email}");
                }
            }
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct GitKeyMetadata {
    git_name: Option<String>,
    git_email: Option<String>,
    pub_file_path: Option<String>,
    pub_file_path_recorded: bool,
}

fn build_ssh_command(label: Option<&str>) -> Result<String, String> {
    match label {
        Some(label) => {
            validate_label(label).map_err(|e| e.to_string())?;
            Ok(format!("sshenc ssh --label {label} --"))
        }
        None => Ok("sshenc ssh --".to_string()),
    }
}

fn signing_key_path(home: &str, label: &str) -> Result<String, String> {
    if label == "default" {
        return Ok(format!("{home}/.ssh/id_ecdsa.pub"));
    }

    validate_label(label).map_err(|e| e.to_string())?;
    Ok(format!("{home}/.ssh/{label}.pub"))
}

fn load_git_key_metadata(label: &str) -> Option<GitKeyMetadata> {
    let meta_dir = dirs::home_dir()?.join(".sshenc").join("keys");
    let meta_path = meta_dir.join(format!("{label}.meta"));
    let content = std::fs::read_to_string(meta_path).ok()?;
    parse_git_key_metadata(&content)
}

fn parse_git_key_metadata(content: &str) -> Option<GitKeyMetadata> {
    let raw: serde_json::Value = serde_json::from_str(content).ok()?;
    let app_specific = raw.get("app_specific").unwrap_or(&raw);
    let git_name = app_specific
        .get("git_name")
        .or_else(|| raw.get("git_name"))
        .and_then(|value| value.as_str())
        .map(String::from);
    let git_email = app_specific
        .get("git_email")
        .or_else(|| raw.get("git_email"))
        .and_then(|value| value.as_str())
        .map(String::from);
    let pub_path_value = app_specific
        .get("pub_file_path")
        .or_else(|| raw.get("pub_file_path"));
    let pub_file_path = pub_path_value
        .and_then(|value| value.as_str())
        .map(String::from);

    Some(GitKeyMetadata {
        git_name,
        git_email,
        pub_file_path,
        pub_file_path_recorded: pub_path_value.is_some(),
    })
}

fn configure_repo_entries(
    label: Option<&str>,
    home: &str,
    sshenc_bin: &str,
    metadata: Option<&GitKeyMetadata>,
) -> Result<Vec<(String, String)>, String> {
    let mut configs = vec![("core.sshCommand".to_string(), build_ssh_command(label)?)];
    let label = label.unwrap_or("default");

    let signing_key = match metadata.and_then(|meta| meta.pub_file_path.as_deref()) {
        Some(path) => {
            if Path::new(path).exists() {
                path.to_string()
            } else {
                return Err(format!("recorded public key file does not exist: {path}"));
            }
        }
        None if metadata.is_some_and(|meta| meta.pub_file_path_recorded) => {
            return Err(format!(
                "key '{label}' does not have a recorded public key file; export one before running gitenc --config"
            ));
        }
        None => signing_key_path(home, label)?,
    };

    configs.extend([
        ("gpg.format".to_string(), "ssh".to_string()),
        ("gpg.ssh.program".to_string(), sshenc_bin.to_string()),
        ("user.signingkey".to_string(), signing_key.clone()),
        ("commit.gpgsign".to_string(), "true".to_string()),
    ]);

    if let Some(metadata) = metadata {
        if let Some(name) = metadata.git_name.as_ref() {
            configs.push(("user.name".to_string(), name.clone()));
        }
        if let Some(email) = metadata.git_email.as_ref() {
            configs.push(("user.email".to_string(), email.clone()));
        }
    }

    // Set up allowed signers file for local signature verification.
    let allowed_signers_path = Path::new(home).join(".ssh").join("allowed_signers");
    if let Some(email) = metadata.and_then(|m| m.git_email.as_deref()) {
        if let Ok(pubkey) = std::fs::read_to_string(&signing_key) {
            let entry = format!("{email} {}", pubkey.trim());
            update_allowed_signers(&allowed_signers_path, email, &entry)
                .map_err(|e| format!("failed to update {}: {e}", allowed_signers_path.display()))?;
        }
    }
    configs.push((
        "gpg.ssh.allowedSignersFile".to_string(),
        allowed_signers_path.display().to_string(),
    ));

    Ok(configs)
}

/// Add or update an entry in the allowed signers file.
///
/// Replaces any existing entry whose principals list names this email
/// exactly. Lines whose first field `starts_with(email)` but is not an
/// exact principal match (e.g. `alice@x.com.attacker ssh-ed25519 …`)
/// are preserved, which is the safe behavior for an authentication
/// trust file.
///
/// The write itself is atomic: the new content goes to a sibling
/// `.tmp.<pid>.<nanos>` file with `O_CREAT|O_EXCL`, and a `rename(2)`
/// replaces the original. A crash mid-write leaves the original
/// allowed_signers intact rather than a half-truncated file (which
/// is what `std::fs::write` would produce). Concurrent
/// `gitenc --config` invocations still race the read-modify-write
/// pattern — the loser's update is lost — but neither ever observes
/// a torn file.
///
/// I/O errors are propagated. The previous version dropped them
/// silently, which made permission/space failures invisible to the
/// user even though `git -Y verify` later fails confusingly.
fn update_allowed_signers(path: &Path, email: &str, entry: &str) -> std::io::Result<()> {
    let existing = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e),
    };
    let mut lines: Vec<&str> = existing
        .lines()
        .filter(|line| !line_principals_contain(line, email))
        .collect();
    lines.push(entry);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_atomic(path, (lines.join("\n") + "\n").as_bytes())
}

/// Best-effort atomic write: write to `<path>.<pid>.<nanos>.tmp`
/// with `create_new`, fsync, then rename into place. The temp name
/// includes pid + nanos so a parallel writer in the same directory
/// cannot collide on the temp filename. This intentionally
/// duplicates `enclaveapp_core::metadata::atomic_write` rather than
/// taking a dependency on it, since gitenc otherwise has no need
/// for that crate.
fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "write_atomic: path has no parent",
        )
    })?;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tmp = parent.join(format!(
        ".{}.{}.{nanos}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("allowed_signers"),
        std::process::id(),
    ));
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&tmp)?;
    file.write_all(data)?;
    file.sync_all()?;
    drop(file);
    if let Err(e) = std::fs::rename(&tmp, path) {
        drop(std::fs::remove_file(&tmp));
        return Err(e);
    }
    Ok(())
}

/// Return true if the first whitespace-separated field on the line (the
/// principals field per ssh-keygen(1) ALLOWED SIGNERS) contains an
/// exact match for `email` among its comma-separated entries.
fn line_principals_contain(line: &str, email: &str) -> bool {
    let Some(first_field) = line.split_whitespace().next() else {
        return false;
    };
    first_field.split(',').any(|principal| principal == email)
}

#[allow(clippy::print_stderr, clippy::exit)]
fn exit_invalid_label(err: &str) -> ! {
    eprintln!("gitenc: invalid label: {err}");
    std::process::exit(2);
}

#[allow(clippy::print_stderr, clippy::exit)]
fn exit_arg_error(err: &str) -> ! {
    eprintln!("gitenc: {err}");
    std::process::exit(2);
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    fn parse(args: &[&str]) -> Cli {
        let mut full = vec!["gitenc"];
        full.extend(args.iter().copied());
        Cli::try_parse_from(full).unwrap()
    }

    fn try_parse(args: &[&str]) -> Result<Cli, clap::Error> {
        let mut full = vec!["gitenc"];
        full.extend(args.iter().copied());
        Cli::try_parse_from(full)
    }

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parse_long_label() {
        let cli = parse(&[
            "--label",
            "github-work",
            "clone",
            "git@github.com:org/repo.git",
        ]);
        assert_eq!(cli.label.as_deref(), Some("github-work"));
        assert!(!cli.config);
        assert_eq!(cli.args, s(&["clone", "git@github.com:org/repo.git"]));
    }

    #[test]
    fn parse_short_label() {
        let cli = parse(&["-l", "mykey", "push", "origin", "main"]);
        assert_eq!(cli.label.as_deref(), Some("mykey"));
        assert_eq!(cli.args, s(&["push", "origin", "main"]));
    }

    #[test]
    fn parse_no_label() {
        let cli = parse(&["pull", "--rebase"]);
        assert_eq!(cli.label, None);
        assert_eq!(cli.args, s(&["pull", "--rebase"]));
    }

    #[test]
    fn parse_empty_args() {
        let cli = parse(&[]);
        assert_eq!(cli.label, None);
        assert!(cli.args.is_empty());
        assert!(!cli.config);
    }

    #[test]
    fn parse_label_requires_value() {
        // Under the old hand-rolled parser, `gitenc --label` fell through to
        // git as a literal arg. Under clap it errors with "missing value",
        // which is the correct UX — git would have rejected `--label` anyway.
        let err = try_parse(&["--label"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::InvalidValue);
    }

    #[test]
    fn parse_config_with_positional_label() {
        let cli = parse(&["--config", "github-work"]);
        assert!(cli.config);
        let label = resolve_config_label(cli.label.as_deref(), &cli.args).unwrap();
        assert_eq!(label.as_deref(), Some("github-work"));
    }

    #[test]
    fn parse_config_without_label() {
        let cli = parse(&["--config"]);
        assert!(cli.config);
        let label = resolve_config_label(cli.label.as_deref(), &cli.args).unwrap();
        assert_eq!(label, None);
    }

    #[test]
    fn parse_config_with_label_flag() {
        let cli = parse(&["--config", "--label", "my-key"]);
        assert!(cli.config);
        let label = resolve_config_label(cli.label.as_deref(), &cli.args).unwrap();
        assert_eq!(label.as_deref(), Some("my-key"));
    }

    #[test]
    fn parse_config_with_short_label_flag() {
        let cli = parse(&["--config", "-l", "my-key"]);
        assert!(cli.config);
        let label = resolve_config_label(cli.label.as_deref(), &cli.args).unwrap();
        assert_eq!(label.as_deref(), Some("my-key"));
    }

    #[test]
    fn config_rejects_both_label_flag_and_positional() {
        let cli = parse(&["--config", "--label", "a", "b"]);
        let err = resolve_config_label(cli.label.as_deref(), &cli.args).unwrap_err();
        assert!(err.contains("either"));
    }

    #[test]
    fn config_rejects_multiple_positionals() {
        let cli = parse(&["--config", "a", "b"]);
        let err = resolve_config_label(cli.label.as_deref(), &cli.args).unwrap_err();
        assert!(err.contains("at most one"));
    }

    #[test]
    fn parse_help_long_first_arg_is_intercepted_by_clap() {
        // clap's help flag prints help and returns DisplayHelp on try_parse.
        let err = try_parse(&["--help"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    #[test]
    fn parse_help_short_first_arg_is_intercepted_by_clap() {
        let err = try_parse(&["-h"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    #[test]
    fn parse_help_after_positional_passes_through_to_git() {
        // `gitenc status --help` — clap stops parsing flags after the first
        // trailing-var-arg token, so --help goes into args verbatim.
        let cli = parse(&["status", "--help"]);
        assert_eq!(cli.args, s(&["status", "--help"]));
    }

    #[test]
    fn parse_double_dash_passes_through_to_git() {
        let cli = parse(&["--", "--help"]);
        // clap consumes the `--` separator; everything after it goes to args.
        assert_eq!(cli.args, s(&["--help"]));
    }

    #[test]
    fn parse_version_first_arg_is_intercepted_by_clap() {
        let err = try_parse(&["--version"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
    }

    #[test]
    fn parse_label_with_double_dash_separator() {
        let cli = parse(&["--label", "mykey", "--", "push", "origin", "main"]);
        assert_eq!(cli.label.as_deref(), Some("mykey"));
        assert_eq!(cli.args, s(&["push", "origin", "main"]));
    }

    #[test]
    fn build_ssh_command_with_valid_label() {
        let command = build_ssh_command(Some("github-work")).unwrap();
        assert_eq!(command, "sshenc ssh --label github-work --");
    }

    #[test]
    fn build_ssh_command_rejects_invalid_label() {
        let err = build_ssh_command(Some("bad;label")).unwrap_err();
        assert!(err.to_lowercase().contains("label"));
    }

    #[test]
    fn inline_signing_args_pure_emits_expected_keys() {
        let out = inline_signing_args_pure(
            "/home/u",
            "/usr/local/bin/sshenc",
            "/home/u/.ssh/id_ecdsa.pub",
        );
        assert_eq!(out.len(), 4);
        assert!(out.contains(&"gpg.format=ssh".to_string()));
        assert!(out.contains(&"gpg.ssh.program=/usr/local/bin/sshenc".to_string()));
        assert!(out.contains(&"user.signingkey=/home/u/.ssh/id_ecdsa.pub".to_string()));
        // allowed_signers path is platform-formatted; check the prefix
        // and the expected leaf rather than a literal full string so
        // this passes on Windows (`\`) and Unix (`/`) alike.
        let allowed = out
            .iter()
            .find(|s| s.starts_with("gpg.ssh.allowedSignersFile="))
            .expect("allowed signers entry");
        assert!(allowed.contains("allowed_signers"));
        assert!(allowed.contains(".ssh"));
    }

    #[test]
    fn inline_signing_args_pure_does_not_set_commit_gpgsign() {
        // commit.gpgsign=true would surprise users with auto-signing
        // every commit. The point of inline-signing is making `-S`
        // work; users opt in by passing it.
        let out = inline_signing_args_pure(
            "/home/u",
            "/usr/local/bin/sshenc",
            "/home/u/.ssh/id_ecdsa.pub",
        );
        assert!(out.iter().all(|s| !s.starts_with("commit.gpgsign=")));
    }

    #[test]
    fn configure_repo_with_temp_git_repo() {
        // tempfile guarantees per-test uniqueness and auto-removes
        // on drop -- so a parallel test thread can't accidentally
        // delete this dir mid-`git init`.
        let dir = tempfile::Builder::new()
            .prefix("sshenc-test-configure-repo-")
            .tempdir()
            .expect("tempdir");

        let status = Command::new("git")
            .args(["init"])
            .current_dir(dir.path())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "git init failed");

        // Run configure_repo's git config commands by calling git config directly
        // in the temp repo context. We test the same logic configure_repo uses.
        let label = "test-key";
        let ssh_command = build_ssh_command(Some(label)).unwrap();
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| "/tmp".into());
        let signing_key = signing_key_path(&home, label).unwrap();

        let configs = vec![
            ("core.sshCommand".to_string(), ssh_command),
            ("gpg.format".to_string(), "ssh".to_string()),
            ("user.signingkey".to_string(), signing_key),
            ("commit.gpgsign".to_string(), "true".to_string()),
        ];

        for (key, value) in &configs {
            let status = Command::new("git")
                .args(["config", key, value])
                .current_dir(dir.path())
                .status()
                .unwrap();
            assert!(status.success(), "git config {key} failed");
        }

        // Verify the configs were set
        for (key, expected) in &configs {
            let output = Command::new("git")
                .args(["config", "--get", key])
                .current_dir(dir.path())
                .output()
                .unwrap();
            assert!(output.status.success(), "git config --get {key} failed");
            let actual = String::from_utf8(output.stdout).unwrap();
            assert_eq!(actual.trim(), expected, "config {key} mismatch");
        }
    }

    #[test]
    fn configure_repo_entries_without_label_sets_default_signing_key() {
        let entries = configure_repo_entries(None, "/tmp/home", "/tmp/sshenc", None).unwrap();
        assert!(entries
            .iter()
            .any(|(key, value)| { key == "core.sshCommand" && value == "sshenc ssh --" }));
        assert!(entries.iter().any(|(key, value)| {
            key == "user.signingkey" && value == "/tmp/home/.ssh/id_ecdsa.pub"
        }));
        assert!(entries
            .iter()
            .any(|(key, value)| key == "commit.gpgsign" && value == "true"));
    }

    #[test]
    fn configure_repo_named_label_uses_label_pub() {
        let entries =
            configure_repo_entries(Some("github-work"), "/tmp/home", "/tmp/sshenc", None).unwrap();

        assert!(entries.iter().any(|(key, value)| {
            key == "user.signingkey" && value == "/tmp/home/.ssh/github-work.pub"
        }));
    }

    #[test]
    fn signing_key_path_rejects_invalid_label() {
        let err = signing_key_path("/tmp/home", "../escape").unwrap_err();
        assert!(err.to_lowercase().contains("label"));
    }

    #[test]
    fn parse_git_key_metadata_reads_app_specific_fields() {
        let parsed = parse_git_key_metadata(
            r#"{
                "label":"work",
                "key_type":"signing",
                "app_specific":{
                    "git_name":"Alice",
                    "git_email":"alice@example.com",
                    "pub_file_path":"/tmp/work.pub"
                }
            }"#,
        )
        .unwrap();

        assert_eq!(parsed.git_name.as_deref(), Some("Alice"));
        assert_eq!(parsed.git_email.as_deref(), Some("alice@example.com"));
        assert_eq!(parsed.pub_file_path.as_deref(), Some("/tmp/work.pub"));
        assert!(parsed.pub_file_path_recorded);
    }

    #[test]
    fn parse_git_key_metadata_reads_legacy_top_level_fields() {
        let parsed = parse_git_key_metadata(
            r#"{
                "label":"work",
                "git_name":"Alice",
                "git_email":"alice@example.com"
            }"#,
        )
        .unwrap();

        assert_eq!(parsed.git_name.as_deref(), Some("Alice"));
        assert_eq!(parsed.git_email.as_deref(), Some("alice@example.com"));
        assert_eq!(parsed.pub_file_path, None);
        assert!(!parsed.pub_file_path_recorded);
    }

    #[test]
    fn configure_repo_entries_uses_recorded_pub_file_path() {
        let dir = std::env::temp_dir().join(format!(
            "sshenc-test-gitenc-pub-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let pub_path = dir.join("custom.pub");
        std::fs::write(&pub_path, "ssh-ed25519 AAAATEST test\n").unwrap();

        let metadata = GitKeyMetadata {
            git_name: None,
            git_email: None,
            pub_file_path: Some(pub_path.display().to_string()),
            pub_file_path_recorded: true,
        };
        let entries =
            configure_repo_entries(Some("work"), "/tmp/home", "/tmp/sshenc", Some(&metadata))
                .unwrap();

        assert!(entries.iter().any(|(key, value)| {
            key == "user.signingkey" && value == &pub_path.display().to_string()
        }));

        drop(std::fs::remove_dir_all(&dir));
    }

    #[test]
    fn configure_repo_entries_rejects_missing_recorded_pub_file_path() {
        let metadata = GitKeyMetadata {
            git_name: None,
            git_email: None,
            pub_file_path: None,
            pub_file_path_recorded: true,
        };

        let err = configure_repo_entries(Some("work"), "/tmp/home", "/tmp/sshenc", Some(&metadata))
            .unwrap_err();
        assert!(err.contains("does not have a recorded public key file"));
    }

    #[test]
    fn line_principals_contain_exact_match() {
        assert!(line_principals_contain(
            "alice@example.com ssh-ed25519 AAAAC3...",
            "alice@example.com"
        ));
    }

    #[test]
    fn line_principals_contain_matches_comma_separated() {
        assert!(line_principals_contain(
            "alice@example.com,alice@work.com ssh-ed25519 AAAAC3...",
            "alice@work.com"
        ));
    }

    #[test]
    fn line_principals_contain_does_not_prefix_match() {
        // Previously starts_with(email) would have matched this — the
        // attacker could lose their entry when the real user rotated.
        // Exact-match semantics keep the attacker's line intact.
        assert!(!line_principals_contain(
            "alice@example.com.attacker ssh-ed25519 AAAAC3...",
            "alice@example.com"
        ));
    }

    #[test]
    fn line_principals_contain_ignores_comments_and_blank_lines() {
        assert!(!line_principals_contain(
            "# alice@example.com is the CEO",
            "alice@example.com"
        ));
        assert!(!line_principals_contain("", "alice@example.com"));
    }

    #[test]
    fn line_principals_contain_ignores_matching_keytype_field() {
        // The email must appear in the first field (principals), not
        // later fields such as key type / base64 / comment.
        assert!(!line_principals_contain(
            "bob@example.com ssh-ed25519 alice@example.com",
            "alice@example.com"
        ));
    }

    #[test]
    fn update_allowed_signers_replaces_only_exact_match() {
        let dir = std::env::temp_dir().join(format!(
            "gitenc-allowed-signers-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("allowed_signers");

        let initial = concat!(
            "alice@example.com ssh-ed25519 AAAA-old-key\n",
            "alice@example.com.attacker ssh-ed25519 AAAA-attacker-key\n",
            "alice@example.com,alice@work.com ssh-ed25519 AAAA-multi-principal-key\n",
            "# alice@example.com is not actually here\n",
            "bob@example.com ssh-ed25519 AAAA-bob-key\n",
        );
        std::fs::write(&path, initial).unwrap();

        update_allowed_signers(
            &path,
            "alice@example.com",
            "alice@example.com ssh-ed25519 AAAA-new-key",
        )
        .unwrap();

        let result = std::fs::read_to_string(&path).unwrap();
        // Old alice exact-match line is gone.
        assert!(!result.contains("AAAA-old-key"));
        // Attacker prefix-collision line is preserved.
        assert!(result.contains("AAAA-attacker-key"));
        // Multi-principal line containing alice@example.com IS removed —
        // we matched alice@example.com exactly within the principals.
        assert!(!result.contains("AAAA-multi-principal-key"));
        // Unrelated bob line is preserved.
        assert!(result.contains("AAAA-bob-key"));
        // Comment line is preserved.
        assert!(result.contains("# alice@example.com is not actually here"));
        // New entry is appended.
        assert!(result.contains("AAAA-new-key"));

        drop(std::fs::remove_dir_all(&dir));
    }

    #[test]
    fn update_allowed_signers_creates_missing_parent_dir() {
        let dir = std::env::temp_dir().join(format!(
            "gitenc-allowed-signers-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        // Note: parent is intentionally NOT created.
        let path = dir.join("allowed_signers");
        assert!(!dir.exists());

        update_allowed_signers(
            &path,
            "alice@example.com",
            "alice@example.com ssh-ed25519 AAAA-new-key",
        )
        .unwrap();

        assert!(dir.exists());
        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("AAAA-new-key"));
        drop(std::fs::remove_dir_all(&dir));
    }

    #[test]
    fn update_allowed_signers_propagates_write_failure() {
        // Point the path inside a non-existent parent that is also
        // unwritable as a parent (the leaf parent path component is
        // a regular file, so create_dir_all will fail). This exercises
        // the error-propagation contract — the previous version would
        // have dropped this silently.
        let dir = std::env::temp_dir().join(format!(
            "gitenc-allowed-signers-fail-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let blocking_file = dir.join("blocker");
        std::fs::write(&blocking_file, b"not a directory").unwrap();
        let path = blocking_file.join("allowed_signers");

        let err = update_allowed_signers(
            &path,
            "alice@example.com",
            "alice@example.com ssh-ed25519 AAAA-new-key",
        )
        .unwrap_err();
        // The exact error kind is OS-dependent (NotADirectory on some
        // systems, NotFound on others); we just want any non-Ok
        // outcome — silent success would mean the bug we're guarding
        // against is back.
        drop(err);
        drop(std::fs::remove_dir_all(&dir));
    }

    // --- config-hint nudge --------------------------------------------------

    /// True if `git` is on PATH and looks runnable. The hint helpers
    /// shell out to git, so the tests that exercise them have to gate
    /// on this. CI runners always have git; developer laptops always
    /// have git for this repo. Skip cleanly on the rare bare image.
    fn git_available() -> bool {
        Command::new("git")
            .arg("--version")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .is_some()
    }

    fn init_temp_git_repo() -> Option<tempfile::TempDir> {
        if !git_available() {
            return None;
        }
        // tempfile::tempdir generates a process-unique, OS-unique
        // path and the returned guard removes the directory on drop.
        // Replaces a homemade pid+nanos scheme that could collide
        // when two cargo test threads in the same process hit the
        // same coarse-resolution `as_nanos()` value -- the loser of
        // that race would see its directory removed mid-`git init`
        // by the winner's cleanup.
        let dir = tempfile::Builder::new()
            .prefix("gitenc-hint-test-")
            .tempdir()
            .expect("tempdir");
        let status = Command::new("git")
            .arg("-C")
            .arg(dir.path())
            .args(["init", "--quiet"])
            .status()
            .unwrap();
        assert!(status.success());
        Some(dir)
    }

    #[test]
    fn repo_already_configured_returns_true_for_sshenc_value() {
        let Some(repo) = init_temp_git_repo() else {
            return;
        };
        Command::new("git")
            .arg("-C")
            .arg(repo.path())
            .args(["config", "--local", "core.sshCommand", "sshenc ssh --"])
            .status()
            .unwrap();
        assert!(repo_already_configured(repo.path()));
    }

    #[test]
    fn repo_already_configured_returns_false_for_unrelated_command() {
        let Some(repo) = init_temp_git_repo() else {
            return;
        };
        Command::new("git")
            .arg("-C")
            .arg(repo.path())
            .args(["config", "--local", "core.sshCommand", "/usr/bin/ssh"])
            .status()
            .unwrap();
        assert!(!repo_already_configured(repo.path()));
    }

    #[test]
    fn repo_already_configured_returns_false_when_unset() {
        let Some(repo) = init_temp_git_repo() else {
            return;
        };
        // No core.sshCommand set.
        assert!(!repo_already_configured(repo.path()));
    }

    #[test]
    fn recently_shown_false_when_sentinel_missing() {
        let dir = std::env::temp_dir().join(format!(
            "gitenc-hint-sentinel-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let sentinel = dir.join("missing");
        assert!(!recently_shown(
            &sentinel,
            SystemTime::now(),
            HINT_REPRINT_AFTER
        ));
    }

    #[test]
    fn recently_shown_true_when_sentinel_just_written() {
        let dir = std::env::temp_dir().join(format!(
            "gitenc-hint-sentinel-fresh-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let sentinel = dir.join("shown");
        touch_sentinel(&sentinel).unwrap();
        assert!(recently_shown(
            &sentinel,
            SystemTime::now(),
            HINT_REPRINT_AFTER
        ));
        drop(std::fs::remove_dir_all(&dir));
    }

    #[test]
    fn recently_shown_false_when_sentinel_older_than_window() {
        let dir = std::env::temp_dir().join(format!(
            "gitenc-hint-sentinel-old-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let sentinel = dir.join("shown");
        touch_sentinel(&sentinel).unwrap();

        // Test a `now` that's far in the future relative to the just-
        // written mtime. Doesn't depend on filesystem mtime granularity.
        let far_future = SystemTime::now() + Duration::from_secs(30 * 24 * 60 * 60);
        assert!(!recently_shown(&sentinel, far_future, HINT_REPRINT_AFTER));
        drop(std::fs::remove_dir_all(&dir));
    }

    #[test]
    fn recently_shown_true_when_mtime_in_future() {
        // Backup-restore / clock-skew case: don't spam if mtime is
        // ahead of `now`. `duration_since` returns Err in that case.
        let dir = std::env::temp_dir().join(format!(
            "gitenc-hint-sentinel-skew-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let sentinel = dir.join("shown");
        touch_sentinel(&sentinel).unwrap();

        let past = SystemTime::now() - Duration::from_secs(60 * 60);
        assert!(recently_shown(&sentinel, past, HINT_REPRINT_AFTER));
        drop(std::fs::remove_dir_all(&dir));
    }

    #[test]
    fn touch_sentinel_creates_parent_dirs() {
        let dir = std::env::temp_dir().join(format!(
            "gitenc-hint-touch-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let nested = dir.join("a").join("b").join("c").join("shown");
        touch_sentinel(&nested).unwrap();
        assert!(nested.exists());
        drop(std::fs::remove_dir_all(&dir));
    }
}
