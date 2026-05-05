// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! macOS LaunchAgent registration for the sshenc agent.
//!
//! Why this exists: a daemonized `sshenc agent` (the default form
//! when `--foreground` isn't passed) double-forks and reparents to
//! launchd. After detach the process is no longer associated with
//! the user's GUI session, so macOS won't let it show
//! `LAContext.evaluatePolicy(.deviceOwnerAuthentication)` UI. The
//! wrapping-key keychain entry is gated on
//! `kSecAccessControl(.userPresence)`, so loading it from a
//! detached process fails silently and every sign request that
//! needs a cold wrapping-key cache returns FAILURE. The
//! user-visible symptom is `sign_and_send_pubkey: signing failed
//! for ECDSA "..." from agent: communication with agent failed`.
//!
//! The fix is a `LaunchAgent` (not `LaunchDaemon` -- agents run in
//! the user's GUI domain, daemons in the system domain). Bootstrap
//! into `gui/<uid>` so it inherits the Aqua session: now Touch ID
//! prompts work and macOS treats the agent like any other GUI-app
//! the user runs. As a side benefit launchd enforces uniqueness on
//! the `Label`, so multiple stale `sshenc-agent` processes can't
//! pile up the way they did when bare-daemonize spawn was retried
//! across shells.

#![cfg(target_os = "macos")]
#![allow(clippy::print_stdout)]

use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

const LABEL: &str = "com.godaddy.sshenc.agent";

/// Path to the user's LaunchAgent plist for sshenc.
pub fn plist_path() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("could not determine home directory"))?;
    Ok(home
        .join("Library/LaunchAgents")
        .join(format!("{LABEL}.plist")))
}

/// Generate the plist contents pointing at `agent_bin` and binding
/// `socket_path`. We hard-code `--foreground` so launchd's
/// `KeepAlive` semantics work (a daemonizing agent would exit the
/// supervised process immediately after fork, defeating KeepAlive).
fn render_plist(agent_bin: &Path, socket_path: &Path) -> String {
    // The plist generator is intentionally hand-written rather than
    // pulling in a plist crate: the schema is tiny and stable, and
    // we already have `plutil -lint` as the validator at write time.
    let agent = agent_bin.display();
    let socket = socket_path.display();
    let home = dirs::home_dir()
        .map(|h| h.display().to_string())
        .unwrap_or_else(|| "/".to_string());
    let stdout_log = format!("{}/.sshenc/agent.out.log", home.trim_end_matches('/'));
    let stderr_log = format!("{}/.sshenc/agent.err.log", home.trim_end_matches('/'));
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{agent}</string>
        <string>--socket</string>
        <string>{socket}</string>
        <string>--foreground</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ProcessType</key>
    <string>Interactive</string>
    <key>StandardOutPath</key>
    <string>{stdout_log}</string>
    <key>StandardErrorPath</key>
    <string>{stderr_log}</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>HOME</key>
        <string>{home}</string>
    </dict>
</dict>
</plist>
"#,
    )
}

fn user_id() -> Result<u32> {
    // Posix `getuid()` -- libc dep would be the cleanest path but
    // the crate already depends on libc transitively via tokio /
    // dirs and the call is one shim away. Use std env to stay shim-
    // free: macOS exports `UID` reliably for login shells, and
    // launchctl-bootstrap targets by numeric uid.
    if let Ok(uid_str) = std::env::var("UID") {
        if let Ok(uid) = uid_str.parse::<u32>() {
            return Ok(uid);
        }
    }
    // Fallback: shell out to `id -u`. Slower but always works,
    // including for processes spawned without UID set in env.
    let out = Command::new("id").arg("-u").output().context("id -u")?;
    if !out.status.success() {
        return Err(anyhow!(
            "id -u failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    s.parse::<u32>()
        .map_err(|e| anyhow!("id -u returned non-numeric output {s:?}: {e}"))
}

fn launchctl_domain() -> Result<String> {
    Ok(format!("gui/{}", user_id()?))
}

/// Whether launchd already has the LaunchAgent loaded under
/// `gui/<uid>`. Lets the install path stay idempotent: if the
/// plist is on disk and loaded with our content, do nothing.
pub fn is_loaded() -> Result<bool> {
    let domain = launchctl_domain()?;
    let out = Command::new("launchctl")
        .args(["print", &format!("{domain}/{LABEL}")])
        .output()
        .context("launchctl print")?;
    Ok(out.status.success())
}

/// Bootout (unload) the LaunchAgent if it's currently loaded. A
/// fresh bootstrap of the same Label fails if the previous instance
/// is still loaded, so callers do this before bootstrap.
fn bootout_if_loaded() -> Result<()> {
    if !is_loaded()? {
        return Ok(());
    }
    let domain = launchctl_domain()?;
    let plist = plist_path()?;
    let out = Command::new("launchctl")
        .args(["bootout", &format!("{domain}/{LABEL}")])
        .arg(&plist)
        .output()
        .context("launchctl bootout")?;
    if !out.status.success() {
        // Bootout's exit code can be non-zero in flaky cases that
        // still result in the service being absent (race with the
        // launchd service db updating). Treat the post-condition
        // (`is_loaded() == false`) as the source of truth.
        if is_loaded().unwrap_or(true) {
            return Err(anyhow!(
                "launchctl bootout failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
    }
    Ok(())
}

/// Write the plist for `agent_bin` listening on `socket_path`,
/// validate via `plutil -lint`, then bootstrap into the user's GUI
/// domain. Idempotent: removes any prior LaunchAgent under the same
/// Label and replaces it.
pub fn install(agent_bin: &Path, socket_path: &Path) -> Result<()> {
    let plist = plist_path()?;
    if let Some(parent) = plist.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }

    let contents = render_plist(agent_bin, socket_path);
    std::fs::write(&plist, contents.as_bytes())
        .with_context(|| format!("writing {}", plist.display()))?;

    let lint = Command::new("plutil")
        .arg("-lint")
        .arg(&plist)
        .output()
        .context("plutil -lint")?;
    if !lint.status.success() {
        return Err(anyhow!(
            "plutil -lint rejected {}: {}",
            plist.display(),
            String::from_utf8_lossy(&lint.stderr)
        ));
    }

    // If a prior instance is loaded, bootout first. Bootstrap rejects
    // a duplicate Label otherwise.
    bootout_if_loaded()?;

    let domain = launchctl_domain()?;
    let bootstrap = Command::new("launchctl")
        .args(["bootstrap", &domain])
        .arg(&plist)
        .output()
        .context("launchctl bootstrap")?;
    if !bootstrap.status.success() {
        return Err(anyhow!(
            "launchctl bootstrap failed: {}",
            String::from_utf8_lossy(&bootstrap.stderr)
        ));
    }
    Ok(())
}

/// Bootout the LaunchAgent and remove its plist. Idempotent: a
/// missing plist or already-unloaded service is treated as success.
pub fn uninstall() -> Result<()> {
    bootout_if_loaded()?;
    let plist = plist_path()?;
    if plist.exists() {
        std::fs::remove_file(&plist).with_context(|| format!("removing {}", plist.display()))?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn render_plist_contains_label_args_and_keepalive() {
        let p = render_plist(
            Path::new("/opt/homebrew/Cellar/sshenc/0.6.55/sshenc.app/Contents/MacOS/sshenc-agent"),
            Path::new("/Users/jay/.sshenc/agent.sock"),
        );
        assert!(p.contains("<string>com.godaddy.sshenc.agent</string>"));
        assert!(p.contains("--foreground"));
        assert!(p.contains("--socket"));
        assert!(p.contains("/Users/jay/.sshenc/agent.sock"));
        assert!(p.contains("<key>KeepAlive</key>"));
        assert!(p.contains("<key>RunAtLoad</key>"));
        // ProcessType=Interactive lets launchd give the agent the
        // session-attach treatment it needs to show LAContext UI.
        assert!(p.contains("<string>Interactive</string>"));
    }

    #[test]
    fn render_plist_validates_with_plutil() {
        let p = render_plist(
            Path::new("/usr/bin/sshenc-agent"),
            Path::new("/tmp/agent.sock"),
        );
        // Round-trip through plutil -lint by writing to a tmp file.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.plist");
        std::fs::write(&path, p.as_bytes()).unwrap();
        let lint = Command::new("plutil")
            .arg("-lint")
            .arg(&path)
            .output()
            .expect("plutil");
        assert!(
            lint.status.success(),
            "plutil -lint rejected the rendered plist:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&lint.stdout),
            String::from_utf8_lossy(&lint.stderr)
        );
    }

    #[test]
    fn plist_path_is_under_user_launchagents() {
        let p = plist_path().unwrap();
        assert!(
            p.to_string_lossy().contains("/Library/LaunchAgents/"),
            "expected LaunchAgents path, got {}",
            p.display()
        );
        assert!(
            p.file_name()
                .is_some_and(|n| n == "com.godaddy.sshenc.agent.plist"),
            "unexpected filename: {}",
            p.display()
        );
    }
}
