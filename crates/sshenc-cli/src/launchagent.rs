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

/// Return the PID that launchd reports for the sshenc-agent job, or `None`
/// if the job is not loaded / has no PID (stopped but registered).
///
/// Parses the first field of `launchctl list com.godaddy.sshenc.agent`
/// output, which is the PID (or `-` when not running).
pub fn launchd_agent_pid() -> Option<u32> {
    let out = Command::new("launchctl")
        .args(["list", LABEL])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    // Output format: "<PID>\t<LastExitStatus>\t<Label>"
    // PID is `-` when the job is loaded but not running.
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first = stdout.split_whitespace().next()?;
    first.parse::<u32>().ok()
}

/// Return the PID of the process that has `socket_path` bound as a Unix
/// socket, using `lsof -U`. Returns `None` if nothing is listening or
/// if `lsof` is unavailable.
pub fn socket_listener_pid(socket_path: &Path) -> Option<u32> {
    let out = Command::new("lsof")
        .args(["-U", "-F", "p"])
        .arg(socket_path)
        .output()
        .ok()?;
    // lsof -F p outputs lines like "p<pid>" for each process.
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if let Some(pid_str) = line.strip_prefix('p') {
            if let Ok(pid) = pid_str.parse::<u32>() {
                return Some(pid);
            }
        }
    }
    None
}

/// If an sshenc-agent is listening on `socket_path` but is NOT the
/// launchd-managed instance, kill it and bootstrap the LaunchAgent so
/// the proper launchd-managed agent takes over.
///
/// Returns `Ok(true)` if a rogue agent was replaced, `Ok(false)` if the
/// listening agent is already the launchd-managed one (or nothing is
/// listening), and `Err` on failure.
pub fn replace_rogue_agent(socket_path: &Path) -> Result<bool> {
    let listener_pid = match socket_listener_pid(socket_path) {
        Some(p) => p,
        None => return Ok(false), // nothing listening
    };
    let launchd_pid = launchd_agent_pid();

    // If the listener IS the launchd-managed agent, nothing to do.
    if launchd_pid == Some(listener_pid) {
        return Ok(false);
    }

    // Rogue agent: kill it and bootstrap the launchd-managed one.
    let plist = plist_path()?;
    if !plist.exists() {
        // No plist → can't replace; just report the mismatch.
        return Err(anyhow!(
            "sshenc-agent PID {} is running outside launchd but no LaunchAgent \
             plist was found at {}. Run `sshenc install` to register the agent.",
            listener_pid,
            plist.display()
        ));
    }

    // SIGTERM the rogue agent; give it up to 2s to exit, then SIGKILL.
    drop(
        Command::new("kill")
            .args(["-TERM", &listener_pid.to_string()])
            .output(),
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        if !process_is_running(listener_pid) {
            break;
        }
        if std::time::Instant::now() >= deadline {
            drop(
                Command::new("kill")
                    .args(["-KILL", &listener_pid.to_string()])
                    .output(),
            );
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // Bootstrap the launchd-managed agent.
    let domain = launchctl_domain()?;
    bootout_if_loaded()?;
    let bootstrap = Command::new("launchctl")
        .args(["bootstrap", &domain])
        .arg(&plist)
        .output()
        .context("launchctl bootstrap")?;
    if !bootstrap.status.success() {
        return Err(anyhow!(
            "launchctl bootstrap failed after killing rogue agent: {}",
            String::from_utf8_lossy(&bootstrap.stderr)
        ));
    }

    Ok(true)
}

/// Returns true if a process with the given PID is still running.
fn process_is_running(pid: u32) -> bool {
    // `kill -0` sends no signal but checks if the process exists and
    // we have permission to signal it.
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
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

    /// Socket paths and binary paths containing hyphens and underscores must
    /// appear verbatim in the generated plist — special characters in paths
    /// must not be escaped or truncated.
    #[test]
    fn render_plist_handles_path_with_hyphens_and_underscores() {
        let p = render_plist(
            Path::new("/opt/my-tools/sshenc_agent"),
            Path::new("/var/run/sshenc-agent_socket/agent.sock"),
        );
        assert!(
            p.contains("/opt/my-tools/sshenc_agent"),
            "binary path with hyphens/underscores must appear verbatim"
        );
        assert!(
            p.contains("/var/run/sshenc-agent_socket/agent.sock"),
            "socket path with hyphens/underscores must appear verbatim"
        );
    }

    /// Calling `render_plist` twice with the same inputs must produce byte-identical
    /// output, confirming idempotent file writes won't cause spurious mtime changes.
    #[test]
    fn render_plist_is_deterministic() {
        let bin = Path::new("/usr/local/bin/sshenc-agent");
        let sock = Path::new("/tmp/.sshenc/agent.sock");
        let first = render_plist(bin, sock);
        let second = render_plist(bin, sock);
        assert_eq!(first, second, "render_plist must be deterministic");
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
