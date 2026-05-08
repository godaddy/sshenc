// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Structured per-operation event log for the sshenc agent.
//!
//! Every HSM-touching request handler in [`crate::server`] (sign,
//! generate, delete, rename, migrate-meta) records one JSONL line
//! to a user-private log file so we can audit:
//!
//! - **What** the user actually triggers (op + label).
//! - **When** it happened (RFC3339 UTC timestamp).
//! - **How long** it took (`duration_ms`).
//! - **Whether a hardware prompt fired** (`prompt_inferred`):
//!   anything past `SSHENC_FINGERPRINT_THRESHOLD_MS` (default 250ms)
//!   is assumed to have triggered a Touch ID / Hello / device
//!   password prompt. This is a heuristic — slow disk or swap
//!   pressure can produce false positives — but we've found it
//!   accurate enough in practice to reason about user-visible
//!   behaviour without surfacing every backend prompt event
//!   explicitly.
//! - **Whether it succeeded** (`ok`).
//!
//! The log is **never** allowed to make a request fail: every write
//! is best-effort and logged-at-debug if it errors. Sensitive
//! material (private bytes, signature bytes, public-key bytes,
//! comments) is never recorded — labels and operation verbs only.
//!
//! Schema (one JSON object per line):
//!
//! ```json
//! {"ts":"2026-05-08T15:02:10.123Z","op":"sign","label":"work","target":null,"duration_ms":312,"prompt_inferred":true,"ok":true,"pid":12345,"in_agent":true}
//! ```
//!
//! `target` is only populated for `rename` (the new label); other
//! operations leave it `null`. `in_agent` is always `true` here — we
//! keep the field for cross-app log parity with other enclave apps
//! that record events from both their agent and CLI sides.
//!
//! The event log is **not** a replacement for `tracing`. `tracing`
//! still emits structured per-event records on stderr / journald;
//! the JSONL log is the durable, parseable, user-visible record.

use serde_json::json;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Default threshold above which we assume an HSM prompt fired.
/// 250ms is well above filesystem/RPC noise on a healthy host but
/// below the floor of a real biometric prompt.
const FINGERPRINT_THRESHOLD_MS_DEFAULT: u64 = 250;

/// Env override for the prompt-inferred threshold. Useful for tests
/// (set to 0 to force `prompt_inferred: true`) and for hosts where
/// the default heuristic is noisy.
const THRESHOLD_ENV: &str = "SSHENC_FINGERPRINT_THRESHOLD_MS";

/// Env override for the log path. When set, replaces the default
/// `~/.sshenc/enclave-events.log` location wholesale.
const LOG_PATH_ENV: &str = "SSHENC_OP_LOG";

fn fingerprint_threshold() -> Duration {
    Duration::from_millis(
        std::env::var(THRESHOLD_ENV)
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|v: &u64| *v > 0)
            .unwrap_or(FINGERPRINT_THRESHOLD_MS_DEFAULT),
    )
}

#[cfg(not(test))]
fn default_log_path() -> Option<PathBuf> {
    Some(dirs::home_dir()?.join(".sshenc").join("enclave-events.log"))
}

/// In `cfg(test)` builds, `record()` writes nowhere by default —
/// neither the env override (`SSHENC_OP_LOG`) nor `~/.sshenc/` is
/// honored. Two reasons:
///
/// 1. Server-handler unit tests that drive `process_request` through
///    the dispatcher would otherwise scribble events into the
///    developer's real audit log on every `cargo test`.
/// 2. Tests that legitimately exercise the writer set
///    `SSHENC_OP_LOG` to a tempdir; if a parallel server-handler
///    test happens to call `record()` while that env var is set, it
///    would race on the same file (concurrent JSONL writes interleave
///    bytes mid-line and the reader sees malformed JSON).
///
/// Tests that exercise the writer call `record_to` directly with
/// an explicit path. Production binaries (where `cfg(test)` is not
/// active) honor `SSHENC_OP_LOG` and the `~/.sshenc/` default.
#[cfg(not(test))]
fn resolved_log_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var(LOG_PATH_ENV) {
        if !p.is_empty() {
            return Some(PathBuf::from(p));
        }
    }
    default_log_path()
}

#[cfg(test)]
fn resolved_log_path() -> Option<PathBuf> {
    None
}

/// Record one enclave-operation event.
///
/// `op` is a stable verb (`sign`, `generate`, `delete`, `rename`,
/// `migrate_meta`, ...). `label` is the user-chosen key label, or
/// `None` for ops that don't operate on a single key. `target` is
/// only used for `rename` (the new label).
///
/// Errors during log write are swallowed — never propagate up to
/// the request handler, since failing to log must not turn a
/// successful sign into a failed sign.
pub fn record(op: &str, label: Option<&str>, target: Option<&str>, elapsed: Duration, ok: bool) {
    record_to(
        resolved_log_path().as_deref(),
        op,
        label,
        target,
        elapsed,
        ok,
    );
}

/// Lower-level form: write to an explicit path (or no-op if `path`
/// is `None`). Used by tests that need to drive the writer without
/// touching process-global env vars.
fn record_to(
    path: Option<&std::path::Path>,
    op: &str,
    label: Option<&str>,
    target: Option<&str>,
    elapsed: Duration,
    ok: bool,
) {
    let Some(path) = path else {
        return;
    };
    let prompt_inferred = elapsed >= fingerprint_threshold();
    let line = json!({
        "ts": now_rfc3339(),
        "op": op,
        "label": label,
        "target": target,
        "duration_ms": elapsed.as_millis() as u64,
        "prompt_inferred": prompt_inferred,
        "ok": ok,
        "pid": std::process::id(),
        "in_agent": true,
    });
    write_line(path, &line.to_string());
}

fn write_line(path: &std::path::Path, line: &str) {
    if let Some(parent) = path.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            tracing::debug!(parent = %parent.display(), error = %e, "op_log: create_dir_all failed");
            return;
        }
    }
    let opened = fs::OpenOptions::new().create(true).append(true).open(path);
    let mut file = match opened {
        Ok(f) => f,
        Err(e) => {
            tracing::debug!(path = %path.display(), error = %e, "op_log: open failed");
            return;
        }
    };
    if let Err(e) = writeln!(file, "{line}") {
        tracing::debug!(path = %path.display(), error = %e, "op_log: write failed");
        return;
    }
    // Tighten perms after first write. Best-effort; same-process
    // re-runs see the perms already restricted, so this is a no-op
    // on the hot path. We don't touch the parent dir's perms — the
    // user may have set umask deliberately.
    set_private_permissions(path);
}

#[cfg(unix)]
fn set_private_permissions(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &std::path::Path) {
    // Windows: the file inherits ACLs from the parent
    // (`%USERPROFILE%\.sshenc\`), which is already user-private on a
    // standard install. The agent never runs as a service / system
    // account in the supported configurations, so re-stamping
    // explicit DACLs would be redundant — and getting it wrong
    // (e.g. dropping the user's own access) would lose events.
}

/// Format `SystemTime::now()` as an RFC3339 string with millisecond
/// precision in UTC, e.g. `2026-05-08T15:02:10.123Z`.
///
/// Hand-rolled to avoid pulling in `chrono` / `time` for one
/// timestamp. Implements Howard Hinnant's
/// [civil_from_days](http://howardhinnant.github.io/date_algorithms.html)
/// algorithm — proleptic Gregorian, valid for any year representable
/// as `i64`. We don't need that range; `SystemTime` clamps us to
/// the system clock, which is well within the algorithm's
/// well-behaved domain.
fn now_rfc3339() -> String {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    epoch_to_rfc3339(dur.as_secs(), dur.subsec_millis())
}

fn epoch_to_rfc3339(epoch_secs: u64, millis: u32) -> String {
    let days = (epoch_secs / 86_400) as i64;
    let secs_of_day = epoch_secs % 86_400;
    let h = secs_of_day / 3_600;
    let m = (secs_of_day % 3_600) / 60;
    let s = secs_of_day % 60;

    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}.{millis:03}Z")
}

/// Convert days-since-1970-01-01 into a (year, month, day) civil
/// Gregorian date. Howard Hinnant's published algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serialize tests that mutate `SSHENC_FINGERPRINT_THRESHOLD_MS`
    /// (the only process-global env var the writer still consults).
    /// All other tests drive the writer through `record_to` directly
    /// so they don't touch env at all and can run concurrently.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn tempdir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "sshenc-op-log-test-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            n,
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn cleanup(dir: &std::path::Path) {
        drop(fs::remove_dir_all(dir));
    }

    fn read_lines(path: &std::path::Path) -> Vec<serde_json::Value> {
        fs::read_to_string(path)
            .unwrap()
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[test]
    fn epoch_to_rfc3339_unix_epoch_zero() {
        assert_eq!(epoch_to_rfc3339(0, 0), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn epoch_to_rfc3339_known_values() {
        // 2026-05-08T15:02:10.123Z = 1778252530s + 123ms.
        // Sanity-checked against a separate date library.
        assert_eq!(
            epoch_to_rfc3339(1_778_252_530, 123),
            "2026-05-08T15:02:10.123Z"
        );
    }

    #[test]
    fn epoch_to_rfc3339_handles_leap_day() {
        // 2024-02-29T12:00:00 = 1709208000.
        assert_eq!(
            epoch_to_rfc3339(1_709_208_000, 0),
            "2024-02-29T12:00:00.000Z"
        );
    }

    #[test]
    fn record_writes_jsonl_with_expected_schema() {
        let dir = tempdir();
        let log = dir.join("events.log");
        // Pin THRESHOLD_ENV so prompt_inferred is deterministic
        // regardless of host clock noise. Serialize on ENV_LOCK
        // because env is process-global.
        let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(THRESHOLD_ENV, "10000");

        record_to(
            Some(&log),
            "sign",
            Some("work"),
            None,
            Duration::from_millis(50),
            true,
        );
        record_to(
            Some(&log),
            "rename",
            Some("old"),
            Some("new"),
            Duration::from_millis(20),
            true,
        );
        record_to(
            Some(&log),
            "generate",
            Some("oops"),
            None,
            Duration::from_millis(75),
            false,
        );

        std::env::remove_var(THRESHOLD_ENV);
        drop(guard);

        let events = read_lines(&log);
        assert_eq!(events.len(), 3);

        let e0 = &events[0];
        assert_eq!(e0["op"], "sign");
        assert_eq!(e0["label"], "work");
        assert_eq!(e0["target"], serde_json::Value::Null);
        assert_eq!(e0["duration_ms"], 50);
        assert_eq!(e0["prompt_inferred"], false);
        assert_eq!(e0["ok"], true);
        assert_eq!(e0["in_agent"], true);
        assert!(e0["pid"].is_u64());
        assert!(
            e0["ts"].as_str().unwrap().ends_with('Z'),
            "ts should be RFC3339-UTC: {}",
            e0["ts"]
        );

        assert_eq!(events[1]["op"], "rename");
        assert_eq!(events[1]["target"], "new");

        assert_eq!(events[2]["ok"], false);

        cleanup(&dir);
    }

    #[test]
    fn prompt_inferred_fires_above_threshold() {
        let dir = tempdir();
        let log = dir.join("events.log");
        let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(THRESHOLD_ENV, "100");

        record_to(
            Some(&log),
            "sign",
            Some("k"),
            None,
            Duration::from_millis(50),
            true,
        );
        record_to(
            Some(&log),
            "sign",
            Some("k"),
            None,
            Duration::from_millis(150),
            true,
        );

        std::env::remove_var(THRESHOLD_ENV);
        drop(guard);

        let events = read_lines(&log);
        assert_eq!(events[0]["prompt_inferred"], false);
        assert_eq!(events[1]["prompt_inferred"], true);

        cleanup(&dir);
    }

    #[test]
    fn record_to_swallows_path_errors() {
        // Point the log at a path whose parent can't be created
        // (a regular file masquerading as a directory). The call
        // must not panic or propagate.
        let dir = tempdir();
        let blocker = dir.join("blocker");
        fs::write(&blocker, b"i am a file").unwrap();
        record_to(
            Some(&blocker.join("events.log")),
            "sign",
            Some("x"),
            None,
            Duration::from_millis(0),
            true,
        );
        cleanup(&dir);
    }

    #[test]
    fn record_to_with_none_path_is_noop() {
        // The cfg(test) build path: `record()` passes `None` and
        // we do nothing. No file written, no panic.
        record_to(
            None,
            "sign",
            Some("k"),
            None,
            Duration::from_millis(0),
            true,
        );
    }

    #[test]
    fn record_appends_across_calls() {
        let dir = tempdir();
        let log = dir.join("events.log");
        for i in 0..5 {
            record_to(
                Some(&log),
                "sign",
                Some(&format!("k{i}")),
                None,
                Duration::from_millis(0),
                true,
            );
        }
        let events = read_lines(&log);
        assert_eq!(events.len(), 5);
        for (i, ev) in events.iter().enumerate() {
            assert_eq!(ev["label"], format!("k{i}"));
        }
        cleanup(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn record_sets_private_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir();
        let log = dir.join("events.log");
        record_to(
            Some(&log),
            "sign",
            Some("k"),
            None,
            Duration::from_millis(0),
            true,
        );
        let mode = fs::metadata(&log).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "log file should be owner-only");
        cleanup(&dir);
    }

    #[test]
    fn cfg_test_record_writes_nowhere_by_default() {
        // The `pub fn record(...)` API must be a no-op in cfg(test)
        // builds even when SSHENC_OP_LOG is set, so server-handler
        // unit tests don't accidentally race on a sibling op_log
        // test's tempdir. (Production paths exercise the env path
        // via `#[cfg(not(test))]`, covered by the integration suite
        // that runs the real agent binary.)
        let dir = tempdir();
        let log = dir.join("events.log");
        let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(LOG_PATH_ENV, &log);
        record("sign", Some("k"), None, Duration::from_millis(0), true);
        std::env::remove_var(LOG_PATH_ENV);
        drop(guard);
        assert!(
            !log.exists(),
            "cfg(test) should disable env-driven log writes"
        );
        cleanup(&dir);
    }
}
