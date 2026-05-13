// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Unified agent log: HSM operation events and warn/error diagnostics.
//!
//! Two record types share one append-only JSONL file (`~/.sshenc/sshenc.log`):
//!
//! **Operation records** — written by [`record`] after every HSM-touching
//! request (sign, generate, delete, rename, migrate-meta):
//!
//! ```json
//! {"ts":"2026-05-08T15:02:10.123Z","op":"sign","label":"work","target":null,"duration_ms":312,"prompt_inferred":true,"ok":true,"pid":12345,"in_agent":true}
//! ```
//!
//! **Diagnostic records** — written by [`WarnErrorFileLayer`] for every
//! `warn!` / `error!` tracing event:
//!
//! ```json
//! {"ts":"2026-05-08T15:02:10.456Z","level":"WARN","target":"sshenc_agent::server","message":"unix socket read error","error":"connection reset by peer"}
//! ```
//!
//! Both record types are best-effort: write failures are never propagated
//! to the caller. Sensitive material (private bytes, signatures, comments)
//! is never recorded.

use serde_json::json;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::Context;

/// Default threshold above which we assume an HSM prompt fired.
/// 250ms is well above filesystem/RPC noise on a healthy host but
/// below the floor of a real biometric prompt.
const FINGERPRINT_THRESHOLD_MS_DEFAULT: u64 = 250;

/// Lower bound for the threshold env override. Anything below this
/// is dominated by filesystem / RPC noise and would mark virtually
/// every op as `prompt_inferred: true`, which neuters the signal.
const FINGERPRINT_THRESHOLD_MS_MIN: u64 = 10;

/// Upper bound for the threshold env override. 5 minutes generously
/// covers slow VMs / paged-out hosts / cold-start TPM warm-up. Past
/// that, any "high threshold" value is either a misconfiguration or
/// a deliberate attempt to hide prompt activity from the audit log
/// (e.g. setting it to days so every op records `prompt_inferred:
/// false`). The HSM still enforces presence regardless — this is a
/// log-accuracy clamp, not a presence-policy gate — but a tamperable
/// audit log is itself a defect.
const FINGERPRINT_THRESHOLD_MS_MAX: u64 = 5 * 60 * 1000;

/// Env override for the prompt-inferred threshold. Honored only
/// when the value is in `[FINGERPRINT_THRESHOLD_MS_MIN, MAX]`;
/// otherwise we fall back to the default with a warn-level trace.
const THRESHOLD_ENV: &str = "SSHENC_FINGERPRINT_THRESHOLD_MS";

/// Env override for the log path. Honored only when the value is
/// (a) absolute, (b) has an existing parent directory, (c) is not
/// a symlink, and (d) does not resolve to a parent that is a
/// symlink (defense against
/// `mkdir /tmp/sneaky && ln -s /var/log /tmp/sneaky/parent`).
/// Otherwise we fall back to the `~/.sshenc/` default with a warn.
const LOG_PATH_ENV: &str = "SSHENC_LOG";

fn fingerprint_threshold() -> Duration {
    let raw = match std::env::var(THRESHOLD_ENV) {
        Ok(v) if !v.is_empty() => v,
        _ => return Duration::from_millis(FINGERPRINT_THRESHOLD_MS_DEFAULT),
    };
    match raw.parse::<u64>() {
        Ok(n) if (FINGERPRINT_THRESHOLD_MS_MIN..=FINGERPRINT_THRESHOLD_MS_MAX).contains(&n) => {
            Duration::from_millis(n)
        }
        Ok(n) => {
            tracing::warn!(
                value = n,
                min = FINGERPRINT_THRESHOLD_MS_MIN,
                max = FINGERPRINT_THRESHOLD_MS_MAX,
                "op_log: SSHENC_FINGERPRINT_THRESHOLD_MS out of range; using default"
            );
            Duration::from_millis(FINGERPRINT_THRESHOLD_MS_DEFAULT)
        }
        Err(_) => {
            tracing::warn!(
                value = %raw,
                "op_log: SSHENC_FINGERPRINT_THRESHOLD_MS not a positive integer; using default"
            );
            Duration::from_millis(FINGERPRINT_THRESHOLD_MS_DEFAULT)
        }
    }
}

#[cfg(not(test))]
fn default_log_path() -> Option<PathBuf> {
    Some(dirs::home_dir()?.join(".sshenc").join("sshenc.log"))
}

/// In `cfg(test)` builds, `record()` writes nowhere by default —
/// neither the env override (`SSHENC_LOG`) nor `~/.sshenc/` is
/// honored. Two reasons:
///
/// 1. Server-handler unit tests that drive `process_request` through
///    the dispatcher would otherwise scribble events into the
///    developer's real log on every `cargo test`.
/// 2. Tests that legitimately exercise the writer set
///    `SSHENC_LOG` to a tempdir; if a parallel server-handler
///    test happens to call `record()` while that env var is set, it
///    would race on the same file (concurrent JSONL writes interleave
///    bytes mid-line and the reader sees malformed JSON).
///
/// Tests that exercise the writer call `record_to` directly with
/// an explicit path. Production binaries (where `cfg(test)` is not
/// active) honor `SSHENC_LOG` and the `~/.sshenc/` default.
#[cfg(not(test))]
fn resolved_log_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var(LOG_PATH_ENV) {
        if !p.is_empty() {
            match validate_log_path_override(&PathBuf::from(p)) {
                Ok(path) => return Some(path),
                Err(reason) => {
                    tracing::warn!(
                        reason,
                        "op_log: SSHENC_LOG override rejected; using default"
                    );
                }
            }
        }
    }
    default_log_path()
}

/// Validate a `SSHENC_LOG` override before honoring it.
///
/// Rules — same intent as OpenSSH's `IdentityFile` validation in
/// principle: don't let an env var trick the agent into writing
/// audit lines somewhere the user didn't mean.
///
/// 1. **Absolute path**: relative paths are interpreted relative
///    to the agent's CWD which is whatever directory the user
///    happened to launch the agent from — basically random. An
///    a log at `sshenc.log` relative to a random CWD is worse than no override.
/// 2. **Parent directory exists**: don't auto-create deep paths
///    that might land in attacker-controlled prefixes. If the
///    operator wants to put the log elsewhere, they create the
///    directory first.
/// 3. **Not a symlink at the target**: refuse if the path itself
///    already exists as a symlink. We never want to follow a
///    symlink for an audit-log write — a malicious symlink could
///    redirect us to clobber a sensitive file.
/// 4. **Parent directory is not a symlink**: closes the
///    `mkdir sneaky/ && ln -s /var/log sneaky/parent` redirect.
///
/// Returns the path on success, or a static reason string on
/// rejection. The reason is suitable for the warn log.
fn validate_log_path_override(path: &std::path::Path) -> Result<PathBuf, &'static str> {
    if !path.is_absolute() {
        return Err("path is not absolute");
    }
    let parent = path.parent().ok_or("path has no parent")?;
    let parent_meta =
        fs::symlink_metadata(parent).map_err(|_| "parent directory does not exist")?;
    if parent_meta.file_type().is_symlink() {
        return Err("parent directory is a symlink");
    }
    if !parent_meta.is_dir() {
        return Err("parent path is not a directory");
    }
    // The target file may or may not exist yet (first run). If it
    // exists, it must be a regular file — never a symlink.
    if let Ok(target_meta) = fs::symlink_metadata(path) {
        if target_meta.file_type().is_symlink() {
            return Err("log path is a symlink");
        }
    }
    Ok(path.to_path_buf())
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
pub fn record(
    op: &str,
    label: Option<&str>,
    target: Option<&str>,
    elapsed: Duration,
    ok: bool,
    error: Option<&str>,
) {
    record_to(
        resolved_log_path().as_deref(),
        op,
        label,
        target,
        elapsed,
        ok,
        error,
    );
}

/// Returns the resolved log path for this process. `None` in `cfg(test)` builds
/// and when `dirs::home_dir()` is unavailable.
pub fn log_path() -> Option<PathBuf> {
    resolved_log_path()
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
    error: Option<&str>,
) {
    let Some(path) = path else {
        return;
    };
    let prompt_inferred = elapsed >= fingerprint_threshold();
    let mut obj = json!({
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
    if let Some(err) = error {
        obj.as_object_mut()
            .expect("json! always produces an object")
            .insert(
                "error".to_string(),
                serde_json::Value::String(err.to_string()),
            );
    }
    write_line(path, &obj.to_string());
}

/// Tracing [`Layer`] that appends `warn!` and `error!` events to the unified
/// log file as JSONL, sharing rotation and file-write infrastructure with
/// [`record`].
///
/// Install via `tracing_subscriber::registry().with(WarnErrorFileLayer::new(log_path()))`.
/// When `path` is `None` (test builds, missing home dir) the layer is a no-op.
#[derive(Debug)]
pub struct WarnErrorFileLayer {
    path: Option<PathBuf>,
}

impl WarnErrorFileLayer {
    pub fn new(path: Option<PathBuf>) -> Self {
        Self { path }
    }
}

struct FieldCollector {
    message: Option<String>,
    extra: serde_json::Map<String, serde_json::Value>,
}

impl FieldCollector {
    fn new() -> Self {
        Self {
            message: None,
            extra: serde_json::Map::new(),
        }
    }
}

impl Visit for FieldCollector {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let s = format!("{value:?}");
        if field.name() == "message" {
            self.message = Some(s);
        } else {
            self.extra
                .insert(field.name().to_string(), serde_json::Value::String(s));
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        } else {
            self.extra.insert(
                field.name().to_string(),
                serde_json::Value::String(value.to_string()),
            );
        }
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.extra.insert(
            field.name().to_string(),
            serde_json::Value::String(value.to_string()),
        );
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.extra
            .insert(field.name().to_string(), serde_json::Value::Bool(value));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.extra.insert(
            field.name().to_string(),
            serde_json::Value::Number(value.into()),
        );
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.extra.insert(
            field.name().to_string(),
            serde_json::Value::Number(value.into()),
        );
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.extra.insert(
            field.name().to_string(),
            serde_json::Number::from_f64(value)
                .map(serde_json::Value::Number)
                .unwrap_or_else(|| serde_json::Value::String(value.to_string())),
        );
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for WarnErrorFileLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        // Only capture WARN and ERROR; INFO/DEBUG/TRACE stay stderr-only.
        if *event.metadata().level() > tracing::Level::WARN {
            return;
        }
        let Some(path) = &self.path else { return };

        let mut collector = FieldCollector::new();
        event.record(&mut collector);

        let mut obj = json!({
            "ts": now_rfc3339(),
            "level": event.metadata().level().as_str(),
            "target": event.metadata().target(),
        });
        let map = obj
            .as_object_mut()
            .expect("json! always produces an object");
        if let Some(msg) = collector.message {
            map.insert("message".to_string(), serde_json::Value::String(msg));
        }
        for (k, v) in collector.extra {
            map.insert(k, v);
        }

        write_line(path, &obj.to_string());
    }
}

/// Maximum size of the active log file before we rotate. 10 MiB
/// is generous for a single-user log — at typical agent volume
/// that's months of events per rotation.
const ROTATE_MAX_BYTES: u64 = 10 * 1024 * 1024;

/// Number of historical rotations to retain. With ROTATE_MAX_BYTES = 10MiB
/// and ROTATE_KEEP = 5, the log occupies at most ~60MiB (active + 5 rotations).
const ROTATE_KEEP: u32 = 5;

fn write_line(path: &std::path::Path, line: &str) {
    if let Some(parent) = path.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            tracing::debug!(parent = %parent.display(), error = %e, "op_log: create_dir_all failed");
            return;
        }
    }
    maybe_rotate(path);
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
    // `drop(...)` rather than `let _ = ...` so we don't trip
    // `clippy::let_underscore_drop` (Result has a destructor); and
    // not `let _unused = ...` either, which trips
    // `clippy::no_effect_underscore_binding`. Permission-tighten
    // failures are best-effort: we already wrote the line.
    drop(fs::set_permissions(path, fs::Permissions::from_mode(0o600)));
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

/// Rotate `path` if its current size is at or above
/// `ROTATE_MAX_BYTES`. Best-effort: failures are surfaced louder
/// than other op_log errors (eprintln + tracing::warn) because a
/// silent rotation failure means the audit log will continue to
/// grow unbounded — exactly the failure mode rotation exists to
/// prevent. We do NOT propagate the error: a rotation failure must
/// not block a successful sign from being recorded (or the caller
/// from succeeding).
///
/// Layout: `path`, `path.1`, `path.2`, ..., `path.{ROTATE_KEEP}`.
/// Rotation shifts `.K-1` → `.K` for `K = ROTATE_KEEP..=1`,
/// dropping any pre-existing `.{ROTATE_KEEP}`. Then `path` →
/// `path.1`, leaving a fresh hole for the next append.
#[allow(clippy::print_stderr)] // intentional loud surface for unbounded-log defect
fn maybe_rotate(path: &std::path::Path) {
    let size = match fs::metadata(path) {
        Ok(m) => m.len(),
        // Doesn't exist yet → nothing to rotate.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        // Stat failed for some other reason (perms, IO). Don't try
        // to rotate; let the open() in write_line surface the
        // underlying problem.
        Err(_) => return,
    };
    if size < ROTATE_MAX_BYTES {
        return;
    }

    // Shift `.K-1` → `.K`, oldest first so we don't clobber.
    // `K = ROTATE_KEEP` is the special drop slot.
    for k in (1..=ROTATE_KEEP).rev() {
        let to = rotation_path(path, k);
        let from = if k == 1 {
            path.to_path_buf()
        } else {
            rotation_path(path, k - 1)
        };
        if !from.exists() {
            continue;
        }
        if k == ROTATE_KEEP {
            // Dropping the oldest rotation. `from` (== `.K-1`) will
            // overwrite `to` (== `.K`); on Windows rename refuses
            // to overwrite, so remove first.
            #[cfg(windows)]
            drop(fs::remove_file(&to));
        }
        if let Err(e) = fs::rename(&from, &to) {
            // Surface louder than usual: a failed rotation means
            // the audit log will grow unbounded. We still don't
            // panic — log + carry on.
            eprintln!(
                "op_log: failed to rotate {} -> {}: {e}",
                from.display(),
                to.display()
            );
            tracing::warn!(
                from = %from.display(),
                to = %to.display(),
                error = %e,
                "op_log: rotation step failed"
            );
            return;
        }
    }
}

fn rotation_path(path: &std::path::Path, k: u32) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".{k}"));
    PathBuf::from(name)
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
            None,
        );
        record_to(
            Some(&log),
            "rename",
            Some("old"),
            Some("new"),
            Duration::from_millis(20),
            true,
            None,
        );
        record_to(
            Some(&log),
            "generate",
            Some("oops"),
            None,
            Duration::from_millis(75),
            false,
            None,
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
            None,
        );
        record_to(
            Some(&log),
            "sign",
            Some("k"),
            None,
            Duration::from_millis(150),
            true,
            None,
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
            None,
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
            None,
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
                None,
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
            None,
        );
        let mode = fs::metadata(&log).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "log file should be owner-only");
        cleanup(&dir);
    }

    #[test]
    fn cfg_test_record_writes_nowhere_by_default() {
        // The `pub fn record(...)` API must be a no-op in cfg(test)
        // builds even when SSHENC_LOG is set, so server-handler
        // unit tests don't accidentally race on a sibling op_log
        // test's tempdir. (Production paths exercise the env path
        // via `#[cfg(not(test))]`, covered by the integration suite
        // that runs the real agent binary.)
        let dir = tempdir();
        let log = dir.join("events.log");
        let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(LOG_PATH_ENV, &log);
        record(
            "sign",
            Some("k"),
            None,
            Duration::from_millis(0),
            true,
            None,
        );
        std::env::remove_var(LOG_PATH_ENV);
        drop(guard);
        assert!(
            !log.exists(),
            "cfg(test) should disable env-driven log writes"
        );
        cleanup(&dir);
    }

    // ---- threshold env clamp ----------------------------------

    #[test]
    fn threshold_env_default_when_unset() {
        let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var(THRESHOLD_ENV);
        let t = fingerprint_threshold();
        drop(guard);
        assert_eq!(t, Duration::from_millis(FINGERPRINT_THRESHOLD_MS_DEFAULT));
    }

    #[test]
    fn threshold_env_in_range_is_honored() {
        let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(THRESHOLD_ENV, "750");
        let t = fingerprint_threshold();
        std::env::remove_var(THRESHOLD_ENV);
        drop(guard);
        assert_eq!(t, Duration::from_millis(750));
    }

    #[test]
    fn threshold_env_below_min_falls_back_to_default() {
        let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(THRESHOLD_ENV, "5"); // below MIN=10
        let t = fingerprint_threshold();
        std::env::remove_var(THRESHOLD_ENV);
        drop(guard);
        assert_eq!(t, Duration::from_millis(FINGERPRINT_THRESHOLD_MS_DEFAULT));
    }

    #[test]
    fn threshold_env_above_max_falls_back_to_default() {
        let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // The exact value the user worried about: a threshold high
        // enough that no real op could ever exceed it, masking
        // every prompt as "no prompt fired" in the audit log.
        std::env::set_var(THRESHOLD_ENV, "999999999"); // > MAX = 5min
        let t = fingerprint_threshold();
        std::env::remove_var(THRESHOLD_ENV);
        drop(guard);
        assert_eq!(t, Duration::from_millis(FINGERPRINT_THRESHOLD_MS_DEFAULT));
    }

    #[test]
    fn threshold_env_at_boundaries_is_honored() {
        let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(THRESHOLD_ENV, FINGERPRINT_THRESHOLD_MS_MIN.to_string());
        assert_eq!(
            fingerprint_threshold(),
            Duration::from_millis(FINGERPRINT_THRESHOLD_MS_MIN)
        );
        std::env::set_var(THRESHOLD_ENV, FINGERPRINT_THRESHOLD_MS_MAX.to_string());
        assert_eq!(
            fingerprint_threshold(),
            Duration::from_millis(FINGERPRINT_THRESHOLD_MS_MAX)
        );
        std::env::remove_var(THRESHOLD_ENV);
        drop(guard);
    }

    #[test]
    fn threshold_env_unparseable_falls_back_to_default() {
        let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(THRESHOLD_ENV, "not-a-number");
        let t = fingerprint_threshold();
        std::env::remove_var(THRESHOLD_ENV);
        drop(guard);
        assert_eq!(t, Duration::from_millis(FINGERPRINT_THRESHOLD_MS_DEFAULT));
    }

    // ---- log path override validation -------------------------

    #[test]
    fn validate_log_path_relative_rejected() {
        let result = validate_log_path_override(std::path::Path::new("relative/path.log"));
        assert!(matches!(result, Err(reason) if reason.contains("absolute")));
    }

    #[test]
    fn validate_log_path_missing_parent_rejected() {
        // Use a clearly nonexistent absolute path. On Windows we
        // need a drive letter; on Unix `/` is fine. Use a tempdir
        // and append a subpath that doesn't exist.
        let dir = tempdir();
        let bogus = dir.join("does-not-exist").join("events.log");
        let result = validate_log_path_override(&bogus);
        assert!(matches!(result, Err(reason) if reason.contains("parent")));
        cleanup(&dir);
    }

    #[test]
    fn validate_log_path_existing_parent_accepted() {
        let dir = tempdir();
        let log = dir.join("events.log");
        let result = validate_log_path_override(&log);
        assert!(result.is_ok(), "expected accept; got {result:?}");
        cleanup(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn validate_log_path_symlink_target_rejected() {
        use std::os::unix::fs::symlink;
        let dir = tempdir();
        let real = dir.join("real.log");
        fs::write(&real, b"existing").unwrap();
        let link = dir.join("events.log");
        symlink(&real, &link).unwrap();
        let result = validate_log_path_override(&link);
        assert!(matches!(result, Err(reason) if reason.contains("symlink")));
        cleanup(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn validate_log_path_symlinked_parent_rejected() {
        use std::os::unix::fs::symlink;
        let dir = tempdir();
        let real_parent = dir.join("real_parent");
        fs::create_dir_all(&real_parent).unwrap();
        let link_parent = dir.join("link_parent");
        symlink(&real_parent, &link_parent).unwrap();
        let log = link_parent.join("events.log");
        let result = validate_log_path_override(&log);
        assert!(matches!(result, Err(reason) if reason.contains("symlink")));
        cleanup(&dir);
    }

    // ---- log rotation -----------------------------------------

    #[test]
    fn rotate_does_nothing_when_under_threshold() {
        let dir = tempdir();
        let log = dir.join("events.log");
        fs::write(&log, b"under-threshold").unwrap();
        maybe_rotate(&log);
        assert!(log.exists(), "log should still exist");
        assert!(
            !rotation_path(&log, 1).exists(),
            "no rotation should have happened"
        );
        cleanup(&dir);
    }

    #[test]
    fn rotate_shifts_when_over_threshold() {
        let dir = tempdir();
        let log = dir.join("events.log");
        // Write enough to exceed ROTATE_MAX_BYTES.
        let big = vec![b'x'; (ROTATE_MAX_BYTES + 1) as usize];
        fs::write(&log, &big).unwrap();
        maybe_rotate(&log);
        // After rotation, .log is gone (renamed to .log.1) and we
        // start fresh on the next write_line.
        assert!(!log.exists(), "active log should have been rotated away");
        assert!(
            rotation_path(&log, 1).exists(),
            "first rotation slot should now exist"
        );
        cleanup(&dir);
    }

    #[test]
    fn rotate_caps_at_rotate_keep() {
        let dir = tempdir();
        let log = dir.join("events.log");

        // Pre-populate every rotation slot from .1 up to .ROTATE_KEEP
        // so we know the rotation has to drop the oldest. Mark each
        // slot with its number so we can verify the shift.
        for k in 1..=ROTATE_KEEP {
            fs::write(rotation_path(&log, k), format!("rot-{k}")).unwrap();
        }
        // Active log is over the threshold, so rotation fires.
        let big = vec![b'y'; (ROTATE_MAX_BYTES + 1) as usize];
        fs::write(&log, &big).unwrap();

        maybe_rotate(&log);

        // .1 should now hold the previously-active log (size > MAX).
        let r1 = fs::read(rotation_path(&log, 1)).unwrap();
        assert_eq!(r1.len(), big.len(), ".log.1 should be the old active");
        // .2 should hold what was in .1 before rotation.
        assert_eq!(
            fs::read_to_string(rotation_path(&log, 2)).unwrap(),
            "rot-1",
            ".log.2 should be the old .log.1"
        );
        // .ROTATE_KEEP should hold what was in .ROTATE_KEEP-1 before;
        // the previous .ROTATE_KEEP must have been dropped.
        let last = rotation_path(&log, ROTATE_KEEP);
        assert_eq!(
            fs::read_to_string(&last).unwrap(),
            format!("rot-{}", ROTATE_KEEP - 1),
            "oldest rotation slot should be old next-to-last; previous oldest must be dropped"
        );
        cleanup(&dir);
    }

    #[test]
    fn write_line_triggers_rotation() {
        // End-to-end: drive record_to with a pre-bloated log file
        // and verify that the next write produces a fresh file
        // containing only the new line, with the old contents
        // moved to .log.1.
        let dir = tempdir();
        let log = dir.join("events.log");
        let big = vec![b'z'; (ROTATE_MAX_BYTES + 1) as usize];
        fs::write(&log, &big).unwrap();

        record_to(
            Some(&log),
            "sign",
            Some("after-rotation"),
            None,
            Duration::from_millis(0),
            true,
            None,
        );

        let after = fs::read_to_string(&log).unwrap();
        assert!(after.lines().count() == 1);
        assert!(after.contains("after-rotation"));
        let r1 = fs::read(rotation_path(&log, 1)).unwrap();
        assert_eq!(r1.len(), big.len());
        cleanup(&dir);
    }
}
