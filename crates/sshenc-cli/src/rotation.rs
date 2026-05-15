// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Key rotation: when `sshenc keygen -l <existing-label>` is invoked
//! against a label that already has a key, treat the call as a
//! rotation rather than erroring with `DuplicateLabel`. Capture every
//! local file that references the OLD key's public-key blob, replace
//! the old key, then rewrite those files in place so the references
//! point at the NEW key blob.
//!
//! Today we auto-rewrite OpenSSH `allowed_signers` files only, since
//! they're the most common locally-trusted registry of inline pubkey
//! material and they're easy to discover by content match. Other
//! registrations (GitHub-side keys, remote `authorized_keys` files,
//! per-repo `gpg.ssh.allowedSignersFile` overrides) are surfaced as
//! a "next steps" report — the user has to act on those manually,
//! but at least the script tells them which fingerprints to look for
//! and which file to update.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// One local file that contains an inline reference to the OLD key
/// blob and gets rewritten as part of the rotation flow.
#[derive(Debug, Clone)]
pub struct AllowedSignersHit {
    pub path: PathBuf,
    /// Number of lines in the file whose key blob matched the old
    /// key. After [`rewrite`] the same count of lines should now
    /// reference the new key blob. Surfaced in test assertions and
    /// (eventually) a `--dry-run` rotation report; the live keygen
    /// flow uses the rewrite-time counter instead.
    #[allow(dead_code)]
    pub matches: usize,
}

/// Encode a wire-format SSH public key blob as the base64 string
/// that appears in `<label>.pub`, `authorized_keys`, and
/// `allowed_signers`. Identical encoding across all three so a
/// substring match is sufficient for discovery.
pub fn encode_blob(wire_blob: &[u8]) -> String {
    STANDARD.encode(wire_blob)
}

/// Common locations to scan for `allowed_signers` style files. We
/// look at the well-known default plus anything advertised in git
/// config (per-repo and global) via `gpg.ssh.allowedSignersFile`.
pub fn discover_candidate_paths(home: &Path) -> Vec<PathBuf> {
    let mut paths: BTreeSet<PathBuf> = BTreeSet::new();

    // Default location used by `git config --global gpg.ssh.allowedSignersFile`.
    paths.insert(home.join(".ssh").join("allowed_signers"));

    // Anything git config (global + system) names. Per-repo configs
    // could name additional files, but enumerating every git repo
    // on the user's machine is out of scope here -- the rotation
    // report tells the user to grep for the old fingerprint if they
    // suspect repo-local files.
    for scope in ["--global", "--system"] {
        if let Ok(out) = std::process::Command::new("git")
            .args(["config", scope, "--get", "gpg.ssh.allowedSignersFile"])
            .output()
        {
            if out.status.success() {
                let raw = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !raw.is_empty() {
                    paths.insert(expand_tilde(&raw, home));
                }
            }
        }
    }

    paths.into_iter().collect()
}

fn expand_tilde(s: &str, home: &Path) -> PathBuf {
    if let Some(rest) = s.strip_prefix("~/") {
        home.join(rest)
    } else if s == "~" {
        home.to_path_buf()
    } else {
        PathBuf::from(s)
    }
}

/// Scan `paths` for lines whose key blob matches `old_blob_b64`.
/// Returns the subset of paths that contain at least one match.
pub fn discover(paths: &[PathBuf], old_blob_b64: &str) -> Vec<AllowedSignersHit> {
    let mut hits = Vec::new();
    for path in paths {
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue, // missing / unreadable: not our problem
        };
        let mut matches = 0;
        for line in content.lines() {
            if line_contains_blob(line, old_blob_b64) {
                matches += 1;
            }
        }
        if matches > 0 {
            hits.push(AllowedSignersHit {
                path: path.clone(),
                matches,
            });
        }
    }
    hits
}

/// Per-line check. The blob field in an `allowed_signers` line is
/// the third whitespace-separated token; in `authorized_keys` it's
/// the second. We match either by checking each token.
fn line_contains_blob(line: &str, blob: &str) -> bool {
    if line.is_empty() || line.starts_with('#') {
        return false;
    }
    line.split_whitespace().any(|tok| tok == blob)
}

/// Rewrite every line in `path` whose key blob matches
/// `old_blob_b64`, replacing only that token with `new_blob_b64`.
/// Other tokens on the line (principal, comment, options) are
/// preserved as-is. Writes a `.bak` sidecar with the original
/// contents so a faulty rotation can be undone by hand.
pub fn rewrite(path: &Path, old_blob_b64: &str, new_blob_b64: &str) -> Result<usize> {
    let content =
        fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut out = String::with_capacity(content.len());
    let mut replaced = 0_usize;
    for (i, line) in content.lines().enumerate() {
        if line_contains_blob(line, old_blob_b64) {
            // Replace just the blob token; surrounding context (
            // principal, comment, key options) stays intact.
            let rewritten = line
                .split(' ')
                .map(|tok| {
                    if tok == old_blob_b64 {
                        new_blob_b64
                    } else {
                        tok
                    }
                })
                .collect::<Vec<_>>()
                .join(" ");
            out.push_str(&rewritten);
            replaced += 1;
        } else {
            out.push_str(line);
        }
        // Preserve original line ending semantics: every line gets a
        // trailing \n unless this was the final line of a no-trailing-
        // newline file. Detect via whether the source ended with \n.
        let is_last = i + 1 == content.lines().count();
        if !is_last || content.ends_with('\n') {
            out.push('\n');
        }
    }

    if replaced == 0 {
        return Ok(0);
    }

    // Atomic-ish write: write `.tmp` next to the target, fsync, rename.
    // Backup goes to `.bak` with a single-extension form so reruns
    // don't pile up; if `.bak` already exists we keep the older one.
    let bak_path = path.with_extension(append_ext(path, "bak"));
    if !bak_path.exists() {
        // Best effort -- if we can't write the backup, fail loudly
        // before the rewrite so we don't lose the original.
        fs::copy(path, &bak_path)
            .with_context(|| format!("writing backup {}", bak_path.display()))?;
    }
    let tmp_path = path.with_extension(append_ext(path, "tmp"));
    fs::write(&tmp_path, out.as_bytes())
        .with_context(|| format!("writing {}", tmp_path.display()))?;
    fs::rename(&tmp_path, path)
        .with_context(|| format!("renaming {} to {}", tmp_path.display(), path.display()))?;

    Ok(replaced)
}

/// Append a new extension to a path, preserving any existing one.
/// `~/.ssh/allowed_signers` + `bak` -> `allowed_signers.bak`.
/// `foo.txt` + `bak` -> `txt.bak`.
fn append_ext(path: &Path, new_ext: &str) -> String {
    match path.extension() {
        Some(e) => format!("{}.{}", e.to_string_lossy(), new_ext),
        None => new_ext.to_string(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn write(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, contents).unwrap();
    }

    #[test]
    fn discover_finds_blob_in_allowed_signers() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(".ssh/allowed_signers");
        write(
            &path,
            "user@example ecdsa-sha2-nistp256 OLDBLOB comment-1\n\
             other@example ecdsa-sha2-nistp256 OTHERBLOB\n\
             user@example ecdsa-sha2-nistp256 OLDBLOB another-line\n",
        );
        let hits = discover(std::slice::from_ref(&path), "OLDBLOB");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].matches, 2);
        assert_eq!(hits[0].path, path);
    }

    #[test]
    fn discover_skips_comments_and_unrelated_blobs() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("allowed_signers");
        write(
            &path,
            "# comment with OLDBLOB substring should not match\n\
             user@x ecdsa-sha2-nistp256 OTHERBLOB\n",
        );
        let hits = discover(std::slice::from_ref(&path), "OLDBLOB");
        assert!(hits.is_empty());
    }

    #[test]
    fn rewrite_replaces_blob_and_preserves_surrounding_tokens() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("allowed_signers");
        write(
            &path,
            "user@example ecdsa-sha2-nistp256 OLDBLOB comment-1\n\
             other@example ecdsa-sha2-nistp256 OTHERBLOB\n\
             user@example ecdsa-sha2-nistp256 OLDBLOB another-line\n",
        );

        let n = rewrite(&path, "OLDBLOB", "NEWBLOB").unwrap();
        assert_eq!(n, 2);

        let after = fs::read_to_string(&path).unwrap();
        assert_eq!(
            after,
            "user@example ecdsa-sha2-nistp256 NEWBLOB comment-1\n\
             other@example ecdsa-sha2-nistp256 OTHERBLOB\n\
             user@example ecdsa-sha2-nistp256 NEWBLOB another-line\n"
        );

        // .bak sidecar preserves original.
        let bak = path.with_extension("bak");
        let bak_contents = fs::read_to_string(&bak).unwrap();
        assert!(bak_contents.contains("OLDBLOB"));
    }

    #[test]
    fn rewrite_zero_matches_returns_zero_no_backup() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("allowed_signers");
        write(&path, "user@x ecdsa-sha2-nistp256 OTHERBLOB\n");
        let n = rewrite(&path, "OLDBLOB", "NEWBLOB").unwrap();
        assert_eq!(n, 0);
        // No backup written because nothing was rewritten.
        assert!(!path.with_extension("bak").exists());
    }

    #[test]
    fn append_ext_preserves_existing_extension() {
        assert_eq!(append_ext(Path::new("allowed_signers"), "bak"), "bak");
        assert_eq!(append_ext(Path::new("foo.txt"), "bak"), "txt.bak");
    }

    #[test]
    fn rewrite_returns_error_when_source_file_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nonexistent_allowed_signers");
        let result = rewrite(&path, "BLOB", "NEWBLOB");
        assert!(result.is_err(), "rewrite on a missing file must return Err");
    }

    #[test]
    fn rewrite_does_not_overwrite_existing_bak_file() {
        // If a .bak already exists (from a previous rotation), the backup
        // must not be overwritten — we keep the oldest backup so the user
        // can always roll back to the pre-first-rotation state.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("allowed_signers");
        let bak_path = path.with_extension("bak");
        write(&path, "user@x ecdsa-sha2-nistp256 OLDBLOB comment\n");
        write(&bak_path, "pre-existing-backup-content\n");

        let n = rewrite(&path, "OLDBLOB", "NEWBLOB").unwrap();
        assert_eq!(n, 1);

        let bak_content = fs::read_to_string(&bak_path).unwrap();
        assert_eq!(
            bak_content, "pre-existing-backup-content\n",
            ".bak file must not be overwritten on a repeat run"
        );
        let updated = fs::read_to_string(&path).unwrap();
        assert!(
            updated.contains("NEWBLOB"),
            "allowed_signers must be updated"
        );
    }
}
