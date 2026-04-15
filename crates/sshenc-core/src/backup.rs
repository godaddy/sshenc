// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Shared backup helpers for overwrite-sensitive file operations.

use crate::error::Result;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileBackup {
    original: PathBuf,
    backup: PathBuf,
}

impl FileBackup {
    pub fn original(&self) -> &Path {
        &self.original
    }

    pub fn backup(&self) -> &Path {
        &self.backup
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BackupPlan {
    entries: Vec<FileBackup>,
}

impl BackupPlan {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[FileBackup] {
        &self.entries
    }

    pub fn cleanup(&self) {
        for entry in &self.entries {
            drop(std::fs::remove_file(&entry.backup));
        }
    }

    pub fn restore(&self) -> Result<()> {
        rollback_backups(&self.entries)
    }
}

#[derive(Debug)]
pub enum BackupExecutionError<E> {
    Backup(crate::error::Error),
    Operation(E),
    Rollback {
        operation: E,
        rollback: crate::error::Error,
        /// Backup files that may still exist on disk after rollback failure.
        remaining_backups: Vec<PathBuf>,
    },
}

/// Run a key-material operation with automatic backup and rollback.
///
/// Convenience wrapper around [`with_existing_key_material_backup`] that
/// converts [`BackupExecutionError`] variants into the caller's error type
/// so binary crates don't need to match each variant individually.
pub fn run_with_backup<T, E, F>(
    public_path: Option<&std::path::Path>,
    paired_private_path: Option<&std::path::Path>,
    operation: F,
) -> std::result::Result<T, E>
where
    E: From<crate::error::Error> + std::fmt::Display,
    F: FnOnce() -> std::result::Result<T, E>,
{
    let Some(public_path) = public_path else {
        return operation();
    };

    match with_existing_key_material_backup(public_path, paired_private_path, operation) {
        Ok(value) => Ok(value),
        Err(BackupExecutionError::Backup(error)) => Err(error.into()),
        Err(BackupExecutionError::Operation(error)) => Err(error),
        Err(BackupExecutionError::Rollback {
            operation,
            rollback,
            remaining_backups,
        }) => {
            let mut msg =
                format!("{operation}; failed to restore backed up SSH key material: {rollback}");
            if !remaining_backups.is_empty() {
                msg.push_str("; backup files remaining on disk:");
                for path in &remaining_backups {
                    msg.push_str(&format!(" {}", path.display()));
                }
            }
            Err(crate::error::Error::Other(msg).into())
        }
    }
}

pub fn with_existing_key_material_backup<T, E, F>(
    public_path: &Path,
    paired_private_path: Option<&Path>,
    operation: F,
) -> std::result::Result<T, BackupExecutionError<E>>
where
    F: FnOnce() -> std::result::Result<T, E>,
{
    let plan = backup_existing_key_material(public_path, paired_private_path)
        .map_err(BackupExecutionError::Backup)?;
    match operation() {
        Ok(value) => {
            plan.cleanup();
            Ok(value)
        }
        Err(operation) => match plan.restore() {
            Ok(()) => Err(BackupExecutionError::Operation(operation)),
            Err(rollback) => {
                let remaining_backups = plan
                    .entries()
                    .iter()
                    .filter(|e| e.backup().exists())
                    .map(|e| e.backup().to_path_buf())
                    .collect();
                Err(BackupExecutionError::Rollback {
                    operation,
                    rollback,
                    remaining_backups,
                })
            }
        },
    }
}

pub fn backup_existing_key_material(
    public_path: &Path,
    paired_private_path: Option<&Path>,
) -> Result<BackupPlan> {
    let mut paths = Vec::new();

    if let Some(private_path) = paired_private_path.filter(|path| *path != public_path) {
        if private_path.exists() {
            paths.push(private_path.to_path_buf());
        }
    }
    if public_path.exists() {
        paths.push(public_path.to_path_buf());
    }

    backup_existing_files(&paths)
}

fn backup_existing_files(paths: &[PathBuf]) -> Result<BackupPlan> {
    let mut entries = Vec::new();

    for path in paths {
        let backup = unique_backup_path(path);
        if let Err(err) = std::fs::rename(path, &backup) {
            if let Err(rollback_err) = rollback_backups(&entries) {
                return Err(crate::error::Error::Other(format!(
                    "backup failed: {err}; rollback also failed: {rollback_err}"
                )));
            }
            return Err(err.into());
        }
        entries.push(FileBackup {
            original: path.clone(),
            backup,
        });
    }

    Ok(BackupPlan { entries })
}

fn rollback_backups(entries: &[FileBackup]) -> Result<()> {
    let mut errors = Vec::new();
    for entry in entries.iter().rev() {
        if !entry.backup.exists() {
            continue;
        }
        if entry.original.exists() {
            if let Err(e) = std::fs::remove_file(&entry.original) {
                errors.push(format!("{}: {e}", entry.original.display()));
                continue;
            }
        }
        if let Err(e) = std::fs::rename(&entry.backup, &entry.original) {
            errors.push(format!("{}: {e}", entry.original.display()));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(crate::error::Error::Other(format!(
            "rollback failures: {}",
            errors.join("; ")
        )))
    }
}

fn unique_backup_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("backup");
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    for attempt in 0_u32..100 {
        let candidate = if attempt == 0 {
            path.with_file_name(format!("{file_name}.{pid}.{nanos}.bak"))
        } else {
            path.with_file_name(format!("{file_name}.{pid}.{nanos}.{attempt}.bak"))
        };
        if !candidate.exists() {
            return candidate;
        }
    }
    path.with_file_name(format!("{file_name}.{pid}.{nanos}.bak"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_dir(name: &str) -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "sshenc-core-backup-test-{}-{}-{name}",
            std::process::id(),
            id
        ));
        drop(std::fs::remove_dir_all(&dir));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn backup_existing_key_material_moves_private_and_public() {
        let dir = test_dir("pair");
        let public_path = dir.join("id_ecdsa.pub");
        let private_path = dir.join("id_ecdsa");
        std::fs::write(&private_path, "private").unwrap();
        std::fs::write(&public_path, "public").unwrap();

        let plan = backup_existing_key_material(&public_path, Some(&private_path)).unwrap();
        assert_eq!(plan.entries.len(), 2);
        assert!(!private_path.exists());
        assert!(!public_path.exists());
        assert!(plan.entries.iter().any(|entry| {
            entry.original() == private_path
                && std::fs::read_to_string(entry.backup()).unwrap() == "private"
        }));
        assert!(plan.entries.iter().any(|entry| {
            entry.original() == public_path
                && std::fs::read_to_string(entry.backup()).unwrap() == "public"
        }));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn backup_existing_key_material_moves_private_without_public() {
        let dir = test_dir("private-only");
        let public_path = dir.join("id_ecdsa.pub");
        let private_path = dir.join("id_ecdsa");
        std::fs::write(&private_path, "private").unwrap();

        let plan = backup_existing_key_material(&public_path, Some(&private_path)).unwrap();
        assert_eq!(plan.entries.len(), 1);
        assert!(!private_path.exists());
        assert!(!public_path.exists());
        assert_eq!(plan.entries[0].original(), private_path);
        assert_eq!(
            std::fs::read_to_string(plan.entries[0].backup()).unwrap(),
            "private"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn backup_existing_files_rolls_back_on_failure() {
        let dir = test_dir("rollback");
        let existing = dir.join("id_ecdsa");
        let missing = dir.join("id_ecdsa.pub");
        std::fs::write(&existing, "private").unwrap();

        let err = backup_existing_files(&[existing.clone(), missing]).unwrap_err();
        assert!(
            existing.exists(),
            "existing file should be restored after rollback"
        );
        assert_eq!(std::fs::read_to_string(&existing).unwrap(), "private");
        assert!(
            err.to_string().contains("No such file") || err.to_string().contains("cannot find")
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn with_existing_key_material_backup_restores_files_after_operation_failure() {
        let dir = test_dir("operation-failure");
        let public_path = dir.join("id_ecdsa.pub");
        let private_path = dir.join("id_ecdsa");
        std::fs::write(&private_path, "private").unwrap();
        std::fs::write(&public_path, "public").unwrap();

        let error = with_existing_key_material_backup::<(), _, _>(
            &public_path,
            Some(&private_path),
            || Err::<(), _>("generation failed"),
        )
        .unwrap_err();

        match error {
            BackupExecutionError::Operation(message) => {
                assert_eq!(message, "generation failed");
            }
            other => panic!("expected operation failure, got {other:?}"),
        }

        assert_eq!(std::fs::read_to_string(&private_path).unwrap(), "private");
        assert_eq!(std::fs::read_to_string(&public_path).unwrap(), "public");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn with_existing_key_material_backup_reports_rollback_failure() {
        let dir = test_dir("rollback-failure");
        let public_path = dir.join("id_ecdsa.pub");
        let private_path = dir.join("id_ecdsa");
        std::fs::write(&private_path, "private").unwrap();
        std::fs::write(&public_path, "public").unwrap();

        let error = with_existing_key_material_backup::<(), _, _>(
            &public_path,
            Some(&private_path),
            || {
                std::fs::create_dir(&private_path).unwrap();
                Err::<(), _>("generation failed")
            },
        )
        .unwrap_err();

        match error {
            BackupExecutionError::Rollback {
                operation,
                rollback,
                ..
            } => {
                assert_eq!(operation, "generation failed");
                assert!(!rollback.to_string().is_empty());
            }
            other => panic!("expected rollback failure, got {other:?}"),
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn backup_existing_key_material_only_moves_explicit_paths() {
        let dir = test_dir("explicit-paths");
        let public_path = dir.join("custom-output.pub");
        let sibling_path = dir.join("custom-output");
        std::fs::write(&public_path, "public").unwrap();
        std::fs::write(&sibling_path, "not-a-private-key").unwrap();

        let plan = backup_existing_key_material(&public_path, None).unwrap();
        assert_eq!(plan.entries.len(), 1);
        assert!(
            sibling_path.exists(),
            "unrelated sibling file should not be moved"
        );
        assert_eq!(
            std::fs::read_to_string(&sibling_path).unwrap(),
            "not-a-private-key"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn with_existing_key_material_backup_cleans_up_backups_on_success() {
        let dir = test_dir("cleanup-on-success");
        let public_path = dir.join("id_ecdsa.pub");
        let private_path = dir.join("id_ecdsa");
        std::fs::write(&private_path, "private").unwrap();
        std::fs::write(&public_path, "public").unwrap();

        let result = with_existing_key_material_backup::<&str, &str, _>(
            &public_path,
            Some(&private_path),
            || Ok("success"),
        )
        .unwrap();

        assert_eq!(result, "success");
        // Backup files should have been cleaned up
        let bak_files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "bak"))
            .collect();
        assert!(
            bak_files.is_empty(),
            "backup files should be cleaned up on success, found: {:?}",
            bak_files.iter().map(|e| e.path()).collect::<Vec<_>>()
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
