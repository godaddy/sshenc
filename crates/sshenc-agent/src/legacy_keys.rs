// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Legacy SSH key loading and signing.
//!
//! Discovers and loads unencrypted SSH private keys from `~/.ssh/` so the
//! sshenc agent can serve them alongside Secure Enclave keys. This allows
//! users to switch to the sshenc agent without losing access to existing keys.

use ssh_key::private::PrivateKey;
use sshenc_agent_proto::message::Identity;
use sshenc_core::pubkey::write_ssh_string;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Well-known SSH private key filenames to look for.
const WELL_KNOWN_KEY_FILES: &[&str] = &[
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    "id_ecdsa_sk",
    "id_ed25519_sk",
];

/// A legacy SSH key loaded from the filesystem.
pub struct LegacyKey {
    /// SSH public key wire blob (for identity enumeration and matching).
    pub key_blob: Vec<u8>,
    /// Comment (filename or from .pub file).
    pub comment: String,
    /// The parsed private key for signing.
    private_key: PrivateKey,
}

impl LegacyKey {
    /// Sign data, returning the SSH signature wire blob.
    ///
    /// The signature blob format is: `string(algorithm) || string(raw_signature)`.
    /// For RSA keys, the `flags` parameter selects the hash algorithm.
    pub fn sign(&self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        use signature::Signer;

        let signature = self.private_key.try_sign(data)?;

        // Build the SSH wire format signature blob:
        // string(algorithm_name) || string(signature_data)
        let algorithm = signature.algorithm();
        let algo_name = algorithm.as_str();
        let sig_bytes = signature.as_bytes();

        let mut blob = Vec::new();
        write_ssh_string(&mut blob, algo_name.as_bytes());
        write_ssh_string(&mut blob, sig_bytes);

        Ok(blob)
    }

    /// Return an Identity for the agent protocol.
    pub fn to_identity(&self) -> Identity {
        Identity {
            key_blob: self.key_blob.clone(),
            comment: self.comment.clone(),
        }
    }
}

/// Discover and load legacy SSH keys from the given directory.
///
/// Looks for well-known key filenames and any file that has a `.pub` sibling.
/// Encrypted keys are skipped with an info log. Parse failures are skipped
/// with a warning.
pub fn load_legacy_keys(ssh_dir: &Path) -> Vec<LegacyKey> {
    if !ssh_dir.is_dir() {
        return Vec::new();
    }

    let mut candidates: HashSet<PathBuf> = HashSet::new();

    // Add well-known key files
    for name in WELL_KNOWN_KEY_FILES {
        let path = ssh_dir.join(name);
        if path.is_file() {
            candidates.insert(path);
        }
    }

    // Add any file that has a .pub sibling
    if let Ok(entries) = std::fs::read_dir(ssh_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(ext) = path.extension() {
                if ext == "pub" {
                    let private_path = path.with_extension("");
                    if private_path.is_file() {
                        candidates.insert(private_path);
                    }
                }
            }
        }
    }

    let mut keys = Vec::new();

    for path in &candidates {
        match load_key(path) {
            Ok(key) => {
                tracing::info!(
                    path = %path.display(),
                    comment = %key.comment,
                    "loaded legacy SSH key"
                );
                keys.push(key);
            }
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "failed to load key"
                );
            }
        }
    }

    // Sort by filename for deterministic ordering
    keys.sort_by(|a, b| a.comment.cmp(&b.comment));
    keys
}

/// Load a single SSH private key from a file.
/// If the key is encrypted, prompts for a passphrase via a macOS GUI dialog.
fn load_key(path: &Path) -> anyhow::Result<LegacyKey> {
    let content = std::fs::read_to_string(path)?;
    let raw_key = ssh_key::private::PrivateKey::from_openssh(&content)?;

    let private_key = if raw_key.is_encrypted() {
        let passphrase = prompt_passphrase(path)?;
        raw_key.decrypt(passphrase.as_bytes())?
    } else {
        raw_key
    };

    let public_key = private_key.public_key();
    let key_blob = public_key.to_bytes()?;

    let comment = read_pub_comment(path).unwrap_or_else(|| {
        path.file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string()
    });

    Ok(LegacyKey {
        key_blob,
        comment,
        private_key,
    })
}

/// Prompt for a passphrase on the terminal with echo disabled.
fn prompt_passphrase(key_path: &Path) -> anyhow::Result<String> {
    let filename = key_path.file_name().unwrap_or_default().to_string_lossy();

    // Use stty to disable echo, read password, re-enable echo.
    // This works even when stdout is redirected since we open /dev/tty directly.
    eprint!("Enter passphrase for {filename}: ");
    let output = std::process::Command::new("bash")
        .arg("-c")
        .arg("stty -echo 2>/dev/null; read -r pw < /dev/tty; stty echo 2>/dev/null; echo \"$pw\"")
        .output()?;
    eprintln!(); // newline after hidden input

    if !output.status.success() {
        anyhow::bail!("passphrase prompt failed");
    }

    let passphrase = String::from_utf8(output.stdout)?
        .trim_end_matches('\n')
        .to_string();
    Ok(passphrase)
}

/// Try to read the comment from a .pub file (third field in the OpenSSH line).
fn read_pub_comment(private_key_path: &Path) -> Option<String> {
    let pub_path = private_key_path.with_extension("pub");
    let content = std::fs::read_to_string(&pub_path).ok()?;
    let first_line = content.lines().next()?;
    let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
    parts.get(2).map(|s| s.to_string())
}
