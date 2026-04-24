// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! sshenc-keygen: Convenience CLI for generating Secure Enclave SSH keys.

use anyhow::Result;
use clap::Parser;
use sshenc_core::backup;
use sshenc_core::key::{KeyGenOptions, KeyLabel};
use sshenc_core::pubkey::SshPublicKey;
use sshenc_core::{AccessPolicy, Config};
use sshenc_se::KeyBackend;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "sshenc-keygen",
    about = "Generate hardware-backed SSH keys",
    long_about = "sshenc-keygen generates a new SSH key backed by hardware security:\n\
                   macOS Secure Enclave or Windows TPM 2.0.\n\
                   The private key is non-exportable and device-bound. The generated key uses\n\
                   ECDSA with the NIST P-256 curve (ecdsa-sha2-nistp256).\n\n\
                   The public key is written to ~/.ssh/<label>.pub by default.",
    version
)]
struct Cli {
    /// Label for the key [default: "default"].
    #[arg(long, short = 'l', default_value = "default")]
    label: String,

    /// Comment for the SSH public key line [default: user@hostname].
    #[arg(long, short = 'C')]
    comment: Option<String>,

    /// Write the public key to this path instead of ~/.ssh/<label>.pub.
    #[arg(long)]
    write_pub: Option<PathBuf>,

    /// Don't write the .pub file.
    #[arg(long)]
    no_pub_file: bool,

    /// Require user presence (Touch ID / password) for each signing operation.
    #[arg(long)]
    require_user_presence: bool,

    /// Suppress public key output to stdout.
    #[arg(long, short = 'q')]
    quiet: bool,
}

#[allow(clippy::print_stdout, clippy::print_stderr)]
fn main() -> Result<()> {
    enclaveapp_core::process::harden_process();

    let cli = Cli::parse();

    let pub_dir = Config::load_default()?.pub_dir;

    let backend = sshenc_se::SshencBackend::new(pub_dir.clone(), false)
        .map_err(|e| anyhow::anyhow!("failed to initialize backend: {e}"))?;

    let write_pub = if cli.no_pub_file {
        None
    } else if let Some(path) = cli.write_pub.as_ref() {
        Some(path.clone())
    } else if cli.label == "default" {
        Some(pub_dir.join("id_ecdsa.pub"))
    } else {
        Some(pub_dir.join(format!("{}.pub", cli.label)))
    };
    let paired_private_path =
        if cli.write_pub.is_none() && !cli.no_pub_file && cli.label == "default" {
            write_pub.as_ref().map(|path| path.with_extension(""))
        } else {
            None
        };

    // Check for existing files before overwriting (like ssh-keygen)
    if let Some(ref path) = write_pub {
        let has_private = paired_private_path
            .as_ref()
            .is_some_and(|private_path| private_path.exists() && private_path != path);

        if has_private {
            eprintln!("Existing SSH key pair will be backed up before generation.");
        } else if path.exists() {
            eprintln!("{} already exists.", path.display());
            eprint!("Overwrite (y/n)? ");
            use std::io::Write;
            std::io::stderr().flush().ok();
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).ok();
            if !input.trim().eq_ignore_ascii_case("y") {
                eprintln!("Cancelled.");
                return Ok(());
            }
        }
    }

    let comment = cli.comment.or_else(default_comment);

    let access_policy = if cli.require_user_presence {
        AccessPolicy::Any
    } else {
        AccessPolicy::None
    };

    let key_label = KeyLabel::new(&cli.label)?;

    // Prefer generating through a running `sshenc-agent`. When the
    // agent creates the wrapping-key entry in the login keychain, it
    // is also the binary that will later read that entry for
    // signing or deletion — creator and reader are the same
    // code-signature, so the legacy ACL does not pop a cross-binary
    // approval prompt. Fall back to the local backend when no agent
    // is available, mirroring the behavior of `sshenc -Y sign` and
    // `sshenc delete`.
    let info =
        backup::run_with_backup(write_pub.as_deref(), paired_private_path.as_deref(), || {
            if let Some(public_bytes) = sshenc_agent_proto::client::try_generate_via_agent(
                &cli.label,
                comment.as_deref(),
                access_policy.as_ffi_value() as u32,
            ) {
                tracing::debug!(label = %cli.label, "keygen: generated via agent proxy");
                build_keyinfo_agent_side(
                    key_label.clone(),
                    comment.clone(),
                    access_policy,
                    write_pub.clone(),
                    public_bytes,
                )
            } else {
                let opts = KeyGenOptions {
                    label: key_label.clone(),
                    comment: comment.clone(),
                    access_policy,
                    write_pub_path: write_pub.clone(),
                };
                backend.generate(&opts).map_err(|e| anyhow::anyhow!("{e}"))
            }
        })?;

    if !cli.quiet {
        eprintln!("Generated key: {}", cli.label);
        eprintln!("  Fingerprint: {}", info.fingerprint_sha256);
        if let Some(ref path) = info.pub_file_path {
            eprintln!("  Public key written to: {}", path.display());
        }

        let pubkey =
            SshPublicKey::from_sec1_bytes(&info.public_key_bytes, info.metadata.comment.clone())?;
        println!("{}", pubkey.to_openssh_line());
    }

    Ok(())
}

/// Reconstruct a `KeyInfo` client-side after the agent has generated
/// the key. Matches what `SshencBackend::generate` would have built
/// locally: compute fingerprints from the public-key bytes, write
/// the OpenSSH `.pub` file at `write_pub` if requested.
fn build_keyinfo_agent_side(
    label: KeyLabel,
    comment: Option<String>,
    access_policy: AccessPolicy,
    write_pub: Option<PathBuf>,
    public_key_bytes: Vec<u8>,
) -> Result<sshenc_core::key::KeyInfo> {
    use sshenc_core::fingerprint;
    use sshenc_core::key::{KeyInfo, KeyMetadata};

    let ssh_pubkey = SshPublicKey::from_sec1_bytes(&public_key_bytes, comment.clone())?;
    let (fp_sha256, fp_md5) = fingerprint::fingerprints(&ssh_pubkey);

    let pub_file_path = if let Some(ref path) = write_pub {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, format!("{}\n", ssh_pubkey.to_openssh_line()))?;
        Some(path.clone())
    } else {
        None
    };

    Ok(KeyInfo {
        metadata: KeyMetadata::new(label, access_policy, comment),
        public_key_bytes,
        fingerprint_sha256: fp_sha256,
        fingerprint_md5: fp_md5,
        pub_file_path,
    })
}

fn default_comment() -> Option<String> {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "user".into());
    let host = std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|h| h.trim().to_string())
        .unwrap_or_else(|| "localhost".into());
    Some(format!("{user}@{host}"))
}
