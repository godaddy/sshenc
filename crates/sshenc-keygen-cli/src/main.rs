// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! sshenc-keygen: Convenience CLI for generating Secure Enclave SSH keys.

use anyhow::Result;
use clap::Parser;
use sshenc_core::key::{KeyGenOptions, KeyLabel};
use sshenc_core::pubkey::SshPublicKey;
use sshenc_se::KeyBackend;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "sshenc-keygen",
    about = "Generate macOS Secure Enclave-backed SSH keys",
    long_about = "sshenc-keygen generates a new SSH key backed by the macOS Secure Enclave.\n\
                   The private key is non-exportable and device-bound. The generated key uses\n\
                   ECDSA with the NIST P-256 curve (ecdsa-sha2-nistp256).\n\n\
                   The public key is written to ~/.ssh/<label>.pub by default.",
    version
)]
struct Cli {
    /// Label for the key (alphanumeric, hyphens, underscores; max 64 chars).
    #[arg(long, short = 'l')]
    label: String,

    /// Comment for the SSH public key line (e.g., user@host).
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

fn main() -> Result<()> {
    #[cfg(not(target_os = "macos"))]
    bail!("sshenc-keygen requires macOS with Secure Enclave");

    #[cfg(target_os = "macos")]
    {
        let cli = Cli::parse();

        let pub_dir = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join(".ssh");
        let backend = sshenc_se::SecureEnclaveBackend::new(pub_dir.clone());

        let write_pub = if cli.no_pub_file {
            None
        } else if let Some(path) = cli.write_pub {
            Some(path)
        } else {
            Some(pub_dir.join(format!("{}.pub", cli.label)))
        };

        let key_label = KeyLabel::new(&cli.label)?;
        let opts = KeyGenOptions {
            label: key_label,
            comment: cli.comment,
            requires_user_presence: cli.require_user_presence,
            write_pub_path: write_pub,
        };

        let info = backend.generate(&opts)?;

        if !cli.quiet {
            eprintln!("Generated Secure Enclave key: {}", cli.label);
            eprintln!("  Fingerprint: {}", info.fingerprint_sha256);
            if let Some(ref path) = info.pub_file_path {
                eprintln!("  Public key written to: {}", path.display());
            }

            let pubkey = SshPublicKey::from_sec1_bytes(
                &info.public_key_bytes,
                info.metadata.comment.clone(),
            )?;
            println!("{}", pubkey.to_openssh_line());
        }

        Ok(())
    }
}
