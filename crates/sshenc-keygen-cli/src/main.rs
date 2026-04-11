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
            if cli.label == "default" {
                Some(pub_dir.join("id_ecdsa.pub"))
            } else {
                Some(pub_dir.join(format!("{}.pub", cli.label)))
            }
        };

        // Check for existing files before overwriting (like ssh-keygen)
        if let Some(ref path) = write_pub {
            let private_path = path.with_extension("");
            let has_private = private_path.exists() && private_path != *path;

            if has_private {
                use std::path::PathBuf;
                let priv_bak = private_path.with_extension("bak");
                let pub_bak = PathBuf::from(format!("{}.bak", path.display()));
                eprintln!("Backing up existing key pair:");
                eprintln!("  {} → {}", private_path.display(), priv_bak.display());
                eprintln!("  {} → {}", path.display(), pub_bak.display());
                std::fs::rename(&private_path, &priv_bak)?;
                std::fs::rename(path, &pub_bak)?;
            } else if path.exists() {
                eprintln!("{} already exists.", path.display());
                eprint!("Overwrite (y/n)? ");
                use std::io::Write;
                std::io::stderr().flush().ok();
                let mut input = String::new();
                std::io::stdin().read_line(&mut input).ok();
                if !input.trim().eq_ignore_ascii_case("y") {
                    eprintln!("Cancelled.");
                    std::process::exit(0);
                }
            }
        }

        let comment = cli.comment.or_else(default_comment);

        let key_label = KeyLabel::new(&cli.label)?;
        let opts = KeyGenOptions {
            label: key_label,
            comment,
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
