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
    let cli = Cli::parse();

    let pub_dir = Config::load_default()?.pub_dir;

    let backend = sshenc_se::SshencBackend::new(pub_dir.clone())
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

    let key_label = KeyLabel::new(&cli.label)?;
    let opts = KeyGenOptions {
        label: key_label,
        comment,
        access_policy: if cli.require_user_presence {
            AccessPolicy::Any
        } else {
            AccessPolicy::None
        },
        write_pub_path: write_pub.clone(),
    };

    let info =
        backup::run_with_backup(write_pub.as_deref(), paired_private_path.as_deref(), || {
            Ok(backend.generate(&opts)?)
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
