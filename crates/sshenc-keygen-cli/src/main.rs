// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! sshenc-keygen: Convenience CLI for generating Secure Enclave SSH keys.

use anyhow::Result;
use clap::Parser;
use enclaveapp_core::types::PresenceMode;
use sshenc_core::backup;
use sshenc_core::key::{KeyGenOptions, KeyLabel};
use sshenc_core::pubkey::SshPublicKey;
use sshenc_core::{AccessPolicy, Config};
use sshenc_se::{AgentProxyBackend, KeyBackend};
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

    /// Require a user-presence prompt for *every* signature, instead
    /// of the default cached cadence (one prompt per cache-TTL window).
    /// Mutually exclusive with `--no-user-presence`.
    #[arg(long)]
    strict: bool,

    /// Generate a key with no user-presence requirement at all. Signs
    /// silently. Mutually exclusive with `--strict`.
    #[arg(long, conflicts_with = "strict")]
    no_user_presence: bool,

    /// Deprecated alias for `--strict`. Kept for backwards compatibility
    /// with scripts written against the pre-default-presence build.
    #[arg(long, hide = true)]
    require_user_presence: bool,

    /// Suppress public key output to stdout.
    #[arg(long, short = 'q')]
    quiet: bool,
}

#[allow(clippy::print_stdout, clippy::print_stderr)]
fn main() -> Result<()> {
    enclaveapp_core::process::harden_process();

    let cli = Cli::parse();

    let config = Config::load_default()?;
    let pub_dir = config.pub_dir.clone();

    // Keygen goes through `sshenc-agent` on every platform — Unix
    // socket on macOS/Linux/WSL, named pipe on Windows (native,
    // Git Bash, PowerShell, cmd.exe). The CLI binary never calls
    // into Secure Enclave / keychain / CNG directly.
    let backend: Box<dyn KeyBackend> = Box::new(
        AgentProxyBackend::new(pub_dir.clone(), config.socket_path.clone())
            .map_err(|e| anyhow::anyhow!("failed to initialize agent-proxy backend: {e}"))?,
    );

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

    if cli.require_user_presence {
        eprintln!(
            "warning: --require-user-presence is deprecated; use --strict instead. \
             Treating it as --strict for this run."
        );
    }
    let strict = cli.strict || cli.require_user_presence;

    // Default policy: `Cached` user presence with `AccessPolicy::Any`.
    // Explicit opt-outs flip the policy in either direction.
    let (access_policy, presence_mode) = if cli.no_user_presence {
        (AccessPolicy::None, PresenceMode::None)
    } else if strict {
        (AccessPolicy::Any, PresenceMode::Strict)
    } else {
        (AccessPolicy::Any, PresenceMode::Cached)
    };

    let key_label = KeyLabel::new(&cli.label)?;
    let opts = KeyGenOptions {
        label: key_label,
        comment,
        access_policy,
        presence_mode,
        write_pub_path: write_pub.clone(),
    };

    // `backend` above is an `AgentProxyBackend` on Unix: the
    // `generate` call routes through `sshenc-agent` so the CLI
    // binary's code signature is never on the `SecItemAdd` for the
    // wrapping-key entry. On Windows it's a direct `SshencBackend`.
    let info =
        backup::run_with_backup(write_pub.as_deref(), paired_private_path.as_deref(), || {
            backend.generate(&opts).map_err(|e| anyhow::anyhow!("{e}"))
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
