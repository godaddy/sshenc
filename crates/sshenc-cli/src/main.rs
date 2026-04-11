// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! sshenc: Main CLI for Secure Enclave SSH key management.

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod commands;

#[derive(Parser)]
#[command(
    name = "sshenc",
    about = "Manage macOS Secure Enclave-backed SSH keys",
    long_about = "sshenc creates, manages, and uses macOS Secure Enclave-backed SSH keys for\n\
                   OpenSSH and git+ssh workflows. Keys are non-exportable, device-bound ECDSA P-256\n\
                   keys stored in the Secure Enclave.",
    version,
    propagate_version = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new Secure Enclave-backed SSH key.
    Keygen {
        /// Label for the key (alphanumeric, hyphens, underscores).
        #[arg(long, short = 'l')]
        label: String,

        /// Comment for the SSH public key line.
        #[arg(long, short = 'C')]
        comment: Option<String>,

        /// Write the public key to this file path.
        #[arg(long)]
        write_pub: Option<PathBuf>,

        /// Print the public key to stdout.
        #[arg(long, default_value_t = true)]
        print_pub: bool,

        /// Require user presence (Touch ID / password) for signing.
        #[arg(long)]
        require_user_presence: bool,

        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },

    /// List all sshenc-managed Secure Enclave keys.
    List {
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },

    /// Show detailed information for a key.
    Inspect {
        /// Key label to inspect.
        label: String,

        /// Output in JSON format.
        #[arg(long)]
        json: bool,

        /// Also show the OpenSSH public key line.
        #[arg(long)]
        show_pub: bool,
    },

    /// Delete a Secure Enclave key.
    Delete {
        /// Key label(s) to delete.
        labels: Vec<String>,

        /// Also delete the associated .pub file(s).
        #[arg(long)]
        delete_pub: bool,

        /// Skip confirmation prompt.
        #[arg(long, short = 'y')]
        yes: bool,
    },

    /// Export the public key in OpenSSH format.
    ExportPub {
        /// Key label to export.
        label: String,

        /// Write to file instead of stdout.
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,

        /// Output as authorized_keys line.
        #[arg(long)]
        authorized_keys: bool,

        /// Show fingerprint only.
        #[arg(long)]
        fingerprint: bool,

        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },

    /// Start the SSH agent daemon.
    Agent {
        /// Path for the agent Unix socket.
        #[arg(long, short = 's')]
        socket: Option<PathBuf>,

        /// Run in foreground.
        #[arg(long, short = 'f', default_value_t = true)]
        foreground: bool,

        /// Enable debug logging.
        #[arg(long, short = 'd')]
        debug: bool,

        /// Only expose keys matching these labels.
        #[arg(long, value_delimiter = ',')]
        labels: Vec<String>,
    },

    /// Configuration management.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Generate OpenSSH config snippets.
    Openssh {
        #[command(subcommand)]
        action: OpensshAction,
    },

    /// Configure SSH to use sshenc for all hosts (adds PKCS11Provider to ~/.ssh/config).
    Install,

    /// Remove sshenc configuration from ~/.ssh/config.
    Uninstall,
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Initialize a default config file.
    Init,
    /// Show the current config file path.
    Path,
    /// Show the current config.
    Show,
}

#[derive(Subcommand)]
enum OpensshAction {
    /// Print an SSH config snippet for a key.
    PrintConfig {
        /// Key label.
        #[arg(long, short = 'l')]
        label: String,

        /// Target hostname.
        #[arg(long)]
        host: String,

        /// Use PKCS#11 mode instead of agent mode.
        #[arg(long)]
        pkcs11: bool,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();

    #[cfg(not(target_os = "macos"))]
    bail!("sshenc requires macOS with Secure Enclave");

    #[cfg(target_os = "macos")]
    {
        let pub_dir = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join(".ssh");
        let backend = sshenc_se::SecureEnclaveBackend::new(pub_dir);
        run_command(cli.command, &backend)
    }
}

#[cfg(target_os = "macos")]
fn run_command(command: Commands, backend: &sshenc_se::SecureEnclaveBackend) -> Result<()> {
    match command {
        Commands::Keygen {
            label,
            comment,
            write_pub,
            print_pub,
            require_user_presence,
            json,
        } => commands::keygen(
            backend,
            &label,
            comment,
            write_pub,
            print_pub,
            require_user_presence,
            json,
        ),
        Commands::List { json } => commands::list(backend, json),
        Commands::Inspect {
            label,
            json,
            show_pub,
        } => commands::inspect(backend, &label, json, show_pub),
        Commands::Delete {
            labels,
            delete_pub,
            yes,
        } => commands::delete(backend, &labels, delete_pub, yes),
        Commands::ExportPub {
            label,
            output,
            authorized_keys,
            fingerprint,
            json,
        } => commands::export_pub(backend, &label, output, authorized_keys, fingerprint, json),
        Commands::Agent {
            socket,
            foreground,
            debug,
            labels,
        } => commands::agent(socket, foreground, debug, labels),
        Commands::Config { action } => match action {
            ConfigAction::Init => commands::config_init(),
            ConfigAction::Path => commands::config_path(),
            ConfigAction::Show => commands::config_show(),
        },
        Commands::Openssh { action } => match action {
            OpensshAction::PrintConfig {
                label,
                host,
                pkcs11,
            } => commands::openssh_print_config(backend, &label, &host, pkcs11),
        },
        Commands::Install => commands::install(),
        Commands::Uninstall => commands::uninstall(),
    }
}
