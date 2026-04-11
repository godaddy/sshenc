// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! sshenc: Main CLI for Secure Enclave SSH key management.

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
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

        /// Comment for the SSH public key line [default: user@hostname].
        #[arg(long, short = 'C')]
        comment: Option<String>,

        /// Write the public key to this path instead of ~/.ssh/<label>.pub.
        #[arg(long)]
        write_pub: Option<PathBuf>,

        /// Don't write the .pub file.
        #[arg(long)]
        no_pub_file: bool,

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

        /// Run in foreground (don't daemonize).
        #[arg(long, short = 'f')]
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

    /// Configure SSH to use sshenc for all hosts (adds IdentityAgent to ~/.ssh/config).
    Install,

    /// Remove sshenc configuration from ~/.ssh/config.
    Uninstall,

    /// Run ssh using a specific sshenc key.
    ///
    /// Example: sshenc ssh --label jgowdy-godaddy git@github.com
    /// Example: GIT_SSH_COMMAND="sshenc ssh --label jgowdy-godaddy" git push
    Ssh {
        /// Key label to use.
        #[arg(long, short = 'l')]
        label: String,

        /// Arguments to pass to ssh.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        ssh_args: Vec<String>,
    },

    /// Generate shell completions.
    Completions {
        /// Shell to generate completions for (bash, zsh, fish).
        shell: clap_complete::Shell,
    },
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
            no_pub_file,
            print_pub,
            require_user_presence,
            json,
        } => {
            let pub_path = if no_pub_file {
                None
            } else if let Some(path) = write_pub {
                Some(path)
            } else {
                let ssh_dir = dirs::home_dir()
                    .expect("could not determine home directory")
                    .join(".ssh");
                Some(ssh_dir.join(format!("{label}.pub")))
            };
            let comment = comment.or_else(default_comment);
            commands::keygen(
                backend,
                &label,
                comment,
                pub_path,
                print_pub,
                require_user_presence,
                json,
            )
        }
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
        Commands::Ssh { label, ssh_args } => commands::ssh_wrapper(&label, &ssh_args),
        Commands::Completions { shell } => {
            clap_complete::generate(shell, &mut Cli::command(), "sshenc", &mut std::io::stdout());
            Ok(())
        }
    }
}

/// Generate a default SSH key comment: user@hostname (same as ssh-keygen).
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
