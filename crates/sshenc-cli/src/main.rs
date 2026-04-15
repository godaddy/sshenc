// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! sshenc: Main CLI for Secure Enclave SSH key management.

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use sshenc_core::backup;
use sshenc_core::{AccessPolicy, Config};
use std::path::PathBuf;

mod commands;
#[cfg(target_os = "windows")]
#[allow(clippy::print_stdout, clippy::print_stderr)]
mod wsl;

#[derive(Parser)]
#[command(
    name = "sshenc",
    about = "Manage hardware-backed SSH keys",
    long_about = "sshenc creates, manages, and uses hardware-backed SSH keys for\n\
                   OpenSSH and git+ssh workflows. Keys are non-exportable, device-bound ECDSA P-256\n\
                   keys stored in the Secure Enclave (macOS), TPM 2.0 (Windows), or software-backed\n\
                   keys on disk (Linux).",
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

        /// Print the public key to stdout after generation.
        #[arg(long)]
        print_pub: bool,

        /// Require user presence (Touch ID or password) for each signing operation.
        #[arg(long)]
        require_user_presence: bool,

        /// Authentication policy: none, any (Touch ID or password), biometric (Touch ID only), password.
        /// Overrides --require-user-presence if both are specified.
        #[arg(long, value_parser = ["none", "any", "biometric", "password"])]
        auth_policy: Option<String>,

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
        /// Key label to inspect [default: "default"].
        #[arg(default_value = "default")]
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
        /// Key label to export [default: "default"].
        #[arg(default_value = "default")]
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

    /// Set the git identity (name and email) for a key.
    ///
    /// When gitenc --config uses this key, it will set user.name and user.email
    /// on the repo automatically.
    Identity {
        /// Key label [default: "default"].
        #[arg(default_value = "default")]
        label: String,

        /// Git author name (e.g., "Jay Gowdy").
        #[arg(long)]
        name: String,

        /// Git author email (e.g., "jay@gowdy.me").
        #[arg(long)]
        email: String,
    },

    /// Remove sshenc configuration from ~/.ssh/config.
    Uninstall,

    /// Promote a named key to be the default key.
    ///
    /// Renames the key to "default" and writes ~/.ssh/id_ecdsa.pub so SSH
    /// and ssh-copy-id find it automatically. The agent will present this
    /// key first.
    Default {
        /// Label of the key to promote.
        label: String,
    },

    /// Run ssh using a specific sshenc key.
    ///
    /// Example: sshenc ssh --label jgowdy-godaddy git@github.com
    /// Example: GIT_SSH_COMMAND="sshenc ssh --label jgowdy-godaddy" git push
    Ssh {
        /// Key label to use. If omitted, the agent offers all SE keys.
        #[arg(long, short = 'l')]
        label: Option<String>,

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

#[allow(clippy::print_stderr)]
fn main() -> Result<()> {
    // Intercept ssh-keygen-compatible mode before clap parsing.
    // Git calls us with -Y sign, -Y verify, -Y find-principals, etc.
    // We only handle -Y sign ourselves; everything else passes to real ssh-keygen.
    let raw_args: Vec<String> = std::env::args().collect();
    if raw_args.len() >= 3 && raw_args[1] == "-Y" {
        if raw_args[2] == "sign" {
            return commands::ssh_sign(&raw_args[1..]);
        }
        return commands::forward_to_ssh_keygen(&raw_args[1..]);
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();
    let pub_dir = Config::load_default()?.pub_dir;

    let backend = sshenc_se::SshencBackend::new(pub_dir)
        .map_err(|e| anyhow::anyhow!("failed to initialize backend: {e}"))?;

    run_command(cli.command, &backend)
}

#[allow(clippy::print_stdout, clippy::print_stderr)]
fn run_command(command: Commands, backend: &dyn sshenc_se::KeyBackend) -> Result<()> {
    match command {
        Commands::Keygen {
            label,
            comment,
            write_pub,
            no_pub_file,
            print_pub,
            require_user_presence,
            auth_policy,
            json,
        } => {
            let pub_path = if no_pub_file {
                None
            } else if let Some(path) = write_pub.as_ref() {
                Some(path.clone())
            } else {
                let ssh_dir = dirs::home_dir()
                    .ok_or_else(|| {
                        anyhow::anyhow!("could not determine home directory; set $HOME")
                    })?
                    .join(".ssh");
                // "default" label uses standard OpenSSH naming (id_ecdsa.pub)
                if label == "default" {
                    Some(ssh_dir.join("id_ecdsa.pub"))
                } else {
                    Some(ssh_dir.join(format!("{label}.pub")))
                }
            };
            let paired_private_path = if write_pub.is_none() && !no_pub_file && label == "default" {
                pub_path.as_ref().map(|path| path.with_extension(""))
            } else {
                None
            };
            // Check for existing files before overwriting (like ssh-keygen)
            if let Some(ref path) = pub_path {
                let has_private = paired_private_path
                    .as_ref()
                    .is_some_and(|private_path| private_path.exists() && private_path != path);

                if has_private {
                    eprintln!("Existing SSH key pair will be backed up before generation.");
                } else if path.exists() {
                    eprintln!("{} already exists.", path.display());
                    eprint!("Overwrite (y/n)? ");
                    std::io::Write::flush(&mut std::io::stderr()).ok();
                    let mut input = String::new();
                    std::io::stdin().read_line(&mut input).ok();
                    if !input.trim().eq_ignore_ascii_case("y") {
                        println!("Cancelled.");
                        return Ok(());
                    }
                }
            }
            let comment = comment.or_else(default_comment);
            let access_policy =
                selected_access_policy(auth_policy.as_deref(), require_user_presence)?;
            backup::run_with_backup(pub_path.as_deref(), paired_private_path.as_deref(), || {
                commands::keygen(
                    backend,
                    &label,
                    comment,
                    pub_path.clone(),
                    print_pub,
                    access_policy,
                    json,
                )
            })
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
        Commands::Identity { label, name, email } => commands::set_identity(&label, &name, &email),
        Commands::Default { label } => commands::promote_to_default(&label),
        Commands::Ssh { label, ssh_args } => commands::ssh_wrapper(label.as_deref(), &ssh_args),
        Commands::Completions { shell } => {
            clap_complete::generate(shell, &mut Cli::command(), "sshenc", &mut std::io::stdout());
            Ok(())
        }
    }
}

fn selected_access_policy(
    auth_policy: Option<&str>,
    require_user_presence: bool,
) -> Result<AccessPolicy> {
    if let Some(policy) = auth_policy {
        return match policy {
            "any" => Ok(AccessPolicy::Any),
            "biometric" => Ok(AccessPolicy::BiometricOnly),
            "password" => Ok(AccessPolicy::PasswordOnly),
            "none" => Ok(AccessPolicy::None),
            other => anyhow::bail!("unknown access policy: {other}"),
        };
    }

    Ok(if require_user_presence {
        AccessPolicy::Any
    } else {
        AccessPolicy::None
    })
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
