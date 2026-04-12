// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! gitenc: Git wrapper that selects sshenc Secure Enclave identities.
//!
//! Usage:
//!   gitenc --label NAME [git args...]         # use a specific SE key
//!   gitenc [git args...]                      # use default (agent picks)
//!   gitenc --config NAME                      # set this repo to always use NAME
//!   gitenc --config                           # set this repo to use default agent
//!
//! Examples:
//!   gitenc --label github-work clone git@github.com:org/repo.git
//!   gitenc --label github-personal push origin main
//!   gitenc --config github-work               # configure current repo
//!   gitenc pull                               # uses configured key

#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::process::Command;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let parsed = parse_args(&args);

    match parsed {
        ParsedArgs::Config(label) => configure_repo(label.as_deref()),
        ParsedArgs::Run { label, git_args } => run_git(label.as_deref(), &git_args),
    }
}

fn run_git(label: Option<&str>, git_args: &[String]) -> ! {
    let ssh_command = match label {
        Some(l) => format!("sshenc ssh --label {} --", l),
        None => "sshenc ssh --".to_string(),
    };

    #[cfg(unix)]
    {
        let err = Command::new("git")
            .args(git_args)
            .env("GIT_SSH_COMMAND", &ssh_command)
            .exec();

        eprintln!("gitenc: failed to exec git: {err}");
        std::process::exit(1);
    }

    #[cfg(windows)]
    {
        let status = Command::new("git")
            .args(git_args)
            .env("GIT_SSH_COMMAND", &ssh_command)
            .status();

        match status {
            Ok(s) => std::process::exit(s.code().unwrap_or(1)),
            Err(e) => {
                eprintln!("gitenc: failed to run git: {e}");
                std::process::exit(1);
            }
        }
    }
}

fn configure_repo(label: Option<&str>) {
    let effective_label = label.unwrap_or("default");
    let ssh_command = format!("sshenc ssh --label {} --", effective_label);

    // Determine the signing key path
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| "/tmp".into());
    let signing_key = if effective_label == "default" {
        format!("{home}/.ssh/id_ecdsa.pub")
    } else {
        format!("{home}/.ssh/{effective_label}.pub")
    };

    // Find sshenc binary (same directory as gitenc, or in PATH)
    let sshenc_bin = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("sshenc")))
        .filter(|p| p.exists())
        .or_else(|| {
            std::process::Command::new("which")
                .arg("sshenc")
                .output()
                .ok()
                .filter(|o| o.status.success())
                .and_then(|o| {
                    String::from_utf8(o.stdout)
                        .ok()
                        .map(|s| std::path::PathBuf::from(s.trim()))
                })
        })
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "sshenc".to_string());

    // Try to load identity from key metadata
    let meta_dir = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
        .join(".sshenc")
        .join("keys");
    let meta_path = meta_dir.join(format!("{effective_label}.meta"));
    let (git_name, git_email) = if let Ok(content) = std::fs::read_to_string(&meta_path) {
        // Parse just the fields we need (avoid pulling in the full FFI crate)
        let name = content
            .lines()
            .find(|l| l.contains("\"git_name\""))
            .and_then(|l| l.split('"').nth(3))
            .map(String::from);
        let email = content
            .lines()
            .find(|l| l.contains("\"git_email\""))
            .and_then(|l| l.split('"').nth(3))
            .map(String::from);
        (name, email)
    } else {
        (None, None)
    };

    // Set SSH command for push/pull and commit signing
    let mut configs: Vec<(&str, &str)> = vec![
        ("core.sshCommand", &ssh_command),
        ("gpg.format", "ssh"),
        ("gpg.ssh.program", &sshenc_bin),
        ("user.signingkey", &signing_key),
        ("commit.gpgsign", "true"),
    ];

    // Set identity if configured on the key
    let name_ref;
    let email_ref;
    if let Some(ref name) = git_name {
        name_ref = name.clone();
        configs.push(("user.name", &name_ref));
    }
    if let Some(ref email) = git_email {
        email_ref = email.clone();
        configs.push(("user.email", &email_ref));
    }

    for (key, value) in &configs {
        let status = Command::new("git").args(["config", key, value]).status();
        match status {
            Ok(s) if s.success() => {}
            Ok(s) => {
                eprintln!(
                    "git config {key} failed (exit {}). Are you in a git repo?",
                    s.code().unwrap_or(-1)
                );
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("gitenc: failed to run git: {e}");
                std::process::exit(1);
            }
        }
    }

    println!("Configured this repo to use sshenc key: {effective_label}");
    println!("  SSH auth:       sshenc ssh --label {effective_label}");
    println!("  Commit signing: {signing_key}");
    if let Some(ref name) = git_name {
        println!("  Author:         {name}");
    }
    if let Some(ref email) = git_email {
        println!("  Email:          {email}");
    }
    if git_name.is_none() && git_email.is_none() {
        println!("  (no git identity set — use 'sshenc identity {effective_label} --name \"...\" --email \"...\"' to configure)");
    }
}

enum ParsedArgs {
    Config(Option<String>),
    Run {
        label: Option<String>,
        git_args: Vec<String>,
    },
}

fn parse_args(args: &[String]) -> ParsedArgs {
    if !args.is_empty() && args[0] == "--config" {
        // Support both: gitenc --config <label> AND gitenc --config --label <label>
        if args.len() >= 3 && (args[1] == "--label" || args[1] == "-l") {
            return ParsedArgs::Config(Some(args[2].clone()));
        }
        let label = args.get(1).cloned();
        return ParsedArgs::Config(label);
    }

    if args.len() >= 2 && (args[0] == "--label" || args[0] == "-l") {
        ParsedArgs::Run {
            label: Some(args[1].clone()),
            git_args: args[2..].to_vec(),
        }
    } else {
        ParsedArgs::Run {
            label: None,
            git_args: args.to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn test_parse_args_long_label() {
        let args = s(&[
            "--label",
            "github-work",
            "clone",
            "git@github.com:org/repo.git",
        ]);
        match parse_args(&args) {
            ParsedArgs::Run { label, git_args } => {
                assert_eq!(label, Some("github-work".to_string()));
                assert_eq!(git_args, s(&["clone", "git@github.com:org/repo.git"]));
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn test_parse_args_short_label() {
        let args = s(&["-l", "mykey", "push", "origin", "main"]);
        match parse_args(&args) {
            ParsedArgs::Run { label, git_args } => {
                assert_eq!(label, Some("mykey".to_string()));
                assert_eq!(git_args, s(&["push", "origin", "main"]));
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn test_parse_args_no_label() {
        let args = s(&["pull", "--rebase"]);
        match parse_args(&args) {
            ParsedArgs::Run { label, git_args } => {
                assert_eq!(label, None);
                assert_eq!(git_args, s(&["pull", "--rebase"]));
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn test_parse_args_empty() {
        let args: Vec<String> = Vec::new();
        match parse_args(&args) {
            ParsedArgs::Run { label, git_args } => {
                assert_eq!(label, None);
                assert!(git_args.is_empty());
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn test_parse_args_label_no_value() {
        let args = s(&["--label"]);
        match parse_args(&args) {
            ParsedArgs::Run { label, git_args } => {
                assert_eq!(label, None);
                assert_eq!(git_args, s(&["--label"]));
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn test_parse_args_config_with_label() {
        let args = s(&["--config", "github-work"]);
        match parse_args(&args) {
            ParsedArgs::Config(label) => {
                assert_eq!(label, Some("github-work".to_string()));
            }
            _ => panic!("expected Config"),
        }
    }

    #[test]
    fn test_parse_args_config_without_label() {
        let args = s(&["--config"]);
        match parse_args(&args) {
            ParsedArgs::Config(label) => {
                assert_eq!(label, None);
            }
            _ => panic!("expected Config"),
        }
    }
}
