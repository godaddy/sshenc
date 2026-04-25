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

use enclaveapp_core::types::validate_label;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

fn main() {
    enclaveapp_core::process::harden_process();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let parsed = parse_args(&args);

    match parsed {
        ParsedArgs::Config(label) => configure_repo(label.as_deref()),
        ParsedArgs::Run { label, git_args } => run_git(label.as_deref(), &git_args),
    }
}

#[allow(clippy::exit, clippy::print_stderr)]
fn run_git(label: Option<&str>, git_args: &[String]) -> ! {
    let ssh_command = build_ssh_command(label).unwrap_or_else(|err| exit_invalid_label(&err));

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

#[allow(clippy::print_stdout, clippy::print_stderr, clippy::exit)]
fn configure_repo(label: Option<&str>) {
    if let Err(err) = build_ssh_command(label) {
        exit_invalid_label(&err);
    }

    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| "/tmp".into());

    // Find sshenc binary (same directory as gitenc, or in PATH)
    let sshenc_bin = {
        #[cfg(windows)]
        let binary_name = "sshenc.exe";
        #[cfg(not(windows))]
        let binary_name = "sshenc";
        enclaveapp_core::bin_discovery::find_trusted_binary(binary_name, "sshenc")
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| {
                eprintln!("gitenc: trusted sshenc binary not found");
                std::process::exit(1);
            })
    };

    let signing_label = label.unwrap_or("default");
    let metadata = load_git_key_metadata(signing_label);
    let configs = configure_repo_entries(label, &home, &sshenc_bin, metadata.as_ref())
        .unwrap_or_else(|err| exit_invalid_label(&err));

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

    match label {
        Some(effective_label) => {
            let signing_key = configs
                .iter()
                .find(|(key, _)| key == "user.signingkey")
                .map(|(_, value)| value.as_str())
                .unwrap_or("");
            println!("Configured this repo to use sshenc key: {effective_label}");
            println!("  SSH auth:       sshenc ssh --label {effective_label}");
            println!("  Commit signing: {signing_key}");
            if let Some(ref meta) = metadata {
                if let Some(ref name) = meta.git_name {
                    println!("  Author:         {name}");
                }
                if let Some(ref email) = meta.git_email {
                    println!("  Email:          {email}");
                }
                if meta.git_name.is_none() && meta.git_email.is_none() {
                    println!("  (no git identity set — use 'sshenc identity {effective_label} --name \"...\" --email \"...\"' to configure)");
                }
            } else {
                println!("  (no git identity set — use 'sshenc identity {effective_label} --name \"...\" --email \"...\"' to configure)");
            }
        }
        None => {
            let signing_key = configs
                .iter()
                .find(|(key, _)| key == "user.signingkey")
                .map(|(_, value)| value.as_str())
                .unwrap_or("");
            println!("Configured this repo to use sshenc agent-default SSH authentication.");
            println!("  SSH auth: sshenc ssh --");
            println!("  Commit signing: {signing_key}");
            if let Some(ref meta) = metadata {
                if let Some(ref name) = meta.git_name {
                    println!("  Author:         {name}");
                }
                if let Some(ref email) = meta.git_email {
                    println!("  Email:          {email}");
                }
            }
        }
    }
}

#[derive(Debug)]
enum ParsedArgs {
    Config(Option<String>),
    Run {
        label: Option<String>,
        git_args: Vec<String>,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct GitKeyMetadata {
    git_name: Option<String>,
    git_email: Option<String>,
    pub_file_path: Option<String>,
    pub_file_path_recorded: bool,
}

fn build_ssh_command(label: Option<&str>) -> Result<String, String> {
    match label {
        Some(label) => {
            validate_label(label).map_err(|e| e.to_string())?;
            Ok(format!("sshenc ssh --label {label} --"))
        }
        None => Ok("sshenc ssh --".to_string()),
    }
}

fn signing_key_path(home: &str, label: &str) -> Result<String, String> {
    if label == "default" {
        return Ok(format!("{home}/.ssh/id_ecdsa.pub"));
    }

    validate_label(label).map_err(|e| e.to_string())?;
    Ok(format!("{home}/.ssh/{label}.pub"))
}

fn load_git_key_metadata(label: &str) -> Option<GitKeyMetadata> {
    let meta_dir = dirs::home_dir()?.join(".sshenc").join("keys");
    let meta_path = meta_dir.join(format!("{label}.meta"));
    let content = std::fs::read_to_string(meta_path).ok()?;
    parse_git_key_metadata(&content)
}

fn parse_git_key_metadata(content: &str) -> Option<GitKeyMetadata> {
    let raw: serde_json::Value = serde_json::from_str(content).ok()?;
    let app_specific = raw.get("app_specific").unwrap_or(&raw);
    let git_name = app_specific
        .get("git_name")
        .or_else(|| raw.get("git_name"))
        .and_then(|value| value.as_str())
        .map(String::from);
    let git_email = app_specific
        .get("git_email")
        .or_else(|| raw.get("git_email"))
        .and_then(|value| value.as_str())
        .map(String::from);
    let pub_path_value = app_specific
        .get("pub_file_path")
        .or_else(|| raw.get("pub_file_path"));
    let pub_file_path = pub_path_value
        .and_then(|value| value.as_str())
        .map(String::from);

    Some(GitKeyMetadata {
        git_name,
        git_email,
        pub_file_path,
        pub_file_path_recorded: pub_path_value.is_some(),
    })
}

fn configure_repo_entries(
    label: Option<&str>,
    home: &str,
    sshenc_bin: &str,
    metadata: Option<&GitKeyMetadata>,
) -> Result<Vec<(String, String)>, String> {
    let mut configs = vec![("core.sshCommand".to_string(), build_ssh_command(label)?)];
    let label = label.unwrap_or("default");

    let signing_key = match metadata.and_then(|meta| meta.pub_file_path.as_deref()) {
        Some(path) => {
            if Path::new(path).exists() {
                path.to_string()
            } else {
                return Err(format!("recorded public key file does not exist: {path}"));
            }
        }
        None if metadata.is_some_and(|meta| meta.pub_file_path_recorded) => {
            return Err(format!(
                "key '{label}' does not have a recorded public key file; export one before running gitenc --config"
            ));
        }
        None => signing_key_path(home, label)?,
    };

    configs.extend([
        ("gpg.format".to_string(), "ssh".to_string()),
        ("gpg.ssh.program".to_string(), sshenc_bin.to_string()),
        ("user.signingkey".to_string(), signing_key.clone()),
        ("commit.gpgsign".to_string(), "true".to_string()),
    ]);

    if let Some(metadata) = metadata {
        if let Some(name) = metadata.git_name.as_ref() {
            configs.push(("user.name".to_string(), name.clone()));
        }
        if let Some(email) = metadata.git_email.as_ref() {
            configs.push(("user.email".to_string(), email.clone()));
        }
    }

    // Set up allowed signers file for local signature verification.
    let allowed_signers_path = Path::new(home).join(".ssh").join("allowed_signers");
    if let Some(email) = metadata.and_then(|m| m.git_email.as_deref()) {
        if let Ok(pubkey) = std::fs::read_to_string(&signing_key) {
            let entry = format!("{email} {}", pubkey.trim());
            update_allowed_signers(&allowed_signers_path, email, &entry);
        }
    }
    configs.push((
        "gpg.ssh.allowedSignersFile".to_string(),
        allowed_signers_path.display().to_string(),
    ));

    Ok(configs)
}

/// Add or update an entry in the allowed signers file.
/// Replaces any existing entry whose principals list names this email
/// exactly. Lines whose first field `starts_with(email)` but is not an
/// exact principal match (e.g. `alice@x.com.attacker ssh-ed25519 …`)
/// are preserved, which is the safe behavior for an authentication
/// trust file.
fn update_allowed_signers(path: &Path, email: &str, entry: &str) {
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    let mut lines: Vec<&str> = existing
        .lines()
        .filter(|line| !line_principals_contain(line, email))
        .collect();
    lines.push(entry);
    if let Some(parent) = path.parent() {
        drop(std::fs::create_dir_all(parent));
    }
    drop(std::fs::write(path, lines.join("\n") + "\n"));
}

/// Return true if the first whitespace-separated field on the line (the
/// principals field per ssh-keygen(1) ALLOWED SIGNERS) contains an
/// exact match for `email` among its comma-separated entries.
fn line_principals_contain(line: &str, email: &str) -> bool {
    let Some(first_field) = line.split_whitespace().next() else {
        return false;
    };
    first_field.split(',').any(|principal| principal == email)
}

#[allow(clippy::print_stderr, clippy::exit)]
fn exit_invalid_label(err: &str) -> ! {
    eprintln!("gitenc: invalid label: {err}");
    std::process::exit(2);
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
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
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
            other => panic!("expected Run, got {other:?}"),
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
            other => panic!("expected Run, got {other:?}"),
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
            other => panic!("expected Run, got {other:?}"),
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
            other => panic!("expected Run, got {other:?}"),
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
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_args_config_with_label() {
        let args = s(&["--config", "github-work"]);
        match parse_args(&args) {
            ParsedArgs::Config(label) => {
                assert_eq!(label, Some("github-work".to_string()));
            }
            other => panic!("expected Config, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_args_config_without_label() {
        let args = s(&["--config"]);
        match parse_args(&args) {
            ParsedArgs::Config(label) => {
                assert_eq!(label, None);
            }
            other => panic!("expected Config, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_args_config_with_label_flag() {
        // gitenc --config --label my-key
        let args = s(&["--config", "--label", "my-key"]);
        match parse_args(&args) {
            ParsedArgs::Config(label) => {
                assert_eq!(label, Some("my-key".to_string()));
            }
            other => panic!("expected Config, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_args_config_with_short_label_flag() {
        // gitenc --config -l my-key
        let args = s(&["--config", "-l", "my-key"]);
        match parse_args(&args) {
            ParsedArgs::Config(label) => {
                assert_eq!(label, Some("my-key".to_string()));
            }
            other => panic!("expected Config, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_args_label_only_no_git_args() {
        // gitenc --label mykey (no git subcommand)
        let args = s(&["--label", "mykey"]);
        match parse_args(&args) {
            ParsedArgs::Run { label, git_args } => {
                assert_eq!(label, Some("mykey".to_string()));
                assert!(git_args.is_empty());
            }
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_args_passthrough_git_args() {
        // gitenc status --short
        let args = s(&["status", "--short"]);
        match parse_args(&args) {
            ParsedArgs::Run { label, git_args } => {
                assert_eq!(label, None);
                assert_eq!(git_args, s(&["status", "--short"]));
            }
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_args_push_origin_main() {
        let args = s(&["push", "origin", "main"]);
        match parse_args(&args) {
            ParsedArgs::Run { label, git_args } => {
                assert_eq!(label, None);
                assert_eq!(git_args, s(&["push", "origin", "main"]));
            }
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_args_label_with_double_dash_separator() {
        // gitenc --label mykey -- push origin main
        let args = s(&["--label", "mykey", "--", "push", "origin", "main"]);
        match parse_args(&args) {
            ParsedArgs::Run { label, git_args } => {
                assert_eq!(label, Some("mykey".to_string()));
                assert_eq!(git_args, s(&["--", "push", "origin", "main"]));
            }
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn test_build_ssh_command_with_valid_label() {
        let command = build_ssh_command(Some("github-work")).unwrap();
        assert_eq!(command, "sshenc ssh --label github-work --");
    }

    #[test]
    fn test_build_ssh_command_rejects_invalid_label() {
        let err = build_ssh_command(Some("bad;label")).unwrap_err();
        assert!(err.to_lowercase().contains("label"));
    }

    #[test]
    fn test_configure_repo_with_temp_git_repo() {
        let dir = std::env::temp_dir().join("sshenc-test-configure-repo");
        // Clean up from any prior run
        drop(std::fs::remove_dir_all(&dir));
        std::fs::create_dir_all(&dir).unwrap();

        let status = Command::new("git")
            .args(["init"])
            .current_dir(&dir)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "git init failed");

        // Run configure_repo's git config commands by calling git config directly
        // in the temp repo context. We test the same logic configure_repo uses.
        let label = "test-key";
        let ssh_command = build_ssh_command(Some(label)).unwrap();
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| "/tmp".into());
        let signing_key = signing_key_path(&home, label).unwrap();

        let configs = vec![
            ("core.sshCommand".to_string(), ssh_command),
            ("gpg.format".to_string(), "ssh".to_string()),
            ("user.signingkey".to_string(), signing_key),
            ("commit.gpgsign".to_string(), "true".to_string()),
        ];

        for (key, value) in &configs {
            let status = Command::new("git")
                .args(["config", key, value])
                .current_dir(&dir)
                .status()
                .unwrap();
            assert!(status.success(), "git config {key} failed");
        }

        // Verify the configs were set
        for (key, expected) in &configs {
            let output = Command::new("git")
                .args(["config", "--get", key])
                .current_dir(&dir)
                .output()
                .unwrap();
            assert!(output.status.success(), "git config --get {key} failed");
            let actual = String::from_utf8(output.stdout).unwrap();
            assert_eq!(actual.trim(), expected, "config {key} mismatch");
        }

        // Cleanup
        drop(std::fs::remove_dir_all(&dir));
    }

    #[test]
    fn test_configure_repo_entries_without_label_sets_default_signing_key() {
        let entries = configure_repo_entries(None, "/tmp/home", "/tmp/sshenc", None).unwrap();
        assert!(entries
            .iter()
            .any(|(key, value)| { key == "core.sshCommand" && value == "sshenc ssh --" }));
        assert!(entries.iter().any(|(key, value)| {
            key == "user.signingkey" && value == "/tmp/home/.ssh/id_ecdsa.pub"
        }));
        assert!(entries
            .iter()
            .any(|(key, value)| key == "commit.gpgsign" && value == "true"));
    }

    #[test]
    fn test_configure_repo_named_label_uses_label_pub() {
        let entries =
            configure_repo_entries(Some("github-work"), "/tmp/home", "/tmp/sshenc", None).unwrap();

        assert!(entries.iter().any(|(key, value)| {
            key == "user.signingkey" && value == "/tmp/home/.ssh/github-work.pub"
        }));
    }

    #[test]
    fn test_signing_key_path_rejects_invalid_label() {
        let err = signing_key_path("/tmp/home", "../escape").unwrap_err();
        assert!(err.to_lowercase().contains("label"));
    }

    #[test]
    fn test_parse_git_key_metadata_reads_app_specific_fields() {
        let parsed = parse_git_key_metadata(
            r#"{
                "label":"work",
                "key_type":"signing",
                "app_specific":{
                    "git_name":"Alice",
                    "git_email":"alice@example.com",
                    "pub_file_path":"/tmp/work.pub"
                }
            }"#,
        )
        .unwrap();

        assert_eq!(parsed.git_name.as_deref(), Some("Alice"));
        assert_eq!(parsed.git_email.as_deref(), Some("alice@example.com"));
        assert_eq!(parsed.pub_file_path.as_deref(), Some("/tmp/work.pub"));
        assert!(parsed.pub_file_path_recorded);
    }

    #[test]
    fn test_parse_git_key_metadata_reads_legacy_top_level_fields() {
        let parsed = parse_git_key_metadata(
            r#"{
                "label":"work",
                "git_name":"Alice",
                "git_email":"alice@example.com"
            }"#,
        )
        .unwrap();

        assert_eq!(parsed.git_name.as_deref(), Some("Alice"));
        assert_eq!(parsed.git_email.as_deref(), Some("alice@example.com"));
        assert_eq!(parsed.pub_file_path, None);
        assert!(!parsed.pub_file_path_recorded);
    }

    #[test]
    fn test_configure_repo_entries_uses_recorded_pub_file_path() {
        let dir = std::env::temp_dir().join("sshenc-test-gitenc-pub");
        drop(std::fs::remove_dir_all(&dir));
        std::fs::create_dir_all(&dir).unwrap();
        let pub_path = dir.join("custom.pub");
        std::fs::write(&pub_path, "ssh-ed25519 AAAATEST test\n").unwrap();

        let metadata = GitKeyMetadata {
            git_name: None,
            git_email: None,
            pub_file_path: Some(pub_path.display().to_string()),
            pub_file_path_recorded: true,
        };
        let entries =
            configure_repo_entries(Some("work"), "/tmp/home", "/tmp/sshenc", Some(&metadata))
                .unwrap();

        assert!(entries.iter().any(|(key, value)| {
            key == "user.signingkey" && value == &pub_path.display().to_string()
        }));

        drop(std::fs::remove_dir_all(&dir));
    }

    #[test]
    fn test_configure_repo_entries_rejects_missing_recorded_pub_file_path() {
        let metadata = GitKeyMetadata {
            git_name: None,
            git_email: None,
            pub_file_path: None,
            pub_file_path_recorded: true,
        };

        let err = configure_repo_entries(Some("work"), "/tmp/home", "/tmp/sshenc", Some(&metadata))
            .unwrap_err();
        assert!(err.contains("does not have a recorded public key file"));
    }

    #[test]
    fn line_principals_contain_exact_match() {
        assert!(line_principals_contain(
            "alice@example.com ssh-ed25519 AAAAC3...",
            "alice@example.com"
        ));
    }

    #[test]
    fn line_principals_contain_matches_comma_separated() {
        assert!(line_principals_contain(
            "alice@example.com,alice@work.com ssh-ed25519 AAAAC3...",
            "alice@work.com"
        ));
    }

    #[test]
    fn line_principals_contain_does_not_prefix_match() {
        // Previously starts_with(email) would have matched this — the
        // attacker could lose their entry when the real user rotated.
        // Exact-match semantics keep the attacker's line intact.
        assert!(!line_principals_contain(
            "alice@example.com.attacker ssh-ed25519 AAAAC3...",
            "alice@example.com"
        ));
    }

    #[test]
    fn line_principals_contain_ignores_comments_and_blank_lines() {
        assert!(!line_principals_contain(
            "# alice@example.com is the CEO",
            "alice@example.com"
        ));
        assert!(!line_principals_contain("", "alice@example.com"));
    }

    #[test]
    fn line_principals_contain_ignores_matching_keytype_field() {
        // The email must appear in the first field (principals), not
        // later fields such as key type / base64 / comment.
        assert!(!line_principals_contain(
            "bob@example.com ssh-ed25519 alice@example.com",
            "alice@example.com"
        ));
    }

    #[test]
    fn update_allowed_signers_replaces_only_exact_match() {
        let dir = std::env::temp_dir().join(format!(
            "gitenc-allowed-signers-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("allowed_signers");

        let initial = concat!(
            "alice@example.com ssh-ed25519 AAAA-old-key\n",
            "alice@example.com.attacker ssh-ed25519 AAAA-attacker-key\n",
            "alice@example.com,alice@work.com ssh-ed25519 AAAA-multi-principal-key\n",
            "# alice@example.com is not actually here\n",
            "bob@example.com ssh-ed25519 AAAA-bob-key\n",
        );
        std::fs::write(&path, initial).unwrap();

        update_allowed_signers(
            &path,
            "alice@example.com",
            "alice@example.com ssh-ed25519 AAAA-new-key",
        );

        let result = std::fs::read_to_string(&path).unwrap();
        // Old alice exact-match line is gone.
        assert!(!result.contains("AAAA-old-key"));
        // Attacker prefix-collision line is preserved.
        assert!(result.contains("AAAA-attacker-key"));
        // Multi-principal line containing alice@example.com IS removed —
        // we matched alice@example.com exactly within the principals.
        assert!(!result.contains("AAAA-multi-principal-key"));
        // Unrelated bob line is preserved.
        assert!(result.contains("AAAA-bob-key"));
        // Comment line is preserved.
        assert!(result.contains("# alice@example.com is not actually here"));
        // New entry is appended.
        assert!(result.contains("AAAA-new-key"));

        drop(std::fs::remove_dir_all(&dir));
    }
}
