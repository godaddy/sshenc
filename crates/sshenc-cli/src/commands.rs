// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! CLI command implementations.

use anyhow::{bail, Result};
use sshenc_core::key::{KeyGenOptions, KeyLabel};
use sshenc_core::pubkey::SshPublicKey;
use sshenc_core::Config;
use sshenc_se::KeyBackend;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub fn keygen(
    backend: &dyn KeyBackend,
    label: &str,
    comment: Option<String>,
    write_pub: Option<PathBuf>,
    print_pub: bool,
    require_user_presence: bool,
    json: bool,
) -> Result<()> {
    let key_label = KeyLabel::new(label)?;

    let opts = KeyGenOptions {
        label: key_label,
        comment,
        requires_user_presence: require_user_presence,
        write_pub_path: write_pub.clone(),
    };

    let info = backend.generate(&opts)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&info)?);
    } else {
        println!("Generated Secure Enclave key: {label}");
        println!("  Algorithm: {}", info.metadata.algorithm);
        println!("  Fingerprint: {}", info.fingerprint_sha256);
        if let Some(ref path) = info.pub_file_path {
            println!("  Public key written to: {}", path.display());
        }
        if print_pub {
            let pubkey = SshPublicKey::from_sec1_bytes(
                &info.public_key_bytes,
                info.metadata.comment.clone(),
            )?;
            println!();
            println!("{}", pubkey.to_openssh_line());
        }
    }
    Ok(())
}

pub fn list(backend: &dyn KeyBackend, json: bool) -> Result<()> {
    let keys = backend.list()?;

    if json {
        println!("{}", serde_json::to_string_pretty(&keys)?);
        return Ok(());
    }

    if keys.is_empty() {
        println!("No sshenc-managed keys found.");
        return Ok(());
    }

    for key in &keys {
        println!("{}", key.metadata.label);
        println!("  Algorithm:     {}", key.metadata.algorithm);
        println!(
            "  Key size:      {} bits",
            key.metadata.algorithm.key_bits()
        );
        println!(
            "  User presence: {}",
            if key.metadata.requires_user_presence {
                "required"
            } else {
                "not required"
            }
        );
        println!("  App tag:       {}", key.metadata.app_tag);
        println!("  SHA256:        {}", key.fingerprint_sha256);
        println!("  MD5:           {}", key.fingerprint_md5);
        if let Some(ref path) = key.pub_file_path {
            println!("  Pub file:      {}", path.display());
        }
        println!();
    }
    println!("{} key(s) found.", keys.len());
    Ok(())
}

pub fn inspect(backend: &dyn KeyBackend, label: &str, json: bool, show_pub: bool) -> Result<()> {
    let info = backend.get(label)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&info)?);
        return Ok(());
    }

    println!("Key: {}", info.metadata.label);
    println!("  Algorithm:       {}", info.metadata.algorithm);
    println!(
        "  Key size:        {} bits",
        info.metadata.algorithm.key_bits()
    );
    println!(
        "  Curve:           {}",
        info.metadata.algorithm.ssh_curve_id()
    );
    println!(
        "  SSH key type:    {}",
        info.metadata.algorithm.ssh_key_type()
    );
    println!(
        "  User presence:   {}",
        if info.metadata.requires_user_presence {
            "required"
        } else {
            "not required"
        }
    );
    println!("  Application tag: {}", info.metadata.app_tag);
    println!("  SHA256:          {}", info.fingerprint_sha256);
    println!("  MD5:             {}", info.fingerprint_md5);
    if let Some(ref path) = info.pub_file_path {
        println!("  Pub file:        {}", path.display());
    }
    if let Some(ref comment) = info.metadata.comment {
        println!("  Comment:         {comment}");
    }

    if show_pub {
        let pubkey =
            SshPublicKey::from_sec1_bytes(&info.public_key_bytes, info.metadata.comment.clone())?;
        println!();
        println!("{}", pubkey.to_openssh_line());
    }

    Ok(())
}

pub fn delete(
    backend: &dyn KeyBackend,
    labels: &[String],
    delete_pub: bool,
    yes: bool,
) -> Result<()> {
    if labels.is_empty() {
        bail!("no key labels specified");
    }

    // Verify all keys exist first
    let mut keys_to_delete = Vec::new();
    for label in labels {
        let info = backend.get(label)?;
        keys_to_delete.push(info);
    }

    if !yes {
        print!("Delete {} key(s)? [y/N] ", keys_to_delete.len());
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Cancelled.");
            return Ok(());
        }
    }

    for key in &keys_to_delete {
        let label = key.metadata.label.as_str();
        backend.delete(label)?;
        println!("Deleted key: {label}");

        if delete_pub {
            if let Some(ref path) = key.pub_file_path {
                if path.exists() {
                    std::fs::remove_file(path)?;
                    println!("Deleted pub file: {}", path.display());
                }
            }
        }
    }

    Ok(())
}

pub fn export_pub(
    backend: &dyn KeyBackend,
    label: &str,
    output: Option<PathBuf>,
    authorized_keys: bool,
    fingerprint_only: bool,
    json: bool,
) -> Result<()> {
    let info = backend.get(label)?;

    if fingerprint_only {
        if json {
            let fp = serde_json::json!({
                "label": label,
                "sha256": info.fingerprint_sha256,
                "md5": info.fingerprint_md5,
            });
            println!("{}", serde_json::to_string_pretty(&fp)?);
        } else {
            println!("{}", info.fingerprint_sha256);
        }
        return Ok(());
    }

    let pubkey =
        SshPublicKey::from_sec1_bytes(&info.public_key_bytes, info.metadata.comment.clone())?;

    let line = if authorized_keys {
        pubkey.to_authorized_keys_line()
    } else {
        pubkey.to_openssh_line()
    };

    if json {
        let out = serde_json::json!({
            "label": label,
            "public_key": line,
            "fingerprint_sha256": info.fingerprint_sha256,
            "fingerprint_md5": info.fingerprint_md5,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else if let Some(path) = output {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, format!("{line}\n"))?;
        println!("Public key written to: {}", path.display());
    } else {
        println!("{line}");
    }

    Ok(())
}

pub fn agent(
    socket: Option<PathBuf>,
    _foreground: bool,
    debug: bool,
    labels: Vec<String>,
) -> Result<()> {
    let config = Config::load_default()?;
    let socket_path = socket.unwrap_or(config.socket_path);

    let level = if debug { "debug" } else { "info" };

    // Re-initialize tracing for agent mode
    // (the main CLI already initialized at warn level, but the agent needs more)
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(level))
        .try_init();

    let allowed_labels = if labels.is_empty() {
        config.allowed_labels
    } else {
        labels
    };

    println!("Starting sshenc agent...");
    println!("SSH_AUTH_SOCK={}", socket_path.display());
    println!();
    println!("To use in your shell:");
    println!("  export SSH_AUTH_SOCK={}", socket_path.display());

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        // Import here to avoid the module path issue
        let server = sshenc_agent::server::run_agent(socket_path, allowed_labels);
        server.await
    })?;

    Ok(())
}

pub fn config_init() -> Result<()> {
    let path = Config::init()?;
    println!("Config file created: {}", path.display());
    Ok(())
}

pub fn config_path() -> Result<()> {
    println!("{}", Config::default_path().display());
    Ok(())
}

pub fn config_show() -> Result<()> {
    let config = Config::load_default()?;
    println!("{}", toml::to_string_pretty(&config)?);
    Ok(())
}

pub fn install() -> Result<()> {
    let config = Config::load_default()?;
    let ssh_config_path = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("could not determine home directory"))?
        .join(".ssh")
        .join("config");

    // Find the launcher dylib if available
    let dylib_path = find_launcher_dylib();

    match sshenc_core::ssh_config::install_block(
        &ssh_config_path,
        &config.socket_path,
        dylib_path.as_deref(),
    )? {
        sshenc_core::ssh_config::InstallResult::Installed => {
            println!("Installed sshenc in {}", ssh_config_path.display());
            println!("  IdentityAgent {}", config.socket_path.display());
            if let Some(ref dylib) = dylib_path {
                println!("  PKCS11Provider {} (agent launcher)", dylib.display());
            }
        }
        sshenc_core::ssh_config::InstallResult::AlreadyPresent => {
            println!("sshenc already configured in {}", ssh_config_path.display());
        }
    }

    // Start the agent as a daemon if it's not already running
    if !agent_is_running(&config.socket_path) {
        let agent_bin = find_agent_binary()?;
        std::process::Command::new(&agent_bin)
            .arg("--socket")
            .arg(&config.socket_path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .ok();
        println!("Started sshenc agent.");
    } else {
        println!("Agent already running.");
    }

    // On Windows, set GIT_SSH_COMMAND as a user environment variable so that
    // Git Bash (which bundles MINGW SSH that doesn't support named pipes) uses
    // the real Windows OpenSSH instead.
    #[cfg(target_os = "windows")]
    {
        let win_ssh = r"C:\Windows\System32\OpenSSH\ssh.exe";
        if std::path::Path::new(win_ssh).exists() {
            let status = std::process::Command::new("setx")
                .args(["GIT_SSH_COMMAND", win_ssh])
                .stdout(std::process::Stdio::null())
                .status();
            match status {
                Ok(s) if s.success() => {
                    println!("Set GIT_SSH_COMMAND={win_ssh} (for Git Bash compatibility).");
                }
                _ => {
                    eprintln!("warning: could not set GIT_SSH_COMMAND. Git Bash users should run:");
                    eprintln!("  setx GIT_SSH_COMMAND \"{}\"", win_ssh);
                }
            }
        }
    }

    println!();
    println!("SSH will now use sshenc for all connections.");
    println!("Your existing ~/.ssh keys continue to work as fallback.");
    Ok(())
}

/// Find the PKCS#11 launcher library, if installed.
fn find_launcher_dylib() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    let lib_name = "libsshenc_pkcs11.dylib";
    #[cfg(target_os = "windows")]
    let lib_name = "sshenc_pkcs11.dll";
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let lib_name = "libsshenc_pkcs11.so";

    // Next to the current executable
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join(lib_name);
            if candidate.exists() {
                return Some(candidate);
            }
            // Homebrew (macOS): binary in bin/, dylib in lib/
            #[cfg(target_os = "macos")]
            {
                let lib_candidate = dir.parent()?.join("lib").join(lib_name);
                if lib_candidate.exists() {
                    return Some(lib_candidate);
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let common = ["/opt/homebrew/lib", "/usr/local/lib"];
        for dir in &common {
            let candidate = PathBuf::from(dir).join(lib_name);
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }

    None
}

/// Check if the agent is actually running by attempting to connect.
/// A stale socket file from a crashed agent will fail to connect.
#[cfg(unix)]
fn agent_is_running(socket_path: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(socket_path).is_ok()
}

/// Check if the agent is running by attempting to open the named pipe.
#[cfg(windows)]
fn agent_is_running(socket_path: &Path) -> bool {
    use std::fs::OpenOptions;
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(socket_path)
        .is_ok()
}

/// Find the sshenc-agent binary.
fn find_agent_binary() -> Result<PathBuf> {
    #[cfg(windows)]
    let agent_name = "sshenc-agent.exe";
    #[cfg(not(windows))]
    let agent_name = "sshenc-agent";

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join(agent_name);
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }
    // Check PATH
    #[cfg(unix)]
    {
        if let Ok(output) = std::process::Command::new("which").arg(agent_name).output() {
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !path.is_empty() {
                    return Ok(PathBuf::from(path));
                }
            }
        }
    }
    #[cfg(windows)]
    {
        if let Ok(output) = std::process::Command::new("where").arg(agent_name).output() {
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if !path.is_empty() {
                    return Ok(PathBuf::from(path));
                }
            }
        }
    }
    bail!("sshenc-agent not found");
}

pub fn uninstall() -> Result<()> {
    let ssh_config_path = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("could not determine home directory"))?
        .join(".ssh")
        .join("config");

    match sshenc_core::ssh_config::uninstall_block(&ssh_config_path)? {
        sshenc_core::ssh_config::UninstallResult::Removed => {
            println!(
                "Removed sshenc agent configuration from {}",
                ssh_config_path.display()
            );
        }
        sshenc_core::ssh_config::UninstallResult::NotPresent => {
            println!(
                "No sshenc configuration found in {}",
                ssh_config_path.display()
            );
        }
    }

    // On Windows, remove the GIT_SSH_COMMAND user environment variable
    #[cfg(target_os = "windows")]
    {
        // setx with empty value doesn't work; use reg delete instead
        let _ = std::process::Command::new("reg")
            .args(["delete", "HKCU\\Environment", "/v", "GIT_SSH_COMMAND", "/f"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        println!("Removed GIT_SSH_COMMAND environment variable.");
    }

    Ok(())
}

pub fn openssh_print_config(
    backend: &dyn KeyBackend,
    label: &str,
    host: &str,
    pkcs11: bool,
) -> Result<()> {
    let info = backend.get(label)?;

    let pub_path = info
        .pub_file_path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| format!("~/.ssh/{label}.pub"));

    let config = Config::load_default()?;

    if pkcs11 {
        println!("# sshenc PKCS#11 configuration for {label}");
        println!("Host {host}");
        println!("  PKCS11Provider /path/to/libsshenc_pkcs11.dylib");
        println!("  IdentitiesOnly yes");
        println!();
        println!("# Note: Update the PKCS11Provider path to the actual location");
        println!("# of the sshenc PKCS#11 library after building.");
    } else {
        println!("# sshenc agent configuration for {label}");
        println!("Host {host}");
        println!("  IdentityAgent {}", config.socket_path.display());
        println!("  IdentityFile {pub_path}");
        println!("  IdentitiesOnly yes");
        println!();
        println!("# Start the agent first:");
        println!("#   sshenc agent --socket {}", config.socket_path.display());
        println!("# Or:");
        println!("#   export SSH_AUTH_SOCK={}", config.socket_path.display());
    }

    Ok(())
}

pub fn ssh_wrapper(label: Option<&str>, ssh_args: &[String]) -> Result<()> {
    #[cfg(target_os = "macos")]
    use sshenc_ffi_apple::se;
    #[cfg(target_os = "windows")]
    use sshenc_ffi_windows::tpm as se;

    let config = Config::load_default()?;

    // Ensure agent is running
    if !agent_is_running(&config.socket_path) {
        let agent_bin = find_agent_binary()?;
        std::process::Command::new(&agent_bin)
            .arg("--socket")
            .arg(&config.socket_path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .ok();
        std::thread::sleep(std::time::Duration::from_millis(500));
        // Verify the agent is reachable; warn but don't fail — it may just be slow to start
        if !agent_is_running(&config.socket_path) {
            eprintln!("warning: agent may not be ready yet (socket not connectable)");
        }
    }

    let mut cmd = std::process::Command::new("ssh");
    cmd.arg("-o")
        .arg(format!("IdentityAgent {}", config.socket_path.display()));

    // If a label is specified, pin to that key only
    if let Some(label) = label {
        let ssh_pub = se::ssh_pub_path(label);
        if !ssh_pub.exists() {
            let pub_bytes = se::load_pub_key(label)
                .map_err(|e| anyhow::anyhow!("key '{label}' not found: {e}"))?;
            se::save_ssh_pub_key(label, &pub_bytes)?;
        }
        cmd.arg("-o")
            .arg(format!("IdentityFile {}", ssh_pub.display()))
            .arg("-o")
            .arg("IdentitiesOnly yes");
    }

    cmd.args(ssh_args);
    let status = cmd.status()?;
    std::process::exit(status.code().unwrap_or(1));
}
