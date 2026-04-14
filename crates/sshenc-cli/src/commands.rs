// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! CLI command implementations.

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use sshenc_core::key::{KeyGenOptions, KeyLabel};
use sshenc_core::pubkey::SshPublicKey;
use sshenc_core::Config;
use sshenc_se::{sshenc_keys_dir, KeyBackend, SshencBackend};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, PartialEq, Eq)]
enum AgentStartStatus {
    Started,
    AlreadyRunning,
}

trait AgentLauncher {
    fn is_running(&self, socket_path: &Path) -> bool;
    fn find_agent_binary(&self) -> Result<PathBuf>;
    fn spawn_agent(&self, agent_bin: &Path, socket_path: &Path) -> Result<()>;
}

#[derive(Debug, Default)]
struct RealAgentLauncher;

impl AgentLauncher for RealAgentLauncher {
    fn is_running(&self, socket_path: &Path) -> bool {
        agent_is_running(socket_path)
    }

    fn find_agent_binary(&self) -> Result<PathBuf> {
        find_agent_binary()
    }

    fn spawn_agent(&self, agent_bin: &Path, socket_path: &Path) -> Result<()> {
        std::process::Command::new(agent_bin)
            .arg("--socket")
            .arg(socket_path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map(|_| ())
            .map_err(Into::into)
    }
}

fn preflight_agent_start(
    launcher: &impl AgentLauncher,
    socket_path: &Path,
) -> Result<Option<PathBuf>> {
    if launcher.is_running(socket_path) {
        return Ok(None);
    }

    Ok(Some(launcher.find_agent_binary()?))
}

fn start_agent_with_binary(
    launcher: &impl AgentLauncher,
    socket_path: &Path,
    agent_bin: Option<&Path>,
) -> Result<AgentStartStatus> {
    match agent_bin {
        Some(agent_bin) => {
            launcher.spawn_agent(agent_bin, socket_path)?;
            Ok(AgentStartStatus::Started)
        }
        None => Ok(AgentStartStatus::AlreadyRunning),
    }
}

fn ensure_agent_running(
    launcher: &impl AgentLauncher,
    socket_path: &Path,
) -> Result<AgentStartStatus> {
    let agent_bin = preflight_agent_start(launcher, socket_path)?;
    start_agent_with_binary(launcher, socket_path, agent_bin.as_deref())
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum WindowsServiceStartMode {
    Auto,
    Demand,
    Disabled,
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
impl WindowsServiceStartMode {
    fn as_sc_value(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Demand => "demand",
            Self::Disabled => "disabled",
        }
    }
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct WindowsInstallState {
    previous_ssh_auth_sock: Option<String>,
    previous_git_ssh_command: Option<String>,
    ssh_agent_start_mode: Option<WindowsServiceStartMode>,
    ssh_agent_was_running: Option<bool>,
    managed_git_ssh_command: bool,
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
enum WindowsAction {
    StopService(&'static str),
    SetServiceStart {
        service: &'static str,
        mode: WindowsServiceStartMode,
    },
    StartService(&'static str),
    SetUserEnv {
        key: &'static str,
        value: String,
    },
    DeleteUserEnv(&'static str),
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn windows_action_description(action: &WindowsAction) -> String {
    match action {
        WindowsAction::StopService(service) => format!("stop Windows service '{service}'"),
        WindowsAction::SetServiceStart { service, mode } => {
            format!(
                "set Windows service '{service}' start mode to {}",
                mode.as_sc_value()
            )
        }
        WindowsAction::StartService(service) => format!("start Windows service '{service}'"),
        WindowsAction::SetUserEnv { key, .. } => format!("set Windows user environment '{key}'"),
        WindowsAction::DeleteUserEnv(key) => {
            format!("delete Windows user environment '{key}'")
        }
    }
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn windows_action_is_allowed_failure(action: &WindowsAction, output: &str) -> bool {
    let normalized = output.to_ascii_lowercase();
    match action {
        WindowsAction::StopService(_) => {
            normalized.contains("service has not been started")
                || normalized.contains("has not been started")
        }
        WindowsAction::StartService(_) => {
            normalized.contains("already been started") || normalized.contains("already running")
        }
        WindowsAction::DeleteUserEnv(_) => {
            normalized.contains("unable to find the specified registry key or value")
                || normalized.contains("cannot find the file specified")
        }
        WindowsAction::SetServiceStart { .. } | WindowsAction::SetUserEnv { .. } => false,
    }
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn validate_windows_action_result(
    action: &WindowsAction,
    success: bool,
    output: &str,
) -> Result<()> {
    if success || windows_action_is_allowed_failure(action, output) {
        return Ok(());
    }

    let details = if output.trim().is_empty() {
        "no command output available"
    } else {
        output.trim()
    };
    bail!(
        "failed to {}: {details}",
        windows_action_description(action)
    );
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn windows_prepare_install_actions() -> Vec<WindowsAction> {
    vec![
        WindowsAction::StopService("ssh-agent"),
        WindowsAction::SetServiceStart {
            service: "ssh-agent",
            mode: WindowsServiceStartMode::Disabled,
        },
    ]
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn windows_finalize_install_actions(
    socket_path: &Path,
    git_ssh_command: Option<String>,
) -> Vec<WindowsAction> {
    let mut actions = vec![WindowsAction::SetUserEnv {
        key: "SSH_AUTH_SOCK",
        value: socket_path.display().to_string().replace('\\', "/"),
    }];
    if let Some(git_ssh_command) = git_ssh_command {
        actions.push(WindowsAction::SetUserEnv {
            key: "GIT_SSH_COMMAND",
            value: git_ssh_command,
        });
    }
    actions
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn windows_restore_actions(state: &WindowsInstallState) -> Vec<WindowsAction> {
    let mut actions = Vec::new();

    match state.previous_ssh_auth_sock.as_ref() {
        Some(value) => actions.push(WindowsAction::SetUserEnv {
            key: "SSH_AUTH_SOCK",
            value: value.clone(),
        }),
        None => actions.push(WindowsAction::DeleteUserEnv("SSH_AUTH_SOCK")),
    }

    if state.managed_git_ssh_command {
        match state.previous_git_ssh_command.as_ref() {
            Some(value) => actions.push(WindowsAction::SetUserEnv {
                key: "GIT_SSH_COMMAND",
                value: value.clone(),
            }),
            None => actions.push(WindowsAction::DeleteUserEnv("GIT_SSH_COMMAND")),
        }
    }

    if let Some(mode) = state.ssh_agent_start_mode {
        actions.push(WindowsAction::SetServiceStart {
            service: "ssh-agent",
            mode,
        });
    }

    if state.ssh_agent_was_running == Some(true) {
        actions.push(WindowsAction::StartService("ssh-agent"));
    }

    actions
}

#[cfg(target_os = "windows")]
fn apply_windows_actions(actions: &[WindowsAction]) -> Result<()> {
    fn command_output(program: &str, args: &[&str]) -> Result<std::process::Output> {
        Ok(std::process::Command::new(program).args(args).output()?)
    }

    fn output_text(output: &std::process::Output) -> String {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        format!("{stdout}\n{stderr}")
    }

    for action in actions {
        match action {
            WindowsAction::StopService(service) => {
                let output = command_output("sc", &["stop", service])?;
                validate_windows_action_result(
                    action,
                    output.status.success(),
                    &output_text(&output),
                )?;
            }
            WindowsAction::SetServiceStart { service, mode } => {
                let output =
                    command_output("sc", &["config", service, "start=", mode.as_sc_value()])?;
                validate_windows_action_result(
                    action,
                    output.status.success(),
                    &output_text(&output),
                )?;
            }
            WindowsAction::StartService(service) => {
                let output = command_output("sc", &["start", service])?;
                validate_windows_action_result(
                    action,
                    output.status.success(),
                    &output_text(&output),
                )?;
            }
            WindowsAction::SetUserEnv { key, value } => {
                let output = command_output("setx", &[key, value.as_str()])?;
                validate_windows_action_result(
                    action,
                    output.status.success(),
                    &output_text(&output),
                )?;
            }
            WindowsAction::DeleteUserEnv(key) => {
                let output =
                    command_output("reg", &["delete", "HKCU\\Environment", "/v", key, "/f"])?;
                validate_windows_action_result(
                    action,
                    output.status.success(),
                    &output_text(&output),
                )?;
            }
        }
    }

    Ok(())
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn windows_install_state_path() -> Result<PathBuf> {
    let config_path = Config::default_path();
    let parent = config_path
        .parent()
        .ok_or_else(|| anyhow!("could not determine sshenc config directory"))?;
    Ok(parent.join("install-state.json"))
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn parse_sc_start_mode(text: &str) -> Option<WindowsServiceStartMode> {
    text.lines().find_map(|line| {
        let normalized = line.trim();
        if !normalized.contains("START_TYPE") {
            return None;
        }
        if normalized.contains("AUTO_START") {
            Some(WindowsServiceStartMode::Auto)
        } else if normalized.contains("DEMAND_START") {
            Some(WindowsServiceStartMode::Demand)
        } else if normalized.contains("DISABLED") {
            Some(WindowsServiceStartMode::Disabled)
        } else {
            None
        }
    })
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn parse_sc_running_state(text: &str) -> Option<bool> {
    text.lines().find_map(|line| {
        let normalized = line.trim();
        if !normalized.contains("STATE") {
            return None;
        }
        if normalized.contains("RUNNING") {
            Some(true)
        } else if normalized.contains("STOPPED") {
            Some(false)
        } else {
            None
        }
    })
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn parse_reg_query_value(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let trimmed = line.trim();
        ["REG_SZ", "REG_EXPAND_SZ", "REG_MULTI_SZ"]
            .into_iter()
            .find_map(|kind| {
                trimmed
                    .split_once(kind)
                    .map(|(_, value)| value.trim().to_string())
            })
    })
}

#[cfg(target_os = "windows")]
fn query_windows_user_env_var(key: &str) -> Result<Option<String>> {
    let output = std::process::Command::new("reg")
        .args(["query", "HKCU\\Environment", "/v", key])
        .output()?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(parse_reg_query_value(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

#[cfg(target_os = "windows")]
fn query_windows_service_start_mode(service: &str) -> Result<Option<WindowsServiceStartMode>> {
    let output = std::process::Command::new("sc")
        .args(["qc", service])
        .output()?;
    if !output.status.success() {
        bail!("failed to query Windows service configuration for {service}");
    }
    Ok(parse_sc_start_mode(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

#[cfg(target_os = "windows")]
fn query_windows_service_running(service: &str) -> Result<Option<bool>> {
    let output = std::process::Command::new("sc")
        .args(["query", service])
        .output()?;
    if !output.status.success() {
        bail!("failed to query Windows service state for {service}");
    }
    Ok(parse_sc_running_state(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

#[cfg(target_os = "windows")]
fn save_windows_install_state(state: &WindowsInstallState) -> Result<()> {
    let path = windows_install_state_path()?;
    let contents = serde_json::to_vec_pretty(state)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    enclaveapp_core::metadata::atomic_write(&path, &contents).map_err(|e| anyhow!(e.to_string()))
}

#[cfg(target_os = "windows")]
fn load_windows_install_state() -> Result<Option<WindowsInstallState>> {
    let path = windows_install_state_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let contents = std::fs::read(&path)?;
    Ok(Some(serde_json::from_slice(&contents)?))
}

#[cfg(target_os = "windows")]
fn remove_windows_install_state() -> Result<()> {
    let path = windows_install_state_path()?;
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn capture_windows_install_state(managed_git_ssh_command: bool) -> Result<WindowsInstallState> {
    Ok(WindowsInstallState {
        previous_ssh_auth_sock: query_windows_user_env_var("SSH_AUTH_SOCK")?,
        previous_git_ssh_command: query_windows_user_env_var("GIT_SSH_COMMAND")?,
        ssh_agent_start_mode: query_windows_service_start_mode("ssh-agent")?,
        ssh_agent_was_running: query_windows_service_running("ssh-agent")?,
        managed_git_ssh_command,
    })
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn restore_windows_state_with(
    state: &WindowsInstallState,
    apply_actions: impl FnOnce(&[WindowsAction]) -> Result<()>,
    remove_state: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let actions = windows_restore_actions(state);
    apply_actions(&actions)?;
    remove_state()?;
    Ok(())
}

#[allow(clippy::print_stdout)]
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

#[allow(clippy::print_stdout)]
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

#[allow(clippy::print_stdout)]
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

#[allow(clippy::print_stdout)]
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

#[allow(clippy::print_stdout)]
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

#[allow(clippy::print_stdout)]
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
    drop(
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new(level))
            .try_init(),
    );

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
        #[cfg(unix)]
        let server = sshenc_agent::server::run_agent(socket_path, allowed_labels);
        #[cfg(windows)]
        let server =
            sshenc_agent::server::run_agent(socket_path.display().to_string(), allowed_labels);
        server.await
    })?;

    Ok(())
}

#[allow(clippy::print_stdout)]
pub fn config_init() -> Result<()> {
    let path = Config::init()?;
    println!("Config file created: {}", path.display());
    Ok(())
}

#[allow(clippy::print_stdout)]
pub fn config_path() -> Result<()> {
    println!("{}", Config::default_path().display());
    Ok(())
}

#[allow(clippy::print_stdout)]
pub fn config_show() -> Result<()> {
    let config = Config::load_default()?;
    println!("{}", toml::to_string_pretty(&config)?);
    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_git_ssh_command() -> Option<String> {
    let win_ssh = r"C:\Windows\System32\OpenSSH\ssh.exe";
    Path::new(win_ssh)
        .exists()
        .then(|| win_ssh.replace('\\', "/"))
}

#[allow(clippy::print_stdout, clippy::print_stderr, unused_qualifications)]
pub fn install() -> Result<()> {
    let config = Config::load_default()?;
    let ssh_config_path = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("could not determine home directory"))?
        .join(".ssh")
        .join("config");
    let agent_bin = preflight_agent_start(&RealAgentLauncher, &config.socket_path)?;

    // Find the launcher dylib if available.
    // On Windows, skip PKCS#11 — the agent listens on the default OpenSSH pipe
    // so auto-launching via PKCS#11 is unnecessary, and the stub PKCS#11 module
    // crashes some OpenSSH builds during key exchange.
    #[cfg(target_os = "windows")]
    let dylib_path: Option<PathBuf> = None;
    #[cfg(not(target_os = "windows"))]
    let dylib_path = find_launcher_dylib();
    #[cfg(target_os = "windows")]
    let git_ssh_command = windows_git_ssh_command();

    let install_result = sshenc_core::ssh_config::install_block(
        &ssh_config_path,
        &config.socket_path,
        dylib_path.as_deref(),
    )?;

    #[cfg(target_os = "windows")]
    let install_state = match capture_windows_install_state(git_ssh_command.is_some()).and_then(
        |state| {
            save_windows_install_state(&state)?;
            Ok(state)
        },
    ) {
        Ok(state) => {
            if let Err(error) = apply_windows_actions(&windows_prepare_install_actions()) {
                if matches!(
                    install_result,
                    sshenc_core::ssh_config::InstallResult::Installed
                ) {
                    let _unused = sshenc_core::ssh_config::uninstall_block(&ssh_config_path);
                }
                let rollback_result = restore_windows_state_with(
                    &state,
                    apply_windows_actions,
                    remove_windows_install_state,
                );
                return match rollback_result {
                    Ok(()) => Err(error),
                    Err(rollback_error) => Err(anyhow!(
                        "{error}; additionally failed to restore previous Windows state: {rollback_error}"
                    )),
                };
            }
            println!("Configured Windows ssh-agent service for sshenc.");
            Some(state)
        }
        Err(error) => {
            if matches!(
                install_result,
                sshenc_core::ssh_config::InstallResult::Installed
            ) {
                let _unused = sshenc_core::ssh_config::uninstall_block(&ssh_config_path);
            }
            return Err(error);
        }
    };

    let agent_status = match start_agent_with_binary(
        &RealAgentLauncher,
        &config.socket_path,
        agent_bin.as_deref(),
    ) {
        Ok(status) => status,
        Err(error) => {
            if matches!(
                install_result,
                sshenc_core::ssh_config::InstallResult::Installed
            ) {
                let _unused = sshenc_core::ssh_config::uninstall_block(&ssh_config_path);
            }

            #[cfg(target_os = "windows")]
            {
                if let Some(ref state) = install_state {
                    let rollback_result = restore_windows_state_with(
                        state,
                        apply_windows_actions,
                        remove_windows_install_state,
                    );
                    return match rollback_result {
                        Ok(()) => Err(error),
                        Err(rollback_error) => Err(anyhow!(
                            "{error}; additionally failed to restore previous Windows state: {rollback_error}"
                        )),
                    };
                }
            }

            return Err(error);
        }
    };

    match install_result {
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

    match agent_status {
        AgentStartStatus::Started => println!("Started sshenc agent."),
        AgentStartStatus::AlreadyRunning => println!("Agent already running."),
    }

    #[cfg(target_os = "windows")]
    {
        if let Err(error) = apply_windows_actions(&windows_finalize_install_actions(
            &config.socket_path,
            git_ssh_command.clone(),
        )) {
            if matches!(
                install_result,
                sshenc_core::ssh_config::InstallResult::Installed
            ) {
                let _unused = sshenc_core::ssh_config::uninstall_block(&ssh_config_path);
            }
            if let Some(ref state) = install_state {
                let rollback_result = restore_windows_state_with(
                    state,
                    apply_windows_actions,
                    remove_windows_install_state,
                );
                return match rollback_result {
                    Ok(()) => Err(error),
                    Err(rollback_error) => Err(anyhow!(
                        "{error}; additionally failed to restore previous Windows state: {rollback_error}"
                    )),
                };
            }
            return Err(error);
        }
        println!(
            "Set SSH_AUTH_SOCK={}",
            config.socket_path.display().to_string().replace('\\', "/")
        );
        if let Some(git_ssh_command) = git_ssh_command {
            println!("Set GIT_SSH_COMMAND={git_ssh_command}");
        }
    }

    // On Windows, configure WSL distros if any are installed
    #[cfg(target_os = "windows")]
    {
        crate::wsl::configure_wsl_distros();
    }

    println!();
    println!("SSH will now use sshenc for all connections.");
    println!("Your existing ~/.ssh keys continue to work as fallback.");
    Ok(())
}

/// Find the PKCS#11 launcher library, if installed.
#[cfg(not(target_os = "windows"))]
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

#[allow(clippy::print_stdout)]
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

    #[cfg(target_os = "windows")]
    {
        if let Some(state) = load_windows_install_state()? {
            restore_windows_state_with(
                &state,
                apply_windows_actions,
                remove_windows_install_state,
            )?;
            println!("Restored the previous Windows SSH environment and ssh-agent service state.");
        } else {
            println!(
                "No saved Windows integration state found; left SSH_AUTH_SOCK, GIT_SSH_COMMAND, and ssh-agent service unchanged."
            );
        }

        // Clean up WSL distros
        crate::wsl::unconfigure_wsl_distros();
    }

    Ok(())
}

#[allow(clippy::print_stdout)]
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

#[derive(Debug)]
struct SshInvocation {
    ssh_bin: String,
    args: Vec<String>,
    temp_identity_file: Option<PathBuf>,
}

fn default_ssh_dir() -> Result<PathBuf> {
    dirs::home_dir()
        .ok_or_else(|| anyhow!("could not determine home directory"))
        .map(|home| home.join(".ssh"))
}

fn ssh_binary() -> String {
    #[cfg(target_os = "windows")]
    {
        let win_ssh = r"C:\Windows\System32\OpenSSH\ssh.exe";
        if Path::new(win_ssh).exists() {
            return win_ssh.to_string();
        }
    }
    "ssh".to_string()
}

fn write_atomic_file(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    enclaveapp_core::metadata::atomic_write(path, data).map_err(|e| anyhow!(e.to_string()))
}

fn unique_temp_identity_path(identity_dir: &Path, label: &str) -> PathBuf {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    identity_dir.join(format!("{label}-{pid}-{nanos}.pub"))
}

fn build_ssh_wrapper_invocation(
    backend: &dyn KeyBackend,
    socket_path: &Path,
    label: Option<&str>,
    ssh_args: &[String],
    identity_dir: &Path,
) -> Result<SshInvocation> {
    let mut args = Vec::new();
    let agent_path = socket_path.display().to_string();
    #[cfg(target_os = "windows")]
    let agent_path = agent_path.replace('\\', "/");
    args.push("-o".to_string());
    args.push(format!("IdentityAgent {agent_path}"));

    let mut temp_identity_file = None;
    if let Some(label) = label {
        let info = backend.get(label)?;
        let ssh_pubkey =
            SshPublicKey::from_sec1_bytes(&info.public_key_bytes, info.metadata.comment.clone())?;
        let identity_path = unique_temp_identity_path(identity_dir, label);
        let line = format!("{}\n", ssh_pubkey.to_openssh_line());
        write_atomic_file(&identity_path, line.as_bytes())?;
        args.push("-o".to_string());
        args.push(format!("IdentityFile {}", identity_path.display()));
        args.push("-o".to_string());
        args.push("IdentitiesOnly yes".to_string());
        temp_identity_file = Some(identity_path);
    }

    args.extend(ssh_args.iter().cloned());

    Ok(SshInvocation {
        ssh_bin: ssh_binary(),
        args,
        temp_identity_file,
    })
}

#[allow(clippy::exit, clippy::print_stderr)]
pub fn ssh_wrapper(label: Option<&str>, ssh_args: &[String]) -> Result<()> {
    let config = Config::load_default()?;

    if ensure_agent_running(&RealAgentLauncher, &config.socket_path)? == AgentStartStatus::Started {
        std::thread::sleep(std::time::Duration::from_millis(500));
        if !agent_is_running(&config.socket_path) {
            eprintln!("warning: agent may not be ready yet (socket not connectable)");
        }
    }

    let ssh_dir = default_ssh_dir()?;
    let backend = SshencBackend::new(ssh_dir.clone())
        .map_err(|e| anyhow!("failed to initialize sshenc backend: {e}"))?;
    let invocation =
        build_ssh_wrapper_invocation(&backend, &config.socket_path, label, ssh_args, &ssh_dir)?;

    let status = std::process::Command::new(&invocation.ssh_bin)
        .args(&invocation.args)
        .status();
    if let Some(path) = invocation.temp_identity_file.as_ref() {
        drop(std::fs::remove_file(path));
    }
    let status = status?;
    std::process::exit(status.code().unwrap_or(1));
}

#[cfg(not(target_os = "windows"))]
#[derive(Debug)]
struct PromoteDefaultResult {
    fingerprint: String,
    public_key_path: PathBuf,
    backup_label: Option<String>,
    removed_old_pub: Option<PathBuf>,
}

#[cfg(not(target_os = "windows"))]
fn unique_backup_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("backup");
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    path.with_file_name(format!("{file_name}.{pid}.{nanos}.bak"))
}

#[cfg(not(target_os = "windows"))]
fn load_label_public_key(keys_dir: &Path, label: &str) -> Result<SshPublicKey> {
    let pub_bytes = enclaveapp_core::metadata::load_pub_key(keys_dir, label)
        .map_err(|_| anyhow!("key '{label}' not found"))?;
    let meta = sshenc_se::compat::load_sshenc_meta(keys_dir, label)
        .map_err(|e| anyhow!("failed to load metadata for '{label}': {e}"))?;
    let comment = meta.get_app_field("comment").map(str::to_owned);
    SshPublicKey::from_sec1_bytes(&pub_bytes, comment).map_err(Into::into)
}

#[cfg(not(target_os = "windows"))]
fn restore_backup(original: &Path, backup: &Path) {
    if backup.exists() {
        if original.exists() {
            drop(std::fs::remove_file(original));
        }
        drop(std::fs::rename(backup, original));
    }
}

#[cfg(not(target_os = "windows"))]
fn key_files_exist(keys_dir: &Path, label: &str) -> bool {
    ["meta", "pub", "handle", "ssh.pub"]
        .into_iter()
        .any(|ext| keys_dir.join(format!("{label}.{ext}")).exists())
}

#[cfg(not(target_os = "windows"))]
fn promote_to_default_with_dirs<F>(
    keys_dir: &Path,
    ssh_dir: &Path,
    label: &str,
    allow_pub_overwrite: bool,
    write_file: F,
) -> Result<Option<PromoteDefaultResult>>
where
    F: Fn(&Path, &[u8]) -> Result<()> + Copy,
{
    use enclaveapp_core::metadata;

    if label == "default" {
        bail!("key is already named 'default'");
    }

    let source_pubkey = load_label_public_key(keys_dir, label)?;
    let id_ecdsa_pub = ssh_dir.join("id_ecdsa.pub");
    let id_ecdsa_priv = ssh_dir.join("id_ecdsa");
    let old_pub = ssh_dir.join(format!("{label}.pub"));

    if id_ecdsa_pub.exists() && !id_ecdsa_priv.exists() && !allow_pub_overwrite {
        return Ok(None);
    }

    std::fs::create_dir_all(ssh_dir)?;

    let mut private_backup = None;
    let mut public_backup = None;
    let mut backup_label = None;
    let mut source_renamed = false;

    let result = (|| -> Result<PromoteDefaultResult> {
        if id_ecdsa_priv.exists() {
            let backup = unique_backup_path(&id_ecdsa_priv);
            std::fs::rename(&id_ecdsa_priv, &backup)?;
            private_backup = Some(backup);
        }
        if id_ecdsa_pub.exists() {
            let backup = unique_backup_path(&id_ecdsa_pub);
            std::fs::rename(&id_ecdsa_pub, &backup)?;
            public_backup = Some(backup);
        }

        if key_files_exist(keys_dir, "default") {
            let renamed_default = format!("default-backup-{}", std::process::id());
            metadata::rename_key_files(keys_dir, "default", &renamed_default)
                .map_err(|e| anyhow!("failed to rename default key: {e}"))?;
            backup_label = Some(renamed_default);
        }

        metadata::rename_key_files(keys_dir, label, "default")
            .map_err(|e| anyhow!("failed to rename key: {e}"))?;
        source_renamed = true;

        let ssh_pubkey = load_label_public_key(keys_dir, "default")
            .map_err(|e| anyhow!("failed to load renamed key: {e}"))?;
        let pub_line = format!("{}\n", ssh_pubkey.to_openssh_line());
        write_file(&id_ecdsa_pub, pub_line.as_bytes())?;

        let removed_old_pub = if old_pub.exists() {
            std::fs::remove_file(&old_pub)?;
            Some(old_pub)
        } else {
            None
        };

        Ok(PromoteDefaultResult {
            fingerprint: sshenc_core::fingerprint::fingerprint_sha256(&source_pubkey),
            public_key_path: id_ecdsa_pub.clone(),
            backup_label: backup_label.clone(),
            removed_old_pub,
        })
    })();

    match result {
        Ok(promotion) => {
            if let Some(backup) = public_backup {
                drop(std::fs::remove_file(backup));
            }
            if let Some(backup) = private_backup {
                drop(std::fs::remove_file(backup));
            }
            Ok(Some(promotion))
        }
        Err(error) => {
            if source_renamed && key_files_exist(keys_dir, "default") {
                drop(metadata::rename_key_files(keys_dir, "default", label));
            }
            if let Some(ref backup_label) = backup_label {
                if key_files_exist(keys_dir, backup_label) {
                    drop(metadata::rename_key_files(
                        keys_dir,
                        backup_label,
                        "default",
                    ));
                }
            }
            if let Some(ref backup) = public_backup {
                restore_backup(&id_ecdsa_pub, backup);
            }
            if let Some(ref backup) = private_backup {
                restore_backup(&id_ecdsa_priv, backup);
            }
            Err(error)
        }
    }
}

#[allow(clippy::print_stdout, clippy::print_stderr)]
pub fn promote_to_default(label: &str) -> Result<()> {
    // On Windows, CNG key names are immutable — create keys with the right name from the start.
    #[cfg(target_os = "windows")]
    {
        let _ = label;
        bail!("'sshenc default' is not yet supported on Windows. Create your default key with: sshenc keygen");
    }

    #[cfg(not(target_os = "windows"))]
    {
        let keys_dir = sshenc_keys_dir();
        let ssh_dir = default_ssh_dir()?;
        let promotion = if let Some(promotion) =
            promote_to_default_with_dirs(&keys_dir, &ssh_dir, label, false, write_atomic_file)?
        {
            promotion
        } else {
            let id_ecdsa_pub = ssh_dir.join("id_ecdsa.pub");
            eprintln!("{} already exists.", id_ecdsa_pub.display());
            eprint!("Overwrite (y/n)? ");
            Write::flush(&mut io::stderr()).ok();
            let mut input = String::new();
            io::stdin().read_line(&mut input).ok();
            if !input.trim().eq_ignore_ascii_case("y") {
                println!("Cancelled.");
                return Ok(());
            }
            promote_to_default_with_dirs(&keys_dir, &ssh_dir, label, true, write_atomic_file)?
                .ok_or_else(|| anyhow!("default-key promotion confirmation was not applied"))?
        };

        println!("Promoted '{label}' to default key.");
        println!("  Public key: {}", promotion.public_key_path.display());
        println!("  Fingerprint: {}", promotion.fingerprint);
        if let Some(ref backup_label) = promotion.backup_label {
            println!("  Previous default key backed up as: {backup_label}");
        }
        if let Some(ref old_pub) = promotion.removed_old_pub {
            println!("Removed {}", old_pub.display());
        }
        println!();
        println!("The agent will now present this key first for all connections.");
        println!("Restart the agent for the change to take effect:");
        println!("  pkill sshenc-agent && sshenc install");

        Ok(())
    } // end #[cfg(not(target_os = "windows"))]
}

#[allow(clippy::print_stdout)]
pub fn set_identity(label: &str, name: &str, email: &str) -> Result<()> {
    use enclaveapp_core::metadata;

    let keys_dir = sshenc_keys_dir();

    let mut meta = sshenc_se::compat::load_sshenc_meta(&keys_dir, label)
        .map_err(|e| anyhow::anyhow!("failed to load metadata for '{label}': {e}"))?;
    meta.set_app_field("git_name", name.to_string());
    meta.set_app_field("git_email", email.to_string());

    // Write updated metadata
    metadata::save_meta(&keys_dir, label, &meta)
        .map_err(|e| anyhow::anyhow!("failed to save metadata for '{label}': {e}"))?;

    println!("Set identity for key '{label}':");
    println!("  Name:  {name}");
    println!("  Email: {email}");
    Ok(())
}

/// Forward unhandled -Y subcommands to real ssh-keygen.
#[allow(clippy::exit)]
pub fn forward_to_ssh_keygen(args: &[String]) -> Result<()> {
    let status = std::process::Command::new("ssh-keygen")
        .args(args)
        .status()?;
    std::process::exit(status.code().unwrap_or(1));
}

#[derive(Debug, PartialEq, Eq)]
struct SshSignArgs {
    namespace: String,
    label: String,
    data_file: PathBuf,
}

fn label_from_key_path(key_path: &Path) -> String {
    let label = if key_path.file_name().map(|f| f.to_string_lossy()) == Some("id_ecdsa.pub".into())
    {
        "default".to_string()
    } else {
        key_path
            .file_stem()
            .map(|stem| stem.to_string_lossy().to_string())
            .unwrap_or_else(|| "default".to_string())
    };

    label.strip_suffix(".ssh").unwrap_or(&label).to_string()
}

fn parse_ssh_sign_args(args: &[String]) -> Result<SshSignArgs> {
    let mut namespace = "git".to_string();
    let mut key_file = None;
    let mut data_file = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-Y" => {
                i += 1;
            }
            "-n" => {
                i += 1;
                if i < args.len() {
                    namespace = args[i].clone();
                }
            }
            "-f" => {
                i += 1;
                if i < args.len() {
                    key_file = Some(PathBuf::from(&args[i]));
                }
            }
            other if !other.starts_with('-') && key_file.is_some() => {
                data_file = Some(PathBuf::from(other));
            }
            _ => {}
        }
        i += 1;
    }

    let key_file = key_file.ok_or_else(|| anyhow!("missing -f <key_file>"))?;
    let data_file = data_file.ok_or_else(|| anyhow!("missing data file argument"))?;

    Ok(SshSignArgs {
        namespace,
        label: label_from_key_path(&key_file),
        data_file,
    })
}

fn ssh_sign_with_backend(backend: &dyn KeyBackend, args: &[String]) -> Result<()> {
    let sign_args = parse_ssh_sign_args(args)?;

    let file_data = std::fs::read(&sign_args.data_file)?;
    let message_hash = {
        use sha2::{Digest, Sha256};
        Sha256::digest(&file_data)
    };
    let signed_data = {
        use sshenc_core::pubkey::write_ssh_string;
        let mut buf = Vec::new();
        buf.extend_from_slice(b"SSHSIG");
        write_ssh_string(&mut buf, sign_args.namespace.as_bytes());
        write_ssh_string(&mut buf, b"");
        write_ssh_string(&mut buf, b"sha256");
        write_ssh_string(&mut buf, &message_hash);
        buf
    };

    let der_sig = backend
        .sign(&sign_args.label, &signed_data)
        .map_err(|e| anyhow!("signing failed: {e}"))?;
    let info = backend.get(&sign_args.label)?;
    let ssh_pubkey =
        SshPublicKey::from_sec1_bytes(&info.public_key_bytes, info.metadata.comment.clone())?;
    let sig_blob = build_ssh_signature(&ssh_pubkey, &sign_args.namespace, &der_sig)?;

    let sig_path = sign_args.data_file.with_extension(format!(
        "{}.sig",
        sign_args
            .data_file
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or_default()
    ));
    let sig_path = if sign_args.data_file.extension().is_some() {
        sig_path
    } else {
        PathBuf::from(format!("{}.sig", sign_args.data_file.display()))
    };
    let pem = format!(
        "-----BEGIN SSH SIGNATURE-----\n{}\n-----END SSH SIGNATURE-----\n",
        base64_wrap(&sig_blob, 70)
    );
    write_atomic_file(&sig_path, pem.as_bytes())?;
    Ok(())
}

/// Handle ssh-keygen-compatible signing mode.
/// Git calls: sshenc -Y sign -n <namespace> -f <pubkey_path> <data_file>
/// We sign via the hardware backend and write an SSH signature to <data_file>.sig.
pub fn ssh_sign(args: &[String]) -> Result<()> {
    let ssh_dir = default_ssh_dir()?;
    let backend = SshencBackend::new(ssh_dir)
        .map_err(|e| anyhow!("failed to initialize sshenc backend: {e}"))?;
    ssh_sign_with_backend(&backend, args)
}

/// Build an SSH signature blob per the SSH signature format spec.
fn build_ssh_signature(pubkey: &SshPublicKey, namespace: &str, der_sig: &[u8]) -> Result<Vec<u8>> {
    use sshenc_core::pubkey::write_ssh_string;

    let mut buf = Vec::new();

    // Magic preamble
    buf.extend_from_slice(b"SSHSIG");

    // Version (uint32)
    buf.extend_from_slice(&1_u32.to_be_bytes());

    // Public key blob
    let pubkey_blob = pubkey.wire_blob();
    write_ssh_string(&mut buf, &pubkey_blob);

    // Namespace
    write_ssh_string(&mut buf, namespace.as_bytes());

    // Reserved (empty string)
    write_ssh_string(&mut buf, b"");

    // Hash algorithm
    write_ssh_string(&mut buf, b"sha256");

    // Signature: string(algo) || string(sig_data)
    // Convert DER to SSH signature format
    let ssh_sig = sshenc_agent_proto::signature::der_to_ssh_signature(der_sig)?;
    write_ssh_string(&mut buf, &ssh_sig);

    Ok(buf)
}

/// Base64-encode with line wrapping.
fn base64_wrap(data: &[u8], width: usize) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let encoded = STANDARD.encode(data);
    encoded
        .as_bytes()
        .chunks(width)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use enclaveapp_core::{AccessPolicy, KeyType};
    use sshenc_test_support::MockKeyBackend;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn mock_backend() -> MockKeyBackend {
        MockKeyBackend::new()
    }

    /// Create a unique temporary directory for a test.
    fn test_dir(prefix: &str) -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("sshenc-cli-test-{prefix}-{pid}-{id}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Helper: generate a key in the mock backend and return the backend.
    fn backend_with_key(label: &str, comment: Option<String>) -> MockKeyBackend {
        let backend = mock_backend();
        let opts = KeyGenOptions {
            label: KeyLabel::new(label).unwrap(),
            comment,
            requires_user_presence: false,
            write_pub_path: None,
        };
        backend.generate(&opts).unwrap();
        backend
    }

    #[derive(Debug)]
    struct FakeLauncher {
        running: bool,
        find_result: Result<PathBuf>,
        spawn_result: Result<()>,
        find_count: Mutex<usize>,
        spawn_count: Mutex<usize>,
    }

    impl AgentLauncher for FakeLauncher {
        fn is_running(&self, _socket_path: &Path) -> bool {
            self.running
        }

        fn find_agent_binary(&self) -> Result<PathBuf> {
            *self
                .find_count
                .lock()
                .map_err(|_| anyhow!("find_count mutex poisoned"))? += 1;
            self.find_result
                .as_ref()
                .cloned()
                .map_err(|error| anyhow!(error.to_string()))
        }

        fn spawn_agent(&self, _agent_bin: &Path, _socket_path: &Path) -> Result<()> {
            *self
                .spawn_count
                .lock()
                .map_err(|_| anyhow!("spawn_count mutex poisoned"))? += 1;
            self.spawn_result
                .as_ref()
                .map(|_| ())
                .map_err(|error| anyhow!(error.to_string()))
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn seed_promote_key(keys_dir: &Path, label: &str, comment: Option<&str>) {
        let backend = backend_with_key(label, comment.map(str::to_owned));
        let info = backend.get(label).unwrap();
        enclaveapp_core::metadata::ensure_dir(keys_dir).unwrap();
        enclaveapp_core::metadata::save_pub_key(keys_dir, label, &info.public_key_bytes).unwrap();

        let mut meta =
            enclaveapp_core::metadata::KeyMeta::new(label, KeyType::Signing, AccessPolicy::None);
        if let Some(comment) = comment {
            meta.set_app_field("comment", comment);
        }
        enclaveapp_core::metadata::save_meta(keys_dir, label, &meta).unwrap();
    }

    // -----------------------------------------------------------------------
    // keygen tests
    // -----------------------------------------------------------------------

    #[test]
    fn keygen_creates_key() {
        let backend = mock_backend();
        let result = keygen(
            &backend,
            "test-key",
            Some("comment".into()),
            None,
            false,
            false,
            false,
        );
        assert!(result.is_ok());
        let keys = backend.list().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].metadata.label.as_str(), "test-key");
    }

    #[test]
    fn keygen_with_comment() {
        let backend = mock_backend();
        keygen(
            &backend,
            "commented",
            Some("user@host".into()),
            None,
            false,
            false,
            false,
        )
        .unwrap();
        let info = backend.get("commented").unwrap();
        assert_eq!(info.metadata.comment.as_deref(), Some("user@host"));
    }

    #[test]
    fn keygen_with_write_pub_path_creates_file() {
        let dir = test_dir("keygen-pub");
        let pub_path = dir.join("my-key.pub");
        let backend = mock_backend();
        keygen(
            &backend,
            "pub-key",
            Some("test@host".into()),
            Some(pub_path.clone()),
            false,
            false,
            false,
        )
        .unwrap();

        assert!(pub_path.exists(), "pub file should exist");
        let contents = std::fs::read_to_string(&pub_path).unwrap();
        assert!(contents.contains("ecdsa-sha2-nistp256"));
        assert!(contents.contains("test@host"));

        // Cleanup
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn keygen_without_write_pub_path_no_file() {
        let backend = mock_backend();
        keygen(&backend, "no-pub", None, None, false, false, false).unwrap();
        let info = backend.get("no-pub").unwrap();
        assert!(info.pub_file_path.is_none());
    }

    #[test]
    fn keygen_duplicate_label_returns_error() {
        let backend = mock_backend();
        keygen(&backend, "dup-key", None, None, false, false, false).unwrap();
        let result = keygen(&backend, "dup-key", None, None, false, false, false);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("duplicate") || err_msg.contains("dup-key"),
            "error: {err_msg}"
        );
    }

    #[test]
    fn keygen_with_user_presence() {
        let backend = mock_backend();
        keygen(&backend, "up-key", None, None, false, true, false).unwrap();
        let info = backend.get("up-key").unwrap();
        assert!(info.metadata.requires_user_presence);
    }

    #[test]
    fn keygen_json_output_succeeds() {
        let backend = mock_backend();
        // Just verify it doesn't error; stdout capture is out of scope.
        let result = keygen(
            &backend,
            "json-key",
            Some("c".into()),
            None,
            false,
            false,
            true,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn keygen_print_pub_succeeds() {
        let backend = mock_backend();
        let result = keygen(
            &backend,
            "print-pub-key",
            Some("c".into()),
            None,
            true,
            false,
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn keygen_invalid_label_returns_error() {
        let backend = mock_backend();
        let result = keygen(&backend, "bad label!", None, None, false, false, false);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // list tests
    // -----------------------------------------------------------------------

    #[test]
    fn list_empty_backend() {
        let backend = mock_backend();
        let result = list(&backend, false);
        assert!(result.is_ok());
    }

    #[test]
    fn list_after_generating_keys() {
        let backend = mock_backend();
        keygen(&backend, "key-a", None, None, false, false, false).unwrap();
        keygen(&backend, "key-b", None, None, false, false, false).unwrap();
        let result = list(&backend, false);
        assert!(result.is_ok());
        // Verify keys actually exist
        let keys = backend.list().unwrap();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn list_json_empty() {
        let backend = mock_backend();
        let result = list(&backend, true);
        assert!(result.is_ok());
    }

    #[test]
    fn list_json_with_keys() {
        let backend = mock_backend();
        keygen(&backend, "jk-1", None, None, false, false, false).unwrap();
        keygen(
            &backend,
            "jk-2",
            Some("comment".into()),
            None,
            false,
            false,
            false,
        )
        .unwrap();
        let result = list(&backend, true);
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // inspect tests
    // -----------------------------------------------------------------------

    #[test]
    fn inspect_existing_key() {
        let backend = backend_with_key("ins-key", Some("test@host".into()));
        let result = inspect(&backend, "ins-key", false, false);
        assert!(result.is_ok());
    }

    #[test]
    fn inspect_nonexistent_key() {
        let backend = mock_backend();
        let result = inspect(&backend, "no-such-key", false, false);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("no-such-key") || err_msg.contains("not found"),
            "error: {err_msg}"
        );
    }

    #[test]
    fn inspect_json() {
        let backend = backend_with_key("ins-json", None);
        let result = inspect(&backend, "ins-json", true, false);
        assert!(result.is_ok());
    }

    #[test]
    fn inspect_show_pub() {
        let backend = backend_with_key("ins-pub", Some("c@h".into()));
        let result = inspect(&backend, "ins-pub", false, true);
        assert!(result.is_ok());
    }

    #[test]
    fn inspect_json_and_show_pub() {
        // When json=true, show_pub is ignored (json branch returns early)
        let backend = backend_with_key("ins-both", None);
        let result = inspect(&backend, "ins-both", true, true);
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // delete tests
    // -----------------------------------------------------------------------

    #[test]
    fn delete_existing_key_with_yes() {
        let backend = backend_with_key("del-key", None);
        assert_eq!(backend.key_count(), 1);
        let labels = vec!["del-key".to_string()];
        let result = delete(&backend, &labels, false, true);
        assert!(result.is_ok());
        assert_eq!(backend.key_count(), 0);
    }

    #[test]
    fn delete_nonexistent_key() {
        let backend = mock_backend();
        let labels = vec!["ghost".to_string()];
        let result = delete(&backend, &labels, false, true);
        assert!(result.is_err());
    }

    #[test]
    fn delete_empty_labels() {
        let backend = mock_backend();
        let labels: Vec<String> = vec![];
        let result = delete(&backend, &labels, false, true);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("no key labels"), "error: {err_msg}");
    }

    #[test]
    fn delete_multiple_keys_with_yes() {
        let backend = mock_backend();
        keygen(&backend, "mk-1", None, None, false, false, false).unwrap();
        keygen(&backend, "mk-2", None, None, false, false, false).unwrap();
        keygen(&backend, "mk-3", None, None, false, false, false).unwrap();
        assert_eq!(backend.key_count(), 3);

        let labels = vec!["mk-1".to_string(), "mk-2".to_string()];
        delete(&backend, &labels, false, true).unwrap();
        assert_eq!(backend.key_count(), 1);
        // The remaining key should be mk-3
        let remaining = backend.list().unwrap();
        assert_eq!(remaining[0].metadata.label.as_str(), "mk-3");
    }

    #[test]
    fn delete_with_pub_file_cleanup() {
        let dir = test_dir("del-pub");
        let pub_path = dir.join("cleanup-key.pub");
        let backend = mock_backend();
        keygen(
            &backend,
            "cleanup-key",
            None,
            Some(pub_path.clone()),
            false,
            false,
            false,
        )
        .unwrap();

        assert!(pub_path.exists());
        let labels = vec!["cleanup-key".to_string()];
        delete(&backend, &labels, true, true).unwrap();
        assert!(!pub_path.exists(), "pub file should be deleted");
        assert_eq!(backend.key_count(), 0);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn delete_one_of_several_leaves_others() {
        let backend = mock_backend();
        keygen(&backend, "keep-a", None, None, false, false, false).unwrap();
        keygen(&backend, "remove-b", None, None, false, false, false).unwrap();
        keygen(&backend, "keep-c", None, None, false, false, false).unwrap();

        let labels = vec!["remove-b".to_string()];
        delete(&backend, &labels, false, true).unwrap();

        assert_eq!(backend.key_count(), 2);
        assert!(backend.get("keep-a").is_ok());
        assert!(backend.get("remove-b").is_err());
        assert!(backend.get("keep-c").is_ok());
    }

    #[test]
    fn delete_second_of_same_label_fails() {
        // If we pass the same label twice, the first delete succeeds and the
        // second will fail because the key was already verified to exist but
        // actually the verification loop checks them all first.
        // Actually delete() checks all keys exist upfront, so duplication
        // will get the same KeyInfo twice. Then the second backend.delete()
        // call will fail.
        let backend = backend_with_key("dupe-del", None);
        let labels = vec!["dupe-del".to_string(), "dupe-del".to_string()];
        let result = delete(&backend, &labels, false, true);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // export_pub tests
    // -----------------------------------------------------------------------

    #[test]
    fn export_pub_existing_key() {
        let backend = backend_with_key("exp-key", Some("test@host".into()));
        let result = export_pub(&backend, "exp-key", None, false, false, false);
        assert!(result.is_ok());
    }

    #[test]
    fn export_pub_nonexistent_key() {
        let backend = mock_backend();
        let result = export_pub(&backend, "missing-key", None, false, false, false);
        assert!(result.is_err());
    }

    #[test]
    fn export_pub_with_output_file() {
        let dir = test_dir("export-pub");
        let out_path = dir.join("exported.pub");
        let backend = backend_with_key("exp-file", Some("comment".into()));

        export_pub(
            &backend,
            "exp-file",
            Some(out_path.clone()),
            false,
            false,
            false,
        )
        .unwrap();

        assert!(out_path.exists());
        let contents = std::fs::read_to_string(&out_path).unwrap();
        assert!(contents.contains("ecdsa-sha2-nistp256"));
        assert!(contents.contains("comment"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn export_pub_output_to_nested_dir() {
        let dir = test_dir("export-nested");
        let out_path = dir.join("sub").join("dir").join("key.pub");
        let backend = backend_with_key("exp-nested", None);

        export_pub(
            &backend,
            "exp-nested",
            Some(out_path.clone()),
            false,
            false,
            false,
        )
        .unwrap();
        assert!(out_path.exists());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn export_pub_fingerprint_only() {
        let backend = backend_with_key("exp-fp", None);
        let result = export_pub(&backend, "exp-fp", None, false, true, false);
        assert!(result.is_ok());
    }

    #[test]
    fn export_pub_fingerprint_only_json() {
        let backend = backend_with_key("exp-fp-json", None);
        let result = export_pub(&backend, "exp-fp-json", None, false, true, true);
        assert!(result.is_ok());
    }

    #[test]
    fn export_pub_json() {
        let backend = backend_with_key("exp-json", Some("c".into()));
        let result = export_pub(&backend, "exp-json", None, false, false, true);
        assert!(result.is_ok());
    }

    #[test]
    fn export_pub_authorized_keys_format() {
        let backend = backend_with_key("exp-authkeys", None);
        let result = export_pub(&backend, "exp-authkeys", None, true, false, false);
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // config_path test
    // -----------------------------------------------------------------------

    #[test]
    fn config_path_succeeds() {
        let result = config_path();
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // config_show test
    // -----------------------------------------------------------------------

    #[test]
    fn config_show_succeeds() {
        // This loads from default path. If no config exists, Config::load
        // returns defaults, which is fine.
        let result = config_show();
        assert!(result.is_ok());
    }

    #[test]
    fn ensure_agent_running_propagates_spawn_errors() {
        let launcher = FakeLauncher {
            running: false,
            find_result: Ok(PathBuf::from("/tmp/sshenc-agent")),
            spawn_result: Err(anyhow!("spawn failed")),
            find_count: Mutex::new(0),
            spawn_count: Mutex::new(0),
        };

        let error = ensure_agent_running(&launcher, Path::new("/tmp/agent.sock")).unwrap_err();
        assert!(error.to_string().contains("spawn failed"));
        assert_eq!(*launcher.spawn_count.lock().unwrap(), 1);
    }

    #[test]
    fn ensure_agent_running_skips_spawn_when_already_running() {
        let launcher = FakeLauncher {
            running: true,
            find_result: Ok(PathBuf::from("/tmp/sshenc-agent")),
            spawn_result: Ok(()),
            find_count: Mutex::new(0),
            spawn_count: Mutex::new(0),
        };

        let status = ensure_agent_running(&launcher, Path::new("/tmp/agent.sock")).unwrap();
        assert_eq!(status, AgentStartStatus::AlreadyRunning);
        assert_eq!(*launcher.find_count.lock().unwrap(), 0);
        assert_eq!(*launcher.spawn_count.lock().unwrap(), 0);
    }

    #[test]
    fn preflight_agent_start_propagates_lookup_errors_without_spawning() {
        let launcher = FakeLauncher {
            running: false,
            find_result: Err(anyhow!("missing sshenc-agent")),
            spawn_result: Ok(()),
            find_count: Mutex::new(0),
            spawn_count: Mutex::new(0),
        };

        let error = preflight_agent_start(&launcher, Path::new("/tmp/agent.sock")).unwrap_err();
        assert!(error.to_string().contains("missing sshenc-agent"));
        assert_eq!(*launcher.find_count.lock().unwrap(), 1);
        assert_eq!(*launcher.spawn_count.lock().unwrap(), 0);
    }

    #[test]
    fn windows_prepare_install_actions_disable_service() {
        let actions = windows_prepare_install_actions();

        assert!(actions.contains(&WindowsAction::StopService("ssh-agent")));
        assert!(actions.contains(&WindowsAction::SetServiceStart {
            service: "ssh-agent",
            mode: WindowsServiceStartMode::Disabled,
        }));
    }

    #[test]
    fn windows_finalize_install_actions_set_socket_env() {
        let actions = windows_finalize_install_actions(
            Path::new(r"\\.\pipe\openssh-ssh-agent"),
            Some("C:/Windows/System32/OpenSSH/ssh.exe".to_string()),
        );

        assert!(actions.contains(&WindowsAction::SetUserEnv {
            key: "SSH_AUTH_SOCK",
            value: "//./pipe/openssh-ssh-agent".to_string(),
        }));
        assert!(actions.contains(&WindowsAction::SetUserEnv {
            key: "GIT_SSH_COMMAND",
            value: "C:/Windows/System32/OpenSSH/ssh.exe".to_string(),
        }));
    }

    #[test]
    fn windows_restore_actions_restore_service_and_previous_env() {
        let state = WindowsInstallState {
            previous_ssh_auth_sock: Some("C:/custom/agent.sock".to_string()),
            previous_git_ssh_command: Some("C:/custom/ssh.exe".to_string()),
            ssh_agent_start_mode: Some(WindowsServiceStartMode::Demand),
            ssh_agent_was_running: Some(true),
            managed_git_ssh_command: true,
        };
        let actions = windows_restore_actions(&state);

        assert!(actions.contains(&WindowsAction::SetUserEnv {
            key: "SSH_AUTH_SOCK",
            value: "C:/custom/agent.sock".to_string(),
        }));
        assert!(actions.contains(&WindowsAction::SetUserEnv {
            key: "GIT_SSH_COMMAND",
            value: "C:/custom/ssh.exe".to_string(),
        }));
        assert!(actions.contains(&WindowsAction::SetServiceStart {
            service: "ssh-agent",
            mode: WindowsServiceStartMode::Demand,
        }));
        assert!(actions.contains(&WindowsAction::StartService("ssh-agent")));
    }

    #[test]
    fn windows_restore_actions_skip_git_env_when_not_managed() {
        let state = WindowsInstallState {
            previous_ssh_auth_sock: None,
            previous_git_ssh_command: Some("C:/custom/ssh.exe".to_string()),
            ssh_agent_start_mode: Some(WindowsServiceStartMode::Disabled),
            ssh_agent_was_running: Some(false),
            managed_git_ssh_command: false,
        };
        let actions = windows_restore_actions(&state);

        assert!(actions.contains(&WindowsAction::DeleteUserEnv("SSH_AUTH_SOCK")));
        assert!(!actions.iter().any(|action| {
            matches!(
                action,
                WindowsAction::SetUserEnv {
                    key: "GIT_SSH_COMMAND",
                    ..
                } | WindowsAction::DeleteUserEnv("GIT_SSH_COMMAND")
            )
        }));
        assert!(actions.contains(&WindowsAction::SetServiceStart {
            service: "ssh-agent",
            mode: WindowsServiceStartMode::Disabled,
        }));
        assert!(!actions.contains(&WindowsAction::StartService("ssh-agent")));
    }

    #[test]
    fn validate_windows_action_result_allows_expected_idempotent_failures() {
        validate_windows_action_result(
            &WindowsAction::StopService("ssh-agent"),
            false,
            "The service has not been started.",
        )
        .unwrap();
        validate_windows_action_result(
            &WindowsAction::StartService("ssh-agent"),
            false,
            "An instance of the service is already running.",
        )
        .unwrap();
        validate_windows_action_result(
            &WindowsAction::DeleteUserEnv("SSH_AUTH_SOCK"),
            false,
            "ERROR: The system was unable to find the specified registry key or value.",
        )
        .unwrap();
    }

    #[test]
    fn validate_windows_action_result_rejects_required_failures() {
        let error = validate_windows_action_result(
            &WindowsAction::SetUserEnv {
                key: "SSH_AUTH_SOCK",
                value: "C:/socket".to_string(),
            },
            false,
            "Access is denied.",
        )
        .unwrap_err();

        assert!(error.to_string().contains("set Windows user environment"));
    }

    #[test]
    fn restore_windows_state_with_keeps_state_when_apply_fails() {
        let state = WindowsInstallState {
            previous_ssh_auth_sock: Some("C:/custom/agent.sock".to_string()),
            previous_git_ssh_command: None,
            ssh_agent_start_mode: Some(WindowsServiceStartMode::Demand),
            ssh_agent_was_running: Some(false),
            managed_git_ssh_command: false,
        };
        let apply_called = std::cell::Cell::new(0);
        let remove_called = std::cell::Cell::new(0);

        let error = restore_windows_state_with(
            &state,
            |_| {
                apply_called.set(apply_called.get() + 1);
                Err(anyhow!("restore failed"))
            },
            || {
                remove_called.set(remove_called.get() + 1);
                Ok(())
            },
        )
        .unwrap_err();

        assert!(error.to_string().contains("restore failed"));
        assert_eq!(apply_called.get(), 1);
        assert_eq!(remove_called.get(), 0);
    }

    #[test]
    fn restore_windows_state_with_removes_state_after_successful_apply() {
        let state = WindowsInstallState {
            previous_ssh_auth_sock: Some("C:/custom/agent.sock".to_string()),
            previous_git_ssh_command: Some("C:/custom/ssh.exe".to_string()),
            ssh_agent_start_mode: Some(WindowsServiceStartMode::Demand),
            ssh_agent_was_running: Some(true),
            managed_git_ssh_command: true,
        };
        let apply_called = std::cell::Cell::new(0);
        let remove_called = std::cell::Cell::new(0);

        restore_windows_state_with(
            &state,
            |actions| {
                apply_called.set(apply_called.get() + 1);
                assert!(actions.contains(&WindowsAction::StartService("ssh-agent")));
                Ok(())
            },
            || {
                remove_called.set(remove_called.get() + 1);
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(apply_called.get(), 1);
        assert_eq!(remove_called.get(), 1);
    }

    #[test]
    fn parse_sc_helpers_extract_service_state() {
        let qc = "START_TYPE         : 3   DEMAND_START";
        let query = "STATE              : 4  RUNNING";

        assert_eq!(
            parse_sc_start_mode(qc),
            Some(WindowsServiceStartMode::Demand)
        );
        assert_eq!(parse_sc_running_state(query), Some(true));
    }

    #[test]
    fn parse_reg_query_value_extracts_existing_env() {
        let output = r"
HKEY_CURRENT_USER\Environment
    SSH_AUTH_SOCK    REG_SZ    //./pipe/openssh-ssh-agent
";

        assert_eq!(
            parse_reg_query_value(output).as_deref(),
            Some("//./pipe/openssh-ssh-agent")
        );
    }

    // -----------------------------------------------------------------------
    // promote_to_default tests
    // -----------------------------------------------------------------------

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn promote_to_default_already_default_is_error() {
        let result = promote_to_default("default");
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("already named 'default'"),
            "error: {err_msg}"
        );
    }

    #[test]
    fn build_ssh_wrapper_invocation_writes_temp_identity_file() {
        let backend = backend_with_key("wrapper-key", Some("wrapper@test".into()));
        let identity_dir = test_dir("wrapper-identities");
        let invocation = build_ssh_wrapper_invocation(
            &backend,
            Path::new("/tmp/sshenc-agent.sock"),
            Some("wrapper-key"),
            &["example.com".to_string()],
            &identity_dir,
        )
        .unwrap();

        let identity_path = invocation.temp_identity_file.unwrap();
        assert!(identity_path.starts_with(&identity_dir));
        assert!(identity_path.exists());
        let contents = std::fs::read_to_string(&identity_path).unwrap();
        assert!(contents.contains("ecdsa-sha2-nistp256"));
        assert!(contents.contains("wrapper@test"));
        assert!(invocation
            .args
            .iter()
            .any(|arg| arg.contains(&identity_path.display().to_string())));

        std::fs::remove_dir_all(&identity_dir).ok();
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn promote_to_default_rolls_back_on_publish_failure() {
        let root = test_dir("promote-rollback");
        let keys_dir = root.join("keys");
        let ssh_dir = root.join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();

        seed_promote_key(&keys_dir, "work", Some("work@test"));
        seed_promote_key(&keys_dir, "default", Some("default@test"));
        std::fs::write(ssh_dir.join("id_ecdsa"), "old private").unwrap();
        std::fs::write(ssh_dir.join("id_ecdsa.pub"), "old public").unwrap();

        let error =
            promote_to_default_with_dirs(&keys_dir, &ssh_dir, "work", true, |_path, _data| {
                Err(anyhow!("disk full"))
            })
            .unwrap_err();
        assert!(error.to_string().contains("disk full"));

        assert!(key_files_exist(&keys_dir, "work"));
        assert!(key_files_exist(&keys_dir, "default"));
        assert_eq!(
            std::fs::read_to_string(ssh_dir.join("id_ecdsa")).unwrap(),
            "old private"
        );
        assert_eq!(
            std::fs::read_to_string(ssh_dir.join("id_ecdsa.pub")).unwrap(),
            "old public"
        );

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn parse_ssh_sign_args_preserves_namespace_and_normalizes_label() {
        let parsed = parse_ssh_sign_args(&[
            "-Y".to_string(),
            "sign".to_string(),
            "-n".to_string(),
            "git-namespace-with-extra-segments".to_string(),
            "-f".to_string(),
            "/tmp/work.ssh.pub".to_string(),
            "/tmp/payload".to_string(),
        ])
        .unwrap();

        assert_eq!(parsed.namespace, "git-namespace-with-extra-segments");
        assert_eq!(parsed.label, "work");
        assert_eq!(parsed.data_file, PathBuf::from("/tmp/payload"));
    }

    #[test]
    fn ssh_sign_with_backend_writes_signature_file() {
        let root = test_dir("ssh-sign");
        let data_path = root.join("payload.txt");
        let pub_path = root.join("sig-key.pub");
        let backend = backend_with_key("sig-key", Some("sig@test".into()));
        std::fs::write(&data_path, "payload").unwrap();

        ssh_sign_with_backend(
            &backend,
            &[
                "-Y".to_string(),
                "sign".to_string(),
                "-n".to_string(),
                "git-namespace".to_string(),
                "-f".to_string(),
                pub_path.display().to_string(),
                data_path.display().to_string(),
            ],
        )
        .unwrap();

        let signature = std::fs::read_to_string(root.join("payload.txt.sig")).unwrap();
        assert!(signature.contains("BEGIN SSH SIGNATURE"));
        assert!(signature.contains("END SSH SIGNATURE"));

        std::fs::remove_dir_all(&root).ok();
    }

    // -----------------------------------------------------------------------
    // openssh_print_config tests
    // -----------------------------------------------------------------------

    #[test]
    fn openssh_print_config_existing_key() {
        let backend = backend_with_key("ssh-cfg", None);
        let result = openssh_print_config(&backend, "ssh-cfg", "github.com", false);
        assert!(result.is_ok());
    }

    #[test]
    fn openssh_print_config_nonexistent_key() {
        let backend = mock_backend();
        let result = openssh_print_config(&backend, "ghost", "example.com", false);
        assert!(result.is_err());
    }

    #[test]
    fn openssh_print_config_pkcs11_mode() {
        let backend = backend_with_key("pkcs-cfg", None);
        let result = openssh_print_config(&backend, "pkcs-cfg", "*.example.com", true);
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // base64_wrap tests (private helper)
    // -----------------------------------------------------------------------

    #[test]
    fn base64_wrap_short_data() {
        let result = base64_wrap(b"hello", 70);
        assert!(!result.contains('\n'));
        // Should be valid base64
        assert_eq!(result, "aGVsbG8=");
    }

    #[test]
    fn base64_wrap_wraps_at_width() {
        // Generate enough data to produce multiple lines
        let data = vec![0xAA; 100];
        let result = base64_wrap(&data, 20);
        for line in result.lines() {
            assert!(line.len() <= 20, "line too long: {}", line.len());
        }
    }

    #[test]
    fn base64_wrap_empty_data() {
        let result = base64_wrap(b"", 70);
        assert!(result.is_empty());
    }

    // -----------------------------------------------------------------------
    // keygen end-to-end: verify key metadata after generation
    // -----------------------------------------------------------------------

    #[test]
    fn keygen_verifies_key_properties() {
        let backend = mock_backend();
        keygen(
            &backend,
            "verify-props",
            Some("user@machine".into()),
            None,
            false,
            true,
            false,
        )
        .unwrap();

        let info = backend.get("verify-props").unwrap();
        assert_eq!(info.metadata.label.as_str(), "verify-props");
        assert_eq!(info.metadata.comment.as_deref(), Some("user@machine"));
        assert!(info.metadata.requires_user_presence);
        assert_eq!(
            info.metadata.algorithm.ssh_key_type(),
            "ecdsa-sha2-nistp256"
        );
        assert!(!info.fingerprint_sha256.is_empty());
        assert!(!info.fingerprint_md5.is_empty());
        assert_eq!(info.public_key_bytes.len(), 65);
        assert_eq!(info.public_key_bytes[0], 0x04); // Uncompressed EC point
    }

    // -----------------------------------------------------------------------
    // delete verifies keys exist before deleting any
    // -----------------------------------------------------------------------

    #[test]
    fn delete_verifies_all_labels_exist_before_deleting() {
        // If one label doesn't exist, no keys should be deleted
        let backend = mock_backend();
        keygen(&backend, "real-key", None, None, false, false, false).unwrap();
        assert_eq!(backend.key_count(), 1);

        let labels = vec!["real-key".to_string(), "fake-key".to_string()];
        let result = delete(&backend, &labels, false, true);
        assert!(result.is_err());
        // The real key should still exist because the function checks all first
        // Actually, looking at the code: it iterates labels calling backend.get()
        // and fails on the second one. The first key is NOT yet deleted.
        assert_eq!(backend.key_count(), 1);
    }

    // -----------------------------------------------------------------------
    // export_pub authorized_keys with output file
    // -----------------------------------------------------------------------

    #[test]
    fn export_pub_authorized_keys_to_file() {
        let dir = test_dir("export-authkeys");
        let out_path = dir.join("authorized_keys");
        let backend = backend_with_key("authkeys-key", Some("test".into()));

        export_pub(
            &backend,
            "authkeys-key",
            Some(out_path.clone()),
            true,
            false,
            false,
        )
        .unwrap();

        assert!(out_path.exists());
        let contents = std::fs::read_to_string(&out_path).unwrap();
        assert!(contents.contains("ecdsa-sha2-nistp256"));

        std::fs::remove_dir_all(&dir).ok();
    }

    // -----------------------------------------------------------------------
    // Multiple keygen calls produce unique keys
    // -----------------------------------------------------------------------

    #[test]
    fn keygen_multiple_keys_have_unique_fingerprints() {
        let backend = mock_backend();
        keygen(&backend, "uniq-1", None, None, false, false, false).unwrap();
        keygen(&backend, "uniq-2", None, None, false, false, false).unwrap();
        keygen(&backend, "uniq-3", None, None, false, false, false).unwrap();

        let k1 = backend.get("uniq-1").unwrap();
        let k2 = backend.get("uniq-2").unwrap();
        let k3 = backend.get("uniq-3").unwrap();

        assert_ne!(k1.fingerprint_sha256, k2.fingerprint_sha256);
        assert_ne!(k2.fingerprint_sha256, k3.fingerprint_sha256);
        assert_ne!(k1.fingerprint_sha256, k3.fingerprint_sha256);

        assert_ne!(k1.public_key_bytes, k2.public_key_bytes);
    }
}
