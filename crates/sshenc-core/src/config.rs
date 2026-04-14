// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Configuration model for sshenc.

use crate::error::{Error, Result};
use enclaveapp_core::metadata::{atomic_write, ensure_dir, restrict_file_permissions};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// User-presence prompt policy for the agent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PromptPolicy {
    /// Always require user presence for signing operations.
    Always,
    /// Never require user presence (keys must be created without the flag).
    Never,
    /// Use whatever the key's access control requires.
    #[default]
    KeyDefault,
}

/// Logging level.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    pub fn as_tracing_str(&self) -> &'static str {
        match self {
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
            LogLevel::Trace => "trace",
        }
    }
}

/// Host-specific identity preference.
///
/// Note: The SSH agent protocol does not include the target hostname in
/// sign requests, so the agent cannot perform host-based key selection.
/// This field is used by `sshenc openssh print-config` to generate
/// per-host SSH config snippets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostIdentity {
    /// Hostname or pattern.
    pub host: String,
    /// Key label to use for this host.
    pub label: String,
}

/// Top-level sshenc configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Path for the agent Unix socket.
    pub socket_path: PathBuf,
    /// Labels of keys the agent should expose. Empty means all sshenc keys.
    pub allowed_labels: Vec<String>,
    /// User-presence prompt policy.
    pub prompt_policy: PromptPolicy,
    /// Default directory for .pub file export.
    pub pub_dir: PathBuf,
    /// Logging level.
    pub log_level: LogLevel,
    /// Host-specific identity preferences.
    pub host_identities: Vec<HostIdentity>,
}

impl Default for Config {
    fn default() -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
        #[cfg(unix)]
        let socket_path = home.join(".sshenc").join("agent.sock");
        #[cfg(windows)]
        let socket_path = PathBuf::from(r"\\.\pipe\openssh-ssh-agent");
        Config {
            socket_path,
            allowed_labels: Vec::new(),
            prompt_policy: PromptPolicy::default(),
            pub_dir: home.join(".ssh"),
            log_level: LogLevel::default(),
            host_identities: Vec::new(),
        }
    }
}

impl Config {
    /// Returns the default config file path.
    pub fn default_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| {
                dirs::home_dir()
                    .unwrap_or_else(|| PathBuf::from("/tmp"))
                    .join(".config")
            })
            .join("sshenc")
            .join("config.toml")
    }

    /// Load config from a file path.
    ///
    /// If the file does not exist, returns `Config::default()` silently.
    /// This is standard behavior: a missing config file means "use defaults".
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Config::default());
        }
        let content = std::fs::read_to_string(path)?;
        let mut config: Config = toml::from_str(&content)?;
        config.expand_paths();
        Ok(config)
    }

    /// Load config from the default path.
    pub fn load_default() -> Result<Self> {
        Self::load(&Self::default_path())
    }

    /// Save config to a file path, creating parent directories if needed.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            ensure_dir(parent).map_err(|e| Error::Config(e.to_string()))?;
        }
        let content = toml::to_string_pretty(self)?;
        atomic_write(path, content.as_bytes()).map_err(|e| Error::Config(e.to_string()))?;
        restrict_file_permissions(path).map_err(|e| Error::Config(e.to_string()))?;
        Ok(())
    }

    /// Initialize a default config file at the default path.
    /// Returns an error if the file already exists.
    pub fn init() -> Result<PathBuf> {
        let path = Self::default_path();
        if path.exists() {
            return Err(Error::Config(format!(
                "config file already exists: {}",
                path.display()
            )));
        }
        let config = Config::default();
        config.save(&path)?;
        Ok(path)
    }

    fn expand_paths(&mut self) {
        self.socket_path = expand_tilde_path(&self.socket_path);
        self.pub_dir = expand_tilde_path(&self.pub_dir);
    }
}

fn expand_tilde_path(path: &Path) -> PathBuf {
    let raw = path.to_string_lossy();
    if raw == "~" {
        return dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    }

    if let Some(suffix) = raw.strip_prefix("~/").or_else(|| raw.strip_prefix("~\\")) {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
        return home.join(suffix);
    }

    path.to_path_buf()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(miri, ignore)] // Config::default() calls dirs::home_dir() -> FFI
    fn test_default_config() {
        let config = Config::default();
        #[cfg(unix)]
        assert!(config.socket_path.to_string_lossy().contains("agent.sock"));
        #[cfg(windows)]
        assert!(config
            .socket_path
            .to_string_lossy()
            .contains("openssh-ssh-agent"));
        assert!(config.allowed_labels.is_empty());
        assert_eq!(config.prompt_policy, PromptPolicy::KeyDefault);
    }

    #[test]
    #[cfg_attr(miri, ignore)] // Config::default() calls dirs::home_dir() -> FFI
    fn test_config_roundtrip() {
        let config = Config {
            allowed_labels: vec!["github-personal".into(), "work".into()],
            prompt_policy: PromptPolicy::Always,
            log_level: LogLevel::Debug,
            host_identities: vec![HostIdentity {
                host: "github.com".into(),
                label: "github-personal".into(),
            }],
            ..Config::default()
        };
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: Config = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.allowed_labels, config.allowed_labels);
        assert_eq!(parsed.prompt_policy, PromptPolicy::Always);
        assert_eq!(parsed.log_level, LogLevel::Debug);
        assert_eq!(parsed.host_identities.len(), 1);
        assert_eq!(parsed.host_identities[0].host, "github.com");
    }

    #[test]
    #[cfg_attr(miri, ignore)] // Config::default() calls dirs::home_dir() -> FFI; file I/O
    fn test_config_save_load() {
        let dir = std::env::temp_dir().join("sshenc-test-config");
        drop(std::fs::remove_dir_all(&dir));
        let path = dir.join("config.toml");

        let config = Config {
            allowed_labels: vec!["test-key".into()],
            ..Config::default()
        };
        config.save(&path).unwrap();
        let loaded = Config::load(&path).unwrap();
        assert_eq!(loaded.allowed_labels, vec!["test-key".to_string()]);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // Config::default() calls dirs::home_dir() -> FFI; file I/O
    fn test_config_save_ignores_preexisting_legacy_tmp_file() {
        let dir = std::env::temp_dir().join("sshenc-test-config-stale-tmp");
        drop(std::fs::remove_dir_all(&dir));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(dir.join(".config.toml.tmp"), "stale").unwrap();

        let config = Config {
            allowed_labels: vec!["test-key".into()],
            ..Config::default()
        };
        config.save(&path).unwrap();

        let loaded = Config::load(&path).unwrap();
        assert_eq!(loaded.allowed_labels, vec!["test-key".to_string()]);
        assert_eq!(
            std::fs::read_to_string(dir.join(".config.toml.tmp")).unwrap(),
            "stale"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // Config::default() calls dirs::home_dir() -> FFI
    fn test_config_load_missing_returns_default() {
        let config = Config::load(Path::new("/nonexistent/path/config.toml")).unwrap();
        assert!(config.allowed_labels.is_empty());
    }

    #[test]
    #[cfg_attr(miri, ignore)] // dirs::home_dir() -> FFI
    fn test_config_load_expands_tilde_paths() {
        let dir = std::env::temp_dir().join("sshenc-test-config-tilde");
        drop(std::fs::remove_dir_all(&dir));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(
            &path,
            r#"
socket_path = "~/.sshenc/agent.sock"
pub_dir = "~/.ssh"
"#,
        )
        .unwrap();

        let config = Config::load(&path).unwrap();
        let home = dirs::home_dir().unwrap();
        assert_eq!(config.socket_path, home.join(".sshenc").join("agent.sock"));
        assert_eq!(config.pub_dir, home.join(".ssh"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // Config::default() calls dirs::home_dir() -> FFI
    fn test_prompt_policy_serializes_lowercase() {
        let config = Config {
            prompt_policy: PromptPolicy::Always,
            ..Config::default()
        };
        let toml_str = toml::to_string_pretty(&config).unwrap();
        assert!(
            toml_str.contains("\"always\""),
            "PromptPolicy::Always should serialize as \"always\", got:\n{toml_str}"
        );

        let config2 = Config {
            prompt_policy: PromptPolicy::Never,
            ..Config::default()
        };
        let toml_str2 = toml::to_string_pretty(&config2).unwrap();
        assert!(
            toml_str2.contains("\"never\""),
            "PromptPolicy::Never should serialize as \"never\", got:\n{toml_str2}"
        );

        let config3 = Config {
            prompt_policy: PromptPolicy::KeyDefault,
            ..Config::default()
        };
        let toml_str3 = toml::to_string_pretty(&config3).unwrap();
        assert!(
            toml_str3.contains("\"keydefault\""),
            "PromptPolicy::KeyDefault should serialize as \"keydefault\", got:\n{toml_str3}"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)] // Config::default() calls dirs::home_dir() -> FFI
    fn test_log_level_serializes_lowercase() {
        for (level, expected) in [
            (LogLevel::Error, "\"error\""),
            (LogLevel::Warn, "\"warn\""),
            (LogLevel::Info, "\"info\""),
            (LogLevel::Debug, "\"debug\""),
            (LogLevel::Trace, "\"trace\""),
        ] {
            let config = Config {
                log_level: level,
                ..Config::default()
            };
            let toml_str = toml::to_string_pretty(&config).unwrap();
            assert!(
                toml_str.contains(expected),
                "LogLevel::{level:?} should serialize containing {expected}, got:\n{toml_str}"
            );
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)] // serde(default) on Config calls dirs::home_dir() -> FFI
    fn test_config_unknown_fields_ignored() {
        // serde(default) on Config means unknown fields should be silently ignored
        let toml_str = r#"
socket_path = "/tmp/agent.sock"
some_future_field = "hello"
another_unknown = 42

[nested_unknown]
key = "value"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.socket_path, PathBuf::from("/tmp/agent.sock"));
    }

    #[test]
    #[cfg_attr(miri, ignore)] // serde(default) on Config calls dirs::home_dir() -> FFI
    fn test_config_all_fields_roundtrip() {
        let config = Config {
            socket_path: PathBuf::from("/custom/agent.sock"),
            allowed_labels: vec!["key1".into(), "key2".into(), "key3".into()],
            prompt_policy: PromptPolicy::Never,
            pub_dir: PathBuf::from("/custom/pubkeys"),
            log_level: LogLevel::Trace,
            host_identities: vec![
                HostIdentity {
                    host: "github.com".into(),
                    label: "github-key".into(),
                },
                HostIdentity {
                    host: "*.internal.corp".into(),
                    label: "work-key".into(),
                },
            ],
        };
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: Config = toml::from_str(&toml_str).unwrap();

        assert_eq!(parsed.socket_path, config.socket_path);
        assert_eq!(parsed.allowed_labels, config.allowed_labels);
        assert_eq!(parsed.prompt_policy, PromptPolicy::Never);
        assert_eq!(parsed.pub_dir, config.pub_dir);
        assert_eq!(parsed.log_level, LogLevel::Trace);
        assert_eq!(parsed.host_identities.len(), 2);
        assert_eq!(parsed.host_identities[0].host, "github.com");
        assert_eq!(parsed.host_identities[0].label, "github-key");
        assert_eq!(parsed.host_identities[1].host, "*.internal.corp");
        assert_eq!(parsed.host_identities[1].label, "work-key");
    }

    #[test]
    #[cfg_attr(miri, ignore)] // serde(default) on Config calls dirs::home_dir() -> FFI
    fn test_config_host_identities_roundtrip() {
        let toml_str = r#"
socket_path = "/tmp/agent.sock"
allowed_labels = []
prompt_policy = "keydefault"
pub_dir = "/tmp/pub"
log_level = "info"

[[host_identities]]
host = "github.com"
label = "gh"

[[host_identities]]
host = "gitlab.com"
label = "gl"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.host_identities.len(), 2);
        assert_eq!(config.host_identities[0].host, "github.com");
        assert_eq!(config.host_identities[0].label, "gh");
        assert_eq!(config.host_identities[1].host, "gitlab.com");
        assert_eq!(config.host_identities[1].label, "gl");

        // Roundtrip
        let re_serialized = toml::to_string_pretty(&config).unwrap();
        let re_parsed: Config = toml::from_str(&re_serialized).unwrap();
        assert_eq!(re_parsed.host_identities.len(), 2);
    }

    #[test]
    #[cfg_attr(miri, ignore)] // Config::default() calls dirs::home_dir() -> FFI
    fn test_platform_conditional_socket_path() {
        let config = Config::default();
        #[cfg(unix)]
        {
            let path_str = config.socket_path.to_string_lossy();
            assert!(
                path_str.contains("agent.sock"),
                "Unix socket path should contain 'agent.sock': {path_str}"
            );
            assert!(
                path_str.contains(".sshenc"),
                "Unix socket path should contain '.sshenc': {path_str}"
            );
        }
        #[cfg(windows)]
        {
            let path_str = config.socket_path.to_string_lossy();
            assert!(
                path_str.contains(r"\\.\pipe\"),
                "Windows socket path should be a named pipe: {path_str}"
            );
        }
    }
}
