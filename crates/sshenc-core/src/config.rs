// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Configuration model for sshenc.

use crate::error::{Error, Result};
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
        Config {
            socket_path: home.join(".sshenc").join("agent.sock"),
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

    /// Load config from a file path. Returns default config if the file doesn't exist.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Config::default());
        }
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    /// Load config from the default path.
    pub fn load_default() -> Result<Self> {
        Self::load(&Self::default_path())
    }

    /// Save config to a file path, creating parent directories if needed.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.socket_path.to_string_lossy().contains("agent.sock"));
        assert!(config.allowed_labels.is_empty());
        assert_eq!(config.prompt_policy, PromptPolicy::KeyDefault);
    }

    #[test]
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
    fn test_config_save_load() {
        let dir = std::env::temp_dir().join("sshenc-test-config");
        let _ = std::fs::remove_dir_all(&dir);
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
    fn test_config_load_missing_returns_default() {
        let config = Config::load(Path::new("/nonexistent/path/config.toml")).unwrap();
        assert!(config.allowed_labels.is_empty());
    }
}
