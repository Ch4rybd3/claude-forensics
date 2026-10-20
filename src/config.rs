use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// On-disk configuration (TOML). Every field can be overridden from the CLI.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct FileConfig {
    pub server: ServerSection,
    pub auth: AuthSection,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ServerSection {
    pub bind: Option<String>,
    pub port: Option<u16>,
    pub data_dir: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct AuthSection {
    pub username: Option<String>,
    /// Plain text password or an argon2 PHC hash (`$argon2id$...`).
    pub password: Option<String>,
}

/// Effective runtime configuration after merging file + CLI.
#[derive(Debug, Clone)]
pub struct Config {
    pub bind: String,
    pub port: u16,
    pub data_dir: PathBuf,
    pub username: String,
    pub password: Secret,
}

#[derive(Clone)]
pub enum Secret {
    Plain(String),
    Argon2(String),
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Secret::Plain(_) => f.write_str("Plain(***)"),
            Secret::Argon2(_) => f.write_str("Argon2(***)"),
        }
    }
}

impl Secret {
    pub fn parse(s: String) -> Self {
        if s.starts_with("$argon2") { Secret::Argon2(s) } else { Secret::Plain(s) }
    }
}

pub const DEFAULT_CONFIG_FILE: &str = "claude-forensics.toml";

pub fn load_file(path: Option<&Path>) -> Result<FileConfig> {
    let (path, explicit) = match path {
        Some(p) => (p.to_path_buf(), true),
        None => (PathBuf::from(DEFAULT_CONFIG_FILE), false),
    };
    if !path.exists() {
        if explicit {
            bail!("config file not found: {}", path.display());
        }
        return Ok(FileConfig::default());
    }
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("reading config {}", path.display()))?;
    let cfg: FileConfig =
        toml::from_str(&raw).with_context(|| format!("parsing config {}", path.display()))?;
    tracing::info!("loaded configuration from {}", path.display());
    Ok(cfg)
}

pub const EXAMPLE_CONFIG: &str = r#"# claude-forensics configuration
[server]
bind = "0.0.0.0"        # listen on all interfaces
port = 8080
data_dir = "./cf-data"  # cases, evidence copies and SQLite databases

[auth]
username = "analyst"
# Plain text or argon2 hash generated with: claude-forensics hash-password
password = "change-me"
"#;
