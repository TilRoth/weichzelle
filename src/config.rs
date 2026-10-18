//! The global host config: `~/.config/weichzelle/config.toml`.
//!
//! This file grants the VMs their power (egress, secrets), so it lives on the
//! host only and is parsed strictly: unknown keys are errors, not ignored.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

pub const DEFAULT_CONFIG: &str = include_str!("../assets/config.toml");
pub const DEFAULT_CONTAINERFILE: &str = include_str!("../assets/Containerfile");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub vm: VmConfig,
    pub git: GitConfig,
    /// Global mise tools installed in every VM: `tool = "version"`.
    #[serde(default)]
    pub tools: BTreeMap<String, String>,
    #[serde(default)]
    pub network: NetworkConfig,
    /// Keyed by the environment variable name the guest sees.
    #[serde(default)]
    pub secrets: BTreeMap<String, SecretConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmConfig {
    #[serde(default = "default_cpus")]
    pub cpus: u8,
    #[serde(default = "default_memory")]
    pub memory_mib: u32,
}

impl Default for VmConfig {
    fn default() -> Self {
        Self { cpus: default_cpus(), memory_mib: default_memory() }
    }
}

fn default_cpus() -> u8 {
    4
}
fn default_memory() -> u32 {
    4096
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitConfig {
    pub name: String,
    pub email: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    /// Hostnames (`example.com`), suffixes (`*.example.com`) or presets
    /// (`preset:github`). Everything else is denied, including DNS.
    #[serde(default)]
    pub allow: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretConfig {
    /// Where the real value comes from: `keyring:<name>` or `env:<VAR>`.
    pub source: String,
    /// The only hosts the real value is ever sent to.
    pub hosts: Vec<String>,
    /// Header fields the value may be substituted into.
    #[serde(default = "default_headers")]
    pub headers: Vec<String>,
}

fn default_headers() -> Vec<String> {
    vec!["authorization".into()]
}

pub fn config_dir() -> Result<PathBuf> {
    Ok(dirs::config_dir().context("no config directory")?.join("weichzelle"))
}

pub fn config_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("config.toml"))
}

pub fn containerfile_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("Containerfile"))
}

pub fn state_dir() -> Result<PathBuf> {
    Ok(dirs::data_dir().context("no data directory")?.join("weichzelle"))
}

impl Config {
    pub fn load() -> Result<Self> {
        let path = config_path()?;
        let text = std::fs::read_to_string(&path).with_context(|| {
            format!("cannot read {} (run `weichzelle init` first)", path.display())
        })?;
        let config: Config =
            toml::from_str(&text).with_context(|| format!("invalid config {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        if self.vm.cpus == 0 || self.vm.memory_mib < 512 {
            bail!("vm.cpus must be >= 1 and vm.memory_mib >= 512");
        }
        for (env, secret) in &self.secrets {
            let valid_env = !env.is_empty()
                && env.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
            if !valid_env {
                bail!("secret name `{env}` must be an UPPER_SNAKE_CASE env var");
            }
            if secret.hosts.is_empty() {
                bail!("secret `{env}` needs at least one host");
            }
            if secret.headers.is_empty() {
                bail!("secret `{env}`: empty `headers` would allow every header; list them");
            }
        }
        Ok(())
    }
}

fn host_git(key: &str) -> Option<String> {
    let out = std::process::Command::new("git").args(["config", "--get", key]).output().ok()?;
    let value = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (out.status.success() && !value.is_empty()).then_some(value)
}

/// Write the default config and Containerfile, never overwriting.
pub fn init() -> Result<()> {
    let dir = config_dir()?;
    std::fs::create_dir_all(&dir)?;
    let config = DEFAULT_CONFIG
        .replace("Your Name", &host_git("user.name").unwrap_or("Your Name".into()))
        .replace("you@example.com", &host_git("user.email").unwrap_or("you@example.com".into()));
    for (path, content) in
        [(config_path()?, config.as_str()), (containerfile_path()?, DEFAULT_CONTAINERFILE)]
    {
        if path.exists() {
            println!("exists:  {}", path.display());
        } else {
            std::fs::write(&path, content)?;
            println!("created: {}", path.display());
        }
    }
    Ok(())
}
