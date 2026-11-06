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
    #[serde(default)]
    pub herdr: HerdrConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HerdrConfig {
    /// Copy the host's herdr config.toml into every VM on start.
    #[serde(default)]
    pub copy_config: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmConfig {
    #[serde(default = "default_cpus")]
    pub cpus: u8,
    #[serde(default = "default_memory")]
    pub memory_mib: u32,
    /// Size of the private Docker data disk (sparse). Fixed at create.
    #[serde(default = "default_docker_disk")]
    pub docker_disk_gib: u32,
}

impl Default for VmConfig {
    fn default() -> Self {
        Self { cpus: default_cpus(), memory_mib: default_memory(), docker_disk_gib: default_docker_disk() }
    }
}

fn default_cpus() -> u8 {
    4
}
fn default_memory() -> u32 {
    4096
}
fn default_docker_disk() -> u32 {
    40
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
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("cannot read {} (run `weichzelle init` first)", path.display()))?;
        let config: Config = toml::from_str(&text).with_context(|| format!("invalid config {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        if self.vm.cpus == 0 || self.vm.memory_mib < 512 {
            bail!("vm.cpus must be >= 1 and vm.memory_mib >= 512");
        }
        if !(1..=4096).contains(&self.vm.docker_disk_gib) {
            bail!("vm.docker_disk_gib must be between 1 and 4096");
        }
        for (env, secret) in &self.secrets {
            let valid_env =
                !env.is_empty() && env.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
            if !valid_env {
                bail!("secret name `{env}` must be an UPPER_SNAKE_CASE env var");
            }
            if secret.hosts.is_empty() {
                bail!("secret `{env}` needs at least one host");
            }
            if secret.hosts.iter().any(|h| h == "*") {
                bail!("secret `{env}`: host `*` would send it anywhere; list the hosts");
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
    for (path, content) in [(config_path()?, config.as_str()), (containerfile_path()?, DEFAULT_CONTAINERFILE)] {
        if path.exists() {
            println!("exists:  {}", path.display());
        } else {
            std::fs::write(&path, content)?;
            println!("created: {}", path.display());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "[git]\nname = \"a\"\nemail = \"a@b.c\"\n";

    #[test]
    fn herdr_copy_is_off_by_default() {
        let c: Config = toml::from_str(BASE).unwrap();
        assert!(!c.herdr.copy_config);
    }

    #[test]
    fn herdr_copy_can_be_enabled() {
        let c: Config = toml::from_str(&format!("{BASE}[herdr]\ncopy_config = true\n")).unwrap();
        assert!(c.herdr.copy_config);
    }

    #[test]
    fn herdr_rejects_unknown_keys() {
        assert!(toml::from_str::<Config>(&format!("{BASE}[herdr]\npath = \"x\"\n")).is_err());
    }

    #[test]
    fn default_config_parses() {
        let c: Config = toml::from_str(DEFAULT_CONFIG).unwrap();
        c.validate().unwrap();
        assert!(!c.herdr.copy_config);
        assert_eq!(c.vm.docker_disk_gib, 40);
    }

    #[test]
    fn secret_needs_real_hosts_and_headers() {
        let secret = |hosts: &str, headers: &str| {
            let text = format!("{BASE}[secrets.T]\nsource = \"env:X\"\nhosts = {hosts}\nheaders = {headers}\n");
            toml::from_str::<Config>(&text).unwrap().validate()
        };
        assert!(secret(r#"["a.example"]"#, r#"["authorization"]"#).is_ok());
        assert!(secret("[]", r#"["authorization"]"#).is_err());
        assert!(secret(r#"["*"]"#, r#"["authorization"]"#).is_err());
        assert!(secret(r#"["a.example"]"#, "[]").is_err());
    }

    #[test]
    fn secret_names_must_be_env_vars() {
        let text = format!("{BASE}[secrets.lower]\nsource = \"env:X\"\nhosts = [\"a\"]\n");
        assert!(toml::from_str::<Config>(&text).unwrap().validate().is_err());
    }

    #[test]
    fn docker_disk_defaults_and_validates() {
        let c: Config = toml::from_str(BASE).unwrap();
        assert_eq!(c.vm.docker_disk_gib, 40);
        let c: Config = toml::from_str(&format!("{BASE}[vm]\ndocker_disk_gib = 0\n")).unwrap();
        assert!(c.validate().is_err());
    }
}
