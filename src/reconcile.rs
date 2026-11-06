//! Bring a VM's network policy and secrets in line with the host config.
//!
//! microsandbox fixes both when a VM is created. Secrets change through the
//! SDK's `modify` API, saved for the next start. The network policy has no
//! such API, so it is rewritten in the VM's saved config in microsandbox's
//! database while the VM is stopped. That depends on microsandbox 0.7.8's
//! format, so every step is checked and anything unexpected is an error.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use microsandbox::sandbox::{SandboxConfig, SandboxHandle, SecretBuilder};
use microsandbox::{NetworkPolicy, Sandbox, SecretSource};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use sqlx::Connection;
use sqlx::sqlite::{SqliteConnectOptions, SqliteConnection};

use crate::config::{Config, SecretConfig};
use crate::{network, secrets};

/// Statuses in which microsandbox boots from the saved config.
const STOPPED: [&str; 3] = ["Stopped", "Crashed", "Created"];

/// The egress policy for `config`: deny everything (including DNS) except
/// the allowlisted names.
pub fn policy(config: &Config) -> Result<NetworkPolicy> {
    let allow = network::expand(&config.network.allow)?;
    NetworkPolicy::none()
        .allow_domains(&allow.hosts)
        .context("invalid host in network.allow")?
        .allow_domain_suffixes(&allow.suffixes)
        .context("invalid suffix in network.allow")
}

/// One secret as microsandbox stores it. The value stays a host env var
/// reference: raw values would be persisted on disk.
pub fn secret(s: SecretBuilder, env: &str, secret: &SecretConfig) -> SecretBuilder {
    let mut s = s
        .env(env)
        .source(SecretSource::Env { var: secrets::host_var(env) })
        .substitute_in_header_fields(secret.headers.clone());
    for host in &secret.hosts {
        s = s.allow(host);
    }
    s
}

/// What differs between a VM's saved config and the host config.
#[derive(Debug, Default)]
pub struct Drift {
    /// The new policy, if it differs.
    policy: Option<Value>,
    /// Secrets to add or update.
    upsert: Vec<String>,
    /// Secrets to remove.
    remove: Vec<String>,
}

impl Drift {
    pub fn is_empty(&self) -> bool {
        self.policy.is_none() && self.upsert.is_empty() && self.remove.is_empty()
    }

    /// e.g. "network.allow and secrets"
    pub fn describe(&self) -> String {
        let secrets = !self.upsert.is_empty() || !self.remove.is_empty();
        match (self.policy.is_some(), secrets) {
            (true, true) => "network.allow and secrets".into(),
            (true, false) => "network.allow".into(),
            _ => "secrets".into(),
        }
    }
}

/// Re-encode `value` as `T`, the type the saved config uses, so both sides
/// of a comparison serialize the same way.
fn as_saved<T: DeserializeOwned + Serialize>(_like: &[T], value: &impl Serialize) -> Result<Value> {
    let saved: T = serde_json::from_value(serde_json::to_value(value)?)?;
    Ok(serde_json::to_value(saved)?)
}

pub fn drift(config: &Config, h: &SandboxHandle) -> Result<Drift> {
    let saved = h.config()?;
    let mut drift = Drift::default();

    let mut wanted = saved.clone();
    wanted.spec.network.policy = Some(serde_json::from_value(serde_json::to_value(policy(config)?)?)?);
    let wanted_policy = serde_json::to_value(&wanted.spec.network.policy)?;
    if serde_json::to_value(&saved.spec.network.policy)? != wanted_policy {
        drift.policy = Some(wanted_policy);
    }

    let saved_secrets = saved.spec.network.secrets.as_ref().map(|s| s.secrets.as_slice()).unwrap_or(&[]);
    let mut current = BTreeMap::new();
    for entry in saved_secrets {
        current.insert(entry.env_var.clone(), serde_json::to_value(entry)?);
    }
    for (env, s) in &config.secrets {
        let entry = secret(SecretBuilder::new(), env, s).build();
        if current.get(env) != Some(&as_saved(saved_secrets, &entry)?) {
            drift.upsert.push(env.clone());
        }
    }
    drift.remove = current.into_keys().filter(|env| !config.secrets.contains_key(env)).collect();
    Ok(drift)
}

/// Apply the host config to a stopped VM, so its next start uses it.
pub async fn apply(config: &Config, vm: &str) -> Result<()> {
    let h = Sandbox::get(vm).await?;
    let drift = drift(config, &h)?;
    if drift.is_empty() {
        return Ok(());
    }
    println!("applying changed {} from config.toml", drift.describe());

    if !drift.upsert.is_empty() || !drift.remove.is_empty() {
        let mut m = h.modify().next_start();
        for env in &drift.upsert {
            let entry = secret(SecretBuilder::new(), env, &config.secrets[env]).build();
            m = m.secret(|p| {
                let mut p = p
                    .env(env)
                    .source(SecretSource::Env { var: secrets::host_var(env) })
                    .substitution(entry.substitution.clone());
                for host in &config.secrets[env].hosts {
                    p = p.allow(host);
                }
                p
            });
        }
        for env in &drift.remove {
            m = m.remove_secret(env);
        }
        m.apply().await.context("cannot update the VM's secrets")?;
    }

    if let Some(policy) = &drift.policy {
        write_policy(vm, policy).await?;
    }

    // Both paths write what `drift` compares against, so nothing may be left.
    let left = self::drift(config, &Sandbox::get(vm).await?)?;
    if !left.is_empty() {
        bail!(
            "{vm}: {} still differ from config.toml after updating. \
             weichzelle expects microsandbox 0.7.8's config format; rebuild the VM instead",
            left.describe()
        );
    }
    Ok(())
}

/// Replace the network policy in a stopped VM's saved config.
async fn write_policy(vm: &str, policy: &Value) -> Result<()> {
    let format_error = || {
        format!(
            "unexpected saved config for {vm}: weichzelle edits microsandbox 0.7.8's format only. \
             Rebuild the VM to change its network policy"
        )
    };
    let path = microsandbox::config::config()?.home().join("db").join("msb.db");
    let options = SqliteConnectOptions::new().filename(&path).busy_timeout(Duration::from_secs(10));
    let mut db = SqliteConnection::connect_with(&options)
        .await
        .with_context(|| format!("cannot open {}", path.display()))?;

    let (old, status): (String, String) =
        sqlx::query_as("SELECT config, status FROM sandbox WHERE name = ?")
            .bind(vm)
            .fetch_optional(&mut db)
            .await?
            .with_context(|| format!("no sandbox `{vm}` in {}", path.display()))?;
    if !STOPPED.contains(&status.as_str()) {
        bail!("{vm} is {status}; it must be stopped to change its network policy");
    }

    let mut config: Value = serde_json::from_str(&old).with_context(format_error)?;
    let slot = config
        .get_mut("network")
        .and_then(|n| n.get_mut("policy"))
        .filter(|p| p.is_object())
        .with_context(format_error)?;
    *slot = policy.clone();
    // The result must still be a valid config holding exactly the new policy.
    let parsed: SandboxConfig = serde_json::from_value(config.clone()).with_context(format_error)?;
    if serde_json::to_value(&parsed.spec.network.policy)? != *policy {
        bail!(format_error());
    }

    // Only if nothing changed the row since it was read.
    let done = sqlx::query("UPDATE sandbox SET config = ? WHERE name = ? AND config = ? AND status = ?")
        .bind(serde_json::to_string(&config)?)
        .bind(vm)
        .bind(&old)
        .bind(&status)
        .execute(&mut db)
        .await?;
    if done.rows_affected() != 1 {
        bail!("{vm} changed while its network policy was updated; try again");
    }
    db.close().await?;
    Ok(())
}
