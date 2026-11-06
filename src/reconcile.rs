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
use microsandbox::sandbox::{SandboxConfig, SecretBuilder};
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

/// Compare a VM's saved config with the host config.
pub fn drift(config: &Config, saved: &SandboxConfig) -> Result<Drift> {
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
    let drift = drift(config, &h.config()?)?;
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
    let left = self::drift(config, &Sandbox::get(vm).await?.config()?)?;
    if !left.is_empty() {
        bail!(
            "{vm}: {} still differ from config.toml after updating. \
             weichzelle expects microsandbox 0.7.8's config format; rebuild the VM instead",
            left.describe()
        );
    }
    Ok(())
}

fn format_error(vm: &str) -> String {
    format!(
        "unexpected saved config for {vm}: weichzelle edits microsandbox 0.7.8's format only. \
         Rebuild the VM to change its network policy"
    )
}

/// Replace the network policy in a stopped VM's saved config.
async fn write_policy(vm: &str, policy: &Value) -> Result<()> {
    let path = microsandbox::config::config()?.home().join("db").join("msb.db");
    let options = SqliteConnectOptions::new().filename(&path).busy_timeout(Duration::from_secs(10));
    let mut db =
        SqliteConnection::connect_with(&options).await.with_context(|| format!("cannot open {}", path.display()))?;
    let (old, status) =
        read_row(&mut db, vm).await?.with_context(|| format!("no sandbox `{vm}` in {}", path.display()))?;
    if !STOPPED.contains(&status.as_str()) {
        bail!("{vm} is {status}; it must be stopped to change its network policy");
    }
    let new = with_policy(vm, &old, policy)?;
    update_row(&mut db, vm, &old, &status, &new).await?;
    db.close().await?;
    Ok(())
}

/// Whether the next `start` could rewrite this VM's network policy: the saved
/// row has the 0.7.8 shape. Opens the database read-only and writes nothing.
pub async fn check_format(vm: &str) -> Result<()> {
    let path = microsandbox::config::config()?.home().join("db").join("msb.db");
    let options = SqliteConnectOptions::new().filename(&path).read_only(true).busy_timeout(Duration::from_secs(5));
    let mut db =
        SqliteConnection::connect_with(&options).await.with_context(|| format!("cannot open {}", path.display()))?;
    let (old, _) = read_row(&mut db, vm).await?.with_context(|| format!("no sandbox `{vm}` in {}", path.display()))?;
    db.close().await?;
    let saved: Value = serde_json::from_str(&old).with_context(|| format_error(vm))?;
    let policy = saved.get("network").and_then(|n| n.get("policy")).with_context(|| format_error(vm))?;
    with_policy(vm, &old, policy).map(|_| ())
}

/// A sandbox's saved config and status.
async fn read_row(db: &mut SqliteConnection, vm: &str) -> Result<Option<(String, String)>> {
    Ok(sqlx::query_as("SELECT config, status FROM sandbox WHERE name = ?").bind(vm).fetch_optional(db).await?)
}

/// The saved config `old` with its network policy replaced by `policy`.
fn with_policy(vm: &str, old: &str, policy: &Value) -> Result<String> {
    let mut config: Value = serde_json::from_str(old).with_context(|| format_error(vm))?;
    let slot = config
        .get_mut("network")
        .and_then(|n| n.get_mut("policy"))
        .filter(|p| p.is_object())
        .with_context(|| format_error(vm))?;
    *slot = policy.clone();
    // The result must still be a valid config holding exactly the new policy.
    let parsed: SandboxConfig = serde_json::from_value(config.clone()).with_context(|| format_error(vm))?;
    if serde_json::to_value(&parsed.spec.network.policy)? != *policy {
        bail!(format_error(vm));
    }
    Ok(serde_json::to_string(&config)?)
}

/// Write `new`, but only if nothing changed the row since it was read.
async fn update_row(db: &mut SqliteConnection, vm: &str, old: &str, status: &str, new: &str) -> Result<()> {
    let done = sqlx::query("UPDATE sandbox SET config = ? WHERE name = ? AND config = ? AND status = ?")
        .bind(new)
        .bind(vm)
        .bind(old)
        .bind(status)
        .execute(db)
        .await?;
    if done.rows_affected() != 1 {
        bail!("{vm} changed while its network policy was updated; try again");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn default_config() -> Config {
        toml::from_str(crate::config::DEFAULT_CONFIG).unwrap()
    }

    /// Every preset turned on.
    fn all_presets() -> Config {
        let mut c = default_config();
        c.network.allow = network::PRESETS.iter().map(|p| format!("preset:{p}")).collect();
        c
    }

    // Invariants on the policy handed to microsandbox: deny by default, and
    // only allow rules for names (no IPs, ranges, groups or "any").
    fn check_policy(config: &Config) {
        let p = serde_json::to_value(policy(config).unwrap()).unwrap();
        assert_eq!(p["default_egress"], "deny");
        assert_eq!(p["default_ingress"], "deny");
        let rules = p["rules"].as_array().unwrap();
        assert!(!rules.is_empty());
        for rule in rules {
            assert_eq!(rule["action"], "allow", "{rule}");
            assert_eq!(rule["direction"], "egress", "{rule}");
            let dest = rule["destination"].as_object().unwrap();
            assert_eq!(dest.len(), 1, "{rule}");
            let (kind, name) = dest.iter().next().unwrap();
            assert!(kind == "domain" || kind == "domain_suffix", "{rule}");
            let name = name.as_str().unwrap();
            // A suffix like "com" would allow a whole TLD.
            if kind == "domain_suffix" {
                assert!(name.split('.').count() >= 2, "suffix too broad: {name}");
            }
        }
    }

    #[test]
    fn default_policy_is_deny_by_default() {
        check_policy(&default_config());
    }

    #[test]
    fn every_preset_keeps_the_invariants() {
        check_policy(&all_presets());
    }

    #[test]
    fn empty_allowlist_has_no_rules() {
        let mut c = default_config();
        c.network.allow.clear();
        let p = serde_json::to_value(policy(&c).unwrap()).unwrap();
        assert_eq!(p["default_egress"], "deny");
        assert_eq!(p["rules"], json!([]));
    }

    // Invariants on each secret: an env reference (never a raw value), only
    // the configured hosts and headers, nothing else enabled.
    #[test]
    fn default_secrets_are_scoped_env_references() {
        let c = default_config();
        assert!(!c.secrets.is_empty());
        for (env, s) in &c.secrets {
            let e = serde_json::to_value(secret(SecretBuilder::new(), env, s).build()).unwrap();
            assert_eq!(e["value"], "", "{env}: raw value in the spec");
            assert_eq!(e["source"], json!({"kind": "env", "var": format!("WZ_SECRET_{env}")}));
            let hosts: Vec<Value> = s.hosts.iter().map(|h| json!({"exact": h})).collect();
            assert_eq!(e["allowed_hosts"], json!(hosts), "{env}");
            assert_eq!(
                e["substitution"],
                json!({"headers": true, "header_fields": s.headers, "query": false, "body": false}),
                "{env}"
            );
            assert_eq!(e["passthrough_hosts"], json!([]), "{env}");
            assert_eq!(e["require_tls_identity"], true, "{env}");
            assert!(e.get("violation_action").is_none(), "{env}");
        }
    }

    #[test]
    fn secret_values_never_reach_the_spec() {
        let s = SecretConfig {
            source: "env:PATH".into(),
            hosts: vec!["a.example".into()],
            headers: vec!["authorization".into()],
        };
        let path = std::env::var("PATH").unwrap();
        let text = serde_json::to_string(&secret(SecretBuilder::new(), "T", &s).build()).unwrap();
        assert!(!text.contains(&path));
    }

    // Saved-config tests against a real 0.7.8 database row, captured by
    // `WZ_UPDATE_FIXTURE=1 cargo vmtest fixture`.
    const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/msb-0.7.8.db");
    const FIXTURE_VM: &str = "wz-fixture";

    async fn open_fixture() -> (tempfile::TempDir, SqliteConnection) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("msb.db");
        std::fs::copy(FIXTURE, &path).unwrap();
        let db = SqliteConnection::connect_with(&SqliteConnectOptions::new().filename(&path)).await.unwrap();
        (dir, db)
    }

    fn saved(row: &str) -> SandboxConfig {
        serde_json::from_str(row).unwrap()
    }

    #[tokio::test]
    async fn fixture_matches_the_default_config() {
        let (_dir, mut db) = open_fixture().await;
        let (row, status) = read_row(&mut db, FIXTURE_VM).await.unwrap().unwrap();
        assert!(STOPPED.contains(&status.as_str()), "{status}");
        assert!(drift(&default_config(), &saved(&row)).unwrap().is_empty());
    }

    #[tokio::test]
    async fn policy_rewrite_round_trips() {
        let (_dir, mut db) = open_fixture().await;
        let (old, status) = read_row(&mut db, FIXTURE_VM).await.unwrap().unwrap();
        let mut c = default_config();
        c.network.allow.push("example.com".into());

        let d = drift(&c, &saved(&old)).unwrap();
        assert_eq!(d.describe(), "network.allow");
        let new = with_policy(FIXTURE_VM, &old, d.policy.as_ref().unwrap()).unwrap();
        update_row(&mut db, FIXTURE_VM, &old, &status, &new).await.unwrap();

        let (row, _) = read_row(&mut db, FIXTURE_VM).await.unwrap().unwrap();
        assert!(drift(&c, &saved(&row)).unwrap().is_empty());
        // Only the policy changed.
        let (mut a, mut b): (Value, Value) = (serde_json::from_str(&old).unwrap(), serde_json::from_str(&row).unwrap());
        a["network"]["policy"] = Value::Null;
        b["network"]["policy"] = Value::Null;
        assert_eq!(a, b);
        // And back.
        let d = drift(&default_config(), &saved(&row)).unwrap();
        let back = with_policy(FIXTURE_VM, &row, d.policy.as_ref().unwrap()).unwrap();
        assert!(drift(&default_config(), &saved(&back)).unwrap().is_empty());
    }

    #[tokio::test]
    async fn update_refuses_a_changed_row() {
        let (_dir, mut db) = open_fixture().await;
        let (old, status) = read_row(&mut db, FIXTURE_VM).await.unwrap().unwrap();
        let mut c = default_config();
        c.network.allow.push("example.com".into());
        let new = with_policy(FIXTURE_VM, &old, drift(&c, &saved(&old)).unwrap().policy.as_ref().unwrap()).unwrap();

        // Someone else writes in between.
        sqlx::query("UPDATE sandbox SET config = ? WHERE name = ?")
            .bind(old.replacen('{', "{ ", 1))
            .bind(FIXTURE_VM)
            .execute(&mut db)
            .await
            .unwrap();
        assert!(update_row(&mut db, FIXTURE_VM, &old, &status, &new).await.is_err());
        // A changed status counts too.
        let (cur, _) = read_row(&mut db, FIXTURE_VM).await.unwrap().unwrap();
        assert!(update_row(&mut db, FIXTURE_VM, &cur, "Running", &new).await.is_err());
    }

    #[tokio::test]
    async fn rewrite_refuses_an_unknown_format() {
        let (_dir, mut db) = open_fixture().await;
        let (old, _) = read_row(&mut db, FIXTURE_VM).await.unwrap().unwrap();
        let p = serde_json::to_value(policy(&default_config()).unwrap()).unwrap();

        let mut moved: Value = serde_json::from_str(&old).unwrap();
        let policy_value = moved["network"]["policy"].take();
        moved["network"].as_object_mut().unwrap().remove("policy");
        moved["egress"] = policy_value;
        assert!(with_policy(FIXTURE_VM, &moved.to_string(), &p).is_err());

        assert!(with_policy(FIXTURE_VM, "not json", &p).is_err());
        assert!(with_policy(FIXTURE_VM, &old, &json!({"default_egress": "maybe"})).is_err());
    }

    #[tokio::test]
    async fn secret_drift_both_directions() {
        let (_dir, mut db) = open_fixture().await;
        let (row, _) = read_row(&mut db, FIXTURE_VM).await.unwrap().unwrap();
        let saved = saved(&row);

        let mut c = default_config();
        c.secrets.insert(
            "EXTRA_TOKEN".into(),
            SecretConfig {
                source: "env:X".into(),
                hosts: vec!["a.example".into()],
                headers: vec!["authorization".into()],
            },
        );
        let d = drift(&c, &saved).unwrap();
        assert_eq!((d.upsert.as_slice(), d.remove.len()), (&["EXTRA_TOKEN".to_string()][..], 0));

        let mut c = default_config();
        c.secrets.remove("GH_TOKEN");
        let d = drift(&c, &saved).unwrap();
        assert_eq!((d.upsert.len(), d.remove.as_slice()), (0, &["GH_TOKEN".to_string()][..]));

        // Narrowing a secret's hosts counts as a change.
        let mut c = default_config();
        c.secrets.get_mut("GH_TOKEN").unwrap().hosts.pop();
        assert_eq!(drift(&c, &saved).unwrap().upsert, ["GH_TOKEN"]);
    }
}
