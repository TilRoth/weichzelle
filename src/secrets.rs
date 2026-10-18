//! Resolve secret values on the host.
//!
//! microsandbox reads secrets from host env vars at VM spawn time, and stores
//! only the env var *name* in its sandbox config (raw values would be written
//! to disk). So we resolve each secret here and export it as `WZ_SECRET_<NAME>`
//! in our own process before any VM is started.

use std::collections::BTreeMap;
use std::io::{IsTerminal, Read};

use anyhow::{Context, Result, bail};

use crate::config::SecretConfig;

const KEYRING_SERVICE: &str = "weichzelle";

/// Host env var that carries the real value of the guest variable `env`.
pub fn host_var(env: &str) -> String {
    format!("WZ_SECRET_{env}")
}

fn resolve(source: &str) -> Result<String> {
    if let Some(name) = source.strip_prefix("keyring:") {
        keyring::Entry::new(KEYRING_SERVICE, name)
            .and_then(|e| e.get_password())
            .with_context(|| {
                format!("keyring secret `{name}` not found (set it: weichzelle secret set {name})")
            })
    } else if let Some(var) = source.strip_prefix("env:") {
        std::env::var(var).with_context(|| format!("host env var `{var}` is not set"))
    } else {
        bail!("unknown secret source `{source}` (use keyring:<name> or env:<VAR>)")
    }
}

/// Resolve every secret and export it for microsandbox to pick up.
///
/// Must run before the async runtime starts: setting env vars is only sound
/// while the process is single-threaded.
pub fn export_all(secrets: &BTreeMap<String, SecretConfig>) -> Result<()> {
    let mut resolved = Vec::new();
    for (env, secret) in secrets {
        let value = resolve(&secret.source).with_context(|| format!("secret `{env}`"))?;
        resolved.push((host_var(env), value));
    }
    for (var, value) in resolved {
        // SAFETY: called from `main` before any other thread exists.
        unsafe { std::env::set_var(var, value) };
    }
    Ok(())
}

/// `weichzelle secret set <name>`: store a value in the OS keyring.
pub fn set(name: &str) -> Result<()> {
    let value = if std::io::stdin().is_terminal() {
        rpassword::prompt_password(format!("value for `{name}`: "))?
    } else {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        buf
    };
    let value = value.trim();
    if value.is_empty() {
        bail!("empty value");
    }
    keyring::Entry::new(KEYRING_SERVICE, name)?
        .set_password(value)
        .context("cannot write to the OS keyring")?;
    println!("stored `{name}` in the keyring");
    Ok(())
}

/// Remove a value from the OS keyring.
pub fn delete(name: &str) -> Result<()> {
    keyring::Entry::new(KEYRING_SERVICE, name)?
        .delete_credential()
        .with_context(|| format!("cannot delete `{name}` from the keyring"))?;
    println!("deleted `{name}` from the keyring");
    Ok(())
}
