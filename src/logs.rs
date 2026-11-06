//! Egress denials, read from the microsandbox runtime log.
//!
//! The runtime logs denials at debug level among a lot of device noise, and
//! rotates the file every 10 MB. So this only covers recent activity.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result};

/// Rotated files, oldest first.
const FILES: [&str; 4] = ["runtime.log.3", "runtime.log.2", "runtime.log.1", "runtime.log"];
/// Fields that name what the guest tried to reach.
const TARGET_FIELDS: [&str; 4] = ["domain", "sni", "host", "dst"];

#[derive(Debug, PartialEq)]
struct Denial {
    time: String,
    /// e.g. "DNS query", "TLS egress"
    kind: String,
    target: String,
}

fn log_dir(vm: &str) -> Result<PathBuf> {
    let home = dirs::home_dir().context("no home directory")?;
    Ok(home.join(".microsandbox/sandboxes").join(vm).join("logs"))
}

/// `2026-..Z DEBUG microsandbox_network::..: DNS query denied by network policy domain=x`
fn parse(line: &str) -> Option<Denial> {
    if !line.contains("microsandbox_network") || !line.contains(" denied by ") {
        return None;
    }
    let time = line.split_whitespace().next()?.to_string();
    let (_, rest) = line.split_once(": ")?;
    let (kind, after) = rest.split_once(" denied by ")?;
    let target = after
        .split_whitespace()
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| TARGET_FIELDS.contains(k))
        .map(|(_, v)| v.trim_matches('"').to_string())
        .unwrap_or_else(|| "?".into());
    Some(Denial { time, kind: kind.to_string(), target })
}

pub fn egress(vm: &str, name: &str) -> Result<()> {
    let dir = log_dir(vm)?;
    if !dir.exists() {
        anyhow::bail!("no logs for `{name}` at {}", dir.display());
    }
    // (target, kind) -> (count, last seen)
    let mut seen: BTreeMap<(String, String), (usize, String)> = BTreeMap::new();
    let mut since = None;
    for file in FILES {
        let Ok(text) = std::fs::read_to_string(dir.join(file)) else { continue };
        if since.is_none() {
            since = text.split_whitespace().next().map(str::to_string);
        }
        for d in text.lines().filter_map(parse) {
            let entry = seen.entry((d.target, d.kind)).or_insert((0, String::new()));
            entry.0 += 1;
            entry.1 = d.time;
        }
    }
    if let Some(since) = since {
        println!("denials since {since} (older entries are rotated out)\n");
    }
    if seen.is_empty() {
        println!("nothing denied");
        return Ok(());
    }
    let mut rows: Vec<_> = seen.into_iter().collect();
    rows.sort_by(|a, b| b.1.1.cmp(&a.1.1)); // most recent first
    println!("{:<6} {:<21} {:<14} TARGET", "COUNT", "LAST SEEN (UTC)", "KIND");
    let mut hosts = Vec::new();
    for ((target, kind), (count, last)) in rows {
        let last = last.get(..19).unwrap_or(&last).replace('T', " ");
        println!("{count:<6} {last:<21} {kind:<14} {target}");
        if is_hostname(&target) && !hosts.contains(&target) {
            hosts.push(target);
        }
    }
    if !hosts.is_empty() {
        println!("\nto allow, add to network.allow in {}:", crate::config::config_path()?.display());
        for host in hosts {
            println!("    \"{host}\",");
        }
        println!("then run `weichzelle restart {name}` (kills running agents)");
    }
    Ok(())
}

/// Denials without a name only carry an address, which can't be allowed.
fn is_hostname(target: &str) -> bool {
    target.contains('.')
        && target.parse::<std::net::IpAddr>().is_err()
        && target.parse::<std::net::SocketAddr>().is_err()
        && target.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_denials() {
        let dns = "2026-10-18T19:53:26.829846Z DEBUG microsandbox_network::engine::dns::forwarder: DNS query denied by network policy domain=example.com";
        assert_eq!(
            parse(dns),
            Some(Denial {
                time: "2026-10-18T19:53:26.829846Z".into(),
                kind: "DNS query".into(),
                target: "example.com".into(),
            })
        );
        let tls = "2026-10-18T19:53:26Z DEBUG microsandbox_network::engine::tcp::deny: TLS egress denied by default policy sni=a.b dst=1.2.3.4:443";
        assert_eq!(parse(tls).unwrap().target, "a.b");
        assert!(parse("2026 DEBUG msb_krun_devices::virtio: queue notify").is_none());
    }

    #[test]
    fn suggests_only_hostnames() {
        assert!(is_hostname("pypi.org"));
        assert!(!is_hostname("1.2.3.4"));
        assert!(!is_hostname("1.2.3.4:443"));
        assert!(!is_hostname("[::1]:443"));
        assert!(!is_hostname("?"));
    }
}
