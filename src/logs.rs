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

/// Under microsandbox's home (`~/.microsandbox`, or `$MSB_HOME`).
fn log_dir(vm: &str) -> Result<PathBuf> {
    let config = microsandbox::config::config().context("cannot read microsandbox's config")?;
    Ok(config.sandboxes_dir().join(vm).join("logs"))
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

/// Denials logged in the last `minutes`: (count, distinct targets).
pub fn recent_denials(vm: &str, minutes: u64) -> Result<(usize, usize)> {
    let dir = log_dir(vm)?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    let cutoff = utc_timestamp(now.saturating_sub(minutes * 60));
    let mut count = 0;
    let mut targets = std::collections::BTreeSet::new();
    for file in FILES {
        let Ok(text) = std::fs::read_to_string(dir.join(file)) else { continue };
        for d in text.lines().filter_map(parse).filter(|d| d.time >= cutoff) {
            count += 1;
            targets.insert(d.target);
        }
    }
    Ok((count, targets.len()))
}

/// `2026-10-18T19:53:26` (UTC) for seconds since the epoch. No `Z`, so it
/// sorts before every log timestamp of that second, fractional or not.
fn utc_timestamp(secs: u64) -> String {
    let (days, rest) = (secs / 86400, secs % 86400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days as i64 + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}", rest / 3600, rest % 3600 / 60, rest % 60)
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
    fn formats_utc_timestamps() {
        assert_eq!(utc_timestamp(0), "1970-01-01T00:00:00");
        assert_eq!(utc_timestamp(1_771_342_406), "2026-02-17T15:33:26");
        assert_eq!(utc_timestamp(951_782_400), "2000-02-29T00:00:00");
        let cutoff = utc_timestamp(1_771_342_406);
        for same_second in ["2026-02-17T15:33:26Z", "2026-02-17T15:33:26.5Z"] {
            assert!(*same_second >= *cutoff, "{same_second}");
        }
        assert!(*"2026-02-17T15:33:25.9Z" < *cutoff);
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
