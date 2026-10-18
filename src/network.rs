//! Egress allowlist: expand presets into host and suffix rules.

use anyhow::{Result, bail};

/// Host lists per preset. `*.x` entries are domain suffixes.
/// Exact lists are refined empirically: deny all, install, read the deny log.
fn preset(name: &str) -> Option<&'static [&'static str]> {
    Some(match name {
        "llm" => &["api.anthropic.com"],
        "github" => &[
            "github.com",
            "api.github.com",
            "codeload.github.com",
            "*.githubusercontent.com",
        ],
        // mise version lookups and downloads. storage.googleapis.com serves
        // Claude Code (accepted risk: it serves every GCS bucket).
        "mise" => &[
            "mise-versions.jdx.dev",
            "mise.jdx.dev",
            "storage.googleapis.com",
            // sigstore trust root, for GitHub release attestation checks
            "tuf-repo-cdn.sigstore.dev",
        ],
        "opencode" => &["models.dev"],
        "npm" => &["registry.npmjs.org"],
        "pypi" => &["pypi.org", "files.pythonhosted.org"],
        "cargo" => &["crates.io", "index.crates.io", "static.crates.io", "static.rust-lang.org"],
        "go" => &["proxy.golang.org", "sum.golang.org", "go.dev", "dl.google.com"],
        "node" => &["nodejs.org"],
        _ => return None,
    })
}

#[derive(Debug, Default, PartialEq)]
pub struct Allowlist {
    pub hosts: Vec<String>,
    pub suffixes: Vec<String>,
}

pub fn expand(entries: &[String]) -> Result<Allowlist> {
    let mut list = Allowlist::default();
    for entry in entries {
        if let Some(name) = entry.strip_prefix("preset:") {
            let Some(hosts) = preset(name) else { bail!("unknown network preset `{name}`") };
            for host in hosts {
                add(&mut list, host);
            }
        } else {
            add(&mut list, entry);
        }
    }
    Ok(list)
}

fn add(list: &mut Allowlist, entry: &str) {
    let (target, value) = match entry.strip_prefix("*.") {
        Some(suffix) => (&mut list.suffixes, suffix),
        None => (&mut list.hosts, entry),
    };
    if !target.iter().any(|h| h == value) {
        target.push(value.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_presets_and_dedups() {
        let list = expand(&[
            "preset:github".into(),
            "github.com".into(),
            "*.example.com".into(),
        ])
        .unwrap();
        assert_eq!(list.hosts.iter().filter(|h| *h == "github.com").count(), 1);
        assert!(list.suffixes.contains(&"githubusercontent.com".to_string()));
        assert!(list.suffixes.contains(&"example.com".to_string()));
    }

    #[test]
    fn rejects_unknown_preset() {
        assert!(expand(&["preset:nope".into()]).is_err());
    }
}
