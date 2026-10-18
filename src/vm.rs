//! VM lifecycle: one long-running microsandbox VM per GitHub repo.

use anyhow::{Context, Result, bail};
use std::io::Write;

use microsandbox::sandbox::{PullPolicy, SandboxHandle, SandboxStatus};
use microsandbox::{ExecEvent, ExecOutput, LogLevel, NetworkPolicy, Sandbox, SecretSource};

use crate::config::Config;
use crate::{image, network, secrets};

const PREFIX: &str = "wz-";
const LABEL_REPO: &str = "weichzelle.repo";
const GUEST_USER: &str = "agent";
const PROVISION: &str = include_str!("../assets/provision.sh");

pub fn vm_name(name: &str) -> String {
    format!("{PREFIX}{name}")
}

fn repo_dir(name: &str) -> String {
    format!("/work/{name}")
}

/// Default sandbox name from a GitHub URL: the repo name.
pub fn name_from_url(url: &str) -> Result<String> {
    let last = url.trim_end_matches('/').rsplit(['/', ':']).next().unwrap_or_default();
    let name = last.trim_end_matches(".git");
    let valid = !name.is_empty()
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.');
    if !valid {
        bail!("cannot derive a name from `{url}`; pass --name");
    }
    Ok(name.to_string())
}

/// Clone over HTTPS so the GitHub token can be injected as a header.
pub fn https_url(url: &str) -> Result<String> {
    if let Some(path) = url.strip_prefix("git@github.com:") {
        return Ok(format!("https://github.com/{path}"));
    }
    if url.starts_with("https://github.com/") {
        return Ok(url.to_string());
    }
    if let Some(path) = url.strip_prefix("github.com/") {
        return Ok(format!("https://github.com/{path}"));
    }
    bail!("only GitHub repos are supported: {url}")
}

fn mise_config(config: &Config) -> String {
    let mut out = String::from("[tools]\n");
    for (tool, version) in &config.tools {
        out.push_str(&format!("{} = {}\n", toml_key(tool), toml_string(version)));
    }
    out
}

fn toml_key(key: &str) -> String {
    if key.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        key.to_string()
    } else {
        toml_string(key)
    }
}

fn toml_string(s: &str) -> String {
    toml::Value::String(s.to_string()).to_string()
}

async fn create_vm(config: &Config, name: &str, repo_url: &str) -> Result<Sandbox> {
    let image = image::ensure().await?;
    let allow = network::expand(&config.network.allow)?;
    // Deny everything (including DNS) except the allowlisted names.
    let policy = NetworkPolicy::none()
        .allow_domains(&allow.hosts)
        .context("invalid host in network.allow")?
        .allow_domain_suffixes(&allow.suffixes)
        .context("invalid suffix in network.allow")?;

    let mut builder = Sandbox::builder(vm_name(name))
        .image(image.as_str())
        .pull_policy(PullPolicy::Never)
        .cpus(config.vm.cpus)
        .memory(config.vm.memory_mib)
        .hostname(name)
        .label(LABEL_REPO, repo_url)
        .log_level(LogLevel::Debug)
        .detached(true)
        .network(|n| n.policy(policy))
        // Hostname rules need TLS interception to see the real request target.
        .intercept_tls()
        .env("PATH", "/home/agent/.local/share/mise/shims:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LANG", "C.UTF-8")
        // herdr panes start $SHELL; without it they get /bin/sh (no line editing).
        .env("SHELL", "/bin/bash")
        .env("MISE_YES", "1")
        // Node/Bun-based tools ship their own CA list; trust the interception CA.
        .env("NODE_EXTRA_CA_CERTS", "/.msb/tls/ca.pem")
        .env("DISABLE_AUTOUPDATER", "1")
        .env("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1");

    for (env, secret) in &config.secrets {
        builder = builder.secret(|s| {
            let mut s = s
                .env(env)
                .source(SecretSource::Env { var: secrets::host_var(env) })
                .substitute_in_header_fields(secret.headers.clone());
            for host in &secret.hosts {
                s = s.allow(host);
            }
            s
        });
    }

    builder.create().await.context("cannot create the VM")
}

async fn shell_as_agent(sb: &Sandbox, script: &str, envs: &[(&str, String)]) -> Result<ExecOutput> {
    let script = script.to_string();
    let envs: Vec<(String, String)> = envs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
    sb.shell_with(script, |o| {
        let mut o = o.user(GUEST_USER).cwd("/home/agent");
        for (k, v) in envs {
            o = o.env(k, v);
        }
        o
    })
    .await
    .context("exec in VM failed")
}

/// Install tools, clone the repo (first time) and write harness profiles.
async fn provision(config: &Config, sb: &Sandbox, name: &str, repo_url: &str) -> Result<()> {
    let envs = [
        ("WZ_MISE_CONFIG", mise_config(config)),
        ("WZ_REPO_URL", repo_url.to_string()),
        ("WZ_REPO_DIR", repo_dir(name)),
        ("WZ_GIT_NAME", config.git.name.clone()),
        ("WZ_GIT_EMAIL", config.git.email.clone()),
    ];
    // Stream output as it arrives so long installs show progress. Plain
    // exec (not attach) also works when the host has no terminal.
    let mut exec = sb
        .exec_stream_with("bash", |e| {
            let mut e = e.args(["-c", PROVISION]).user(GUEST_USER).cwd("/home/agent").stdin_null();
            for (k, v) in &envs {
                e = e.env(*k, v.clone());
            }
            e
        })
        .await
        .context("provisioning failed to run")?;
    let mut code = -1;
    while let Some(event) = exec.recv().await {
        match event {
            ExecEvent::Stdout(b) => std::io::stdout().write_all(&b)?,
            ExecEvent::Stderr(b) => std::io::stderr().write_all(&b)?,
            ExecEvent::Exited { code: c } => code = c,
            ExecEvent::Failed(f) => bail!("provisioning failed to start: {f:?}"),
            _ => {}
        }
    }
    if code != 0 {
        bail!("provisioning failed (exit {code}); fix the cause and run `weichzelle start {name}`");
    }
    Ok(())
}

async fn handle(name: &str) -> Result<SandboxHandle> {
    Sandbox::get(&vm_name(name))
        .await
        .with_context(|| format!("no sandbox named `{name}` (see `weichzelle list`)"))
}

fn repo_label(h: &SandboxHandle) -> Result<String> {
    let config = h.config()?;
    config
        .spec
        .labels
        .iter()
        .find(|(k, _)| k.as_str() == LABEL_REPO)
        .map(|(_, v)| v.clone())
        .context("sandbox has no repo label (not created by weichzelle?)")
}

/// Running sandbox for `name`, starting and re-provisioning it if needed.
async fn running(config: &Config, name: &str) -> Result<Sandbox> {
    let h = handle(name).await?;
    if h.status_snapshot() == SandboxStatus::Running {
        return h.connect().await.context("cannot connect to the VM");
    }
    println!("starting {name}…");
    let repo = repo_label(&h)?;
    let sb = h.start_detached().await.context("cannot start the VM")?;
    provision(config, &sb, name, &repo).await?;
    Ok(sb)
}

pub async fn create(config: &Config, url: &str, name: Option<String>) -> Result<()> {
    let url = https_url(url)?;
    let name = match name {
        Some(n) => n,
        None => name_from_url(&url)?,
    };
    if Sandbox::get(&vm_name(&name)).await.is_ok() {
        bail!("sandbox `{name}` already exists");
    }
    println!("creating {name} for {url}…");
    let sb = create_vm(config, &name, &url).await?;
    provision(config, &sb, &name, &url).await?;
    sb.detach().await;
    println!("created {name}. attach with: weichzelle attach {name}");
    Ok(())
}

pub async fn start(config: &Config, name: &str) -> Result<()> {
    running(config, name).await?.detach().await;
    println!("{name} is running");
    Ok(())
}

pub async fn attach(config: &Config, name: &str) -> Result<()> {
    let sb = running(config, name).await?;
    let dir = repo_dir(name);
    let code = sb
        .attach_with("herdr", |a| a.user(GUEST_USER).cwd(dir.as_str()).env("SHELL", "/bin/bash"))
        .await
        .context("cannot attach")?;
    sb.detach().await;
    if code != 0 {
        bail!("herdr exited with {code}");
    }
    Ok(())
}

pub async fn stop(name: &str) -> Result<()> {
    let h = handle(name).await?;
    if h.status_snapshot() == SandboxStatus::Running {
        h.stop().await.context("cannot stop the VM")?;
    }
    println!("{name} stopped");
    Ok(())
}

/// What would be lost if the VM's clone were deleted. This guards against
/// accidents only: a compromised VM can lie.
async fn unpushed_work(sb: &Sandbox, name: &str) -> Result<String> {
    let script = format!(
        r#"cd {dir} 2>/dev/null || exit 0
git status --porcelain | sed 's/^/uncommitted: /'
git log --branches --not --remotes --oneline | sed 's/^/unpushed: /'
git stash list | sed 's/^/stash: /'"#,
        dir = repo_dir(name)
    );
    let out = shell_as_agent(sb, &script, &[]).await?;
    Ok(out.stdout()?.trim().to_string())
}

pub async fn destroy(config: &Config, name: &str, force: bool) -> Result<String> {
    let h = handle(name).await?;
    let repo = repo_label(&h)?;
    if !force {
        let sb = running(config, name).await?;
        let lost = unpushed_work(&sb, name).await?;
        sb.detach().await;
        if !lost.is_empty() {
            bail!("{name} has work that is not on GitHub:\n{lost}\nPush it, or pass --force.");
        }
    }
    let h = handle(name).await?;
    if h.status_snapshot() == SandboxStatus::Running {
        h.stop().await.context("cannot stop the VM")?;
    }
    Sandbox::remove(&vm_name(name)).await.context("cannot remove the VM")?;
    println!("{name} destroyed");
    Ok(repo)
}

pub async fn rebuild(config: &Config, name: &str, force: bool) -> Result<()> {
    let repo = destroy(config, name, force).await?;
    create(config, &repo, Some(name.to_string())).await
}

pub async fn list() -> Result<()> {
    let page = Sandbox::list().await?;
    println!("{:<24} {:<10} REPO", "NAME", "STATUS");
    for h in page.sandboxes {
        let Some(name) = h.name().strip_prefix(PREFIX) else { continue };
        let repo = repo_label(&h).unwrap_or_default();
        println!("{:<24} {:<10} {}", name, format!("{:?}", h.status_snapshot()), repo);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_urls() {
        assert_eq!(name_from_url("https://github.com/a/b-c.git").unwrap(), "b-c");
        assert_eq!(name_from_url("git@github.com:a/repo").unwrap(), "repo");
        assert_eq!(https_url("git@github.com:a/b.git").unwrap(), "https://github.com/a/b.git");
        assert_eq!(https_url("github.com/a/b").unwrap(), "https://github.com/a/b");
        assert!(https_url("https://gitlab.com/a/b").is_err());
    }

    #[test]
    fn mise_config_quotes_backend_keys() {
        let toml: Config = toml::from_str(
            r#"
            [git]
            name = "n"
            email = "e"
            [tools]
            herdr = "0.9"
            "aqua:anomalyco/opencode" = "latest"
            "#,
        )
        .unwrap();
        let out = mise_config(&toml);
        assert!(out.contains("herdr = \"0.9\""));
        assert!(out.contains("\"aqua:anomalyco/opencode\" = \"latest\""));
    }
}
