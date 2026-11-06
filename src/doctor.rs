//! `weichzelle doctor [name]`: a read-only health report, like Neovim's
//! `:checkhealth`.
//!
//! It never changes anything: no boot, no reconcile, no fixes. Security-
//! relevant state (policy, secrets, saved config) is checked on the host
//! only. In-VM checks only say whether the sandbox works, because the guest
//! can lie; they are not a security audit.

use std::collections::BTreeMap;
use std::io::IsTerminal;
use std::time::Duration;

use anyhow::Result;
use microsandbox::sandbox::{RootfsSource, SandboxStatus};
use microsandbox::{Image, Sandbox};
use sha2::{Digest, Sha256};

use crate::config::{self, Config};
use crate::{image, logs, reconcile, secrets, vm};

/// The runtime version reconcile.rs's database write is written for.
const RUNTIME_VERSION: &str = "0.7.8";
const DOCTOR: &str = include_str!("../assets/doctor.sh");
/// The guest script's own limit; the host waits a little longer.
const GUEST_TIMEOUT: Duration = Duration::from_secs(20);
const DENIAL_MINUTES: u64 = 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
    Ok,
    Warn,
    Error,
    Skip,
}

#[derive(Debug)]
struct Check {
    status: Status,
    text: String,
    /// Advice for a problem, or the reason for a skip.
    note: Option<String>,
}

#[derive(Debug)]
struct Section {
    title: String,
    checks: Vec<Check>,
}

impl Section {
    fn new(title: impl Into<String>) -> Self {
        Section { title: title.into(), checks: Vec::new() }
    }

    fn push(&mut self, status: Status, text: impl Into<String>, note: impl Into<String>) {
        let note = note.into();
        self.checks.push(Check { status, text: text.into(), note: (!note.is_empty()).then_some(note) });
    }

    fn ok(&mut self, text: impl Into<String>) {
        self.push(Status::Ok, text, "");
    }

    fn warn(&mut self, text: impl Into<String>, advice: impl Into<String>) {
        self.push(Status::Warn, text, advice);
    }

    fn error(&mut self, text: impl Into<String>, advice: impl Into<String>) {
        self.push(Status::Error, text, advice);
    }

    fn skip(&mut self, text: impl Into<String>, reason: impl Into<String>) {
        self.push(Status::Skip, text, reason);
    }
}

/// Run every check and print the report. Returns false if anything is an error.
pub async fn run(name: Option<&str>) -> Result<bool> {
    let mut sections = Vec::new();
    let host = host_checks(&mut sections).await;
    if let Some(name) = name {
        vm_checks(&mut sections, &host, name).await;
    }
    let color = std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    print!("{}", render(&sections, color));
    Ok(healthy(&sections))
}

/// What the VM checks need from the host checks.
struct Host {
    config: Option<Config>,
    /// The image tag for the current Containerfile.
    image: Option<String>,
    runtime: bool,
}

async fn host_checks(sections: &mut Vec<Section>) -> Host {
    let mut s = Section::new("Host");

    let config = match Config::load() {
        Ok(c) => {
            s.ok(format!("config {}", path_or_default(config::config_path())));
            Some(c)
        }
        Err(e) => {
            s.error(format!("config: {e:#}"), "fix the file, or run `weichzelle init` to create it");
            None
        }
    };

    let containerfile = config::containerfile_path().ok().filter(|p| p.is_file());
    let image = match (&containerfile, image::reference()) {
        (Some(path), Ok(reference)) => {
            s.ok(format!("Containerfile {}", path.display()));
            Some(reference)
        }
        _ => {
            s.error(
                format!("no Containerfile at {}", path_or_default(config::containerfile_path())),
                "run `weichzelle init`",
            );
            None
        }
    };

    let runtime = runtime_check(&mut s);
    kvm_check(&mut s);

    let cached = match (&image, runtime) {
        (Some(reference), true) => {
            let cached = Image::get(reference).await.is_ok();
            if cached {
                s.ok(format!("image {reference} built"));
            } else {
                s.warn(format!("image {reference} not built yet"), "the next `create` or `rebuild` builds it");
            }
            cached
        }
        (None, _) => {
            s.skip("image", "no Containerfile");
            false
        }
        (Some(_), false) => {
            s.skip("image", "microsandbox runtime missing");
            false
        }
    };
    match image::builder() {
        Ok(tool) => s.ok(format!("image builder: {tool}")),
        Err(e) if cached => s.warn(format!("{e:#}"), "only needed when the Containerfile changes"),
        Err(e) => s.error(format!("{e:#}"), "install podman: `sudo apt install podman`"),
    }

    match &config {
        Some(c) => {
            match reconcile::policy(c) {
                Ok(_) => s.ok(format!("network.allow ({} entries)", c.network.allow.len())),
                Err(e) => s.error(format!("network.allow: {e:#}"), "fix network.allow in config.toml"),
            }
            for (env, secret) in &c.secrets {
                match secrets::check(&secret.source) {
                    Ok(()) => s.ok(format!("secret {env} ({})", secret.source)),
                    Err(e) => s.error(format!("secret {env}: {e:#}"), secret_advice(&secret.source)),
                }
            }
            if c.herdr.copy_config {
                match vm::host_herdr_config(c) {
                    Ok(_) => s.ok("host herdr config (herdr.copy_config)"),
                    Err(e) => s.error(format!("{e:#}"), "create it, or set herdr.copy_config = false"),
                }
            }
        }
        None => s.skip("network.allow, secrets, herdr config", "config.toml is invalid"),
    }

    sections.push(s);
    Host { config, image, runtime }
}

fn path_or_default(path: Result<std::path::PathBuf>) -> String {
    path.map(|p| p.display().to_string()).unwrap_or_else(|_| "?".into())
}

fn secret_advice(source: &str) -> String {
    match source.strip_prefix("keyring:") {
        Some(name) => format!("weichzelle secret set {name}"),
        None => format!("set {} in the environment you run weichzelle from", source.trim_start_matches("env:")),
    }
}

/// The runtime the SDK would use, and that it is the pinned version.
/// Doesn't run it (the SDK reads the version from the binary).
fn runtime_check(s: &mut Section) -> bool {
    let install = format!("install microsandbox {RUNTIME_VERSION} (see README)");
    let config = match microsandbox::config::config() {
        Ok(c) => c,
        Err(e) => {
            s.error(format!("cannot read microsandbox's config: {e}"), install);
            return false;
        }
    };
    let runtime = match microsandbox::setup::resolve_runtime(&config) {
        Ok(r) => r,
        Err(e) => {
            s.error(format!("microsandbox runtime not found: {e}"), install);
            return false;
        }
    };
    let path = runtime.msb_path.display();
    match microsandbox::setup::resolve_runtime_version(&runtime.msb_path) {
        Ok(Some(v)) if v.to_string() == RUNTIME_VERSION => {
            s.ok(format!("microsandbox {v} ({path})"));
            true
        }
        Ok(Some(v)) => {
            s.error(
                format!("microsandbox {v} at {path}; weichzelle needs {RUNTIME_VERSION}"),
                format!("{install}: changing a VM's network policy depends on its database format"),
            );
            true
        }
        Ok(None) => {
            s.warn(format!("microsandbox at {path} has no version"), install);
            true
        }
        Err(e) => {
            s.error(format!("{e}"), install);
            false
        }
    }
}

fn kvm_check(s: &mut Section) {
    match std::fs::OpenOptions::new().read(true).write(true).open("/dev/kvm") {
        Ok(_) => s.ok("/dev/kvm read/write"),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            s.error("/dev/kvm: permission denied", "sudo usermod -aG kvm $USER, then log in again")
        }
        Err(e) => s.error(format!("/dev/kvm: {e}"), "enable virtualization in the firmware and load the kvm module"),
    }
}

async fn vm_checks(sections: &mut Vec<Section>, host: &Host, name: &str) {
    let mut s = Section::new(format!("VM {name}"));
    let mut inside = Section::new(format!("VM {name}: inside (informational, the guest can lie)"));
    let vm = vm::vm_name(name);

    if !host.runtime {
        s.skip("VM checks", "microsandbox runtime missing");
        sections.push(s);
        return;
    }
    let h = match Sandbox::get(&vm).await {
        Ok(h) => h,
        Err(_) => {
            s.error(format!("no VM named `{name}`"), "see `weichzelle list`");
            sections.push(s);
            return;
        }
    };

    let status = h.status_snapshot();
    let running = status == SandboxStatus::Running;
    match status {
        SandboxStatus::Running => s.ok("running"),
        SandboxStatus::Stopped | SandboxStatus::Created => s.ok("stopped"),
        SandboxStatus::Crashed => {
            s.error("crashed", format!("weichzelle restart {name}; runtime log: ~/.microsandbox/sandboxes/{vm}/logs/"))
        }
        other => s.warn(format!("{other:?}"), "try again in a moment"),
    }

    match reconcile::check_format(&vm).await {
        Ok(()) => s.ok(format!("saved config has the {RUNTIME_VERSION} format")),
        Err(e) => s.error(format!("{e:#}"), format!("weichzelle rebuild {name}")),
    }

    match h.config() {
        Ok(saved) => {
            match &host.config {
                Some(config) => match reconcile::drift(config, &saved) {
                    Ok(d) if d.is_empty() => s.ok("network.allow and secrets match config.toml"),
                    Ok(d) if running => s.warn(
                        format!("{} changed in config.toml since it started", d.describe()),
                        format!("weichzelle restart {name} applies it (kills running agents)"),
                    ),
                    Ok(d) => s.ok(format!("{} changed in config.toml; applies on the next start", d.describe())),
                    Err(e) => {
                        s.error(format!("cannot compare with config.toml: {e:#}"), format!("weichzelle rebuild {name}"))
                    }
                },
                None => s.skip("config drift", "config.toml is invalid"),
            }
            let created_from = match &saved.spec.image {
                RootfsSource::Oci(o) => Some(o.reference.as_str()),
                _ => None,
            };
            match (&host.image, created_from) {
                (Some(current), Some(from)) if current == from => s.ok("built from the current Containerfile"),
                (Some(_), from) => s.warn(
                    format!("built from an older Containerfile ({})", from.unwrap_or("?")),
                    format!("weichzelle rebuild {name} (wipes the VM and its clone)"),
                ),
                (None, _) => s.skip("image", "no Containerfile"),
            }
        }
        Err(e) => s.error(format!("cannot read the saved config: {e}"), format!("weichzelle rebuild {name}")),
    }

    match logs::recent_denials(&vm, DENIAL_MINUTES) {
        Ok((0, _)) => s.ok("no egress denials in the last hour"),
        Ok((n, targets)) => s.warn(
            format!("{n} egress denials in the last hour ({targets} targets)"),
            format!("weichzelle logs {name} --egress"),
        ),
        Err(e) => s.warn(format!("cannot read the runtime log: {e:#}"), ""),
    }

    if running {
        guest_checks(&mut inside, &h, name).await;
    } else {
        inside.skip("in-VM checks", "the VM is not running");
    }
    sections.push(s);
    sections.push(inside);
}

/// One probe in assets/doctor.sh. The host owns every message; the guest only
/// answers ok, fail or skip.
struct Probe {
    id: &'static str,
    text: &'static str,
    /// Severity of a failure.
    fail: Status,
    advice: &'static str,
    skip: &'static str,
}

const PROBES: [Probe; 8] = [
    Probe {
        id: "repo",
        text: "repo cloned",
        fail: Status::Error,
        advice: "weichzelle restart {name} clones it again",
        skip: "",
    },
    Probe {
        id: "tools",
        text: "global tools installed (mise)",
        fail: Status::Warn,
        advice: "weichzelle restart {name} reinstalls them; if that fails: weichzelle logs {name} --egress",
        skip: "",
    },
    Probe {
        id: "herdr",
        text: "herdr runs",
        fail: Status::Error,
        advice: "`attach` needs it: weichzelle restart {name}",
        skip: "",
    },
    Probe {
        id: "toolchain",
        text: "project toolchain installed (mise)",
        fail: Status::Warn,
        advice: "weichzelle logs {name} --egress, then weichzelle restart {name}",
        skip: "the repo has no mise config",
    },
    Probe {
        id: "docker",
        text: "dockerd answers",
        fail: Status::Warn,
        advice: "weichzelle restart {name}; log: /var/log/dockerd.log in the VM",
        skip: "Docker is not in the image",
    },
    Probe {
        id: "runc",
        text: "CA wrapper installed over runc",
        fail: Status::Warn,
        advice: "weichzelle restart {name} reinstalls it",
        skip: "Docker is not in the image",
    },
    Probe {
        id: "disk-root",
        text: "root disk under 90% full",
        fail: Status::Warn,
        advice: "free space in the VM, or weichzelle rebuild {name}",
        skip: "",
    },
    Probe {
        id: "disk-docker",
        text: "Docker disk under 90% full",
        fail: Status::Warn,
        advice: "`docker system prune` in the VM",
        skip: "",
    },
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Answer {
    Ok,
    Fail,
    Skip,
}

/// Known `<id> <answer>` lines from the guest. Everything else is dropped,
/// so guest output never reaches the terminal.
fn parse_guest(out: &str) -> BTreeMap<&'static str, Answer> {
    let mut answers = BTreeMap::new();
    for line in out.lines() {
        let Some((id, answer)) = line.split_once(' ') else { continue };
        let Some(probe) = PROBES.iter().find(|p| p.id == id) else { continue };
        let answer = match answer {
            "ok" => Answer::Ok,
            "fail" => Answer::Fail,
            "skip" => Answer::Skip,
            _ => continue,
        };
        answers.entry(probe.id).or_insert(answer);
    }
    answers
}

async fn guest_checks(s: &mut Section, h: &microsandbox::sandbox::SandboxHandle, name: &str) {
    let sb = match h.connect().await {
        Ok(sb) => sb,
        Err(e) => {
            s.warn(format!("cannot connect to the VM: {e}"), "");
            return;
        }
    };
    let runc_hash = hex::encode(Sha256::digest(vm::WZ_RUNC.as_bytes()));
    // bash explicitly: shell_with uses /bin/sh (dash in the image).
    let exec = sb.exec_with("bash", |o| {
        o.args(["-c", DOCTOR])
            .user(vm::GUEST_USER)
            .cwd(vm::GUEST_HOME)
            .env("WZ_REPO_DIR", vm::repo_dir(name))
            .env("WZ_RUNC_SHA256", runc_hash)
            .timeout(GUEST_TIMEOUT)
    });
    let out = tokio::time::timeout(GUEST_TIMEOUT + Duration::from_secs(5), exec).await;
    sb.detach().await;

    let (answers, missing) = match out {
        Ok(Ok(out)) => (parse_guest(&String::from_utf8_lossy(out.stdout_bytes())), "no answer"),
        Ok(Err(e)) => {
            s.warn(format!("cannot run the checks in the VM: {e}"), "");
            return;
        }
        Err(_) => (BTreeMap::new(), "timed out"),
    };
    for probe in &PROBES {
        let advice = probe.advice.replace("{name}", name);
        match answers.get(probe.id) {
            Some(Answer::Ok) => s.ok(probe.text),
            Some(Answer::Fail) => s.push(probe.fail, probe.text, advice),
            Some(Answer::Skip) => s.skip(probe.text, probe.skip),
            None => s.warn(format!("{}: {missing}", probe.text), ""),
        }
    }
}

fn healthy(sections: &[Section]) -> bool {
    sections.iter().flat_map(|s| &s.checks).all(|c| c.status != Status::Error)
}

fn render(sections: &[Section], color: bool) -> String {
    let paint = |code: &str, text: &str| if color { format!("\x1b[{code}m{text}\x1b[0m") } else { text.to_string() };
    let mut out = String::new();
    let (mut errors, mut warnings) = (0, 0);
    for section in sections {
        out.push_str(&format!("{}\n", paint("1", &section.title)));
        for check in &section.checks {
            let (label, code) = match check.status {
                Status::Ok => ("OK", "32"),
                Status::Warn => ("WARN", "33"),
                Status::Error => ("ERROR", "31"),
                Status::Skip => ("SKIP", "2"),
            };
            errors += usize::from(check.status == Status::Error);
            warnings += usize::from(check.status == Status::Warn);
            out.push_str(&format!("  {} {}", paint(code, &format!("{label:<5}")), check.text));
            match (&check.note, check.status) {
                (Some(reason), Status::Skip) => out.push_str(&format!(" ({reason})\n")),
                (Some(advice), _) => out.push_str(&format!("\n        ↳ {advice}\n")),
                (None, _) => out.push('\n'),
            }
        }
        out.push('\n');
    }
    let plural = |n: usize, word: &str| format!("{n} {word}{}", if n == 1 { "" } else { "s" });
    out.push_str(&match (errors, warnings) {
        (0, 0) => "all good\n".to_string(),
        _ => format!("{}, {}\n", plural(errors, "error"), plural(warnings, "warning")),
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_output_keeps_only_known_answers() {
        let out = "repo ok\n\
                   herdr fail\n\
                   toolchain skip\n\
                   docker maybe\n\
                   evil ok\n\
                   \x1b]0;pwned\x07 ok\n\
                   tools ok trailing\n\
                   repo fail\n\
                   random noise";
        let answers = parse_guest(out);
        assert_eq!(answers.get("repo"), Some(&Answer::Ok), "first answer wins");
        assert_eq!(answers.get("herdr"), Some(&Answer::Fail));
        assert_eq!(answers.get("toolchain"), Some(&Answer::Skip));
        assert_eq!(answers.len(), 3, "{answers:?}");
    }

    #[test]
    fn every_probe_is_in_the_script() {
        for probe in &PROBES {
            assert!(DOCTOR.contains(&format!("probe {} ", probe.id)), "{} missing from doctor.sh", probe.id);
            assert!(probe.fail != Status::Ok && probe.fail != Status::Skip);
        }
    }

    #[test]
    fn only_errors_are_unhealthy() {
        let mut s = Section::new("t");
        s.ok("a");
        s.warn("b", "fix");
        s.skip("c", "why");
        assert!(healthy(std::slice::from_ref(&s)));
        s.error("d", "fix");
        assert!(!healthy(&[s]));
    }

    #[test]
    fn renders_plain_without_color() {
        let mut s = Section::new("Host");
        s.ok("fine");
        s.error("broken", "do this");
        s.skip("later", "because");
        let out = render(&[s], false);
        assert!(!out.contains('\x1b'));
        assert!(out.contains("  OK    fine\n"), "{out}");
        assert!(out.contains("  ERROR broken\n        ↳ do this\n"), "{out}");
        assert!(out.contains("  SKIP  later (because)\n"), "{out}");
        assert!(out.ends_with("1 error, 0 warnings\n"), "{out}");
    }
}
