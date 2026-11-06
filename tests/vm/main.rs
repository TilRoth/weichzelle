//! VM tests: real VMs, booted from the fixture repo
//! (github.com/TilRoth/weichzelle-fixture).
//!
//! Need KVM, podman and the microsandbox runtime in `~/.microsandbox`. Run
//! with `cargo vmtest` (all ignored by plain `cargo test`). See DESIGN.md,
//! "Testing".
//!
//! Optional env:
//! - `WZ_TEST_GH_TOKEN`: a real token for the fixture repo; enables the push test.
//! - `WZ_UPDATE_FIXTURE=1`: rewrite `tests/fixtures/msb-0.7.8.db` from a live VM.

mod harness;

use std::collections::BTreeSet;
use std::io::Read;
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use harness::{Vm, assert_no_leaks, env, serial};
use serde_json::Value;

const PROBES: &str = include_str!("probes.sh");
const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/msb-0.7.8.db");
const PEER_PORT: u16 = 4444;

/// Counts connections to a host port on all interfaces.
fn host_listener() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("0.0.0.0:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            counter.fetch_add(1, Ordering::SeqCst);
            let _ = stream.read(&mut [0; 64]);
        }
    });
    (port, hits)
}

fn host_ips() -> String {
    let out = std::process::Command::new("hostname").arg("-I").output().unwrap();
    String::from_utf8_lossy(&out.stdout).split_whitespace().filter(|ip| !ip.contains(':')).collect::<Vec<_>>().join(" ")
}

/// Security probes in one VM, plus a second VM as a neighbour to reach.
#[test]
#[ignore = "boots VMs; run with `cargo vmtest`"]
fn probes() {
    let _lock = serial();
    let peer = Vm::new("peer");
    peer.create();
    let peer_ip = peer.guest_ok("hostname -I | awk '{print $1}'").trim().to_string();
    peer.guest_ok(&format!(
        "setsid nohup perl -MIO::Socket::INET -e '$s = IO::Socket::INET->new(LocalPort => {PEER_PORT}, Listen => 5, ReuseAddr => 1) or die; \
         while ($c = $s->accept) {{ open F, \">>/tmp/peer.log\"; print F \"hit\\n\"; close F }}' >/dev/null 2>&1 &"
    ));

    let vm = Vm::new("probe");
    vm.create();
    assert_no_leaks("after create");

    let (port, hits) = host_listener();
    let script = format!(
        "REPO_DIR={}\nHOST_PORT={port}\nHOST_IPS='{}'\nPEER_IP={peer_ip}\nPEER_PORT={PEER_PORT}\n{PROBES}",
        vm.repo_dir(),
        host_ips()
    );
    let (_, out) = vm.guest(&script);
    println!("{out}");
    let failed: Vec<&str> = out.lines().filter(|l| l.starts_with("FAIL")).collect();
    let passed = out.lines().filter(|l| l.starts_with("PASS")).count();

    assert!(failed.is_empty(), "probes failed:\n{}", failed.join("\n"));
    assert!(passed >= 30, "only {passed} probes passed; did the script run?\n{out}");
    assert_eq!(hits.load(Ordering::SeqCst), 0, "the guest reached a host port");
    assert_eq!(peer.guest_ok("cat /tmp/peer.log 2>/dev/null; true").trim(), "", "the guest reached another VM");
    // The peer's listener works: it is reachable from inside the peer.
    peer.guest_ok(&format!("echo x >/dev/tcp/127.0.0.1/{PEER_PORT}"));
    assert_no_leaks("after the probes");

    // Denials show up in `weichzelle logs`.
    let logs = vm.wz_ok(&["logs", &vm.name, "--egress"]);
    assert!(logs.contains("example.com"), "{logs}");
}

/// Create, restart, reconcile, rebuild and destroy one VM.
#[test]
#[ignore = "boots VMs; run with `cargo vmtest`"]
fn lifecycle() {
    let _lock = serial();
    let vm = Vm::new("life");
    vm.create();
    let repo = vm.repo_dir();

    // The saved config still has the format reconcile.rs edits.
    vm.wz_ok(&["stop", &vm.name]);
    check_fixture(&vm);
    vm.wz_ok(&["start", &vm.name]);

    // Provisioning is idempotent and keeps the agent's own settings.
    vm.guest_ok("jq '.myKey = 1' ~/.claude.json > /tmp/c && mv /tmp/c ~/.claude.json");
    std::fs::create_dir_all(vm.herdr_config_path().parent().unwrap()).unwrap();
    std::fs::write(vm.herdr_config_path(), "# wzherdr-copied\n").unwrap();
    vm.edit_config(|c| c["herdr"]["copy_config"] = true.into());
    vm.wz_ok(&["restart", &vm.name]);
    let out = vm.guest_ok(&format!(
        "jq -r '.myKey, .hasCompletedOnboarding, .projects[\"{repo}\"].hasTrustDialogAccepted' ~/.claude.json; \
         git config --global user.name; cat ~/.config/herdr/config.toml"
    ));
    assert_eq!(out.lines().collect::<Vec<_>>(), ["1", "true", "true", "weichzelle test", "# wzherdr-copied"], "{out}");
    vm.edit_config(|c| c["herdr"]["copy_config"] = false.into());

    // A config change doesn't touch a running VM, but it says so.
    assert!(!vm.can_fetch("https://example.com"));
    vm.edit_config(|c| {
        c["network"]["allow"].as_array_mut().unwrap().push("example.com".into());
        let extra = toml::Table::from_iter([
            ("source".to_string(), "env:WZT_EXTRA".into()),
            ("hosts".to_string(), vec!["example.com"].into()),
        ]);
        c["secrets"].as_table_mut().unwrap().insert("EXTRA_TOKEN".into(), extra.into());
    });
    let out = vm.wz_ok(&["start", &vm.name]);
    assert!(out.contains("note: network.allow and secrets"), "{out}");
    assert!(!vm.can_fetch("https://example.com"));

    // `restart` applies it, both ways.
    let out = vm.wz_ok(&["restart", &vm.name]);
    assert!(out.contains("applying changed network.allow and secrets"), "{out}");
    assert!(vm.can_fetch("https://example.com"));
    assert_eq!(vm.guest_ok("echo \"$EXTRA_TOKEN\"").trim(), "$MSB_EXTRA_TOKEN");
    assert_no_leaks("after adding a secret");

    vm.edit_config(|c| {
        c["network"]["allow"].as_array_mut().unwrap().retain(|v| v.as_str() != Some("example.com"));
        c["secrets"].as_table_mut().unwrap().remove("EXTRA_TOKEN");
    });
    vm.wz_ok(&["restart", &vm.name]);
    assert!(!vm.can_fetch("https://example.com"));
    assert_eq!(vm.guest_ok("echo \"${EXTRA_TOKEN-unset}\"").trim(), "unset");
    assert!(vm.wz_ok(&["start", &vm.name]).lines().all(|l| !l.starts_with("note:")));

    // Pushing with the injected token, if a real one is given.
    if std::env::var("WZ_TEST_GH_TOKEN").is_ok() {
        let branch = format!("wz-test-{}", vm.name);
        vm.guest_ok(&format!(
            "cd {repo} && git switch -c {branch} && git commit -q --allow-empty -m test \
             && git push -q origin {branch} && git push -q origin --delete {branch} && git switch -q main"
        ));
    } else {
        eprintln!("skipping the push test: WZ_TEST_GH_TOKEN is not set");
    }

    // Rebuild refuses to drop work that isn't on GitHub.
    vm.guest_ok(&format!("echo x > {repo}/dirty.txt"));
    let (ok, out) = vm.wz(&["rebuild", &vm.name]);
    assert!(!ok && out.contains("not on GitHub") && out.contains("dirty.txt"), "{out}");
    assert!(vm.guest_ok(&format!("ls {repo}")).contains("dirty.txt"));
    vm.wz_ok(&["rebuild", &vm.name, "--force"]);
    assert!(!vm.guest_ok(&format!("ls {repo}")).contains("dirty.txt"));

    // Destroy removes the VM and its disks.
    vm.wz_ok(&["destroy", &vm.name]);
    assert!(!env().sandboxes().contains(&vm.vm()));
    assert!(!vm.sandbox_dir().exists(), "{} still exists", vm.sandbox_dir().display());
}

/// `doctor` on a healthy VM, then with Docker down, a config change, a
/// stopped VM and a missing secret. It must never change anything.
#[test]
#[ignore = "boots VMs; run with `cargo vmtest`"]
fn doctor() {
    let _lock = serial();
    let vm = Vm::new("doc");
    // `doctor` reports a missing herdr as an error.
    vm.edit_config(|c| {
        c["tools"].as_table_mut().unwrap().insert("herdr".into(), "latest".into());
    });
    vm.create();
    let has = |out: &str, line: &str| out.lines().any(|l| l.trim_start().starts_with(line));

    // Healthy: no errors, and the only warning allowed is the known denials
    // from provisioning (herdr.dev, downloads.claude.ai).
    let out = vm.wz_ok(&["doctor", &vm.name]);
    for line in [
        "OK    running",
        "OK    saved config has the 0.7.8 format",
        "OK    network.allow and secrets match config.toml",
        "OK    built from the current Containerfile",
        "OK    repo cloned",
        "OK    global tools installed",
        "OK    herdr runs",
        "OK    dockerd answers",
        "OK    CA wrapper installed over runc",
        "OK    root disk under 90% full",
        "OK    Docker disk under 90% full",
    ] {
        assert!(has(&out, line), "missing `{line}`:\n{out}");
    }
    let unexpected: Vec<_> =
        out.lines().filter(|l| l.contains("ERROR") || (l.contains("WARN") && !l.contains("egress denials"))).collect();
    assert!(unexpected.is_empty(), "{out}");

    // Docker down and a config change: warnings, still exit 0.
    vm.guest_ok(
        "sudo pkill -x dockerd; for _ in $(seq 20); do pgrep -x dockerd >/dev/null || exit 0; sleep 0.5; done; exit 1",
    );
    vm.edit_config(|c| c["network"]["allow"].as_array_mut().unwrap().push("example.com".into()));
    let out = vm.wz_ok(&["doctor", &vm.name]);
    assert!(has(&out, "WARN  dockerd answers"), "{out}");
    assert!(has(&out, "WARN  network.allow changed in config.toml since it started"), "{out}");
    assert!(!vm.can_fetch("https://example.com"), "doctor applied the config");

    // Stopped: in-VM checks skipped, and doctor doesn't boot it.
    vm.wz_ok(&["stop", &vm.name]);
    let out = vm.wz_ok(&["doctor", &vm.name]);
    assert!(has(&out, "SKIP  in-VM checks"), "{out}");
    assert!(has(&out, "OK    network.allow changed in config.toml; applies on the next start"), "{out}");
    let (_, list) = vm.wz(&["list"]);
    assert!(list.lines().any(|l| l.starts_with(&vm.name) && l.contains("Stopped")), "{list}");

    // A missing secret is an error: exit 1, value never printed.
    vm.edit_config(|c| c["secrets"]["GH_TOKEN"]["source"] = "env:WZT_MISSING".into());
    let (ok, out) = vm.wz(&["doctor", &vm.name]);
    assert!(!ok, "{out}");
    assert!(has(&out, "ERROR secret GH_TOKEN"), "{out}");
    assert!(!out.contains(harness::LEAK), "{out}");

    // Still unchanged: the saved policy differs from config.toml.
    vm.edit_config(|c| c["secrets"]["GH_TOKEN"]["source"] = "env:WZT_GH".into());
    let out = vm.wz_ok(&["doctor", &vm.name]);
    assert!(has(&out, "OK    network.allow changed in config.toml"), "{out}");
    assert!(env().sandboxes().contains(&vm.vm()));
}

/// Compare the live saved config's shape with the fixture's, or rewrite the
/// fixture (`WZ_UPDATE_FIXTURE=1`).
fn check_fixture(vm: &Vm) {
    let (config, status) = saved_row(&env().msb_home.join("db/msb.db"), &vm.vm());
    if std::env::var("WZ_UPDATE_FIXTURE").is_ok_and(|v| v == "1") {
        write_fixture(vm, &config, &status);
        eprintln!("rewrote {FIXTURE}");
        return;
    }
    let (fixture, _) = saved_row(std::path::Path::new(FIXTURE), "wz-fixture");
    let shape = |text: &str| keys(&serde_json::from_str(text).unwrap());
    assert_eq!(
        shape(&config),
        shape(&fixture),
        "microsandbox's saved config format changed: review reconcile.rs, then run \
         WZ_UPDATE_FIXTURE=1 cargo vmtest lifecycle"
    );
}

/// Every key path in a JSON value; arrays merge their elements.
fn keys(v: &Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    fn walk(v: &Value, path: &str, out: &mut BTreeSet<String>) {
        match v {
            Value::Object(m) => {
                for (k, v) in m {
                    let p = format!("{path}.{k}");
                    out.insert(p.clone());
                    walk(v, &p, out);
                }
            }
            Value::Array(a) => a.iter().for_each(|v| walk(v, &format!("{path}[]"), out)),
            _ => {}
        }
    }
    walk(v, "", &mut out);
    out
}

fn block_on<T>(f: impl Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(f)
}

fn saved_row(db: &std::path::Path, vm: &str) -> (String, String) {
    use sqlx::Connection;
    block_on(async {
        let options = sqlx::sqlite::SqliteConnectOptions::new().filename(db).read_only(true);
        let mut db = sqlx::SqliteConnection::connect_with(&options).await.unwrap();
        sqlx::query_as("SELECT config, status FROM sandbox WHERE name = ?").bind(vm).fetch_one(&mut db).await.unwrap()
    })
}

/// A database with just the `sandbox` row reconcile.rs reads, renamed to
/// `wz-fixture` and with host paths replaced.
fn write_fixture(vm: &Vm, config: &str, status: &str) {
    use sqlx::Connection;
    let home = std::env::var("HOME").unwrap();
    let config = config
        .replace(&env().msb_home.display().to_string(), "/msb-home")
        .replace(&home, "/home/user")
        .replace(&vm.vm(), "wz-fixture")
        .replace(&vm.name, "fixture");
    assert!(!config.contains(harness::LEAK));
    let _ = std::fs::remove_file(FIXTURE);
    std::fs::create_dir_all(std::path::Path::new(FIXTURE).parent().unwrap()).unwrap();
    block_on(async {
        let options = sqlx::sqlite::SqliteConnectOptions::new().filename(FIXTURE).create_if_missing(true);
        let mut db = sqlx::SqliteConnection::connect_with(&options).await.unwrap();
        sqlx::query("CREATE TABLE sandbox (name TEXT PRIMARY KEY, config TEXT NOT NULL, status TEXT NOT NULL)")
            .execute(&mut db)
            .await
            .unwrap();
        sqlx::query("INSERT INTO sandbox (name, config, status) VALUES ('wz-fixture', ?, ?)")
            .bind(config)
            .bind(status)
            .execute(&mut db)
            .await
            .unwrap();
        db.close().await.unwrap();
    });
}
