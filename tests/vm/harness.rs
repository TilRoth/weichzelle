//! Test VMs in an isolated microsandbox home.
//!
//! Everything lives under `~/.cache/weichzelle-test`: microsandbox's state
//! (`MSB_HOME`), one weichzelle config dir per VM (`XDG_CONFIG_HOME`) and the
//! image archive (`XDG_DATA_HOME`). The runtime binaries come from the normal
//! `~/.microsandbox` install. Real VMs, config and keyring are never touched.

use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Dummy secret values start with this, so a leak is easy to find.
pub const LEAK: &str = "wzleak";
const FIXTURE_REPO: &str = "https://github.com/TilRoth/weichzelle-fixture";
const CONFIG: &str = include_str!("../../assets/config.toml");
const CONTAINERFILE: &str = include_str!("../../assets/Containerfile");

pub struct Env {
    pub root: PathBuf,
    pub msb_home: PathBuf,
    runtime: PathBuf,
}

/// The shared test environment. Removes VMs left from earlier runs.
pub fn env() -> &'static Env {
    static ENV: OnceLock<Env> = OnceLock::new();
    ENV.get_or_init(|| {
        let home = PathBuf::from(std::env::var("HOME").expect("HOME"));
        let root = home.join(".cache/weichzelle-test");
        let env = Env { msb_home: root.join("msb"), runtime: home.join(".microsandbox"), root };
        assert!(env.runtime.join("bin/msb").exists(), "microsandbox runtime missing in ~/.microsandbox");
        std::fs::create_dir_all(&env.msb_home).unwrap();
        env.sweep();
        env
    })
}

/// VM tests boot real VMs; run them one at a time even without `--test-threads=1`.
pub fn serial() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

impl Env {
    fn apply(&self, cmd: &mut Command) {
        cmd.env("MSB_HOME", &self.msb_home)
            .env("MSB_PATH", self.runtime.join("bin/msb"))
            .env("MSB_LIBKRUNFW_PATH", self.runtime.join("lib/libkrunfw.so"))
            .env("XDG_DATA_HOME", self.root.join("data"));
    }

    pub fn msb(&self, args: &[&str]) -> Output {
        let mut cmd = Command::new(self.runtime.join("bin/msb"));
        cmd.args(args);
        self.apply(&mut cmd);
        cmd.output().expect("cannot run msb")
    }

    /// Sandbox names in the test home.
    pub fn sandboxes(&self) -> Vec<String> {
        let out = self.msb(&["ls"]);
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .skip(1)
            .filter_map(|l| l.split_whitespace().next())
            .filter(|n| n.starts_with("wz-"))
            .map(str::to_string)
            .collect()
    }

    /// Remove every VM and config dir left in the test home.
    fn sweep(&self) {
        for name in self.sandboxes() {
            eprintln!("removing leftover test VM {name}");
            self.msb(&["rm", "-f", "-q", &name]);
        }
        for entry in std::fs::read_dir(&self.root).unwrap().flatten() {
            if entry.file_name().to_string_lossy().starts_with("vm-") {
                std::fs::remove_dir_all(entry.path()).unwrap();
            }
        }
    }

    /// Files under `MSB_HOME` that contain `needle`. Skips the image cache
    /// and the guest's disks: what the guest sees is checked inside it.
    pub fn files_containing(&self, needle: &str) -> Vec<PathBuf> {
        let mut hits = Vec::new();
        let mut stack = vec![self.msb_home.clone()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap().flatten() {
                let path = entry.path();
                let Ok(meta) = std::fs::symlink_metadata(&path) else { continue };
                if meta.is_dir() {
                    if path != self.msb_home.join("cache") && path.file_name().unwrap() != "rootfs" {
                        stack.push(path);
                    }
                    continue;
                }
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if !meta.is_file() || matches!(ext, "raw" | "ext4" | "erofs" | "img") {
                    continue;
                }
                if let Ok(bytes) = std::fs::read(&path)
                    && bytes.windows(needle.len()).any(|w| w == needle.as_bytes())
                {
                    hits.push(path);
                }
            }
        }
        hits
    }
}

fn unique() -> String {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    format!("{:x}", (nanos as u64) ^ (std::process::id() as u64) << 40)
}

/// A test VM with its own weichzelle config. Removed on success, kept on
/// failure for debugging (the next run sweeps it).
pub struct Vm {
    /// weichzelle's name for it (`t-…`); microsandbox's is `wz-` + this.
    pub name: String,
    pub dir: PathBuf,
    /// Dummy secret values and other env for weichzelle.
    pub vars: Vec<(String, String)>,
}

impl Vm {
    /// A config like the default one, with dummy env secrets, only `gh` as a
    /// global tool, and a sentinel the guest must never see.
    pub fn new(label: &str) -> Vm {
        let env = env();
        let id = unique();
        let name = format!("t-{label}-{}", &id[id.len() - 6..]);
        let dir = env.root.join(format!("vm-{name}"));
        let wz_dir = dir.join("weichzelle");
        std::fs::create_dir_all(&wz_dir).unwrap();
        std::fs::write(wz_dir.join("Containerfile"), CONTAINERFILE).unwrap();

        let mut vars = vec![
            ("WZT_CLAUDE".to_string(), format!("{LEAK}-claude-{id}")),
            ("WZT_GH".to_string(), format!("{LEAK}-gh-{id}")),
            ("WZT_EXTRA".to_string(), format!("{LEAK}-extra-{id}")),
        ];
        let gh_source = match std::env::var("WZ_TEST_GH_TOKEN") {
            Ok(token) => {
                vars.push(("WZT_REAL_GH".into(), token));
                "env:WZT_REAL_GH"
            }
            Err(_) => "env:WZT_GH",
        };
        let vm = Vm { name, dir, vars };
        vm.edit_config(|c| {
            c["git"]["name"] = "weichzelle test".into();
            c["git"]["email"] = "test@weichzelle.invalid".into();
            c["tools"] = toml::Table::from_iter([("gh".to_string(), "latest".into())]).into();
            c["secrets"]["CLAUDE_CODE_OAUTH_TOKEN"]["source"] = "env:WZT_CLAUDE".into();
            c["secrets"]["GH_TOKEN"]["source"] = gh_source.into();
        });
        vm
    }

    pub fn vm(&self) -> String {
        format!("wz-{}", self.name)
    }

    pub fn config_path(&self) -> PathBuf {
        self.dir.join("weichzelle/config.toml")
    }

    /// The host's herdr config, as weichzelle sees it.
    pub fn herdr_config_path(&self) -> PathBuf {
        self.dir.join("herdr/config.toml")
    }

    /// Change the config. The file also carries a sentinel comment.
    pub fn edit_config(&self, f: impl FnOnce(&mut toml::Table)) {
        let path = self.config_path();
        let text = std::fs::read_to_string(&path).unwrap_or_else(|_| CONFIG.to_string());
        let mut table: toml::Table = toml::from_str(&text).unwrap();
        f(&mut table);
        let text = format!("# {}\n{}", self.host_sentinel(), toml::to_string(&table).unwrap());
        std::fs::write(path, text).unwrap();
    }

    /// Appears only in host-side files; the guest must never see it.
    pub fn host_sentinel(&self) -> String {
        format!("wzhostcfg-{}", self.name)
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_weichzelle"));
        cmd.args(args).env("XDG_CONFIG_HOME", &self.dir).envs(self.vars.iter().map(|(k, v)| (k, v)));
        env().apply(&mut cmd);
        cmd
    }

    /// Run weichzelle; returns success and the combined output.
    pub fn wz(&self, args: &[&str]) -> (bool, String) {
        let out = self.command(args).output().expect("cannot run weichzelle");
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        (out.status.success(), text)
    }

    /// Run weichzelle, which must succeed.
    pub fn wz_ok(&self, args: &[&str]) -> String {
        let (ok, text) = self.wz(args);
        assert!(ok, "weichzelle {} failed:\n{text}", args.join(" "));
        text
    }

    pub fn create(&self) {
        self.wz_ok(&["create", FIXTURE_REPO, "--name", &self.name]);
    }

    pub fn repo_dir(&self) -> String {
        format!("/work/{}", self.name)
    }

    /// Run a bash script in the guest as the agent user, with the VM's env
    /// (secret placeholders). Returns the exit code and combined output.
    pub fn guest(&self, script: &str) -> (i32, String) {
        use base64_lite::encode;
        let cmd = format!("echo {} | base64 -d | bash", encode(script.as_bytes()));
        let out = env().msb(&["exec", &self.vm(), "--", "sudo", "-E", "-H", "-u", "insasse", "bash", "-c", &cmd]);
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        (out.status.code().unwrap_or(-1), text)
    }

    /// Run a guest script that must succeed; returns its output.
    pub fn guest_ok(&self, script: &str) -> String {
        let (code, out) = self.guest(script);
        assert_eq!(code, 0, "guest script failed:\n{script}\n---\n{out}");
        out
    }

    /// Whether the guest can fetch `url` over HTTPS.
    pub fn can_fetch(&self, url: &str) -> bool {
        self.guest(&format!("curl -fsS --max-time 15 -o /dev/null {url}")).0 == 0
    }

    pub fn sandbox_dir(&self) -> PathBuf {
        env().msb_home.join("sandboxes").join(self.vm())
    }
}

impl Drop for Vm {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "kept {} for debugging: MSB_HOME={} msb exec {} -- bash",
                self.vm(),
                env().msb_home.display(),
                self.vm()
            );
            return;
        }
        env().msb(&["rm", "-f", "-q", &self.vm()]);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

pub fn assert_no_leaks(what: &str) {
    let hits = env().files_containing(LEAK);
    assert!(hits.is_empty(), "dummy secret values on disk {what}: {hits:#?}");
}

/// Minimal base64, to avoid a dependency for one call.
mod base64_lite {
    const ABC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub fn encode(data: &[u8]) -> String {
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
            let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(ABC[(n >> (18 - 6 * i) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }
}
