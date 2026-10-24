mod config;
mod image;
mod logs;
mod network;
mod secrets;
mod vm;

use anyhow::Result;
use clap::{Parser, Subcommand};

/// A long-running VM sandbox per GitHub repo for coding agents.
#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Write the default config and Containerfile to ~/.config/weichzelle.
    Init,
    /// Create a VM with a fresh clone of a GitHub repo.
    Create {
        url: String,
        #[arg(long)]
        name: Option<String>,
    },
    /// Open herdr in the VM (starts it if stopped).
    Attach { name: String },
    /// Open a bash shell in the VM (starts it if stopped).
    Shell { name: String },
    /// Start a stopped VM.
    Start { name: String },
    /// Stop a running VM. Its disk is kept.
    Stop { name: String },
    /// Wipe the VM and its clone, then recreate it from the current image.
    Rebuild {
        name: String,
        /// Skip the unpushed-work check.
        #[arg(long)]
        force: bool,
    },
    /// Delete the VM and its clone.
    Destroy {
        name: String,
        /// Skip the unpushed-work check.
        #[arg(long)]
        force: bool,
    },
    /// List weichzelle VMs.
    List,
    /// Show what the VM tried to reach and was denied.
    Logs {
        name: String,
        /// Egress denials (currently the only log).
        #[arg(long, required = true)]
        egress: bool,
    },
    /// Manage secret values in the OS keyring.
    Secret {
        #[command(subcommand)]
        command: SecretCmd,
    },
}

#[derive(Subcommand)]
enum SecretCmd {
    /// Store a value (prompted, or read from stdin).
    Set { name: String },
    /// Remove a stored value.
    Delete { name: String },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Cmd::Init => return config::init(),
        Cmd::Secret { command: SecretCmd::Set { name } } => return secrets::set(name),
        Cmd::Secret { command: SecretCmd::Delete { name } } => return secrets::delete(name),
        Cmd::Logs { name, .. } => return logs::egress(&vm::vm_name(name), name),
        _ => {}
    }

    let config = config::Config::load()?;
    // Commands that may boot a VM need the real secret values exported first,
    // and that must happen before the async runtime spawns threads.
    let boots_vm = matches!(
        cli.command,
        Cmd::Create { .. } | Cmd::Attach { .. } | Cmd::Shell { .. } | Cmd::Start { .. } | Cmd::Rebuild { .. } | Cmd::Destroy { force: false, .. }
    );
    if boots_vm {
        secrets::export_all(&config.secrets)?;
    }

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(async {
        match cli.command {
            Cmd::Create { url, name } => vm::create(&config, &url, name).await,
            Cmd::Attach { name } => vm::attach(&config, &name).await,
            Cmd::Shell { name } => vm::shell(&config, &name).await,
            Cmd::Start { name } => vm::start(&config, &name).await,
            Cmd::Stop { name } => vm::stop(&name).await,
            Cmd::Rebuild { name, force } => vm::rebuild(&config, &name, force).await,
            Cmd::Destroy { name, force } => vm::destroy(&config, &name, force).await.map(|_| ()),
            Cmd::List => vm::list().await,
            Cmd::Init | Cmd::Secret { .. } | Cmd::Logs { .. } => unreachable!(),
        }
    })
}
