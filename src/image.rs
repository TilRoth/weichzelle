//! Build the global Containerfile on the host and import it into microsandbox.
//!
//! The image tag is derived from the Containerfile's hash, so editing the
//! Containerfile produces a new image on the next create or rebuild.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use microsandbox::Image;
use sha2::{Digest, Sha256};

use crate::config;

/// Image reference for the current Containerfile.
pub fn reference() -> Result<String> {
    let path = config::containerfile_path()?;
    let content = std::fs::read(&path)
        .with_context(|| format!("cannot read {} (run `weichzelle init`)", path.display()))?;
    let hash = hex::encode(Sha256::digest(&content));
    Ok(format!("localhost/weichzelle-base:{}", &hash[..12]))
}

fn builder() -> Result<&'static str> {
    for tool in ["podman", "buildah", "docker"] {
        let found = Command::new(tool)
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success());
        if found {
            return Ok(tool);
        }
    }
    bail!("no image builder found: install podman (e.g. `sudo apt install podman`)")
}

fn run(cmd: &mut Command) -> Result<()> {
    let status = cmd.status().with_context(|| format!("cannot run {cmd:?}"))?;
    if !status.success() {
        bail!("{cmd:?} failed with {status}");
    }
    Ok(())
}

/// Make sure the image for the current Containerfile is in microsandbox's cache.
pub async fn ensure() -> Result<String> {
    let reference = reference()?;
    if Image::get(&reference).await.is_ok() {
        return Ok(reference);
    }
    let containerfile = config::containerfile_path()?;
    let context_dir = containerfile.parent().unwrap_or(Path::new("."));
    let tool = builder()?;
    println!("building base image {reference} with {tool}…");

    let archive_dir = config::state_dir()?.join("images");
    std::fs::create_dir_all(&archive_dir)?;
    let archive = archive_dir.join("base.tar");

    let mut build = Command::new(tool);
    match tool {
        "buildah" => build.args(["bud", "--layers"]),
        _ => build.arg("build"),
    };
    run(build.arg("-t").arg(&reference).arg("-f").arg(&containerfile).arg(context_dir))?;

    let mut save = Command::new(tool);
    match tool {
        "buildah" => save.arg("push").arg(&reference).arg(format!("oci-archive:{}", archive.display())),
        "podman" => save.args(["save", "--format", "oci-archive", "-o"]).arg(&archive).arg(&reference),
        _ => save.args(["save", "-o"]).arg(&archive).arg(&reference),
    };
    run(&mut save)?;

    Image::load(&archive, vec![reference.clone()])
        .await
        .context("cannot import the image into microsandbox")?;
    let _ = std::fs::remove_file(&archive);
    Ok(reference)
}
