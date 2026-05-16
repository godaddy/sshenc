// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Windows upgrade command: download and install the latest sshenc release zip.

#![allow(clippy::print_stdout, clippy::print_stderr)]

use anyhow::{bail, Context, Result};
use reqwest::blocking::Client;
use serde::Deserialize;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::{env, fs, time::Duration};

#[cfg(target_arch = "x86_64")]
const UPGRADE_ARTIFACT: &str = "sshenc-x86_64-pc-windows-msvc.zip";

#[cfg(target_arch = "aarch64")]
const UPGRADE_ARTIFACT: &str = "sshenc-aarch64-pc-windows-msvc.zip";

/// Files to extract and install, in order.  sshenc.exe is last — it is the
/// running binary, so the rename trick is used for it on every upgrade run.
const UPGRADE_FILES: &[&str] = &[
    "sshenc-keygen.exe",
    "sshenc-agent.exe",
    "gitenc.exe",
    "sshenc-tpm-bridge.exe",
    "sshenc_pkcs11.dll",
    "sshenc.exe",
];

#[derive(Deserialize)]
struct GhRelease {
    tag_name: String,
    assets: Vec<GhAsset>,
}

#[derive(Deserialize)]
struct GhAsset {
    name: String,
    /// API URL — works for both public and private repos with Bearer auth.
    url: String,
}

enum InstallSource {
    Local,
    Scoop { exe: PathBuf },
}

fn detect_install_source() -> InstallSource {
    let cur_exe = env::current_exe().ok();
    let cur_lower = cur_exe
        .as_ref()
        .map(|p| p.to_string_lossy().to_ascii_lowercase());

    if let Ok(userprofile) = env::var("USERPROFILE") {
        let scoop_root = PathBuf::from(&userprofile).join("scoop");
        let scoop_app_dir = scoop_root.join("apps").join("sshenc");
        let running_under_scoop = cur_lower
            .as_ref()
            .is_some_and(|s| s.starts_with(&scoop_root.to_string_lossy().to_ascii_lowercase()));
        if running_under_scoop && scoop_app_dir.exists() {
            let exe = scoop_app_dir.join("current").join("sshenc.exe");
            return InstallSource::Scoop { exe };
        }
    }

    InstallSource::Local
}

fn install_dir() -> Result<PathBuf> {
    let local = env::var("LOCALAPPDATA").context("LOCALAPPDATA not set")?;
    Ok(PathBuf::from(local).join("sshenc").join("bin"))
}

fn read_gh_token() -> Option<String> {
    if let Ok(tok) = env::var("GITHUB_TOKEN") {
        let tok = tok.trim().to_owned();
        if !tok.is_empty() {
            return Some(tok);
        }
    }
    let out = std::process::Command::new("gh")
        .args(["auth", "token"])
        .output()
        .ok()?;
    if out.status.success() {
        String::from_utf8(out.stdout)
            .ok()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
    } else {
        None
    }
}

/// Kill the running sshenc-agent.exe so it releases its open handle before
/// we attempt to overwrite it.
fn kill_agent() {
    drop(
        std::process::Command::new("taskkill")
            .args(["/IM", "sshenc-agent.exe", "/F"])
            .output(),
    );
}

fn extract_from_zip(zip_bytes: &[u8], out_dir: &Path) -> Result<()> {
    let cursor = io::Cursor::new(zip_bytes);
    let mut archive = zip::ZipArchive::new(cursor).context("open zip archive")?;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).context("read zip entry")?;
        let entry_name = entry.name().to_owned();
        let file_name = Path::new(&entry_name)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if UPGRADE_FILES.contains(&file_name.as_str()) {
            let out_path = out_dir.join(&file_name);
            let mut buf = Vec::new();
            entry
                .read_to_end(&mut buf)
                .with_context(|| format!("read {file_name} from zip"))?;
            fs::write(&out_path, &buf).with_context(|| format!("write {}", out_path.display()))?;
        }
    }
    Ok(())
}

/// Copy `source` to `target`, using the rename trick when the target is locked.
fn install_file(source: &Path, target: &Path) -> Result<()> {
    if source.canonicalize().ok() == target.canonicalize().ok() {
        println!("  {} already up-to-date", target.display());
        return Ok(());
    }

    // Sweep stale sidecars left by previous failed upgrade attempts.
    if let Some(dir) = target.parent() {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let s = name.to_string_lossy();
                if s.ends_with(".old") || s.ends_with(".replacing") {
                    drop(fs::remove_file(entry.path()));
                }
            }
        }
    }

    // Try a direct copy first; retry on transient locks (e.g. AV scanner).
    let mut last_err = io::Error::other("not attempted");
    for attempt in 0_u32..5 {
        match fs::copy(source, target) {
            Ok(_) => {
                println!("  installed {}", target.display());
                return Ok(());
            }
            Err(err) => {
                last_err = err;
                if attempt < 4 {
                    std::thread::sleep(Duration::from_millis(100 * u64::from(attempt + 1)));
                }
            }
        }
    }

    // ERROR_SHARING_VIOLATION (32): binary is held open.
    // Windows allows renaming an open executable; the open handles keep
    // pointing at the old inode, so we rename it aside and copy the new
    // binary into its place.
    if last_err.raw_os_error() == Some(32) {
        let ext = target
            .extension()
            .map(|e| e.to_string_lossy().into_owned())
            .unwrap_or_else(|| "bin".to_owned());
        let old = target.with_extension(format!("{ext}.{}.old", std::process::id()));
        if fs::rename(target, &old).is_ok() {
            match fs::copy(source, target) {
                Ok(_) => {
                    drop(fs::remove_file(&old));
                    println!("  installed {} (via rename)", target.display());
                    return Ok(());
                }
                Err(copy_err) => {
                    drop(fs::rename(&old, target));
                    bail!(
                        "could not replace {} — rename succeeded but copy failed: {copy_err:#}",
                        target.display()
                    );
                }
            }
        }
        bail!(
            "could not overwrite {} — it is held open by another process. \
             Close any shells using sshenc or run `taskkill /IM sshenc-agent.exe /F` and retry.",
            target.display()
        );
    }

    Err(last_err).with_context(|| format!("copy {} -> {}", source.display(), target.display()))
}

pub fn run(to_version: Option<String>, force: bool, dry_run: bool) -> Result<()> {
    let user_agent = format!("sshenc/{}", env!("CARGO_PKG_VERSION"));
    let client = Client::builder()
        .user_agent(user_agent)
        .timeout(Duration::from_secs(120))
        .build()
        .context("build HTTP client")?;

    let repo = env!("CARGO_PKG_REPOSITORY");
    let slug = repo.trim_start_matches("https://github.com/");
    let api_base = format!("https://api.github.com/repos/{slug}/releases");
    let api_url = match &to_version {
        Some(v) => format!("{api_base}/tags/v{}", v.trim_start_matches('v')),
        None => format!("{api_base}/latest"),
    };

    let gh_token = read_gh_token();

    print!("Fetching release info... ");
    drop(io::stdout().flush());

    let mut req = client
        .get(&api_url)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28");
    if let Some(ref tok) = gh_token {
        req = req.bearer_auth(tok);
    }
    let release: GhRelease = req
        .send()
        .context("fetch release info")?
        .error_for_status()
        .context("GitHub releases API")?
        .json()
        .context("parse release JSON")?;

    let version = release.tag_name.trim_start_matches('v').to_owned();
    println!("{version}");

    let current = env!("CARGO_PKG_VERSION");
    if current == version && !force {
        println!("Already at {current}. Use --force to reinstall.");
        return Ok(());
    }

    let asset = release
        .assets
        .iter()
        .find(|a| a.name == UPGRADE_ARTIFACT)
        .with_context(|| format!("release {version} has no {UPGRADE_ARTIFACT} asset"))?;

    let bin_dir: PathBuf = match detect_install_source() {
        InstallSource::Scoop { exe } if to_version.is_none() => {
            println!("Detected Scoop install — running `scoop update sshenc`...");
            match std::process::Command::new("scoop")
                .args(["update", "sshenc"])
                .status()
            {
                Ok(s) if s.success() => {
                    println!("Upgraded to {version} via Scoop.");
                    return Ok(());
                }
                Ok(s) => eprintln!(
                    "  scoop update exited {s}; falling back to direct binary replacement\n\
                     (scoop list will show the old version until `scoop update` succeeds)"
                ),
                Err(e) => eprintln!(
                    "  could not run scoop: {e:#}; falling back to direct binary replacement\n\
                     (scoop list will show the old version until `scoop update` succeeds)"
                ),
            }
            exe.parent()
                .with_context(|| format!("scoop exe has no parent: {}", exe.display()))?
                .to_path_buf()
        }
        InstallSource::Scoop { exe } => {
            eprintln!(
                "  note: Scoop metadata will show the previously installed version;\n\
                 run `scoop update sshenc` to re-sync."
            );
            exe.parent()
                .with_context(|| format!("scoop exe has no parent: {}", exe.display()))?
                .to_path_buf()
        }
        InstallSource::Local => install_dir()?,
    };

    if dry_run {
        println!("Would download: {}", asset.url);
        println!("Would install to: {}", bin_dir.display());
        return Ok(());
    }

    println!("Downloading {UPGRADE_ARTIFACT} ({version})...");
    let mut dl_req = client
        .get(&asset.url)
        .header("Accept", "application/octet-stream");
    if let Some(tok) = gh_token.as_deref() {
        dl_req = dl_req.bearer_auth(tok);
    }
    let bytes = dl_req
        .send()
        .context("download request")?
        .error_for_status()
        .context("download zip")?
        .bytes()
        .context("read zip bytes")?;
    println!("  {} bytes", bytes.len());

    let tmp_dir = env::temp_dir().join(format!("sshenc-upgrade-{}", std::process::id()));
    fs::create_dir_all(&tmp_dir).context("create temp dir")?;
    extract_from_zip(&bytes, &tmp_dir)?;

    fs::create_dir_all(&bin_dir).with_context(|| format!("create {}", bin_dir.display()))?;

    kill_agent();

    println!("Installing to {}...", bin_dir.display());
    for name in UPGRADE_FILES {
        let src = tmp_dir.join(name);
        if !src.exists() {
            // Absent from this release; skip silently.
            continue;
        }
        let dst = bin_dir.join(name);
        install_file(&src, &dst)?;
    }

    drop(fs::remove_dir_all(&tmp_dir));

    println!();
    if current != version {
        println!("Upgraded {current} \u{2192} {version}.");
    } else {
        println!("Reinstalled {version}.");
    }
    println!("  Binaries: {}", bin_dir.display());
    Ok(())
}
