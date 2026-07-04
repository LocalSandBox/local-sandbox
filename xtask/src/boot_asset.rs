use std::io::Write;
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};
use lsb_platform::PlatformSpec;

use crate::args::{flag_value, resolve_platform};
use crate::context::workspace_root;

const WINDOWS_BOOT_ASSET_KEY_VERSION: &str = "boot-assets-v2";
const WINDOWS_BOOT_ASSET_KEY_INPUTS: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "crates/lsb-guest",
    "crates/lsb-proto",
    "xtask/src/rootfs.rs",
    "xtask/src/kernel.rs",
    "xtask/src/guest.rs",
    "xtask/src/context.rs",
    "xtask/src/args.rs",
    "xtask/src/release.rs",
    "kernel/lsb_x86_64_defconfig",
    "crates/lsb-platform/src/windows_x86_64/mod.rs",
];

pub fn print_boot_asset_key(args: &[String]) -> Result<()> {
    let platform = resolve_platform(args)?;
    let format = flag_value(args, "--format").unwrap_or("plain");
    let key = boot_asset_key_for_platform(platform)?;

    match format {
        "plain" => println!("{key}"),
        "env" => println!("BOOT_ASSET_KEY={key}"),
        other => bail!("unsupported --format value: {other}"),
    }

    Ok(())
}

pub fn boot_asset_key_for_platform(platform: &PlatformSpec) -> Result<String> {
    if platform.id != "windows-x86_64" {
        bail!(
            "boot asset key generation is only defined for windows-x86_64, got {}",
            platform.id
        );
    }

    let tracked_inputs = tracked_input_index_entries()?;
    if tracked_inputs.is_empty() {
        bail!("no tracked files matched the Windows boot asset key inputs");
    }

    let mut payload = Vec::new();
    payload.extend_from_slice(WINDOWS_BOOT_ASSET_KEY_VERSION.as_bytes());
    payload.push(0);
    payload.extend_from_slice(platform.id.as_bytes());
    payload.push(0);
    for input in WINDOWS_BOOT_ASSET_KEY_INPUTS {
        payload.extend_from_slice(input.as_bytes());
        payload.push(0);
    }
    payload.extend_from_slice(&tracked_inputs);

    let digest = git_hash_payload(&payload)?;
    Ok(format!(
        "{WINDOWS_BOOT_ASSET_KEY_VERSION}-{}-{digest}",
        platform.id
    ))
}

fn tracked_input_index_entries() -> Result<Vec<u8>> {
    let root = workspace_root();
    let mut command = Command::new("git");
    command
        .arg("ls-files")
        .arg("-s")
        .arg("-z")
        .arg("--")
        .args(WINDOWS_BOOT_ASSET_KEY_INPUTS)
        .current_dir(&root);

    let output = command
        .output()
        .with_context(|| format!("failed to list tracked files in {}", root.display()))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git ls-files failed: {}", stderr.trim());
    }

    Ok(output.stdout)
}

fn git_hash_payload(payload: &[u8]) -> Result<String> {
    let root = workspace_root();
    let mut child = Command::new("git")
        .arg("hash-object")
        .arg("--stdin")
        .current_dir(&root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to start git hash-object in {}", root.display()))?;

    child
        .stdin
        .take()
        .context("git hash-object stdin was not piped")?
        .write_all(payload)
        .context("failed to write boot asset key payload to git hash-object")?;

    let output = child
        .wait_with_output()
        .context("failed to wait for git hash-object")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git hash-object failed: {}", stderr.trim());
    }

    let digest = String::from_utf8(output.stdout)
        .context("git hash-object output was not valid UTF-8")?
        .trim()
        .to_string();
    if digest.is_empty() || !digest.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("git hash-object returned an invalid digest: {digest}");
    }

    Ok(digest)
}
