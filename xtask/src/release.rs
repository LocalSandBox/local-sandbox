use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use lsb_platform::{default_data_dir, PlatformSpec};
use semver::Version;
use toml_edit::{value, DocumentMut};

use crate::args::{flag_value, required_flag_value, resolve_platform};
use crate::context::{resolved_data_dir, run_command, workspace_root};

const RELEASE_CRATES: &[&str] = &[
    "lsb-cli",
    "lsb-guest",
    "lsb-platform",
    "lsb-proto",
    "lsb-proxy",
    "lsb-sdk",
    "lsb-store",
    "lsb-vm",
];
const VERSIONED_WORKSPACE_DEPENDENCIES: &[&str] = &[
    "lsb-platform",
    "lsb-proto",
    "lsb-proxy",
    "lsb-sdk",
    "lsb-store",
    "lsb-vm",
];
const WORKSPACE_MANIFESTS: &[&str] = &[
    "crates/lsb-cli/Cargo.toml",
    "crates/lsb-guest/Cargo.toml",
    "crates/lsb-platform/Cargo.toml",
    "crates/lsb-proto/Cargo.toml",
    "crates/lsb-proxy/Cargo.toml",
    "crates/lsb-sdk/Cargo.toml",
    "crates/lsb-store/Cargo.toml",
    "crates/lsb-vm/Cargo.toml",
];
const NODE_CARGO_MANIFEST: &str = "bindings/nodejs/Cargo.toml";
const NODE_PACKAGE_MANIFESTS: &[&str] = &[
    "bindings/nodejs/package.json",
    "bindings/nodejs/npm/darwin-arm64/package.json",
    "bindings/nodejs/npm/darwin-x64/package.json",
    "bindings/nodejs/npm/win32-x64-msvc/package.json",
];

pub fn release(args: &[String]) -> Result<()> {
    let Some(command) = args.first().map(String::as_str) else {
        bail!("usage: release <current|prepare|verify>");
    };

    match command {
        "current" => {
            if args.len() != 1 {
                bail!("usage: release current");
            }
            println!("{}", canonical_version(&workspace_root())?);
            Ok(())
        }
        "prepare" => {
            let Some(selector) = args.get(1) else {
                bail!("usage: release prepare <patch|minor|major|X.Y.Z>");
            };
            if args.len() != 2 {
                bail!("usage: release prepare <patch|minor|major|X.Y.Z>");
            }
            prepare_release(selector)
        }
        "verify" => verify_release(flag_value(&args[1..], "--version")),
        other => bail!("unknown release command: {other}"),
    }
}

fn prepare_release(selector: &str) -> Result<()> {
    let root = workspace_root();
    let current = verify_release_tree(&root, None)?;
    let target = next_version(&current, selector)?;

    let mut root_manifest = read_toml(&root.join("Cargo.toml"))?;
    root_manifest["workspace"]["package"]["version"] = value(target.to_string());
    for dependency in VERSIONED_WORKSPACE_DEPENDENCIES {
        let dependency = root_manifest["workspace"]["dependencies"][dependency]
            .as_inline_table_mut()
            .with_context(|| {
                format!("workspace dependency {dependency} must be an inline table")
            })?;
        dependency.insert("version", target.to_string().into());
    }

    let mut node_manifest = read_toml(&root.join(NODE_CARGO_MANIFEST))?;
    node_manifest["package"]["version"] = value(target.to_string());

    let mut lockfile = read_toml(&root.join("Cargo.lock"))?;
    let packages = lockfile["package"]
        .as_array_of_tables_mut()
        .context("Cargo.lock is missing package entries")?;
    for crate_name in RELEASE_CRATES {
        let package = packages
            .iter_mut()
            .find(|package| package["name"].as_str() == Some(crate_name))
            .with_context(|| format!("Cargo.lock is missing {crate_name}"))?;
        package["version"] = value(target.to_string());
    }

    let mut writes = vec![
        (root.join("Cargo.toml"), root_manifest.to_string()),
        (root.join(NODE_CARGO_MANIFEST), node_manifest.to_string()),
        (root.join("Cargo.lock"), lockfile.to_string()),
    ];
    for relative_path in NODE_PACKAGE_MANIFESTS {
        let path = root.join(relative_path);
        let mut manifest: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&path)
                .with_context(|| format!("failed to read {}", path.display()))?,
        )
        .with_context(|| format!("failed to parse {}", path.display()))?;
        manifest["version"] = serde_json::Value::String(target.to_string());
        let mut contents = serde_json::to_string_pretty(&manifest)?;
        contents.push('\n');
        writes.push((path, contents));
    }

    for (path, contents) in writes {
        fs::write(&path, contents)
            .with_context(|| format!("failed to update {}", path.display()))?;
    }

    verify_release_tree(&root, Some(&target))?;
    println!("Prepared release v{target}");
    Ok(())
}

fn verify_release(expected: Option<&str>) -> Result<()> {
    let root = workspace_root();
    let expected = expected.map(parse_stable_version).transpose()?;
    let version = verify_release_tree(&root, expected.as_ref())?;
    println!("Release version {version} is consistent");
    Ok(())
}

fn verify_release_tree(root: &Path, expected: Option<&Version>) -> Result<Version> {
    let version = canonical_version(root)?;
    if let Some(expected) = expected {
        if &version != expected {
            bail!("canonical version is {version}, expected {expected}");
        }
    }

    let root_manifest = read_toml(&root.join("Cargo.toml"))?;
    for dependency in VERSIONED_WORKSPACE_DEPENDENCIES {
        let dependency_version = root_manifest["workspace"]["dependencies"][dependency]["version"]
            .as_str()
            .with_context(|| format!("workspace dependency {dependency} is missing a version"))?;
        if dependency_version != version.to_string() {
            bail!(
                "workspace dependency {dependency} has version {dependency_version}, expected {version}"
            );
        }
    }

    for relative_path in WORKSPACE_MANIFESTS {
        let manifest = read_toml(&root.join(relative_path))?;
        if manifest["package"]["version"]["workspace"].as_bool() != Some(true) {
            bail!("{relative_path} must inherit package.version from the workspace");
        }
        if let Some(dependencies) = manifest["dependencies"].as_table() {
            for (name, dependency) in dependencies {
                if VERSIONED_WORKSPACE_DEPENDENCIES.contains(&name)
                    && dependency["workspace"].as_bool() != Some(true)
                {
                    bail!("{relative_path} dependency {name} must inherit from the workspace");
                }
            }
        }
    }

    let node_manifest = read_toml(&root.join(NODE_CARGO_MANIFEST))?;
    verify_string_version(
        NODE_CARGO_MANIFEST,
        node_manifest["package"]["version"].as_str(),
        &version,
    )?;

    for relative_path in NODE_PACKAGE_MANIFESTS {
        let path = root.join(relative_path);
        let manifest: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&path)
                .with_context(|| format!("failed to read {}", path.display()))?,
        )
        .with_context(|| format!("failed to parse {}", path.display()))?;
        verify_string_version(relative_path, manifest["version"].as_str(), &version)?;
    }

    let lockfile = read_toml(&root.join("Cargo.lock"))?;
    let packages = lockfile["package"]
        .as_array_of_tables()
        .context("Cargo.lock is missing package entries")?;
    for crate_name in RELEASE_CRATES {
        let package = packages
            .iter()
            .find(|package| package["name"].as_str() == Some(crate_name))
            .with_context(|| format!("Cargo.lock is missing {crate_name}"))?;
        verify_string_version(
            &format!("Cargo.lock package {crate_name}"),
            package["version"].as_str(),
            &version,
        )?;
    }

    Ok(version)
}

fn canonical_version(root: &Path) -> Result<Version> {
    let manifest = read_toml(&root.join("Cargo.toml"))?;
    let raw = manifest["workspace"]["package"]["version"]
        .as_str()
        .context("Cargo.toml is missing workspace.package.version")?;
    parse_stable_version(raw)
}

fn read_toml(path: &Path) -> Result<DocumentMut> {
    fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?
        .parse::<DocumentMut>()
        .with_context(|| format!("failed to parse {}", path.display()))
}

fn verify_string_version(label: &str, actual: Option<&str>, expected: &Version) -> Result<()> {
    let actual = actual.with_context(|| format!("{label} is missing a version"))?;
    if actual != expected.to_string() {
        bail!("{label} has version {actual}, expected {expected}");
    }
    Ok(())
}

fn parse_stable_version(raw: &str) -> Result<Version> {
    let version = Version::parse(raw)
        .with_context(|| format!("invalid release version '{raw}'; expected X.Y.Z"))?;
    if !version.pre.is_empty() || !version.build.is_empty() {
        bail!("release versions must not contain prerelease or build metadata: {raw}");
    }
    Ok(version)
}

fn next_version(current: &Version, selector: &str) -> Result<Version> {
    let mut target = current.clone();
    match selector {
        "patch" => target.patch += 1,
        "minor" => {
            target.minor += 1;
            target.patch = 0;
        }
        "major" => {
            target.major += 1;
            target.minor = 0;
            target.patch = 0;
        }
        exact => target = parse_stable_version(exact)?,
    }
    if target <= *current {
        bail!("release version {target} must be greater than current version {current}");
    }
    Ok(target)
}

pub fn platform_meta(args: &[String]) -> Result<()> {
    let platform = resolve_platform(args)?;
    let version = flag_value(args, "--version");
    let format = flag_value(args, "--format").unwrap_or("json");

    match format {
        "json" => {
            let mut payload = serde_json::Map::new();
            payload.insert("platform".into(), serde_json::to_value(platform)?);
            if let Some(version) = version {
                payload.insert(
                    "cli_tarball".into(),
                    serde_json::Value::String(platform.cli_tarball_name(version)),
                );
                payload.insert(
                    "os_image_tarball".into(),
                    serde_json::Value::String(platform.os_image_tarball_name(version)),
                );
                payload.insert(
                    "release_tag".into(),
                    serde_json::Value::String(platform.release_tag(version)),
                );
            }
            if platform.id == "windows-x86_64" {
                payload.insert(
                    "managed_qemu".into(),
                    serde_json::to_value(
                        lsb_platform::windows_x86_64::host_tools::managed_qemu_package_metadata(),
                    )?,
                );
            }
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
        "env" => {
            print_env(platform, version);
        }
        other => bail!("unsupported --format value: {other}"),
    }

    Ok(())
}

pub fn package_release(args: &[String]) -> Result<()> {
    let platform = resolve_platform(args)?;
    let artifact = required_flag_value(args, "--artifact")?;
    let version = required_flag_value(args, "--version")?;
    let root = workspace_root();
    let output_dir = PathBuf::from(flag_value(args, "--output-dir").unwrap_or("."));
    let output_dir = if output_dir.is_absolute() {
        output_dir
    } else {
        root.join(output_dir)
    };

    fs::create_dir_all(&output_dir)?;

    match artifact {
        "cli" => package_cli(platform, version, &root, &output_dir),
        "os-image" => package_os_image(platform, version, &output_dir),
        other => bail!("unsupported --artifact value: {other}"),
    }
}

fn print_env(platform: &PlatformSpec, version: Option<&str>) {
    println!("LSB_PLATFORM_ID={}", platform.id);
    println!("LSB_HOST_TARGET={}", platform.host_target);
    println!("LSB_CLI_BINARY={}", platform.cli_binary_name());
    println!("LSB_GUEST_TARGET={}", platform.guest_target);
    println!("LSB_DOCKER_PLATFORM={}", platform.docker_platform);
    println!("LSB_KERNEL_ARCH={}", platform.kernel_arch);
    println!("LSB_DEBOOTSTRAP_ARCH={}", platform.debootstrap_arch);
    println!("LSB_DEFAULT_DATA_DIR={}", default_data_dir());
    if let Some(entitlements) = platform.codesign_entitlements {
        println!("LSB_CODESIGN_ENTITLEMENTS={entitlements}");
    }
    if let Some(version) = version {
        println!("LSB_RELEASE_TAG={}", platform.release_tag(version));
        println!("LSB_CLI_TARBALL={}", platform.cli_tarball_name(version));
        println!(
            "LSB_OS_IMAGE_TARBALL={}",
            platform.os_image_tarball_name(version)
        );
    }
    if platform.id == "windows-x86_64" {
        let qemu = lsb_platform::windows_x86_64::host_tools::managed_qemu_package_metadata();
        println!("LSB_MANAGED_QEMU_PLATFORM={}", qemu.platform);
        println!("LSB_MANAGED_QEMU_VERSION={}", qemu.qemu_version);
        println!("LSB_MANAGED_QEMU_LSB_VERSION={}", qemu.lsb_version);
        println!(
            "LSB_MANAGED_QEMU_PACKAGE_REVISION={}",
            qemu.package_revision
        );
        println!("LSB_MANAGED_QEMU_PACKAGE_VERSION={}", qemu.package_version);
        println!("LSB_MANAGED_QEMU_RELEASE_TAG={}", qemu.release_tag);
        println!("LSB_MANAGED_QEMU_TARBALL={}", qemu.tarball_name);
        println!("LSB_MANAGED_QEMU_URL={}", qemu.artifact_url);
        println!("LSB_MANAGED_QEMU_SHA256={}", qemu.artifact_sha256);
        println!("LSB_MANAGED_QEMU_TOP_LEVEL_DIR={}", qemu.top_level_dir);
    }
}

fn package_cli(
    platform: &PlatformSpec,
    version: &str,
    root: &Path,
    output_dir: &Path,
) -> Result<()> {
    let tarball = output_dir.join(platform.cli_tarball_name(version));
    run_tar(
        root,
        &tarball,
        &["-C", "target/release", platform.cli_binary_name()],
    )
}

fn package_os_image(platform: &PlatformSpec, version: &str, output_dir: &Path) -> Result<()> {
    let data_dir = resolved_data_dir();
    let tarball = output_dir.join(platform.os_image_tarball_name(version));
    run_tar(
        &data_dir,
        &tarball,
        &["Image", "initramfs.cpio.gz", "rootfs.ext4"],
    )
}

fn run_tar(base_dir: &Path, tarball: &Path, extra_args: &[&str]) -> Result<()> {
    run_command(
        Command::new("tar")
            .arg("czf")
            .arg(tarball)
            .args(extra_args)
            .current_dir(base_dir),
        &format!("create tarball {}", tarball.display()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_selectors_increment_semver() {
        let current = Version::parse("0.4.6").unwrap();

        assert_eq!(
            next_version(&current, "patch").unwrap().to_string(),
            "0.4.7"
        );
        assert_eq!(
            next_version(&current, "minor").unwrap().to_string(),
            "0.5.0"
        );
        assert_eq!(
            next_version(&current, "major").unwrap().to_string(),
            "1.0.0"
        );
        assert_eq!(
            next_version(&current, "0.6.2").unwrap().to_string(),
            "0.6.2"
        );
    }

    #[test]
    fn release_version_must_advance_and_be_stable() {
        let current = Version::parse("0.4.6").unwrap();

        assert!(next_version(&current, "0.4.6").is_err());
        assert!(next_version(&current, "0.4.5").is_err());
        assert!(next_version(&current, "0.5.0-rc.1").is_err());
        assert!(next_version(&current, "v0.5.0").is_err());
    }
}
