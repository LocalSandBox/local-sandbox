use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

pub const MANAGED_QEMU_CURRENT_SCHEMA_VERSION: u32 = 1;
pub const MANAGED_QEMU_MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const MANAGED_QEMU_PLATFORM: &str = "windows-x86_64";
pub const MANAGED_QEMU_QEMU_VERSION: &str = "11.0.50";
pub const MANAGED_QEMU_LSB_VERSION: &str = "0.4.0";
pub const MANAGED_QEMU_PACKAGE_REVISION: &str = "lsb0.4.0";
pub const MANAGED_QEMU_PACKAGE_VERSION: &str = "qemu-11.0.50-lsb0.4.0";
pub const MANAGED_QEMU_RELEASE_TAG: &str = "qemu-windows-x86_64-v11.0.50-lsb0.4.0";
pub const MANAGED_QEMU_TARBALL_NAME: &str = "lsb-qemu-windows-x86_64-qemu-11.0.50-lsb0.4.0.tar.gz";
pub const MANAGED_QEMU_ARTIFACT_URL: &str = "https://github.com/LocalSandBox/local-sandbox/releases/download/qemu-windows-x86_64-v11.0.50-lsb0.4.0/lsb-qemu-windows-x86_64-qemu-11.0.50-lsb0.4.0.tar.gz";
pub const MANAGED_QEMU_ARTIFACT_SHA256: &str =
    "49021ed8481ad8bc3e2d71ab3d088e60414ec2bb78654c96f6da33b2dd0c6251";
pub const MANAGED_QEMU_TOP_LEVEL_DIR: &str = MANAGED_QEMU_PACKAGE_VERSION;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ManagedQemuPackageMetadata {
    pub platform: &'static str,
    pub qemu_version: &'static str,
    pub lsb_version: &'static str,
    pub package_revision: &'static str,
    pub package_version: &'static str,
    pub release_tag: &'static str,
    pub tarball_name: &'static str,
    pub artifact_url: &'static str,
    pub artifact_sha256: &'static str,
    pub top_level_dir: &'static str,
}

pub fn managed_qemu_package_metadata() -> ManagedQemuPackageMetadata {
    ManagedQemuPackageMetadata {
        platform: MANAGED_QEMU_PLATFORM,
        qemu_version: MANAGED_QEMU_QEMU_VERSION,
        lsb_version: MANAGED_QEMU_LSB_VERSION,
        package_revision: MANAGED_QEMU_PACKAGE_REVISION,
        package_version: MANAGED_QEMU_PACKAGE_VERSION,
        release_tag: MANAGED_QEMU_RELEASE_TAG,
        tarball_name: MANAGED_QEMU_TARBALL_NAME,
        artifact_url: MANAGED_QEMU_ARTIFACT_URL,
        artifact_sha256: MANAGED_QEMU_ARTIFACT_SHA256,
        top_level_dir: MANAGED_QEMU_TOP_LEVEL_DIR,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManagedQemuPaths {
    pub data_dir: PathBuf,
    pub tools_dir: PathBuf,
    pub qemu_dir: PathBuf,
    pub package_dir: PathBuf,
    pub current_json: PathBuf,
}

pub fn managed_qemu_paths(data_dir: impl AsRef<Path>) -> ManagedQemuPaths {
    let data_dir = data_dir.as_ref().to_path_buf();
    let tools_dir = data_dir.join("tools");
    let qemu_dir = tools_dir.join("qemu");
    ManagedQemuPaths {
        package_dir: qemu_dir.join(MANAGED_QEMU_PACKAGE_VERSION),
        current_json: qemu_dir.join("current.json"),
        data_dir,
        tools_dir,
        qemu_dir,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedQemuManifest {
    pub schema_version: u32,
    pub package_version: String,
    pub qemu_version: String,
    pub lsb_version: String,
    pub platform: String,
    pub qemu_system_x86_64: String,
    pub qemu_img: String,
    #[serde(default)]
    pub files: Vec<ManagedQemuManifestFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedQemuManifestFile {
    #[serde(alias = "name", alias = "relative_path")]
    pub path: String,
    #[serde(alias = "size")]
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedQemuCurrent {
    pub schema_version: u32,
    pub package_version: String,
    pub artifact_url: String,
    pub artifact_sha256: String,
    pub installed_at_unix_secs: u64,
    pub qemu_system_x86_64: PathBuf,
    pub qemu_img: PathBuf,
    pub manifest: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedQemuInstall {
    pub package_version: String,
    pub package_dir: PathBuf,
    pub qemu_system_x86_64: PathBuf,
    pub qemu_img: PathBuf,
    pub manifest: PathBuf,
    pub current_json: PathBuf,
}

pub fn read_managed_qemu_manifest(path: impl AsRef<Path>) -> Result<ManagedQemuManifest> {
    let path = path.as_ref();
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read managed QEMU manifest '{}'", path.display()))?;
    serde_json::from_str(&contents)
        .with_context(|| format!("failed to parse managed QEMU manifest '{}'", path.display()))
}

pub fn read_managed_qemu_current(path: impl AsRef<Path>) -> Result<ManagedQemuCurrent> {
    let path = path.as_ref();
    let contents = fs::read_to_string(path).with_context(|| {
        format!(
            "failed to read managed QEMU current file '{}'",
            path.display()
        )
    })?;
    serde_json::from_str(&contents).with_context(|| {
        format!(
            "failed to parse managed QEMU current file '{}'",
            path.display()
        )
    })
}

pub fn active_managed_qemu(data_dir: impl AsRef<Path>) -> Option<ManagedQemuInstall> {
    try_active_managed_qemu(data_dir).ok()
}

pub fn try_active_managed_qemu(data_dir: impl AsRef<Path>) -> Result<ManagedQemuInstall> {
    let paths = managed_qemu_paths(data_dir);
    let current = read_managed_qemu_current(&paths.current_json)?;
    let metadata = managed_qemu_package_metadata();

    if current.schema_version != MANAGED_QEMU_CURRENT_SCHEMA_VERSION {
        return Err(anyhow!(
            "managed QEMU current schema version {} is unsupported",
            current.schema_version
        ));
    }
    if current.package_version != metadata.package_version {
        return Err(anyhow!(
            "managed QEMU current package '{}' does not match expected '{}'",
            current.package_version,
            metadata.package_version
        ));
    }
    if current.artifact_url != metadata.artifact_url {
        return Err(anyhow!(
            "managed QEMU current artifact URL does not match this build"
        ));
    }
    if !current
        .artifact_sha256
        .eq_ignore_ascii_case(metadata.artifact_sha256)
    {
        return Err(anyhow!(
            "managed QEMU current artifact sha256 does not match this build"
        ));
    }

    let manifest = read_managed_qemu_manifest(&current.manifest)?;
    if manifest.schema_version != MANAGED_QEMU_MANIFEST_SCHEMA_VERSION {
        return Err(anyhow!(
            "managed QEMU manifest schema version {} is unsupported",
            manifest.schema_version
        ));
    }
    if manifest.package_version != metadata.package_version
        || manifest.platform != metadata.platform
        || manifest.qemu_version != metadata.qemu_version
        || manifest.lsb_version != metadata.lsb_version
    {
        return Err(anyhow!(
            "managed QEMU manifest metadata does not match this build"
        ));
    }

    if !current.qemu_system_x86_64.is_file() {
        return Err(anyhow!(
            "managed QEMU system emulator is missing: '{}'",
            current.qemu_system_x86_64.display()
        ));
    }
    if !current.qemu_img.is_file() {
        return Err(anyhow!(
            "managed QEMU image utility is missing: '{}'",
            current.qemu_img.display()
        ));
    }
    if !current.manifest.is_file() {
        return Err(anyhow!(
            "managed QEMU manifest is missing: '{}'",
            current.manifest.display()
        ));
    }

    Ok(ManagedQemuInstall {
        package_version: current.package_version,
        package_dir: paths.package_dir,
        qemu_system_x86_64: current.qemu_system_x86_64,
        qemu_img: current.qemu_img,
        manifest: current.manifest,
        current_json: paths.current_json,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_qemu_metadata_matches_pinned_artifact_contract() {
        let metadata = managed_qemu_package_metadata();

        assert_eq!(metadata.platform, "windows-x86_64");
        assert_eq!(metadata.qemu_version, "11.0.50");
        assert_eq!(metadata.lsb_version, "0.4.0");
        assert_eq!(metadata.package_revision, "lsb0.4.0");
        assert_eq!(metadata.package_version, "qemu-11.0.50-lsb0.4.0");
        assert_eq!(
            metadata.release_tag,
            "qemu-windows-x86_64-v11.0.50-lsb0.4.0"
        );
        assert_eq!(
            metadata.tarball_name,
            "lsb-qemu-windows-x86_64-qemu-11.0.50-lsb0.4.0.tar.gz"
        );
        assert_eq!(
            metadata.artifact_sha256,
            "49021ed8481ad8bc3e2d71ab3d088e60414ec2bb78654c96f6da33b2dd0c6251"
        );
        assert_eq!(
            metadata.artifact_url,
            "https://github.com/LocalSandBox/local-sandbox/releases/download/qemu-windows-x86_64-v11.0.50-lsb0.4.0/lsb-qemu-windows-x86_64-qemu-11.0.50-lsb0.4.0.tar.gz"
        );
    }

    #[test]
    fn managed_qemu_paths_use_tools_qemu_layout() {
        let paths = managed_qemu_paths(Path::new("/data/lsb"));

        assert_eq!(paths.qemu_dir, PathBuf::from("/data/lsb/tools/qemu"));
        assert_eq!(
            paths.package_dir,
            PathBuf::from("/data/lsb/tools/qemu/qemu-11.0.50-lsb0.4.0")
        );
        assert_eq!(
            paths.current_json,
            PathBuf::from("/data/lsb/tools/qemu/current.json")
        );
    }

    #[test]
    fn manifest_parses_executable_relative_paths_at_package_root() {
        let manifest: ManagedQemuManifest = serde_json::from_str(
            r#"{
              "schema_version": 1,
              "package_version": "qemu-11.0.50-lsb0.4.0",
              "qemu_version": "11.0.50",
              "lsb_version": "0.4.0",
              "platform": "windows-x86_64",
              "qemu_system_x86_64": "qemu-system-x86_64.exe",
              "qemu_img": "qemu-img.exe",
              "files": [
                {
                  "path": "qemu-system-x86_64.exe",
                  "size_bytes": 1,
                  "sha256": "abc"
                }
              ]
            }"#,
        )
        .expect("manifest should parse");

        assert_eq!(manifest.qemu_system_x86_64, "qemu-system-x86_64.exe");
        assert_eq!(manifest.qemu_img, "qemu-img.exe");
        assert_eq!(manifest.files[0].path, "qemu-system-x86_64.exe");
    }
}
