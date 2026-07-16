use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};

use crate::paths::ServicePaths;

#[derive(Debug, Clone)]
pub struct ServiceEngineConfig {
    bundle_root: PathBuf,
    qemu_executable: PathBuf,
    resources_root: PathBuf,
    operation_timeout: Duration,
}

impl ServiceEngineConfig {
    pub fn from_verified_bundle(
        bundle_root: PathBuf,
        qemu_executable: PathBuf,
        service_paths: &ServicePaths,
    ) -> Result<Self> {
        if !bundle_root.is_absolute() || !qemu_executable.is_absolute() {
            bail!("trusted engine paths must be absolute");
        }
        require_below(&qemu_executable, &bundle_root)
            .context("QEMU executable escapes verified bundle")?;
        if qemu_executable.file_name().and_then(|name| name.to_str())
            != Some("qemu-system-x86_64.exe")
        {
            bail!("trusted engine QEMU path has an unexpected filename");
        }
        service_paths.require_below_root(&service_paths.users)?;
        Ok(Self {
            bundle_root,
            qemu_executable,
            resources_root: service_paths.users.clone(),
            operation_timeout: Duration::from_secs(60),
        })
    }

    pub fn bundle_root(&self) -> &Path {
        &self.bundle_root
    }

    pub fn qemu_executable(&self) -> &Path {
        &self.qemu_executable
    }

    pub fn resources_root(&self) -> &Path {
        &self.resources_root
    }

    pub fn operation_timeout(&self) -> Duration {
        self.operation_timeout
    }
}

fn require_below(path: &Path, root: &Path) -> Result<()> {
    let normalize = |path: &Path| {
        path.as_os_str()
            .to_string_lossy()
            .trim_end_matches(['\\', '/'])
            .replace('/', "\\")
            .to_lowercase()
    };
    let path = normalize(path);
    let root = normalize(root);
    if path == root
        || !path
            .strip_prefix(&root)
            .is_some_and(|suffix| suffix.starts_with('\\'))
    {
        bail!("path is not a child of the trusted root");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_rejects_runtime_selection_outside_verified_bundle() {
        let program_data = std::env::temp_dir().join("lsbsw-engine-state");
        let paths = ServicePaths::for_test(program_data);
        let bundle = PathBuf::from(r"C:\Program Files\SeaWork\LocalSandbox\versions\1");
        assert!(ServiceEngineConfig::from_verified_bundle(
            bundle,
            PathBuf::from(r"C:\Users\caller\qemu-system-x86_64.exe"),
            &paths,
        )
        .is_err());
    }
}
