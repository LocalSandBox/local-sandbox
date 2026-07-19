use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServicePaths {
    pub root: PathBuf,
    pub config: PathBuf,
    pub product_ca_bundle: PathBuf,
    pub ledger: PathBuf,
    pub pending_update: PathBuf,
    pub users: PathBuf,
    pub quarantine: PathBuf,
    pub runtime: PathBuf,
    pub logs: PathBuf,
}

impl ServicePaths {
    pub fn discover() -> Result<Self> {
        Self::from_program_data(program_data()?)
    }

    fn from_program_data(program_data: PathBuf) -> Result<Self> {
        if !program_data.is_absolute() {
            bail!("ProgramData known-folder path is not absolute");
        }
        let root = program_data.join("LocalSandbox").join("SeaWork");
        Ok(Self {
            config: root.join("config").join("service.json"),
            product_ca_bundle: root.join("config").join("product-ca.pem"),
            ledger: root.join("state").join("ledger"),
            pending_update: root.join("state").join("pending-update.json"),
            users: root.join("state").join("users"),
            quarantine: root.join("state").join("quarantine"),
            runtime: root.join("runtime"),
            logs: root.join("logs"),
            root,
        })
    }

    pub fn prepare(&self) -> Result<()> {
        for path in [
            self.config.parent().context("config path has no parent")?,
            self.ledger.as_path(),
            self.users.as_path(),
            self.quarantine.as_path(),
            self.runtime.as_path(),
            self.logs.as_path(),
        ] {
            std::fs::create_dir_all(path)
                .with_context(|| format!("create protected service path {}", path.display()))?;
            self.require_below_root(path)?;
        }
        Ok(())
    }

    pub fn require_below_root(&self, path: &Path) -> Result<()> {
        if !path.starts_with(&self.root) {
            bail!("path escapes fixed service root: {}", path.display());
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn for_test(root: PathBuf) -> Self {
        Self::from_program_data(root).expect("absolute test root")
    }
}

#[cfg(windows)]
fn program_data() -> Result<PathBuf> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use std::ptr;

    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath};

    let mut raw = ptr::null_mut();
    let result =
        unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, ptr::null_mut(), &mut raw) };
    if result < 0 {
        bail!("SHGetKnownFolderPath(ProgramData) failed: HRESULT 0x{result:08x}");
    }
    let len = (0..)
        .take_while(|index| unsafe { *raw.add(*index) } != 0)
        .count();
    let path = PathBuf::from(OsString::from_wide(unsafe {
        std::slice::from_raw_parts(raw, len)
    }));
    unsafe { CoTaskMemFree(raw.cast()) };
    Ok(path)
}

#[cfg(not(windows))]
fn program_data() -> Result<PathBuf> {
    bail!("ProgramData is available only on Windows")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_only_fixed_paths() {
        let base = std::env::temp_dir().join("lsbsw-path-test");
        let paths = ServicePaths::for_test(base.clone());
        assert_eq!(paths.root, base.join("LocalSandbox").join("SeaWork"));
        assert!(paths.config.starts_with(&paths.root));
        assert!(paths.product_ca_bundle.starts_with(&paths.root));
        assert!(paths.ledger.starts_with(&paths.root));
        assert!(paths.pending_update.starts_with(&paths.root));
        assert!(paths.require_below_root(&base.join("elsewhere")).is_err());
    }
}
