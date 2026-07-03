use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::QemuPreflightError;

pub(crate) const LSB_QEMU_ENV: &str = "LSB_QEMU";
pub(crate) const QEMU_SYSTEM_X86_64_EXE: &str = "qemu-system-x86_64.exe";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum QemuPathSource {
    Env,
    Config,
    Path,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct QemuPath {
    pub path: PathBuf,
    pub source: QemuPathSource,
}

pub(crate) trait QemuDiscoveryHost {
    fn env_var(&self, name: &str) -> Option<OsString>;
    fn path_entries(&self) -> Vec<PathBuf>;
    fn is_file(&self, path: &Path) -> bool;
    fn canonicalize(&self, path: &Path) -> Option<PathBuf>;
    fn host_os(&self) -> String;
    fn host_arch(&self) -> String;
    fn windows_major_version(&self) -> Option<u32>;
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct StdQemuDiscoveryHost;

impl QemuDiscoveryHost for StdQemuDiscoveryHost {
    fn env_var(&self, name: &str) -> Option<OsString> {
        env::var_os(name)
    }

    fn path_entries(&self) -> Vec<PathBuf> {
        env::var_os("PATH")
            .map(|path| env::split_paths(&path).collect())
            .unwrap_or_default()
    }

    fn is_file(&self, path: &Path) -> bool {
        fs::metadata(path)
            .map(|metadata| metadata.is_file())
            .unwrap_or(false)
    }

    fn canonicalize(&self, path: &Path) -> Option<PathBuf> {
        fs::canonicalize(path).ok()
    }

    fn host_os(&self) -> String {
        env::consts::OS.to_string()
    }

    fn host_arch(&self) -> String {
        env::consts::ARCH.to_string()
    }

    fn windows_major_version(&self) -> Option<u32> {
        None
    }
}

#[derive(Debug)]
pub(crate) struct QemuDiscovery<'host, H>
where
    H: QemuDiscoveryHost,
{
    host: &'host H,
    configured_qemu: Option<PathBuf>,
}

impl<'host, H> QemuDiscovery<'host, H>
where
    H: QemuDiscoveryHost,
{
    pub(crate) fn new(host: &'host H) -> Self {
        Self {
            host,
            configured_qemu: None,
        }
    }

    pub(crate) fn with_configured_qemu(mut self, path: impl Into<PathBuf>) -> Self {
        self.configured_qemu = Some(path.into());
        self
    }

    pub(crate) fn host(&self) -> &'host H {
        self.host
    }

    pub(crate) fn discover(&self) -> Result<QemuPath, QemuPreflightError> {
        if let Some(path) = self.host.env_var(LSB_QEMU_ENV) {
            return self.validate_explicit_env_path(PathBuf::from(path));
        }

        if let Some(path) = &self.configured_qemu {
            return self.validate_config_path(path.clone());
        }

        let path_entries = self.host.path_entries();
        for entry in &path_entries {
            let candidate = entry.join(QEMU_SYSTEM_X86_64_EXE);
            if self.host.is_file(&candidate) {
                return Ok(QemuPath {
                    path: self.canonical_or_original(&candidate),
                    source: QemuPathSource::Path,
                });
            }
        }

        Err(QemuPreflightError::QemuNotFound {
            searched_path_entries: path_entries.len(),
        })
    }

    fn validate_explicit_env_path(&self, path: PathBuf) -> Result<QemuPath, QemuPreflightError> {
        self.validate_explicit_path(path, QemuPathSource::Env)
            .map_err(|(path, reason)| QemuPreflightError::EnvQemuPathInvalid {
                env_var: LSB_QEMU_ENV,
                path,
                reason,
            })
    }

    fn validate_config_path(&self, path: PathBuf) -> Result<QemuPath, QemuPreflightError> {
        self.validate_explicit_path(path, QemuPathSource::Config)
            .map_err(|(path, reason)| QemuPreflightError::ConfigQemuPathInvalid { path, reason })
    }

    fn validate_explicit_path(
        &self,
        path: PathBuf,
        source: QemuPathSource,
    ) -> Result<QemuPath, (PathBuf, String)> {
        if path.as_os_str().is_empty() {
            return Err((path, "path is empty".to_string()));
        }
        if !self.host.is_file(&path) {
            return Err((path, "path does not exist or is not a file".to_string()));
        }
        Ok(QemuPath {
            path: self.canonical_or_original(&path),
            source,
        })
    }

    fn canonical_or_original(&self, path: &Path) -> PathBuf {
        self.host
            .canonicalize(path)
            .unwrap_or_else(|| path.to_path_buf())
    }
}
