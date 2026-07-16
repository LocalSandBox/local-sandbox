use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};

use crate::ledger::schema::ResourceRecord;
use crate::paths::ServicePaths;
use crate::resource::transaction::ResourceTransaction;
use crate::session::ResourceHandle;
use crate::windows::job::{JobLimits, SandboxJob};
use crate::windows::process::ContainedProcess;

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

pub struct ServiceEngine {
    config: ServiceEngineConfig,
}

impl ServiceEngine {
    pub fn new(config: ServiceEngineConfig) -> Self {
        Self { config }
    }

    pub fn launch_managed_qemu(
        &self,
        arguments: &[OsString],
        working_directory: &Path,
        limits: JobLimits,
        transaction: &mut ResourceTransaction,
    ) -> Result<RunningQemu> {
        require_below(working_directory, self.config.resources_root())
            .context("QEMU working directory escapes protected resources")?;
        let relative_image = self
            .config
            .qemu_executable()
            .strip_prefix(self.config.bundle_root())
            .context("QEMU image is not relative to verified bundle")?
            .display()
            .to_string();
        let job_id = ResourceHandle::random()?.to_string();
        let intent = transaction.intent(ResourceRecord::QemuProcess {
            pid: 0,
            creation_time: 0,
            image_relative_path: relative_image.clone(),
            job_id: job_id.clone(),
            committed: false,
        })?;
        let job = SandboxJob::create(limits)?;
        let process = ContainedProcess::spawn_suspended_into_job(
            &job,
            self.config.qemu_executable(),
            arguments,
            working_directory,
        )?;
        let pid = process.id();
        let creation_time = process.creation_time()?;
        transaction.replace_and_commit(
            intent,
            ResourceRecord::QemuProcess {
                pid,
                creation_time,
                image_relative_path: relative_image,
                job_id: job_id.clone(),
                committed: true,
            },
        )?;
        Ok(RunningQemu {
            job_id,
            job,
            process,
        })
    }
}

pub struct RunningQemu {
    pub job_id: String,
    job: SandboxJob,
    process: ContainedProcess,
}

impl RunningQemu {
    pub fn process_id(&self) -> u32 {
        self.process.id()
    }

    pub fn stop(&self) -> Result<()> {
        self.job.terminate(1)
    }

    pub fn wait(&self, timeout: Duration) -> Result<Option<u32>> {
        self.process.wait(timeout)
    }
}

impl std::fmt::Debug for RunningQemu {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RunningQemu")
            .field("job_id", &self.job_id)
            .field("process_id", &self.process.id())
            .finish_non_exhaustive()
    }
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
