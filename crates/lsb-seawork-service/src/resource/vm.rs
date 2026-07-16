use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use crate::engine::ServiceEngineConfig;
use crate::session::CancellationToken;

#[derive(Debug, Clone)]
pub struct ManagedVmSpec {
    pub instance_dir: PathBuf,
    pub rootfs_image: PathBuf,
    pub cpus: usize,
    pub memory_mib: u64,
}

enum Command {
    Stop(mpsc::SyncSender<Result<()>>),
}

pub struct ManagedVm {
    commands: mpsc::SyncSender<Command>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl std::fmt::Debug for ManagedVm {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ManagedVm").finish_non_exhaustive()
    }
}

impl ManagedVm {
    pub fn start(
        engine: &ServiceEngineConfig,
        spec: ManagedVmSpec,
        cancellation: CancellationToken,
    ) -> Result<Self> {
        validate_spec(engine, &spec)?;
        let engine = engine.clone();
        let (commands, receiver) = mpsc::sync_channel(8);
        let (ready, started) = mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name("lsbsw-managed-vm".to_string())
            .spawn(move || run(engine, spec, cancellation, receiver, ready))
            .context("spawn managed VM thread")?;
        match started
            .recv()
            .context("managed VM thread lost startup reply")?
        {
            Ok(()) => Ok(Self {
                commands,
                thread: Some(thread),
            }),
            Err(error) => {
                let _ = thread.join();
                Err(error)
            }
        }
    }

    pub fn stop(mut self, timeout: Duration) -> Result<()> {
        let (reply, response) = mpsc::sync_channel(1);
        self.commands
            .send(Command::Stop(reply))
            .context("managed VM thread stopped before cleanup")?;
        let result = response
            .recv_timeout(timeout)
            .map_err(|_| anyhow::anyhow!("managed VM stop exceeded bounded deadline"))?;
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| anyhow::anyhow!("managed VM thread panicked"))?;
        }
        result
    }
}

impl Drop for ManagedVm {
    fn drop(&mut self) {
        let finished = self
            .thread
            .as_ref()
            .is_some_and(|thread| thread.is_finished());
        if !finished {
            return;
        }
        let Some(thread) = self.thread.take() else {
            return;
        };
        if thread.join().is_err() {
            std::process::abort();
        }
    }
}

fn run(
    engine: ServiceEngineConfig,
    spec: ManagedVmSpec,
    cancellation: CancellationToken,
    commands: mpsc::Receiver<Command>,
    ready: mpsc::SyncSender<Result<()>>,
) {
    let result = build_and_start(&engine, &spec);
    let Ok(sandbox) = result else {
        let _ = cleanup_instance(&engine, &spec);
        let _ = ready.send(result.map(|_| ()));
        return;
    };
    if ready.send(Ok(())).is_err() {
        let _ = sandbox.stop();
        let _ = cleanup_instance(&engine, &spec);
        return;
    }
    loop {
        if cancellation.is_cancelled() {
            let _ = sandbox.stop();
            let _ = cleanup_instance(&engine, &spec);
            return;
        }
        match commands.recv_timeout(Duration::from_millis(100)) {
            Ok(Command::Stop(reply)) => {
                let result = sandbox
                    .stop()
                    .and_then(|()| cleanup_instance(&engine, &spec));
                let _ = reply.send(result);
                return;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let _ = sandbox.stop();
                let _ = cleanup_instance(&engine, &spec);
                return;
            }
        }
    }
}

fn cleanup_instance(engine: &ServiceEngineConfig, spec: &ManagedVmSpec) -> Result<()> {
    engine.require_resource_path(&spec.instance_dir)?;
    if spec.instance_dir.exists() {
        std::fs::remove_dir_all(&spec.instance_dir).context("remove managed VM instance")?;
    }
    Ok(())
}

fn build_and_start(engine: &ServiceEngineConfig, spec: &ManagedVmSpec) -> Result<lsb_vm::Sandbox> {
    let sandbox = lsb_vm::Sandbox::builder()
        .data_dir(path_text(engine.resources_root())?)
        .service_qemu_executable(path_text(engine.qemu_executable())?)
        .kernel(path_text(engine.kernel_image())?)
        .initrd(path_text(engine.initrd_image())?)
        .rootfs(path_text(&spec.rootfs_image)?)
        .cpus(spec.cpus)
        .memory_mb(spec.memory_mib)
        .console(false)
        .build()?;
    sandbox.start()?;
    Ok(sandbox)
}

fn validate_spec(engine: &ServiceEngineConfig, spec: &ManagedVmSpec) -> Result<()> {
    engine.require_resource_path(&spec.instance_dir)?;
    engine.require_resource_path(&spec.rootfs_image)?;
    if spec.rootfs_image.parent() != Some(spec.instance_dir.as_path()) {
        bail!("managed rootfs must be directly below its protected instance directory");
    }
    if !(1..=16).contains(&spec.cpus) || !(256..=32 * 1024).contains(&spec.memory_mib) {
        bail!("managed VM resource request exceeds compiled bounds");
    }
    Ok(())
}

fn path_text(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_string)
        .context("managed VM path is not valid Unicode")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::ServicePaths;

    #[test]
    fn managed_vm_rejects_caller_paths_and_excess_resources_before_boot() {
        let root = std::env::temp_dir().join("lsbsw-vm-config");
        let paths = ServicePaths::for_test(root.clone());
        let bundle = PathBuf::from(r"C:\Program Files\SeaWork\LocalSandbox\versions\1");
        let engine = ServiceEngineConfig::from_verified_bundle(
            bundle.clone(),
            bundle.join("qemu-system-x86_64.exe"),
            bundle.join("Image"),
            bundle.join("initramfs.cpio.gz"),
            bundle.join("rootfs.ext4"),
            &paths,
        )
        .unwrap();
        let spec = ManagedVmSpec {
            instance_dir: PathBuf::from(r"C:\Users\caller\instance"),
            rootfs_image: PathBuf::from(r"C:\Users\caller\instance\rootfs.ext4"),
            cpus: 100,
            memory_mib: 64,
        };
        assert!(validate_spec(&engine, &spec).is_err());
    }
}
