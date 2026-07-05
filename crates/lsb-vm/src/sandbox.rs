use std::collections::HashMap;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use std::fs;
#[cfg(target_os = "macos")]
use std::io::{BufReader, BufWriter};
use std::io::{Read, Write};
use std::net::TcpStream;
#[cfg(target_os = "macos")]
use std::net::{Shutdown, TcpListener};
#[cfg(target_os = "macos")]
use std::os::fd::AsRawFd;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use std::path::{Path, PathBuf};
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
#[cfg(target_os = "macos")]
use std::time::Duration;

use anyhow::{bail, Context, Result};
use crossbeam_channel::Receiver;
#[cfg(target_os = "macos")]
use lsb_platform::terminal;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use lsb_platform::windows_x86_64::fs::{
    join_guest_child, open_copy_in_file_checked, plan_copy_in, validate_copy_out_destination,
    validate_guest_absolute_path, validate_guest_path_component,
    validate_windows_host_path_lexical, CaseFoldSet, CopyInEntryKind, CopyInFileIdentity,
    CopyInPlan, CopyPathOperation,
};
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use lsb_platform::windows_x86_64::fs::{
    plan_windows_mounts, replan_windows_mount_import, WindowsMountImport, WindowsMountMode,
    WindowsMountSpec,
};
use lsb_platform::PlatformControlStream;
use lsb_platform::{self, PlatformSharedDir, PlatformVm, PlatformVmConfig, VmState};

use lsb_proto::{
    frame, ChmodRequest, CopyRequest, ExecRequest, FsOkResponse, MkdirRequest, MountRequest,
    MountResponse, PortMapping, ReadDirRequest, ReadDirResponse, ReadFileRequest, RemoveRequest,
    RenameRequest, StatRequest, StatResponse, WatchRequest, WriteFileRequest, WriteFileResponse,
    CAP_FILE_RANGE_IO, FILE_TRANSFER_CHUNK_SIZE,
};
#[cfg(target_os = "macos")]
use lsb_proto::{ForwardRequest, ForwardResponse, VSOCK_PORT, VSOCK_PORT_FORWARD};

#[cfg(not(target_os = "macos"))]
#[derive(Debug)]
struct UnsupportedWindowsRuntime {
    capability: &'static str,
    milestone: &'static str,
}

#[cfg(not(target_os = "macos"))]
impl std::fmt::Display for UnsupportedWindowsRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Windows support is in progress: {} is not implemented yet ({}); current Windows runtime support includes VM startup through the M07 guest-ready handshake, non-interactive exec through M08, guest file copy transfer primitives through M09, and overlay mount copy-import semantics through M10",
            self.capability, self.milestone
        )
    }
}

#[cfg(not(target_os = "macos"))]
impl std::error::Error for UnsupportedWindowsRuntime {}

#[cfg(not(target_os = "macos"))]
fn unsupported_runtime(capability: &'static str, milestone: &'static str) -> anyhow::Error {
    UnsupportedWindowsRuntime {
        capability,
        milestone,
    }
    .into()
}

// --- Mount types ---

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
const MS_RDONLY: u64 = 1;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
static COPY_OUT_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub enum MountConfig {
    Overlay {
        host_path: String,
        guest_path: String,
    },
    Direct {
        host_path: String,
        guest_path: String,
        flags: u64,
    },
}

// --- VmConfigBuilder ---

pub struct VmConfigBuilder {
    kernel: Option<String>,
    rootfs: Option<String>,
    initrd: Option<String>,
    cpus: usize,
    memory_mb: u64,
    console: bool,
    verbose: bool,
    network_fd: Option<i32>,
    nbd_uri: Option<String>,
    mounts: Vec<MountConfig>,
}

impl VmConfigBuilder {
    pub(crate) fn new() -> Self {
        VmConfigBuilder {
            kernel: None,
            rootfs: None,
            initrd: None,
            cpus: 2,
            memory_mb: 2048,
            console: true,
            verbose: false,
            network_fd: None,
            nbd_uri: None,
            mounts: Vec::new(),
        }
    }

    /// When false, serial console stdin is disconnected and stdout goes to
    /// stderr. This prevents the serial console from consuming host stdin
    /// in exec/shell mode.
    pub fn console(mut self, enabled: bool) -> Self {
        self.console = enabled;
        self
    }

    /// When true, serial console output (kernel dmesg, initramfs) is shown
    /// even in non-console mode. Default is false (quiet).
    pub fn verbose(mut self, enabled: bool) -> Self {
        self.verbose = enabled;
        self
    }

    pub fn kernel(mut self, path: impl Into<String>) -> Self {
        self.kernel = Some(path.into());
        self
    }

    pub fn rootfs(mut self, path: impl Into<String>) -> Self {
        self.rootfs = Some(path.into());
        self
    }

    pub fn initrd(mut self, path: impl Into<String>) -> Self {
        self.initrd = Some(path.into());
        self
    }

    pub fn cpus(mut self, n: usize) -> Self {
        self.cpus = n;
        self
    }

    pub fn memory_mb(mut self, mb: u64) -> Self {
        self.memory_mb = mb;
        self
    }

    /// Attach a network device via a socketpair fd for proxy-based networking.
    pub fn network_fd(mut self, fd: i32) -> Self {
        self.network_fd = Some(fd);
        self
    }

    pub fn nbd_uri(mut self, uri: impl Into<String>) -> Self {
        self.nbd_uri = Some(uri.into());
        self
    }

    /// Add a host directory mount (virtio-fs).
    pub fn mount(mut self, config: MountConfig) -> Self {
        self.mounts.push(config);
        self
    }

    pub fn build(self) -> Result<Sandbox> {
        let kernel_path = self.kernel.context("kernel path is required")?;
        let rootfs_path = self.rootfs.context("rootfs path is required")?;

        let memory_bytes = self.memory_mb * 1024 * 1024;
        let mount_plan = build_mount_plan(&self.mounts)?;

        Ok(Sandbox {
            vm: lsb_platform::create_vm(PlatformVmConfig {
                kernel_path,
                rootfs_path,
                initrd_path: self.initrd,
                cpus: self.cpus,
                memory_bytes,
                console: self.console,
                verbose: self.verbose,
                network_fd: self.network_fd,
                nbd_uri: self.nbd_uri,
                shared_dirs: mount_plan.shared_dirs,
            })?,
            mounts: Mutex::new(mount_plan.mount_requests),
            #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
            windows_mounts: Mutex::new(mount_plan.windows_imports),
            #[cfg(not(target_os = "macos"))]
            control_session: Mutex::new(()),
        })
    }
}

// --- Sandbox ---

pub struct Sandbox {
    vm: Arc<dyn PlatformVm>,
    mounts: Mutex<Vec<MountRequest>>,
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    windows_mounts: Mutex<Vec<WindowsMountImport>>,
    #[cfg(not(target_os = "macos"))]
    control_session: Mutex<()>,
}

struct SandboxMountPlan {
    shared_dirs: Vec<PlatformSharedDir>,
    mount_requests: Vec<MountRequest>,
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    windows_imports: Vec<WindowsMountImport>,
}

fn build_mount_plan(mounts: &[MountConfig]) -> Result<SandboxMountPlan> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        build_windows_mount_plan(mounts)
    }

    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    {
        Ok(build_shared_directory_mount_plan(mounts))
    }
}

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
fn build_shared_directory_mount_plan(mounts: &[MountConfig]) -> SandboxMountPlan {
    let mut mount_requests = Vec::new();
    let mut shared_dirs = Vec::new();

    for (i, mount) in mounts.iter().enumerate() {
        let tag = format!("mount{}", i);
        match mount {
            MountConfig::Overlay {
                host_path,
                guest_path,
            } => {
                shared_dirs.push(PlatformSharedDir {
                    host_path: host_path.clone(),
                    tag: tag.clone(),
                    read_only: true,
                });
                mount_requests.push(MountRequest::Overlay {
                    source: tag,
                    target: guest_path.clone(),
                });
            }
            MountConfig::Direct {
                host_path,
                guest_path,
                flags,
            } => {
                shared_dirs.push(PlatformSharedDir {
                    host_path: host_path.clone(),
                    tag: tag.clone(),
                    read_only: flags & MS_RDONLY != 0,
                });
                mount_requests.push(MountRequest::Direct {
                    source: tag,
                    target: guest_path.clone(),
                    flags: *flags,
                });
            }
        }
    }

    SandboxMountPlan {
        shared_dirs,
        mount_requests,
    }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn build_windows_mount_plan(mounts: &[MountConfig]) -> Result<SandboxMountPlan> {
    let specs = mounts
        .iter()
        .enumerate()
        .map(|(i, mount)| {
            let tag = format!("mount{}", i);
            match mount {
                MountConfig::Overlay {
                    host_path,
                    guest_path,
                } => WindowsMountSpec {
                    tag,
                    host_path: PathBuf::from(host_path),
                    guest_path: guest_path.clone(),
                    mode: WindowsMountMode::Overlay,
                },
                MountConfig::Direct {
                    host_path,
                    guest_path,
                    flags,
                } => WindowsMountSpec {
                    tag,
                    host_path: PathBuf::from(host_path),
                    guest_path: guest_path.clone(),
                    mode: WindowsMountMode::Direct { flags: *flags },
                },
            }
        })
        .collect::<Vec<_>>();
    let plan = plan_windows_mounts(&specs)
        .map_err(|error| anyhow::anyhow!("planning Windows mount imports: {error}"))?;

    Ok(SandboxMountPlan {
        shared_dirs: Vec::new(),
        mount_requests: plan.mount_requests,
        windows_imports: plan.imports,
    })
}

impl Sandbox {
    pub fn builder() -> VmConfigBuilder {
        VmConfigBuilder::new()
    }

    pub fn start(&self) -> Result<()> {
        self.vm.start().context("Failed to start VM")?;

        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        if let Err(error) = self.initialize_windows_mounts() {
            let _ = self.vm.stop();
            return Err(error).context("Failed to initialize Windows mounts");
        }

        Ok(())
    }

    pub fn stop(&self) -> Result<()> {
        self.vm.stop().context("Failed to stop VM")
    }

    pub fn state_channel(&self) -> Receiver<VmState> {
        self.vm.state_channel()
    }

    /// Send pending mount requests over an established guest control connection.
    /// Clears the mount list only after all requests succeed so failed startup
    /// attempts cannot silently drop configured mounts.
    fn send_mount_requests(&self, writer: &mut impl Write, reader: &mut impl Read) -> Result<()> {
        let mut mounts = self.mounts.lock().unwrap();
        for req in mounts.iter() {
            frame::send_json(writer, frame::MOUNT_REQ, req).context("sending mount request")?;
            let (msg_type, payload) =
                read_response_frame(reader, "mount init").context("reading mount response")?;
            if msg_type == frame::ERROR {
                bail!("{}", String::from_utf8_lossy(&payload));
            }
            if msg_type != frame::MOUNT_RESP {
                bail!("unexpected frame type 0x{msg_type:02x} in mount response");
            }
            let resp: MountResponse = match serde_json::from_slice(&payload) {
                Ok(r) => r,
                Err(_) => {
                    bail!(
                        "guest does not support directory mounts. \
                         Run `lsb upgrade` and recreate the checkpoint to enable --mount."
                    );
                }
            };
            if !resp.ok {
                let (source, target) = match req {
                    MountRequest::Overlay { source, target } => (source, target),
                    MountRequest::Direct { source, target, .. } => (source, target),
                };
                bail!(
                    "mount failed: {} -> {}: {}",
                    source,
                    target,
                    resp.error.unwrap_or_else(|| "unknown error".into())
                );
            }
        }
        mounts.clear();
        Ok(())
    }

    /// Run a command non-interactively over vsock, streaming output to the
    /// provided writers. Returns the guest process exit code.
    pub fn exec(
        &self,
        argv: &[impl AsRef<str>],
        stdout: &mut impl Write,
        stderr: &mut impl Write,
    ) -> Result<i32> {
        self.exec_with_env(argv, &HashMap::new(), stdout, stderr)
    }

    pub fn exec_with_env(
        &self,
        argv: &[impl AsRef<str>],
        env: &HashMap<String, String>,
        stdout: &mut impl Write,
        stderr: &mut impl Write,
    ) -> Result<i32> {
        self.exec_with_env_and_cwd(argv, env, None, stdout, stderr)
    }

    pub fn exec_with_env_and_cwd(
        &self,
        argv: &[impl AsRef<str>],
        env: &HashMap<String, String>,
        cwd: Option<&str>,
        stdout: &mut impl Write,
        stderr: &mut impl Write,
    ) -> Result<i32> {
        self.with_guest_control_session("exec", |writer, reader| {
            let req = build_exec_request(argv, env, cwd, None, Some(true));
            send_exec_request(writer, &req)?;
            collect_exec_response(reader, stdout, stderr)
        })
    }

    pub fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        if self.supports_file_range_io() {
            let stat = self.stat(path)?;
            if stat.is_file && stat.size > FILE_TRANSFER_CHUNK_SIZE as u64 {
                return self.read_file_chunked(path, stat.size);
            }
        }

        self.read_file_single(path)
    }

    fn read_file_single(&self, path: &str) -> Result<Vec<u8>> {
        let req = ReadFileRequest {
            path: path.to_string(),
            offset: None,
            len: None,
        };

        self.send_read_file_request(&req)
    }

    fn send_read_file_request(&self, req: &ReadFileRequest) -> Result<Vec<u8>> {
        self.with_guest_control_session("read_file", |writer, reader| {
            frame::send_json(writer, frame::READ_FILE_REQ, req)?;

            let (msg_type, payload) =
                read_response_frame(reader, "read_file").context("reading read_file response")?;
            match msg_type {
                frame::READ_FILE_RESP => Ok(payload),
                frame::ERROR => {
                    bail!("{}", String::from_utf8_lossy(&payload));
                }
                other => {
                    bail!(
                        "unexpected frame type 0x{:02x} in read_file response",
                        other
                    );
                }
            }
        })
    }

    fn read_file_chunked(&self, path: &str, size: u64) -> Result<Vec<u8>> {
        let capacity = usize::try_from(size)
            .map_err(|_| anyhow::anyhow!("read_file '{}' is too large to buffer", path))?;
        let mut out = Vec::with_capacity(capacity);
        let mut offset = 0u64;
        while offset < size {
            let len = std::cmp::min(FILE_TRANSFER_CHUNK_SIZE as u64, size - offset);
            let req = ReadFileRequest {
                path: path.to_string(),
                offset: Some(offset),
                len: Some(len),
            };
            let chunk = self.send_read_file_request(&req)?;
            let chunk_len = validate_read_chunk("read_file", path, offset, len, &chunk, size)?;
            offset += chunk_len;
            out.extend_from_slice(&chunk);
        }
        validate_chunked_transfer_complete("read_file", path, offset, size)?;
        Ok(out)
    }

    pub fn write_file(&self, path: &str, content: &[u8]) -> Result<()> {
        if content.len() > frame::MAX_FRAME_PAYLOAD {
            self.ensure_file_range_io("write_file")?;
            return self.write_file_chunked(path, content);
        }

        let req = WriteFileRequest {
            path: path.to_string(),
            len: content.len() as u64,
            offset: None,
            truncate: None,
        };

        self.send_write_file_request(&req, content)
    }

    fn write_file_chunked(&self, path: &str, content: &[u8]) -> Result<()> {
        if content.is_empty() {
            let req = WriteFileRequest {
                path: path.to_string(),
                len: 0,
                offset: Some(0),
                truncate: Some(true),
            };
            return self.send_write_file_request(&req, &[]);
        }

        let mut offset = 0usize;
        while offset < content.len() {
            let end = std::cmp::min(offset + FILE_TRANSFER_CHUNK_SIZE, content.len());
            let chunk = &content[offset..end];
            let req = WriteFileRequest {
                path: path.to_string(),
                len: chunk.len() as u64,
                offset: Some(offset as u64),
                truncate: Some(offset == 0),
            };
            self.send_write_file_request(&req, chunk)?;
            offset = end;
        }

        Ok(())
    }

    fn send_write_file_request(&self, req: &WriteFileRequest, content: &[u8]) -> Result<()> {
        if content.len() > frame::MAX_FRAME_PAYLOAD {
            bail!(
                "write_file chunk for '{}' is {} bytes, exceeding protocol payload limit {}",
                req.path,
                content.len(),
                frame::MAX_FRAME_PAYLOAD
            );
        }

        self.with_guest_control_session("write_file", |writer, reader| {
            frame::send_json(writer, frame::WRITE_FILE_REQ, req)?;
            frame::write_frame(writer, frame::WRITE_FILE_DATA, content)?;

            let (msg_type, payload) =
                read_response_frame(reader, "write_file").context("reading write_file response")?;
            if msg_type == frame::ERROR {
                bail!("{}", String::from_utf8_lossy(&payload));
            }
            if msg_type != frame::WRITE_FILE_RESP {
                bail!("unexpected frame type 0x{msg_type:02x} in write_file response");
            }

            let resp: WriteFileResponse =
                serde_json::from_slice(&payload).context("parsing write_file response")?;

            if !resp.ok {
                bail!(
                    "write_file failed: {}",
                    resp.error.unwrap_or_else(|| "unknown error".into())
                );
            }

            Ok(())
        })
    }

    /// Send a request and expect FS_OK_RESP or ERROR. Used by void fs ops.
    fn void_fs_op(&self, req_frame: u8, req: &impl serde::Serialize) -> Result<()> {
        self.with_guest_control_session("filesystem operation", |writer, reader| {
            frame::send_json(writer, req_frame, req)?;

            match read_response_frame(reader, "filesystem operation")
                .context("reading fs op response")?
            {
                (frame::FS_OK_RESP, payload) => {
                    let resp: FsOkResponse =
                        serde_json::from_slice(&payload).context("parsing fs ok response")?;
                    if !resp.ok {
                        bail!("{}", resp.error.unwrap_or_else(|| "unknown error".into()));
                    }
                    Ok(())
                }
                (frame::ERROR, payload) => {
                    bail!("{}", String::from_utf8_lossy(&payload));
                }
                (other, _) => {
                    bail!("unexpected frame type 0x{:02x}", other);
                }
            }
        })
    }

    pub fn mkdir(&self, path: &str, recursive: bool) -> Result<()> {
        self.void_fs_op(
            frame::MKDIR_REQ,
            &MkdirRequest {
                path: path.to_string(),
                recursive,
            },
        )
    }

    pub fn read_dir(&self, path: &str) -> Result<ReadDirResponse> {
        let req = ReadDirRequest {
            path: path.to_string(),
        };
        self.with_guest_control_session("read_dir", |writer, reader| {
            frame::send_json(writer, frame::READ_DIR_REQ, &req)?;

            let (msg_type, payload) =
                read_response_frame(reader, "read_dir").context("reading read_dir response")?;
            match msg_type {
                frame::READ_DIR_RESP => {
                    Ok(serde_json::from_slice(&payload).context("parsing read_dir response")?)
                }
                frame::ERROR => {
                    bail!("{}", String::from_utf8_lossy(&payload));
                }
                other => {
                    bail!("unexpected frame type 0x{:02x} in read_dir response", other);
                }
            }
        })
    }

    pub fn stat(&self, path: &str) -> Result<StatResponse> {
        let req = StatRequest {
            path: path.to_string(),
        };
        self.with_guest_control_session("stat", |writer, reader| {
            frame::send_json(writer, frame::STAT_REQ, &req)?;

            let (msg_type, payload) =
                read_response_frame(reader, "stat").context("reading stat response")?;
            match msg_type {
                frame::STAT_RESP => {
                    Ok(serde_json::from_slice(&payload).context("parsing stat response")?)
                }
                frame::ERROR => {
                    bail!("{}", String::from_utf8_lossy(&payload));
                }
                other => {
                    bail!("unexpected frame type 0x{:02x} in stat response", other);
                }
            }
        })
    }

    pub fn remove(&self, path: &str, recursive: bool) -> Result<()> {
        self.void_fs_op(
            frame::REMOVE_REQ,
            &RemoveRequest {
                path: path.to_string(),
                recursive,
            },
        )
    }

    pub fn rename(&self, old_path: &str, new_path: &str) -> Result<()> {
        self.void_fs_op(
            frame::RENAME_REQ,
            &RenameRequest {
                old_path: old_path.to_string(),
                new_path: new_path.to_string(),
            },
        )
    }

    pub fn copy(&self, src: &str, dst: &str, recursive: bool) -> Result<()> {
        self.void_fs_op(
            frame::COPY_REQ,
            &CopyRequest {
                src: src.to_string(),
                dst: dst.to_string(),
                recursive,
            },
        )
    }

    pub fn chmod(&self, path: &str, mode: u32) -> Result<()> {
        self.void_fs_op(
            frame::CHMOD_REQ,
            &ChmodRequest {
                path: path.to_string(),
                mode,
            },
        )
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    pub fn copy_from_host(&self, source: impl AsRef<Path>, guest_destination: &str) -> Result<()> {
        self.ensure_file_range_io("copy-in")?;
        let plan = plan_copy_in(source.as_ref(), guest_destination)?;
        self.copy_from_host_plan(&plan)
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn copy_from_host_plan(&self, plan: &CopyInPlan) -> Result<()> {
        for entry in &plan.entries {
            match &entry.kind {
                CopyInEntryKind::Directory => {
                    self.mkdir(&entry.guest_path, true).with_context(|| {
                        format!("copy-in create guest dir '{}'", entry.guest_path)
                    })?;
                }
                CopyInEntryKind::File { len, identity } => self
                    .copy_host_file_to_guest(&entry.host_path, *len, *identity, &entry.guest_path)
                    .with_context(|| format!("copy-in file to '{}'", entry.guest_path))?,
            }
        }

        Ok(())
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    pub fn copy_to_host(
        &self,
        guest_source: &str,
        host_destination: impl AsRef<Path>,
        overwrite: bool,
    ) -> Result<()> {
        self.ensure_file_range_io("copy-out")?;
        validate_guest_absolute_path(guest_source, CopyPathOperation::CopyOutGuestSource)?;
        let destination = validate_copy_out_destination(host_destination.as_ref(), overwrite)?;
        let stat = self.stat(guest_source)?;
        if stat.is_symlink {
            bail!("copy-out guest source '{}' is a symlink; symlink export is unsupported in the Windows MVP", guest_source);
        }

        if stat.is_file {
            self.copy_guest_file_to_host_atomic(
                guest_source,
                stat.size,
                &destination.path,
                overwrite,
            )
        } else if stat.is_dir {
            self.copy_guest_dir_to_host_atomic(guest_source, &destination.path, overwrite)
        } else {
            bail!(
                "copy-out guest source '{}' is not a regular file or directory",
                guest_source
            );
        }
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn copy_host_file_to_guest(
        &self,
        host_path: &Path,
        expected_len: u64,
        expected_identity: CopyInFileIdentity,
        guest_path: &str,
    ) -> Result<()> {
        let mut file = open_copy_in_file_checked(host_path, expected_len, expected_identity)
            .with_context(|| format!("opening copy-in source '{}'", host_path.display()))?;
        let mut buffer = vec![0u8; FILE_TRANSFER_CHUNK_SIZE];
        let mut offset = 0u64;
        let mut first = true;

        loop {
            let len = file
                .read(&mut buffer)
                .with_context(|| format!("reading copy-in source '{}'", host_path.display()))?;
            if len == 0 {
                if first {
                    self.write_guest_file_range(guest_path, 0, true, &[])?;
                }
                break;
            }
            self.write_guest_file_range(guest_path, offset, first, &buffer[..len])?;
            offset += len as u64;
            first = false;
        }

        Ok(())
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn write_guest_file_range(
        &self,
        guest_path: &str,
        offset: u64,
        truncate: bool,
        content: &[u8],
    ) -> Result<()> {
        let req = WriteFileRequest {
            path: guest_path.to_string(),
            len: content.len() as u64,
            offset: Some(offset),
            truncate: Some(truncate),
        };
        self.send_write_file_request(&req, content)
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn copy_guest_file_to_host_atomic(
        &self,
        guest_path: &str,
        size: u64,
        destination: &Path,
        overwrite: bool,
    ) -> Result<()> {
        let temp_path = temp_sibling_path(destination, "file")?;
        let result = self
            .copy_guest_file_to_host_path(guest_path, size, &temp_path)
            .and_then(|_| {
                replace_with_temp_path(&temp_path, destination, overwrite).with_context(|| {
                    format!("publishing copy-out file '{}'", destination.display())
                })
            });
        if result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        result
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn copy_guest_file_to_host_path(
        &self,
        guest_path: &str,
        size: u64,
        destination: &Path,
    ) -> Result<()> {
        if destination.exists() {
            bail!(
                "copy-out destination '{}' already exists while exporting guest file '{}'",
                destination.display(),
                guest_path
            );
        }
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("creating copy-out parent directory '{}'", parent.display())
            })?;
        }

        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)
            .with_context(|| format!("creating copy-out temp file '{}'", destination.display()))?;
        let mut offset = 0u64;
        while offset < size {
            let len = std::cmp::min(FILE_TRANSFER_CHUNK_SIZE as u64, size - offset);
            let req = ReadFileRequest {
                path: guest_path.to_string(),
                offset: Some(offset),
                len: Some(len),
            };
            let chunk = self.send_read_file_request(&req)?;
            let chunk_len = validate_read_chunk("copy-out", guest_path, offset, len, &chunk, size)?;
            file.write_all(&chunk)
                .with_context(|| format!("writing copy-out file '{}'", destination.display()))?;
            offset += chunk_len;
        }
        validate_chunked_transfer_complete("copy-out", guest_path, offset, size)?;
        file.sync_all()
            .with_context(|| format!("syncing copy-out file '{}'", destination.display()))?;
        Ok(())
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn copy_guest_dir_to_host_atomic(
        &self,
        guest_path: &str,
        destination: &Path,
        overwrite: bool,
    ) -> Result<()> {
        let temp_path = temp_sibling_path(destination, "dir")?;
        fs::create_dir(&temp_path)
            .with_context(|| format!("creating copy-out temp dir '{}'", temp_path.display()))?;

        let result = self
            .copy_guest_dir_to_host_path(guest_path, &temp_path)
            .and_then(|_| {
                replace_with_temp_path(&temp_path, destination, overwrite).with_context(|| {
                    format!("publishing copy-out directory '{}'", destination.display())
                })
            });
        if result.is_err() {
            let _ = fs::remove_dir_all(&temp_path);
        }
        result
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn copy_guest_dir_to_host_path(&self, guest_path: &str, destination: &Path) -> Result<()> {
        validate_guest_absolute_path(guest_path, CopyPathOperation::CopyOutGuestSource)?;
        let entries = self.read_dir(guest_path)?;
        let mut case_fold = CaseFoldSet::default();

        for entry in entries.entries {
            validate_guest_path_component(
                &entry.name,
                CopyPathOperation::CopyOutGuestEntry,
                guest_path,
            )?;
            case_fold.insert(
                &entry.name,
                CopyPathOperation::CopyOutGuestEntry,
                guest_path,
            )?;

            let guest_child = join_guest_child(guest_path, &entry.name);
            let host_child = destination.join(&entry.name);
            validate_windows_host_path_lexical(
                &host_child,
                CopyPathOperation::CopyOutHostDestination,
            )?;
            let stat = self.stat(&guest_child)?;
            if stat.is_symlink {
                bail!(
                    "copy-out guest entry '{}' is a symlink; symlink export is unsupported in the Windows MVP",
                    guest_child
                );
            }

            if stat.is_dir {
                fs::create_dir(&host_child).with_context(|| {
                    format!("creating copy-out directory '{}'", host_child.display())
                })?;
                self.copy_guest_dir_to_host_path(&guest_child, &host_child)?;
            } else if stat.is_file {
                self.copy_guest_file_to_host_path(&guest_child, stat.size, &host_child)?;
            } else {
                bail!(
                    "copy-out guest entry '{}' is not a regular file or directory",
                    guest_child
                );
            }
        }

        Ok(())
    }

    /// Open a vsock connection for streaming exec. Returns the raw stream
    /// after sending mounts + ExecRequest. Caller manages I/O (reads
    /// STDOUT/STDERR/EXIT frames, writes STDIN/KILL frames).
    pub fn open_exec(
        &self,
        argv: &[impl AsRef<str>],
        env: &HashMap<String, String>,
        cwd: Option<&str>,
    ) -> Result<TcpStream> {
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (argv, env, cwd);
            return Err(unsupported_runtime(
                "streaming exec stdin/kill",
                "M11 transport multiplexer; M08 supports non-interactive exec through Sandbox::exec",
            ));
        }

        #[cfg(target_os = "macos")]
        {
            let stream = self.connect_vsock()?;
            let mut writer = stream.try_clone()?;
            let mut reader = stream.try_clone()?;

            self.send_mount_requests(&mut writer, &mut reader)?;

            let req = build_exec_request(argv, env, cwd, None, None);
            send_exec_request(&mut writer, &req)?;

            Ok(stream)
        }
    }

    /// Open a vsock connection for an interactive shell with PTY support.
    /// Like `open_exec` but with `tty=true`. Returns the raw stream after
    /// sending mounts + ExecRequest. Caller manages I/O using the binary
    /// frame protocol (STDIN/STDOUT/RESIZE/EXIT frames).
    pub fn open_shell(
        &self,
        argv: &[impl AsRef<str>],
        env: &HashMap<String, String>,
        rows: u16,
        cols: u16,
    ) -> Result<TcpStream> {
        let stream = self.connect_vsock()?;
        let mut writer = stream.try_clone()?;
        let mut reader = stream.try_clone()?;

        self.send_mount_requests(&mut writer, &mut reader)?;

        let req = ExecRequest {
            argv: argv.iter().map(|s| s.as_ref().to_string()).collect(),
            env: env.clone(),
            tty: Some(true),
            rows: Some(rows),
            cols: Some(cols),
            cwd: None,
            stdin_closed: None,
        };
        frame::send_json(&mut writer, frame::EXEC_REQ, &req)?;

        Ok(stream)
    }

    /// Open a vsock connection for file watching. Returns a stream that
    /// emits WATCH_EVENT frames until the connection is closed.
    pub fn open_watch(&self, path: &str, recursive: bool) -> Result<TcpStream> {
        let stream = self.connect_vsock()?;
        let mut writer = stream.try_clone()?;
        let mut reader = stream.try_clone()?;

        self.send_mount_requests(&mut writer, &mut reader)?;

        let req = WatchRequest {
            path: path.to_string(),
            recursive,
        };
        frame::send_json(&mut writer, frame::WATCH_REQ, &req)?;

        Ok(stream)
    }

    /// Run an interactive shell session with PTY support.
    /// Puts the host terminal in raw mode, relays I/O bidirectionally over
    /// vsock, and handles SIGWINCH for window resize.
    /// Returns the guest process exit code.
    #[cfg(target_os = "macos")]
    pub fn shell(&self, argv: &[impl AsRef<str>], env: &HashMap<String, String>) -> Result<i32> {
        let stdin_fd = std::io::stdin().as_raw_fd();
        let (rows, cols) = terminal::terminal_size(stdin_fd);

        let stream = self.connect_vsock()?;
        let mut writer = stream.try_clone()?;
        let mut reader = stream;

        // Mount phase (sync, before raw mode)
        self.send_mount_requests(&mut writer, &mut reader)?;

        // Send ExecRequest with tty=true
        let req = ExecRequest {
            argv: argv.iter().map(|s| s.as_ref().to_string()).collect(),
            env: env.clone(),
            tty: Some(true),
            rows: Some(rows),
            cols: Some(cols),
            cwd: None,
            stdin_closed: None,
        };
        frame::send_json(&mut writer, frame::EXEC_REQ, &req)?;

        // Enter raw mode - TerminalState restores on drop
        let _raw_guard = terminal::TerminalState::enter_raw_mode(stdin_fd);

        // Set up kqueue-based stdin relay (zero-latency I/O multiplexing)
        let (relay, shutdown_signal) =
            terminal::StdinRelay::new(stdin_fd).expect("failed to init stdin relay");

        let exit_code = Arc::new(Mutex::new(0i32));

        // Thread A: stdin → vsock (kqueue blocks until data/resize/shutdown)
        let mut vsock_writer = writer.try_clone()?;
        let stdin_thread = std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match relay.wait() {
                    terminal::StdinEvent::Ready => {
                        let n = terminal::read_raw(stdin_fd, &mut buf);
                        if n == 0 {
                            break;
                        }
                        if frame::write_frame(&mut vsock_writer, frame::STDIN, &buf[..n]).is_err() {
                            break;
                        }
                    }
                    terminal::StdinEvent::Resize => {
                        let (rows, cols) = terminal::terminal_size(stdin_fd);
                        let payload = frame::resize_payload(rows, cols);
                        if frame::write_frame(&mut vsock_writer, frame::RESIZE, &payload).is_err() {
                            break;
                        }
                    }
                    terminal::StdinEvent::Shutdown => break,
                }
            }
        });

        // Thread B: vsock -> stdout (read binary frames, write raw output)
        // Uses BufWriter + deferred flush to batch rapid TUI updates into
        // fewer terminal writes, preventing visible tearing/flickering.
        let exit_code_b = exit_code.clone();
        let vsock_thread = std::thread::spawn(move || {
            let mut reader = BufReader::new(reader);
            let mut stdout = BufWriter::new(std::io::stdout());
            loop {
                match frame::read_frame(&mut reader) {
                    Ok(Some((frame::STDOUT, payload))) => {
                        let _ = stdout.write_all(&payload);
                        // Only flush to the terminal when no more data is
                        // already buffered from the vsock. This batches
                        // rapid sequential messages (e.g. a full TUI
                        // screen redraw) into a single terminal write.
                        if reader.buffer().is_empty() {
                            let _ = stdout.flush();
                        }
                    }
                    Ok(Some((frame::EXIT, payload))) => {
                        let _ = stdout.flush();
                        *exit_code_b.lock().unwrap() =
                            frame::parse_exit_code(&payload).unwrap_or(0);
                        break;
                    }
                    Ok(Some((frame::ERROR, payload))) => {
                        let _ = stdout.flush();
                        let msg = String::from_utf8_lossy(&payload);
                        let _ = std::io::stderr()
                            .write_all(format!("guest error: {}\r\n", msg).as_bytes());
                        *exit_code_b.lock().unwrap() = 1;
                        break;
                    }
                    Ok(Some(_)) => {} // unknown type, skip
                    Ok(None) | Err(_) => break,
                }
            }
            let _ = stdout.flush();
            shutdown_signal.signal();
        });

        // Wait for threads
        let _ = vsock_thread.join();
        let _ = stdin_thread.join();

        // Terminal restored by _raw_guard drop
        // SIGWINCH restored by StdinRelay drop
        let code = *exit_code.lock().unwrap();
        Ok(code)
    }

    /// Interactive shell support on Windows depends on the future control
    /// transport and PTY work; M01 only guarantees compile-time scaffolding.
    #[cfg(not(target_os = "macos"))]
    pub fn shell(&self, _argv: &[impl AsRef<str>], _env: &HashMap<String, String>) -> Result<i32> {
        Err(unsupported_runtime(
            "interactive shell",
            "M06 virtio-serial control transport and M08 exec",
        ))
    }

    /// Start port forwarding proxies. Returns a handle that stops all
    /// listeners when dropped.
    #[cfg(target_os = "macos")]
    pub fn start_port_forwarding(&self, forwards: &[PortMapping]) -> Result<PortForwardHandle> {
        let stop = Arc::new(AtomicBool::new(false));
        let mut listeners = Vec::new();

        for mapping in forwards {
            let addr = format!("127.0.0.1:{}", mapping.host_port);
            let tcp_listener = TcpListener::bind(&addr)
                .with_context(|| format!("Failed to bind port {}", mapping.host_port))?;
            tcp_listener.set_nonblocking(true)?;

            let guest_port = mapping.guest_port;
            let vm = Arc::clone(&self.vm);
            let stop_flag = stop.clone();

            eprintln!(
                "lsb: forwarding 127.0.0.1:{} -> guest:{}",
                mapping.host_port, mapping.guest_port
            );

            let handle = std::thread::spawn(move || {
                while !stop_flag.load(Ordering::Relaxed) {
                    match tcp_listener.accept() {
                        Ok((tcp_stream, _)) => {
                            // macOS accept() inherits non-blocking from the
                            // listener — force blocking for the relay.
                            let _ = tcp_stream.set_nonblocking(false);
                            let vm = Arc::clone(&vm);
                            std::thread::spawn(move || {
                                if let Err(e) =
                                    handle_forward_connection(tcp_stream, vm.as_ref(), guest_port)
                                {
                                    tracing::debug!("port forward error: {}", e);
                                }
                            });
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(50));
                        }
                        Err(e) => {
                            if !stop_flag.load(Ordering::Relaxed) {
                                tracing::debug!("accept error on port forward listener: {}", e);
                            }
                            break;
                        }
                    }
                }
            });

            listeners.push(handle);
        }

        Ok(PortForwardHandle {
            stop,
            threads: listeners,
        })
    }

    /// Windows port forwarding must preserve no-network-by-default. Until the
    /// transport is implemented, fail before opening any host listener.
    #[cfg(not(target_os = "macos"))]
    pub fn start_port_forwarding(&self, _forwards: &[PortMapping]) -> Result<PortForwardHandle> {
        Err(unsupported_runtime(
            "port forwarding",
            "M11 port forwarding; no listener was opened",
        ))
    }

    fn supports_file_range_io(&self) -> bool {
        self.vm
            .guest_capabilities()
            .iter()
            .any(|capability| capability == CAP_FILE_RANGE_IO)
    }

    fn ensure_file_range_io(&self, operation: &str) -> Result<()> {
        if self.supports_file_range_io() {
            Ok(())
        } else {
            bail!(
                "{operation} requires guest capability '{}' for chunked transfers larger than {} bytes",
                CAP_FILE_RANGE_IO,
                frame::MAX_FRAME_PAYLOAD
            );
        }
    }

    fn with_guest_control_session<T>(
        &self,
        operation: &'static str,
        f: impl FnOnce(&mut PlatformControlStream, &mut PlatformControlStream) -> Result<T>,
    ) -> Result<T> {
        #[cfg(not(target_os = "macos"))]
        let _control_guard = self
            .control_session
            .lock()
            .map_err(|_| anyhow::anyhow!("Windows guest control session lock poisoned"))?;

        let stream = self.connect_guest_control(operation)?;
        let mut writer = stream
            .try_clone()
            .with_context(|| format!("cloning guest control stream for {operation}"))?;
        let mut reader = stream;

        #[cfg(target_os = "macos")]
        self.send_mount_requests(&mut writer, &mut reader)?;
        f(&mut writer, &mut reader)
    }

    #[cfg(target_os = "macos")]
    fn connect_vsock(&self) -> Result<TcpStream> {
        let state_rx = self.vm.state_channel();
        for attempt in 1..=50 {
            // Check if VM died (e.g. guest mount failure -> reboot POWER_OFF)
            if let Ok(state) = state_rx.try_recv() {
                match state {
                    VmState::Stopped => {
                        bail!("VM stopped during startup - check boot output above for errors")
                    }
                    VmState::Error => bail!("VM encountered an error during startup"),
                    _ => {}
                }
            }
            match self.vm.connect_to_vsock_port(VSOCK_PORT) {
                Ok(s) => {
                    let _ = s.set_nodelay(true);
                    return Ok(s);
                }
                Err(e) => {
                    if attempt == 50 {
                        bail!(
                            "Failed to connect to guest after {} attempts: {}",
                            attempt,
                            e
                        );
                    }
                    tracing::debug!("vsock connect attempt {} failed: {}", attempt, e);
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        }
        unreachable!()
    }

    #[cfg(not(target_os = "macos"))]
    fn connect_vsock(&self) -> Result<TcpStream> {
        Err(unsupported_runtime(
            "macOS-style vsock guest control transport",
            "Windows uses virtio-serial guest control for M08 exec and M09 file transfer primitives; watch, shell, streaming spawn, port forwarding, and muxed sessions are later milestones",
        ))
    }

    #[cfg(target_os = "macos")]
    fn connect_guest_control(&self, _operation: &'static str) -> Result<PlatformControlStream> {
        self.connect_vsock()
            .map(PlatformControlStream::from_tcp_stream)
    }

    #[cfg(not(target_os = "macos"))]
    fn connect_guest_control(&self, operation: &'static str) -> Result<PlatformControlStream> {
        let stream = self
            .vm
            .connect_control()
            .with_context(|| format!("opening Windows virtio-serial {operation} control stream"))?;
        let _ = stream.set_nodelay_if_tcp(true);
        Ok(stream)
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn initialize_windows_mounts(&self) -> Result<()> {
        let imports = self
            .windows_mounts
            .lock()
            .map_err(|_| anyhow::anyhow!("Windows mount import lock poisoned"))?
            .clone();
        if imports.is_empty() {
            return Ok(());
        }

        self.ensure_file_range_io("Windows mount import")?;
        for import in &imports {
            let refreshed = replan_windows_mount_import(import).with_context(|| {
                format!(
                    "revalidating Windows mount '{}' source before import",
                    import.tag
                )
            })?;
            self.copy_from_host_plan(&refreshed.copy_plan)
                .with_context(|| {
                    format!(
                        "copying Windows mount '{}' into guest staging path '{}'",
                        refreshed.tag, refreshed.guest_source
                    )
                })?;
        }

        let result = self.with_guest_control_session("mount init", |writer, reader| {
            self.send_mount_requests(writer, reader)
        });
        if result.is_ok() {
            self.windows_mounts
                .lock()
                .map_err(|_| anyhow::anyhow!("Windows mount import lock poisoned"))?
                .clear();
        }
        result
    }
}

fn build_exec_request(
    argv: &[impl AsRef<str>],
    env: &HashMap<String, String>,
    cwd: Option<&str>,
    tty: Option<bool>,
    stdin_closed: Option<bool>,
) -> ExecRequest {
    ExecRequest {
        argv: argv.iter().map(|s| s.as_ref().to_string()).collect(),
        env: env.clone(),
        tty,
        rows: None,
        cols: None,
        cwd: cwd.map(|s| s.to_string()),
        stdin_closed,
    }
}

fn send_exec_request(writer: &mut impl Write, req: &ExecRequest) -> Result<()> {
    frame::send_json(writer, frame::EXEC_REQ, req).context("sending exec request")
}

fn read_response_frame(reader: &mut impl Read, operation: &str) -> Result<(u8, Vec<u8>)> {
    loop {
        match frame::read_frame(reader).with_context(|| format!("reading {operation} response"))? {
            Some((frame::GUEST_READY, _)) => continue,
            Some(frame) => return Ok(frame),
            None => bail!("guest closed connection during {operation}"),
        }
    }
}

fn collect_exec_response(
    reader: &mut impl Read,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<i32> {
    loop {
        match frame::read_frame(reader).context("reading guest exec response")? {
            Some((frame::STDOUT, payload)) => {
                stdout.write_all(&payload)?;
            }
            Some((frame::STDERR, payload)) => {
                stderr.write_all(&payload)?;
            }
            Some((frame::EXIT, payload)) => {
                return Ok(frame::parse_exit_code(&payload).unwrap_or(0));
            }
            Some((frame::ERROR, payload)) => {
                let msg = String::from_utf8_lossy(&payload);
                write!(stderr, "guest error: {}", msg)?;
                return Ok(1);
            }
            Some(_) => {} // unknown frame, skip
            None => bail!("guest closed exec stream before exit"),
        }
    }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn temp_sibling_path(destination: &Path, label: &str) -> Result<PathBuf> {
    let parent = destination.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "copy-out destination '{}' has no parent directory",
            destination.display()
        )
    })?;
    let file_name = destination
        .file_name()
        .map(|name| name.to_string_lossy())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "copy-out destination '{}' has no file name",
                destination.display()
            )
        })?;
    let nonce = COPY_OUT_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    Ok(parent.join(format!(
        ".{file_name}.lsb-copyout-{label}-{}-{nonce}.tmp",
        std::process::id()
    )))
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn replace_with_temp_path(temp_path: &Path, destination: &Path, overwrite: bool) -> Result<()> {
    if destination.exists() {
        if !overwrite {
            bail!(
                "copy-out destination '{}' already exists; explicit overwrite is required",
                destination.display()
            );
        }
        let temp_metadata = fs::symlink_metadata(temp_path)
            .with_context(|| format!("inspecting copy-out temp path '{}'", temp_path.display()))?;
        if metadata_is_symlink_or_reparse(&temp_metadata) {
            bail!(
                "copy-out temp path '{}' is a symlink or reparse point; refusing to publish it",
                temp_path.display()
            );
        }
        let metadata = fs::symlink_metadata(destination).with_context(|| {
            format!(
                "inspecting copy-out destination '{}'",
                destination.display()
            )
        })?;
        if metadata_is_symlink_or_reparse(&metadata) {
            bail!(
                "copy-out destination '{}' is a symlink or reparse point; refusing to replace it",
                destination.display()
            );
        }
        let temp_is_dir = temp_metadata.is_dir();
        let destination_is_dir = metadata.is_dir();
        if temp_is_dir != destination_is_dir {
            let temp_kind = if temp_is_dir { "directory" } else { "file" };
            let destination_kind = if destination_is_dir {
                "directory"
            } else {
                "file"
            };
            bail!(
                "copy-out destination '{}' is an existing {}; refusing to replace it with a {}",
                destination.display(),
                destination_kind,
                temp_kind
            );
        }
        if temp_is_dir {
            fs::remove_dir_all(destination).with_context(|| {
                format!(
                    "removing existing copy-out directory '{}'",
                    destination.display()
                )
            })?;
        } else {
            fs::remove_file(destination).with_context(|| {
                format!(
                    "removing existing copy-out file '{}'",
                    destination.display()
                )
            })?;
        }
    }

    fs::rename(temp_path, destination).with_context(|| {
        format!(
            "renaming copy-out temp path '{}' to '{}'",
            temp_path.display(),
            destination.display()
        )
    })
}

fn validate_read_chunk(
    operation: &str,
    path: &str,
    offset: u64,
    requested_len: u64,
    chunk: &[u8],
    expected_size: u64,
) -> Result<u64> {
    let chunk_len = u64::try_from(chunk.len())
        .map_err(|_| anyhow::anyhow!("{operation} chunk for '{path}' is too large"))?;
    if chunk_len == 0 && requested_len > 0 {
        bail!(
            "guest returned empty {operation} chunk before EOF for '{}'",
            path
        );
    }
    if chunk_len > requested_len {
        bail!(
            "guest returned {} bytes for {operation} chunk at offset {} in '{}', exceeding requested length {}",
            chunk_len,
            offset,
            path,
            requested_len
        );
    }
    let end = offset
        .checked_add(chunk_len)
        .ok_or_else(|| anyhow::anyhow!("{operation} chunk offset overflow for '{path}'"))?;
    if end > expected_size {
        bail!(
            "guest returned {operation} chunk ending at byte {} for '{}', exceeding advertised size {}",
            end,
            path,
            expected_size
        );
    }
    Ok(chunk_len)
}

fn validate_chunked_transfer_complete(
    operation: &str,
    path: &str,
    transferred: u64,
    expected_size: u64,
) -> Result<()> {
    if transferred != expected_size {
        bail!(
            "{operation} transferred {} bytes for '{}', but guest stat advertised {} bytes",
            transferred,
            path,
            expected_size
        );
    }
    Ok(())
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn metadata_is_symlink_or_reparse(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }

    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

// --- Port forwarding ---

/// Handle returned by `start_port_forwarding`. Signals all listener threads
/// to stop and joins them when dropped.
pub struct PortForwardHandle {
    stop: Arc<AtomicBool>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

impl Drop for PortForwardHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

#[cfg(target_os = "macos")]
fn handle_forward_connection(
    tcp_stream: TcpStream,
    vm: &dyn PlatformVm,
    guest_port: u16,
) -> Result<()> {
    let mut vsock_stream = vm
        .connect_to_vsock_port(VSOCK_PORT_FORWARD)
        .map_err(|e| anyhow::anyhow!("vsock connect for port forward: {}", e))?;
    let _ = vsock_stream.set_nodelay(true);

    // Send forward request
    let req = ForwardRequest { port: guest_port };
    frame::send_json(&mut vsock_stream, frame::FWD_REQ, &req)?;

    // Read response frame
    let (_msg_type, payload) = frame::read_frame(&mut vsock_stream)
        .context("reading forward response")?
        .context("guest closed connection during forward handshake")?;
    let resp: ForwardResponse =
        serde_json::from_slice(&payload).context("parsing forward response")?;

    if resp.status != "ok" {
        bail!(
            "guest refused forward: {}",
            resp.message.unwrap_or_default()
        );
    }

    // Bidirectional relay between TCP and vsock
    relay(tcp_stream, vsock_stream);
    Ok(())
}

#[cfg(target_os = "macos")]
fn relay(a: TcpStream, b: TcpStream) {
    let mut a_read = a.try_clone().expect("clone tcp stream");
    let mut b_write = b.try_clone().expect("clone vsock stream");
    let mut b_read = b;
    let mut a_write = a;

    let t1 = std::thread::spawn(move || {
        let _ = std::io::copy(&mut a_read, &mut b_write);
        let _ = b_write.shutdown(Shutdown::Write);
    });
    let t2 = std::thread::spawn(move || {
        let _ = std::io::copy(&mut b_read, &mut a_write);
        let _ = a_write.shutdown(Shutdown::Write);
    });
    let _ = t1.join();
    let _ = t2.join();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    use std::path::PathBuf;

    struct TestVm;

    impl PlatformVm for TestVm {
        fn start(&self) -> Result<()> {
            Ok(())
        }

        fn stop(&self) -> Result<()> {
            Ok(())
        }

        fn state_channel(&self) -> Receiver<VmState> {
            let (_tx, rx) = crossbeam_channel::unbounded();
            rx
        }

        fn connect_control(&self) -> Result<PlatformControlStream> {
            bail!("test VM does not provide a control stream")
        }

        fn connect_to_vsock_port(&self, _port: u32) -> Result<TcpStream> {
            bail!("test VM does not provide vsock")
        }
    }

    fn sandbox_with_mount_requests(mount_requests: Vec<MountRequest>) -> Sandbox {
        Sandbox {
            vm: Arc::new(TestVm),
            mounts: Mutex::new(mount_requests),
            #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
            windows_mounts: Mutex::new(Vec::new()),
            #[cfg(not(target_os = "macos"))]
            control_session: Mutex::new(()),
        }
    }

    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    #[test]
    fn overlay_mount_generates_readonly_shared_dir_and_overlay_request() {
        let mounts = vec![MountConfig::Overlay {
            host_path: "/host".into(),
            guest_path: "/workspace".into(),
        }];

        let mount_plan = build_mount_plan(&mounts).expect("mount plan should build");

        assert_eq!(mount_plan.shared_dirs.len(), 1);
        assert_eq!(mount_plan.shared_dirs[0].host_path, "/host");
        assert_eq!(mount_plan.shared_dirs[0].tag, "mount0");
        assert!(mount_plan.shared_dirs[0].read_only);

        match &mount_plan.mount_requests[0] {
            MountRequest::Overlay { source, target } => {
                assert_eq!(source, "mount0");
                assert_eq!(target, "/workspace");
            }
            MountRequest::Direct { .. } => panic!("expected overlay request"),
        }
    }

    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    #[test]
    fn direct_mount_preserves_flags_and_derives_platform_readonly() {
        let mounts = vec![
            MountConfig::Direct {
                host_path: "/rw".into(),
                guest_path: "/rw".into(),
                flags: 0,
            },
            MountConfig::Direct {
                host_path: "/ro".into(),
                guest_path: "/ro".into(),
                flags: MS_RDONLY,
            },
        ];

        let mount_plan = build_mount_plan(&mounts).expect("mount plan should build");

        assert!(!mount_plan.shared_dirs[0].read_only);
        assert!(mount_plan.shared_dirs[1].read_only);

        match &mount_plan.mount_requests[0] {
            MountRequest::Direct {
                source,
                target,
                flags,
            } => {
                assert_eq!(source, "mount0");
                assert_eq!(target, "/rw");
                assert_eq!(*flags, 0);
            }
            MountRequest::Overlay { .. } => panic!("expected direct request"),
        }

        match &mount_plan.mount_requests[1] {
            MountRequest::Direct {
                source,
                target,
                flags,
            } => {
                assert_eq!(source, "mount1");
                assert_eq!(target, "/ro");
                assert_eq!(*flags, MS_RDONLY);
            }
            MountRequest::Overlay { .. } => panic!("expected direct request"),
        }
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn windows_overlay_mount_plan_uses_copy_imports_not_shared_dirs() {
        let root = temp_dir("mount-plan");
        let source = root.join("src");
        std::fs::create_dir_all(source.join("nested")).expect("fixture dirs");
        write_fixture(&source.join("hello.txt"), b"hello");

        let plan = build_mount_plan(&[MountConfig::Overlay {
            host_path: source.display().to_string(),
            guest_path: "/workspace".into(),
        }])
        .expect("Windows overlay mount plan should build");

        assert!(plan.shared_dirs.is_empty());
        assert_eq!(plan.windows_imports.len(), 1);
        assert_eq!(
            plan.windows_imports[0].guest_source,
            "/tmp/lsb/mounts/mount0/source"
        );
        match &plan.mount_requests[0] {
            MountRequest::Overlay { source, target } => {
                assert_eq!(source, "/tmp/lsb/mounts/mount0/source");
                assert_eq!(target, "/workspace");
            }
            MountRequest::Direct { .. } => panic!("expected overlay request"),
        }

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn windows_direct_mount_plan_fails_closed() {
        let err = match build_mount_plan(&[MountConfig::Direct {
            host_path: r"C:\project".into(),
            guest_path: "/workspace".into(),
            flags: 0,
        }]) {
            Ok(_) => panic!("Windows direct host mounts should fail"),
            Err(error) => error,
        };

        let message = err.to_string();
        assert!(message.contains("direct host mounts"));
        assert!(message.contains("Windows MVP"));
    }

    #[test]
    fn send_mount_requests_retains_pending_mounts_on_guest_error() {
        let request = MountRequest::Overlay {
            source: "mount0".into(),
            target: "/workspace".into(),
        };
        let sandbox = sandbox_with_mount_requests(vec![request.clone()]);
        let mut writer = Vec::new();
        let mut reader_payload = Vec::new();
        frame::write_frame(&mut reader_payload, frame::ERROR, b"mount failed")
            .expect("error frame should encode");
        let mut reader = Cursor::new(reader_payload);

        let err = sandbox
            .send_mount_requests(&mut writer, &mut reader)
            .expect_err("guest mount error should fail");

        assert!(err.to_string().contains("mount failed"));
        let retained = sandbox.mounts.lock().unwrap();
        assert_eq!(retained.len(), 1);
        assert!(matches!(
            &retained[0],
            MountRequest::Overlay { source, target }
                if source == "mount0" && target == "/workspace"
        ));
    }

    #[test]
    fn exec_request_frame_includes_argv_env_and_cwd() {
        let mut env = HashMap::new();
        env.insert("LSB_M08_ENV".to_string(), "present".to_string());
        let req = build_exec_request(
            &["/bin/sh", "-c", "printf test"],
            &env,
            Some("/workspace"),
            None,
            Some(true),
        );
        let mut encoded = Vec::new();

        send_exec_request(&mut encoded, &req).expect("exec request should encode");

        let mut reader = Cursor::new(encoded);
        let (msg_type, payload) = frame::read_frame(&mut reader)
            .expect("frame should decode")
            .expect("frame should be present");
        let decoded: ExecRequest =
            serde_json::from_slice(&payload).expect("exec request should decode");

        assert_eq!(msg_type, frame::EXEC_REQ);
        assert_eq!(decoded.argv, ["/bin/sh", "-c", "printf test"]);
        assert_eq!(
            decoded.env.get("LSB_M08_ENV").map(String::as_str),
            Some("present")
        );
        assert_eq!(decoded.cwd.as_deref(), Some("/workspace"));
        assert_eq!(decoded.tty, None);
        assert_eq!(decoded.stdin_closed, Some(true));
    }

    #[test]
    fn exec_response_streams_stdout_stderr_and_exit_code() {
        let mut reader = exec_response_stream(&[
            (frame::STDOUT, b"hello ".as_slice()),
            (frame::STDERR, b"warn".as_slice()),
            (frame::STDOUT, b"world\n".as_slice()),
            (frame::EXIT, &frame::exit_payload(0)),
        ]);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code =
            collect_exec_response(&mut reader, &mut stdout, &mut stderr).expect("exec response");

        assert_eq!(exit_code, 0);
        assert_eq!(stdout, b"hello world\n");
        assert_eq!(stderr, b"warn");
    }

    #[test]
    fn exec_response_preserves_nonzero_exit_code() {
        let mut reader = exec_response_stream(&[(frame::EXIT, &frame::exit_payload(7))]);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code =
            collect_exec_response(&mut reader, &mut stdout, &mut stderr).expect("exec response");

        assert_eq!(exit_code, 7);
        assert!(stdout.is_empty());
        assert!(stderr.is_empty());
    }

    #[test]
    fn exec_response_collects_large_stdout_frame() {
        let large = vec![b'x'; 256 * 1024];
        let mut reader = exec_response_stream(&[
            (frame::STDOUT, &large),
            (frame::EXIT, &frame::exit_payload(0)),
        ]);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code =
            collect_exec_response(&mut reader, &mut stdout, &mut stderr).expect("exec response");

        assert_eq!(exit_code, 0);
        assert_eq!(stdout, large);
        assert!(stderr.is_empty());
    }

    #[test]
    fn exec_response_maps_guest_error_to_stderr_and_exit_one() {
        let mut reader = exec_response_stream(&[(frame::ERROR, b"failed to spawn: missing")]);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code =
            collect_exec_response(&mut reader, &mut stdout, &mut stderr).expect("exec response");

        assert_eq!(exit_code, 1);
        assert!(stdout.is_empty());
        assert_eq!(stderr, b"guest error: failed to spawn: missing");
    }

    #[test]
    fn exec_response_ignores_guest_ready_frames_before_output() {
        let mut ready =
            lsb_proto::GuestReady::new(lsb_proto::GuestTransport::VirtioSerial, "guest-test");
        ready.capabilities.push("exec".to_string());
        let ready_payload = serde_json::to_vec(&ready).expect("ready should encode");
        let mut reader = exec_response_stream(&[
            (frame::GUEST_READY, &ready_payload),
            (frame::STDOUT, b"after-ready\n"),
            (frame::EXIT, &frame::exit_payload(0)),
        ]);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code =
            collect_exec_response(&mut reader, &mut stdout, &mut stderr).expect("exec response");

        assert_eq!(exit_code, 0);
        assert_eq!(stdout, b"after-ready\n");
        assert!(stderr.is_empty());
    }

    #[test]
    fn file_response_reader_skips_guest_ready_frames() {
        let ready =
            lsb_proto::GuestReady::new(lsb_proto::GuestTransport::VirtioSerial, "guest-test");
        let ready_payload = serde_json::to_vec(&ready).expect("ready should encode");
        let mut reader = exec_response_stream(&[
            (frame::GUEST_READY, &ready_payload),
            (frame::READ_FILE_RESP, b"file-content"),
        ]);

        let (msg_type, payload) =
            read_response_frame(&mut reader, "read_file").expect("response should read");

        assert_eq!(msg_type, frame::READ_FILE_RESP);
        assert_eq!(payload, b"file-content");
    }

    #[test]
    fn chunk_validation_rejects_oversized_guest_response() {
        let err = validate_read_chunk("read_file", "/tmp/file", 0, 4, b"12345", 4)
            .expect_err("oversized chunk should fail");

        assert!(err.to_string().contains("exceeding requested length"));
    }

    #[test]
    fn chunk_validation_rejects_guest_response_beyond_stat_size() {
        let err = validate_read_chunk("copy-out", "/tmp/file", 3, 4, b"1234", 6)
            .expect_err("chunk beyond advertised size should fail");

        assert!(err.to_string().contains("exceeding advertised size"));
    }

    #[test]
    fn chunk_validation_requires_exact_advertised_byte_count() {
        let err = validate_chunked_transfer_complete("copy-out", "/tmp/file", 3, 4)
            .expect_err("incomplete transfer should fail");

        assert!(err.to_string().contains("advertised 4 bytes"));
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn copy_out_overwrite_rejects_file_to_directory_replacement() {
        let root = copy_overwrite_test_dir("file-to-dir");
        let temp_file = root.join("temp-file");
        let destination = root.join("destination");
        std::fs::write(&temp_file, b"new").expect("temp file");
        std::fs::create_dir(&destination).expect("destination dir");
        std::fs::write(destination.join("kept.txt"), b"old").expect("existing child");

        let err = replace_with_temp_path(&temp_file, &destination, true)
            .expect_err("file must not replace directory");

        assert!(err.to_string().contains("refusing to replace"));
        assert!(destination.is_dir());
        assert_eq!(
            std::fs::read(destination.join("kept.txt")).expect("existing child should remain"),
            b"old"
        );
        assert_eq!(
            std::fs::read(&temp_file).expect("temp file should remain for cleanup"),
            b"new"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn copy_out_overwrite_rejects_directory_to_file_replacement() {
        let root = copy_overwrite_test_dir("dir-to-file");
        let temp_dir = root.join("temp-dir");
        let destination = root.join("destination.txt");
        std::fs::create_dir(&temp_dir).expect("temp dir");
        std::fs::write(temp_dir.join("new.txt"), b"new").expect("temp child");
        std::fs::write(&destination, b"old").expect("destination file");

        let err = replace_with_temp_path(&temp_dir, &destination, true)
            .expect_err("directory must not replace file");

        assert!(err.to_string().contains("refusing to replace"));
        assert_eq!(
            std::fs::read(&destination).expect("destination file should remain"),
            b"old"
        );
        assert_eq!(
            std::fs::read(temp_dir.join("new.txt")).expect("temp dir should remain for cleanup"),
            b"new"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn copy_out_overwrite_replaces_same_kind_file() {
        let root = copy_overwrite_test_dir("file-to-file");
        let temp_file = root.join("temp-file");
        let destination = root.join("destination.txt");
        std::fs::write(&temp_file, b"new").expect("temp file");
        std::fs::write(&destination, b"old").expect("destination file");

        replace_with_temp_path(&temp_file, &destination, true)
            .expect("file should replace file with explicit overwrite");

        assert_eq!(
            std::fs::read(&destination).expect("destination should contain new data"),
            b"new"
        );
        assert!(!temp_file.exists());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn exec_response_errors_when_guest_closes_before_exit() {
        let mut reader = exec_response_stream(&[(frame::STDOUT, b"partial")]);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let err = collect_exec_response(&mut reader, &mut stdout, &mut stderr)
            .expect_err("missing exit should fail");

        assert!(err.to_string().contains("before exit"));
        assert_eq!(stdout, b"partial");
        assert!(stderr.is_empty());
    }

    fn exec_response_stream(frames: &[(u8, &[u8])]) -> Cursor<Vec<u8>> {
        let mut stream = Cursor::new(Vec::new());
        for (msg_type, payload) in frames {
            frame::write_frame(&mut stream, *msg_type, payload).expect("frame should write");
        }
        stream.set_position(0);
        stream
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn copy_overwrite_test_dir(label: &str) -> PathBuf {
        let nonce = COPY_OUT_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "lsb-copy-overwrite-{label}-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("test root");
        root
    }

    #[test]
    #[ignore = "requires Windows 11 x86_64 with WHPX, QEMU, and disposable LocalSandbox assets"]
    fn windows_qemu_exec_smoke() {
        #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
        {
            eprintln!("skipping Windows QEMU exec smoke on non-Windows host");
        }

        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        {
            let kernel = required_env_path("LSB_WINDOWS_BOOT_KERNEL");
            let initrd = required_env_path("LSB_WINDOWS_BOOT_INITRD");
            let rootfs = required_env_path("LSB_WINDOWS_BOOT_ROOTFS");
            let sandbox = Sandbox::builder()
                .kernel(kernel.display().to_string())
                .initrd(initrd.display().to_string())
                .rootfs(rootfs.display().to_string())
                .console(false)
                .build()
                .expect("Windows exec smoke sandbox should build");

            sandbox
                .start()
                .expect("Windows exec smoke should reach guest ready before exec");

            let result = (|| -> Result<()> {
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();

                let code = sandbox.exec(&["/bin/true"], &mut stdout, &mut stderr)?;
                assert_eq!(code, 0);
                assert!(stdout.is_empty());
                assert!(stderr.is_empty());

                stdout.clear();
                stderr.clear();
                let code = sandbox.exec(&["/bin/echo", "hello"], &mut stdout, &mut stderr)?;
                assert_eq!(code, 0);
                assert_eq!(String::from_utf8_lossy(&stdout), "hello\n");
                assert!(stderr.is_empty());

                stdout.clear();
                stderr.clear();
                let code = sandbox.exec(
                    &["/bin/sh", "-c", "printf err >&2"],
                    &mut stdout,
                    &mut stderr,
                )?;
                assert_eq!(code, 0);
                assert!(stdout.is_empty());
                assert_eq!(String::from_utf8_lossy(&stderr), "err");

                stdout.clear();
                stderr.clear();
                let mut env = HashMap::new();
                env.insert("LSB_M08_ENV".to_string(), "present".to_string());
                let code = sandbox.exec_with_env_and_cwd(
                    &["/bin/sh", "-c", "printf '%s:%s' \"$PWD\" \"$LSB_M08_ENV\""],
                    &env,
                    Some("/tmp"),
                    &mut stdout,
                    &mut stderr,
                )?;
                assert_eq!(code, 0);
                assert_eq!(String::from_utf8_lossy(&stdout), "/tmp:present");
                assert!(stderr.is_empty());

                stdout.clear();
                stderr.clear();
                let code = sandbox.exec(
                    &["/bin/sh", "-c", "printf nope >&2; exit 7"],
                    &mut stdout,
                    &mut stderr,
                )?;
                assert_eq!(code, 7);
                assert!(stdout.is_empty());
                assert_eq!(String::from_utf8_lossy(&stderr), "nope");

                Ok(())
            })();

            let stop_result = sandbox.stop();
            result.expect("Windows exec smoke commands should pass");
            stop_result.expect("Windows exec smoke QEMU should stop cleanly");
        }
    }

    #[test]
    #[ignore = "requires Windows 11 x86_64 with WHPX, QEMU, and disposable LocalSandbox assets"]
    fn windows_qemu_copy_transfer_smoke() {
        #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
        {
            eprintln!("skipping Windows QEMU copy transfer smoke on non-Windows host");
        }

        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        {
            let kernel = required_env_path("LSB_WINDOWS_BOOT_KERNEL");
            let initrd = required_env_path("LSB_WINDOWS_BOOT_INITRD");
            let rootfs = required_env_path("LSB_WINDOWS_BOOT_ROOTFS");
            let host_root = rootfs
                .parent()
                .expect("rootfs should live in a work directory")
                .join("copy-transfer-fixture");
            let _ = std::fs::remove_dir_all(&host_root);
            std::fs::create_dir_all(host_root.join("in/nested/empty")).expect("host fixture dirs");
            std::fs::create_dir_all(host_root.join("out")).expect("host output dir");
            std::fs::write(host_root.join("in/hello.txt"), b"hello from host")
                .expect("host fixture file");
            let large = vec![b'x'; lsb_proto::FILE_TRANSFER_CHUNK_SIZE + 123];
            std::fs::write(host_root.join("in/nested/large.bin"), &large)
                .expect("host large fixture");

            let sandbox = Sandbox::builder()
                .kernel(kernel.display().to_string())
                .initrd(initrd.display().to_string())
                .rootfs(rootfs.display().to_string())
                .console(false)
                .build()
                .expect("Windows copy smoke sandbox should build");

            sandbox
                .start()
                .expect("Windows copy smoke should reach guest ready before transfers");

            let result = (|| -> Result<()> {
                sandbox
                    .copy_from_host(host_root.join("in/hello.txt"), "/tmp/lsb-copy/hello.txt")?;
                let copied = sandbox.read_file("/tmp/lsb-copy/hello.txt")?;
                assert_eq!(copied, b"hello from host");

                sandbox.copy_from_host(host_root.join("in"), "/tmp/lsb-copy/tree")?;
                let copied_large = sandbox.read_file("/tmp/lsb-copy/tree/nested/large.bin")?;
                assert_eq!(copied_large, large);

                sandbox.write_file("/tmp/lsb-copy/out/result.txt", b"result from guest")?;
                sandbox.copy_to_host(
                    "/tmp/lsb-copy/out/result.txt",
                    host_root.join("out/result.txt"),
                    false,
                )?;
                assert_eq!(
                    std::fs::read(host_root.join("out/result.txt"))?,
                    b"result from guest"
                );

                sandbox.copy_to_host(
                    "/tmp/lsb-copy/tree",
                    host_root.join("exported-tree"),
                    false,
                )?;
                assert_eq!(
                    std::fs::read(host_root.join("exported-tree/nested/large.bin"))?,
                    copied_large
                );

                let traversal =
                    sandbox.copy_to_host("/tmp/../etc/passwd", host_root.join("bad.txt"), false);
                assert!(traversal.is_err());

                let overwrite = sandbox.copy_to_host(
                    "/tmp/lsb-copy/out/result.txt",
                    host_root.join("out/result.txt"),
                    false,
                );
                assert!(overwrite.is_err());

                Ok(())
            })();

            let stop_result = sandbox.stop();
            let _ = std::fs::remove_dir_all(&host_root);
            result.expect("Windows copy smoke transfers should pass");
            stop_result.expect("Windows copy smoke QEMU should stop cleanly");
        }
    }

    #[test]
    #[ignore = "requires Windows 11 x86_64 with WHPX, QEMU, and disposable LocalSandbox assets"]
    fn windows_qemu_mount_mvp_smoke() {
        #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
        {
            eprintln!("skipping Windows QEMU mount MVP smoke on non-Windows host");
        }

        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        {
            let kernel = required_env_path("LSB_WINDOWS_BOOT_KERNEL");
            let initrd = required_env_path("LSB_WINDOWS_BOOT_INITRD");
            let rootfs = required_env_path("LSB_WINDOWS_BOOT_ROOTFS");
            let host_root = rootfs
                .parent()
                .expect("rootfs should live in a work directory")
                .join("mount-mvp-fixture");
            let _ = std::fs::remove_dir_all(&host_root);
            let source = host_root.join("source");
            let export = host_root.join("export");
            std::fs::create_dir_all(source.join("nested")).expect("mount fixture dirs");
            std::fs::create_dir_all(&export).expect("export fixture dir");
            std::fs::write(source.join("hello.txt"), b"hello from host")
                .expect("mount fixture file");
            std::fs::write(source.join("nested/data.txt"), b"nested from host")
                .expect("nested mount fixture file");

            let sandbox = Sandbox::builder()
                .kernel(kernel.display().to_string())
                .initrd(initrd.display().to_string())
                .rootfs(rootfs.display().to_string())
                .console(false)
                .mount(MountConfig::Overlay {
                    host_path: source.display().to_string(),
                    guest_path: "/workspace".into(),
                })
                .build()
                .expect("Windows mount smoke sandbox should build");

            sandbox
                .start()
                .expect("Windows mount smoke should import and mount the source snapshot");

            let result = (|| -> Result<()> {
                assert_eq!(
                    sandbox.read_file("/workspace/hello.txt")?,
                    b"hello from host"
                );
                assert_eq!(
                    sandbox.read_file("/workspace/nested/data.txt")?,
                    b"nested from host"
                );

                sandbox.write_file("/workspace/guest.txt", b"guest write")?;
                assert!(
                    !source.join("guest.txt").exists(),
                    "guest writes under the mounted target must not mutate the host source"
                );

                std::fs::write(source.join("after-start.txt"), b"host live update")
                    .expect("host source live update fixture");
                assert!(
                    sandbox.read_file("/workspace/after-start.txt").is_err(),
                    "Windows MVP mounts expose a startup snapshot, not live host synchronization"
                );

                sandbox.copy_to_host("/workspace/guest.txt", export.join("guest.txt"), false)?;
                assert_eq!(std::fs::read(export.join("guest.txt"))?, b"guest write");

                let direct = Sandbox::builder()
                    .kernel(kernel.display().to_string())
                    .initrd(initrd.display().to_string())
                    .rootfs(rootfs.display().to_string())
                    .console(false)
                    .mount(MountConfig::Direct {
                        host_path: source.display().to_string(),
                        guest_path: "/direct-rw".into(),
                        flags: 0,
                    })
                    .build();
                let direct_error = match direct {
                    Ok(_) => panic!("direct read-write host mount should fail"),
                    Err(error) => error,
                };
                assert!(direct_error.to_string().contains("direct host mounts"));

                Ok(())
            })();

            let stop_result = sandbox.stop();
            let _ = std::fs::remove_dir_all(&host_root);
            result.expect("Windows mount MVP smoke should pass");
            stop_result.expect("Windows mount smoke QEMU should stop cleanly");
        }
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn required_env_path(name: &str) -> PathBuf {
        std::env::var_os(name)
            .map(PathBuf::from)
            .unwrap_or_else(|| panic!("{name} must point to a disposable boot asset path"))
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn write_fixture(path: &std::path::Path, content: &[u8]) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("fixture parent dir");
        }
        let mut file = std::fs::File::create(path).expect("fixture file");
        file.write_all(content).expect("fixture content");
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn temp_dir(label: &str) -> PathBuf {
        static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
        let nonce = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "lsb-windows-vm-{label}-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        root
    }
}
