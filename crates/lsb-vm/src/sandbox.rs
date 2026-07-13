use std::collections::{HashMap, HashSet};
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use std::fs;
#[cfg(target_os = "macos")]
use std::io::{BufReader, BufWriter};
use std::io::{Read, Write};
use std::net::TcpStream;
#[cfg(any(
    target_os = "macos",
    all(target_os = "windows", target_arch = "x86_64")
))]
use std::net::{Shutdown, TcpListener};
#[cfg(target_os = "macos")]
use std::os::fd::AsRawFd;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use std::path::{Path, PathBuf};
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
#[cfg(any(
    target_os = "macos",
    all(target_os = "windows", target_arch = "x86_64")
))]
use std::time::Duration;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use std::time::Instant;

use anyhow::{bail, Context, Result};
use crossbeam_channel::Receiver;
#[cfg(target_os = "macos")]
use lsb_platform::terminal;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use lsb_platform::windows_x86_64::fs::smb::{
    remove_windows_smb_cleanup_manifest, windows_smb_cleanup_manifest_path,
    write_windows_smb_cleanup_manifest, WindowsSmbActiveResources, WindowsSmbInstanceGuard,
    WindowsSmbLifecycleConfig, WindowsSmbLifecycleManager, WindowsSmbMount,
};
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use lsb_platform::windows_x86_64::fs::{
    join_guest_child, open_copy_in_file_checked, open_copy_in_file_for_snapshot, plan_copy_in,
    validate_copy_out_destination, validate_guest_absolute_path, validate_guest_path_component,
    validate_windows_host_path_lexical, CaseFoldSet, CopyInEntryKind, CopyInFileIdentity,
    CopyInPlan, CopyPathOperation,
};
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use lsb_platform::windows_x86_64::fs::{
    plan_windows_mounts, replan_windows_smb_mount, snapshot_windows_mount, WindowsMountCache,
    WindowsMountCacheBuild, WindowsMountCacheHit, WindowsMountCacheSelection,
    WindowsMountDescriptor, WindowsMountMode, WindowsMountSnapshot, WindowsMountSnapshotEntry,
    WindowsMountSnapshotEntryKind, WindowsMountSpec, WINDOWS_MOUNT_STAGING_ROOT,
};
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use lsb_platform::PlatformControlSessionKind;
use lsb_platform::PlatformControlStream;
use lsb_platform::{
    self, PlatformNetworkAttachment, PlatformSharedDir, PlatformVm, PlatformVmConfig, VmState,
};
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use lsb_platform::{PlatformDataDisk, PlatformDiskFormat};

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use lsb_proto::SyncFsRequest;
use lsb_proto::{
    frame, ChmodRequest, CopyRequest, ExecRequest, FsOkResponse, MkdirRequest, MountRequest,
    MountResponse, PortMapping, ReadDirRequest, ReadDirResponse, ReadFileRequest, RemoveRequest,
    RenameRequest, StatRequest, StatResponse, WatchRequest, WriteFileRequest, WriteFileResponse,
    CAP_FILE_RANGE_IO, FILE_TRANSFER_CHUNK_SIZE,
};
#[cfg(any(
    target_os = "macos",
    all(target_os = "windows", target_arch = "x86_64")
))]
use lsb_proto::{ForwardRequest, ForwardResponse};
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use lsb_proto::{
    MountCacheImportEntry, MountCacheRejectReason, MountCacheRequest, MountCacheResponse,
    CAP_CIFS_MOUNT, CAP_DEFERRED_FILE_SYNC, CAP_MOUNT_CACHE_IMPORT_BATCH_V1, CAP_MOUNT_CACHE_V1,
    CAP_SESSION_MUX,
};
#[cfg(target_os = "macos")]
use lsb_proto::{VSOCK_PORT, VSOCK_PORT_FORWARD};

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use crate::mount_metrics::{
    CacheDecision, DurationMetric, ErrorCategory, FailedPhase, FallbackReason, MountSourceSummary,
    TerminalOutcome, WindowsMountMetrics,
};

#[cfg(not(target_os = "macos"))]
#[derive(Debug)]
struct UnsupportedWindowsRuntime {
    capability: &'static str,
    detail: &'static str,
}

#[cfg(not(target_os = "macos"))]
impl std::fmt::Display for UnsupportedWindowsRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "LocalSandbox does not support {} on this host. {} Supported Windows x86_64 runtime operations include QEMU boot, guest-ready, non-interactive exec, guest file copy, overlay mount import/export, loopback port forwarding, policy-mediated proxy networking, and qcow2 checkpoint/store semantics.",
            self.capability, self.detail
        )
    }
}

#[cfg(not(target_os = "macos"))]
impl std::error::Error for UnsupportedWindowsRuntime {}

#[cfg(not(target_os = "macos"))]
fn unsupported_runtime(capability: &'static str, detail: &'static str) -> anyhow::Error {
    UnsupportedWindowsRuntime { capability, detail }.into()
}

// --- Mount types ---

#[cfg(any(not(all(target_os = "windows", target_arch = "x86_64")), test))]
const MS_RDONLY: u64 = 1;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
static COPY_OUT_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
static PORT_FORWARD_SESSION_COUNTER: AtomicU64 = AtomicU64::new(1);
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
const MOUNT_CACHE_BATCH_DATA_SIZE: usize = 512 * 1024;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
const MOUNT_CACHE_BATCH_METADATA_BUDGET: usize = 256 * 1024;

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
    data_dir: Option<String>,
    kernel: Option<String>,
    rootfs: Option<String>,
    initrd: Option<String>,
    cpus: usize,
    memory_mb: u64,
    console: bool,
    verbose: bool,
    network_fd: Option<i32>,
    network_attachment: Option<PlatformNetworkAttachment>,
    nbd_uri: Option<String>,
    mounts: Vec<MountConfig>,
}

impl VmConfigBuilder {
    pub(crate) fn new() -> Self {
        VmConfigBuilder {
            data_dir: None,
            kernel: None,
            rootfs: None,
            initrd: None,
            cpus: 2,
            memory_mb: 2048,
            console: true,
            verbose: false,
            network_fd: None,
            network_attachment: None,
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

    pub fn data_dir(mut self, path: impl Into<String>) -> Self {
        self.data_dir = Some(path.into());
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
        self.network_attachment = Some(PlatformNetworkAttachment::file_descriptor(fd));
        self
    }

    /// Attach a platform-specific proxy-backed network device.
    pub fn network_attachment(mut self, attachment: PlatformNetworkAttachment) -> Self {
        self.network_fd = match attachment {
            PlatformNetworkAttachment::FileDescriptor(fd) => Some(fd),
            PlatformNetworkAttachment::QemuStream(_) => None,
        };
        self.network_attachment = Some(attachment);
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
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        let mount_metrics = WindowsMountMetrics::from_env();
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        mount_metrics.set_failure_context(
            FailedPhase::Configuration,
            ErrorCategory::InvalidConfiguration,
        );

        let kernel_path = match self.kernel.context("kernel path is required") {
            Ok(path) => path,
            Err(error) => {
                #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
                mount_metrics.finish_current_failure();
                return Err(error);
            }
        };
        let rootfs_path = match self.rootfs.context("rootfs path is required") {
            Ok(path) => path,
            Err(error) => {
                #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
                mount_metrics.finish_current_failure();
                return Err(error);
            }
        };

        let memory_bytes = self.memory_mb * 1024 * 1024;
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        let windows_data_dir = PathBuf::from(
            self.data_dir
                .clone()
                .unwrap_or_else(lsb_platform::default_data_dir),
        );
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        mount_metrics.set_failure_context(FailedPhase::InitialPlan, ErrorCategory::UnsafeSource);
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        let initial_plan_started = Instant::now();
        let mount_plan_result = build_mount_plan(&self.mounts);
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        mount_metrics.add_duration(DurationMetric::InitialPlan, initial_plan_started.elapsed());
        let mount_plan = match mount_plan_result {
            Ok(plan) => plan,
            Err(error) => {
                #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
                mount_metrics.finish_current_failure();
                return Err(error);
            }
        };
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        let windows_smb_instance_id = windows_smb_instance_id(&rootfs_path);
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        let windows_smb_cleanup_manifest_path =
            windows_smb_cleanup_manifest_path_from_rootfs(&rootfs_path)?;

        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        mount_metrics.set_failure_context(FailedPhase::VmCreate, ErrorCategory::VmCreateFailed);
        let vm_result = lsb_platform::create_vm(PlatformVmConfig {
            data_dir: self.data_dir,
            kernel_path,
            rootfs_path,
            initrd_path: self.initrd,
            cpus: self.cpus,
            memory_bytes,
            console: self.console,
            verbose: self.verbose,
            network_fd: self.network_fd,
            network_attachment: self.network_attachment,
            nbd_uri: self.nbd_uri,
            shared_dirs: mount_plan.shared_dirs,
        });
        let vm = match vm_result {
            Ok(vm) => vm,
            Err(error) => {
                #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
                mount_metrics.finish_current_failure();
                return Err(error);
            }
        };

        Ok(Sandbox {
            vm,
            mounts: Mutex::new(mount_plan.mount_requests),
            #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
            windows_mounts: Mutex::new(mount_plan.windows_imports),
            #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
            windows_smb_mounts: Mutex::new(mount_plan.windows_smb_mounts),
            #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
            windows_smb_resources: Mutex::new(None),
            #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
            windows_smb_instance_guard: Mutex::new(None),
            #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
            windows_smb_instance_id,
            #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
            windows_smb_cleanup_manifest_path,
            #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
            windows_data_dir,
            #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
            windows_mount_cache_run: Mutex::new(None),
            #[cfg(not(target_os = "macos"))]
            control_session: Mutex::new(()),
            #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
            port_forward_session: Arc::new(Mutex::new(())),
            #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
            mount_metrics,
        })
    }
}

// --- Sandbox ---

pub struct Sandbox {
    vm: Arc<dyn PlatformVm>,
    mounts: Mutex<Vec<MountRequest>>,
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    windows_mounts: Mutex<Vec<WindowsMountDescriptor>>,
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    windows_smb_mounts: Mutex<Vec<WindowsSmbMount>>,
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    windows_smb_resources: Mutex<Option<WindowsSmbActiveResources>>,
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    windows_smb_instance_guard: Mutex<Option<WindowsSmbInstanceGuard>>,
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    windows_smb_instance_id: String,
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    windows_smb_cleanup_manifest_path: PathBuf,
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    windows_data_dir: PathBuf,
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    windows_mount_cache_run: Mutex<Option<WindowsMountCacheRun>>,
    #[cfg(not(target_os = "macos"))]
    control_session: Mutex<()>,
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    port_forward_session: Arc<Mutex<()>>,
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    mount_metrics: WindowsMountMetrics,
}

struct SandboxMountPlan {
    shared_dirs: Vec<PlatformSharedDir>,
    mount_requests: Vec<MountRequest>,
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    windows_imports: Vec<WindowsMountDescriptor>,
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    windows_smb_mounts: Vec<WindowsSmbMount>,
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
struct WindowsMountCacheRun {
    cache: Option<WindowsMountCache>,
    images: Vec<WindowsMountCacheRunImage>,
    routes: Vec<WindowsMountCacheRoute>,
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
struct WindowsMountCacheRunImage {
    image_id: String,
    serial: String,
    lease: WindowsMountCacheLease,
    state: WindowsMountCacheImageState,
    binding_indices: Vec<usize>,
    invalidate_after_stop: bool,
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
enum WindowsMountCacheLease {
    Hit(Option<WindowsMountCacheHit>),
    Build(Option<WindowsMountCacheBuild>),
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[derive(Debug, Clone)]
enum WindowsMountCacheRoute {
    Selected {
        image_index: usize,
        binding_id: String,
    },
    Fallback {
        reason: String,
    },
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
enum WindowsMountCacheImageState {
    Selected,
    Sealed { raw_device_digest: String },
    AllBindingsMounted { raw_device_digest: Option<String> },
    PublishEligible { raw_device_digest: String },
    Fallback,
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[derive(Debug)]
struct MountCacheImportRejected(MountCacheRejectReason);

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
impl std::fmt::Display for MountCacheImportRejected {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "guest rejected cache import batch: {:?}", self.0)
    }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
impl std::error::Error for MountCacheImportRejected {}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
impl WindowsMountCacheLease {
    fn image_path(&self) -> &Path {
        match self {
            Self::Hit(Some(hit)) => &hit.image_path,
            Self::Build(Some(build)) => &build.image_path,
            Self::Hit(None) | Self::Build(None) => {
                panic!("mount cache lease was already finalized")
            }
        }
    }

    fn virtual_size(&self) -> u64 {
        match self {
            Self::Hit(Some(hit)) => hit.virtual_size,
            Self::Build(Some(build)) => build.virtual_size,
            Self::Hit(None) | Self::Build(None) => {
                panic!("mount cache lease was already finalized")
            }
        }
    }

    fn inode_count(&self) -> u64 {
        match self {
            Self::Hit(Some(hit)) => hit.inode_count,
            Self::Build(Some(build)) => build.inode_count,
            Self::Hit(None) | Self::Build(None) => {
                panic!("mount cache lease was already finalized")
            }
        }
    }

    fn is_hit(&self) -> bool {
        matches!(self, Self::Hit(Some(_)))
    }

    fn take_and_discard(&mut self) {
        match self {
            Self::Hit(hit) => {
                drop(hit.take());
            }
            Self::Build(build) => {
                if let Some(build) = build.take() {
                    if let Err(error) = build.discard() {
                        eprintln!("lsb: failed to discard mount cache staging image: {error:#}");
                    }
                }
            }
        }
    }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
impl WindowsMountCacheRun {
    fn all_fallback(snapshots: &[WindowsMountSnapshot], reason: impl Into<String>) -> Self {
        let reason = reason.into();
        Self {
            cache: None,
            images: Vec::new(),
            routes: snapshots
                .iter()
                .map(|_| WindowsMountCacheRoute::Fallback {
                    reason: reason.clone(),
                })
                .collect(),
        }
    }

    fn data_disks(&self) -> Vec<PlatformDataDisk> {
        self.images
            .iter()
            .enumerate()
            .map(|(index, image)| PlatformDataDisk {
                id: format!("cache{index}"),
                path: image.lease.image_path().to_path_buf(),
                format: PlatformDiskFormat::Raw,
                read_only: image.lease.is_hit(),
                serial: image.serial.clone(),
                virtual_size_bytes: image.lease.virtual_size(),
            })
            .collect()
    }

    fn has_disks(&self) -> bool {
        !self.images.is_empty()
    }

    fn route_is_selected(&self, snapshot_index: usize) -> bool {
        matches!(
            self.routes.get(snapshot_index),
            Some(WindowsMountCacheRoute::Selected { .. })
        )
    }

    fn has_selected_routes(&self) -> bool {
        self.routes
            .iter()
            .any(|route| matches!(route, WindowsMountCacheRoute::Selected { .. }))
    }

    fn has_fallback_routes(&self) -> bool {
        self.routes
            .iter()
            .any(|route| matches!(route, WindowsMountCacheRoute::Fallback { .. }))
    }

    fn report_fallbacks(&self) {
        let reasons = self
            .routes
            .iter()
            .filter_map(|route| match route {
                WindowsMountCacheRoute::Fallback { reason } => Some(reason.as_str()),
                WindowsMountCacheRoute::Selected { .. } => None,
            })
            .collect::<HashSet<_>>();
        for reason in reasons {
            eprintln!("lsb: Windows mount cache fallback: {reason}");
        }
    }

    fn record_metrics(&self, metrics: &WindowsMountMetrics) {
        for image in &self.images {
            metrics.record_cache_image_size(image.lease.virtual_size());
            if image.lease.is_hit() {
                metrics.record_raw_image_bytes_hashed(image.lease.virtual_size());
            }
        }
        for (snapshot_index, route) in self.routes.iter().enumerate() {
            match route {
                WindowsMountCacheRoute::Selected { image_index, .. } => {
                    let is_hit = self.images[*image_index].lease.is_hit();
                    metrics.record_cache_route(
                        snapshot_index,
                        if is_hit {
                            CacheDecision::HitSelected
                        } else {
                            CacheDecision::BuildSelected
                        },
                        None,
                        if is_hit {
                            TerminalOutcome::HitUsed
                        } else {
                            TerminalOutcome::BuildNotPublished
                        },
                    );
                }
                WindowsMountCacheRoute::Fallback { reason } => {
                    let selected_image = self
                        .images
                        .iter()
                        .find(|image| image.binding_indices.contains(&snapshot_index));
                    let decision = selected_image.map_or_else(
                        || cache_bypass_decision(reason),
                        |image| {
                            if image.lease.is_hit() {
                                CacheDecision::HitSelected
                            } else {
                                CacheDecision::BuildSelected
                            }
                        },
                    );
                    metrics.record_cache_route(
                        snapshot_index,
                        decision,
                        Some(cache_fallback_reason(reason)),
                        TerminalOutcome::FallbackUsed,
                    );
                }
            }
        }
    }

    fn needs_payload_transfer(&self) -> bool {
        self.has_fallback_routes()
            || self.images.iter().any(|image| {
                matches!(image.lease, WindowsMountCacheLease::Build(Some(_)))
                    && !matches!(image.state, WindowsMountCacheImageState::Fallback)
            })
    }

    fn fallback_image(
        &mut self,
        image_index: usize,
        reason: impl Into<String>,
        invalidate_hit: bool,
    ) {
        let reason = reason.into();
        if let Some(image) = self.images.get_mut(image_index) {
            image.state = WindowsMountCacheImageState::Fallback;
            image.invalidate_after_stop |= invalidate_hit && image.lease.is_hit();
        }
        for route in &mut self.routes {
            if matches!(
                route,
                WindowsMountCacheRoute::Selected {
                    image_index: selected,
                    ..
                } if *selected == image_index
            ) {
                *route = WindowsMountCacheRoute::Fallback {
                    reason: reason.clone(),
                };
            }
        }
    }

    fn disable_before_boot(&mut self, reason: impl Into<String>) {
        let reason = reason.into();
        for image in &mut self.images {
            image.lease.take_and_discard();
            image.state = WindowsMountCacheImageState::Fallback;
        }
        for route in &mut self.routes {
            *route = WindowsMountCacheRoute::Fallback {
                reason: reason.clone(),
            };
        }
        self.images.clear();
    }

    fn disable_while_running(&mut self, reason: impl Into<String>) {
        let reason = reason.into();
        for image in &mut self.images {
            image.state = WindowsMountCacheImageState::Fallback;
        }
        for route in &mut self.routes {
            *route = WindowsMountCacheRoute::Fallback {
                reason: reason.clone(),
            };
        }
    }

    fn mark_startup_succeeded(&mut self) {
        for image in &mut self.images {
            if let WindowsMountCacheImageState::AllBindingsMounted {
                raw_device_digest: Some(raw_device_digest),
            } = &image.state
            {
                image.state = WindowsMountCacheImageState::PublishEligible {
                    raw_device_digest: raw_device_digest.clone(),
                };
            }
        }
    }

    fn finalize_after_stop(mut self, metrics: &WindowsMountMetrics) {
        for image in &mut self.images {
            let image_size = image.lease.virtual_size();
            match &mut image.lease {
                WindowsMountCacheLease::Hit(hit) => {
                    drop(hit.take());
                    if image.invalidate_after_stop {
                        match self.cache.as_ref().map(|cache| cache.invalidate(&image.image_id)) {
                            Some(Ok(true)) => eprintln!(
                                "lsb: invalidated guest-rejected mount cache object {}",
                                image.image_id
                            ),
                            Some(Ok(false)) => eprintln!(
                                "lsb: deferred invalidation of active mount cache object {}",
                                image.image_id
                            ),
                            Some(Err(error)) => eprintln!(
                                "lsb: failed to invalidate guest-rejected mount cache object {}: {error:#}",
                                image.image_id
                            ),
                            None => {}
                        }
                    }
                }
                WindowsMountCacheLease::Build(build) => {
                    let Some(build) = build.take() else {
                        continue;
                    };
                    match &image.state {
                        WindowsMountCacheImageState::PublishEligible { raw_device_digest } => {
                            metrics.record_raw_image_bytes_hashed(image_size);
                            let publish_started = Instant::now();
                            let publish_result = build.publish(raw_device_digest);
                            metrics.add_duration(
                                DurationMetric::CachePublish,
                                publish_started.elapsed(),
                            );
                            match publish_result {
                                Ok(path) => {
                                    for binding in &image.binding_indices {
                                        metrics.set_cache_terminal_outcome(
                                            *binding,
                                            TerminalOutcome::BuildPublished,
                                        );
                                    }
                                    eprintln!(
                                        "lsb: published mount cache object {} at {}",
                                        image.image_id,
                                        path.display()
                                    );
                                }
                                Err(error) => eprintln!(
                                    "lsb: discarded mount cache object {} after verification: {error:#}",
                                    image.image_id
                                ),
                            }
                        }
                        _ => {
                            if let Err(error) = build.discard() {
                                eprintln!(
                                    "lsb: failed to discard ineligible mount cache object {}: {error:#}",
                                    image.image_id
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn capabilities_support_mount_cache(capabilities: &[String]) -> bool {
    [CAP_MOUNT_CACHE_V1, CAP_MOUNT_CACHE_IMPORT_BATCH_V1]
        .iter()
        .all(|required| capabilities.iter().any(|capability| capability == required))
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn cache_bypass_decision(reason: &str) -> CacheDecision {
    if reason.contains("another process") {
        CacheDecision::BusyBypass
    } else if reason.contains("invalid") || reason.contains("corrupt") {
        CacheDecision::InvalidCorruptBypass
    } else {
        CacheDecision::UnsupportedBypass
    }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn cache_fallback_reason(reason: &str) -> FallbackReason {
    if reason.contains("another process") {
        FallbackReason::Busy
    } else if reason.contains("does not advertise") || reason.contains("requires the persistent") {
        FallbackReason::UnsupportedGuest
    } else if reason.contains("VM start") {
        FallbackReason::BootRetry
    } else if reason.contains("guest cache") {
        FallbackReason::GuestRejected
    } else if reason.contains("corrupt") {
        FallbackReason::CorruptObject
    } else if reason.contains("invalid") {
        FallbackReason::InvalidObject
    } else if reason.contains("image") || reason.contains("disk configuration") {
        FallbackReason::ImageCreateFailed
    } else {
        FallbackReason::CacheDisabled
    }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn windows_mount_source_summaries(snapshots: &[WindowsMountSnapshot]) -> Vec<MountSourceSummary> {
    snapshots
        .iter()
        .map(|snapshot| MountSourceSummary {
            mount_id: snapshot.descriptor.tag.clone(),
            file_count: snapshot.file_count,
            directory_count: snapshot.directory_count,
            logical_bytes: snapshot.logical_bytes,
            entries_visited: snapshot.entries.len() as u64,
        })
        .collect()
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
        windows_smb_mounts: plan.smb_directs,
    })
}

impl Sandbox {
    pub fn builder() -> VmConfigBuilder {
        VmConfigBuilder::new()
    }

    pub fn start(&self) -> Result<()> {
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        self.mount_metrics.begin_start();

        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        self.mount_metrics
            .set_failure_context(FailedPhase::SnapshotWalk, ErrorCategory::UnsafeSource);
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        let snapshot_started = Instant::now();
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        let windows_mount_snapshots = match self.snapshot_windows_mounts() {
            Ok(snapshots) => snapshots,
            Err(error) => {
                self.mount_metrics
                    .add_duration(DurationMetric::SnapshotWalk, snapshot_started.elapsed());
                self.mount_metrics.finish_current_failure();
                return Err(error).context("Failed to snapshot Windows mounts");
            }
        };
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        {
            self.mount_metrics
                .add_duration(DurationMetric::SnapshotWalk, snapshot_started.elapsed());
            self.mount_metrics
                .initialize_mounts(windows_mount_source_summaries(&windows_mount_snapshots));
            let snapshot_bytes = windows_mount_snapshots
                .iter()
                .fold(0u64, |total, snapshot| {
                    total.saturating_add(snapshot.logical_bytes)
                });
            self.mount_metrics
                .record_snapshot_bytes_hashed(snapshot_bytes);
        }

        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        let cache_lookup_started = Instant::now();
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        let mut windows_mount_cache_run = self.plan_windows_mount_cache(&windows_mount_snapshots);
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        self.mount_metrics
            .add_duration(DurationMetric::CacheLookup, cache_lookup_started.elapsed());

        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        if windows_mount_cache_run.has_disks() {
            let disk_config_started = Instant::now();
            let disks = windows_mount_cache_run.data_disks();
            let disk_config_result = self.vm.configure_data_disks(disks);
            self.mount_metrics.add_duration(
                DurationMetric::CacheDiskConfig,
                disk_config_started.elapsed(),
            );
            if let Err(error) = disk_config_result {
                eprintln!(
                    "lsb: mount cache disk configuration failed; using copy fallback: {error:#}"
                );
                windows_mount_cache_run
                    .disable_before_boot(format!("cache disk configuration failed: {error:#}"));
                let _ = self.vm.configure_data_disks(Vec::new());
            }
        }

        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        if let Err(error) = self
            .prepare_windows_smb_mounts()
            .context("Failed to prepare Windows SMB mounts")
        {
            self.mount_metrics.finish_failure(
                FailedPhase::Configuration,
                ErrorCategory::InvalidConfiguration,
            );
            return Err(error);
        }

        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        self.mount_metrics
            .set_failure_context(FailedPhase::GuestReady, ErrorCategory::VmStartFailed);
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        let guest_ready_started = Instant::now();
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        let vm_start_result = match self.vm.start() {
            Ok(()) => Ok(()),
            Err(first_error) if windows_mount_cache_run.has_disks() => {
                eprintln!(
                    "lsb: VM start with mount cache disks failed; retrying once without cache disks: {first_error:#}"
                );
                let clear_result = self.vm.configure_data_disks(Vec::new());
                windows_mount_cache_run.disable_before_boot(format!(
                    "VM start with cache disks failed: {first_error:#}"
                ));
                match clear_result {
                    Ok(()) => self.vm.start().with_context(|| {
                        format!(
                            "VM start failed after diskless retry; initial cache-disk start error: {first_error:#}"
                        )
                    }),
                    Err(error) => Err(error).context(format!(
                        "failed to clear cache disks after VM start error: {first_error:#}"
                    )),
                }
            }
            Err(error) => Err(error),
        };
        #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
        let vm_start_result = self.vm.start();
        if let Err(error) = vm_start_result.context("Failed to start VM") {
            #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
            {
                self.mount_metrics
                    .add_duration(DurationMetric::GuestReady, guest_ready_started.elapsed());
                self.cleanup_windows_smb_mounts_best_effort();
                self.mount_metrics.finish_current_failure();
            }
            return Err(error);
        }
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        self.mount_metrics
            .add_duration(DurationMetric::GuestReady, guest_ready_started.elapsed());

        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        if !self.supports_mount_cache() && windows_mount_cache_run.has_disks() {
            windows_mount_cache_run.disable_while_running(
                "guest does not advertise persistent mount-cache capability",
            );
        }

        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        if let Err(error) =
            self.initialize_windows_mounts(&windows_mount_snapshots, &mut windows_mount_cache_run)
        {
            let _ = self.vm.stop();
            let _ = self.vm.configure_data_disks(Vec::new());
            self.cleanup_windows_smb_mounts_best_effort();
            self.mount_metrics.finish_current_failure();
            return Err(error).context("Failed to initialize Windows mounts");
        }

        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        {
            windows_mount_cache_run.mark_startup_succeeded();
            let mut active_cache = self
                .windows_mount_cache_run
                .lock()
                .map_err(|_| anyhow::anyhow!("Windows mount cache run lock poisoned"))?;
            if active_cache.is_some() {
                let _ = self.vm.stop();
                bail!("a Windows mount cache run is already active");
            }
            *active_cache = Some(windows_mount_cache_run);
            self.mount_metrics.complete_start();
        }

        Ok(())
    }

    pub fn stop(&self) -> Result<()> {
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        {
            self.sync_windows_smb_mounts_best_effort();
            let stop_result = self.vm.stop().context("Failed to stop VM");
            if stop_result.is_ok() {
                if let Err(error) = self.vm.configure_data_disks(Vec::new()) {
                    eprintln!("lsb: failed to clear stopped mount cache disks: {error:#}");
                }
                let cache_run = self
                    .windows_mount_cache_run
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Windows mount cache run lock poisoned"))?
                    .take();
                if let Some(cache_run) = cache_run {
                    cache_run.finalize_after_stop(&self.mount_metrics);
                }
            }
            let cleanup_result = self.cleanup_windows_smb_mounts();
            let result = match (stop_result, cleanup_result) {
                (Ok(()), Ok(())) => Ok(()),
                (Err(error), Ok(())) => Err(error),
                (Ok(()), Err(error)) => Err(error).context("Failed to clean up Windows SMB mounts"),
                (Err(stop_error), Err(cleanup_error)) => Err(stop_error).context(format!(
                    "Failed to stop VM; additionally failed to clean up Windows SMB mounts: {cleanup_error}"
                )),
            };
            if result.is_ok() {
                self.mount_metrics.finish_success();
            } else {
                self.mount_metrics
                    .finish_failure(FailedPhase::VmStop, ErrorCategory::VmStopFailed);
            }
            result
        }

        #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
        {
            self.vm.stop().context("Failed to stop VM")
        }
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
            #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
            if self.mount_metrics.mount_init_active() {
                self.mount_metrics.record_filesystem_request();
            }
            let (msg_type, payload) =
                read_response_frame(reader, "mount init").context("reading mount response")?;
            #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
            if self.mount_metrics.mount_init_active() {
                self.mount_metrics.record_filesystem_response();
            }
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
                let error = resp.error.unwrap_or_else(|| "unknown error".into());
                let (source, target, error) = match req {
                    MountRequest::Overlay { source, target } => {
                        (source.clone(), target.as_str(), error)
                    }
                    MountRequest::Direct { source, target, .. } => {
                        (source.clone(), target.as_str(), error)
                    }
                    MountRequest::Smb {
                        share,
                        target,
                        username,
                        password,
                        ..
                    } => {
                        let error =
                            sanitize_smb_mount_failure_message(error, share, username, password);
                        (
                            "Windows SMB direct mount".to_string(),
                            target.as_str(),
                            error,
                        )
                    }
                };
                bail!("mount failed: {} -> {}: {}", source, target, error);
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
            defer_sync: None,
            mode: None,
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
                defer_sync: None,
                mode: None,
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
                defer_sync: None,
                mode: None,
            };
            self.send_write_file_request(&req, chunk)?;
            offset = end;
        }

        Ok(())
    }

    fn send_write_file_request(&self, req: &WriteFileRequest, content: &[u8]) -> Result<()> {
        self.with_guest_control_session("write_file", |writer, reader| {
            self.send_write_file_request_on_session(writer, reader, req, content)
        })
    }

    fn send_write_file_request_on_session(
        &self,
        writer: &mut impl Write,
        reader: &mut impl Read,
        req: &WriteFileRequest,
        content: &[u8],
    ) -> Result<()> {
        if content.len() > frame::MAX_FRAME_PAYLOAD {
            bail!(
                "write_file chunk for '{}' is {} bytes, exceeding protocol payload limit {}",
                req.path,
                content.len(),
                frame::MAX_FRAME_PAYLOAD
            );
        }

        frame::send_json(writer, frame::WRITE_FILE_REQ, req)?;
        frame::write_frame(writer, frame::WRITE_FILE_DATA, content)?;
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        if self.mount_metrics.mount_init_active() {
            self.mount_metrics.record_filesystem_request();
        }

        let (msg_type, payload) =
            read_response_frame(reader, "write_file").context("reading write_file response")?;
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        if self.mount_metrics.mount_init_active() {
            self.mount_metrics.record_filesystem_response();
        }
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

        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        if self.mount_metrics.mount_init_active() {
            self.mount_metrics
                .record_file_write(content.len() as u64, req.defer_sync.unwrap_or(false));
        }

        Ok(())
    }

    /// Send a request and expect FS_OK_RESP or ERROR. Used by void fs ops.
    fn void_fs_op(&self, req_frame: u8, req: &impl serde::Serialize) -> Result<()> {
        self.with_guest_control_session("filesystem operation", |writer, reader| {
            self.void_fs_op_on_session(writer, reader, req_frame, req)
        })
    }

    fn void_fs_op_on_session(
        &self,
        writer: &mut impl Write,
        reader: &mut impl Read,
        req_frame: u8,
        req: &impl serde::Serialize,
    ) -> Result<()> {
        frame::send_json(writer, req_frame, req)?;
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        if self.mount_metrics.mount_init_active() {
            self.mount_metrics.record_filesystem_request();
        }

        let response = read_response_frame(reader, "filesystem operation")
            .context("reading fs op response")?;
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        if self.mount_metrics.mount_init_active() {
            self.mount_metrics.record_filesystem_response();
        }
        match response {
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
    }

    pub fn mkdir(&self, path: &str, recursive: bool) -> Result<()> {
        self.void_fs_op(
            frame::MKDIR_REQ,
            &MkdirRequest {
                path: path.to_string(),
                recursive,
                mode: None,
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
        if self.supports_session_mux() {
            return self.with_guest_control_session("copy_from_host", |writer, reader| {
                self.copy_from_host_plan_on_session(writer, reader, plan, false)
            });
        }
        self.copy_from_host_plan_legacy(plan, false)
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn copy_from_host_plan_legacy(&self, plan: &CopyInPlan, defer_sync: bool) -> Result<()> {
        for entry in &plan.entries {
            match &entry.kind {
                CopyInEntryKind::Directory => {
                    self.mkdir(&entry.guest_path, true).with_context(|| {
                        format!("copy-in create guest dir '{}'", entry.guest_path)
                    })?;
                }
                CopyInEntryKind::File { len, identity } => self
                    .copy_host_file_to_guest(
                        &entry.host_path,
                        *len,
                        *identity,
                        &entry.guest_path,
                        defer_sync,
                    )
                    .with_context(|| format!("copy-in file to '{}'", entry.guest_path))?,
            }
        }

        Ok(())
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn copy_from_host_plan_on_session(
        &self,
        writer: &mut impl Write,
        reader: &mut impl Read,
        plan: &CopyInPlan,
        defer_sync: bool,
    ) -> Result<()> {
        for entry in &plan.entries {
            match &entry.kind {
                CopyInEntryKind::Directory => self
                    .void_fs_op_on_session(
                        writer,
                        reader,
                        frame::MKDIR_REQ,
                        &MkdirRequest {
                            path: entry.guest_path.clone(),
                            recursive: true,
                            mode: None,
                        },
                    )
                    .with_context(|| format!("copy-in create guest dir '{}'", entry.guest_path))?,
                CopyInEntryKind::File { len, identity } => self
                    .copy_host_file_to_guest_on_session(
                        writer,
                        reader,
                        &entry.host_path,
                        *len,
                        *identity,
                        &entry.guest_path,
                        defer_sync,
                    )
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
            bail!(
                "copy-out guest source '{}' is a symlink; symlink export is unsupported on Windows",
                guest_source
            );
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
        defer_sync: bool,
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
                    self.write_guest_file_range(guest_path, 0, true, &[], defer_sync, None)?;
                }
                break;
            }
            self.write_guest_file_range(
                guest_path,
                offset,
                first,
                &buffer[..len],
                defer_sync,
                None,
            )?;
            offset += len as u64;
            first = false;
        }

        Ok(())
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn copy_host_file_to_guest_on_session(
        &self,
        writer: &mut impl Write,
        reader: &mut impl Read,
        host_path: &Path,
        expected_len: u64,
        expected_identity: CopyInFileIdentity,
        guest_path: &str,
        defer_sync: bool,
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
                    self.write_guest_file_range_on_session(
                        writer,
                        reader,
                        guest_path,
                        0,
                        true,
                        &[],
                        defer_sync,
                        None,
                    )?;
                }
                break;
            }
            self.write_guest_file_range_on_session(
                writer,
                reader,
                guest_path,
                offset,
                first,
                &buffer[..len],
                defer_sync,
                None,
            )?;
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
        defer_sync: bool,
        mode: Option<u32>,
    ) -> Result<()> {
        let req = WriteFileRequest {
            path: guest_path.to_string(),
            len: content.len() as u64,
            offset: Some(offset),
            truncate: Some(truncate),
            defer_sync: defer_sync.then_some(true),
            mode,
        };
        self.send_write_file_request(&req, content)
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn write_guest_file_range_on_session(
        &self,
        writer: &mut impl Write,
        reader: &mut impl Read,
        guest_path: &str,
        offset: u64,
        truncate: bool,
        content: &[u8],
        defer_sync: bool,
        mode: Option<u32>,
    ) -> Result<()> {
        let req = WriteFileRequest {
            path: guest_path.to_string(),
            len: content.len() as u64,
            offset: Some(offset),
            truncate: Some(truncate),
            defer_sync: defer_sync.then_some(true),
            mode,
        };
        self.send_write_file_request_on_session(writer, reader, &req, content)
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
                    "copy-out guest entry '{}' is a symlink; symlink export is unsupported on Windows",
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

    /// Open a macOS vsock connection for streaming exec. Returns the raw stream
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
                "Use Sandbox::exec for non-interactive commands; streaming stdin/kill requires a multiplexed guest control session.",
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

    /// Internal streaming exec entry point used by higher-level SDK bindings.
    /// This preserves the public `open_exec` `TcpStream` API while allowing
    /// platform backends to provide non-TCP control sessions.
    #[doc(hidden)]
    pub fn open_exec_session(
        &self,
        argv: &[impl AsRef<str>],
        env: &HashMap<String, String>,
        cwd: Option<&str>,
    ) -> Result<PlatformControlStream> {
        #[cfg(not(any(
            target_os = "macos",
            all(target_os = "windows", target_arch = "x86_64")
        )))]
        {
            let _ = (argv, env, cwd);
            return Err(unsupported_runtime(
                "streaming exec stdin/kill",
                "Use Sandbox::exec for non-interactive commands; streaming stdin/kill requires a multiplexed guest control session.",
            ));
        }

        #[cfg(target_os = "macos")]
        {
            let session = PlatformControlStream::from_tcp_stream(self.connect_vsock()?);
            self.initialize_exec_session(session, argv, env, cwd)
        }

        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        {
            let session = self
                .vm
                .open_control_session(PlatformControlSessionKind::Exec)
                .context("opening Windows mux exec control session")?;
            self.initialize_exec_session(session, argv, env, cwd)
        }
    }

    #[cfg(any(
        target_os = "macos",
        all(target_os = "windows", target_arch = "x86_64")
    ))]
    fn initialize_exec_session(
        &self,
        session: PlatformControlStream,
        argv: &[impl AsRef<str>],
        env: &HashMap<String, String>,
        cwd: Option<&str>,
    ) -> Result<PlatformControlStream> {
        let mut writer = session.try_clone()?;
        let mut reader = session.try_clone()?;

        self.send_mount_requests(&mut writer, &mut reader)?;

        let req = build_exec_request(argv, env, cwd, None, None);
        send_exec_request(&mut writer, &req)?;

        Ok(session)
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

    /// Open a macOS vsock connection for file watching. Returns a stream that
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

    /// Internal watch entry point used by higher-level SDK bindings. This keeps
    /// the public `open_watch` `TcpStream` API stable while allowing platform
    /// backends to use non-TCP control sessions.
    #[doc(hidden)]
    pub fn open_watch_session(&self, path: &str, recursive: bool) -> Result<PlatformControlStream> {
        #[cfg(not(any(
            target_os = "macos",
            all(target_os = "windows", target_arch = "x86_64")
        )))]
        {
            let _ = (path, recursive);
            return Err(unsupported_runtime(
                "file watch",
                "File watch requires a supported guest control session.",
            ));
        }

        #[cfg(target_os = "macos")]
        {
            let session = PlatformControlStream::from_tcp_stream(self.connect_vsock()?);
            self.initialize_watch_session(session, path, recursive)
        }

        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        {
            self.ensure_guest_side_windows_watch_path(path)?;
            let session = self
                .vm
                .open_control_session(PlatformControlSessionKind::Watch)
                .context("opening Windows mux watch control session")?;
            self.initialize_watch_session(session, path, recursive)
        }
    }

    #[cfg(any(
        target_os = "macos",
        all(target_os = "windows", target_arch = "x86_64")
    ))]
    fn initialize_watch_session(
        &self,
        session: PlatformControlStream,
        path: &str,
        recursive: bool,
    ) -> Result<PlatformControlStream> {
        let mut writer = session.try_clone()?;
        let mut reader = session.try_clone()?;

        self.send_mount_requests(&mut writer, &mut reader)?;

        let req = WatchRequest {
            path: path.to_string(),
            recursive,
        };
        frame::send_json(&mut writer, frame::WATCH_REQ, &req)?;

        Ok(session)
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn ensure_guest_side_windows_watch_path(&self, path: &str) -> Result<()> {
        if let Some(target) = self.windows_smb_watch_target(path)? {
            bail!(
                "Windows direct SMB mount watch for guest path '{}' under '{}' is handled by the SDK/Node host watcher; guest-side VM watch sessions only support normal guest paths and overlay/import mounts",
                path,
                target
            );
        }
        Ok(())
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn windows_smb_watch_target(&self, path: &str) -> Result<Option<String>> {
        let mounts = self
            .windows_smb_mounts
            .lock()
            .map_err(|_| anyhow::anyhow!("Windows SMB mount lock poisoned"))?;

        Ok(mounts
            .iter()
            .filter(|mount| guest_path_contains_or_equals(path, &mount.target))
            .max_by_key(|mount| mount.target.len())
            .map(|mount| mount.target.clone()))
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

    /// Interactive shell support on Windows needs PTY handling over the guest
    /// control transport. Non-interactive exec is supported through `exec`.
    #[cfg(not(target_os = "macos"))]
    pub fn shell(&self, _argv: &[impl AsRef<str>], _env: &HashMap<String, String>) -> Result<i32> {
        Err(unsupported_runtime(
            "interactive shell",
            "Use Sandbox::exec for non-interactive commands; interactive shells require PTY support over the guest control transport.",
        ))
    }

    /// Start port forwarding proxies. Returns a handle that stops all
    /// listeners when dropped.
    #[cfg(target_os = "macos")]
    pub fn start_port_forwarding(&self, forwards: &[PortMapping]) -> Result<PortForwardHandle> {
        validate_port_mappings(forwards)?;
        let stop = Arc::new(AtomicBool::new(false));
        let mut listeners = Vec::new();
        let mut bound_listeners = Vec::new();

        for mapping in forwards {
            let tcp_listener = bind_loopback_listener(mapping.host_port).with_context(|| {
                format!("failed to bind host loopback port {}", mapping.host_port)
            })?;
            tcp_listener.set_nonblocking(true)?;
            bound_listeners.push((mapping.clone(), tcp_listener));
        }

        for (mapping, tcp_listener) in bound_listeners {
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

    /// Windows port forwarding preserves no-network-by-default by using the
    /// dedicated LocalSandbox virtio-serial forwarding channel.
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    pub fn start_port_forwarding(&self, forwards: &[PortMapping]) -> Result<PortForwardHandle> {
        validate_port_mappings(forwards)?;
        self.vm.connect_port_forward().context(
            "opening Windows virtio-serial port-forward transport before binding listeners",
        )?;

        let stop = Arc::new(AtomicBool::new(false));
        let mut listeners = Vec::new();
        let mut bound_listeners = Vec::new();
        let state_rx = self.vm.state_channel();
        let state_stop = Arc::clone(&stop);
        listeners.push(std::thread::spawn(move || {
            stop_port_forwarding_when_vm_stops(state_rx, state_stop);
        }));

        for mapping in forwards {
            let tcp_listener = bind_loopback_listener(mapping.host_port).with_context(|| {
                format!("failed to bind host loopback port {}", mapping.host_port)
            })?;
            tcp_listener.set_nonblocking(true)?;
            bound_listeners.push((mapping.clone(), tcp_listener));
        }

        for (mapping, tcp_listener) in bound_listeners {
            let guest_port = mapping.guest_port;
            let vm = Arc::clone(&self.vm);
            let stop_flag = stop.clone();
            let session_lock = Arc::clone(&self.port_forward_session);

            eprintln!(
                "lsb: forwarding 127.0.0.1:{} -> guest:{}",
                mapping.host_port, mapping.guest_port
            );

            let handle = std::thread::spawn(move || {
                while !stop_flag.load(Ordering::Relaxed) {
                    match tcp_listener.accept() {
                        Ok((tcp_stream, _)) => {
                            let _ = tcp_stream.set_nonblocking(false);
                            let vm = Arc::clone(&vm);
                            let session_lock = Arc::clone(&session_lock);
                            std::thread::spawn(move || {
                                if let Err(error) = handle_windows_forward_connection(
                                    tcp_stream,
                                    vm.as_ref(),
                                    guest_port,
                                    session_lock,
                                ) {
                                    tracing::debug!("port forward error: {}", error);
                                }
                            });
                        }
                        Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(50));
                        }
                        Err(error) => {
                            if !stop_flag.load(Ordering::Relaxed) {
                                tracing::debug!("accept error on port forward listener: {}", error);
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

    #[cfg(not(any(
        target_os = "macos",
        all(target_os = "windows", target_arch = "x86_64")
    )))]
    pub fn start_port_forwarding(&self, _forwards: &[PortMapping]) -> Result<PortForwardHandle> {
        Err(unsupported_runtime(
            "port forwarding",
            "Port forwarding is available only on the macOS and Windows x86_64 backends; no listener was opened.",
        ))
    }

    fn supports_file_range_io(&self) -> bool {
        self.vm
            .guest_capabilities()
            .iter()
            .any(|capability| capability == CAP_FILE_RANGE_IO)
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn supports_session_mux(&self) -> bool {
        self.vm
            .guest_capabilities()
            .iter()
            .any(|capability| capability == CAP_SESSION_MUX)
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn supports_deferred_file_sync(&self) -> bool {
        self.vm
            .guest_capabilities()
            .iter()
            .any(|capability| capability == CAP_DEFERRED_FILE_SYNC)
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn supports_mount_cache(&self) -> bool {
        let capabilities = self.vm.guest_capabilities();
        capabilities_support_mount_cache(&capabilities)
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn supports_cifs_mount(&self) -> bool {
        self.vm
            .guest_capabilities()
            .iter()
            .any(|capability| capability == CAP_CIFS_MOUNT)
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

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn ensure_cifs_mount(&self, operation: &str) -> Result<()> {
        if self.supports_cifs_mount() {
            Ok(())
        } else {
            bail!(
                "{operation} requires guest capability '{}'. Run `lsb upgrade` and recreate the checkpoint to enable Windows direct mounts.",
                CAP_CIFS_MOUNT
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

        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        let track_mux_file_session = self.mount_metrics.mount_init_active()
            && self.supports_session_mux()
            && windows_control_session_kind(operation) == PlatformControlSessionKind::File;
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        let connect_started = Instant::now();
        let stream_result = self.connect_guest_control(operation);
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        if track_mux_file_session {
            self.mount_metrics
                .record_mux_file_session(connect_started.elapsed(), stream_result.is_ok());
        }
        let stream = stream_result?;
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
            "Windows uses virtio-serial guest control for exec and file transfer; macOS-style vsock guest control is not available on Windows.",
        ))
    }

    #[cfg(target_os = "macos")]
    fn connect_guest_control(&self, _operation: &'static str) -> Result<PlatformControlStream> {
        self.connect_vsock()
            .map(PlatformControlStream::from_tcp_stream)
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn connect_guest_control(&self, operation: &'static str) -> Result<PlatformControlStream> {
        if self.supports_session_mux() {
            let kind = windows_control_session_kind(operation);
            let stream = self.vm.open_control_session(kind).with_context(|| {
                format!("opening Windows virtio-serial mux {operation} control session")
            })?;
            let _ = stream.set_nodelay_if_tcp(true);
            return Ok(stream);
        }

        let stream = self
            .vm
            .connect_control()
            .with_context(|| format!("opening Windows virtio-serial {operation} control stream"))?;
        let _ = stream.set_nodelay_if_tcp(true);
        Ok(stream)
    }

    #[cfg(not(any(
        target_os = "macos",
        all(target_os = "windows", target_arch = "x86_64")
    )))]
    fn connect_guest_control(&self, operation: &'static str) -> Result<PlatformControlStream> {
        let stream = self
            .vm
            .connect_control()
            .with_context(|| format!("opening guest {operation} control stream"))?;
        let _ = stream.set_nodelay_if_tcp(true);
        Ok(stream)
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn prepare_windows_smb_mounts(&self) -> Result<()> {
        let mounts = self
            .windows_smb_mounts
            .lock()
            .map_err(|_| anyhow::anyhow!("Windows SMB mount lock poisoned"))?
            .clone();
        if mounts.is_empty() {
            return Ok(());
        }

        if self
            .windows_smb_resources
            .lock()
            .map_err(|_| anyhow::anyhow!("Windows SMB resource lock poisoned"))?
            .is_some()
        {
            bail!("Windows SMB mount resources are already active; stop the sandbox before starting it again");
        }
        if self
            .windows_smb_instance_guard
            .lock()
            .map_err(|_| anyhow::anyhow!("Windows SMB instance lock poisoned"))?
            .is_some()
        {
            bail!("Windows SMB mount instance lock is already active; stop the sandbox before starting it again");
        }

        let instance_dir = self
            .windows_smb_cleanup_manifest_path
            .parent()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Windows SMB cleanup manifest path '{}' has no instance directory",
                    self.windows_smb_cleanup_manifest_path.display()
                )
            })?;
        let guard = WindowsSmbInstanceGuard::acquire(instance_dir).with_context(|| {
            format!(
                "acquiring Windows SMB instance lock for '{}'",
                instance_dir.display()
            )
        })?;

        let mut refreshed_mounts = Vec::with_capacity(mounts.len());
        for mount in &mounts {
            let refreshed = replan_windows_smb_mount(mount).with_context(|| {
                format!(
                    "revalidating Windows SMB mount target '{}' source before sharing",
                    mount.target
                )
            })?;
            refreshed_mounts.push(refreshed);
        }

        let config =
            WindowsSmbLifecycleConfig::new(self.windows_smb_instance_id.clone(), refreshed_mounts);
        let mut manager = WindowsSmbLifecycleManager::native();

        if self.windows_smb_cleanup_manifest_path.is_file() {
            manager
                .recover_cleanup_manifest(&self.windows_smb_cleanup_manifest_path)
                .with_context(|| {
                    format!(
                        "recovering stale Windows SMB cleanup manifest '{}'",
                        self.windows_smb_cleanup_manifest_path.display()
                    )
                })?;
        }

        let mut resources = manager.prepare(&config)?;
        if let Err(error) = write_windows_smb_cleanup_manifest(
            &self.windows_smb_cleanup_manifest_path,
            &self.windows_smb_instance_id,
            &resources,
        ) {
            let cleanup_result = manager.cleanup(resources);
            if let Err(cleanup_error) = cleanup_result {
                return Err(error).context(format!(
                    "failed to write Windows SMB cleanup manifest; additionally failed to clean up prepared SMB resources: {cleanup_error}"
                ));
            }
            return Err(error).context("failed to write Windows SMB cleanup manifest");
        }

        {
            let mut pending_mounts = self
                .mounts
                .lock()
                .map_err(|_| anyhow::anyhow!("mount request lock poisoned"))?;
            pending_mounts.extend(resources.mount_requests().iter().cloned());
        }
        resources.mount_requests.clear();

        *self
            .windows_smb_resources
            .lock()
            .map_err(|_| anyhow::anyhow!("Windows SMB resource lock poisoned"))? = Some(resources);
        *self
            .windows_smb_instance_guard
            .lock()
            .map_err(|_| anyhow::anyhow!("Windows SMB instance lock poisoned"))? = Some(guard);

        Ok(())
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn cleanup_windows_smb_mounts(&self) -> Result<()> {
        self.remove_windows_smb_mount_requests()?;

        let resources = self
            .windows_smb_resources
            .lock()
            .map_err(|_| anyhow::anyhow!("Windows SMB resource lock poisoned"))?
            .take();
        let Some(resources) = resources else {
            self.release_windows_smb_instance_guard()?;
            return Ok(());
        };

        let mut manager = WindowsSmbLifecycleManager::native();
        let cleanup_result = manager.cleanup(resources);
        if let Err(error) = cleanup_result {
            self.release_windows_smb_instance_guard()?;
            return Err(error.into());
        }
        let manifest_result =
            remove_windows_smb_cleanup_manifest(&self.windows_smb_cleanup_manifest_path);
        self.release_windows_smb_instance_guard()?;
        manifest_result?;
        Ok(())
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn cleanup_windows_smb_mounts_best_effort(&self) {
        if let Err(error) = self.cleanup_windows_smb_mounts() {
            tracing::debug!("Windows SMB mount cleanup failed: {}", error);
        }
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn remove_windows_smb_mount_requests(&self) -> Result<()> {
        let mut mounts = self
            .mounts
            .lock()
            .map_err(|_| anyhow::anyhow!("mount request lock poisoned"))?;
        mounts.retain(|request| !matches!(request, MountRequest::Smb { .. }));
        Ok(())
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn release_windows_smb_instance_guard(&self) -> Result<()> {
        let guard = self
            .windows_smb_instance_guard
            .lock()
            .map_err(|_| anyhow::anyhow!("Windows SMB instance lock poisoned"))?
            .take();
        drop(guard);
        Ok(())
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn has_windows_smb_resources(&self) -> bool {
        self.windows_smb_resources
            .lock()
            .map(|resources| resources.is_some())
            .unwrap_or(false)
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn sync_windows_smb_mounts_best_effort(&self) {
        if !self.has_windows_smb_resources() {
            return;
        }

        let _ = self.exec(&["sync"], &mut std::io::sink(), &mut std::io::sink());
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn snapshot_windows_mounts(&self) -> Result<Vec<WindowsMountSnapshot>> {
        let descriptors = self
            .windows_mounts
            .lock()
            .map_err(|_| anyhow::anyhow!("Windows mount import lock poisoned"))?
            .clone();
        descriptors
            .iter()
            .map(|descriptor| {
                snapshot_windows_mount(descriptor).with_context(|| {
                    format!("snapshotting Windows mount '{}' source", descriptor.tag)
                })
            })
            .collect()
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn plan_windows_mount_cache(&self, snapshots: &[WindowsMountSnapshot]) -> WindowsMountCacheRun {
        if snapshots.is_empty() {
            return WindowsMountCacheRun {
                cache: None,
                images: Vec::new(),
                routes: Vec::new(),
            };
        }
        let cache = match WindowsMountCache::new(&self.windows_data_dir) {
            Ok(cache) => cache,
            Err(error) => {
                return WindowsMountCacheRun::all_fallback(
                    snapshots,
                    format!("mount cache initialization failed: {error:#}"),
                );
            }
        };
        if let Err(error) = cache.maintain() {
            eprintln!(
                "lsb: mount cache maintenance failed; continuing without eviction: {error:#}"
            );
        }
        let mut images = Vec::<WindowsMountCacheRunImage>::new();
        let mut routes = Vec::with_capacity(snapshots.len());
        let mut digests = HashMap::<String, Option<usize>>::new();

        for (snapshot_index, snapshot) in snapshots.iter().enumerate() {
            let image_id = snapshot.key.to_hex();
            if let Some(existing) = digests.get(&image_id) {
                match existing {
                    Some(image_index) => {
                        images[*image_index].binding_indices.push(snapshot_index);
                        routes.push(WindowsMountCacheRoute::Selected {
                            image_index: *image_index,
                            binding_id: format!("binding-{}", snapshot.descriptor.tag),
                        });
                    }
                    None => routes.push(WindowsMountCacheRoute::Fallback {
                        reason: "cache selection for this content digest was bypassed".to_string(),
                    }),
                }
                continue;
            }

            match cache.select(snapshot) {
                Ok(WindowsMountCacheSelection::Hit(hit)) => {
                    let image_index = images.len();
                    images.push(WindowsMountCacheRunImage {
                        image_id: image_id.clone(),
                        serial: format!("lsb-cache-{image_index}"),
                        lease: WindowsMountCacheLease::Hit(Some(hit)),
                        state: WindowsMountCacheImageState::Selected,
                        binding_indices: vec![snapshot_index],
                        invalidate_after_stop: false,
                    });
                    digests.insert(image_id, Some(image_index));
                    routes.push(WindowsMountCacheRoute::Selected {
                        image_index,
                        binding_id: format!("binding-{}", snapshot.descriptor.tag),
                    });
                }
                Ok(WindowsMountCacheSelection::Build(build)) => {
                    let image_index = images.len();
                    images.push(WindowsMountCacheRunImage {
                        image_id: image_id.clone(),
                        serial: format!("lsb-cache-{image_index}"),
                        lease: WindowsMountCacheLease::Build(Some(build)),
                        state: WindowsMountCacheImageState::Selected,
                        binding_indices: vec![snapshot_index],
                        invalidate_after_stop: false,
                    });
                    digests.insert(image_id, Some(image_index));
                    routes.push(WindowsMountCacheRoute::Selected {
                        image_index,
                        binding_id: format!("binding-{}", snapshot.descriptor.tag),
                    });
                }
                Ok(WindowsMountCacheSelection::Bypass { reason }) => {
                    digests.insert(image_id, None);
                    routes.push(WindowsMountCacheRoute::Fallback { reason });
                }
                Err(error) => {
                    digests.insert(image_id, None);
                    routes.push(WindowsMountCacheRoute::Fallback {
                        reason: format!("cache selection failed: {error:#}"),
                    });
                }
            }
        }

        WindowsMountCacheRun {
            cache: Some(cache),
            images,
            routes,
        }
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn initialize_windows_mounts(
        &self,
        snapshots: &[WindowsMountSnapshot],
        cache_run: &mut WindowsMountCacheRun,
    ) -> Result<()> {
        let has_pending_mounts = !self
            .mounts
            .lock()
            .map_err(|_| anyhow::anyhow!("mount request lock poisoned"))?
            .is_empty();
        let has_pending_smb_mounts = self
            .mounts
            .lock()
            .map_err(|_| anyhow::anyhow!("mount request lock poisoned"))?
            .iter()
            .any(|request| matches!(request, MountRequest::Smb { .. }));
        if snapshots.is_empty() && !has_pending_mounts {
            return Ok(());
        }

        let _metrics_guard = self.mount_metrics.begin_mount_init();

        if cache_run.has_selected_routes() && !self.supports_session_mux() {
            cache_run.disable_while_running(
                "guest mount cache requires the persistent mux file session",
            );
        }
        if cache_run.needs_payload_transfer() {
            self.mount_metrics
                .set_failure_context(FailedPhase::Transfer, ErrorCategory::ProtocolFailure);
            self.ensure_file_range_io("Windows mount import")?;
        }
        if has_pending_smb_mounts {
            self.ensure_cifs_mount("Windows SMB direct mount")?;
        }
        let result = if self.supports_session_mux() {
            self.initialize_windows_mounts_mux(snapshots, cache_run)
        } else {
            self.initialize_windows_mounts_legacy(snapshots)
        };
        if result.is_ok() {
            self.windows_mounts
                .lock()
                .map_err(|_| anyhow::anyhow!("Windows mount import lock poisoned"))?
                .clear();
            cache_run.record_metrics(&self.mount_metrics);
            if cache_run.has_fallback_routes() {
                self.mount_metrics.mark_fallback_mounts_used();
                cache_run.report_fallbacks();
            }
        }
        result
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn initialize_windows_mounts_mux(
        &self,
        snapshots: &[WindowsMountSnapshot],
        cache_run: &mut WindowsMountCacheRun,
    ) -> Result<()> {
        let defer_sync = self.supports_deferred_file_sync();
        self.mount_metrics
            .set_failure_context(FailedPhase::Transfer, ErrorCategory::TransportFailure);
        self.with_guest_control_session("mount init", |writer, reader| {
            self.mount_metrics
                .set_failure_context(FailedPhase::Transfer, ErrorCategory::SourceMutation);
            if cache_run.has_selected_routes() {
                self.initialize_mount_cache_on_session(writer, reader, snapshots, cache_run)?;
            }
            for (snapshot_index, snapshot) in snapshots.iter().enumerate() {
                if cache_run.route_is_selected(snapshot_index) {
                    continue;
                }
                let transfer_started = Instant::now();
                let copy_result = self
                    .copy_windows_mount_snapshot_on_session(writer, reader, snapshot, defer_sync);
                self.mount_metrics
                    .add_duration(DurationMetric::Transfer, transfer_started.elapsed());
                copy_result.with_context(|| {
                    format!(
                        "copying Windows mount '{}' into guest staging path '{}'",
                        snapshot.descriptor.tag, snapshot.descriptor.guest_source
                    )
                })?;
            }

            if defer_sync && cache_run.has_fallback_routes() {
                self.sync_windows_mount_import_on_session(writer, reader)?;
            }

            self.mount_metrics
                .set_failure_context(FailedPhase::OverlayMount, ErrorCategory::GuestRejected);
            let overlay_started = Instant::now();
            let result = self.send_mount_requests(writer, reader);
            self.mount_metrics
                .add_duration(DurationMetric::OverlayMount, overlay_started.elapsed());
            result
        })
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn initialize_mount_cache_on_session(
        &self,
        writer: &mut impl Write,
        reader: &mut impl Read,
        snapshots: &[WindowsMountSnapshot],
        cache_run: &mut WindowsMountCacheRun,
    ) -> Result<()> {
        for image_index in 0..cache_run.images.len() {
            if matches!(
                cache_run.images[image_index].state,
                WindowsMountCacheImageState::Fallback
            ) {
                continue;
            }
            let image_id = cache_run.images[image_index].image_id.clone();
            let serial = cache_run.images[image_index].serial.clone();
            let expected_size = cache_run.images[image_index].lease.virtual_size();
            let inode_count = cache_run.images[image_index].lease.inode_count();
            let is_hit = cache_run.images[image_index].lease.is_hit();
            let prepare = if is_hit {
                MountCacheRequest::PrepareHit {
                    image_id: image_id.clone(),
                    serial,
                    expected_size,
                    expected_key: image_id.clone(),
                }
            } else {
                MountCacheRequest::PrepareBuild {
                    image_id: image_id.clone(),
                    serial,
                    expected_size,
                    expected_key: image_id.clone(),
                    inode_count,
                }
            };
            let prepare_started = Instant::now();
            let prepare_response =
                self.send_mount_cache_request_on_session(writer, reader, &prepare)?;
            self.mount_metrics.add_duration(
                if is_hit {
                    DurationMetric::CacheValidate
                } else {
                    DurationMetric::CacheFormat
                },
                prepare_started.elapsed(),
            );
            match prepare_response {
                MountCacheResponse::Rejected { reason, .. } => {
                    eprintln!(
                        "lsb: guest rejected mount cache image {image_id} during prepare ({reason:?}); using copy fallback"
                    );
                    cache_run.fallback_image(
                        image_index,
                        format!("guest cache prepare rejected: {reason:?}"),
                        is_hit,
                    );
                    continue;
                }
                MountCacheResponse::Ready { computed_key, .. } => {
                    if is_hit && computed_key.as_deref() != Some(image_id.as_str()) {
                        bail!(
                            "guest cache hit validation returned a different source key for {image_id}"
                        );
                    }
                    if is_hit {
                        let snapshot_index = cache_run.images[image_index]
                            .binding_indices
                            .first()
                            .copied()
                            .ok_or_else(|| anyhow::anyhow!("cache hit has no mount bindings"))?;
                        self.mount_metrics.record_guest_validation_bytes_hashed(
                            snapshots[snapshot_index].logical_bytes,
                        );
                    }
                }
            }

            let mut raw_device_digest = None;
            if !is_hit {
                let snapshot_index = *cache_run.images[image_index]
                    .binding_indices
                    .first()
                    .ok_or_else(|| anyhow::anyhow!("cache image has no mount bindings"))?;
                let snapshot = snapshots.get(snapshot_index).ok_or_else(|| {
                    anyhow::anyhow!("cache image binding references a missing snapshot")
                })?;
                let transfer_started = Instant::now();
                let copy_result = self.copy_windows_mount_snapshot_to_cache_on_session(
                    writer, reader, snapshot, &image_id,
                );
                self.mount_metrics
                    .add_duration(DurationMetric::Transfer, transfer_started.elapsed());
                if let Err(error) = copy_result {
                    if let Some(rejected) = error.downcast_ref::<MountCacheImportRejected>() {
                        eprintln!(
                            "lsb: guest rejected mount cache image {image_id} during import ({:?}); using copy fallback",
                            rejected.0
                        );
                        cache_run.fallback_image(
                            image_index,
                            format!("guest cache import rejected: {:?}", rejected.0),
                            false,
                        );
                        continue;
                    }
                    let abort = MountCacheRequest::AbortBuild {
                        image_id: image_id.clone(),
                    };
                    let _ = self.send_mount_cache_request_on_session(writer, reader, &abort);
                    return Err(error).context(format!(
                        "copying Windows mount '{}' into cache build image",
                        snapshot.descriptor.tag
                    ));
                }
                let seal = MountCacheRequest::SealBuild {
                    image_id: image_id.clone(),
                    expected_key: image_id.clone(),
                };
                let seal_started = Instant::now();
                let seal_response =
                    self.send_mount_cache_request_on_session(writer, reader, &seal)?;
                self.mount_metrics
                    .add_duration(DurationMetric::CacheValidate, seal_started.elapsed());
                match seal_response {
                    MountCacheResponse::Rejected { reason, .. } => {
                        eprintln!(
                            "lsb: guest rejected mount cache image {image_id} during seal ({reason:?}); using copy fallback"
                        );
                        cache_run.fallback_image(
                            image_index,
                            format!("guest cache seal rejected: {reason:?}"),
                            false,
                        );
                        continue;
                    }
                    MountCacheResponse::Ready {
                        computed_key,
                        raw_device_digest: sealed_digest,
                        ..
                    } => {
                        if computed_key.as_deref() != Some(image_id.as_str()) {
                            bail!(
                                "guest cache seal returned a different source key for {image_id}"
                            );
                        }
                        let digest = sealed_digest.ok_or_else(|| {
                            anyhow::anyhow!("guest cache seal omitted its raw-device digest")
                        })?;
                        cache_run.images[image_index].state = WindowsMountCacheImageState::Sealed {
                            raw_device_digest: digest.clone(),
                        };
                        self.mount_metrics.record_guest_validation_bytes_hashed(
                            snapshot.logical_bytes.saturating_mul(2),
                        );
                        self.mount_metrics
                            .record_raw_image_bytes_hashed(expected_size);
                        self.mount_metrics.record_final_barrier();
                    }
                }
            }

            let binding_indices = cache_run.images[image_index].binding_indices.clone();
            let mut rejected = None;
            for snapshot_index in &binding_indices {
                let snapshot = snapshots.get(*snapshot_index).ok_or_else(|| {
                    anyhow::anyhow!("cache binding references a missing snapshot")
                })?;
                let binding_id = match cache_run.routes.get(*snapshot_index) {
                    Some(WindowsMountCacheRoute::Selected {
                        image_index: selected_image,
                        binding_id,
                    }) if *selected_image == image_index => binding_id.clone(),
                    _ => bail!("cache binding route changed before overlay mount"),
                };
                let request = MountCacheRequest::MountOverlay {
                    image_id: image_id.clone(),
                    binding_id,
                    target: snapshot.descriptor.guest_target.clone(),
                };
                let overlay_started = Instant::now();
                let response =
                    self.send_mount_cache_request_on_session(writer, reader, &request)?;
                self.mount_metrics
                    .add_duration(DurationMetric::OverlayMount, overlay_started.elapsed());
                if let MountCacheResponse::Rejected { reason, .. } = response {
                    rejected = Some(reason);
                    break;
                }
            }
            if let Some(reason) = rejected {
                eprintln!(
                    "lsb: guest rejected mount cache overlay for {image_id} ({reason:?}); using copy fallback"
                );
                cache_run.fallback_image(
                    image_index,
                    format!("guest cache overlay rejected: {reason:?}"),
                    false,
                );
                continue;
            }

            if !is_hit {
                raw_device_digest = match &cache_run.images[image_index].state {
                    WindowsMountCacheImageState::Sealed { raw_device_digest } => {
                        Some(raw_device_digest.clone())
                    }
                    _ => bail!("cache build lost its sealed state before binding mounts"),
                };
            }
            self.consume_cache_mount_requests(snapshots, &binding_indices)?;
            cache_run.images[image_index].state =
                WindowsMountCacheImageState::AllBindingsMounted { raw_device_digest };
        }
        Ok(())
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn send_mount_cache_request_on_session(
        &self,
        writer: &mut impl Write,
        reader: &mut impl Read,
        request: &MountCacheRequest,
    ) -> Result<MountCacheResponse> {
        request
            .validate()
            .context("validating host mount cache request")?;
        frame::send_json(writer, frame::MOUNT_CACHE_REQ, request)
            .context("sending mount cache request")?;
        self.mount_metrics.record_filesystem_request();
        let (msg_type, payload) =
            read_response_frame(reader, "mount cache").context("reading mount cache response")?;
        self.mount_metrics.record_filesystem_response();
        if msg_type == frame::ERROR {
            bail!(
                "guest mount cache protocol error: {}",
                String::from_utf8_lossy(&payload)
            );
        }
        if msg_type != frame::MOUNT_CACHE_RESP {
            bail!("unexpected frame type 0x{msg_type:02x} in mount cache response");
        }
        let response: MountCacheResponse =
            serde_json::from_slice(&payload).context("decoding mount cache response")?;
        response
            .validate_for(request)
            .context("validating mount cache response")?;
        Ok(response)
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn consume_cache_mount_requests(
        &self,
        snapshots: &[WindowsMountSnapshot],
        snapshot_indices: &[usize],
    ) -> Result<()> {
        let mut mounts = self
            .mounts
            .lock()
            .map_err(|_| anyhow::anyhow!("mount request lock poisoned"))?;
        let mut positions = Vec::with_capacity(snapshot_indices.len());
        for snapshot_index in snapshot_indices {
            let snapshot = snapshots.get(*snapshot_index).ok_or_else(|| {
                anyhow::anyhow!("cache mount consumption references a missing snapshot")
            })?;
            let matching = mounts
                .iter()
                .enumerate()
                .filter_map(|(position, request)| match request {
                    MountRequest::Overlay { source, target }
                        if source == &snapshot.descriptor.guest_source
                            && target == &snapshot.descriptor.guest_target =>
                    {
                        Some(position)
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            if matching.len() != 1 {
                bail!(
                    "cache mount '{}' expected exactly one pending legacy request, found {}",
                    snapshot.descriptor.tag,
                    matching.len()
                );
            }
            positions.push(matching[0]);
        }
        positions.sort_unstable();
        positions.dedup();
        if positions.len() != snapshot_indices.len() {
            bail!("multiple cache bindings resolved to the same pending mount request");
        }
        for position in positions.into_iter().rev() {
            mounts.remove(position);
        }
        Ok(())
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn initialize_windows_mounts_legacy(&self, snapshots: &[WindowsMountSnapshot]) -> Result<()> {
        let defer_sync = self.supports_deferred_file_sync();
        for snapshot in snapshots {
            self.mount_metrics
                .set_failure_context(FailedPhase::Transfer, ErrorCategory::SourceMutation);
            let mux_open_before = self
                .mount_metrics
                .duration_ms(DurationMetric::MuxSessionOpen);
            let transfer_started = Instant::now();
            let copy_result = self.copy_windows_mount_snapshot_legacy(snapshot, defer_sync);
            let transfer_elapsed_ms = transfer_started.elapsed().as_secs_f64() * 1000.0;
            let mux_open_after = self
                .mount_metrics
                .duration_ms(DurationMetric::MuxSessionOpen);
            self.mount_metrics.add_duration_ms(
                DurationMetric::Transfer,
                (transfer_elapsed_ms - (mux_open_after - mux_open_before)).max(0.0),
            );
            copy_result.with_context(|| {
                format!(
                    "copying Windows mount '{}' into guest staging path '{}'",
                    snapshot.descriptor.tag, snapshot.descriptor.guest_source
                )
            })?;
        }

        if defer_sync && !snapshots.is_empty() {
            self.mount_metrics
                .set_failure_context(FailedPhase::Barrier, ErrorCategory::BarrierFailed);
            self.with_guest_control_session("mount import sync", |writer, reader| {
                self.sync_windows_mount_import_on_session(writer, reader)
            })?;
        }

        self.mount_metrics
            .set_failure_context(FailedPhase::OverlayMount, ErrorCategory::GuestRejected);
        self.with_guest_control_session("mount init", |writer, reader| {
            let overlay_started = Instant::now();
            let result = self.send_mount_requests(writer, reader);
            self.mount_metrics
                .add_duration(DurationMetric::OverlayMount, overlay_started.elapsed());
            result
        })
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn copy_windows_mount_snapshot_legacy(
        &self,
        snapshot: &WindowsMountSnapshot,
        defer_sync: bool,
    ) -> Result<()> {
        for entry in &snapshot.entries {
            match entry.kind {
                WindowsMountSnapshotEntryKind::Directory { mode } => self
                    .void_fs_op(
                        frame::MKDIR_REQ,
                        &MkdirRequest {
                            path: entry.guest_path.clone(),
                            recursive: true,
                            mode: Some(mode),
                        },
                    )
                    .with_context(|| {
                        format!("creating mount snapshot directory '{}'", entry.guest_path)
                    })?,
                WindowsMountSnapshotEntryKind::File { mode, .. } => self
                    .transfer_windows_mount_snapshot_file(entry, |offset, truncate, data| {
                        self.write_guest_file_range(
                            &entry.guest_path,
                            offset,
                            truncate,
                            data,
                            defer_sync,
                            Some(mode),
                        )
                    })?,
            }
        }
        Ok(())
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn copy_windows_mount_snapshot_to_cache_on_session(
        &self,
        writer: &mut impl Write,
        reader: &mut impl Read,
        snapshot: &WindowsMountSnapshot,
        image_id: &str,
    ) -> Result<()> {
        let mut entries = Vec::<MountCacheImportEntry>::new();
        let mut data = Vec::<u8>::new();
        let mut metadata_bytes = 0usize;
        for entry in &snapshot.entries {
            if entry.relative_path.is_empty() {
                continue;
            }
            match entry.kind {
                WindowsMountSnapshotEntryKind::Directory { .. } => {
                    let entry_cost = entry.relative_path.len().saturating_add(64);
                    if !entries.is_empty()
                        && (entries.len() >= 1024
                            || metadata_bytes.saturating_add(entry_cost)
                                > MOUNT_CACHE_BATCH_METADATA_BUDGET)
                    {
                        self.flush_mount_cache_import_batch(
                            writer,
                            reader,
                            image_id,
                            &mut entries,
                            &mut data,
                        )?;
                        metadata_bytes = 0;
                    }
                    entries.push(MountCacheImportEntry::Directory {
                        path: entry.relative_path.clone(),
                    });
                    metadata_bytes = metadata_bytes.saturating_add(entry_cost);
                }
                WindowsMountSnapshotEntryKind::File { .. } => {
                    self.transfer_windows_mount_snapshot_file(entry, |offset, truncate, bytes| {
                        let entry_cost = entry.relative_path.len().saturating_add(96);
                        if !entries.is_empty()
                            && (entries.len() >= 1024
                                || metadata_bytes.saturating_add(entry_cost)
                                    > MOUNT_CACHE_BATCH_METADATA_BUDGET
                                || data.len().saturating_add(bytes.len())
                                    > MOUNT_CACHE_BATCH_DATA_SIZE)
                        {
                            self.flush_mount_cache_import_batch(
                                writer,
                                reader,
                                image_id,
                                &mut entries,
                                &mut data,
                            )?;
                            metadata_bytes = 0;
                        }
                        entries.push(MountCacheImportEntry::FileChunk {
                            path: entry.relative_path.clone(),
                            offset,
                            len: u32::try_from(bytes.len())
                                .context("cache import chunk exceeds u32")?,
                            truncate,
                        });
                        data.extend_from_slice(bytes);
                        metadata_bytes = metadata_bytes.saturating_add(entry_cost);
                        if data.len() >= MOUNT_CACHE_BATCH_DATA_SIZE {
                            self.flush_mount_cache_import_batch(
                                writer,
                                reader,
                                image_id,
                                &mut entries,
                                &mut data,
                            )?;
                            metadata_bytes = 0;
                        }
                        Ok(())
                    })?;
                }
            }
        }
        self.flush_mount_cache_import_batch(writer, reader, image_id, &mut entries, &mut data)
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn flush_mount_cache_import_batch(
        &self,
        writer: &mut impl Write,
        reader: &mut impl Read,
        image_id: &str,
        entries: &mut Vec<MountCacheImportEntry>,
        data: &mut Vec<u8>,
    ) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        let file_chunks = entries
            .iter()
            .filter(|entry| matches!(entry, MountCacheImportEntry::FileChunk { .. }))
            .count() as u64;
        let request = MountCacheRequest::ImportBatch {
            image_id: image_id.to_string(),
            entries: std::mem::take(entries),
            data_len: u32::try_from(data.len()).context("cache import batch exceeds u32")?,
        };
        request
            .validate()
            .context("validating host cache import batch")?;
        frame::send_json(writer, frame::MOUNT_CACHE_REQ, &request)
            .context("sending cache import batch request")?;
        frame::write_frame(writer, frame::MOUNT_CACHE_DATA, data)
            .context("sending cache import batch data")?;
        self.mount_metrics.record_filesystem_request();
        let (message_type, payload) = read_response_frame(reader, "mount cache import")
            .context("reading cache import batch response")?;
        self.mount_metrics.record_filesystem_response();
        if message_type == frame::ERROR {
            bail!(
                "guest mount cache import protocol error: {}",
                String::from_utf8_lossy(&payload)
            );
        }
        if message_type != frame::MOUNT_CACHE_RESP {
            bail!("unexpected frame type 0x{message_type:02x} in cache import batch response");
        }
        let response: MountCacheResponse =
            serde_json::from_slice(&payload).context("decoding cache import batch response")?;
        response
            .validate_for(&request)
            .context("validating cache import batch response")?;
        if let MountCacheResponse::Rejected { reason, .. } = response {
            return Err(anyhow::Error::new(MountCacheImportRejected(reason)));
        }
        self.mount_metrics
            .record_cache_import_batch(data.len() as u64, file_chunks);
        data.clear();
        Ok(())
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn copy_windows_mount_snapshot_on_session(
        &self,
        writer: &mut impl Write,
        reader: &mut impl Read,
        snapshot: &WindowsMountSnapshot,
        defer_sync: bool,
    ) -> Result<()> {
        self.copy_windows_mount_snapshot_to_source_on_session(
            writer,
            reader,
            snapshot,
            &snapshot.descriptor.guest_source,
            defer_sync,
        )
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn copy_windows_mount_snapshot_to_source_on_session(
        &self,
        writer: &mut impl Write,
        reader: &mut impl Read,
        snapshot: &WindowsMountSnapshot,
        guest_source: &str,
        defer_sync: bool,
    ) -> Result<()> {
        for entry in &snapshot.entries {
            let guest_path = if entry.relative_path.is_empty() {
                guest_source.to_string()
            } else {
                join_guest_child(guest_source, &entry.relative_path)
            };
            match entry.kind {
                WindowsMountSnapshotEntryKind::Directory { mode } => self
                    .void_fs_op_on_session(
                        writer,
                        reader,
                        frame::MKDIR_REQ,
                        &MkdirRequest {
                            path: guest_path.clone(),
                            recursive: true,
                            mode: Some(mode),
                        },
                    )
                    .with_context(|| format!("creating mount snapshot directory '{guest_path}'"))?,
                WindowsMountSnapshotEntryKind::File { mode, .. } => self
                    .transfer_windows_mount_snapshot_file(entry, |offset, truncate, data| {
                        self.write_guest_file_range_on_session(
                            writer,
                            reader,
                            &guest_path,
                            offset,
                            truncate,
                            data,
                            defer_sync,
                            Some(mode),
                        )
                    })?,
            }
        }
        Ok(())
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn transfer_windows_mount_snapshot_file(
        &self,
        entry: &WindowsMountSnapshotEntry,
        mut write_chunk: impl FnMut(u64, bool, &[u8]) -> Result<()>,
    ) -> Result<()> {
        let WindowsMountSnapshotEntryKind::File {
            len,
            identity,
            digest: expected_digest,
            ..
        } = entry.kind
        else {
            bail!("mount snapshot transfer received a directory entry");
        };
        let mut checked =
            open_copy_in_file_for_snapshot(&entry.host_path, Some(len), Some(identity))
                .with_context(|| {
                    format!(
                        "reopening mount snapshot source '{}'",
                        entry.host_path.display()
                    )
                })?;
        let mut hasher = blake3::Hasher::new();
        let mut buffer = vec![0u8; FILE_TRANSFER_CHUNK_SIZE];
        let mut offset = 0u64;
        let mut first = true;
        loop {
            let count = checked.file_mut().read(&mut buffer).with_context(|| {
                format!(
                    "reading mount snapshot source '{}'",
                    entry.host_path.display()
                )
            })?;
            if count == 0 {
                if first {
                    write_chunk(0, true, &[])?;
                }
                break;
            }
            write_chunk(offset, first, &buffer[..count])?;
            hasher.update(&buffer[..count]);
            offset = offset.saturating_add(count as u64);
            first = false;
        }
        if offset != len {
            bail!(
                "mount snapshot source '{}' changed length during transfer: expected {} bytes, read {} bytes",
                entry.host_path.display(),
                len,
                offset
            );
        }
        checked.validate_unchanged(&entry.host_path)?;
        if hasher.finalize().as_bytes() != &expected_digest {
            bail!(
                "mount snapshot source '{}' content changed between snapshot and transfer",
                entry.host_path.display()
            );
        }
        self.mount_metrics
            .record_transfer_verification_bytes_hashed(offset);
        Ok(())
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn sync_windows_mount_import_on_session(
        &self,
        writer: &mut impl Write,
        reader: &mut impl Read,
    ) -> Result<()> {
        self.mount_metrics
            .set_failure_context(FailedPhase::Barrier, ErrorCategory::BarrierFailed);
        let barrier_started = Instant::now();
        let result = self.void_fs_op_on_session(
            writer,
            reader,
            frame::SYNC_FS_REQ,
            &SyncFsRequest {
                path: WINDOWS_MOUNT_STAGING_ROOT.to_string(),
            },
        );
        self.mount_metrics
            .add_duration(DurationMetric::Barrier, barrier_started.elapsed());
        if result.is_ok() {
            self.mount_metrics.record_final_barrier();
        }
        result.context("syncing deferred Windows mount imports")
    }
}

fn sanitize_smb_mount_failure_message(
    mut message: String,
    share: &str,
    username: &str,
    password: &str,
) -> String {
    for sensitive in [share, username, password] {
        if !sensitive.is_empty() {
            message = message.replace(sensitive, "<redacted>");
        }
    }
    message
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

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn windows_control_session_kind(operation: &str) -> PlatformControlSessionKind {
    if operation == "exec" {
        PlatformControlSessionKind::Exec
    } else {
        PlatformControlSessionKind::File
    }
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
fn windows_smb_instance_id(rootfs_path: &str) -> String {
    Path::new(rootfs_path)
        .parent()
        .and_then(|parent| parent.file_name())
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("sandbox")
        .to_string()
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn guest_path_contains_or_equals(path: &str, ancestor: &str) -> bool {
    let path = normalize_guest_watch_path(path);
    let ancestor = normalize_guest_watch_path(ancestor);
    path == ancestor
        || path
            .strip_prefix(ancestor.as_str())
            .is_some_and(|suffix| suffix.starts_with('/'))
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn normalize_guest_watch_path(path: &str) -> String {
    if path.len() > 1 {
        path.trim_end_matches('/').to_string()
    } else {
        path.to_string()
    }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn windows_smb_cleanup_manifest_path_from_rootfs(rootfs_path: &str) -> Result<PathBuf> {
    let instance_dir = Path::new(rootfs_path).parent().ok_or_else(|| {
        anyhow::anyhow!(
            "Windows SMB rootfs path '{}' has no instance directory",
            rootfs_path
        )
    })?;
    Ok(windows_smb_cleanup_manifest_path(instance_dir))
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

fn validate_port_mappings(forwards: &[PortMapping]) -> Result<()> {
    let mut host_ports = HashSet::new();
    for mapping in forwards {
        if mapping.host_port == 0 {
            bail!("invalid port forward host port 0; use an explicit TCP port");
        }
        if mapping.guest_port == 0 {
            bail!("invalid port forward guest port 0; use an explicit TCP port");
        }
        if !host_ports.insert(mapping.host_port) {
            bail!(
                "duplicate port forward host port {}; each host listener port must be unique",
                mapping.host_port
            );
        }
    }
    Ok(())
}

#[cfg(any(
    target_os = "macos",
    all(target_os = "windows", target_arch = "x86_64")
))]
fn bind_loopback_listener(host_port: u16) -> Result<TcpListener> {
    let addr = format!("127.0.0.1:{host_port}");
    TcpListener::bind(&addr).with_context(|| format!("binding {addr}"))
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn stop_port_forwarding_when_vm_stops(state_rx: Receiver<VmState>, stop: Arc<AtomicBool>) {
    let mut observed_running = false;
    while !stop.load(Ordering::Relaxed) {
        match state_rx.recv_timeout(Duration::from_millis(50)) {
            Ok(state) if port_forward_state_should_stop(state, &mut observed_running) => {
                stop.store(true, Ordering::Relaxed);
                break;
            }
            Ok(_) | Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                stop.store(true, Ordering::Relaxed);
                break;
            }
        }
    }
}

#[cfg(any(test, all(target_os = "windows", target_arch = "x86_64")))]
fn port_forward_state_should_stop(state: VmState, observed_running: &mut bool) -> bool {
    match state {
        VmState::Running => {
            *observed_running = true;
            false
        }
        VmState::Stopping | VmState::Stopped | VmState::Error if *observed_running => true,
        _ => false,
    }
}

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
    let req = ForwardRequest {
        port: guest_port,
        session_id: None,
    };
    frame::send_json(&mut vsock_stream, frame::FWD_REQ, &req)?;

    // Read response frame
    let (msg_type, payload) = frame::read_frame(&mut vsock_stream)
        .context("reading forward response")?
        .context("guest closed connection during forward handshake")?;
    if msg_type != frame::FWD_RESP {
        bail!("unexpected frame type 0x{msg_type:02x} in forward response");
    }
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

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn handle_windows_forward_connection(
    tcp_stream: TcpStream,
    vm: &dyn PlatformVm,
    guest_port: u16,
    session_lock: Arc<Mutex<()>>,
) -> Result<()> {
    let _session_guard = session_lock
        .lock()
        .map_err(|_| anyhow::anyhow!("Windows port-forward session lock poisoned"))?;
    let forward_stream = vm
        .connect_port_forward()
        .context("opening Windows virtio-serial port-forward stream")?;
    let mut writer = forward_stream
        .try_clone()
        .context("cloning Windows port-forward writer")?;
    let mut reader = forward_stream;
    let session_id = PORT_FORWARD_SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);

    let req = ForwardRequest {
        port: guest_port,
        session_id: Some(session_id),
    };
    frame::send_json(&mut writer, frame::FWD_REQ, &req)
        .context("sending Windows port-forward request")?;

    let (msg_type, payload) =
        read_response_frame(&mut reader, "port forward").context("reading forward response")?;
    if msg_type != frame::FWD_RESP {
        bail!("unexpected frame type 0x{msg_type:02x} in forward response");
    }
    let resp: ForwardResponse =
        serde_json::from_slice(&payload).context("parsing forward response")?;
    if resp.session_id != Some(session_id) {
        bail!(
            "guest returned mismatched forward session id {:?}; expected {}",
            resp.session_id,
            session_id
        );
    }
    if resp.status != "ok" {
        bail!(
            "guest refused forward to port {}: {}",
            guest_port,
            resp.message.unwrap_or_else(|| "unknown error".to_string())
        );
    }

    relay_windows_forward(tcp_stream, reader, writer, session_id)
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn relay_windows_forward(
    tcp_stream: TcpStream,
    mut forward_reader: PlatformControlStream,
    mut forward_writer: PlatformControlStream,
    session_id: u64,
) -> Result<()> {
    let mut tcp_read = tcp_stream
        .try_clone()
        .context("cloning host TCP stream for port-forward upload")?;
    tcp_read
        .set_read_timeout(Some(Duration::from_millis(100)))
        .context("setting host TCP read timeout for port-forward upload")?;
    let mut tcp_write = tcp_stream;
    let upload_done = Arc::new(AtomicBool::new(false));
    let upload_done_thread = Arc::clone(&upload_done);
    let stop_upload = Arc::new(AtomicBool::new(false));
    let stop_upload_thread = Arc::clone(&stop_upload);

    let upload = std::thread::spawn(move || {
        let mut buffer = [0u8; 16 * 1024];
        loop {
            match tcp_read.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    let payload = lsb_proto::encode_forward_payload(session_id, &buffer[..n]);
                    if frame::write_frame(&mut forward_writer, frame::FWD_DATA, &payload).is_err() {
                        upload_done_thread.store(true, Ordering::Relaxed);
                        return;
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    if stop_upload_thread.load(Ordering::Relaxed) {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = frame::write_frame(
            &mut forward_writer,
            frame::FWD_CLOSE,
            &lsb_proto::encode_forward_close(session_id),
        );
        upload_done_thread.store(true, Ordering::Relaxed);
    });

    let result = loop {
        let frame = match frame::read_frame(&mut forward_reader) {
            Ok(Some(frame)) => frame,
            Ok(None) => {
                break Err(anyhow::anyhow!(
                    "Windows port-forward channel closed before guest closed the session"
                ));
            }
            Err(error) => {
                break Err(anyhow::anyhow!("reading forwarded guest bytes: {error}"));
            }
        };

        match frame {
            (frame::FWD_DATA, payload) => {
                let (frame_session_id, data) = match lsb_proto::decode_forward_payload(&payload) {
                    Ok(decoded) => decoded,
                    Err(error) => break Err(anyhow::anyhow!("decoding forward data: {error}")),
                };
                if frame_session_id != session_id {
                    break Err(anyhow::anyhow!(
                        "received forward data for session {}; expected {}",
                        frame_session_id,
                        session_id
                    ));
                }
                if let Err(error) = tcp_write.write_all(data) {
                    break Err(anyhow::anyhow!(
                        "writing forwarded guest bytes to host TCP client: {error}"
                    ));
                }
            }
            (frame::FWD_CLOSE, payload) => {
                let frame_session_id = match lsb_proto::decode_forward_close(&payload) {
                    Ok(session_id) => session_id,
                    Err(error) => {
                        break Err(anyhow::anyhow!("decoding forward close: {error}"));
                    }
                };
                if frame_session_id == session_id {
                    break Ok(());
                }
                break Err(anyhow::anyhow!(
                    "received forward close for session {}; expected {}",
                    frame_session_id,
                    session_id
                ));
            }
            (frame::ERROR, payload) => {
                break Err(anyhow::anyhow!(
                    "guest port-forward error: {}",
                    String::from_utf8_lossy(&payload)
                ));
            }
            (other, _) => {
                break Err(anyhow::anyhow!(
                    "unexpected frame type 0x{other:02x} in forwarded data stream"
                ));
            }
        }
    };

    stop_upload.store(true, Ordering::Relaxed);
    let _ = if result.is_ok() {
        tcp_write.shutdown(Shutdown::Write)
    } else {
        tcp_write.shutdown(Shutdown::Both)
    };
    let _ = upload.join();
    if !upload_done.load(Ordering::Relaxed) {
        tracing::debug!("port forward upload thread ended before close frame was sent");
    }
    result
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
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    use sha2::{Digest, Sha256};
    use std::io::Cursor;
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    use std::path::PathBuf;
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    use std::process::{Command, Stdio};

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
            #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
            windows_smb_mounts: Mutex::new(Vec::new()),
            #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
            windows_smb_resources: Mutex::new(None),
            #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
            windows_smb_instance_guard: Mutex::new(None),
            #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
            windows_smb_instance_id: "test-instance".to_string(),
            #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
            windows_smb_cleanup_manifest_path: temp_dir("test-instance")
                .join("windows-smb-cleanup.json"),
            #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
            windows_data_dir: temp_dir("test-cache-data"),
            #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
            windows_mount_cache_run: Mutex::new(None),
            #[cfg(not(target_os = "macos"))]
            control_session: Mutex::new(()),
            #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
            port_forward_session: Arc::new(Mutex::new(())),
            #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
            mount_metrics: WindowsMountMetrics::default(),
        }
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn mount_cache_hit_sends_zero_file_payload_and_consumes_legacy_route() {
        let fixture = temp_dir("cache-hit-fixture");
        fs::create_dir_all(&fixture).unwrap();
        fs::write(fixture.join("hello.txt"), b"hello").unwrap();
        let snapshot = snapshot_windows_mount(&WindowsMountDescriptor {
            tag: "mount0".to_string(),
            host_root: fixture.clone(),
            guest_source: "/tmp/lsb/mounts/mount0/source".to_string(),
            guest_target: "/workspace".to_string(),
        })
        .unwrap();
        let sandbox = sandbox_with_mount_requests(vec![MountRequest::Overlay {
            source: snapshot.descriptor.guest_source.clone(),
            target: snapshot.descriptor.guest_target.clone(),
        }]);
        seed_mount_cache_hit(&sandbox.windows_data_dir, &snapshot);
        let mut cache_run = sandbox.plan_windows_mount_cache(std::slice::from_ref(&snapshot));
        assert!(cache_run.images[0].lease.is_hit());

        let image_id = snapshot.key.to_hex();
        let mut responses = Vec::new();
        frame::send_json(
            &mut responses,
            frame::MOUNT_CACHE_RESP,
            &MountCacheResponse::Ready {
                action: lsb_proto::MountCacheAction::PrepareHit,
                image_id: image_id.clone(),
                binding_id: None,
                computed_key: Some(image_id.clone()),
                raw_device_digest: None,
            },
        )
        .unwrap();
        frame::send_json(
            &mut responses,
            frame::MOUNT_CACHE_RESP,
            &MountCacheResponse::Ready {
                action: lsb_proto::MountCacheAction::MountOverlay,
                image_id,
                binding_id: Some("binding-mount0".to_string()),
                computed_key: None,
                raw_device_digest: None,
            },
        )
        .unwrap();
        let mut writer = Vec::new();
        sandbox
            .initialize_mount_cache_on_session(
                &mut writer,
                &mut Cursor::new(responses),
                std::slice::from_ref(&snapshot),
                &mut cache_run,
            )
            .unwrap();

        let frames = collect_frames(&writer);
        assert_eq!(frames.len(), 2);
        assert!(frames
            .iter()
            .all(|(message_type, _)| *message_type == frame::MOUNT_CACHE_REQ));
        assert!(sandbox.mounts.lock().unwrap().is_empty());
        drop(cache_run);
        let _ = fs::remove_dir_all(fixture);
        cleanup_test_cache_data(&sandbox.windows_data_dir);
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn duplicate_snapshot_digests_attach_one_disk_with_distinct_bindings() {
        let fixture = temp_dir("cache-dedup-fixture");
        fs::create_dir_all(&fixture).unwrap();
        fs::write(fixture.join("hello.txt"), b"hello").unwrap();
        let first = snapshot_windows_mount(&WindowsMountDescriptor {
            tag: "mount0".to_string(),
            host_root: fixture.clone(),
            guest_source: "/tmp/lsb/mounts/mount0/source".to_string(),
            guest_target: "/one".to_string(),
        })
        .unwrap();
        let second = snapshot_windows_mount(&WindowsMountDescriptor {
            tag: "mount1".to_string(),
            host_root: fixture.clone(),
            guest_source: "/tmp/lsb/mounts/mount1/source".to_string(),
            guest_target: "/two".to_string(),
        })
        .unwrap();
        assert_eq!(first.key, second.key);
        let sandbox = sandbox_with_mount_requests(Vec::new());
        let mut cache_run = sandbox.plan_windows_mount_cache(&[first, second]);

        assert_eq!(cache_run.images.len(), 1);
        assert_eq!(cache_run.data_disks().len(), 1);
        assert_eq!(cache_run.images[0].binding_indices, [0, 1]);
        assert!(matches!(
            &cache_run.routes[0],
            WindowsMountCacheRoute::Selected { binding_id, .. } if binding_id == "binding-mount0"
        ));
        assert!(matches!(
            &cache_run.routes[1],
            WindowsMountCacheRoute::Selected { binding_id, .. } if binding_id == "binding-mount1"
        ));
        cache_run.disable_before_boot("test cleanup");
        let _ = fs::remove_dir_all(fixture);
        cleanup_test_cache_data(&sandbox.windows_data_dir);
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn cache_rejection_keeps_exactly_one_legacy_fallback_route() {
        let fixture = temp_dir("cache-reject-fixture");
        fs::create_dir_all(&fixture).unwrap();
        fs::write(fixture.join("hello.txt"), b"hello").unwrap();
        let snapshot = snapshot_windows_mount(&WindowsMountDescriptor {
            tag: "mount0".to_string(),
            host_root: fixture.clone(),
            guest_source: "/tmp/lsb/mounts/mount0/source".to_string(),
            guest_target: "/workspace".to_string(),
        })
        .unwrap();
        let sandbox = sandbox_with_mount_requests(vec![MountRequest::Overlay {
            source: snapshot.descriptor.guest_source.clone(),
            target: snapshot.descriptor.guest_target.clone(),
        }]);
        seed_mount_cache_hit(&sandbox.windows_data_dir, &snapshot);
        let mut cache_run = sandbox.plan_windows_mount_cache(std::slice::from_ref(&snapshot));
        let mut responses = Vec::new();
        frame::send_json(
            &mut responses,
            frame::MOUNT_CACHE_RESP,
            &MountCacheResponse::Rejected {
                action: lsb_proto::MountCacheAction::PrepareHit,
                image_id: snapshot.key.to_hex(),
                reason: lsb_proto::MountCacheRejectReason::InvalidSourceTree,
            },
        )
        .unwrap();
        sandbox
            .initialize_mount_cache_on_session(
                &mut Vec::new(),
                &mut Cursor::new(responses),
                std::slice::from_ref(&snapshot),
                &mut cache_run,
            )
            .unwrap();

        assert!(cache_run.has_fallback_routes());
        assert_eq!(sandbox.mounts.lock().unwrap().len(), 1);
        cache_run.finalize_after_stop(&sandbox.mount_metrics);
        let cache = WindowsMountCache::new(&sandbox.windows_data_dir).unwrap();
        let WindowsMountCacheSelection::Build(build) = cache.select(&snapshot).unwrap() else {
            panic!("guest-rejected hit should be invalidated for rebuild");
        };
        build.discard().unwrap();
        let _ = fs::remove_dir_all(fixture);
        cleanup_test_cache_data(&sandbox.windows_data_dir);
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn mount_cache_requires_base_and_batch_capabilities() {
        assert!(!capabilities_support_mount_cache(&[]));
        assert!(!capabilities_support_mount_cache(&[
            CAP_MOUNT_CACHE_V1.to_string()
        ]));
        assert!(!capabilities_support_mount_cache(&[
            CAP_MOUNT_CACHE_IMPORT_BATCH_V1.to_string()
        ]));
        assert!(capabilities_support_mount_cache(&[
            CAP_MOUNT_CACHE_V1.to_string(),
            CAP_MOUNT_CACHE_IMPORT_BATCH_V1.to_string(),
        ]));
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn sealed_or_mounted_build_without_startup_success_is_discarded() {
        for mounted in [false, true] {
            let fixture = temp_dir(if mounted {
                "cache-mounted-discard-fixture"
            } else {
                "cache-sealed-discard-fixture"
            });
            fs::create_dir_all(&fixture).unwrap();
            fs::write(fixture.join("hello.txt"), b"hello").unwrap();
            let snapshot = snapshot_windows_mount(&WindowsMountDescriptor {
                tag: "mount0".to_string(),
                host_root: fixture.clone(),
                guest_source: "/tmp/lsb/mounts/mount0/source".to_string(),
                guest_target: "/workspace".to_string(),
            })
            .unwrap();
            let sandbox = sandbox_with_mount_requests(Vec::new());
            let mut cache_run = sandbox.plan_windows_mount_cache(std::slice::from_ref(&snapshot));
            let raw_device_digest = "05".repeat(32);
            cache_run.images[0].state = if mounted {
                WindowsMountCacheImageState::AllBindingsMounted {
                    raw_device_digest: Some(raw_device_digest),
                }
            } else {
                WindowsMountCacheImageState::Sealed { raw_device_digest }
            };
            cache_run.finalize_after_stop(&sandbox.mount_metrics);

            let cache = WindowsMountCache::new(&sandbox.windows_data_dir).unwrap();
            let WindowsMountCacheSelection::Build(build) = cache.select(&snapshot).unwrap() else {
                panic!("an ineligible build must not leave a cache hit");
            };
            build.discard().unwrap();
            let _ = fs::remove_dir_all(fixture);
            cleanup_test_cache_data(&sandbox.windows_data_dir);
        }
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn seed_mount_cache_hit(data_dir: &Path, snapshot: &WindowsMountSnapshot) {
        let cache = WindowsMountCache::new(data_dir).unwrap();
        let WindowsMountCacheSelection::Build(build) = cache.select(snapshot).unwrap() else {
            panic!("cache seed should select a build");
        };
        let mut file = std::fs::File::open(&build.image_path).unwrap();
        let mut hasher = blake3::Hasher::new();
        let mut buffer = vec![0u8; 1024 * 1024];
        let mut remaining = build.virtual_size;
        while remaining != 0 {
            let wanted = remaining.min(buffer.len() as u64) as usize;
            file.read_exact(&mut buffer[..wanted]).unwrap();
            hasher.update(&buffer[..wanted]);
            remaining -= wanted as u64;
        }
        let digest = hasher.finalize().to_hex();
        drop(file);
        build.publish(&digest).unwrap();
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn collect_frames(bytes: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let mut reader = Cursor::new(bytes);
        let mut frames = Vec::new();
        while let Some(frame) = frame::read_frame(&mut reader).unwrap() {
            frames.push(frame);
        }
        frames
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn cleanup_test_cache_data(path: &Path) {
        fn clear_readonly(path: &Path) {
            let Ok(metadata) = fs::symlink_metadata(path) else {
                return;
            };
            if metadata.is_dir() {
                if let Ok(entries) = fs::read_dir(path) {
                    for entry in entries.flatten() {
                        clear_readonly(&entry.path());
                    }
                }
            } else if metadata.permissions().readonly() {
                let mut permissions = metadata.permissions();
                permissions.set_readonly(false);
                let _ = fs::set_permissions(path, permissions);
            }
        }
        clear_readonly(path);
        let _ = fs::remove_dir_all(path);
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
            MountRequest::Direct { .. } | MountRequest::Smb { .. } => {
                panic!("expected overlay request")
            }
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
            MountRequest::Overlay { .. } | MountRequest::Smb { .. } => {
                panic!("expected direct request")
            }
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
            MountRequest::Overlay { .. } | MountRequest::Smb { .. } => {
                panic!("expected direct request")
            }
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
            MountRequest::Direct { .. } | MountRequest::Smb { .. } => {
                panic!("expected overlay request")
            }
        }

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn windows_mount_transcript_uses_one_supplied_session_for_2000_files() {
        let root = temp_dir("persistent-mount-transcript");
        let source = root.join("src");
        for directory_index in 0..100 {
            let directory = source.join(format!("dir-{directory_index:03}"));
            std::fs::create_dir_all(&directory).expect("fixture directory");
            for file_index in 0..20 {
                write_fixture(
                    &directory.join(format!("file-{file_index:03}.bin")),
                    &[directory_index as u8, file_index as u8],
                );
            }
        }

        let snapshot = snapshot_windows_mount(&WindowsMountDescriptor {
            tag: "mount0".to_string(),
            host_root: source.clone(),
            guest_source: "/tmp/lsb/mounts/mount0/source".to_string(),
            guest_target: "/workspace".to_string(),
        })
        .expect("mount snapshot should build");
        let sandbox = sandbox_with_mount_requests(vec![MountRequest::Overlay {
            source: "/tmp/lsb/mounts/mount0/source".to_string(),
            target: "/workspace".to_string(),
        }]);

        let mut scripted_responses = Vec::new();
        for entry in &snapshot.entries {
            match entry.kind {
                WindowsMountSnapshotEntryKind::Directory { .. } => frame::send_json(
                    &mut scripted_responses,
                    frame::FS_OK_RESP,
                    &FsOkResponse {
                        ok: true,
                        error: None,
                    },
                )
                .expect("mkdir response"),
                WindowsMountSnapshotEntryKind::File { .. } => frame::send_json(
                    &mut scripted_responses,
                    frame::WRITE_FILE_RESP,
                    &WriteFileResponse {
                        ok: true,
                        error: None,
                    },
                )
                .expect("write response"),
            }
        }
        frame::send_json(
            &mut scripted_responses,
            frame::FS_OK_RESP,
            &FsOkResponse {
                ok: true,
                error: None,
            },
        )
        .expect("syncfs response");
        frame::send_json(
            &mut scripted_responses,
            frame::MOUNT_RESP,
            &MountResponse {
                source: "/tmp/lsb/mounts/mount0/source".to_string(),
                target: "/workspace".to_string(),
                ok: true,
                error: None,
            },
        )
        .expect("mount response");

        let mut reader = Cursor::new(scripted_responses);
        let mut writer = Vec::new();
        sandbox
            .copy_windows_mount_snapshot_on_session(&mut writer, &mut reader, &snapshot, true)
            .expect("copy transcript");
        sandbox
            .sync_windows_mount_import_on_session(&mut writer, &mut reader)
            .expect("syncfs transcript");
        sandbox
            .send_mount_requests(&mut writer, &mut reader)
            .expect("mount transcript");
        assert_eq!(reader.position(), reader.get_ref().len() as u64);

        let mut emitted = Cursor::new(writer);
        let mut directory_requests = 0usize;
        let mut write_requests = 0usize;
        let mut data_frames = 0usize;
        let mut sync_requests = 0usize;
        let mut mount_requests = 0usize;
        while emitted.position() < emitted.get_ref().len() as u64 {
            let (frame_type, payload) = frame::read_frame(&mut emitted)
                .expect("read emitted request frame")
                .expect("emitted request frame");
            match frame_type {
                frame::MKDIR_REQ => {
                    assert_eq!(mount_requests, 0);
                    let request: MkdirRequest =
                        serde_json::from_slice(&payload).expect("mkdir request json");
                    assert_eq!(request.mode, Some(lsb_proto::MOUNT_IMPORT_DIRECTORY_MODE));
                    directory_requests += 1;
                }
                frame::WRITE_FILE_REQ => {
                    assert_eq!(mount_requests, 0);
                    assert_eq!(sync_requests, 0);
                    let request: WriteFileRequest =
                        serde_json::from_slice(&payload).expect("write request json");
                    assert_eq!(request.defer_sync, Some(true));
                    assert_eq!(request.mode, Some(lsb_proto::MOUNT_IMPORT_FILE_MODE));
                    write_requests += 1;
                }
                frame::WRITE_FILE_DATA => {
                    assert_eq!(mount_requests, 0);
                    data_frames += 1;
                }
                frame::SYNC_FS_REQ => {
                    assert_eq!(write_requests, 2_000);
                    assert_eq!(data_frames, 2_000);
                    assert_eq!(mount_requests, 0);
                    sync_requests += 1;
                }
                frame::MOUNT_REQ => mount_requests += 1,
                other => panic!("unexpected transcript frame 0x{other:02x}"),
            }
        }

        assert_eq!(directory_requests, 101);
        assert_eq!(write_requests, 2_000);
        assert_eq!(data_frames, 2_000);
        assert_eq!(sync_requests, 1);
        assert_eq!(mount_requests, 1);
        assert!(sandbox.mounts.lock().expect("mount lock").is_empty());

        let image_id = snapshot.key.to_hex();
        let mut batch_responses = Vec::new();
        for _ in 0..10 {
            frame::send_json(
                &mut batch_responses,
                frame::MOUNT_CACHE_RESP,
                &MountCacheResponse::Ready {
                    action: lsb_proto::MountCacheAction::ImportBatch,
                    image_id: image_id.clone(),
                    binding_id: None,
                    computed_key: None,
                    raw_device_digest: None,
                },
            )
            .unwrap();
        }
        let mut batch_writer = Vec::new();
        sandbox
            .copy_windows_mount_snapshot_to_cache_on_session(
                &mut batch_writer,
                &mut Cursor::new(batch_responses),
                &snapshot,
                &image_id,
            )
            .expect("cache batch transcript");
        let frames = collect_frames(&batch_writer);
        let batch_requests = frames
            .iter()
            .filter(|(message_type, _)| *message_type == frame::MOUNT_CACHE_REQ)
            .count();
        let batch_data = frames
            .iter()
            .filter(|(message_type, _)| *message_type == frame::MOUNT_CACHE_DATA)
            .collect::<Vec<_>>();
        assert_eq!(batch_requests, 3);
        assert_eq!(batch_data.len(), 3);
        assert_eq!(
            batch_data
                .iter()
                .map(|(_, payload)| payload.len())
                .sum::<usize>(),
            4_000
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn windows_mount_transfer_rejects_same_length_content_mutation() {
        let root = temp_dir("mount-transfer-mutation");
        let source = root.join("src");
        std::fs::create_dir_all(&source).expect("fixture source");
        let file = source.join("input.txt");
        write_fixture(&file, b"before");
        let snapshot = snapshot_windows_mount(&WindowsMountDescriptor {
            tag: "mount0".to_string(),
            host_root: source,
            guest_source: "/tmp/lsb/mounts/mount0/source".to_string(),
            guest_target: "/workspace".to_string(),
        })
        .expect("mount snapshot");
        let entry = snapshot
            .entries
            .iter()
            .find(|entry| matches!(entry.kind, WindowsMountSnapshotEntryKind::File { .. }))
            .expect("snapshot file entry");

        write_fixture(&file, b"after!");
        let sandbox = sandbox_with_mount_requests(Vec::new());
        let error = sandbox
            .transfer_windows_mount_snapshot_file(entry, |_, _, _| Ok(()))
            .expect_err("changed content should reject transfer");

        assert!(error.to_string().contains("content changed"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn windows_direct_mount_plan_uses_smb_lifecycle_inputs() {
        let root = temp_dir("direct-mount-plan");
        let rw_source = root.join("rw");
        let ro_source = root.join("ro");
        std::fs::create_dir_all(&rw_source).expect("rw source dir");
        std::fs::create_dir_all(&ro_source).expect("ro source dir");

        let plan = build_mount_plan(&[
            MountConfig::Direct {
                host_path: rw_source.display().to_string(),
                guest_path: "/workspace".into(),
                flags: 0,
            },
            MountConfig::Direct {
                host_path: ro_source.display().to_string(),
                guest_path: "/readonly".into(),
                flags: MS_RDONLY,
            },
        ])
        .expect("Windows direct mount plan should build");

        assert!(plan.shared_dirs.is_empty());
        assert!(plan.windows_imports.is_empty());
        assert!(plan.mount_requests.is_empty());
        assert_eq!(plan.windows_smb_mounts.len(), 2);
        assert_eq!(plan.windows_smb_mounts[0].target, "/workspace");
        assert!(!plan.windows_smb_mounts[0].access.read_only());
        assert_eq!(plan.windows_smb_mounts[1].target, "/readonly");
        assert!(plan.windows_smb_mounts[1].access.read_only());

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn windows_watch_routes_only_non_smb_paths_to_guest_watch() {
        let sandbox = sandbox_with_mount_requests(Vec::new());
        {
            let mut mounts = sandbox
                .windows_smb_mounts
                .lock()
                .expect("Windows SMB mount lock");
            mounts.push(WindowsSmbMount::read_write(
                PathBuf::from(r"C:\host\workspace"),
                "/workspace",
            ));
            mounts.push(WindowsSmbMount::read_write(
                PathBuf::from(r"C:\host\nested"),
                "/workspace/nested",
            ));
        }

        assert_eq!(sandbox.windows_smb_watch_target("/tmp").unwrap(), None);
        assert_eq!(
            sandbox.windows_smb_watch_target("/workspace").unwrap(),
            Some("/workspace".to_string())
        );
        assert_eq!(
            sandbox
                .windows_smb_watch_target("/workspace/file.txt")
                .unwrap(),
            Some("/workspace".to_string())
        );
        assert_eq!(
            sandbox
                .windows_smb_watch_target("/workspace/nested/deep.txt")
                .unwrap(),
            Some("/workspace/nested".to_string())
        );
        assert_eq!(
            sandbox.windows_smb_watch_target("/workspace/").unwrap(),
            Some("/workspace".to_string())
        );
        assert_eq!(
            sandbox
                .windows_smb_watch_target("/workspace2/file.txt")
                .unwrap(),
            None
        );
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn windows_direct_mount_plan_rejects_unsupported_flags() {
        let root = temp_dir("direct-mount-flags");
        let source = root.join("src");
        std::fs::create_dir_all(&source).expect("source dir");

        let err = match build_mount_plan(&[MountConfig::Direct {
            host_path: source.display().to_string(),
            guest_path: "/workspace".into(),
            flags: MS_RDONLY | 2,
        }]) {
            Ok(_) => panic!("Windows direct mount unsupported flags should fail"),
            Err(error) => error,
        };

        let message = err.to_string();
        assert!(message.contains("unsupported flags"));
        assert!(message.contains("MS_RDONLY"));

        let _ = std::fs::remove_dir_all(root);
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
    fn send_mount_requests_redacts_smb_source_on_mount_failure() {
        let request = MountRequest::Smb {
            server: "localhost".into(),
            share: "lsb-secretinstance-m0-deadbeef".into(),
            target: "/workspace".into(),
            username: "lsb_123456789abc".into(),
            password: "SecretPassword123!".into(),
            domain: "WINHOST".into(),
            read_only: false,
            uid: 0,
            gid: 0,
            file_mode: 0o666,
            dir_mode: 0o777,
            options: Vec::new(),
        };
        let sandbox = sandbox_with_mount_requests(vec![request]);
        let mut writer = Vec::new();
        let mut reader_payload = Vec::new();
        frame::send_json(
            &mut reader_payload,
            frame::MOUNT_RESP,
            &MountResponse {
                source: "//localhost/lsb-secretinstance-m0-deadbeef".into(),
                target: "/workspace".into(),
                ok: false,
                error: Some(
                    "mount.cifs exited with status 32 for lsb-secretinstance-m0-deadbeef as lsb_123456789abc using SecretPassword123!".into(),
                ),
            },
        )
        .expect("mount response should encode");
        let mut reader = Cursor::new(reader_payload);

        let err = sandbox
            .send_mount_requests(&mut writer, &mut reader)
            .expect_err("SMB mount failure should fail");
        let message = err.to_string();

        assert!(message.contains("Windows SMB direct mount -> /workspace"));
        assert!(message.contains("mount.cifs exited with status 32"));
        assert!(message.contains("<redacted>"));
        assert!(!message.contains("lsb-secretinstance-m0-deadbeef"));
        assert!(!message.contains("lsb_123456789abc"));
        assert!(!message.contains("SecretPassword123!"));
        assert!(!message.contains("//localhost"));
    }

    #[test]
    fn port_forward_validation_rejects_zero_ports() {
        let host_zero = validate_port_mappings(&[PortMapping {
            host_port: 0,
            guest_port: 80,
        }])
        .expect_err("host port 0 should fail");
        assert!(host_zero.to_string().contains("host port 0"));

        let guest_zero = validate_port_mappings(&[PortMapping {
            host_port: 8080,
            guest_port: 0,
        }])
        .expect_err("guest port 0 should fail");
        assert!(guest_zero.to_string().contains("guest port 0"));
    }

    #[test]
    fn port_forward_validation_rejects_duplicate_host_ports() {
        let err = validate_port_mappings(&[
            PortMapping {
                host_port: 8080,
                guest_port: 80,
            },
            PortMapping {
                host_port: 8080,
                guest_port: 81,
            },
        ])
        .expect_err("duplicate host listener ports should fail");

        assert!(err
            .to_string()
            .contains("duplicate port forward host port 8080"));
    }

    #[cfg(any(
        target_os = "macos",
        all(target_os = "windows", target_arch = "x86_64")
    ))]
    #[test]
    fn port_forward_listener_binds_ipv4_loopback() {
        let listener = bind_loopback_listener(0).expect("ephemeral loopback bind should work");
        let addr = listener.local_addr().expect("listener addr");

        assert_eq!(addr.ip().to_string(), "127.0.0.1");
        assert_ne!(addr.port(), 0);
    }

    #[test]
    fn port_forward_stop_waits_for_running_before_terminal_state() {
        let mut observed_running = false;

        assert!(!port_forward_state_should_stop(
            VmState::Stopped,
            &mut observed_running
        ));
        assert!(!port_forward_state_should_stop(
            VmState::Starting,
            &mut observed_running
        ));
        assert!(!port_forward_state_should_stop(
            VmState::Running,
            &mut observed_running
        ));
        assert!(port_forward_state_should_stop(
            VmState::Stopped,
            &mut observed_running
        ));
    }

    #[test]
    fn exec_request_frame_includes_argv_env_and_cwd() {
        let mut env = HashMap::new();
        env.insert("LSB_TEST_ENV".to_string(), "present".to_string());
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
            decoded.env.get("LSB_TEST_ENV").map(String::as_str),
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
                env.insert("LSB_TEST_ENV".to_string(), "present".to_string());
                let code = sandbox.exec_with_env_and_cwd(
                    &["/bin/sh", "-c", "printf '%s:%s' \"$PWD\" \"$LSB_TEST_ENV\""],
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
    fn windows_qemu_spawn_guest_watch_smoke() {
        #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
        {
            eprintln!("skipping Windows QEMU spawn/watch smoke on non-Windows host");
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
                .expect("Windows spawn/watch smoke sandbox should build");

            sandbox
                .start()
                .expect("Windows spawn/watch smoke should reach guest ready");

            let watch_root = format!("/tmp/lsb-windows-watch-{}", std::process::id());
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let code = sandbox
                .exec(
                    &[
                        "/bin/sh",
                        "-c",
                        &format!("rm -rf {watch_root}; mkdir -p {watch_root}/sub"),
                    ],
                    &mut stdout,
                    &mut stderr,
                )
                .expect("watch fixture setup should run");
            assert_eq!(
                code,
                0,
                "watch fixture setup failed: stdout={}, stderr={}",
                String::from_utf8_lossy(&stdout),
                String::from_utf8_lossy(&stderr)
            );

            let watch_session = sandbox
                .open_watch_session(&watch_root, true)
                .expect("Windows mux guest watch session should open");
            let (watch_events, watch_reader) = spawn_watch_event_reader(watch_session);
            std::thread::sleep(Duration::from_secs(1));

            let result = (|| -> Result<()> {
                let env = HashMap::new();

                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                let mut stream = sandbox.open_exec_session(
                    &[
                        "/bin/sh",
                        "-c",
                        "echo chunk1; echo warn >&2; echo chunk2; exit 0",
                    ],
                    &env,
                    None,
                )?;
                let code = collect_exec_response(&mut stream, &mut stdout, &mut stderr)?;
                assert_eq!(code, 0);
                assert_eq!(String::from_utf8_lossy(&stdout), "chunk1\nchunk2\n");
                assert_eq!(String::from_utf8_lossy(&stderr), "warn\n");

                stdout.clear();
                stderr.clear();
                let mut stream = sandbox.open_exec_session(
                    &["/bin/sh", "-c", "printf '%s:%s' \"$PWD\" \"$LSB_TEST_ENV\""],
                    &HashMap::from([("LSB_TEST_ENV".to_string(), "present".to_string())]),
                    Some("/tmp"),
                )?;
                let code = collect_exec_response(&mut stream, &mut stdout, &mut stderr)?;
                assert_eq!(code, 0);
                assert_eq!(String::from_utf8_lossy(&stdout), "/tmp:present");
                assert!(stderr.is_empty());

                stdout.clear();
                stderr.clear();
                let mut stream =
                    sandbox.open_exec_session(&["/bin/sh", "-c", "exit 42"], &env, None)?;
                let code = collect_exec_response(&mut stream, &mut stdout, &mut stderr)?;
                assert_eq!(code, 42);
                assert!(stdout.is_empty());
                assert!(stderr.is_empty());

                let stream = sandbox.open_exec_session(
                    &[
                        "/bin/sh",
                        "-c",
                        "IFS= read -r line; printf '%s\n' \"$line\"",
                    ],
                    &env,
                    None,
                )?;
                let mut writer = stream.try_clone()?;
                frame::write_frame(&mut writer, frame::STDIN, b"spawn-stdin\n")?;
                writer.flush()?;
                drop(writer);
                stdout.clear();
                stderr.clear();
                let mut reader = stream;
                let code = collect_exec_response(&mut reader, &mut stdout, &mut stderr)?;
                assert_eq!(code, 0);
                assert_eq!(String::from_utf8_lossy(&stdout), "spawn-stdin\n");
                assert!(stderr.is_empty());

                let stream =
                    sandbox.open_exec_session(&["/bin/sh", "-c", "sleep 30"], &env, None)?;
                let mut writer = stream.try_clone()?;
                frame::write_frame(&mut writer, frame::KILL, &[])?;
                writer.flush()?;
                drop(writer);
                stdout.clear();
                stderr.clear();
                let mut reader = stream;
                let code = collect_exec_response(&mut reader, &mut stdout, &mut stderr)?;
                assert_ne!(code, 0, "killed process should not report success");

                let mut one = sandbox.open_exec_session(
                    &["/bin/sh", "-c", "sleep 0.2; echo one"],
                    &env,
                    None,
                )?;
                let mut two = sandbox.open_exec_session(
                    &["/bin/sh", "-c", "sleep 0.2; echo two"],
                    &env,
                    None,
                )?;
                let mut one_stdout = Vec::new();
                let mut one_stderr = Vec::new();
                let mut two_stdout = Vec::new();
                let mut two_stderr = Vec::new();
                assert_eq!(
                    collect_exec_response(&mut one, &mut one_stdout, &mut one_stderr)?,
                    0
                );
                assert_eq!(
                    collect_exec_response(&mut two, &mut two_stdout, &mut two_stderr)?,
                    0
                );
                assert_eq!(String::from_utf8_lossy(&one_stdout), "one\n");
                assert_eq!(String::from_utf8_lossy(&two_stdout), "two\n");
                assert!(one_stderr.is_empty());
                assert!(two_stderr.is_empty());

                let mut large = sandbox.open_exec_session(
                    &[
                        "/bin/sh",
                        "-c",
                        "i=0; while [ \"$i\" -lt 256 ]; do dd if=/dev/zero bs=4096 count=1 2>/dev/null | tr '\\0' L; i=$((i + 1)); done",
                    ],
                    &env,
                    None,
                )?;
                let mut small = sandbox.open_exec_session(
                    &["/bin/sh", "-c", "sleep 0.1; echo small-ready"],
                    &env,
                    None,
                )?;
                let mut small_stdout = Vec::new();
                let mut small_stderr = Vec::new();
                assert_eq!(
                    collect_exec_response(&mut small, &mut small_stdout, &mut small_stderr)?,
                    0
                );
                assert_eq!(String::from_utf8_lossy(&small_stdout), "small-ready\n");
                assert!(small_stderr.is_empty());

                let mut large_stdout = Vec::new();
                let mut large_stderr = Vec::new();
                assert_eq!(
                    collect_exec_response(&mut large, &mut large_stdout, &mut large_stderr)?,
                    0
                );
                assert!(
                    large_stdout.len() >= 1024 * 1024,
                    "large spawn should emit at least 1MiB, got {} bytes",
                    large_stdout.len()
                );
                assert!(large_stderr.is_empty());

                let mut touch = sandbox.open_exec_session(
                    &[
                        "/bin/sh",
                        "-c",
                        &format!(
                            "touch {watch_root}/new.txt && printf x >> {watch_root}/new.txt && mv {watch_root}/new.txt {watch_root}/renamed.txt && rm {watch_root}/renamed.txt && touch {watch_root}/sub/deep.txt"
                        ),
                    ],
                    &env,
                    None,
                )?;
                stdout.clear();
                stderr.clear();
                assert_eq!(
                    collect_exec_response(&mut touch, &mut stdout, &mut stderr)?,
                    0
                );

                let mut concurrent = sandbox.open_exec_session(
                    &[
                        "/bin/sh",
                        "-c",
                        &format!("sleep 0.2; echo started; touch {watch_root}/spawn-created.txt; echo done"),
                    ],
                    &env,
                    None,
                )?;
                stdout.clear();
                stderr.clear();
                assert_eq!(
                    collect_exec_response(&mut concurrent, &mut stdout, &mut stderr)?,
                    0
                );
                assert!(String::from_utf8_lossy(&stdout).contains("started"));
                assert!(String::from_utf8_lossy(&stdout).contains("done"));

                wait_for_guest_watch_events(
                    &watch_events,
                    &[
                        (&format!("{watch_root}/new.txt"), Some("create")),
                        (&format!("{watch_root}/new.txt"), Some("modify")),
                        (&format!("{watch_root}/renamed.txt"), Some("rename")),
                        (&format!("{watch_root}/renamed.txt"), Some("delete")),
                        (&format!("{watch_root}/sub/deep.txt"), Some("create")),
                        (&format!("{watch_root}/spawn-created.txt"), Some("create")),
                    ],
                )?;

                Ok(())
            })();

            let stop_result = sandbox.stop();
            watch_reader
                .join()
                .expect("Windows watch reader thread should not panic")
                .expect("Windows watch reader should stop cleanly");

            result.expect("Windows spawn/watch smoke should pass");
            stop_result.expect("Windows spawn/watch smoke QEMU should stop cleanly");
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
    fn windows_qemu_mount_smoke() {
        #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
        {
            eprintln!("skipping Windows QEMU mount smoke on non-Windows host");
        }

        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        {
            let kernel = required_env_path("LSB_WINDOWS_BOOT_KERNEL");
            let initrd = required_env_path("LSB_WINDOWS_BOOT_INITRD");
            let rootfs = required_env_path("LSB_WINDOWS_BOOT_ROOTFS");
            let host_root = rootfs
                .parent()
                .expect("rootfs should live in a work directory")
                .join("mount-fixture");
            let _ = std::fs::remove_dir_all(&host_root);
            let source = host_root.join("source");
            let export = host_root.join("export");
            let data_dir = host_root.join("data");
            let expected_manifest = create_windows_mount_benchmark_fixture(&source);
            std::fs::create_dir_all(&export).expect("export fixture dir");

            let sandbox = Sandbox::builder()
                .kernel(kernel.display().to_string())
                .initrd(initrd.display().to_string())
                .rootfs(rootfs.display().to_string())
                .data_dir(data_dir.display().to_string())
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
            {
                let active = sandbox.windows_mount_cache_run.lock().unwrap();
                let cache_run = active.as_ref().expect("cache run should remain active");
                assert_eq!(cache_run.images.len(), 1);
                assert!(!cache_run.images[0].lease.is_hit());
                assert!(matches!(
                    cache_run.images[0].state,
                    WindowsMountCacheImageState::PublishEligible { .. }
                ));
            }

            let result = (|| -> Result<()> {
                assert_eq!(guest_mount_manifest(&sandbox)?, expected_manifest);

                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                let code = sandbox.exec(
                    &[
                        "/bin/sh",
                        "-c",
                        "stat -c '%a:%n' /workspace /workspace/dir-000 /workspace/dir-000/file-000.bin",
                    ],
                    &mut stdout,
                    &mut stderr,
                )?;
                assert_eq!(
                    code,
                    0,
                    "mount mode assertion failed: {}",
                    String::from_utf8_lossy(&stderr)
                );
                let modes = String::from_utf8_lossy(&stdout);
                assert!(
                    modes.contains("755:/workspace\n"),
                    "unexpected modes: {modes}"
                );
                assert!(
                    modes.contains("755:/workspace/dir-000\n"),
                    "unexpected modes: {modes}"
                );
                assert!(
                    modes.contains("644:/workspace/dir-000/file-000.bin\n"),
                    "unexpected modes: {modes}"
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
                    "Windows mounts expose a startup snapshot, not live host synchronization"
                );

                sandbox.copy_to_host("/workspace/guest.txt", export.join("guest.txt"), false)?;
                assert_eq!(std::fs::read(export.join("guest.txt"))?, b"guest write");

                Ok(())
            })();

            let stop_result = sandbox.stop();
            result.expect("Windows mount smoke should pass");
            stop_result.expect("Windows mount smoke QEMU should stop cleanly");
            std::fs::remove_file(source.join("after-start.txt"))
                .expect("restore the original source key before the cache-hit run");

            let hit_sandbox = Sandbox::builder()
                .kernel(kernel.display().to_string())
                .initrd(initrd.display().to_string())
                .rootfs(rootfs.display().to_string())
                .data_dir(data_dir.display().to_string())
                .console(false)
                .mount(MountConfig::Overlay {
                    host_path: source.display().to_string(),
                    guest_path: "/workspace".into(),
                })
                .build()
                .expect("Windows mount cache-hit sandbox should build");
            hit_sandbox
                .start()
                .expect("Windows mount cache-hit sandbox should start");
            {
                let active = hit_sandbox.windows_mount_cache_run.lock().unwrap();
                let cache_run = active.as_ref().expect("cache hit should remain active");
                assert_eq!(cache_run.images.len(), 1);
                assert!(cache_run.images[0].lease.is_hit());
            }
            assert_eq!(
                guest_mount_manifest(&hit_sandbox).expect("cache-hit manifest"),
                expected_manifest
            );
            assert!(hit_sandbox.read_file("/workspace/guest.txt").is_err());
            assert!(hit_sandbox.read_file("/workspace/after-start.txt").is_err());
            let active_prune = WindowsMountCache::new(&data_dir)
                .unwrap()
                .prune_all()
                .unwrap();
            assert_eq!(active_prune.removed_objects, 0);
            assert_eq!(active_prune.skipped_locked, 1);
            hit_sandbox
                .stop()
                .expect("Windows mount cache-hit QEMU should stop cleanly");

            WindowsMountCache::new(&data_dir)
                .unwrap()
                .prune_all()
                .unwrap();
            let _ = std::fs::remove_dir_all(&host_root);
        }
    }

    #[test]
    #[ignore = "requires Windows 11 x86_64 with WHPX, QEMU, and preserved pre-cache LocalSandbox assets"]
    fn windows_qemu_old_guest_mount_fallback_smoke() {
        #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
        {
            eprintln!("skipping Windows QEMU old-guest fallback smoke on non-Windows host");
        }

        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        {
            let kernel = required_env_path("LSB_WINDOWS_OLD_BOOT_KERNEL");
            let initrd = required_env_path("LSB_WINDOWS_OLD_BOOT_INITRD");
            let rootfs = required_env_path("LSB_WINDOWS_OLD_BOOT_ROOTFS");
            let host_root = rootfs
                .parent()
                .expect("old rootfs should live in a work directory")
                .join("old-guest-mount-fixture");
            let _ = std::fs::remove_dir_all(&host_root);
            let source = host_root.join("source");
            let data_dir = temp_dir("old-guest-cache-data");
            let expected_manifest = create_windows_mount_benchmark_fixture(&source);

            let sandbox = Sandbox::builder()
                .kernel(kernel.display().to_string())
                .initrd(initrd.display().to_string())
                .rootfs(rootfs.display().to_string())
                .data_dir(data_dir.display().to_string())
                .console(false)
                .mount(MountConfig::Overlay {
                    host_path: source.display().to_string(),
                    guest_path: "/workspace".into(),
                })
                .build()
                .expect("old-guest fallback sandbox should build");
            sandbox
                .start()
                .expect("old-guest fallback should import the complete fixture");

            let capabilities = sandbox.vm.guest_capabilities();
            assert!(capabilities.iter().any(|value| value == CAP_SESSION_MUX));
            assert!(!capabilities.iter().any(|value| value == CAP_MOUNT_CACHE_V1));
            assert!(!capabilities
                .iter()
                .any(|value| value == CAP_MOUNT_CACHE_IMPORT_BATCH_V1));
            {
                let active = sandbox.windows_mount_cache_run.lock().unwrap();
                let cache_run = active.as_ref().expect("fallback run should remain active");
                assert_eq!(cache_run.images.len(), 1);
                assert!(matches!(
                    cache_run.images[0].state,
                    WindowsMountCacheImageState::Fallback
                ));
                assert!(cache_run.has_fallback_routes());
            }
            assert_eq!(
                guest_mount_manifest(&sandbox).expect("old-guest fallback manifest"),
                expected_manifest
            );
            sandbox
                .stop()
                .expect("old-guest fallback QEMU should stop cleanly");
            let _ = std::fs::remove_dir_all(&host_root);
            let _ = std::fs::remove_dir_all(&data_dir);
        }
    }

    #[test]
    #[ignore = "requires Windows 11 x86_64 with WHPX, QEMU, and disposable LocalSandbox assets"]
    fn windows_qemu_mount_cache_corruption_smoke() {
        #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
        {
            eprintln!("skipping Windows QEMU mount-cache corruption smoke on non-Windows host");
        }

        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        {
            let kernel = required_env_path("LSB_WINDOWS_BOOT_KERNEL");
            let initrd = required_env_path("LSB_WINDOWS_BOOT_INITRD");
            let rootfs = required_env_path("LSB_WINDOWS_BOOT_ROOTFS");
            let host_root = temp_dir("mount-cache-corruption-smoke");
            let source = host_root.join("source");
            let data_dir = host_root.join("data");
            std::fs::create_dir_all(&source).expect("corruption fixture directory");
            std::fs::write(source.join("content.txt"), b"expected content")
                .expect("corruption fixture file");
            let snapshot = snapshot_windows_mount(&WindowsMountDescriptor {
                tag: "mount0".to_string(),
                host_root: source.clone(),
                guest_source: "/tmp/lsb/mounts/mount0/source".to_string(),
                guest_target: "/workspace".to_string(),
            })
            .expect("corruption fixture snapshot");
            let object_dir = data_dir
                .join("mount-cache/v1/objects")
                .join(snapshot.key.to_hex());

            for (run_index, expect_hit) in [false, false, false, true].into_iter().enumerate() {
                let sandbox = build_windows_overlay_test_sandbox(
                    &kernel, &initrd, &rootfs, &data_dir, &source,
                );
                sandbox.start().unwrap_or_else(|error| {
                    panic!("corruption recovery run {run_index} should start: {error:#}")
                });
                {
                    let active = sandbox.windows_mount_cache_run.lock().unwrap();
                    let cache_run = active.as_ref().expect("cache run should remain active");
                    assert_eq!(cache_run.images.len(), 1);
                    assert_eq!(cache_run.images[0].lease.is_hit(), expect_hit);
                }
                assert_eq!(
                    sandbox.read_file("/workspace/content.txt").unwrap(),
                    b"expected content"
                );
                sandbox.stop().unwrap_or_else(|error| {
                    panic!("corruption recovery run {run_index} should stop: {error:#}")
                });

                match run_index {
                    0 => {
                        let image = object_dir.join("image.ext4");
                        let mut permissions = std::fs::metadata(&image).unwrap().permissions();
                        permissions.set_readonly(false);
                        std::fs::set_permissions(&image, permissions).unwrap();
                        std::fs::OpenOptions::new()
                            .write(true)
                            .open(&image)
                            .unwrap()
                            .set_len(64 * 1024 * 1024)
                            .unwrap();
                        let mut permissions = std::fs::metadata(&image).unwrap().permissions();
                        permissions.set_readonly(true);
                        std::fs::set_permissions(&image, permissions).unwrap();
                    }
                    1 => {
                        std::fs::write(object_dir.join("manifest.json"), b"{}")
                            .expect("replace cache manifest with invalid JSON shape");
                    }
                    _ => {}
                }
            }

            WindowsMountCache::new(&data_dir)
                .unwrap()
                .prune_all()
                .unwrap();
            let _ = std::fs::remove_dir_all(&host_root);
        }
    }

    #[test]
    #[ignore = "requires Windows 11 x86_64 with WHPX, QEMU, and disposable LocalSandbox assets"]
    fn windows_qemu_mount_cache_invalidation_smoke() {
        #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
        {
            eprintln!("skipping Windows QEMU mount-cache invalidation smoke on non-Windows host");
        }

        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        {
            let kernel = required_env_path("LSB_WINDOWS_BOOT_KERNEL");
            let initrd = required_env_path("LSB_WINDOWS_BOOT_INITRD");
            let rootfs = required_env_path("LSB_WINDOWS_BOOT_ROOTFS");
            let host_root = temp_dir("mount-cache-invalidation-smoke");
            let source = host_root.join("source");
            let data_dir = host_root.join("data");
            std::fs::create_dir_all(source.join("baseline-empty"))
                .expect("invalidation fixture directories");
            let primary = source.join("primary.txt");
            std::fs::write(&primary, b"AAAA").expect("invalidation fixture file");

            let initial =
                build_windows_overlay_test_sandbox(&kernel, &initrd, &rootfs, &data_dir, &source);
            initial.start().expect("initial cache build should start");
            assert_windows_mount_cache_kind(&initial, false);
            initial.stop().expect("initial cache build should stop");

            let original_modified = std::fs::metadata(&primary).unwrap().modified().unwrap();
            std::fs::write(&primary, b"BBBB").expect("same-length mutation");
            std::fs::OpenOptions::new()
                .write(true)
                .open(&primary)
                .unwrap()
                .set_times(std::fs::FileTimes::new().set_modified(original_modified))
                .unwrap();
            let content_mutation =
                build_windows_overlay_test_sandbox(&kernel, &initrd, &rootfs, &data_dir, &source);
            content_mutation
                .start()
                .expect("same-length mutation should start");
            assert_windows_mount_cache_kind(&content_mutation, false);
            assert_eq!(
                content_mutation
                    .read_file("/workspace/primary.txt")
                    .unwrap(),
                b"BBBB"
            );
            content_mutation.stop().unwrap();

            std::fs::OpenOptions::new()
                .write(true)
                .open(&primary)
                .unwrap()
                .set_times(
                    std::fs::FileTimes::new()
                        .set_modified(original_modified + Duration::from_secs(120)),
                )
                .unwrap();
            let timestamp_only =
                build_windows_overlay_test_sandbox(&kernel, &initrd, &rootfs, &data_dir, &source);
            timestamp_only
                .start()
                .expect("timestamp-only change should start");
            assert_windows_mount_cache_kind(&timestamp_only, true);
            timestamp_only.stop().unwrap();

            let added = source.join("added.txt");
            std::fs::write(&added, b"added").unwrap();
            let addition =
                build_windows_overlay_test_sandbox(&kernel, &initrd, &rootfs, &data_dir, &source);
            addition.start().expect("added file should start");
            assert_windows_mount_cache_kind(&addition, false);
            assert_eq!(
                addition.read_file("/workspace/added.txt").unwrap(),
                b"added"
            );
            addition.stop().unwrap();

            std::fs::remove_file(&primary).unwrap();
            let deletion =
                build_windows_overlay_test_sandbox(&kernel, &initrd, &rootfs, &data_dir, &source);
            deletion.start().expect("deleted file should start");
            assert_windows_mount_cache_kind(&deletion, false);
            assert!(deletion.read_file("/workspace/primary.txt").is_err());
            deletion.stop().unwrap();

            std::fs::rename(&added, source.join("renamed.txt")).unwrap();
            let rename =
                build_windows_overlay_test_sandbox(&kernel, &initrd, &rootfs, &data_dir, &source);
            rename.start().expect("renamed file should start");
            assert_windows_mount_cache_kind(&rename, false);
            assert!(rename.read_file("/workspace/added.txt").is_err());
            assert_eq!(
                rename.read_file("/workspace/renamed.txt").unwrap(),
                b"added"
            );
            rename.stop().unwrap();

            std::fs::create_dir(source.join("new-empty")).unwrap();
            let empty_directory =
                build_windows_overlay_test_sandbox(&kernel, &initrd, &rootfs, &data_dir, &source);
            empty_directory
                .start()
                .expect("new empty directory should start");
            assert_windows_mount_cache_kind(&empty_directory, false);
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            assert_eq!(
                empty_directory
                    .exec(
                        &["/bin/sh", "-c", "test -d /workspace/new-empty"],
                        &mut stdout,
                        &mut stderr,
                    )
                    .unwrap(),
                0,
                "empty directory missing: {}",
                String::from_utf8_lossy(&stderr)
            );
            empty_directory.stop().unwrap();

            WindowsMountCache::new(&data_dir)
                .unwrap()
                .prune_all()
                .unwrap();
            let _ = std::fs::remove_dir_all(&host_root);
        }
    }

    #[test]
    #[ignore = "requires Windows 11 x86_64 with WHPX, QEMU, and disposable LocalSandbox assets"]
    fn windows_qemu_mount_cache_post_seal_tamper_smoke() {
        #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
        {
            eprintln!("skipping Windows QEMU post-seal tamper smoke on non-Windows host");
        }

        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        {
            let kernel = required_env_path("LSB_WINDOWS_BOOT_KERNEL");
            let initrd = required_env_path("LSB_WINDOWS_BOOT_INITRD");
            let rootfs = required_env_path("LSB_WINDOWS_BOOT_ROOTFS");
            let host_root = temp_dir("mount-cache-post-seal-tamper-smoke");
            let source = host_root.join("source");
            let data_dir = host_root.join("data");
            std::fs::create_dir_all(&source).unwrap();
            std::fs::write(source.join("content.txt"), b"untampered").unwrap();
            let snapshot = snapshot_windows_mount(&WindowsMountDescriptor {
                tag: "mount0".to_string(),
                host_root: source.clone(),
                guest_source: "/tmp/lsb/mounts/mount0/source".to_string(),
                guest_target: "/workspace".to_string(),
            })
            .unwrap();
            let object_dir = data_dir
                .join("mount-cache/v1/objects")
                .join(snapshot.key.to_hex());

            let tampered =
                build_windows_overlay_test_sandbox(&kernel, &initrd, &rootfs, &data_dir, &source);
            tampered.start().expect("tamper candidate should start");
            assert_windows_mount_cache_kind(&tampered, false);
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let exit_code = tampered
                .exec(
                    &[
                        "/bin/sh",
                        "-c",
                        "blockdev --setrw /dev/vdb && printf X | dd of=/dev/vdb bs=1 seek=0 conv=notrunc status=none",
                    ],
                    &mut stdout,
                    &mut stderr,
                )
                .unwrap();
            assert_eq!(
                exit_code,
                0,
                "post-seal tamper failed: {}",
                String::from_utf8_lossy(&stderr)
            );
            tampered.stop().expect("tampered candidate should stop");
            assert!(!object_dir.join("manifest.json").exists());

            let retry =
                build_windows_overlay_test_sandbox(&kernel, &initrd, &rootfs, &data_dir, &source);
            retry.start().expect("clean retry should start");
            assert_windows_mount_cache_kind(&retry, false);
            retry.stop().expect("clean retry should publish");
            assert!(object_dir.join("manifest.json").exists());

            WindowsMountCache::new(&data_dir)
                .unwrap()
                .prune_all()
                .unwrap();
            let _ = std::fs::remove_dir_all(&host_root);
        }
    }

    #[test]
    #[ignore = "requires Windows 11 x86_64 with WHPX, QEMU, and disposable LocalSandbox assets"]
    fn windows_qemu_mount_cache_sentinel_rejection_smoke() {
        #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
        {
            eprintln!("skipping Windows QEMU sentinel rejection smoke on non-Windows host");
        }

        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        {
            let kernel = required_env_path("LSB_WINDOWS_BOOT_KERNEL");
            let initrd = required_env_path("LSB_WINDOWS_BOOT_INITRD");
            let rootfs = required_env_path("LSB_WINDOWS_BOOT_ROOTFS");
            let host_root = temp_dir("mount-cache-sentinel-rejection-smoke");
            let source = host_root.join("source");
            let data_dir = host_root.join("data");
            std::fs::create_dir_all(&source).unwrap();
            std::fs::write(source.join("content.txt"), b"sentinel fixture").unwrap();
            let snapshot = snapshot_windows_mount(&WindowsMountDescriptor {
                tag: "mount0".to_string(),
                host_root: source.clone(),
                guest_source: "/tmp/lsb/mounts/mount0/source".to_string(),
                guest_target: "/workspace".to_string(),
            })
            .unwrap();
            let image_id = snapshot.key.to_hex();
            let object_dir = data_dir.join("mount-cache/v1/objects").join(&image_id);

            let builder =
                build_windows_overlay_test_sandbox(&kernel, &initrd, &rootfs, &data_dir, &source);
            builder.start().expect("sentinel builder should start");
            assert_windows_mount_cache_kind(&builder, false);
            let private_mount = format!("/tmp/lsb/cache-images/{image_id}");
            let wrong_key = "ff".repeat(32);
            let command = format!(
                "set -eu; blockdev --setrw /dev/vdb; mount -o remount,rw {private_mount}; printf 'abi=1\\nkey={wrong_key}\\n' > {private_mount}/.lsb-mount-cache-v1; sync"
            );
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let exit_code = builder
                .exec(&["/bin/sh", "-c", &command], &mut stdout, &mut stderr)
                .unwrap();
            assert_eq!(
                exit_code,
                0,
                "sentinel tamper failed: {}",
                String::from_utf8_lossy(&stderr)
            );

            builder
                .vm
                .stop()
                .expect("sentinel builder VM should stop directly");
            let mut cache_run = builder
                .windows_mount_cache_run
                .lock()
                .unwrap()
                .take()
                .expect("sentinel cache run should remain available");
            let image_path = cache_run.images[0].lease.image_path().to_path_buf();
            let image_size = cache_run.images[0].lease.virtual_size();
            let tampered_digest = hash_windows_cache_test_image(&image_path, image_size);
            cache_run.images[0].state = WindowsMountCacheImageState::PublishEligible {
                raw_device_digest: tampered_digest,
            };
            cache_run.finalize_after_stop(&builder.mount_metrics);
            assert!(object_dir.join("manifest.json").exists());

            let rejected_hit =
                build_windows_overlay_test_sandbox(&kernel, &initrd, &rootfs, &data_dir, &source);
            rejected_hit
                .start()
                .expect("sentinel mismatch should use copy fallback");
            {
                let active = rejected_hit.windows_mount_cache_run.lock().unwrap();
                let cache_run = active
                    .as_ref()
                    .expect("rejected hit run should remain active");
                assert!(cache_run.images[0].lease.is_hit());
                assert!(matches!(
                    cache_run.images[0].state,
                    WindowsMountCacheImageState::Fallback
                ));
                assert!(cache_run.has_fallback_routes());
            }
            assert_eq!(
                rejected_hit.read_file("/workspace/content.txt").unwrap(),
                b"sentinel fixture"
            );
            rejected_hit
                .stop()
                .expect("sentinel fallback should stop cleanly");
            assert!(!object_dir.exists());

            let retry =
                build_windows_overlay_test_sandbox(&kernel, &initrd, &rootfs, &data_dir, &source);
            retry.start().expect("sentinel retry should rebuild");
            assert_windows_mount_cache_kind(&retry, false);
            retry.stop().expect("sentinel retry should publish");

            WindowsMountCache::new(&data_dir)
                .unwrap()
                .prune_all()
                .unwrap();
            let _ = std::fs::remove_dir_all(&host_root);
        }
    }

    #[test]
    #[ignore = "requires elevated Windows 11 x86_64 with WHPX, QEMU, SMB, and disposable LocalSandbox assets"]
    fn windows_qemu_direct_smb_failure_cleanup_smoke() {
        #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
        {
            eprintln!("skipping Windows QEMU direct SMB failure cleanup smoke on non-Windows host");
        }

        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        {
            let kernel = required_env_path("LSB_WINDOWS_BOOT_KERNEL");
            let initrd = required_env_path("LSB_WINDOWS_BOOT_INITRD");
            let rootfs = required_env_path("LSB_WINDOWS_BOOT_ROOTFS");
            let host_root = rootfs
                .parent()
                .expect("rootfs should live in a work directory")
                .join("direct-smb-failure-fixture");
            let _ = std::fs::remove_dir_all(&host_root);
            let source = host_root.join("source");
            std::fs::create_dir_all(&source).expect("direct SMB failure fixture dir");
            std::fs::write(source.join("input.txt"), b"host input")
                .expect("direct SMB failure fixture file");

            let before = windows_lsb_smb_resource_snapshot();
            let sandbox = Sandbox::builder()
                .kernel(kernel.display().to_string())
                .initrd(initrd.display().to_string())
                .rootfs(rootfs.display().to_string())
                .console(false)
                .mount(MountConfig::Direct {
                    host_path: source.display().to_string(),
                    guest_path: "/direct-missing-proxy".into(),
                    flags: 0,
                })
                .build()
                .expect("Windows direct SMB failure sandbox should build");

            let start_error = sandbox
                .start()
                .expect_err("direct SMB start without proxy should fail during guest mount");
            assert!(
                start_error.to_string().contains("Windows mounts")
                    || start_error.to_string().contains("SMB")
                    || start_error.to_string().contains("mount"),
                "unexpected direct SMB failure: {start_error}"
            );
            let _ = sandbox.stop();

            let after = windows_lsb_smb_resource_snapshot();
            let _ = std::fs::remove_dir_all(&host_root);
            assert_eq!(
                after, before,
                "failed direct SMB startup should not leave generated users or shares"
            );
        }
    }

    #[test]
    #[ignore = "requires Windows 11 x86_64 with WHPX, QEMU, and disposable LocalSandbox assets"]
    fn windows_qemu_port_forward_smoke() {
        #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
        {
            eprintln!("skipping Windows QEMU port-forward smoke on non-Windows host");
        }

        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        {
            let kernel = required_env_path("LSB_WINDOWS_BOOT_KERNEL");
            let initrd = required_env_path("LSB_WINDOWS_BOOT_INITRD");
            let rootfs = required_env_path("LSB_WINDOWS_BOOT_ROOTFS");
            let host_port = reserve_loopback_port();
            let guest_port = 18080;

            let sandbox = Sandbox::builder()
                .kernel(kernel.display().to_string())
                .initrd(initrd.display().to_string())
                .rootfs(rootfs.display().to_string())
                .console(false)
                .build()
                .expect("Windows port-forward smoke sandbox should build");

            sandbox
                .start()
                .expect("Windows port-forward smoke should reach guest ready");

            let result = (|| -> Result<()> {
                let ready_path = "/tmp/lsb-port-forward-ready";
                let server_script = format!(
                    "set -eu; \
                     rm -f {ready_path}; \
                     /usr/bin/lsb-init --lsb-test-tcp-server {guest_port} lsb-port-forward-ok {ready_path} \
                     >/tmp/lsb-port-forward.log 2>&1 & echo $! >/tmp/lsb-port-forward.pid"
                );
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                let code =
                    sandbox.exec(&["/bin/sh", "-c", &server_script], &mut stdout, &mut stderr)?;
                assert_eq!(
                    code,
                    0,
                    "guest server setup failed: stdout={}, stderr={}",
                    String::from_utf8_lossy(&stdout),
                    String::from_utf8_lossy(&stderr)
                );

                let ready_deadline = std::time::Instant::now() + Duration::from_secs(5);
                loop {
                    if sandbox.read_file(ready_path).is_ok() {
                        break;
                    }
                    if std::time::Instant::now() >= ready_deadline {
                        let server_log = sandbox
                            .read_file("/tmp/lsb-port-forward.log")
                            .unwrap_or_default();
                        anyhow::bail!(
                            "guest port-forward test server did not become ready: {}",
                            String::from_utf8_lossy(&server_log)
                        );
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }

                let forward = sandbox.start_port_forwarding(&[PortMapping {
                    host_port,
                    guest_port,
                }])?;

                let connect_deadline = std::time::Instant::now() + Duration::from_secs(5);
                let mut client = loop {
                    match TcpStream::connect(("127.0.0.1", host_port)) {
                        Ok(stream) => break stream,
                        Err(error) if std::time::Instant::now() >= connect_deadline => {
                            return Err(error)
                                .context("connecting to forwarded host loopback port");
                        }
                        Err(_) => std::thread::sleep(Duration::from_millis(100)),
                    }
                };
                client.set_read_timeout(Some(Duration::from_secs(5)))?;
                let mut response = String::new();
                client
                    .read_to_string(&mut response)
                    .context("reading forwarded response")?;
                assert_eq!(response, "lsb-port-forward-ok");

                sandbox
                    .stop()
                    .context("stopping sandbox while port-forward handle is alive")?;
                std::thread::sleep(Duration::from_millis(100));
                assert!(
                    TcpStream::connect(("127.0.0.1", host_port)).is_err(),
                    "forwarded host port should close after sandbox shutdown"
                );

                drop(forward);
                std::thread::sleep(Duration::from_millis(100));
                assert!(
                    TcpStream::connect(("127.0.0.1", host_port)).is_err(),
                    "forwarded host port should close after dropping PortForwardHandle"
                );
                Ok(())
            })();

            let stop_result = sandbox.stop();
            result.expect("Windows port-forward smoke should pass");
            stop_result.expect("Windows port-forward smoke QEMU should stop cleanly");
        }
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[derive(Debug, PartialEq, Eq)]
    struct WindowsLsbSmbResourceSnapshot {
        users: HashSet<String>,
        shares: HashSet<String>,
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn windows_lsb_smb_resource_snapshot() -> WindowsLsbSmbResourceSnapshot {
        WindowsLsbSmbResourceSnapshot {
            users: windows_command_tokens("net", &["user"], "lsb_"),
            shares: windows_command_tokens("net", &["share"], "lsb-"),
        }
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn windows_command_tokens(command: &str, args: &[&str], prefix: &str) -> HashSet<String> {
        let Ok(output) = Command::new(command)
            .args(args)
            .stderr(Stdio::null())
            .output()
        else {
            return HashSet::new();
        };
        String::from_utf8_lossy(&output.stdout)
            .split_whitespace()
            .filter(|token| token.starts_with(prefix))
            .map(str::to_string)
            .collect()
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn required_env_path(name: &str) -> PathBuf {
        std::env::var_os(name)
            .map(PathBuf::from)
            .unwrap_or_else(|| panic!("{name} must point to a disposable boot asset path"))
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn create_windows_mount_benchmark_fixture(source: &Path) -> String {
        use std::fmt::Write as _;

        let mut manifest = String::new();
        for directory_index in 0..100 {
            let directory_name = format!("dir-{directory_index:03}");
            let directory = source.join(&directory_name);
            std::fs::create_dir_all(&directory).expect("benchmark fixture directory");
            for file_index in 0..20 {
                let file_name = format!("file-{file_index:03}.bin");
                let mut payload = [0u8; 1024];
                for (byte_index, byte) in payload.iter_mut().enumerate() {
                    *byte = ((directory_index * 31 + file_index * 17 + byte_index) % 256) as u8;
                }
                std::fs::write(directory.join(&file_name), payload)
                    .expect("benchmark fixture file");
                let digest = Sha256::digest(payload);
                for byte in digest {
                    write!(&mut manifest, "{byte:02x}").unwrap();
                }
                writeln!(&mut manifest, "  ./{directory_name}/{file_name}").unwrap();
            }
        }
        manifest
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn guest_mount_manifest(sandbox: &Sandbox) -> Result<String> {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = sandbox.exec(
            &[
                "/bin/sh",
                "-c",
                "cd /workspace && find . -type f | LC_ALL=C sort | while IFS= read -r path; do sha256sum \"$path\"; done",
            ],
            &mut stdout,
            &mut stderr,
        )?;
        if exit_code != 0 {
            bail!(
                "guest fixture manifest failed with {exit_code}: {}",
                String::from_utf8_lossy(&stderr)
            );
        }
        String::from_utf8(stdout).context("guest fixture manifest was not UTF-8")
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn build_windows_overlay_test_sandbox(
        kernel: &Path,
        initrd: &Path,
        rootfs: &Path,
        data_dir: &Path,
        source: &Path,
    ) -> Sandbox {
        Sandbox::builder()
            .kernel(kernel.display().to_string())
            .initrd(initrd.display().to_string())
            .rootfs(rootfs.display().to_string())
            .data_dir(data_dir.display().to_string())
            .console(false)
            .mount(MountConfig::Overlay {
                host_path: source.display().to_string(),
                guest_path: "/workspace".into(),
            })
            .build()
            .expect("Windows overlay test sandbox should build")
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn assert_windows_mount_cache_kind(sandbox: &Sandbox, expected_hit: bool) {
        let active = sandbox.windows_mount_cache_run.lock().unwrap();
        let cache_run = active.as_ref().expect("cache run should remain active");
        assert_eq!(cache_run.images.len(), 1);
        assert_eq!(cache_run.images[0].lease.is_hit(), expected_hit);
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn hash_windows_cache_test_image(path: &Path, size: u64) -> String {
        let mut file = std::fs::File::open(path).expect("cache test image should open");
        let mut hasher = blake3::Hasher::new();
        let mut buffer = vec![0u8; 1024 * 1024];
        let mut remaining = size;
        while remaining != 0 {
            let wanted = remaining.min(buffer.len() as u64) as usize;
            file.read_exact(&mut buffer[..wanted])
                .expect("cache test image should contain its advertised size");
            hasher.update(&buffer[..wanted]);
            remaining -= wanted as u64;
        }
        hasher.finalize().to_hex().to_string()
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
    fn spawn_watch_event_reader(
        mut stream: PlatformControlStream,
    ) -> (
        std::sync::mpsc::Receiver<std::result::Result<lsb_proto::WatchEvent, String>>,
        std::thread::JoinHandle<std::result::Result<(), String>>,
    ) {
        let (events_tx, events_rx) = std::sync::mpsc::channel();
        let handle = std::thread::Builder::new()
            .name("lsb-windows-watch-smoke-reader".to_string())
            .spawn(move || loop {
                match frame::read_frame(&mut stream) {
                    Ok(Some((frame::WATCH_EVENT, payload))) => {
                        let event = serde_json::from_slice::<lsb_proto::WatchEvent>(&payload)
                            .map_err(|error| error.to_string());
                        if events_tx.send(event).is_err() {
                            return Ok(());
                        }
                    }
                    Ok(Some((frame::ERROR, payload))) => {
                        let message = String::from_utf8_lossy(&payload).to_string();
                        let _ = events_tx.send(Err(message.clone()));
                        return Err(message);
                    }
                    Ok(Some(_)) => {}
                    Ok(None) => return Ok(()),
                    Err(error) => return Err(error.to_string()),
                }
            })
            .expect("watch reader thread should start");

        (events_rx, handle)
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn wait_for_guest_watch_events(
        events_rx: &std::sync::mpsc::Receiver<std::result::Result<lsb_proto::WatchEvent, String>>,
        expected: &[(&str, Option<&str>)],
    ) -> Result<()> {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut remaining = expected
            .iter()
            .map(|(path, event)| ((*path).to_string(), event.map(str::to_string)))
            .collect::<Vec<_>>();
        let mut seen = Vec::new();

        while !remaining.is_empty() {
            let now = std::time::Instant::now();
            if now >= deadline {
                bail!(
                    "timed out waiting for guest watch events {:?}; seen {:?}",
                    remaining,
                    seen
                );
            }

            match events_rx.recv_timeout((deadline - now).min(Duration::from_millis(200))) {
                Ok(Ok(event)) => {
                    seen.push(format!("{}:{}", event.event, event.path));
                    remaining.retain(|(path, expected_event)| {
                        event.path != *path
                            || expected_event
                                .as_deref()
                                .is_some_and(|kind| event.event != kind)
                    });
                }
                Ok(Err(error)) => bail!("guest watch reported error: {error}"),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    bail!(
                        "guest watch event stream closed before expectations {:?}; seen {:?}",
                        remaining,
                        seen
                    );
                }
            }
        }

        Ok(())
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

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn reserve_loopback_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("reserve ephemeral loopback port");
        listener.local_addr().expect("reserved addr").port()
    }
}
