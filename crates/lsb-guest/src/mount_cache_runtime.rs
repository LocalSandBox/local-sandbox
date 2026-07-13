use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, CString};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use lsb_proto::{
    MountCacheAction, MountCacheImportEntry, MountCacheRejectReason, MountCacheRequest,
    MountCacheResponse, MountSnapshotKeyEncoder, MOUNT_IMPORT_DIRECTORY_MODE,
    MOUNT_IMPORT_FILE_MODE,
};

const CACHE_MOUNT_ROOT: &str = "/tmp/lsb/cache-images";
const OVERLAY_ROOT: &str = "/mnt/.overlay";
const SENTINEL_NAME: &str = ".lsb-mount-cache-v1";
const FORMAT_TIMEOUT: Duration = Duration::from_secs(30);
const FORMAT_POLL_INTERVAL: Duration = Duration::from_millis(25);
const MAX_FORMAT_DIAGNOSTIC: usize = 4096;
const HASH_BUFFER_SIZE: usize = 512 * 1024;
const BLKROSET: libc::c_int = 0x125d;

pub(crate) struct MountCacheManager {
    images: HashMap<String, CacheImage>,
    bindings: HashSet<String>,
    targets: HashSet<String>,
}

struct CacheImage {
    device: PathBuf,
    mount_dir: PathBuf,
    expected_size: u64,
    expected_key: String,
    phase: CacheImagePhase,
    overlays: Vec<OverlayBinding>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CacheImagePhase {
    Building,
    Validated,
}

struct OverlayBinding {
    binding_id: String,
    target: String,
    staging_dir: PathBuf,
}

impl Default for MountCacheManager {
    fn default() -> Self {
        Self {
            images: HashMap::new(),
            bindings: HashSet::new(),
            targets: HashSet::new(),
        }
    }
}

impl MountCacheManager {
    pub(crate) fn handle(
        &mut self,
        request: MountCacheRequest,
    ) -> Result<MountCacheResponse, String> {
        request.validate().map_err(|error| error.to_string())?;
        match request {
            MountCacheRequest::PrepareBuild {
                image_id,
                serial,
                expected_size,
                expected_key,
                inode_count,
            } => self.prepare_build(image_id, serial, expected_size, expected_key, inode_count),
            MountCacheRequest::PrepareHit {
                image_id,
                serial,
                expected_size,
                expected_key,
            } => self.prepare_hit(image_id, serial, expected_size, expected_key),
            MountCacheRequest::ImportBatch { .. } => {
                Err("cache import batch requires its data frame".to_string())
            }
            MountCacheRequest::SealBuild {
                image_id,
                expected_key,
            } => self.seal_build(image_id, expected_key),
            MountCacheRequest::AbortBuild { image_id } => self.abort(image_id),
            MountCacheRequest::MountOverlay {
                image_id,
                binding_id,
                target,
            } => self.mount_overlay(image_id, binding_id, target),
        }
    }

    pub(crate) fn import_batch(
        &mut self,
        request: MountCacheRequest,
        data: &[u8],
    ) -> Result<MountCacheResponse, String> {
        request.validate().map_err(|error| error.to_string())?;
        let MountCacheRequest::ImportBatch {
            image_id,
            entries,
            data_len,
        } = request
        else {
            return Err("expected a cache import batch request".to_string());
        };
        if data.len() != data_len as usize {
            return Err("cache import data frame length changed after validation".to_string());
        }
        let Some(image) = self.images.get(&image_id) else {
            return Err(format!("cache image {image_id} was not prepared"));
        };
        if image.phase != CacheImagePhase::Building {
            return Err(format!("cache image {image_id} is not in build state"));
        }
        let source = image.mount_dir.join("source");
        if let Err(error) = apply_import_batch(&source, &entries, data) {
            eprintln!("lsb-guest: cache import batch rejected: {error}");
            self.rollback_image(&image_id)?;
            return Ok(rejected(
                MountCacheAction::ImportBatch,
                image_id,
                MountCacheRejectReason::MountFailed,
            ));
        }
        Ok(ready(MountCacheAction::ImportBatch, image_id))
    }

    fn prepare_build(
        &mut self,
        image_id: String,
        serial: String,
        expected_size: u64,
        expected_key: String,
        inode_count: u64,
    ) -> Result<MountCacheResponse, String> {
        if self.images.contains_key(&image_id) {
            return Err(format!("cache image {image_id} is already prepared"));
        }
        let device = match discover_cache_device(&serial, expected_size, false) {
            Ok(device) => device,
            Err(reason) => return Ok(rejected(MountCacheAction::PrepareBuild, image_id, reason)),
        };
        let Some(formatter) = super::control_transport::cache_formatter_path() else {
            return Ok(rejected(
                MountCacheAction::PrepareBuild,
                image_id,
                MountCacheRejectReason::FormatterUnavailable,
            ));
        };
        if let Err(reason) = format_ext4(&formatter, &device, inode_count) {
            return Ok(rejected(MountCacheAction::PrepareBuild, image_id, reason));
        }

        let mount_dir = image_mount_dir(&image_id);
        prepare_empty_directory(&mount_dir)
            .map_err(|error| format!("failed to prepare private cache mount directory: {error}"))?;
        if let Err(error) = mount_ext4(&device, &mount_dir, false) {
            let _ = std::fs::remove_dir(&mount_dir);
            eprintln!("lsb-guest: cache build mount rejected: {error}");
            return Ok(rejected(
                MountCacheAction::PrepareBuild,
                image_id,
                MountCacheRejectReason::MountFailed,
            ));
        }
        if let Err(error) = make_mount_private(&mount_dir) {
            let _ = unmount(&mount_dir);
            let _ = std::fs::remove_dir(&mount_dir);
            return Err(format!("failed to make cache build mount private: {error}"));
        }
        let source = mount_dir.join("source");
        if let Err(error) = create_directory_with_mode(&source, MOUNT_IMPORT_DIRECTORY_MODE) {
            let _ = unmount(&mount_dir);
            let _ = std::fs::remove_dir(&mount_dir);
            return Err(format!("failed to create cache source directory: {error}"));
        }

        self.images.insert(
            image_id.clone(),
            CacheImage {
                device,
                mount_dir,
                expected_size,
                expected_key,
                phase: CacheImagePhase::Building,
                overlays: Vec::new(),
            },
        );
        Ok(ready(MountCacheAction::PrepareBuild, image_id))
    }

    fn prepare_hit(
        &mut self,
        image_id: String,
        serial: String,
        expected_size: u64,
        expected_key: String,
    ) -> Result<MountCacheResponse, String> {
        if self.images.contains_key(&image_id) {
            return Err(format!("cache image {image_id} is already prepared"));
        }
        let device = match discover_cache_device(&serial, expected_size, true) {
            Ok(device) => device,
            Err(reason) => return Ok(rejected(MountCacheAction::PrepareHit, image_id, reason)),
        };
        let mount_dir = image_mount_dir(&image_id);
        prepare_empty_directory(&mount_dir)
            .map_err(|error| format!("failed to prepare private cache mount directory: {error}"))?;
        if let Err(error) = mount_ext4(&device, &mount_dir, true) {
            let _ = std::fs::remove_dir(&mount_dir);
            eprintln!("lsb-guest: cache hit mount rejected: {error}");
            return Ok(rejected(
                MountCacheAction::PrepareHit,
                image_id,
                MountCacheRejectReason::MountFailed,
            ));
        }
        if let Err(error) = make_mount_private(&mount_dir) {
            let _ = unmount(&mount_dir);
            let _ = std::fs::remove_dir(&mount_dir);
            return Err(format!("failed to make cache hit mount private: {error}"));
        }

        let sentinel = read_sentinel(&mount_dir);
        match sentinel {
            Ok(sentinel) if sentinel == expected_key => {}
            Ok(_) => {
                self.rollback_untracked_mount(&mount_dir)?;
                return Ok(rejected(
                    MountCacheAction::PrepareHit,
                    image_id,
                    MountCacheRejectReason::SourceKeyMismatch,
                ));
            }
            Err(error) => {
                eprintln!("lsb-guest: cache hit validation rejected: {error}");
                self.rollback_untracked_mount(&mount_dir)?;
                return Ok(rejected(
                    MountCacheAction::PrepareHit,
                    image_id,
                    MountCacheRejectReason::InvalidSourceTree,
                ));
            }
        }
        let computed_key = match hash_source_tree(&mount_dir.join("source")) {
            Ok(key) => key,
            Err(error) => {
                eprintln!("lsb-guest: cache hit source-tree validation rejected: {error}");
                self.rollback_untracked_mount(&mount_dir)?;
                return Ok(rejected(
                    MountCacheAction::PrepareHit,
                    image_id,
                    MountCacheRejectReason::InvalidSourceTree,
                ));
            }
        };
        if computed_key != expected_key {
            self.rollback_untracked_mount(&mount_dir)?;
            return Ok(rejected(
                MountCacheAction::PrepareHit,
                image_id,
                MountCacheRejectReason::SourceKeyMismatch,
            ));
        }

        self.images.insert(
            image_id.clone(),
            CacheImage {
                device,
                mount_dir,
                expected_size,
                expected_key,
                phase: CacheImagePhase::Validated,
                overlays: Vec::new(),
            },
        );
        Ok(MountCacheResponse::Ready {
            action: MountCacheAction::PrepareHit,
            image_id,
            binding_id: None,
            computed_key: Some(computed_key),
            raw_device_digest: None,
        })
    }

    fn seal_build(
        &mut self,
        image_id: String,
        expected_key: String,
    ) -> Result<MountCacheResponse, String> {
        let Some(image) = self.images.get(&image_id) else {
            return Err(format!("cache image {image_id} was not prepared"));
        };
        if image.phase != CacheImagePhase::Building {
            return Err(format!("cache image {image_id} is not in build state"));
        }
        if image.expected_key != expected_key {
            return Err(format!("cache image {image_id} seal key changed"));
        }

        let mount_dir = image.mount_dir.clone();
        let device = image.device.clone();
        let expected_size = image.expected_size;
        let computed_key = match hash_source_tree(&mount_dir.join("source")) {
            Ok(key) => key,
            Err(error) => {
                eprintln!("lsb-guest: cache build source validation rejected: {error}");
                self.rollback_image(&image_id)?;
                return Ok(rejected(
                    MountCacheAction::SealBuild,
                    image_id,
                    MountCacheRejectReason::InvalidSourceTree,
                ));
            }
        };
        if computed_key != expected_key {
            self.rollback_image(&image_id)?;
            return Ok(rejected(
                MountCacheAction::SealBuild,
                image_id,
                MountCacheRejectReason::SourceKeyMismatch,
            ));
        }
        write_sentinel(&mount_dir, &expected_key)
            .map_err(|error| format!("failed to write cache sentinel: {error}"))?;
        sync_mount(&mount_dir).map_err(|error| format!("failed to sync cache image: {error}"))?;
        unmount(&mount_dir)
            .map_err(|error| format!("failed to unmount sealed cache image: {error}"))?;
        set_block_read_only(&device)
            .map_err(|error| format!("failed to set sealed cache device read-only: {error}"))?;
        let raw_device_digest = hash_raw_device(&device, expected_size)
            .map_err(|error| format!("failed to hash sealed cache device: {error}"))?;
        mount_ext4(&device, &mount_dir, true)
            .map_err(|error| format!("failed to remount sealed cache image: {error}"))?;
        make_mount_private(&mount_dir)
            .map_err(|error| format!("failed to make sealed cache mount private: {error}"))?;
        let remounted_key = hash_source_tree(&mount_dir.join("source"))
            .map_err(|error| format!("failed to validate remounted cache source: {error}"))?;
        if remounted_key != expected_key {
            self.rollback_image(&image_id)?;
            return Ok(rejected(
                MountCacheAction::SealBuild,
                image_id,
                MountCacheRejectReason::SourceKeyMismatch,
            ));
        }
        self.images
            .get_mut(&image_id)
            .expect("cache image remains present")
            .phase = CacheImagePhase::Validated;

        Ok(MountCacheResponse::Ready {
            action: MountCacheAction::SealBuild,
            image_id,
            binding_id: None,
            computed_key: Some(computed_key),
            raw_device_digest: Some(raw_device_digest),
        })
    }

    fn mount_overlay(
        &mut self,
        image_id: String,
        binding_id: String,
        target: String,
    ) -> Result<MountCacheResponse, String> {
        let Some(image) = self.images.get(&image_id) else {
            return Err(format!("cache image {image_id} was not prepared"));
        };
        if image.phase != CacheImagePhase::Validated {
            return Err(format!("cache image {image_id} was not validated"));
        }
        if self.bindings.contains(&binding_id) || self.targets.contains(&target) {
            return Err("cache overlay binding or target was already used".to_string());
        }
        validate_target(&target)?;

        let lower = image.mount_dir.join("source");
        let staging_dir = Path::new(OVERLAY_ROOT).join(format!("cache-{binding_id}"));
        if let Err(error) = mount_cache_overlay(&lower, &staging_dir, Path::new(&target)) {
            eprintln!("lsb-guest: cache overlay mount rejected: {error}");
            self.rollback_image(&image_id)?;
            return Ok(rejected(
                MountCacheAction::MountOverlay,
                image_id,
                MountCacheRejectReason::MountFailed,
            ));
        }
        self.bindings.insert(binding_id.clone());
        self.targets.insert(target.clone());
        self.images
            .get_mut(&image_id)
            .expect("cache image remains present")
            .overlays
            .push(OverlayBinding {
                binding_id: binding_id.clone(),
                target,
                staging_dir,
            });

        let mut response = ready(MountCacheAction::MountOverlay, image_id);
        if let MountCacheResponse::Ready {
            binding_id: response_binding,
            ..
        } = &mut response
        {
            *response_binding = Some(binding_id);
        }
        Ok(response)
    }

    fn abort(&mut self, image_id: String) -> Result<MountCacheResponse, String> {
        self.rollback_image(&image_id)?;
        Ok(ready(MountCacheAction::AbortBuild, image_id))
    }

    fn rollback_untracked_mount(&self, mount_dir: &Path) -> Result<(), String> {
        unmount(mount_dir).map_err(|error| format!("failed to roll back cache mount: {error}"))?;
        std::fs::remove_dir(mount_dir)
            .map_err(|error| format!("failed to remove cache mount directory: {error}"))
    }

    fn rollback_image(&mut self, image_id: &str) -> Result<(), String> {
        let Some(mut image) = self.images.remove(image_id) else {
            return Ok(());
        };
        for overlay in image.overlays.drain(..).rev() {
            unmount(Path::new(&overlay.target)).map_err(|error| {
                format!(
                    "failed to roll back cache overlay target {}: {error}",
                    overlay.target
                )
            })?;
            unmount(&overlay.staging_dir).map_err(|error| {
                format!(
                    "failed to roll back cache overlay staging {}: {error}",
                    overlay.staging_dir.display()
                )
            })?;
            self.bindings.remove(&overlay.binding_id);
            self.targets.remove(&overlay.target);
        }
        unmount(&image.mount_dir).map_err(|error| {
            format!(
                "failed to roll back private cache mount {}: {error}",
                image.mount_dir.display()
            )
        })?;
        std::fs::remove_dir(&image.mount_dir).map_err(|error| {
            format!(
                "failed to remove private cache mount directory {}: {error}",
                image.mount_dir.display()
            )
        })?;
        Ok(())
    }
}

fn ready(action: MountCacheAction, image_id: String) -> MountCacheResponse {
    MountCacheResponse::Ready {
        action,
        image_id,
        binding_id: None,
        computed_key: None,
        raw_device_digest: None,
    }
}

fn rejected(
    action: MountCacheAction,
    image_id: String,
    reason: MountCacheRejectReason,
) -> MountCacheResponse {
    MountCacheResponse::Rejected {
        action,
        image_id,
        reason,
    }
}

fn image_mount_dir(image_id: &str) -> PathBuf {
    Path::new(CACHE_MOUNT_ROOT).join(image_id)
}

fn prepare_empty_directory(path: &Path) -> io::Result<()> {
    std::fs::create_dir_all(CACHE_MOUNT_ROOT)?;
    match std::fs::remove_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    create_directory_with_mode(path, 0o700)
}

fn create_directory_with_mode(path: &Path, mode: u32) -> io::Result<()> {
    std::fs::create_dir(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

fn apply_import_batch(
    source: &Path,
    entries: &[MountCacheImportEntry],
    data: &[u8],
) -> io::Result<()> {
    let mut data_offset = 0usize;
    for entry in entries {
        match entry {
            MountCacheImportEntry::Directory { path } => {
                let target = source.join(path);
                create_directory_with_mode(&target, MOUNT_IMPORT_DIRECTORY_MODE)?;
            }
            MountCacheImportEntry::FileChunk {
                path,
                offset,
                len,
                truncate,
            } => {
                let length = *len as usize;
                let end = data_offset.checked_add(length).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "cache batch data overflow")
                })?;
                let bytes = data.get(data_offset..end).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "cache batch data is incomplete",
                    )
                })?;
                let target = source.join(path);
                let mut options = OpenOptions::new();
                options
                    .write(true)
                    .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
                if *truncate {
                    options.create_new(true).mode(MOUNT_IMPORT_FILE_MODE);
                }
                let mut file = options.open(&target)?;
                let metadata = file.metadata()?;
                if !metadata.file_type().is_file()
                    || metadata.nlink() != 1
                    || metadata.len() != *offset
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "cache import file is not a sequential single-link regular file",
                    ));
                }
                file.seek(SeekFrom::Start(*offset))?;
                file.write_all(bytes)?;
                if *truncate {
                    file.set_permissions(std::fs::Permissions::from_mode(MOUNT_IMPORT_FILE_MODE))?;
                }
                data_offset = end;
            }
        }
    }
    if data_offset != data.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "cache batch contains unreferenced data",
        ));
    }
    Ok(())
}

fn validate_target(target: &str) -> Result<(), String> {
    let path = Path::new(target);
    if target == "/" || !path.is_absolute() {
        return Err("cache overlay target must be a non-root absolute path".to_string());
    }
    if path
        .components()
        .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err("cache overlay target contains an unsafe path component".to_string());
    }
    if path.starts_with(CACHE_MOUNT_ROOT) || path.starts_with(OVERLAY_ROOT) {
        return Err("cache overlay target overlaps guest cache staging".to_string());
    }
    Ok(())
}

fn mount_cache_overlay(lower: &Path, staging: &Path, target: &Path) -> io::Result<()> {
    std::fs::create_dir_all(OVERLAY_ROOT)?;
    prepare_empty_directory_at(staging, 0o700)?;
    std::fs::create_dir_all(target)?;
    mount_raw(
        Some(Path::new("tmpfs")),
        staging,
        Some("tmpfs"),
        (libc::MS_NODEV | libc::MS_NOSUID) as libc::c_ulong,
        None,
    )?;
    if let Err(error) = make_mount_private(staging) {
        let _ = unmount(staging);
        return Err(error);
    }
    let upper = staging.join("upper");
    let work = staging.join("work");
    std::fs::create_dir(&upper)?;
    std::fs::create_dir(&work)?;
    let options = format!(
        "lowerdir={},upperdir={},workdir={}",
        lower.display(),
        upper.display(),
        work.display()
    );
    if let Err(error) = mount_raw(
        Some(Path::new("overlay")),
        target,
        Some("overlay"),
        0,
        Some(&options),
    ) {
        let _ = unmount(staging);
        return Err(error);
    }
    Ok(())
}

fn prepare_empty_directory_at(path: &Path, mode: u32) -> io::Result<()> {
    match std::fs::remove_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    create_directory_with_mode(path, mode)
}

fn mount_ext4(device: &Path, target: &Path, read_only: bool) -> io::Result<()> {
    let mut flags = (libc::MS_NODEV | libc::MS_NOSUID) as libc::c_ulong;
    if read_only {
        flags |= libc::MS_RDONLY as libc::c_ulong;
    }
    mount_raw(Some(device), target, Some("ext4"), flags, None)
}

fn mount_raw(
    source: Option<&Path>,
    target: &Path,
    filesystem: Option<&str>,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> io::Result<()> {
    let source = source.map(path_cstring).transpose()?;
    let target = path_cstring(target)?;
    let filesystem = filesystem
        .map(CString::new)
        .transpose()
        .map_err(nul_error)?;
    let data = data.map(CString::new).transpose().map_err(nul_error)?;
    let result = unsafe {
        libc::mount(
            source
                .as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr()),
            target.as_ptr(),
            filesystem
                .as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr()),
            flags,
            data.as_ref().map_or(std::ptr::null(), |value| {
                value.as_ptr().cast::<libc::c_void>()
            }),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn make_mount_private(path: &Path) -> io::Result<()> {
    mount_raw(
        None,
        path,
        None,
        (libc::MS_PRIVATE | libc::MS_REC) as libc::c_ulong,
        None,
    )
}

fn unmount(path: &Path) -> io::Result<()> {
    let path = path_cstring(path)?;
    let result = unsafe { libc::umount2(path.as_ptr(), 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn path_cstring(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(nul_error)
}

fn nul_error(error: std::ffi::NulError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error)
}

fn format_ext4(
    formatter: &Path,
    device: &Path,
    inode_count: u64,
) -> Result<(), MountCacheRejectReason> {
    let mut child = Command::new(formatter)
        .arg("-F")
        .arg("-q")
        .arg("-m")
        .arg("0")
        .arg("-O")
        .arg("^has_journal")
        .arg("-E")
        .arg("lazy_itable_init=0")
        .arg("-N")
        .arg(inode_count.to_string())
        .arg(device)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| MountCacheRejectReason::FormatterFailed)?;
    let stderr = child.stderr.take().expect("formatter stderr was piped");
    let stderr_reader = thread::spawn(move || bounded_diagnostic(stderr));
    let deadline = Instant::now() + FORMAT_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(FORMAT_POLL_INTERVAL),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let diagnostic = stderr_reader.join().unwrap_or_default();
    if status.is_some_and(|status| status.success()) {
        Ok(())
    } else {
        if !diagnostic.is_empty() {
            eprintln!("lsb-guest: mkfs.ext4 rejected cache image: {diagnostic}");
        }
        Err(MountCacheRejectReason::FormatterFailed)
    }
}

fn bounded_diagnostic(mut reader: impl Read) -> String {
    let mut retained = Vec::with_capacity(MAX_FORMAT_DIAGNOSTIC);
    let mut buffer = [0u8; 1024];
    loop {
        let Ok(count) = reader.read(&mut buffer) else {
            break;
        };
        if count == 0 {
            break;
        }
        let remaining = MAX_FORMAT_DIAGNOSTIC.saturating_sub(retained.len());
        retained.extend_from_slice(&buffer[..count.min(remaining)]);
    }
    String::from_utf8_lossy(&retained)
        .chars()
        .map(|character| {
            if character == '\n' || character == '\t' || !character.is_control() {
                character
            } else {
                '?'
            }
        })
        .collect::<String>()
        .trim()
        .to_string()
}

#[derive(Debug)]
struct DeviceFacts {
    path: PathBuf,
    serial: String,
    size: u64,
    read_only: bool,
    is_root: bool,
    is_virtio: bool,
    is_mounted: bool,
    is_block: bool,
}

fn validate_device_facts(
    facts: DeviceFacts,
    serial: &str,
    size: u64,
    read_only: bool,
) -> Result<PathBuf, MountCacheRejectReason> {
    if facts.serial != serial {
        return Err(MountCacheRejectReason::SerialMismatch);
    }
    if facts.is_root {
        return Err(MountCacheRejectReason::RootDevice);
    }
    if !facts.is_virtio || !facts.is_block {
        return Err(MountCacheRejectReason::NonVirtioDevice);
    }
    if facts.size != size {
        return Err(MountCacheRejectReason::SizeMismatch);
    }
    if facts.read_only != read_only {
        return Err(MountCacheRejectReason::ReadOnlyMismatch);
    }
    if facts.is_mounted {
        return Err(MountCacheRejectReason::DeviceMounted);
    }
    Ok(facts.path)
}

fn discover_cache_device(
    expected_serial: &str,
    expected_size: u64,
    expected_read_only: bool,
) -> Result<PathBuf, MountCacheRejectReason> {
    let entries = std::fs::read_dir("/sys/class/block")
        .map_err(|_| MountCacheRejectReason::DeviceNotFound)?;
    for entry in entries.flatten() {
        let sys_path = entry.path();
        let Ok(serial) = std::fs::read_to_string(sys_path.join("serial")) else {
            continue;
        };
        if serial.trim() != expected_serial {
            continue;
        }
        let name = entry.file_name();
        let device_path = Path::new("/dev").join(&name);
        let sectors = read_u64(&sys_path.join("size"))?;
        let size = sectors
            .checked_mul(512)
            .ok_or(MountCacheRejectReason::SizeMismatch)?;
        let read_only = read_u64(&sys_path.join("ro"))? == 1;
        let device_number = std::fs::read_to_string(sys_path.join("dev"))
            .map_err(|_| MountCacheRejectReason::DeviceNotFound)?;
        let mount_state = read_mount_state(device_number.trim());
        let canonical = std::fs::canonicalize(&sys_path)
            .map_err(|_| MountCacheRejectReason::NonVirtioDevice)?;
        let is_virtio = canonical
            .components()
            .any(|component| component.as_os_str().as_bytes().starts_with(b"virtio"));
        let is_block = std::fs::symlink_metadata(&device_path)
            .map(|metadata| metadata.file_type().is_block_device())
            .unwrap_or(false);
        let facts = DeviceFacts {
            path: device_path,
            serial: serial.trim().to_string(),
            size,
            read_only,
            is_root: mount_state.0,
            is_virtio,
            is_mounted: mount_state.1,
            is_block,
        };
        return validate_device_facts(facts, expected_serial, expected_size, expected_read_only);
    }
    Err(MountCacheRejectReason::DeviceNotFound)
}

fn read_u64(path: &Path) -> Result<u64, MountCacheRejectReason> {
    std::fs::read_to_string(path)
        .map_err(|_| MountCacheRejectReason::DeviceNotFound)?
        .trim()
        .parse()
        .map_err(|_| MountCacheRejectReason::DeviceNotFound)
}

fn read_mount_state(device_number: &str) -> (bool, bool) {
    let Ok(mountinfo) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return (false, true);
    };
    let mut is_root = false;
    let mut is_mounted = false;
    for line in mountinfo.lines() {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() < 5 || fields[2] != device_number {
            continue;
        }
        is_mounted = true;
        if fields[4] == "/" {
            is_root = true;
        }
    }
    (is_root, is_mounted)
}

fn write_sentinel(mount_dir: &Path, expected_key: &str) -> io::Result<()> {
    let path = mount_dir.join(SENTINEL_NAME);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(format!("abi=1\nkey={expected_key}\n").as_bytes())?;
    file.sync_all()
}

fn read_sentinel(mount_dir: &Path) -> io::Result<String> {
    let directory = open_directory_at(libc::AT_FDCWD, mount_dir.as_os_str().as_bytes())?;
    let name = CString::new(SENTINEL_NAME).expect("sentinel name has no NUL");
    let file = open_file_at(&directory, &name)?;
    let metadata = fstat(&file)?;
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG
        || metadata.st_nlink != 1
        || metadata.st_size < 0
        || metadata.st_size > 256
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid cache sentinel",
        ));
    }
    let mut value = String::new();
    file.take(257).read_to_string(&mut value)?;
    let Some(key) = value
        .strip_prefix("abi=1\nkey=")
        .and_then(|value| value.strip_suffix('\n'))
    else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid cache sentinel",
        ));
    };
    Ok(key.to_string())
}

fn sync_mount(mount_dir: &Path) -> io::Result<()> {
    let directory = File::open(mount_dir)?;
    let result = unsafe { libc::syncfs(directory.as_raw_fd()) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn set_block_read_only(device: &Path) -> io::Result<()> {
    let file = OpenOptions::new().read(true).write(true).open(device)?;
    let read_only: libc::c_int = 1;
    let result = unsafe { libc::ioctl(file.as_raw_fd(), BLKROSET, &read_only) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn hash_raw_device(device: &Path, expected_size: u64) -> io::Result<String> {
    let mut file = File::open(device)?;
    let mut remaining = expected_size;
    let mut buffer = vec![0u8; HASH_BUFFER_SIZE];
    let mut hasher = blake3::Hasher::new();
    while remaining != 0 {
        let wanted = remaining.min(buffer.len() as u64) as usize;
        file.read_exact(&mut buffer[..wanted])?;
        hasher.update(&buffer[..wanted]);
        remaining -= wanted as u64;
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn hash_source_tree(source: &Path) -> io::Result<String> {
    let root = open_directory_at(libc::AT_FDCWD, source.as_os_str().as_bytes())?;
    verify_directory_mode(&root)?;
    let mut encoder = MountSnapshotKeyEncoder::new();
    encoder.add_directory("").map_err(encoding_error)?;
    hash_directory(&root, "", &mut encoder)?;
    encoder
        .finish()
        .map(|key| key.to_hex())
        .map_err(encoding_error)
}

fn hash_directory(
    directory: &File,
    relative_directory: &str,
    encoder: &mut MountSnapshotKeyEncoder,
) -> io::Result<()> {
    let names = directory_names(directory)?;
    for name in &names {
        let relative = if relative_directory.is_empty() {
            name.clone()
        } else {
            format!("{relative_directory}/{name}")
        };
        let name_c = CString::new(name.as_bytes()).map_err(nul_error)?;
        let metadata = stat_at(directory, &name_c)?;
        let kind = metadata.st_mode & libc::S_IFMT;
        if kind == libc::S_IFDIR {
            let child = open_directory_at(directory.as_raw_fd(), name.as_bytes())?;
            verify_directory_mode(&child)?;
            encoder.add_directory(&relative).map_err(encoding_error)?;
            hash_directory(&child, &relative, encoder)?;
        } else if kind == libc::S_IFREG {
            if metadata.st_nlink != 1 || (metadata.st_mode & 0o7777) != MOUNT_IMPORT_FILE_MODE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "cache source contains a hard link or wrong-mode file",
                ));
            }
            let mut file = open_file_at(directory, &name_c)?;
            let opened = fstat(&file)?;
            if !same_file(&metadata, &opened) || opened.st_size < 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "cache source file changed while opening",
                ));
            }
            let length = opened.st_size as u64;
            encoder
                .begin_file(&relative, length)
                .map_err(encoding_error)?;
            let mut remaining = length;
            let mut buffer = vec![0u8; HASH_BUFFER_SIZE];
            while remaining != 0 {
                let wanted = remaining.min(buffer.len() as u64) as usize;
                file.read_exact(&mut buffer[..wanted])?;
                encoder
                    .write_file_bytes(&buffer[..wanted])
                    .map_err(encoding_error)?;
                remaining -= wanted as u64;
            }
            let mut extra = [0u8; 1];
            if file.read(&mut extra)? != 0 || !same_file(&opened, &fstat(&file)?) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "cache source file changed while hashing",
                ));
            }
            encoder.finish_file().map_err(encoding_error)?;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "cache source contains an unsupported entry type",
            ));
        }
    }
    if directory_names(directory)? != names {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "cache source directory changed while hashing",
        ));
    }
    Ok(())
}

fn verify_directory_mode(directory: &File) -> io::Result<()> {
    let metadata = fstat(directory)?;
    if metadata.st_mode & libc::S_IFMT != libc::S_IFDIR
        || (metadata.st_mode & 0o7777) != MOUNT_IMPORT_DIRECTORY_MODE
    {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "cache source contains a wrong-mode directory",
        ))
    } else {
        Ok(())
    }
}

fn directory_names(directory: &File) -> io::Result<Vec<String>> {
    let current = c".";
    let duplicated = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            current.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if duplicated < 0 {
        return Err(io::Error::last_os_error());
    }
    let stream = unsafe { libc::fdopendir(duplicated) };
    if stream.is_null() {
        unsafe { libc::close(duplicated) };
        return Err(io::Error::last_os_error());
    }
    let mut names = Vec::new();
    loop {
        unsafe { *libc::__errno_location() = 0 };
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            unsafe { libc::closedir(stream) };
            if error.raw_os_error() == Some(0) {
                break;
            }
            return Err(error);
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        let name = std::str::from_utf8(name).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "cache source entry name is not UTF-8",
            )
        })?;
        if name.contains('\\') {
            unsafe { libc::closedir(stream) };
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "cache source entry contains a backslash",
            ));
        }
        names.push(name.to_string());
    }
    names.sort();
    if names.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "cache source contains duplicate names",
        ));
    }
    Ok(names)
}

fn open_directory_at(parent: libc::c_int, name: &[u8]) -> io::Result<File> {
    let name = CString::new(name).map_err(nul_error)?;
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

fn open_file_at(directory: &File, name: &CString) -> io::Result<File> {
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

fn stat_at(directory: &File, name: &CString) -> io::Result<libc::stat> {
    let mut metadata = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            &mut metadata,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        Ok(metadata)
    } else {
        Err(io::Error::last_os_error())
    }
}

fn fstat(file: &File) -> io::Result<libc::stat> {
    let mut metadata = unsafe { std::mem::zeroed() };
    let result = unsafe { libc::fstat(file.as_raw_fd(), &mut metadata) };
    if result == 0 {
        Ok(metadata)
    } else {
        Err(io::Error::last_os_error())
    }
}

fn same_file(left: &libc::stat, right: &libc::stat) -> bool {
    left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
        && left.st_mode == right.st_mode
        && left.st_nlink == right.st_nlink
        && left.st_size == right.st_size
}

fn encoding_error(error: lsb_proto::MountSnapshotEncodingError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn device_validation_rejects_every_unsafe_device_property() {
        let valid = || DeviceFacts {
            path: PathBuf::from("/dev/vdb"),
            serial: "lsb-cache-0".to_string(),
            size: 128 * 1024 * 1024,
            read_only: false,
            is_root: false,
            is_virtio: true,
            is_mounted: false,
            is_block: true,
        };
        assert!(validate_device_facts(valid(), "lsb-cache-0", 128 * 1024 * 1024, false).is_ok());

        let mut facts = valid();
        facts.is_root = true;
        assert_eq!(
            validate_device_facts(facts, "lsb-cache-0", 128 * 1024 * 1024, false),
            Err(MountCacheRejectReason::RootDevice)
        );
        let mut facts = valid();
        facts.is_virtio = false;
        assert_eq!(
            validate_device_facts(facts, "lsb-cache-0", 128 * 1024 * 1024, false),
            Err(MountCacheRejectReason::NonVirtioDevice)
        );
        let mut facts = valid();
        facts.is_mounted = true;
        assert_eq!(
            validate_device_facts(facts, "lsb-cache-0", 128 * 1024 * 1024, false),
            Err(MountCacheRejectReason::DeviceMounted)
        );
        assert_eq!(
            validate_device_facts(valid(), "wrong", 128 * 1024 * 1024, false),
            Err(MountCacheRejectReason::SerialMismatch)
        );
        assert_eq!(
            validate_device_facts(valid(), "lsb-cache-0", 256 * 1024 * 1024, false),
            Err(MountCacheRejectReason::SizeMismatch)
        );
        assert_eq!(
            validate_device_facts(valid(), "lsb-cache-0", 128 * 1024 * 1024, true),
            Err(MountCacheRejectReason::ReadOnlyMismatch)
        );
    }

    #[test]
    fn source_tree_hash_matches_shared_encoder_and_rejects_unsafe_entries() {
        let root = temp_dir("tree");
        create_directory_with_mode(&root, MOUNT_IMPORT_DIRECTORY_MODE).unwrap();
        create_directory_with_mode(&root.join("empty"), MOUNT_IMPORT_DIRECTORY_MODE).unwrap();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(MOUNT_IMPORT_FILE_MODE)
            .open(root.join("hello.txt"))
            .unwrap();
        file.write_all(b"hello").unwrap();

        let mut expected = MountSnapshotKeyEncoder::new();
        expected.add_directory("").unwrap();
        expected.add_directory("empty").unwrap();
        expected.begin_file("hello.txt", 5).unwrap();
        expected.write_file_bytes(b"hello").unwrap();
        expected.finish_file().unwrap();
        assert_eq!(
            hash_source_tree(&root).unwrap(),
            expected.finish().unwrap().to_hex()
        );

        std::os::unix::fs::symlink("hello.txt", root.join("link")).unwrap();
        assert!(hash_source_tree(&root).is_err());
        std::fs::remove_file(root.join("link")).unwrap();
        std::fs::set_permissions(
            root.join("hello.txt"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(hash_source_tree(&root).is_err());
        std::fs::set_permissions(
            root.join("hello.txt"),
            std::fs::Permissions::from_mode(MOUNT_IMPORT_FILE_MODE),
        )
        .unwrap();
        std::fs::set_permissions(root.join("empty"), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        assert!(hash_source_tree(&root).is_err());
        std::fs::set_permissions(
            root.join("empty"),
            std::fs::Permissions::from_mode(MOUNT_IMPORT_DIRECTORY_MODE),
        )
        .unwrap();
        std::fs::hard_link(root.join("hello.txt"), root.join("hard-link")).unwrap();
        assert!(hash_source_tree(&root).is_err());
        std::fs::remove_file(root.join("hard-link")).unwrap();
        let fifo = root.join("fifo");
        let fifo_name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
        assert!(hash_source_tree(&root).is_err());
        std::fs::remove_file(fifo).unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn source_tree_hash_detects_add_rename_and_content_changes() {
        let root = temp_dir("mutations");
        create_directory_with_mode(&root, MOUNT_IMPORT_DIRECTORY_MODE).unwrap();
        write_mode(&root.join("one"), b"same");
        let original = hash_source_tree(&root).unwrap();
        write_mode(&root.join("two"), b"more");
        assert_ne!(hash_source_tree(&root).unwrap(), original);
        std::fs::remove_file(root.join("two")).unwrap();
        std::fs::rename(root.join("one"), root.join("renamed")).unwrap();
        assert_ne!(hash_source_tree(&root).unwrap(), original);
        std::fs::rename(root.join("renamed"), root.join("one")).unwrap();
        write_mode_replace(&root.join("one"), b"diff");
        assert_ne!(hash_source_tree(&root).unwrap(), original);
        std::fs::remove_file(root.join("one")).unwrap();
        assert_ne!(hash_source_tree(&root).unwrap(), original);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn import_batches_create_normalized_directories_and_sequential_file_chunks() {
        let root = temp_dir("batch-import");
        create_directory_with_mode(&root, MOUNT_IMPORT_DIRECTORY_MODE).unwrap();
        apply_import_batch(
            &root,
            &[
                MountCacheImportEntry::Directory {
                    path: "nested".to_string(),
                },
                MountCacheImportEntry::FileChunk {
                    path: "nested/file.txt".to_string(),
                    offset: 0,
                    len: 2,
                    truncate: true,
                },
            ],
            b"he",
        )
        .unwrap();
        apply_import_batch(
            &root,
            &[MountCacheImportEntry::FileChunk {
                path: "nested/file.txt".to_string(),
                offset: 2,
                len: 3,
                truncate: false,
            }],
            b"llo",
        )
        .unwrap();

        assert_eq!(
            std::fs::read(root.join("nested/file.txt")).unwrap(),
            b"hello"
        );
        assert_eq!(
            std::fs::metadata(root.join("nested"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            MOUNT_IMPORT_DIRECTORY_MODE
        );
        assert_eq!(
            std::fs::metadata(root.join("nested/file.txt"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            MOUNT_IMPORT_FILE_MODE
        );
        assert!(apply_import_batch(
            &root,
            &[MountCacheImportEntry::FileChunk {
                path: "nested/file.txt".to_string(),
                offset: 99,
                len: 1,
                truncate: false,
            }],
            b"x",
        )
        .is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    fn write_mode(path: &Path, contents: &[u8]) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(MOUNT_IMPORT_FILE_MODE)
            .open(path)
            .unwrap();
        file.write_all(contents).unwrap();
    }

    fn write_mode_replace(path: &Path, contents: &[u8]) {
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(path)
            .unwrap();
        file.write_all(contents).unwrap();
    }

    fn temp_dir(label: &str) -> PathBuf {
        let nonce = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "lsb-guest-cache-{label}-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        root
    }
}
