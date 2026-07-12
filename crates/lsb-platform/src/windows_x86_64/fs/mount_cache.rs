use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, ERROR_LOCK_VIOLATION, GENERIC_READ, GENERIC_WRITE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetFileInformationByHandle, LockFileEx, SetFileAttributesW, UnlockFileEx,
    BY_HANDLE_FILE_INFORMATION, CREATE_NEW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_SHARE_READ, FILE_SHARE_WRITE, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
    OPEN_ALWAYS, OPEN_EXISTING,
};
use windows_sys::Win32::System::IO::{DeviceIoControl, OVERLAPPED};

use super::WindowsMountSnapshot;

const CACHE_SCHEMA_VERSION: u16 = 1;
const CACHE_DIRECTORY: &str = "mount-cache";
const CACHE_VERSION_DIRECTORY: &str = "v1";
const IMAGE_NAME: &str = "image.ext4";
const MANIFEST_NAME: &str = "manifest.json";
const IMAGE_ALIGNMENT: u64 = 16 * 1024 * 1024;
const MIN_IMAGE_SIZE: u64 = 128 * 1024 * 1024;
const DEFAULT_MAX_IMAGE_SIZE: u64 = 8 * 1024 * 1024 * 1024;
const DEFAULT_NONSPARSE_MAX: u64 = 512 * 1024 * 1024;
const DEFAULT_TOTAL_LOGICAL_LIMIT: u64 = 4 * 1024 * 1024 * 1024;
const DEFAULT_OBJECT_LIMIT: usize = 64;
const DEFAULT_MAX_AGE_SECONDS: u64 = 30 * 24 * 60 * 60;
const STAGING_MAX_AGE_SECONDS: u64 = 60 * 60;
const MANIFEST_LIMIT: u64 = 64 * 1024;
const HASH_BUFFER_SIZE: usize = 1024 * 1024;
const FSCTL_SET_SPARSE_CODE: u32 = 0x0009_00c4;
pub const WINDOWS_MOUNT_CACHE_DIR_ENV: &str = "LSB_WINDOWS_MOUNT_CACHE_DIR";

#[derive(Debug, Clone)]
pub struct WindowsMountCache {
    layout: CacheLayout,
    limits: WindowsMountCacheLimits,
}

#[derive(Debug, Clone)]
struct CacheLayout {
    root: PathBuf,
    locks: PathBuf,
    objects: PathBuf,
    access: PathBuf,
    staging: PathBuf,
}

#[derive(Debug, Clone, Copy)]
pub struct WindowsMountCacheLimits {
    pub max_image_size: u64,
    pub max_nonsparse_image_size: u64,
    pub max_total_logical_size: u64,
    pub max_objects: usize,
    pub max_age_seconds: u64,
}

impl Default for WindowsMountCacheLimits {
    fn default() -> Self {
        Self {
            max_image_size: DEFAULT_MAX_IMAGE_SIZE,
            max_nonsparse_image_size: DEFAULT_NONSPARSE_MAX,
            max_total_logical_size: DEFAULT_TOTAL_LOGICAL_LIMIT,
            max_objects: DEFAULT_OBJECT_LIMIT,
            max_age_seconds: DEFAULT_MAX_AGE_SECONDS,
        }
    }
}

pub enum WindowsMountCacheSelection {
    Hit(WindowsMountCacheHit),
    Build(WindowsMountCacheBuild),
    Bypass { reason: String },
}

pub struct WindowsMountCacheHit {
    pub image_id: String,
    pub image_path: PathBuf,
    pub virtual_size: u64,
    pub inode_count: u64,
    pub raw_image_blake3: String,
    _lock: DigestLock,
    _image: ValidatedImage,
}

pub struct WindowsMountCacheBuild {
    pub image_id: String,
    pub image_path: PathBuf,
    pub virtual_size: u64,
    pub inode_count: u64,
    manifest: MountCacheManifest,
    object_dir: PathBuf,
    staging_dir: Option<PathBuf>,
    _lock: DigestLock,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MountCacheManifest {
    pub schema_version: u16,
    pub cache_key_abi: u16,
    pub source_tree_digest: String,
    pub raw_image_blake3: String,
    pub image_format: MountCacheImageFormat,
    pub virtual_size: u64,
    pub source_bytes: u64,
    pub file_count: u64,
    pub directory_count: u64,
    pub inode_count: u64,
    pub created_unix_seconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MountCacheImageFormat {
    RawExt4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MountCacheImageSizing {
    pub virtual_size: u64,
    pub inode_count: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MountCacheMaintenanceReport {
    pub removed_objects: u64,
    pub removed_staging_directories: u64,
    pub skipped_locked: u64,
    pub objects_after: u64,
    pub logical_bytes_after: u64,
}

struct EvictionCandidate {
    image_id: String,
    virtual_size: u64,
    last_access: SystemTime,
}

struct DigestLock {
    file: File,
}

struct ValidatedImage {
    file: File,
}

struct ValidatedHit {
    image_path: PathBuf,
    manifest: MountCacheManifest,
    image: ValidatedImage,
}

impl WindowsMountCache {
    pub fn new(data_dir: impl AsRef<Path>) -> Result<Self> {
        let override_dir = std::env::var_os(WINDOWS_MOUNT_CACHE_DIR_ENV)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from);
        Self::with_limits(
            override_dir.as_deref().unwrap_or_else(|| data_dir.as_ref()),
            WindowsMountCacheLimits::default(),
        )
    }

    pub fn with_limits(
        data_dir: impl AsRef<Path>,
        limits: WindowsMountCacheLimits,
    ) -> Result<Self> {
        let layout = CacheLayout::new(data_dir.as_ref())?;
        Ok(Self { layout, limits })
    }

    pub fn root(&self) -> &Path {
        &self.layout.root
    }

    pub fn maintain(&self) -> Result<MountCacheMaintenanceReport> {
        let mut report = MountCacheMaintenanceReport::default();
        self.sweep_staging(false, &mut report)?;
        let mut candidates = self.collect_eviction_candidates(&mut report)?;
        candidates.sort_by_key(|candidate| candidate.last_access);
        let now = SystemTime::now();
        let mut total = candidates.iter().fold(0u64, |total, candidate| {
            total.saturating_add(candidate.virtual_size)
        });
        let mut count = candidates.len();
        for candidate in candidates {
            let expired = now
                .duration_since(candidate.last_access)
                .map(|age| age.as_secs() > self.limits.max_age_seconds)
                .unwrap_or(false);
            if !expired
                && count <= self.limits.max_objects
                && total <= self.limits.max_total_logical_size
            {
                continue;
            }
            if self.try_remove_object(&candidate.image_id)? {
                report.removed_objects = report.removed_objects.saturating_add(1);
                count = count.saturating_sub(1);
                total = total.saturating_sub(candidate.virtual_size);
            } else {
                report.skipped_locked = report.skipped_locked.saturating_add(1);
            }
        }
        report.objects_after = count as u64;
        report.logical_bytes_after = total;
        Ok(report)
    }

    pub fn prune_all(&self) -> Result<MountCacheMaintenanceReport> {
        let mut report = MountCacheMaintenanceReport::default();
        self.sweep_staging(true, &mut report)?;
        for entry in fs::read_dir(&self.layout.objects).with_context(|| {
            format!(
                "failed to enumerate mount cache objects {}",
                self.layout.objects.display()
            )
        })? {
            let entry = entry?;
            let Some(image_id) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if validate_digest(&image_id).is_err() {
                continue;
            }
            if self.try_remove_object(&image_id)? {
                report.removed_objects = report.removed_objects.saturating_add(1);
            } else {
                report.skipped_locked = report.skipped_locked.saturating_add(1);
            }
        }
        let remaining = self.collect_eviction_candidates(&mut report)?;
        report.objects_after = remaining.len() as u64;
        report.logical_bytes_after = remaining.iter().fold(0u64, |total, candidate| {
            total.saturating_add(candidate.virtual_size)
        });
        Ok(report)
    }

    pub fn invalidate(&self, image_id: &str) -> Result<bool> {
        self.try_remove_object(image_id)
    }

    pub fn select(&self, snapshot: &WindowsMountSnapshot) -> Result<WindowsMountCacheSelection> {
        let image_id = snapshot.key.to_hex();
        validate_digest(&image_id)?;
        let lock_path = self.layout.locks.join(format!("{image_id}.lock"));

        if let Some(lock) = DigestLock::try_acquire(&lock_path, false)? {
            match self.validate_hit(&image_id) {
                Ok(Some(hit)) => {
                    return Ok(WindowsMountCacheSelection::Hit(
                        hit.with_lock(lock, &image_id),
                    ));
                }
                Ok(None) => {}
                Err(error) => {
                    eprintln!("lsb: mount cache object {image_id} was rejected: {error:#}");
                }
            }
        }

        let Some(lock) = DigestLock::try_acquire(&lock_path, true)? else {
            return Ok(WindowsMountCacheSelection::Bypass {
                reason: "another process is building or maintaining this cache key".to_string(),
            });
        };

        match self.validate_hit(&image_id) {
            Ok(Some(hit)) => {
                return Ok(WindowsMountCacheSelection::Hit(
                    hit.with_lock(lock, &image_id),
                ));
            }
            Ok(None) => {}
            Err(error) => {
                eprintln!("lsb: removing invalid mount cache object {image_id}: {error:#}");
            }
        }

        let object_dir = self.layout.objects.join(&image_id);
        if object_dir.exists() {
            remove_tree_secure(&object_dir).with_context(|| {
                format!(
                    "failed to remove incomplete cache object {}",
                    object_dir.display()
                )
            })?;
        }

        let sizing = match mount_cache_image_sizing(snapshot, self.limits.max_image_size) {
            Ok(sizing) => sizing,
            Err(error) => {
                return Ok(WindowsMountCacheSelection::Bypass {
                    reason: error.to_string(),
                });
            }
        };
        let staging_dir = self.create_staging_directory(&image_id)?;
        let image_path = staging_dir.join(IMAGE_NAME);
        if let Err(error) = create_staging_image(
            &image_path,
            sizing.virtual_size,
            self.limits.max_nonsparse_image_size,
        ) {
            let _ = remove_tree_secure(&staging_dir);
            return Ok(WindowsMountCacheSelection::Bypass {
                reason: format!("failed to create a safe cache image: {error:#}"),
            });
        }

        let created_unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let manifest = MountCacheManifest {
            schema_version: CACHE_SCHEMA_VERSION,
            cache_key_abi: lsb_proto::MOUNT_CACHE_KEY_ABI_VERSION,
            source_tree_digest: image_id.clone(),
            raw_image_blake3: String::new(),
            image_format: MountCacheImageFormat::RawExt4,
            virtual_size: sizing.virtual_size,
            source_bytes: snapshot.logical_bytes,
            file_count: snapshot.file_count,
            directory_count: snapshot.directory_count,
            inode_count: sizing.inode_count,
            created_unix_seconds,
        };
        Ok(WindowsMountCacheSelection::Build(WindowsMountCacheBuild {
            image_id,
            image_path,
            virtual_size: sizing.virtual_size,
            inode_count: sizing.inode_count,
            manifest,
            object_dir,
            staging_dir: Some(staging_dir),
            _lock: lock,
        }))
    }

    fn validate_hit(&self, image_id: &str) -> Result<Option<ValidatedHit>> {
        let object_dir = self.layout.objects.join(image_id);
        let manifest_path = object_dir.join(MANIFEST_NAME);
        if !manifest_path.exists() {
            return Ok(None);
        }
        ensure_directory_no_reparse(&object_dir)?;
        validate_object_directory(&object_dir)?;
        let manifest = read_manifest(&manifest_path)?;
        validate_manifest(&manifest, image_id, self.limits.max_image_size)?;
        let image_path = object_dir.join(IMAGE_NAME);
        let image = open_validated_image(&image_path, manifest.virtual_size, true)?;
        let actual_digest = hash_exact(&image.file, manifest.virtual_size)?;
        if actual_digest != manifest.raw_image_blake3 {
            bail!("raw image digest does not match its manifest");
        }
        let _ = update_access_marker(&self.layout.access.join(image_id));
        Ok(Some(ValidatedHit {
            image_path,
            manifest,
            image,
        }))
    }

    fn create_staging_directory(&self, image_id: &str) -> Result<PathBuf> {
        for _ in 0..16 {
            let mut nonce = [0u8; 8];
            getrandom::fill(&mut nonce)
                .map_err(|error| anyhow!("failed to generate cache staging nonce: {error}"))?;
            let nonce = nonce
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let path = self
                .layout
                .staging
                .join(format!("{image_id}.{}.{nonce}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => {
                    ensure_directory_no_reparse(&path)?;
                    return Ok(path);
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "failed to create cache staging directory {}",
                            path.display()
                        )
                    });
                }
            }
        }
        bail!("failed to allocate a unique cache staging directory")
    }

    fn sweep_staging(
        &self,
        remove_all: bool,
        report: &mut MountCacheMaintenanceReport,
    ) -> Result<()> {
        let now = SystemTime::now();
        for entry in fs::read_dir(&self.layout.staging).with_context(|| {
            format!(
                "failed to enumerate mount cache staging {}",
                self.layout.staging.display()
            )
        })? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some(image_id) = name.get(..64) else {
                continue;
            };
            if validate_digest(image_id).is_err() {
                continue;
            }
            let metadata = fs::symlink_metadata(entry.path())?;
            let stale = remove_all
                || metadata
                    .modified()
                    .ok()
                    .and_then(|modified| now.duration_since(modified).ok())
                    .is_some_and(|age| age.as_secs() > STAGING_MAX_AGE_SECONDS);
            if !stale {
                continue;
            }
            let lock_path = self.layout.locks.join(format!("{image_id}.lock"));
            let Some(_lock) = DigestLock::try_acquire(&lock_path, true)? else {
                report.skipped_locked = report.skipped_locked.saturating_add(1);
                continue;
            };
            remove_tree_secure(&entry.path()).with_context(|| {
                format!(
                    "failed to remove stale mount cache staging {}",
                    entry.path().display()
                )
            })?;
            report.removed_staging_directories =
                report.removed_staging_directories.saturating_add(1);
        }
        Ok(())
    }

    fn collect_eviction_candidates(
        &self,
        report: &mut MountCacheMaintenanceReport,
    ) -> Result<Vec<EvictionCandidate>> {
        let mut candidates = Vec::new();
        for entry in fs::read_dir(&self.layout.objects).with_context(|| {
            format!(
                "failed to enumerate mount cache objects {}",
                self.layout.objects.display()
            )
        })? {
            let entry = entry?;
            let Some(image_id) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if validate_digest(&image_id).is_err() {
                continue;
            }
            let manifest_path = entry.path().join(MANIFEST_NAME);
            let manifest = read_manifest(&manifest_path).and_then(|manifest| {
                validate_manifest(&manifest, &image_id, self.limits.max_image_size)?;
                Ok(manifest)
            });
            let manifest = match manifest {
                Ok(manifest) => manifest,
                Err(_) => {
                    if self.try_remove_object(&image_id)? {
                        report.removed_objects = report.removed_objects.saturating_add(1);
                    } else {
                        report.skipped_locked = report.skipped_locked.saturating_add(1);
                    }
                    continue;
                }
            };
            let access_path = self.layout.access.join(&image_id);
            let last_access = fs::symlink_metadata(&access_path)
                .ok()
                .filter(|metadata| metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0)
                .and_then(|metadata| metadata.modified().ok())
                .unwrap_or_else(|| UNIX_EPOCH + Duration::from_secs(manifest.created_unix_seconds));
            candidates.push(EvictionCandidate {
                image_id,
                virtual_size: manifest.virtual_size,
                last_access,
            });
        }
        Ok(candidates)
    }

    fn try_remove_object(&self, image_id: &str) -> Result<bool> {
        validate_digest(image_id)?;
        let lock_path = self.layout.locks.join(format!("{image_id}.lock"));
        let Some(_lock) = DigestLock::try_acquire(&lock_path, true)? else {
            return Ok(false);
        };
        let object_dir = self.layout.objects.join(image_id);
        if object_dir.exists() {
            remove_object_secure(&object_dir)?;
        }
        let access_path = self.layout.access.join(image_id);
        if access_path.exists() {
            remove_file_secure(&access_path)?;
        }
        Ok(true)
    }
}

impl ValidatedHit {
    fn with_lock(self, lock: DigestLock, image_id: &str) -> WindowsMountCacheHit {
        WindowsMountCacheHit {
            image_id: image_id.to_string(),
            image_path: self.image_path,
            virtual_size: self.manifest.virtual_size,
            inode_count: self.manifest.inode_count,
            raw_image_blake3: self.manifest.raw_image_blake3,
            _lock: lock,
            _image: self.image,
        }
    }
}

impl CacheLayout {
    fn new(data_dir: &Path) -> Result<Self> {
        let cache = data_dir.join(CACHE_DIRECTORY);
        let root = cache.join(CACHE_VERSION_DIRECTORY);
        let layout = Self {
            locks: root.join("locks"),
            objects: root.join("objects"),
            access: root.join("access"),
            staging: root.join("staging"),
            root,
        };
        for path in [
            &cache,
            &layout.root,
            &layout.locks,
            &layout.objects,
            &layout.access,
            &layout.staging,
        ] {
            fs::create_dir_all(path).with_context(|| {
                format!("failed to create mount cache directory {}", path.display())
            })?;
            ensure_directory_no_reparse(path)?;
        }
        Ok(layout)
    }
}

impl WindowsMountCacheBuild {
    pub fn publish(mut self, sealed_raw_digest: &str) -> Result<PathBuf> {
        validate_digest(sealed_raw_digest)?;
        let staging_dir = self
            .staging_dir
            .as_ref()
            .ok_or_else(|| anyhow!("cache build was already finalized"))?;
        ensure_directory_no_reparse(staging_dir)?;
        let image = open_validated_image(&self.image_path, self.virtual_size, false)?;
        let actual_digest = hash_exact(&image.file, self.virtual_size)?;
        if actual_digest != sealed_raw_digest {
            bail!("post-stop cache image digest does not match the sealed guest digest");
        }
        drop(image);

        set_read_only(&self.image_path, true)?;
        let readonly_image = open_validated_image(&self.image_path, self.virtual_size, true)?;
        drop(readonly_image);
        self.manifest.raw_image_blake3 = actual_digest;
        write_manifest(&staging_dir.join(MANIFEST_NAME), &self.manifest)?;
        if self.object_dir.exists() {
            bail!(
                "cache object appeared before publication: {}",
                self.object_dir.display()
            );
        }
        fs::rename(staging_dir, &self.object_dir).with_context(|| {
            format!(
                "failed to atomically publish cache object {}",
                self.object_dir.display()
            )
        })?;
        self.staging_dir = None;
        Ok(self.object_dir.join(IMAGE_NAME))
    }

    pub fn discard(mut self) -> Result<()> {
        self.cleanup_staging()
    }

    fn cleanup_staging(&mut self) -> Result<()> {
        if let Some(staging_dir) = self.staging_dir.take() {
            if staging_dir.exists() {
                remove_tree_secure(&staging_dir).with_context(|| {
                    format!(
                        "failed to discard cache staging directory {}",
                        staging_dir.display()
                    )
                })?;
            }
        }
        Ok(())
    }
}

impl Drop for WindowsMountCacheBuild {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup_staging() {
            eprintln!("lsb: failed to clean discarded mount cache build: {error:#}");
        }
    }
}

impl DigestLock {
    fn try_acquire(path: &Path, exclusive: bool) -> Result<Option<Self>> {
        ensure_parent_directory_no_reparse(path)?;
        let file = open_windows_file(
            path,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        )?;
        validate_regular_handle(&file, None, false)?;
        let mut overlapped = unsafe { std::mem::zeroed::<OVERLAPPED>() };
        let mut flags = LOCKFILE_FAIL_IMMEDIATELY;
        if exclusive {
            flags |= LOCKFILE_EXCLUSIVE_LOCK;
        }
        let locked = unsafe {
            LockFileEx(
                file.as_raw_handle() as _,
                flags,
                0,
                u32::MAX,
                u32::MAX,
                &mut overlapped,
            )
        };
        if locked != 0 {
            Ok(Some(Self { file }))
        } else {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_LOCK_VIOLATION as i32) {
                Ok(None)
            } else {
                Err(error).with_context(|| {
                    format!("failed to lock mount cache key file {}", path.display())
                })
            }
        }
    }
}

impl Drop for DigestLock {
    fn drop(&mut self) {
        let mut overlapped = unsafe { std::mem::zeroed::<OVERLAPPED>() };
        unsafe {
            UnlockFileEx(
                self.file.as_raw_handle() as _,
                0,
                u32::MAX,
                u32::MAX,
                &mut overlapped,
            );
        }
    }
}

pub fn mount_cache_image_sizing(
    snapshot: &WindowsMountSnapshot,
    max_image_size: u64,
) -> Result<MountCacheImageSizing> {
    let entry_count = snapshot
        .file_count
        .checked_add(snapshot.directory_count)
        .ok_or_else(|| anyhow!("mount cache entry count overflow"))?;
    let inode_count = entry_count
        .checked_add(1024)
        .and_then(|value| value.checked_mul(2))
        .ok_or_else(|| anyhow!("mount cache inode count overflow"))?
        .max(8192);
    let file_blocks = snapshot
        .file_count
        .checked_mul(4096)
        .ok_or_else(|| anyhow!("mount cache file-block estimate overflow"))?;
    let directory_blocks = snapshot
        .directory_count
        .checked_mul(16 * 1024)
        .ok_or_else(|| anyhow!("mount cache directory estimate overflow"))?;
    let inode_tables = inode_count
        .checked_mul(512)
        .ok_or_else(|| anyhow!("mount cache inode-table estimate overflow"))?;
    let payload = snapshot
        .logical_bytes
        .checked_add(file_blocks)
        .and_then(|value| value.checked_add(directory_blocks))
        .ok_or_else(|| anyhow!("mount cache payload estimate overflow"))?;
    let metadata = payload
        .checked_div(4)
        .and_then(|value| value.checked_add(inode_tables))
        .and_then(|value| value.checked_add(32 * 1024 * 1024))
        .ok_or_else(|| anyhow!("mount cache metadata estimate overflow"))?;
    let requested = payload
        .checked_add(metadata)
        .ok_or_else(|| anyhow!("mount cache image size overflow"))?
        .max(MIN_IMAGE_SIZE);
    let virtual_size = align_up(requested, IMAGE_ALIGNMENT)?;
    if virtual_size > max_image_size {
        bail!(
            "mount cache image requires {virtual_size} bytes, above the configured {max_image_size}-byte limit"
        );
    }
    Ok(MountCacheImageSizing {
        virtual_size,
        inode_count,
    })
}

fn align_up(value: u64, alignment: u64) -> Result<u64> {
    value
        .checked_add(alignment - 1)
        .map(|value| value / alignment * alignment)
        .ok_or_else(|| anyhow!("mount cache alignment overflow"))
}

fn create_staging_image(path: &Path, size: u64, nonsparse_limit: u64) -> Result<()> {
    ensure_parent_directory_no_reparse(path)?;
    let file = open_windows_file(
        path,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ,
        CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
    )?;
    validate_regular_handle(&file, Some(0), false)?;
    let sparse = set_sparse(&file).is_ok();
    if !sparse && size > nonsparse_limit {
        bail!(
            "NTFS sparse allocation is unavailable and {size} bytes exceeds the safe non-sparse limit"
        );
    }
    file.set_len(size)
        .with_context(|| format!("failed to size cache image {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to flush cache image {}", path.display()))?;
    validate_regular_handle(&file, Some(size), false)
}

fn set_sparse(file: &File) -> io::Result<()> {
    let mut returned = 0u32;
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle() as _,
            FSCTL_SET_SPARSE_CODE,
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok != 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn read_manifest(path: &Path) -> Result<MountCacheManifest> {
    let file = open_windows_file(
        path,
        GENERIC_READ,
        FILE_SHARE_READ,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
    )?;
    validate_regular_handle(&file, None, false)?;
    let mut bytes = Vec::new();
    file.take(MANIFEST_LIMIT + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read cache manifest {}", path.display()))?;
    if bytes.len() as u64 > MANIFEST_LIMIT {
        bail!("cache manifest exceeds {MANIFEST_LIMIT} bytes");
    }
    serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse cache manifest {}", path.display()))
}

fn write_manifest(path: &Path, manifest: &MountCacheManifest) -> Result<()> {
    ensure_parent_directory_no_reparse(path)?;
    let mut bytes =
        serde_json::to_vec_pretty(manifest).context("failed to serialize cache manifest")?;
    bytes.push(b'\n');
    let mut file = open_windows_file(
        path,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ,
        CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
    )?;
    validate_regular_handle(&file, Some(0), false)?;
    file.write_all(&bytes)
        .with_context(|| format!("failed to write cache manifest {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to flush cache manifest {}", path.display()))
}

fn validate_manifest(
    manifest: &MountCacheManifest,
    image_id: &str,
    max_image_size: u64,
) -> Result<()> {
    if manifest.schema_version != CACHE_SCHEMA_VERSION {
        bail!("unsupported mount cache schema version");
    }
    if manifest.cache_key_abi != lsb_proto::MOUNT_CACHE_KEY_ABI_VERSION {
        bail!("unsupported mount cache key ABI");
    }
    validate_digest(&manifest.source_tree_digest)?;
    validate_digest(&manifest.raw_image_blake3)?;
    if manifest.source_tree_digest != image_id {
        bail!("cache manifest digest does not match its object path");
    }
    if manifest.image_format != MountCacheImageFormat::RawExt4 {
        bail!("unsupported mount cache image format");
    }
    if manifest.virtual_size < MIN_IMAGE_SIZE
        || manifest.virtual_size % IMAGE_ALIGNMENT != 0
        || manifest.virtual_size > max_image_size
    {
        bail!("cache manifest has an invalid virtual image size");
    }
    let minimum_inodes = manifest
        .file_count
        .checked_add(manifest.directory_count)
        .and_then(|value| value.checked_add(1024))
        .and_then(|value| value.checked_mul(2))
        .ok_or_else(|| anyhow!("cache manifest inode count overflow"))?
        .max(8192);
    if manifest.inode_count < minimum_inodes {
        bail!("cache manifest inode count is too small");
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<()> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        bail!("expected a lowercase 64-character BLAKE3 digest")
    }
}

fn open_validated_image(path: &Path, size: u64, require_read_only: bool) -> Result<ValidatedImage> {
    ensure_parent_directory_no_reparse(path)?;
    let file = open_windows_file(
        path,
        GENERIC_READ,
        FILE_SHARE_READ,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
    )?;
    validate_regular_handle(&file, Some(size), require_read_only)?;
    Ok(ValidatedImage { file })
}

fn hash_exact(file: &File, size: u64) -> Result<String> {
    let mut file = file
        .try_clone()
        .context("failed to duplicate cache image hash handle")?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0u8; HASH_BUFFER_SIZE];
    let mut remaining = size;
    while remaining != 0 {
        let wanted = remaining.min(buffer.len() as u64) as usize;
        file.read_exact(&mut buffer[..wanted])
            .context("cache image ended before its advertised virtual size")?;
        hasher.update(&buffer[..wanted]);
        remaining -= wanted as u64;
    }
    let mut extra = [0u8; 1];
    if file.read(&mut extra)? != 0 {
        bail!("cache image exceeds its advertised virtual size");
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn open_windows_file(
    path: &Path,
    access: u32,
    share: u32,
    disposition: u32,
    flags: u32,
) -> Result<File> {
    let wide = wide_path(path);
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            access,
            share,
            std::ptr::null(),
            disposition,
            flags,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        let error = io::Error::last_os_error();
        if disposition == CREATE_NEW
            && matches!(
                error.raw_os_error(),
                Some(code) if code == ERROR_FILE_EXISTS as i32 || code == ERROR_ALREADY_EXISTS as i32
            )
        {
            bail!("cache path already exists: {}", path.display());
        }
        return Err(error).with_context(|| format!("failed to open cache path {}", path.display()));
    }
    Ok(unsafe { File::from_raw_handle(handle as RawHandle) })
}

fn validate_regular_handle(
    file: &File,
    expected_size: Option<u64>,
    require_read_only: bool,
) -> Result<()> {
    let info = handle_info(file)?;
    if info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
        bail!("cache path is a directory or reparse point");
    }
    if info.nNumberOfLinks != 1 {
        bail!("cache file must have exactly one hard link");
    }
    if require_read_only && info.dwFileAttributes & FILE_ATTRIBUTE_READONLY == 0 {
        bail!("published cache image is not marked read-only");
    }
    let size = (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow);
    if expected_size.is_some_and(|expected| expected != size) {
        bail!("cache file size mismatch: expected {expected_size:?}, found {size}");
    }
    Ok(())
}

fn handle_info(file: &File) -> Result<BY_HANDLE_FILE_INFORMATION> {
    let mut info = unsafe { std::mem::zeroed::<BY_HANDLE_FILE_INFORMATION>() };
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, &mut info) };
    if ok == 0 {
        Err(io::Error::last_os_error()).context("failed to inspect cache file handle")
    } else {
        Ok(info)
    }
}

fn ensure_parent_directory_no_reparse(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("cache path has no parent: {}", path.display()))?;
    ensure_directory_no_reparse(parent)
}

fn ensure_directory_no_reparse(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect cache directory {}", path.display()))?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        bail!(
            "cache directory is not a no-follow directory: {}",
            path.display()
        );
    }
    Ok(())
}

fn validate_object_directory(path: &Path) -> Result<()> {
    let mut names = fs::read_dir(path)
        .with_context(|| format!("failed to enumerate cache object {}", path.display()))?
        .map(|entry| {
            entry
                .map(|entry| entry.file_name())
                .with_context(|| format!("failed to inspect cache object {}", path.display()))
        })
        .collect::<Result<Vec<_>>>()?;
    names.sort();
    let mut expected = vec![
        OsStr::new(IMAGE_NAME).to_os_string(),
        OsStr::new(MANIFEST_NAME).to_os_string(),
    ];
    expected.sort();
    if names != expected {
        bail!("cache object contains unexpected or missing files");
    }
    Ok(())
}

fn set_read_only(path: &Path, read_only: bool) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect cache image {}", path.display()))?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        bail!("refusing to change attributes on a cache reparse point");
    }
    let mut attributes = metadata.file_attributes();
    if read_only {
        attributes |= FILE_ATTRIBUTE_READONLY;
    } else {
        attributes &= !FILE_ATTRIBUTE_READONLY;
    }
    let wide = wide_path(path);
    let ok = unsafe { SetFileAttributesW(wide.as_ptr(), attributes) };
    if ok == 0 {
        Err(io::Error::last_os_error())
            .with_context(|| format!("failed to set cache image attributes {}", path.display()))
    } else {
        Ok(())
    }
}

fn update_access_marker(path: &Path) -> Result<()> {
    ensure_parent_directory_no_reparse(path)?;
    let mut file = open_windows_file(
        path,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
    )?;
    validate_regular_handle(&file, None, false)?;
    file.set_len(0)?;
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    file.write_all(seconds.to_string().as_bytes())?;
    file.sync_all()?;
    Ok(())
}

fn remove_tree_secure(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect cache cleanup path {}", path.display()))?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        bail!(
            "refusing to traverse cache reparse point {}",
            path.display()
        );
    }
    if metadata.is_dir() {
        for entry in fs::read_dir(path)
            .with_context(|| format!("failed to enumerate cache directory {}", path.display()))?
        {
            remove_tree_secure(&entry?.path())?;
        }
        fs::remove_dir(path)
            .with_context(|| format!("failed to remove cache directory {}", path.display()))?;
    } else {
        if metadata.file_attributes() & FILE_ATTRIBUTE_READONLY != 0 {
            set_read_only(path, false)?;
        }
        fs::remove_file(path)
            .with_context(|| format!("failed to remove cache file {}", path.display()))?;
    }
    Ok(())
}

fn remove_object_secure(path: &Path) -> Result<()> {
    ensure_directory_no_reparse(path)?;
    let manifest = path.join(MANIFEST_NAME);
    if manifest.exists() {
        remove_file_secure(&manifest)?;
    }
    remove_tree_secure(path)
}

fn remove_file_secure(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect cache file {}", path.display()))?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || metadata.is_dir() {
        bail!(
            "refusing to remove non-regular cache file {}",
            path.display()
        );
    }
    if metadata.file_attributes() & FILE_ATTRIBUTE_READONLY != 0 {
        set_read_only(path, false)?;
    }
    fs::remove_file(path).with_context(|| format!("failed to remove cache file {}", path.display()))
}

fn wide_path(path: &Path) -> Vec<u16> {
    OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows_x86_64::fs::{WindowsMountDescriptor, WindowsMountSnapshotEntry};
    use lsb_proto::MountSnapshotKey;
    use std::fs::OpenOptions;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn sizing_covers_metadata_heavy_mounts_and_enforces_limits() {
        for (files, directories, bytes) in [(2000, 1, 0), (2000, 1, 2000 * 1024), (0, 2001, 0)] {
            let snapshot = synthetic_snapshot(files, directories, bytes);
            let sizing = mount_cache_image_sizing(&snapshot, DEFAULT_MAX_IMAGE_SIZE).unwrap();
            assert!(sizing.virtual_size >= MIN_IMAGE_SIZE);
            assert_eq!(sizing.virtual_size % IMAGE_ALIGNMENT, 0);
            assert!(sizing.inode_count >= 2 * (files + directories + 1024));
        }

        let huge = synthetic_snapshot(1, 1, DEFAULT_MAX_IMAGE_SIZE);
        assert!(mount_cache_image_sizing(&huge, DEFAULT_MAX_IMAGE_SIZE).is_err());
    }

    #[test]
    fn lock_contention_is_nonblocking_and_shared_locks_coexist() {
        let root = temp_dir("locking");
        fs::create_dir_all(&root).unwrap();
        let path = root.join("digest.lock");
        let first = DigestLock::try_acquire(&path, false).unwrap().unwrap();
        let second = DigestLock::try_acquire(&path, false).unwrap().unwrap();
        assert!(DigestLock::try_acquire(&path, true).unwrap().is_none());
        drop(first);
        drop(second);
        assert!(DigestLock::try_acquire(&path, true).unwrap().is_some());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn staging_image_is_sparse_sized_and_no_follow() {
        let root = temp_dir("sparse");
        fs::create_dir_all(&root).unwrap();
        let path = root.join(IMAGE_NAME);
        create_staging_image(&path, MIN_IMAGE_SIZE, DEFAULT_NONSPARSE_MAX).unwrap();
        let image = open_validated_image(&path, MIN_IMAGE_SIZE, false).unwrap();
        assert_eq!(handle_info(&image.file).unwrap().nNumberOfLinks, 1);
        drop(image);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn manifest_validation_rejects_path_and_raw_digest_mismatches() {
        let digest = "01".repeat(32);
        let mut manifest = MountCacheManifest {
            schema_version: CACHE_SCHEMA_VERSION,
            cache_key_abi: lsb_proto::MOUNT_CACHE_KEY_ABI_VERSION,
            source_tree_digest: digest.clone(),
            raw_image_blake3: "02".repeat(32),
            image_format: MountCacheImageFormat::RawExt4,
            virtual_size: MIN_IMAGE_SIZE,
            source_bytes: 0,
            file_count: 1,
            directory_count: 1,
            inode_count: 8192,
            created_unix_seconds: 1,
        };
        assert!(validate_manifest(&manifest, &digest, DEFAULT_MAX_IMAGE_SIZE).is_ok());
        manifest.source_tree_digest = "03".repeat(32);
        assert!(validate_manifest(&manifest, &digest, DEFAULT_MAX_IMAGE_SIZE).is_err());
        manifest.source_tree_digest = digest.clone();
        manifest.raw_image_blake3 = "AA".repeat(32);
        assert!(validate_manifest(&manifest, &digest, DEFAULT_MAX_IMAGE_SIZE).is_err());
    }

    #[test]
    fn post_stop_publication_rejects_mutation_and_publishes_atomically() {
        let root = temp_dir("publication");
        let cache = WindowsMountCache::new(&root).unwrap();
        let snapshot = synthetic_snapshot(1, 1, 4);
        let WindowsMountCacheSelection::Build(build) = cache.select(&snapshot).unwrap() else {
            panic!("first selection should build");
        };
        let digest = hash_path(&build.image_path, build.virtual_size);
        OpenOptions::new()
            .write(true)
            .open(&build.image_path)
            .unwrap()
            .write_all(b"x")
            .unwrap();
        assert!(build.publish(&digest).is_err());
        assert!(!cache
            .layout
            .objects
            .join(snapshot.key.to_hex())
            .join(MANIFEST_NAME)
            .exists());

        let WindowsMountCacheSelection::Build(build) = cache.select(&snapshot).unwrap() else {
            panic!("discarded mutation should rebuild");
        };
        let digest = hash_path(&build.image_path, build.virtual_size);
        let object_image = build.publish(&digest).unwrap();
        assert!(object_image.exists());
        assert!(object_image.parent().unwrap().join(MANIFEST_NAME).exists());
        let _ = remove_tree_secure(&cache.layout.root);
    }

    #[test]
    fn explicit_prune_skips_shared_hit_lock_then_removes_readonly_object() {
        let root = temp_dir("prune-lock");
        let cache = WindowsMountCache::new(&root).unwrap();
        let snapshot = synthetic_snapshot(1, 1, 4);
        publish_zero_object(&cache, &snapshot);
        let WindowsMountCacheSelection::Hit(hit) = cache.select(&snapshot).unwrap() else {
            panic!("published object should be a hit");
        };

        let active_report = cache.prune_all().unwrap();
        assert_eq!(active_report.removed_objects, 0);
        assert_eq!(active_report.skipped_locked, 1);
        assert_eq!(active_report.objects_after, 1);
        drop(hit);

        let pruned = cache.prune_all().unwrap();
        assert_eq!(pruned.removed_objects, 1);
        assert_eq!(pruned.objects_after, 0);
        assert!(!cache.layout.objects.join(snapshot.key.to_hex()).exists());
        let _ = remove_tree_secure(&cache.layout.root);
    }

    #[test]
    fn maintenance_enforces_object_count_quota_oldest_first() {
        let root = temp_dir("eviction");
        let limits = WindowsMountCacheLimits {
            max_objects: 1,
            max_total_logical_size: DEFAULT_TOTAL_LOGICAL_LIMIT,
            ..WindowsMountCacheLimits::default()
        };
        let cache = WindowsMountCache::with_limits(&root, limits).unwrap();
        let first = synthetic_snapshot(1, 1, 4);
        let mut second = synthetic_snapshot(1, 1, 4);
        second.key = MountSnapshotKey::from_bytes([8; 32]);
        publish_zero_object(&cache, &first);
        publish_zero_object(&cache, &second);

        let report = cache.maintain().unwrap();
        assert_eq!(report.removed_objects, 1);
        assert_eq!(report.objects_after, 1);
        assert_eq!(report.logical_bytes_after, MIN_IMAGE_SIZE);
        cache.prune_all().unwrap();
        let _ = remove_tree_secure(&cache.layout.root);
    }

    fn hash_path(path: &Path, size: u64) -> String {
        let file = File::open(path).unwrap();
        hash_exact(&file, size).unwrap()
    }

    fn publish_zero_object(cache: &WindowsMountCache, snapshot: &WindowsMountSnapshot) {
        let WindowsMountCacheSelection::Build(build) = cache.select(snapshot).unwrap() else {
            panic!("new object should select a build");
        };
        let digest = hash_path(&build.image_path, build.virtual_size);
        build.publish(&digest).unwrap();
    }

    fn synthetic_snapshot(
        file_count: u64,
        directory_count: u64,
        logical_bytes: u64,
    ) -> WindowsMountSnapshot {
        WindowsMountSnapshot {
            descriptor: WindowsMountDescriptor {
                tag: "mount0".to_string(),
                host_root: PathBuf::from(r"C:\fixture"),
                guest_source: "/tmp/lsb/mounts/mount0/source".to_string(),
                guest_target: "/workspace".to_string(),
            },
            entries: Vec::<WindowsMountSnapshotEntry>::new(),
            key: MountSnapshotKey::from_bytes([7; 32]),
            file_count,
            directory_count,
            logical_bytes,
        }
    }

    fn temp_dir(label: &str) -> PathBuf {
        let nonce = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "lsb-mount-cache-{label}-{}-{nonce}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        root
    }
}
