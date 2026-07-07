use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

pub const WINDOWS_CHECKPOINT_SCHEMA_VERSION: u32 = 1;
const CHECKPOINT_QCOW2_EXT: &str = "qcow2";
const CHECKPOINT_METADATA_EXT: &str = "json";
const LEGACY_EXT4_EXT: &str = "ext4";
const CAS_INDEX_EXT: &str = "idx";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsCheckpointStore {
    data_dir: PathBuf,
    checkpoints_dir: PathBuf,
}

impl WindowsCheckpointStore {
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        let data_dir = data_dir.into();
        let checkpoints_dir = data_dir.join("checkpoints");
        Self {
            data_dir,
            checkpoints_dir,
        }
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn checkpoints_dir(&self) -> &Path {
        &self.checkpoints_dir
    }

    pub fn checkpoint_paths(&self, name: &str) -> WindowsCheckpointPaths {
        WindowsCheckpointPaths {
            name: name.to_string(),
            qcow2_path: self
                .checkpoints_dir
                .join(format!("{name}.{CHECKPOINT_QCOW2_EXT}")),
            metadata_path: self
                .checkpoints_dir
                .join(format!("{name}.{CHECKPOINT_METADATA_EXT}")),
            legacy_ext4_path: self
                .checkpoints_dir
                .join(format!("{name}.{LEGACY_EXT4_EXT}")),
            cas_index_path: self.checkpoints_dir.join(format!("{name}.{CAS_INDEX_EXT}")),
        }
    }

    pub fn checkpoint_exists(&self, name: &str) -> bool {
        let paths = self.checkpoint_paths(name);
        paths.qcow2_path.exists()
            || paths.metadata_path.exists()
            || paths.legacy_ext4_path.exists()
            || paths.cas_index_path.exists()
    }

    pub fn resolve_source(
        &self,
        rootfs_path: impl AsRef<Path>,
        from: Option<&str>,
        base_version: Option<&str>,
        custom_rootfs: bool,
    ) -> Result<WindowsCheckpointSource, WindowsCheckpointError> {
        if from.is_some() && base_version.is_some() {
            return Err(WindowsCheckpointError::UnsupportedMode {
                mode: "checkpoint plus base version".to_string(),
                detail:
                    "Windows checkpoint restore accepts either `from` or `base_version`, not both"
                        .to_string(),
            });
        }

        match from {
            Some(name) => self.resolve_checkpoint_source(name),
            None => self.resolve_base_source(rootfs_path.as_ref(), base_version, custom_rootfs),
        }
    }

    pub fn create_active_overlay(
        &self,
        source: &WindowsCheckpointSource,
        destination: impl AsRef<Path>,
        virtual_size_bytes: u64,
    ) -> Result<(), WindowsCheckpointError> {
        let destination = destination.as_ref();
        if virtual_size_bytes < source.virtual_size_bytes {
            return Err(WindowsCheckpointError::DiskSizeTooSmall {
                requested_bytes: virtual_size_bytes,
                source_bytes: source.virtual_size_bytes,
            });
        }

        let qemu_img = QemuImg::discover_for_data_dir(&self.data_dir)?;
        let tmp = temp_path_for(destination, "create");
        remove_file_if_exists(&tmp)?;
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(|source| WindowsCheckpointError::Io {
                path: parent.to_path_buf(),
                operation: "create active overlay directory",
                source,
            })?;
        }

        let invocation = qemu_img.create_overlay_invocation(
            source.path(),
            source.disk_format,
            &tmp,
            virtual_size_bytes,
        );
        let result = run_qemu_img(&invocation).and_then(|_| {
            install_temp_file(&tmp, destination, true)?;
            Ok(())
        });
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result
    }

    pub fn save_flat_checkpoint(
        &self,
        name: &str,
        active_disk: impl AsRef<Path>,
        source: &WindowsCheckpointSource,
        virtual_size_bytes: u64,
    ) -> Result<WindowsCheckpointMetadata, WindowsCheckpointError> {
        validate_checkpoint_name(name)?;
        let paths = self.checkpoint_paths(name);
        if checkpoint_artifact_exists(&paths) {
            return Err(WindowsCheckpointError::AlreadyExists {
                name: name.to_string(),
            });
        }

        fs::create_dir_all(&self.checkpoints_dir).map_err(|source| WindowsCheckpointError::Io {
            path: self.checkpoints_dir.clone(),
            operation: "create checkpoints directory",
            source,
        })?;

        let active_disk = active_disk.as_ref();
        ensure_file(active_disk, "active Windows checkpoint disk")?;
        let qemu_img = QemuImg::discover_for_data_dir(&self.data_dir)?;
        let tmp_disk = temp_path_for(&paths.qcow2_path, "convert");
        let tmp_metadata = temp_path_for(&paths.metadata_path, "metadata");
        let _ = fs::remove_file(&tmp_disk);
        let _ = fs::remove_file(&tmp_metadata);

        let metadata =
            WindowsCheckpointMetadata::new(name, source, virtual_size_bytes, unix_timestamp()?);
        let invocation = qemu_img.convert_flat_invocation(active_disk, &tmp_disk);
        let mut disk_installed = false;

        let result = (|| {
            run_qemu_img(&invocation)?;
            write_metadata_path(&tmp_metadata, &metadata)?;
            install_new_checkpoint_file(&tmp_disk, &paths.qcow2_path)?;
            disk_installed = true;
            install_new_checkpoint_file(&tmp_metadata, &paths.metadata_path)?;
            Ok(metadata)
        })();

        if result.is_err() {
            let _ = fs::remove_file(&tmp_disk);
            let _ = fs::remove_file(&tmp_metadata);
            if disk_installed {
                let _ = fs::remove_file(&paths.qcow2_path);
            }
        }

        result
    }

    pub fn list_checkpoints(&self) -> Result<Vec<WindowsCheckpointEntry>, WindowsCheckpointError> {
        let entries = match fs::read_dir(&self.checkpoints_dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(source) => {
                return Err(WindowsCheckpointError::Io {
                    path: self.checkpoints_dir.clone(),
                    operation: "read checkpoints directory",
                    source,
                })
            }
        };

        let mut checkpoints = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|source| WindowsCheckpointError::Io {
                path: self.checkpoints_dir.clone(),
                operation: "read checkpoint directory entry",
                source,
            })?;
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some(CHECKPOINT_METADATA_EXT) {
                continue;
            }
            let Some(name) = path.file_stem().and_then(|stem| stem.to_str()) else {
                continue;
            };
            let paths = self.checkpoint_paths(name);
            if !paths.qcow2_path.is_file() {
                continue;
            }
            let metadata = read_metadata_path(&paths.metadata_path)?;
            let disk_metadata =
                fs::metadata(&paths.qcow2_path).map_err(|source| WindowsCheckpointError::Io {
                    path: paths.qcow2_path.clone(),
                    operation: "stat checkpoint disk",
                    source,
                })?;
            let modified =
                disk_metadata
                    .modified()
                    .map_err(|source| WindowsCheckpointError::Io {
                        path: paths.qcow2_path.clone(),
                        operation: "read checkpoint mtime",
                        source,
                    })?;
            checkpoints.push(WindowsCheckpointEntry {
                name: name.to_string(),
                disk_path: paths.qcow2_path,
                metadata_path: paths.metadata_path,
                metadata,
                disk_bytes: disk_metadata.len(),
                modified,
            });
        }
        checkpoints.sort_by_key(|entry| entry.modified);
        Ok(checkpoints)
    }

    pub fn delete_checkpoint(&self, name: &str) -> Result<bool, WindowsCheckpointError> {
        validate_checkpoint_name(name)?;
        let paths = self.checkpoint_paths(name);
        let mut removed = false;
        for path in [
            &paths.metadata_path,
            &paths.qcow2_path,
            &paths.legacy_ext4_path,
            &paths.cas_index_path,
        ] {
            match fs::remove_file(path) {
                Ok(()) => removed = true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(WindowsCheckpointError::Io {
                        path: path.clone(),
                        operation: "delete checkpoint file",
                        source,
                    })
                }
            }
        }
        Ok(removed)
    }

    fn resolve_checkpoint_source(
        &self,
        name: &str,
    ) -> Result<WindowsCheckpointSource, WindowsCheckpointError> {
        validate_checkpoint_name(name)?;
        let paths = self.checkpoint_paths(name);
        if paths.cas_index_path.exists() {
            return Err(WindowsCheckpointError::UnsupportedMode {
                mode: "CAS/NBD checkpoint index".to_string(),
                detail: format!(
                    "checkpoint '{name}' is stored as '{}', but Windows uses qcow2/raw disk artifacts and does not support Unix-socket NBD/CAS restore",
                    paths.cas_index_path.display()
                ),
            });
        }

        if paths.metadata_path.exists() || paths.qcow2_path.exists() {
            if !paths.metadata_path.is_file() || !paths.qcow2_path.is_file() {
                return Err(WindowsCheckpointError::IncompleteCheckpoint {
                    name: name.to_string(),
                    detail: format!(
                        "expected both '{}' and '{}'",
                        paths.qcow2_path.display(),
                        paths.metadata_path.display()
                    ),
                });
            }
            let metadata = read_metadata_path(&paths.metadata_path)?;
            if metadata.schema_version != WINDOWS_CHECKPOINT_SCHEMA_VERSION {
                return Err(WindowsCheckpointError::UnsupportedMode {
                    mode: "Windows checkpoint metadata version".to_string(),
                    detail: format!(
                        "checkpoint '{name}' uses schema version {}, but this build supports version {}",
                        metadata.schema_version, WINDOWS_CHECKPOINT_SCHEMA_VERSION
                    ),
                });
            }
            let virtual_size_bytes = metadata.virtual_size_bytes;
            return Ok(WindowsCheckpointSource {
                kind: WindowsCheckpointSourceKind::Checkpoint {
                    name: name.to_string(),
                    metadata,
                },
                path: paths.qcow2_path,
                disk_format: WindowsDiskImageFormat::Qcow2,
                virtual_size_bytes,
            });
        }

        if paths.legacy_ext4_path.is_file() {
            let virtual_size_bytes = file_size(&paths.legacy_ext4_path)?;
            return Ok(WindowsCheckpointSource {
                kind: WindowsCheckpointSourceKind::LegacyExt4Checkpoint {
                    name: name.to_string(),
                },
                path: paths.legacy_ext4_path,
                disk_format: WindowsDiskImageFormat::Raw,
                virtual_size_bytes,
            });
        }

        Err(WindowsCheckpointError::NotFound {
            name: name.to_string(),
        })
    }

    fn resolve_base_source(
        &self,
        rootfs_path: &Path,
        base_version: Option<&str>,
        custom_rootfs: bool,
    ) -> Result<WindowsCheckpointSource, WindowsCheckpointError> {
        ensure_file(rootfs_path, "base rootfs")?;
        let (path, version) = if custom_rootfs {
            (rootfs_path.to_path_buf(), None)
        } else if let Some(version) = base_version {
            validate_base_version(version)?;
            match crate::resolve_base_version(path_to_str(&self.data_dir)?, version) {
                Ok(record) => (PathBuf::from(record.rootfs_path), Some(version.to_string())),
                Err(error) => {
                    let current = crate::read_data_dir_version(path_to_str(&self.data_dir)?).ok();
                    if current.as_deref() == Some(version) {
                        (rootfs_path.to_path_buf(), Some(version.to_string()))
                    } else {
                        return Err(WindowsCheckpointError::BaseVersionUnavailable {
                            version: version.to_string(),
                            detail: error.to_string(),
                        });
                    }
                }
            }
        } else {
            let version = crate::read_data_dir_version(path_to_str(&self.data_dir)?).ok();
            (rootfs_path.to_path_buf(), version)
        };

        ensure_file(&path, "base rootfs")?;
        let virtual_size_bytes = file_size(&path)?;
        Ok(WindowsCheckpointSource {
            kind: WindowsCheckpointSourceKind::BaseRootfs {
                base_version: version,
            },
            path,
            disk_format: WindowsDiskImageFormat::Raw,
            virtual_size_bytes,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsCheckpointPaths {
    pub name: String,
    pub qcow2_path: PathBuf,
    pub metadata_path: PathBuf,
    pub legacy_ext4_path: PathBuf,
    pub cas_index_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsCheckpointSource {
    pub kind: WindowsCheckpointSourceKind,
    pub path: PathBuf,
    pub disk_format: WindowsDiskImageFormat,
    pub virtual_size_bytes: u64,
}

impl WindowsCheckpointSource {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn base_version(&self) -> Option<&str> {
        match &self.kind {
            WindowsCheckpointSourceKind::BaseRootfs { base_version } => base_version.as_deref(),
            WindowsCheckpointSourceKind::Checkpoint { metadata, .. } => {
                metadata.base_version.as_deref()
            }
            WindowsCheckpointSourceKind::LegacyExt4Checkpoint { .. } => None,
        }
    }

    pub fn parent_checkpoint(&self) -> Option<&str> {
        match &self.kind {
            WindowsCheckpointSourceKind::Checkpoint { name, .. }
            | WindowsCheckpointSourceKind::LegacyExt4Checkpoint { name } => Some(name),
            WindowsCheckpointSourceKind::BaseRootfs { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WindowsCheckpointSourceKind {
    BaseRootfs {
        base_version: Option<String>,
    },
    Checkpoint {
        name: String,
        metadata: WindowsCheckpointMetadata,
    },
    LegacyExt4Checkpoint {
        name: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsCheckpointEntry {
    pub name: String,
    pub disk_path: PathBuf,
    pub metadata_path: PathBuf,
    pub metadata: WindowsCheckpointMetadata,
    pub disk_bytes: u64,
    pub modified: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsCheckpointMetadata {
    pub schema_version: u32,
    pub name: String,
    pub disk_format: WindowsDiskImageFormat,
    pub layout: WindowsCheckpointLayout,
    pub source: WindowsCheckpointSourceMetadata,
    pub base_version: Option<String>,
    pub parent: Option<String>,
    pub created_unix_secs: u64,
    pub virtual_size_bytes: u64,
}

impl WindowsCheckpointMetadata {
    pub fn new(
        name: &str,
        source: &WindowsCheckpointSource,
        virtual_size_bytes: u64,
        created_unix_secs: u64,
    ) -> Self {
        Self {
            schema_version: WINDOWS_CHECKPOINT_SCHEMA_VERSION,
            name: name.to_string(),
            disk_format: WindowsDiskImageFormat::Qcow2,
            layout: WindowsCheckpointLayout::Flat,
            source: WindowsCheckpointSourceMetadata::from_source(source),
            base_version: source.base_version().map(str::to_string),
            parent: source.parent_checkpoint().map(str::to_string),
            created_unix_secs,
            virtual_size_bytes,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsDiskImageFormat {
    Raw,
    Qcow2,
}

impl WindowsDiskImageFormat {
    pub fn as_qemu_img_arg(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Qcow2 => "qcow2",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsCheckpointLayout {
    Flat,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsCheckpointSourceMetadata {
    pub kind: WindowsCheckpointSourceMetadataKind,
    pub name: Option<String>,
    pub disk_format: WindowsDiskImageFormat,
}

impl WindowsCheckpointSourceMetadata {
    fn from_source(source: &WindowsCheckpointSource) -> Self {
        match &source.kind {
            WindowsCheckpointSourceKind::BaseRootfs { .. } => Self {
                kind: WindowsCheckpointSourceMetadataKind::BaseRootfs,
                name: None,
                disk_format: source.disk_format,
            },
            WindowsCheckpointSourceKind::Checkpoint { name, .. } => Self {
                kind: WindowsCheckpointSourceMetadataKind::Checkpoint,
                name: Some(name.clone()),
                disk_format: source.disk_format,
            },
            WindowsCheckpointSourceKind::LegacyExt4Checkpoint { name } => Self {
                kind: WindowsCheckpointSourceMetadataKind::LegacyExt4Checkpoint,
                name: Some(name.clone()),
                disk_format: source.disk_format,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsCheckpointSourceMetadataKind {
    BaseRootfs,
    Checkpoint,
    LegacyExt4Checkpoint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QemuImg {
    program: PathBuf,
}

impl QemuImg {
    pub fn discover() -> Result<Self, WindowsCheckpointError> {
        Self::discover_for_data_dir(Path::new(&lsb_platform::default_data_dir()))
    }

    pub fn discover_for_data_dir(data_dir: &Path) -> Result<Self, WindowsCheckpointError> {
        Self::discover_with_configured_qemu(data_dir, None)
    }

    pub fn discover_with_configured_qemu(
        data_dir: &Path,
        configured_qemu: Option<&Path>,
    ) -> Result<Self, WindowsCheckpointError> {
        if let Some(path) = std::env::var_os("LSB_QEMU_IMG") {
            let path = PathBuf::from(path);
            if path.is_file() {
                return Ok(Self { program: path });
            }
            return Err(WindowsCheckpointError::QemuImgNotFound {
                detail: format!(
                    "LSB_QEMU_IMG points to '{}', which is not an existing file",
                    path.display()
                ),
            });
        }

        if let Some(qemu_path) = std::env::var_os("LSB_QEMU") {
            let sibling = PathBuf::from(qemu_path).with_file_name(qemu_img_file_name());
            if sibling.is_file() {
                return Ok(Self { program: sibling });
            }
        }

        if let Some(qemu_path) = configured_qemu {
            let sibling = qemu_path.with_file_name(qemu_img_file_name());
            if sibling.is_file() {
                return Ok(Self { program: sibling });
            }
        }

        if let Some(program) = managed_qemu_img(data_dir) {
            return Ok(Self { program });
        }

        let default_data_dir = PathBuf::from(lsb_platform::default_data_dir());
        if default_data_dir.as_path() != data_dir {
            if let Some(program) = managed_qemu_img(&default_data_dir) {
                return Ok(Self { program });
            }
        }

        let path_entries = std::env::var_os("PATH")
            .map(|value| std::env::split_paths(&value).collect::<Vec<_>>())
            .unwrap_or_default();
        for entry in &path_entries {
            let candidate = entry.join(qemu_img_file_name());
            if candidate.is_file() {
                return Ok(Self { program: candidate });
            }
        }

        Err(WindowsCheckpointError::QemuImgNotFound {
            detail: format!(
                "{} was not found via LSB_QEMU_IMG, next to LSB_QEMU, next to configured QEMU, managed QEMU in the sandbox data dir, managed QEMU in the default data dir, or in {} PATH entries",
                qemu_img_file_name(),
                path_entries.len()
            ),
        })
    }

    pub fn from_program(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
        }
    }

    pub fn program(&self) -> &Path {
        &self.program
    }

    pub fn create_overlay_invocation(
        &self,
        backing: &Path,
        backing_format: WindowsDiskImageFormat,
        destination: &Path,
        virtual_size_bytes: u64,
    ) -> QemuImgInvocation {
        QemuImgInvocation {
            program: self.program.clone(),
            args: vec![
                OsString::from("create"),
                OsString::from("-f"),
                OsString::from("qcow2"),
                OsString::from("-F"),
                OsString::from(backing_format.as_qemu_img_arg()),
                OsString::from("-b"),
                backing.as_os_str().to_owned(),
                destination.as_os_str().to_owned(),
                OsString::from(virtual_size_bytes.to_string()),
            ],
        }
    }

    pub fn convert_flat_invocation(&self, source: &Path, destination: &Path) -> QemuImgInvocation {
        QemuImgInvocation {
            program: self.program.clone(),
            args: vec![
                OsString::from("convert"),
                OsString::from("-f"),
                OsString::from("qcow2"),
                OsString::from("-O"),
                OsString::from("qcow2"),
                source.as_os_str().to_owned(),
                destination.as_os_str().to_owned(),
            ],
        }
    }
}

fn managed_qemu_img(data_dir: &Path) -> Option<PathBuf> {
    lsb_platform::windows_x86_64::host_tools::active_managed_qemu(data_dir)
        .and_then(|managed| managed.qemu_img.is_file().then_some(managed.qemu_img))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QemuImgInvocation {
    pub program: PathBuf,
    pub args: Vec<OsString>,
}

#[derive(Debug)]
pub enum WindowsCheckpointError {
    InvalidName {
        name: String,
        reason: String,
    },
    NotFound {
        name: String,
    },
    AlreadyExists {
        name: String,
    },
    IncompleteCheckpoint {
        name: String,
        detail: String,
    },
    UnsupportedMode {
        mode: String,
        detail: String,
    },
    BaseVersionUnavailable {
        version: String,
        detail: String,
    },
    DiskSizeTooSmall {
        requested_bytes: u64,
        source_bytes: u64,
    },
    QemuImgNotFound {
        detail: String,
    },
    QemuImgFailed {
        program: PathBuf,
        args: Vec<String>,
        status: String,
        stderr: String,
    },
    Io {
        path: PathBuf,
        operation: &'static str,
        source: std::io::Error,
    },
    Json {
        path: PathBuf,
        operation: &'static str,
        source: serde_json::Error,
    },
    PathNotUtf8 {
        path: PathBuf,
    },
    Time {
        detail: String,
    },
}

impl fmt::Display for WindowsCheckpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName { name, reason } => {
                write!(f, "invalid Windows checkpoint name '{name}': {reason}")
            }
            Self::NotFound { name } => write!(f, "Windows checkpoint '{name}' not found"),
            Self::AlreadyExists { name } => {
                write!(f, "Windows checkpoint '{name}' already exists")
            }
            Self::IncompleteCheckpoint { name, detail } => write!(
                f,
                "Windows checkpoint '{name}' is incomplete and cannot be restored: {detail}. Delete it and recreate the checkpoint"
            ),
            Self::UnsupportedMode { mode, detail } => {
                write!(f, "unsupported Windows checkpoint mode '{mode}': {detail}")
            }
            Self::BaseVersionUnavailable { version, detail } => write!(
                f,
                "Windows checkpoint base version '{version}' is unavailable: {detail}"
            ),
            Self::DiskSizeTooSmall {
                requested_bytes,
                source_bytes,
            } => write!(
                f,
                "requested Windows checkpoint disk size {}MB is smaller than the source image {}MB",
                requested_bytes / 1024 / 1024,
                source_bytes / 1024 / 1024
            ),
            Self::QemuImgNotFound { detail } => write!(
                f,
                "qemu-img.exe is required for the Windows checkpoint/store backend but was not found: {detail}. Run `lsb init` to install managed QEMU host tools or set LSB_QEMU_IMG"
            ),
            Self::QemuImgFailed {
                program,
                args,
                status,
                stderr,
            } => write!(
                f,
                "qemu-img command '{}' {:?} failed with {status}: {}",
                program.display(),
                args,
                empty_as_placeholder(stderr)
            ),
            Self::Io {
                path,
                operation,
                source,
            } => write!(
                f,
                "failed to {operation} for Windows checkpoint path '{}': {source}",
                path.display()
            ),
            Self::Json {
                path,
                operation,
                source,
            } => write!(
                f,
                "failed to {operation} Windows checkpoint metadata '{}': {source}",
                path.display()
            ),
            Self::PathNotUtf8 { path } => write!(
                f,
                "Windows checkpoint path is not valid UTF-8: '{}'",
                path.display()
            ),
            Self::Time { detail } => write!(f, "failed to timestamp Windows checkpoint: {detail}"),
        }
    }
}

impl std::error::Error for WindowsCheckpointError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Json { source, .. } => Some(source),
            _ => None,
        }
    }
}

fn run_qemu_img(invocation: &QemuImgInvocation) -> Result<(), WindowsCheckpointError> {
    let output = Command::new(&invocation.program)
        .args(&invocation.args)
        .output()
        .map_err(|source| WindowsCheckpointError::Io {
            path: invocation.program.clone(),
            operation: "run qemu-img",
            source,
        })?;
    if output.status.success() {
        return Ok(());
    }
    Err(WindowsCheckpointError::QemuImgFailed {
        program: invocation.program.clone(),
        args: invocation
            .args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect(),
        status: output
            .status
            .code()
            .map(|code| format!("exit code {code}"))
            .unwrap_or_else(|| "terminated without exit code".to_string()),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
    })
}

fn qemu_img_file_name() -> &'static str {
    if cfg!(windows) {
        "qemu-img.exe"
    } else {
        "qemu-img"
    }
}

fn validate_checkpoint_name(name: &str) -> Result<(), WindowsCheckpointError> {
    if name.is_empty() {
        return Err(WindowsCheckpointError::InvalidName {
            name: name.to_string(),
            reason: "checkpoint name cannot be empty".to_string(),
        });
    }
    if name.contains('/') || name.contains('\\') || name.contains('\0') || name.contains("..") {
        return Err(WindowsCheckpointError::InvalidName {
            name: name.to_string(),
            reason: format!("invalid checkpoint name: '{name}'"),
        });
    }
    Ok(())
}

fn validate_base_version(version: &str) -> Result<(), WindowsCheckpointError> {
    if version.is_empty()
        || version.contains('/')
        || version.contains('\\')
        || version.contains('\0')
        || version.contains("..")
    {
        return Err(WindowsCheckpointError::UnsupportedMode {
            mode: "base version".to_string(),
            detail: format!("invalid base version '{version}'"),
        });
    }
    Ok(())
}

fn ensure_file(path: &Path, label: &'static str) -> Result<(), WindowsCheckpointError> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(_) => Err(WindowsCheckpointError::Io {
            path: path.to_path_buf(),
            operation: label,
            source: std::io::Error::new(std::io::ErrorKind::InvalidInput, "path is not a file"),
        }),
        Err(source) => Err(WindowsCheckpointError::Io {
            path: path.to_path_buf(),
            operation: label,
            source,
        }),
    }
}

fn file_size(path: &Path) -> Result<u64, WindowsCheckpointError> {
    Ok(fs::metadata(path)
        .map_err(|source| WindowsCheckpointError::Io {
            path: path.to_path_buf(),
            operation: "stat checkpoint source",
            source,
        })?
        .len())
}

fn read_metadata_path(path: &Path) -> Result<WindowsCheckpointMetadata, WindowsCheckpointError> {
    let contents = fs::read_to_string(path).map_err(|source| WindowsCheckpointError::Io {
        path: path.to_path_buf(),
        operation: "read checkpoint metadata",
        source,
    })?;
    serde_json::from_str(&contents).map_err(|source| WindowsCheckpointError::Json {
        path: path.to_path_buf(),
        operation: "parse",
        source,
    })
}

fn write_metadata_path(
    path: &Path,
    metadata: &WindowsCheckpointMetadata,
) -> Result<(), WindowsCheckpointError> {
    let contents =
        serde_json::to_string_pretty(metadata).map_err(|source| WindowsCheckpointError::Json {
            path: path.to_path_buf(),
            operation: "serialize",
            source,
        })?;
    fs::write(path, format!("{contents}\n")).map_err(|source| WindowsCheckpointError::Io {
        path: path.to_path_buf(),
        operation: "write checkpoint metadata",
        source,
    })
}

fn install_temp_file(
    tmp: &Path,
    destination: &Path,
    overwrite: bool,
) -> Result<(), WindowsCheckpointError> {
    if destination.exists() {
        if overwrite {
            fs::remove_file(destination).map_err(|source| WindowsCheckpointError::Io {
                path: destination.to_path_buf(),
                operation: "remove previous checkpoint file",
                source,
            })?;
        } else {
            return Err(WindowsCheckpointError::AlreadyExists {
                name: destination
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .unwrap_or("?")
                    .to_string(),
            });
        }
    }
    fs::rename(tmp, destination).map_err(|source| WindowsCheckpointError::Io {
        path: destination.to_path_buf(),
        operation: "install checkpoint file",
        source,
    })
}

fn install_new_checkpoint_file(
    tmp: &Path,
    destination: &Path,
) -> Result<(), WindowsCheckpointError> {
    if destination.exists() {
        return Err(WindowsCheckpointError::AlreadyExists {
            name: destination
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or("?")
                .to_string(),
        });
    }
    match fs::hard_link(tmp, destination) {
        Ok(()) => {
            let _ = fs::remove_file(tmp);
            Ok(())
        }
        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(WindowsCheckpointError::AlreadyExists {
                name: destination
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .unwrap_or("?")
                    .to_string(),
            })
        }
        Err(source) => Err(WindowsCheckpointError::Io {
            path: destination.to_path_buf(),
            operation: "install checkpoint file without replacing existing artifact",
            source,
        }),
    }
}

fn checkpoint_artifact_exists(paths: &WindowsCheckpointPaths) -> bool {
    paths.qcow2_path.exists()
        || paths.metadata_path.exists()
        || paths.legacy_ext4_path.exists()
        || paths.cas_index_path.exists()
}

fn remove_file_if_exists(path: &Path) -> Result<(), WindowsCheckpointError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(WindowsCheckpointError::Io {
            path: path.to_path_buf(),
            operation: "remove stale temporary checkpoint file",
            source,
        }),
    }
}

fn temp_path_for(path: &Path, label: &str) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("checkpoint");
    path.with_file_name(format!(".{file_name}.{label}.{}.tmp", std::process::id()))
}

fn path_to_str(path: &Path) -> Result<&str, WindowsCheckpointError> {
    path.to_str()
        .ok_or_else(|| WindowsCheckpointError::PathNotUtf8 {
            path: path.to_path_buf(),
        })
}

fn unix_timestamp() -> Result<u64, WindowsCheckpointError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| WindowsCheckpointError::Time {
            detail: error.to_string(),
        })?
        .as_secs())
}

fn empty_as_placeholder(value: &str) -> &str {
    if value.is_empty() {
        "<empty>"
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn store(root: &Path) -> WindowsCheckpointStore {
        WindowsCheckpointStore::new(root.join("data"))
    }

    fn base_source(root: &Path) -> WindowsCheckpointSource {
        WindowsCheckpointSource {
            kind: WindowsCheckpointSourceKind::BaseRootfs {
                base_version: Some("1.2.3".to_string()),
            },
            path: root.join("data/rootfs.ext4"),
            disk_format: WindowsDiskImageFormat::Raw,
            virtual_size_bytes: 4096,
        }
    }

    fn write_managed_qemu(data_dir: &Path) -> (PathBuf, PathBuf) {
        use lsb_platform::windows_x86_64::host_tools::{
            managed_qemu_package_metadata, managed_qemu_paths, ManagedQemuCurrent,
            MANAGED_QEMU_CURRENT_SCHEMA_VERSION, MANAGED_QEMU_MANIFEST_SCHEMA_VERSION,
        };

        let metadata = managed_qemu_package_metadata();
        let paths = managed_qemu_paths(data_dir);
        fs::create_dir_all(&paths.package_dir).expect("managed qemu dir");
        let qemu_system = paths.package_dir.join("qemu-system-x86_64.exe");
        let qemu_img = paths.package_dir.join("qemu-img.exe");
        let manifest = paths.package_dir.join("manifest.json");
        fs::write(&qemu_system, b"qemu system").expect("qemu system");
        fs::write(&qemu_img, b"qemu img").expect("qemu img");
        fs::write(
            &manifest,
            format!(
                r#"{{
                  "schema_version": {},
                  "package_version": "{}",
                  "qemu_version": "{}",
                  "lsb_version": "{}",
                  "platform": "{}",
                  "qemu_system_x86_64": "qemu-system-x86_64.exe",
                  "qemu_img": "qemu-img.exe",
                  "files": []
                }}"#,
                MANAGED_QEMU_MANIFEST_SCHEMA_VERSION,
                metadata.package_version,
                metadata.qemu_version,
                metadata.lsb_version,
                metadata.platform
            ),
        )
        .expect("manifest");
        fs::create_dir_all(&paths.qemu_dir).expect("qemu dir");
        fs::write(
            &paths.current_json,
            serde_json::to_string_pretty(&ManagedQemuCurrent {
                schema_version: MANAGED_QEMU_CURRENT_SCHEMA_VERSION,
                package_version: metadata.package_version.to_string(),
                artifact_url: metadata.artifact_url.to_string(),
                artifact_sha256: metadata.artifact_sha256.to_string(),
                installed_at_unix_secs: 1,
                qemu_system_x86_64: qemu_system.clone(),
                qemu_img: qemu_img.clone(),
                manifest,
            })
            .expect("current json"),
        )
        .expect("write current");
        (qemu_system, qemu_img)
    }

    fn with_env_lock<T>(f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let old_qemu_img = std::env::var_os("LSB_QEMU_IMG");
        let old_qemu = std::env::var_os("LSB_QEMU");
        let old_path = std::env::var_os("PATH");
        let old_home = std::env::var_os("HOME");
        let old_local_app_data = std::env::var_os("LOCALAPPDATA");
        let old_user_profile = std::env::var_os("USERPROFILE");
        let isolated_home = tempfile::tempdir().expect("isolated HOME");
        std::env::remove_var("LSB_QEMU_IMG");
        std::env::remove_var("LSB_QEMU");
        std::env::remove_var("PATH");
        std::env::remove_var("LOCALAPPDATA");
        std::env::remove_var("USERPROFILE");
        std::env::set_var("HOME", isolated_home.path());
        let result = f();
        restore_env("LSB_QEMU_IMG", old_qemu_img);
        restore_env("LSB_QEMU", old_qemu);
        restore_env("PATH", old_path);
        restore_env("HOME", old_home);
        restore_env("LOCALAPPDATA", old_local_app_data);
        restore_env("USERPROFILE", old_user_profile);
        result
    }

    fn restore_env(name: &str, value: Option<std::ffi::OsString>) {
        match value {
            Some(value) => std::env::set_var(name, value),
            None => std::env::remove_var(name),
        }
    }

    #[test]
    fn checkpoint_paths_are_deterministic_under_data_dir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = store(tmp.path());
        let paths = store.checkpoint_paths("dev");

        assert_eq!(
            paths.qcow2_path,
            tmp.path().join("data/checkpoints/dev.qcow2")
        );
        assert_eq!(
            paths.metadata_path,
            tmp.path().join("data/checkpoints/dev.json")
        );
        assert_eq!(
            paths.legacy_ext4_path,
            tmp.path().join("data/checkpoints/dev.ext4")
        );
        assert_eq!(
            paths.cas_index_path,
            tmp.path().join("data/checkpoints/dev.idx")
        );
    }

    #[test]
    fn qemu_img_create_overlay_invocation_uses_typed_args() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let qemu_img = QemuImg::from_program(tmp.path().join("qemu-img.exe"));
        let invocation = qemu_img.create_overlay_invocation(
            &tmp.path().join("rootfs.ext4"),
            WindowsDiskImageFormat::Raw,
            &tmp.path().join("instances/1/root.qcow2"),
            1024 * 1024,
        );

        let args = invocation
            .args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            args,
            [
                "create",
                "-f",
                "qcow2",
                "-F",
                "raw",
                "-b",
                tmp.path().join("rootfs.ext4").to_string_lossy().as_ref(),
                tmp.path()
                    .join("instances/1/root.qcow2")
                    .to_string_lossy()
                    .as_ref(),
                "1048576"
            ]
        );
    }

    #[test]
    fn qemu_img_convert_invocation_flattens_checkpoint() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let qemu_img = QemuImg::from_program(tmp.path().join("qemu-img.exe"));
        let invocation = qemu_img.convert_flat_invocation(
            &tmp.path().join("instances/1/root.qcow2"),
            &tmp.path().join("checkpoints/dev.qcow2"),
        );

        let args = invocation
            .args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            args,
            [
                "convert",
                "-f",
                "qcow2",
                "-O",
                "qcow2",
                tmp.path()
                    .join("instances/1/root.qcow2")
                    .to_string_lossy()
                    .as_ref(),
                tmp.path()
                    .join("checkpoints/dev.qcow2")
                    .to_string_lossy()
                    .as_ref()
            ]
        );
    }

    #[test]
    fn qemu_img_discovery_prefers_env_over_managed() {
        with_env_lock(|| {
            let tmp = tempfile::tempdir().expect("tempdir");
            let data_dir = tmp.path().join("data");
            let (_, managed_img) = write_managed_qemu(&data_dir);
            let env_img = tmp.path().join("env").join(qemu_img_file_name());
            fs::create_dir_all(env_img.parent().expect("parent")).expect("env dir");
            fs::write(&env_img, b"env").expect("env img");
            std::env::set_var("LSB_QEMU_IMG", &env_img);

            let discovered =
                QemuImg::discover_for_data_dir(&data_dir).expect("env qemu-img should win");

            assert_eq!(discovered.program(), env_img);
            assert_ne!(discovered.program(), managed_img);
        });
    }

    #[test]
    fn qemu_img_discovery_uses_lsb_qemu_sibling_before_managed() {
        with_env_lock(|| {
            let tmp = tempfile::tempdir().expect("tempdir");
            let data_dir = tmp.path().join("data");
            write_managed_qemu(&data_dir);
            let env_qemu = tmp.path().join("env/qemu-system-x86_64.exe");
            let env_img = tmp.path().join("env").join(qemu_img_file_name());
            fs::create_dir_all(env_qemu.parent().expect("parent")).expect("env dir");
            fs::write(&env_qemu, b"env qemu").expect("env qemu");
            fs::write(&env_img, b"env img").expect("env img");
            std::env::set_var("LSB_QEMU", &env_qemu);

            let discovered =
                QemuImg::discover_for_data_dir(&data_dir).expect("LSB_QEMU sibling should win");

            assert_eq!(discovered.program(), env_img);
        });
    }

    #[test]
    fn qemu_img_discovery_uses_configured_qemu_sibling_before_managed() {
        with_env_lock(|| {
            let tmp = tempfile::tempdir().expect("tempdir");
            let data_dir = tmp.path().join("data");
            write_managed_qemu(&data_dir);
            let config_qemu = tmp.path().join("config/qemu-system-x86_64.exe");
            let config_img = tmp.path().join("config").join(qemu_img_file_name());
            fs::create_dir_all(config_qemu.parent().expect("parent")).expect("config dir");
            fs::write(&config_qemu, b"config qemu").expect("config qemu");
            fs::write(&config_img, b"config img").expect("config img");

            let discovered = QemuImg::discover_with_configured_qemu(&data_dir, Some(&config_qemu))
                .expect("configured sibling should win");

            assert_eq!(discovered.program(), config_img);
        });
    }

    #[test]
    fn qemu_img_discovery_uses_managed_before_path() {
        with_env_lock(|| {
            let tmp = tempfile::tempdir().expect("tempdir");
            let data_dir = tmp.path().join("data");
            let (_, managed_img) = write_managed_qemu(&data_dir);
            let path_dir = tmp.path().join("path");
            let path_img = path_dir.join(qemu_img_file_name());
            fs::create_dir_all(&path_dir).expect("path dir");
            fs::write(&path_img, b"path img").expect("path img");
            std::env::set_var("PATH", std::env::join_paths([path_dir]).expect("join PATH"));

            let discovered =
                QemuImg::discover_for_data_dir(&data_dir).expect("managed qemu-img should win");

            assert_eq!(discovered.program(), managed_img);
            assert_ne!(discovered.program(), path_img);
        });
    }

    #[test]
    fn qemu_img_discovery_uses_default_managed_before_path_when_data_dir_is_custom() {
        with_env_lock(|| {
            let tmp = tempfile::tempdir().expect("tempdir");
            let data_dir = tmp.path().join("sandbox-data");
            let default_data_dir = PathBuf::from(lsb_platform::default_data_dir());
            assert_ne!(data_dir, default_data_dir);
            let (_, default_managed_img) = write_managed_qemu(&default_data_dir);
            let path_dir = tmp.path().join("path");
            let path_img = path_dir.join(qemu_img_file_name());
            fs::create_dir_all(&path_dir).expect("path dir");
            fs::write(&path_img, b"path img").expect("path img");
            std::env::set_var("PATH", std::env::join_paths([path_dir]).expect("join PATH"));

            let discovered = QemuImg::discover_for_data_dir(&data_dir)
                .expect("default managed qemu-img should win");

            assert_eq!(discovered.program(), default_managed_img);
            assert_ne!(discovered.program(), path_img);
        });
    }

    #[test]
    fn qemu_img_discovery_falls_back_to_path() {
        with_env_lock(|| {
            let tmp = tempfile::tempdir().expect("tempdir");
            let data_dir = tmp.path().join("data");
            let path_dir = tmp.path().join("path");
            let path_img = path_dir.join(qemu_img_file_name());
            fs::create_dir_all(&path_dir).expect("path dir");
            fs::write(&path_img, b"path img").expect("path img");
            std::env::set_var("PATH", std::env::join_paths([path_dir]).expect("join PATH"));

            let discovered =
                QemuImg::discover_for_data_dir(&data_dir).expect("PATH qemu-img should resolve");

            assert_eq!(discovered.program(), path_img);
        });
    }

    #[test]
    fn save_flat_checkpoint_rejects_any_existing_checkpoint_artifact() {
        for extension in ["qcow2", "json", "ext4", "idx"] {
            let tmp = tempfile::tempdir().expect("tempdir");
            let store = store(tmp.path());
            fs::create_dir_all(store.checkpoints_dir()).expect("checkpoints dir");
            let paths = store.checkpoint_paths("dev");
            let conflict = match extension {
                "qcow2" => paths.qcow2_path,
                "json" => paths.metadata_path,
                "ext4" => paths.legacy_ext4_path,
                "idx" => paths.cas_index_path,
                _ => unreachable!(),
            };
            fs::write(&conflict, b"existing").expect("conflict artifact");

            let err = store
                .save_flat_checkpoint(
                    "dev",
                    tmp.path().join("active.qcow2"),
                    &base_source(tmp.path()),
                    4096,
                )
                .expect_err("existing artifact should reject checkpoint save");

            assert!(
                matches!(err, WindowsCheckpointError::AlreadyExists { ref name } if name == "dev"),
                "unexpected error for .{extension} conflict: {err}"
            );
        }
    }

    #[test]
    fn install_new_checkpoint_file_does_not_replace_existing_destination() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let source = tmp.path().join(".dev.qcow2.convert.tmp");
        let destination = tmp.path().join("dev.qcow2");
        fs::write(&source, b"new").expect("source temp");
        fs::write(&destination, b"old").expect("existing destination");

        let err = install_new_checkpoint_file(&source, &destination)
            .expect_err("existing destination should reject install");

        assert!(
            matches!(err, WindowsCheckpointError::AlreadyExists { ref name } if name == "dev"),
            "unexpected error: {err}"
        );
        assert_eq!(
            fs::read(&destination).expect("destination should remain readable"),
            b"old"
        );
        assert!(source.exists(), "failed install should leave temp source");
    }

    #[test]
    fn metadata_pins_base_version_and_parent() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let parent_metadata =
            WindowsCheckpointMetadata::new("parent", &base_source(tmp.path()), 4096, 10);
        let source = WindowsCheckpointSource {
            kind: WindowsCheckpointSourceKind::Checkpoint {
                name: "parent".to_string(),
                metadata: parent_metadata,
            },
            path: tmp.path().join("data/checkpoints/parent.qcow2"),
            disk_format: WindowsDiskImageFormat::Qcow2,
            virtual_size_bytes: 4096,
        };

        let metadata = WindowsCheckpointMetadata::new("child", &source, 8192, 20);

        assert_eq!(metadata.name, "child");
        assert_eq!(metadata.layout, WindowsCheckpointLayout::Flat);
        assert_eq!(metadata.disk_format, WindowsDiskImageFormat::Qcow2);
        assert_eq!(metadata.base_version.as_deref(), Some("1.2.3"));
        assert_eq!(metadata.parent.as_deref(), Some("parent"));
        assert_eq!(metadata.virtual_size_bytes, 8192);
        assert_eq!(
            metadata.source.kind,
            WindowsCheckpointSourceMetadataKind::Checkpoint
        );
        assert_eq!(metadata.source.disk_format, WindowsDiskImageFormat::Qcow2);
    }

    #[test]
    fn resolve_source_rejects_cas_index_with_windows_error() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = store(tmp.path());
        fs::create_dir_all(store.checkpoints_dir()).expect("checkpoints dir");
        fs::write(store.checkpoint_paths("dev").cas_index_path, b"idx").expect("idx");

        let err = store
            .resolve_source(
                tmp.path().join("data/rootfs.ext4"),
                Some("dev"),
                None,
                false,
            )
            .expect_err("CAS index should be unsupported on Windows");

        let message = err.to_string();
        assert!(message.contains("CAS/NBD checkpoint index"));
        assert!(message.contains("Windows uses qcow2/raw"));
        assert!(message.contains("qcow2/raw"));
    }

    #[test]
    fn list_requires_metadata_and_disk_to_register_checkpoint() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = store(tmp.path());
        fs::create_dir_all(store.checkpoints_dir()).expect("checkpoints dir");
        let partial = store.checkpoint_paths("partial");
        fs::write(&partial.qcow2_path, b"orphan").expect("orphan disk");

        assert!(store.list_checkpoints().expect("list").is_empty());

        let valid = store.checkpoint_paths("valid");
        fs::write(&valid.qcow2_path, b"disk").expect("valid disk");
        let metadata = WindowsCheckpointMetadata::new("valid", &base_source(tmp.path()), 4096, 30);
        write_metadata_path(&valid.metadata_path, &metadata).expect("metadata");

        let entries = store.list_checkpoints().expect("list");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "valid");
        assert_eq!(entries[0].metadata, metadata);
    }

    #[test]
    fn delete_checkpoint_removes_partial_windows_files() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = store(tmp.path());
        fs::create_dir_all(store.checkpoints_dir()).expect("checkpoints dir");
        let paths = store.checkpoint_paths("dev");
        fs::write(&paths.qcow2_path, b"orphan").expect("orphan disk");

        assert!(store.delete_checkpoint("dev").expect("delete"));
        assert!(!paths.qcow2_path.exists());
        assert!(!store.delete_checkpoint("dev").expect("delete again"));
    }
}
