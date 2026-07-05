use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyPathOperation {
    CopyInSource,
    CopyInGuestDestination,
    CopyOutGuestSource,
    CopyOutHostDestination,
    CopyOutGuestEntry,
}

impl CopyPathOperation {
    fn label(self) -> &'static str {
        match self {
            Self::CopyInSource => "copy-in source",
            Self::CopyInGuestDestination => "copy-in guest destination",
            Self::CopyOutGuestSource => "copy-out guest source",
            Self::CopyOutHostDestination => "copy-out host destination",
            Self::CopyOutGuestEntry => "copy-out guest entry",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyPathError {
    operation: CopyPathOperation,
    path: String,
    reason: String,
}

impl CopyPathError {
    fn new(
        operation: CopyPathOperation,
        path: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            operation,
            path: sanitize_path(path.into()),
            reason: reason.into(),
        }
    }

    pub fn operation(&self) -> CopyPathOperation {
        self.operation
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl fmt::Display for CopyPathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} '{}' is unsafe: {}",
            self.operation.label(),
            self.path,
            self.reason
        )
    }
}

impl Error for CopyPathError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymlinkPolicy {
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsPathKind {
    DriveAbsolute,
    UnixAbsoluteForTests,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyOutDestination {
    pub path: PathBuf,
    pub exists: bool,
    pub overwrite: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyInPlan {
    pub source_root: PathBuf,
    pub guest_root: String,
    pub entries: Vec<CopyInEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyInEntry {
    pub host_path: PathBuf,
    pub guest_path: String,
    pub kind: CopyInEntryKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CopyInEntryKind {
    Directory,
    File {
        len: u64,
        #[cfg(windows)]
        identity: CopyInFileIdentity,
    },
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyInFileIdentity {
    volume_serial_number: u32,
    file_index_high: u32,
    file_index_low: u32,
}

#[derive(Debug, Default)]
pub struct CaseFoldSet {
    seen: HashSet<String>,
}

impl CaseFoldSet {
    pub fn insert(
        &mut self,
        component: &str,
        operation: CopyPathOperation,
        parent: &str,
    ) -> Result<(), CopyPathError> {
        let key = windows_copy_case_key(component);
        if !self.seen.insert(key) {
            return Err(CopyPathError::new(
                operation,
                parent,
                format!(
                    "contains entries that collide on a case-insensitive Windows filesystem: '{}'",
                    component
                ),
            ));
        }
        Ok(())
    }
}

/// Best-effort Unicode fold for Windows MVP copy collision checks.
///
/// This catches common non-ASCII case pairs that ASCII folding misses, but it
/// does not attempt NTFS upcase-table matching or Unicode normalization.
fn windows_copy_case_key(component: &str) -> String {
    component.chars().flat_map(|ch| ch.to_lowercase()).collect()
}

pub fn plan_copy_in(source: &Path, guest_root: &str) -> Result<CopyInPlan, CopyPathError> {
    validate_guest_absolute_path(guest_root, CopyPathOperation::CopyInGuestDestination)?;
    validate_copy_in_source(source)?;

    let source_root = source.canonicalize().map_err(|error| {
        CopyPathError::new(
            CopyPathOperation::CopyInSource,
            source.display().to_string(),
            format!("failed to canonicalize source: {error}"),
        )
    })?;

    let metadata = reject_reparse_point(source, CopyPathOperation::CopyInSource)?;
    let guest_root = normalize_guest_absolute_path(guest_root);
    let mut entries = Vec::new();

    if metadata.is_file() {
        entries.push(CopyInEntry {
            host_path: source_root.clone(),
            guest_path: guest_root.clone(),
            kind: copy_in_file_entry_kind(source, &metadata, CopyPathOperation::CopyInSource)?,
        });
    } else if metadata.is_dir() {
        entries.push(CopyInEntry {
            host_path: source_root.clone(),
            guest_path: guest_root.clone(),
            kind: CopyInEntryKind::Directory,
        });
        plan_copy_in_dir(&source_root, &guest_root, &mut entries)?;
    } else {
        return Err(CopyPathError::new(
            CopyPathOperation::CopyInSource,
            source.display().to_string(),
            "source is not a regular file or directory",
        ));
    }

    entries.sort_by(|left, right| {
        let left_dir = matches!(left.kind, CopyInEntryKind::Directory);
        let right_dir = matches!(right.kind, CopyInEntryKind::Directory);
        right_dir
            .cmp(&left_dir)
            .then_with(|| left.guest_path.cmp(&right.guest_path))
    });

    Ok(CopyInPlan {
        source_root,
        guest_root,
        entries,
    })
}

pub fn validate_copy_out_destination(
    destination: &Path,
    overwrite: bool,
) -> Result<CopyOutDestination, CopyPathError> {
    validate_windows_host_path_lexical(destination, CopyPathOperation::CopyOutHostDestination)?;

    if let Some(parent) = destination.parent() {
        if !parent.as_os_str().is_empty() {
            validate_existing_prefixes(parent, CopyPathOperation::CopyOutHostDestination)?;
            if !parent.exists() {
                return Err(CopyPathError::new(
                    CopyPathOperation::CopyOutHostDestination,
                    destination.display().to_string(),
                    format!("parent directory '{}' does not exist", parent.display()),
                ));
            }
            let parent_meta =
                reject_reparse_point(parent, CopyPathOperation::CopyOutHostDestination)?;
            if !parent_meta.is_dir() {
                return Err(CopyPathError::new(
                    CopyPathOperation::CopyOutHostDestination,
                    destination.display().to_string(),
                    "parent path is not a directory",
                ));
            }
        }
    }

    let exists = destination.exists();
    if exists {
        reject_reparse_point(destination, CopyPathOperation::CopyOutHostDestination)?;
        if !overwrite {
            return Err(CopyPathError::new(
                CopyPathOperation::CopyOutHostDestination,
                destination.display().to_string(),
                "destination already exists; pass explicit overwrite to replace it",
            ));
        }
    }

    Ok(CopyOutDestination {
        path: destination.to_path_buf(),
        exists,
        overwrite,
    })
}

fn validate_copy_in_source(source: &Path) -> Result<(), CopyPathError> {
    validate_windows_host_path_lexical(source, CopyPathOperation::CopyInSource)?;
    validate_existing_prefixes(source, CopyPathOperation::CopyInSource)?;
    if !source.exists() {
        return Err(CopyPathError::new(
            CopyPathOperation::CopyInSource,
            source.display().to_string(),
            "source does not exist",
        ));
    }
    Ok(())
}

pub fn validate_windows_host_path_lexical(
    path: &Path,
    operation: CopyPathOperation,
) -> Result<WindowsPathKind, CopyPathError> {
    let raw = path_to_string(path);
    if raw.is_empty() {
        return Err(CopyPathError::new(operation, raw, "path is empty"));
    }
    if raw.contains('\0') {
        return Err(CopyPathError::new(operation, raw, "path contains NUL byte"));
    }

    let normalized = raw.replace('/', "\\");
    let lexical = if let Some(verbatim) = normalized.strip_prefix("\\\\?\\") {
        if verbatim.starts_with("UNC\\") {
            return Err(CopyPathError::new(
                operation,
                raw,
                "UNC paths are not supported in the Windows MVP",
            ));
        }
        verbatim
    } else {
        normalized.as_str()
    };

    if lexical.starts_with("\\\\.\\") {
        return Err(CopyPathError::new(
            operation,
            raw,
            "device paths are not supported in the Windows MVP",
        ));
    }
    if lexical.starts_with("\\\\") {
        return Err(CopyPathError::new(
            operation,
            raw,
            "UNC paths are not supported in the Windows MVP",
        ));
    }

    let (kind, remainder) = if let Some(remainder) = drive_absolute_remainder(lexical) {
        (WindowsPathKind::DriveAbsolute, remainder)
    } else if cfg!(not(windows)) && lexical.starts_with('\\') {
        (
            WindowsPathKind::UnixAbsoluteForTests,
            lexical.trim_start_matches('\\'),
        )
    } else {
        return Err(CopyPathError::new(
            operation,
            raw,
            "path must be an absolute drive path such as C:\\path\\to\\file",
        ));
    };

    if remainder.is_empty() {
        return Err(CopyPathError::new(
            operation,
            raw,
            "drive root is too broad for copy transfer operations",
        ));
    }
    if remainder.contains("\\\\") {
        return Err(CopyPathError::new(
            operation,
            raw,
            "path contains empty components or repeated separators",
        ));
    }

    for component in remainder.split('\\') {
        validate_windows_component(component, operation, &raw)?;
    }

    Ok(kind)
}

pub fn validate_guest_absolute_path(
    path: &str,
    operation: CopyPathOperation,
) -> Result<(), CopyPathError> {
    if path.is_empty() {
        return Err(CopyPathError::new(operation, path, "guest path is empty"));
    }
    if path.contains('\0') {
        return Err(CopyPathError::new(
            operation,
            path,
            "guest path contains NUL byte",
        ));
    }
    if path.contains('\\') {
        return Err(CopyPathError::new(
            operation,
            path,
            "guest path must use '/' separators, not backslashes",
        ));
    }
    if !path.starts_with('/') {
        return Err(CopyPathError::new(
            operation,
            path,
            "guest path must be absolute",
        ));
    }
    if path.len() > 1 && path.ends_with('/') {
        return Err(CopyPathError::new(
            operation,
            path,
            "guest path must not have a trailing slash",
        ));
    }
    if path.contains("//") {
        return Err(CopyPathError::new(
            operation,
            path,
            "guest path contains empty components or repeated separators",
        ));
    }
    if path == "/" {
        return Err(CopyPathError::new(
            operation,
            path,
            "guest root is too broad for copy transfer operations",
        ));
    }
    for component in path.trim_start_matches('/').split('/') {
        validate_guest_path_component(component, operation, path)?;
    }
    Ok(())
}

pub fn validate_guest_path_component(
    component: &str,
    operation: CopyPathOperation,
    parent: &str,
) -> Result<(), CopyPathError> {
    if component.is_empty() {
        return Err(CopyPathError::new(
            operation,
            parent,
            "guest path contains an empty component",
        ));
    }
    if component == "." || component == ".." {
        return Err(CopyPathError::new(
            operation,
            parent,
            "guest path traversal components are not allowed",
        ));
    }
    if component.contains('/') || component.contains('\\') || component.contains('\0') {
        return Err(CopyPathError::new(
            operation,
            parent,
            format!(
                "guest path component '{}' contains an unsafe separator",
                component
            ),
        ));
    }
    Ok(())
}

fn plan_copy_in_dir(
    host_dir: &Path,
    guest_dir: &str,
    entries: &mut Vec<CopyInEntry>,
) -> Result<(), CopyPathError> {
    let mut children = Vec::new();
    let mut case_fold = CaseFoldSet::default();

    for child in fs::read_dir(host_dir).map_err(|error| {
        CopyPathError::new(
            CopyPathOperation::CopyInSource,
            host_dir.display().to_string(),
            format!("failed to read directory: {error}"),
        )
    })? {
        let child = child.map_err(|error| {
            CopyPathError::new(
                CopyPathOperation::CopyInSource,
                host_dir.display().to_string(),
                format!("failed to read directory entry: {error}"),
            )
        })?;
        let name = child.file_name().to_string_lossy().into_owned();
        validate_windows_component(
            &name,
            CopyPathOperation::CopyInSource,
            &path_to_string(host_dir),
        )?;
        validate_guest_path_component(&name, CopyPathOperation::CopyInGuestDestination, guest_dir)?;
        case_fold.insert(
            &name,
            CopyPathOperation::CopyInSource,
            &path_to_string(host_dir),
        )?;
        children.push(child.path());
    }

    children.sort();
    for child_path in children {
        let name = child_path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .ok_or_else(|| {
                CopyPathError::new(
                    CopyPathOperation::CopyInSource,
                    child_path.display().to_string(),
                    "directory entry has no file name",
                )
            })?;
        let child_guest_path = join_guest_child(guest_dir, &name);
        let metadata = reject_reparse_point(&child_path, CopyPathOperation::CopyInSource)?;

        if metadata.is_dir() {
            entries.push(CopyInEntry {
                host_path: child_path.clone(),
                guest_path: child_guest_path.clone(),
                kind: CopyInEntryKind::Directory,
            });
            plan_copy_in_dir(&child_path, &child_guest_path, entries)?;
        } else if metadata.is_file() {
            entries.push(CopyInEntry {
                host_path: child_path.clone(),
                guest_path: child_guest_path,
                kind: copy_in_file_entry_kind(
                    &child_path,
                    &metadata,
                    CopyPathOperation::CopyInSource,
                )?,
            });
        } else {
            return Err(CopyPathError::new(
                CopyPathOperation::CopyInSource,
                child_path.display().to_string(),
                "only regular files and directories can be copied in",
            ));
        }
    }

    Ok(())
}

fn copy_in_file_entry_kind(
    path: &Path,
    metadata: &fs::Metadata,
    operation: CopyPathOperation,
) -> Result<CopyInEntryKind, CopyPathError> {
    #[cfg(windows)]
    {
        let identity = inspect_copy_in_file_for_plan(path, metadata.len(), operation)?;
        Ok(CopyInEntryKind::File {
            len: metadata.len(),
            identity,
        })
    }

    #[cfg(not(windows))]
    {
        let _ = (path, operation);
        Ok(CopyInEntryKind::File {
            len: metadata.len(),
        })
    }
}

fn validate_existing_prefixes(
    path: &Path,
    operation: CopyPathOperation,
) -> Result<(), CopyPathError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if current.exists() {
            reject_reparse_point(&current, operation)?;
        }
    }
    Ok(())
}

fn reject_reparse_point(
    path: &Path,
    operation: CopyPathOperation,
) -> Result<fs::Metadata, CopyPathError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        CopyPathError::new(
            operation,
            path.display().to_string(),
            format!("failed to inspect path metadata: {error}"),
        )
    })?;
    if is_symlink_or_reparse_point(&metadata) {
        return Err(CopyPathError::new(
            operation,
            path.display().to_string(),
            "symlinks and junction/reparse-point paths are not followed in the Windows MVP",
        ));
    }
    Ok(metadata)
}

#[cfg(windows)]
pub fn open_copy_in_file_checked(
    path: &Path,
    expected_len: u64,
    expected_identity: CopyInFileIdentity,
) -> Result<fs::File, CopyPathError> {
    use std::os::windows::io::{FromRawHandle, RawHandle};

    validate_windows_host_path_lexical(path, CopyPathOperation::CopyInSource)?;
    validate_existing_prefixes(path, CopyPathOperation::CopyInSource)?;

    let (handle, info) = open_windows_file_handle(
        path,
        windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ,
        windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL
            | windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT
            | windows_sys::Win32::Storage::FileSystem::FILE_FLAG_SEQUENTIAL_SCAN,
        CopyPathOperation::CopyInSource,
    )?;
    if let Err(error) =
        validate_copy_in_file_info(path, &info, Some(expected_len), Some(expected_identity))
    {
        let _ = unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) };
        return Err(error);
    }
    if let Err(error) = validate_existing_prefixes(path, CopyPathOperation::CopyInSource) {
        let _ = unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) };
        return Err(error);
    }

    Ok(unsafe { fs::File::from_raw_handle(handle as RawHandle) })
}

#[cfg(windows)]
fn inspect_copy_in_file_for_plan(
    path: &Path,
    expected_len: u64,
    operation: CopyPathOperation,
) -> Result<CopyInFileIdentity, CopyPathError> {
    let (handle, info) = open_windows_file_handle(
        path,
        windows_sys::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES,
        windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL
            | windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT,
        operation,
    )?;
    let close_result = unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) };
    if close_result == 0 {
        return Err(CopyPathError::new(
            operation,
            path.display().to_string(),
            format!(
                "failed to close Windows copy-in inspection handle: {}",
                std::io::Error::last_os_error()
            ),
        ));
    }

    validate_copy_in_file_info(path, &info, Some(expected_len), None)?;
    Ok(copy_in_file_identity_from_info(&info))
}

#[cfg(windows)]
fn open_windows_file_handle(
    path: &Path,
    desired_access: u32,
    flags_and_attributes: u32,
    operation: CopyPathOperation,
) -> Result<
    (
        windows_sys::Win32::Foundation::HANDLE,
        windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION,
    ),
    CopyPathError,
> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_SHARE_DELETE,
        FILE_SHARE_READ, OPEN_EXISTING,
    };

    let path_text = path.display().to_string();
    let mut wide_path = path.as_os_str().encode_wide().collect::<Vec<_>>();
    wide_path.push(0);

    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            desired_access,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            flags_and_attributes,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(CopyPathError::new(
            operation,
            path_text,
            format!(
                "failed to open Windows copy-in source without following final reparse points: {}",
                std::io::Error::last_os_error()
            ),
        ));
    }

    let mut info = unsafe { std::mem::zeroed::<BY_HANDLE_FILE_INFORMATION>() };
    let ok = unsafe { GetFileInformationByHandle(handle, &mut info) };
    if ok == 0 {
        let error = std::io::Error::last_os_error();
        let _ = unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) };
        return Err(CopyPathError::new(
            operation,
            path_text,
            format!("failed to inspect Windows copy-in file handle: {error}"),
        ));
    }

    Ok((handle, info))
}

#[cfg(windows)]
fn validate_copy_in_file_info(
    path: &Path,
    info: &windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION,
    expected_len: Option<u64>,
    expected_identity: Option<CopyInFileIdentity>,
) -> Result<(), CopyPathError> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    };

    let path_text = path.display().to_string();
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(CopyPathError::new(
            CopyPathOperation::CopyInSource,
            path_text,
            "symlinks and junction/reparse-point paths are not followed in the Windows MVP",
        ));
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        return Err(CopyPathError::new(
            CopyPathOperation::CopyInSource,
            path_text,
            "copy-in source changed from a file to a directory before import",
        ));
    }
    if info.nNumberOfLinks > 1 {
        return Err(CopyPathError::new(
            CopyPathOperation::CopyInSource,
            path_text,
            "hardlinked files are not copied in the Windows MVP",
        ));
    }
    if let Some(expected_len) = expected_len {
        let actual_len = windows_file_len(info);
        if actual_len != expected_len {
            return Err(CopyPathError::new(
                CopyPathOperation::CopyInSource,
                path_text,
                format!(
                    "copy-in source changed before import: expected {expected_len} bytes, found {actual_len} bytes"
                ),
            ));
        }
    }
    if let Some(expected_identity) = expected_identity {
        let actual_identity = copy_in_file_identity_from_info(info);
        if actual_identity != expected_identity {
            return Err(CopyPathError::new(
                CopyPathOperation::CopyInSource,
                path_text,
                "copy-in source changed identity before import",
            ));
        }
    }

    Ok(())
}

#[cfg(windows)]
fn copy_in_file_identity_from_info(
    info: &windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION,
) -> CopyInFileIdentity {
    CopyInFileIdentity {
        volume_serial_number: info.dwVolumeSerialNumber,
        file_index_high: info.nFileIndexHigh,
        file_index_low: info.nFileIndexLow,
    }
}

#[cfg(windows)]
fn windows_file_len(
    info: &windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION,
) -> u64 {
    ((info.nFileSizeHigh as u64) << 32) | info.nFileSizeLow as u64
}

fn is_symlink_or_reparse_point(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn validate_windows_component(
    component: &str,
    operation: CopyPathOperation,
    path: &str,
) -> Result<(), CopyPathError> {
    if component.is_empty() {
        return Err(CopyPathError::new(
            operation,
            path,
            "path contains an empty component",
        ));
    }
    if component == "." || component == ".." {
        return Err(CopyPathError::new(
            operation,
            path,
            "path traversal components are not allowed",
        ));
    }
    if component.ends_with(' ') || component.ends_with('.') {
        return Err(CopyPathError::new(
            operation,
            path,
            format!("component '{}' ends with a space or dot", component),
        ));
    }
    if component
        .chars()
        .any(|ch| matches!(ch, '<' | '>' | ':' | '"' | '|' | '?' | '*') || ch.is_control())
    {
        return Err(CopyPathError::new(
            operation,
            path,
            format!(
                "component '{}' contains Windows-reserved characters",
                component
            ),
        ));
    }

    let stem = component
        .split_once('.')
        .map(|(stem, _)| stem)
        .unwrap_or(component)
        .to_ascii_uppercase();
    let reserved = matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || reserved_numbered_device(&stem, "COM")
        || reserved_numbered_device(&stem, "LPT");
    if reserved {
        return Err(CopyPathError::new(
            operation,
            path,
            format!(
                "component '{}' is a reserved Windows device name",
                component
            ),
        ));
    }

    Ok(())
}

fn reserved_numbered_device(stem: &str, prefix: &str) -> bool {
    stem.len() == 4
        && stem.starts_with(prefix)
        && stem
            .as_bytes()
            .get(3)
            .is_some_and(|byte| matches!(byte, b'1'..=b'9'))
}

fn drive_absolute_remainder(normalized: &str) -> Option<&str> {
    let bytes = normalized.as_bytes();
    if bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\' {
        Some(&normalized[3..])
    } else {
        None
    }
}

fn normalize_guest_absolute_path(path: &str) -> String {
    if path.len() > 1 {
        path.trim_end_matches('/').to_string()
    } else {
        path.to_string()
    }
}

pub fn join_guest_child(parent: &str, child: &str) -> String {
    if parent == "/" {
        format!("/{child}")
    } else {
        format!("{}/{child}", parent.trim_end_matches('/'))
    }
}

fn path_to_string(path: &Path) -> String {
    path.display().to_string()
}

fn sanitize_path(path: String) -> String {
    path.replace('\0', "\\0")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn windows_path_accepts_drive_absolute_path() {
        let kind = validate_windows_host_path_lexical(
            Path::new(r"C:\Users\alice\project\file.txt"),
            CopyPathOperation::CopyInSource,
        )
        .expect("drive absolute path should be valid");

        assert_eq!(kind, WindowsPathKind::DriveAbsolute);
    }

    #[test]
    fn windows_path_accepts_verbatim_drive_absolute_path() {
        let kind = validate_windows_host_path_lexical(
            Path::new(r"\\?\C:\Users\alice\project\file.txt"),
            CopyPathOperation::CopyInSource,
        )
        .expect("canonicalized Windows drive path should be valid");

        assert_eq!(kind, WindowsPathKind::DriveAbsolute);
    }

    #[test]
    fn windows_path_rejects_relative_drive_and_unc_paths() {
        let drive_relative = validate_windows_host_path_lexical(
            Path::new(r"C:project\file.txt"),
            CopyPathOperation::CopyInSource,
        )
        .expect_err("drive-relative path should fail");
        assert!(drive_relative.reason().contains("absolute drive path"));

        let unc = validate_windows_host_path_lexical(
            Path::new(r"\\server\share\file.txt"),
            CopyPathOperation::CopyInSource,
        )
        .expect_err("UNC path should fail");
        assert!(unc.reason().contains("UNC"));
    }

    #[test]
    fn windows_path_rejects_traversal_and_reserved_names() {
        let traversal = validate_windows_host_path_lexical(
            Path::new(r"C:\safe\..\secret.txt"),
            CopyPathOperation::CopyOutHostDestination,
        )
        .expect_err("traversal should fail");
        assert!(traversal.reason().contains("traversal"));

        let reserved = validate_windows_host_path_lexical(
            Path::new(r"C:\safe\CON.txt"),
            CopyPathOperation::CopyOutHostDestination,
        )
        .expect_err("reserved device name should fail");
        assert!(reserved.reason().contains("reserved Windows device"));
    }

    #[test]
    fn guest_absolute_path_rejects_relative_absolute_root_and_backslash() {
        assert!(validate_guest_absolute_path(
            "workspace",
            CopyPathOperation::CopyInGuestDestination
        )
        .is_err());
        assert!(validate_guest_absolute_path("/", CopyPathOperation::CopyOutGuestSource).is_err());
        let err = validate_guest_absolute_path(
            r"/workspace\bad",
            CopyPathOperation::CopyInGuestDestination,
        )
        .expect_err("backslash should fail");
        assert!(err.reason().contains("backslashes"));
    }

    #[test]
    fn guest_component_rejects_traversal_separator_and_nul() {
        assert!(validate_guest_path_component(
            "..",
            CopyPathOperation::CopyOutGuestEntry,
            "/workspace",
        )
        .is_err());
        assert!(validate_guest_path_component(
            "a/b",
            CopyPathOperation::CopyOutGuestEntry,
            "/workspace",
        )
        .is_err());
        assert!(validate_guest_path_component(
            "bad\0name",
            CopyPathOperation::CopyOutGuestEntry,
            "/workspace",
        )
        .is_err());
    }

    #[test]
    fn case_fold_set_rejects_case_insensitive_collisions() {
        let mut set = CaseFoldSet::default();
        set.insert(
            "Readme.md",
            CopyPathOperation::CopyOutGuestEntry,
            "/workspace",
        )
        .expect("first entry should insert");

        let err = set
            .insert(
                "README.md",
                CopyPathOperation::CopyOutGuestEntry,
                "/workspace",
            )
            .expect_err("case collision should fail");

        assert!(err.reason().contains("case-insensitive"));
    }

    #[test]
    fn case_fold_set_rejects_non_ascii_case_collisions() {
        let mut set = CaseFoldSet::default();
        set.insert(
            "Ångström.txt",
            CopyPathOperation::CopyOutGuestEntry,
            "/workspace",
        )
        .expect("first entry should insert");

        let err = set
            .insert(
                "ångström.txt",
                CopyPathOperation::CopyOutGuestEntry,
                "/workspace",
            )
            .expect_err("non-ASCII case collision should fail");

        assert!(err.reason().contains("case-insensitive"));
    }

    #[test]
    fn case_fold_set_does_not_normalize_unicode_equivalence() {
        let mut set = CaseFoldSet::default();
        set.insert("é.txt", CopyPathOperation::CopyOutGuestEntry, "/workspace")
            .expect("first entry should insert");

        set.insert(
            "e\u{301}.txt",
            CopyPathOperation::CopyOutGuestEntry,
            "/workspace",
        )
        .expect("Windows MVP copy folding does not perform Unicode normalization");
    }

    #[test]
    fn copy_in_plan_includes_nested_directories_and_files() {
        let root = temp_dir("plan");
        let source = root.join("src");
        fs::create_dir_all(source.join("nested/empty")).expect("fixture dirs");
        write_fixture(&source.join("alpha.txt"), b"alpha");
        write_fixture(&source.join("nested/beta.txt"), b"beta");

        let plan = plan_copy_in(&source, "/workspace/input").expect("copy-in plan should build");
        let entries: Vec<_> = plan
            .entries
            .iter()
            .map(|entry| {
                (
                    entry.guest_path.as_str(),
                    matches!(entry.kind, CopyInEntryKind::Directory),
                )
            })
            .collect();

        assert_eq!(
            entries,
            vec![
                ("/workspace/input", true),
                ("/workspace/input/nested", true),
                ("/workspace/input/nested/empty", true),
                ("/workspace/input/alpha.txt", false),
                ("/workspace/input/nested/beta.txt", false),
            ]
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn copy_in_plan_rejects_missing_source() {
        let err = plan_copy_in(
            &temp_dir("missing").join("missing.txt"),
            "/workspace/missing.txt",
        )
        .expect_err("missing source should fail");

        assert_eq!(err.operation(), CopyPathOperation::CopyInSource);
        assert!(err.reason().contains("source does not exist"));
    }

    #[test]
    fn copy_in_plan_rejects_symlink_inputs() {
        let root = temp_dir("symlink");
        let source = root.join("src");
        fs::create_dir_all(&source).expect("source dir");
        write_fixture(&root.join("target.txt"), b"target");

        #[cfg(unix)]
        std::os::unix::fs::symlink(root.join("target.txt"), source.join("link.txt"))
            .expect("symlink fixture");
        #[cfg(windows)]
        {
            match std::os::windows::fs::symlink_file(
                root.join("target.txt"),
                source.join("link.txt"),
            ) {
                Ok(()) => {}
                Err(error) if error.raw_os_error() == Some(1314) => {
                    eprintln!(
                        "skipping Windows symlink rejection fixture because the runner lacks symlink privilege: {error}"
                    );
                    let _ = fs::remove_dir_all(root);
                    return;
                }
                Err(error) => panic!("symlink fixture: {error}"),
            }
        }

        let err = plan_copy_in(&source, "/workspace/input").expect_err("symlink should fail");

        assert!(err.reason().contains("symlinks"));

        let _ = fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn copy_in_plan_rejects_hardlinked_files_on_windows() {
        let root = temp_dir("hardlink");
        let source = root.join("src");
        fs::create_dir_all(&source).expect("source dir");
        let input = source.join("input.txt");
        write_fixture(&input, b"linked content");
        fs::hard_link(&input, root.join("outside-link.txt")).expect("hardlink fixture");

        let err = plan_copy_in(&source, "/workspace/input")
            .expect_err("hardlinked files should fail closed");

        assert_eq!(err.operation(), CopyPathOperation::CopyInSource);
        assert!(err.reason().contains("hardlinked files"));

        let _ = fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn copy_in_checked_open_rejects_file_replaced_after_plan_on_windows() {
        let root = temp_dir("checked-open-replaced-file");
        let source = root.join("src");
        fs::create_dir_all(&source).expect("source dir");
        let input = source.join("input.txt");
        write_fixture(&input, b"safe");

        let plan = plan_copy_in(&source, "/workspace/input").expect("copy-in plan should build");
        let entry = plan
            .entries
            .iter()
            .find(|entry| matches!(entry.kind, CopyInEntryKind::File { .. }))
            .expect("planned file entry");
        let (len, identity) = match &entry.kind {
            CopyInEntryKind::File { len, identity } => (*len, *identity),
            CopyInEntryKind::Directory => panic!("expected file entry"),
        };

        fs::remove_file(&input).expect("remove planned file");
        write_fixture(&input, b"safe");

        let err = open_copy_in_file_checked(&entry.host_path, len, identity)
            .expect_err("replacement file identity should fail closed");

        assert_eq!(err.operation(), CopyPathOperation::CopyInSource);
        assert!(err.reason().contains("changed identity"));

        let _ = fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn copy_in_checked_open_rejects_parent_replaced_with_symlink_on_windows() {
        let root = temp_dir("checked-open-parent-symlink");
        let source = root.join("src");
        let nested = source.join("nested");
        fs::create_dir_all(&nested).expect("nested source dir");
        let input = nested.join("input.txt");
        write_fixture(&input, b"safe");

        let plan = plan_copy_in(&source, "/workspace/input").expect("copy-in plan should build");
        let entry = plan
            .entries
            .iter()
            .find(|entry| entry.guest_path == "/workspace/input/nested/input.txt")
            .expect("planned nested file entry");
        let (len, identity) = match &entry.kind {
            CopyInEntryKind::File { len, identity } => (*len, *identity),
            CopyInEntryKind::Directory => panic!("expected file entry"),
        };

        fs::remove_dir_all(&nested).expect("remove planned parent");
        let outside = root.join("outside");
        fs::create_dir_all(&outside).expect("outside dir");
        write_fixture(&outside.join("input.txt"), b"safe");
        match std::os::windows::fs::symlink_dir(&outside, &nested) {
            Ok(()) => {}
            Err(error) if error.raw_os_error() == Some(1314) => {
                eprintln!(
                    "skipping Windows parent symlink replacement fixture because the runner lacks symlink privilege: {error}"
                );
                let _ = fs::remove_dir_all(root);
                return;
            }
            Err(error) => panic!("directory symlink fixture: {error}"),
        }

        let err = open_copy_in_file_checked(&entry.host_path, len, identity)
            .expect_err("parent symlink replacement should fail closed");

        assert_eq!(err.operation(), CopyPathOperation::CopyInSource);
        assert!(
            err.reason().contains("changed identity")
                || err.reason().contains("symlinks and junction")
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn copy_out_destination_rejects_existing_path_without_overwrite() {
        let root = temp_dir("destination");
        let destination = root.join("out.txt");
        write_fixture(&destination, b"old");

        let err = validate_copy_out_destination(&destination, false)
            .expect_err("existing destination without overwrite should fail");

        assert!(err.reason().contains("already exists"));

        let ok = validate_copy_out_destination(&destination, true)
            .expect("explicit overwrite should be accepted");
        assert!(ok.exists);
        assert!(ok.overwrite);

        let _ = fs::remove_dir_all(root);
    }

    fn write_fixture(path: &Path, content: &[u8]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("parent dir");
        }
        let mut file = File::create(path).expect("fixture file");
        file.write_all(content).expect("fixture content");
    }

    fn temp_dir(label: &str) -> PathBuf {
        let nonce = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        #[cfg(windows)]
        let base = std::env::temp_dir();
        #[cfg(not(windows))]
        let base = PathBuf::from("/private/tmp");
        let root = base.join(format!(
            "lsb-windows-copy-{label}-{}-{nonce}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        root
    }
}
