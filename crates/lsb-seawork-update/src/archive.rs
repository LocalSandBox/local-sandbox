use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use zip::ZipArchive;

const MAX_ARCHIVE_ENTRIES: usize = 20_002;
const MAX_ARCHIVE_FILES: usize = 10_002;
const MAX_EXPANDED_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_PATH_BYTES: usize = 512;
const MAX_DIRECTORY_DEPTH: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveExtraction {
    pub files: usize,
    pub expanded_bytes: u64,
    pub archive_sha256: String,
}

#[derive(Debug, Clone)]
struct EntryPlan {
    index: usize,
    relative: String,
    is_directory: bool,
    size: u64,
}

/// Extracts an update ZIP into a destination that must not already exist.
///
/// The complete central directory is validated before any archive payload is written.
/// A failed extraction removes only the destination created by this invocation.
pub fn extract_zip_archive(archive_path: &Path, destination: &Path) -> Result<ArchiveExtraction> {
    require_new_destination(destination)?;
    let result = extract_owned_zip_archive(archive_path, destination);
    if result.is_err() {
        let _ = fs::remove_dir_all(destination);
    }
    result
}

fn extract_owned_zip_archive(archive_path: &Path, destination: &Path) -> Result<ArchiveExtraction> {
    let archive_sha256 = sha256_file(archive_path)?;
    let file = File::open(archive_path)
        .with_context(|| format!("open update archive {}", archive_path.display()))?;
    let mut archive = ZipArchive::new(file).context("parse update ZIP central directory")?;
    let plans = plan_entries(&mut archive)?;
    fs::create_dir(destination)
        .with_context(|| format!("create exclusive staging root {}", destination.display()))?;

    let mut copied = 0u64;
    let mut files = 0usize;
    for plan in plans {
        let output = join_relative(destination, &plan.relative);
        if plan.is_directory {
            create_directory_chain(destination, &output)?;
            continue;
        }
        let parent = output.parent().context("archive file has no parent")?;
        create_directory_chain(destination, parent)?;
        let source = archive
            .by_index(plan.index)
            .with_context(|| format!("reopen validated ZIP entry {}", plan.relative))?;
        if !source.is_file() || source.size() != plan.size {
            bail!("ZIP entry metadata changed during extraction");
        }
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&output)
            .with_context(|| format!("create extracted file {}", output.display()))?;
        let mut writer = BufWriter::new(file);
        let written = io::copy(&mut source.take(plan.size.saturating_add(1)), &mut writer)?;
        if written != plan.size {
            bail!("ZIP entry size differs from its validated declaration");
        }
        writer.flush()?;
        writer.get_ref().sync_all()?;
        copied = copied
            .checked_add(written)
            .context("expanded update archive size overflow")?;
        if copied > MAX_EXPANDED_BYTES {
            bail!("expanded update archive exceeds the compiled byte limit");
        }
        files += 1;
    }

    Ok(ArchiveExtraction {
        files,
        expanded_bytes: copied,
        archive_sha256,
    })
}

fn plan_entries<R: Read + std::io::Seek>(archive: &mut ZipArchive<R>) -> Result<Vec<EntryPlan>> {
    if archive.is_empty() || archive.len() > MAX_ARCHIVE_ENTRIES {
        bail!("ZIP entry count is outside the compiled limit");
    }
    let mut plans = Vec::with_capacity(archive.len());
    let mut folded = BTreeMap::<String, String>::new();
    let mut files = 0usize;
    let mut expanded = 0u64;
    for index in 0..archive.len() {
        let entry = archive.by_index(index)?;
        let raw_name = std::str::from_utf8(entry.name_raw())
            .context("ZIP entry name is not canonical UTF-8")?;
        let is_directory = entry.is_dir();
        let relative = validate_archive_path(raw_name, is_directory)?;
        validate_entry_kind(&entry, is_directory)?;
        let folded_name = relative.to_ascii_lowercase();
        if let Some(existing) = folded.insert(folded_name, relative.clone()) {
            bail!("case-insensitive ZIP path collision: {existing} and {relative}");
        }
        if !is_directory {
            files += 1;
            if files > MAX_ARCHIVE_FILES {
                bail!("ZIP file count exceeds the compiled limit");
            }
            expanded = expanded
                .checked_add(entry.size())
                .context("expanded update archive size overflow")?;
            if expanded > MAX_EXPANDED_BYTES {
                bail!("expanded update archive exceeds the compiled byte limit");
            }
        }
        plans.push(EntryPlan {
            index,
            relative,
            is_directory,
            size: entry.size(),
        });
    }
    Ok(plans)
}

fn validate_entry_kind<R: Read>(
    entry: &zip::read::ZipFile<'_, R>,
    is_directory: bool,
) -> Result<()> {
    if entry.is_symlink() || (!is_directory && !entry.is_file()) {
        bail!("ZIP contains a link or nonregular entry");
    }
    if let Some(mode) = entry.unix_mode() {
        let kind = mode & 0o170000;
        if kind != 0 && kind != 0o100000 && !(is_directory && kind == 0o040000) {
            bail!("ZIP contains a special Unix entry");
        }
    }
    Ok(())
}

fn validate_archive_path(raw: &str, is_directory: bool) -> Result<String> {
    if raw.is_empty()
        || raw.len() > MAX_PATH_BYTES
        || raw.starts_with(['/', '\\'])
        || raw.contains(['\\', ':', '\0'])
    {
        bail!("ZIP contains an unsafe path");
    }
    let relative = if is_directory {
        raw.strip_suffix('/')
            .context("ZIP directory lacks a trailing slash")?
    } else {
        raw
    };
    let components = relative.split('/').collect::<Vec<_>>();
    if relative.is_empty()
        || components.len() > MAX_DIRECTORY_DEPTH + 1
        || components
            .iter()
            .any(|part| part.is_empty() || *part == "." || *part == "..")
    {
        bail!("ZIP contains an unsafe path");
    }
    Ok(relative.to_string())
}

fn require_new_destination(destination: &Path) -> Result<()> {
    if !destination.is_absolute() {
        bail!("staging destination must be absolute");
    }
    match fs::symlink_metadata(destination) {
        Ok(_) => bail!("staging destination already exists"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let parent = destination
        .parent()
        .context("staging destination has no parent")?;
    let metadata = fs::symlink_metadata(parent)
        .with_context(|| format!("inspect staging parent {}", parent.display()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || has_reparse_attribute(&metadata) {
        bail!("staging parent is not a trusted regular directory");
    }
    Ok(())
}

fn create_directory_chain(root: &Path, directory: &Path) -> Result<()> {
    let relative = directory
        .strip_prefix(root)
        .context("archive directory escapes staging root")?;
    let mut current = root.to_path_buf();
    for part in relative.components() {
        current.push(part.as_os_str());
        match fs::create_dir(&current) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let metadata = fs::symlink_metadata(&current)?;
                if !metadata.is_dir()
                    || metadata.file_type().is_symlink()
                    || has_reparse_attribute(&metadata)
                {
                    bail!("archive path crosses a nonregular directory");
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn join_relative(root: &Path, relative: &str) -> PathBuf {
    relative
        .split('/')
        .fold(root.to_path_buf(), |path, part| path.join(part))
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut reader = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(windows)]
fn has_reparse_attribute(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn has_reparse_attribute(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    static TEST_ID: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn extracts_only_new_closed_regular_trees() {
        let root = test_root();
        fs::create_dir_all(&root).unwrap();
        let archive = root.join("valid.zip");
        write_zip(&archive, &[("LocalSandbox/runtime/VERSION", b"0.5.0")]);
        let destination = root.join("staging");
        let report = extract_zip_archive(&archive, &destination).unwrap();
        assert_eq!(report.files, 1);
        assert_eq!(report.expanded_bytes, 5);
        assert_eq!(
            fs::read(destination.join("LocalSandbox/runtime/VERSION")).unwrap(),
            b"0.5.0"
        );
        assert!(extract_zip_archive(&archive, &destination).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_escape_duplicate_case_collision_and_symlink_before_writing() {
        for entries in [
            vec![("../escape", b"x".as_slice()), ("safe", b"y".as_slice())],
            vec![("A/file", b"x".as_slice()), ("a/File", b"y".as_slice())],
            vec![("C:ads", b"x".as_slice())],
            vec![("a\\b", b"x".as_slice())],
        ] {
            let root = test_root();
            fs::create_dir_all(&root).unwrap();
            let archive = root.join("hostile.zip");
            write_zip(&archive, &entries);
            let destination = root.join("staging");
            assert!(extract_zip_archive(&archive, &destination).is_err());
            assert!(!destination.exists());
            fs::remove_dir_all(root).unwrap();
        }

        let root = test_root();
        fs::create_dir_all(&root).unwrap();
        let archive = root.join("symlink.zip");
        let file = File::create(&archive).unwrap();
        let mut writer = ZipWriter::new(file);
        writer
            .add_symlink(
                "link",
                "../outside",
                SimpleFileOptions::default().unix_permissions(0o777),
            )
            .unwrap();
        writer.finish().unwrap();
        let destination = root.join("staging");
        assert!(extract_zip_archive(&archive, &destination).is_err());
        assert!(!destination.exists());
        fs::remove_dir_all(root).unwrap();
    }

    fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
        let file = File::create(path).unwrap();
        let mut writer = ZipWriter::new(file);
        for (name, bytes) in entries {
            writer
                .start_file(*name, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(bytes).unwrap();
        }
        writer.finish().unwrap();
    }

    fn test_root() -> PathBuf {
        let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("lsb-update-archive-{}-{id}", std::process::id()))
    }
}
