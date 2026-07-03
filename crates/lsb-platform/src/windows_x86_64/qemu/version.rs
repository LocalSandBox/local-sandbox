use std::path::Path;

use serde::Serialize;

use super::{QemuCommandRunner, QemuPreflightError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct QemuVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: Option<u32>,
    pub raw: String,
}

impl QemuVersion {
    pub(crate) fn parse(output: &[u8]) -> Option<Self> {
        let text = String::from_utf8_lossy(output);
        let raw = text.lines().next().unwrap_or("").trim().to_string();
        let (major, minor, patch) = parse_version_components(&text)?;
        Some(Self {
            major,
            minor,
            patch,
            raw,
        })
    }
}

pub(crate) fn probe_qemu_version<R>(
    runner: &R,
    qemu_path: &Path,
) -> Result<QemuVersion, QemuPreflightError>
where
    R: QemuCommandRunner,
{
    let output = runner.run(qemu_path, &["--version"]).map_err(|err| {
        QemuPreflightError::QemuCannotExecute {
            path: qemu_path.to_path_buf(),
            probe: "qemu-system-x86_64.exe --version",
            detail: format!("{} ({:?})", err.message, err.kind),
        }
    })?;

    if !output.status.success {
        return Err(QemuPreflightError::QemuCannotExecute {
            path: qemu_path.to_path_buf(),
            probe: "qemu-system-x86_64.exe --version",
            detail: format!("{}; output: {}", output.status, output.combined_excerpt()),
        });
    }

    QemuVersion::parse(&output.stdout).ok_or_else(|| QemuPreflightError::VersionOutputUnparseable {
        path: qemu_path.to_path_buf(),
        output_excerpt: output.combined_excerpt(),
    })
}

fn parse_version_components(text: &str) -> Option<(u32, u32, Option<u32>)> {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if !bytes[index].is_ascii_digit() {
            index += 1;
            continue;
        }

        let (major, after_major) = parse_number(bytes, index)?;
        if bytes.get(after_major) != Some(&b'.') {
            index = after_major + 1;
            continue;
        }

        let minor_start = after_major + 1;
        let (minor, after_minor) = parse_number(bytes, minor_start)?;
        let patch = if bytes.get(after_minor) == Some(&b'.') {
            let patch_start = after_minor + 1;
            let (patch, _) = parse_number(bytes, patch_start)?;
            Some(patch)
        } else {
            None
        };

        return Some((major, minor, patch));
    }
    None
}

fn parse_number(bytes: &[u8], start: usize) -> Option<(u32, usize)> {
    let mut end = start;
    while bytes.get(end).is_some_and(u8::is_ascii_digit) {
        end += 1;
    }
    if end == start {
        return None;
    }
    let value = std::str::from_utf8(&bytes[start..end]).ok()?.parse().ok()?;
    Some((value, end))
}
