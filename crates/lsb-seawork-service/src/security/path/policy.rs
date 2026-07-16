use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

pub const MAX_MOUNT_ENTRIES: u32 = 100_000;
pub const MAX_MOUNT_BYTES: u64 = 10 * 1024 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct MountPolicy {
    service_root: PathBuf,
}

impl MountPolicy {
    pub fn new(service_root: PathBuf) -> Result<Self> {
        if !service_root.is_absolute() {
            bail!("service root must be absolute");
        }
        Ok(Self { service_root })
    }

    pub fn service_root(&self) -> &Path {
        &self.service_root
    }
}

pub(super) fn validate_lexical(path: &Path) -> Result<()> {
    let value = path.as_os_str().to_string_lossy().replace('/', "\\");
    if value.contains('\0') || value.starts_with("\\\\") || value.starts_with("\\\\?\\UNC\\") {
        bail!("mount path must be a local drive path");
    }
    if value.starts_with("\\\\.\\") || value.contains("GLOBALROOT") {
        bail!("device paths are not eligible mount roots");
    }
    let lexical = value.strip_prefix("\\\\?\\").unwrap_or(&value);
    let bytes = lexical.as_bytes();
    if bytes.len() < 4 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'\\' {
        bail!("mount path must be an absolute drive path below the volume root");
    }
    if lexical[2..].contains(':') {
        bail!("alternate data stream syntax is not eligible for mounts");
    }
    if lexical.trim_end_matches('\\').len() == 2 {
        bail!("volume roots are not eligible mount roots");
    }
    if lexical.split('\\').any(|part| part == "." || part == "..") {
        bail!("mount path must not contain dot components");
    }
    Ok(())
}

pub(super) fn require_outside_protected_roots(
    path: &Path,
    protected_roots: &[PathBuf],
    profiles_root: Option<&Path>,
    caller_profile: Option<&Path>,
) -> Result<()> {
    if protected_roots.iter().any(|root| is_within(path, root)) {
        bail!("mount path is below a protected system or service root");
    }
    if let Some(profiles_root) = profiles_root {
        if is_within(path, profiles_root)
            && caller_profile.is_none_or(|profile| !is_within(path, profile))
        {
            bail!("mount path is below another user profile");
        }
    }
    Ok(())
}

fn is_within(path: &Path, root: &Path) -> bool {
    let normalize = |value: &Path| {
        value
            .as_os_str()
            .to_string_lossy()
            .trim_start_matches("\\\\?\\")
            .trim_end_matches(['\\', '/'])
            .replace('/', "\\")
            .to_lowercase()
    };
    let path = normalize(path);
    let root = normalize(root);
    path == root
        || path
            .strip_prefix(&root)
            .is_some_and(|suffix| suffix.starts_with('\\'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lexical_policy_rejects_non_local_and_ads_paths() {
        for path in [
            r"relative",
            r"C:\",
            r"\\server\share",
            r"\\.\C:",
            r"C:\work:file",
        ] {
            assert!(validate_lexical(Path::new(path)).is_err(), "{path}");
        }
        assert!(validate_lexical(Path::new(r"C:\Users\me\work")).is_ok());
    }

    #[test]
    fn protected_roots_are_case_insensitive_and_component_aware() {
        let roots = vec![PathBuf::from(r"C:\ProgramData")];
        assert!(require_outside_protected_roots(
            Path::new(r"c:\PROGRAMDATA\LocalSandbox"),
            &roots,
            None,
            None
        )
        .is_err());
        assert!(require_outside_protected_roots(
            Path::new(r"C:\ProgramDataElsewhere\work"),
            &roots,
            None,
            None
        )
        .is_ok());
    }

    #[test]
    fn only_the_callers_profile_is_eligible_below_users() {
        let profiles = Path::new(r"C:\Users");
        let caller = Path::new(r"C:\Users\alice");
        assert!(require_outside_protected_roots(
            Path::new(r"C:\Users\bob\work"),
            &[],
            Some(profiles),
            Some(caller)
        )
        .is_err());
        assert!(require_outside_protected_roots(
            Path::new(r"C:\Users\alice\work"),
            &[],
            Some(profiles),
            Some(caller)
        )
        .is_ok());
    }
}
