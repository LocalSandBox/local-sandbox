use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use lsb_service_proto::limits::MAX_MOUNT_WINDOWS_UTF16;
use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegGetValueW, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
    RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ,
};

use super::policy::validate_lexical;

const PROFILE_LIST_KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
const PROFILE_IMAGE_PATH: &str = "ProfileImagePath";
const MAX_PROFILE_KEYS: u32 = 1_024;
const MAX_PROFILE_KEY_UTF16: usize = 256;

pub(super) fn profile_list_roots() -> Result<Vec<PathBuf>> {
    let key = RegistryKey::open_local_machine(PROFILE_LIST_KEY)?;
    enumerate_profile_roots(&key)
}

fn enumerate_profile_roots(key: &RegistryKey) -> Result<Vec<PathBuf>> {
    let mut profiles: Vec<PathBuf> = Vec::new();
    for index in 0..=MAX_PROFILE_KEYS {
        let Some(subkey) = enum_subkey(key, index)? else {
            profiles.sort_by_key(|path| normalized(path));
            profiles.dedup_by(|left, right| normalized(left) == normalized(right));
            return Ok(profiles);
        };
        if index == MAX_PROFILE_KEYS {
            bail!("ProfileList exceeds {MAX_PROFILE_KEYS} entries");
        }
        profiles.push(read_profile_path(key, &subkey)?);
    }
    unreachable!("bounded ProfileList enumeration always returns or fails")
}

fn enum_subkey(key: &RegistryKey, index: u32) -> Result<Option<Vec<u16>>> {
    let mut name = [0u16; MAX_PROFILE_KEY_UTF16];
    let mut name_len = name.len() as u32;
    let status = unsafe {
        RegEnumKeyExW(
            key.0,
            index,
            name.as_mut_ptr(),
            &mut name_len,
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if status == ERROR_NO_MORE_ITEMS {
        return Ok(None);
    }
    if status == ERROR_MORE_DATA {
        bail!("ProfileList contains an overlong subkey name");
    }
    if status != 0 {
        bail!("enumerate protected ProfileList failed with {status}");
    }
    let name_len = usize::try_from(name_len).context("ProfileList name length overflow")?;
    if name_len == 0 || name_len >= name.len() {
        bail!("ProfileList contains an invalid subkey name");
    }
    let mut subkey = name[..name_len].to_vec();
    subkey.push(0);
    Ok(Some(subkey))
}

fn read_profile_path(key: &RegistryKey, subkey: &[u16]) -> Result<PathBuf> {
    let value = wide(PROFILE_IMAGE_PATH);
    let flags = RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ;
    let mut bytes = 0u32;
    let status = unsafe {
        RegGetValueW(
            key.0,
            subkey.as_ptr(),
            value.as_ptr(),
            flags,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut bytes,
        )
    };
    if status != 0 {
        bail!("query protected ProfileImagePath size failed with {status}");
    }
    let max_bytes = (MAX_MOUNT_WINDOWS_UTF16 as u32 + 1)
        .checked_mul(2)
        .context("ProfileImagePath byte bound overflow")?;
    if bytes < 2 || bytes > max_bytes || !bytes.is_multiple_of(2) {
        bail!("protected ProfileImagePath has an invalid size");
    }
    let mut path = vec![0u16; bytes as usize / 2];
    let mut actual_bytes = bytes;
    let status = unsafe {
        RegGetValueW(
            key.0,
            subkey.as_ptr(),
            value.as_ptr(),
            flags,
            std::ptr::null_mut(),
            path.as_mut_ptr().cast(),
            &mut actual_bytes,
        )
    };
    if status != 0 {
        bail!("read protected ProfileImagePath failed with {status}");
    }
    if actual_bytes < 2 || actual_bytes > bytes || !actual_bytes.is_multiple_of(2) {
        bail!("protected ProfileImagePath changed size while it was read");
    }
    path.truncate(actual_bytes as usize / 2);
    profile_path_from_utf16(path)
}

fn profile_path_from_utf16(mut path: Vec<u16>) -> Result<PathBuf> {
    let terminator = path
        .iter()
        .position(|unit| *unit == 0)
        .context("protected ProfileImagePath is not NUL-terminated")?;
    path.truncate(terminator);
    if path.is_empty() {
        bail!("protected ProfileImagePath is empty");
    }
    let path = PathBuf::from(std::ffi::OsString::from_wide(&path));
    validate_lexical(&path).context("validate protected ProfileImagePath")?;
    Ok(path)
}

struct RegistryKey(HKEY);

impl RegistryKey {
    fn open_local_machine(path: &str) -> Result<Self> {
        let path = wide(path);
        let mut key = std::ptr::null_mut();
        let status =
            unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, KEY_READ, &mut key) };
        if status != 0 || key.is_null() {
            bail!("open protected ProfileList failed with {status}");
        }
        Ok(Self(key))
    }
}

impl Drop for RegistryKey {
    fn drop(&mut self) {
        unsafe {
            RegCloseKey(self.0);
        }
    }
}

fn normalized(path: &std::path::Path) -> String {
    path.as_os_str()
        .to_string_lossy()
        .trim_start_matches(r"\\?\")
        .trim_end_matches(['\\', '/'])
        .replace('/', "\\")
        .to_lowercase()
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_machine_profile_list_is_bounded_and_local() {
        let profiles = profile_list_roots().unwrap();
        assert!(!profiles.is_empty());
        assert!(profiles.len() <= MAX_PROFILE_KEYS as usize);
        for profile in profiles {
            validate_lexical(&profile).unwrap();
        }
    }

    #[test]
    fn effective_registry_string_requires_a_nonempty_terminated_local_path() {
        let mut path = r"D:\Profiles\alice".encode_utf16().collect::<Vec<_>>();
        path.extend([0, 'x' as u16]);
        assert_eq!(
            profile_path_from_utf16(path).unwrap(),
            PathBuf::from(r"D:\Profiles\alice")
        );
        assert!(profile_path_from_utf16(vec![0]).is_err());
        assert!(profile_path_from_utf16(r"D:\Profiles\alice".encode_utf16().collect()).is_err());
        let mut network = r"\\server\profiles\alice"
            .encode_utf16()
            .collect::<Vec<_>>();
        network.push(0);
        assert!(profile_path_from_utf16(network).is_err());
    }
}
