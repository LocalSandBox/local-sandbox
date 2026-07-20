use std::ffi::c_void;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr;

use anyhow::{bail, Result};
use windows_sys::Win32::Foundation::{GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Cryptography::{
    CertCloseStore, CertFindCertificateInStore, CertFreeCertificateContext,
    CertGetCertificateContextProperty, CryptMsgClose, CryptMsgGetParam, CryptQueryObject,
    CERT_FIND_SUBJECT_CERT, CERT_INFO, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
    CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_OBJECT_FILE, CERT_SHA1_HASH_PROP_ID,
    CERT_SHA256_HASH_PROP_ID, CMSG_SIGNER_INFO, CMSG_SIGNER_INFO_PARAM, HCERTSTORE,
};
use windows_sys::Win32::Security::WinTrust::{
    WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
    WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE,
    WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
    WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetFileInformationByHandle, GetFinalPathNameByHandleW, BY_HANDLE_FILE_INFORMATION,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_NAME_NORMALIZED, FILE_SHARE_READ, OPEN_EXISTING, VOLUME_NAME_DOS,
};
use windows_sys::Win32::System::Threading::QueryFullProcessImageNameW;

pub fn query_process_image(process: &OwnedHandle) -> Result<PathBuf> {
    let mut capacity = 32_768u32;
    let mut buffer = vec![0u16; capacity as usize];
    if unsafe {
        QueryFullProcessImageNameW(
            process.as_raw_handle() as HANDLE,
            0,
            buffer.as_mut_ptr(),
            &mut capacity,
        )
    } == 0
    {
        bail!(
            "QueryFullProcessImageNameW failed: {}",
            std::io::Error::last_os_error()
        );
    }
    buffer.truncate(capacity as usize);
    Ok(PathBuf::from(std::ffi::OsString::from_wide(&buffer)))
}

pub fn require_absolute_image(image: &Path) -> Result<()> {
    if !image.is_absolute()
        || image
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        bail!("client image path is not an absolute normalized path");
    }
    Ok(())
}

pub fn pin_process_image(process: &OwnedHandle) -> Result<(PathBuf, OwnedHandle)> {
    let first_path = query_process_image(process)?;
    require_absolute_image(&first_path)?;
    let held_image = open_image_for_trust(&first_path)?;
    let second_path = query_process_image(process)?;
    if !windows_path_eq(&first_path, &second_path) {
        bail!("client process image path changed while it was being pinned");
    }
    Ok((second_path, held_image))
}

pub fn authorize_maintenance_image(
    image: &Path,
    roots: &[String],
    publisher_thumbprints: &[String],
) -> Result<()> {
    let held_image = open_image_for_trust(image)?;
    authorize_maintenance_image_handle(image, &held_image, roots, publisher_thumbprints)
}

pub fn authorize_maintenance_image_handle(
    image: &Path,
    held_image: &OwnedHandle,
    roots: &[String],
    publisher_thumbprints: &[String],
) -> Result<()> {
    require_absolute_image(image)?;
    if roots.is_empty() || publisher_thumbprints.is_empty() {
        bail!("maintenance image policy is not configured");
    }
    if !roots.iter().any(|root| is_within(image, Path::new(root))) {
        bail!("client image is outside configured maintenance roots");
    }

    verify_authenticode(image, held_image)?;
    let signer = signer_thumbprints(image)?;
    if !publisher_thumbprints.iter().any(|allowed| {
        signer
            .iter()
            .any(|actual| allowed.eq_ignore_ascii_case(actual))
    }) {
        bail!("client image signer is not in the publisher allowlist");
    }
    Ok(())
}

pub fn open_image_for_trust(image: &Path) -> Result<OwnedHandle> {
    require_absolute_image(image)?;
    let wide = wide_path(image)?;
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        bail!(
            "open client image without write/delete sharing failed: {}",
            std::io::Error::last_os_error()
        );
    }
    let held = unsafe { OwnedHandle::from_raw_handle(raw as _) };
    require_regular_non_reparse_image(&held)?;
    let final_path = final_path(&held)?;
    if !windows_path_eq(&final_path, image) {
        bail!("client image handle final path does not match the process image path");
    }
    Ok(held)
}

fn require_regular_non_reparse_image(image: &OwnedHandle) -> Result<()> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(image.as_raw_handle() as HANDLE, &mut info) } == 0 {
        bail!(
            "inspect client image handle failed: {}",
            std::io::Error::last_os_error()
        );
    }
    if info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || info.nNumberOfLinks != 1
    {
        bail!("client image is not a single-link regular non-reparse file");
    }
    Ok(())
}

fn final_path(handle: &OwnedHandle) -> Result<PathBuf> {
    let raw = handle.as_raw_handle() as HANDLE;
    let flags = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS;
    let required = unsafe { GetFinalPathNameByHandleW(raw, ptr::null_mut(), 0, flags) };
    if required == 0 {
        bail!(
            "query client image final path size failed: {}",
            std::io::Error::last_os_error()
        );
    }
    let mut buffer = vec![0u16; required as usize + 1];
    let length =
        unsafe { GetFinalPathNameByHandleW(raw, buffer.as_mut_ptr(), buffer.len() as u32, flags) };
    if length == 0 || length as usize >= buffer.len() {
        bail!(
            "query client image final path failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(PathBuf::from(std::ffi::OsString::from_wide(
        &buffer[..length as usize],
    )))
}

fn is_within(path: &Path, root: &Path) -> bool {
    let path = normalized_windows_path(path);
    let root = normalized_windows_path(root)
        .trim_end_matches('\\')
        .to_string();
    path == root
        || path
            .strip_prefix(&root)
            .is_some_and(|suffix| suffix.starts_with('\\'))
}

fn normalized_windows_path(path: &Path) -> String {
    let mut path = path.as_os_str().to_string_lossy().replace('/', "\\");
    if let Some(rest) = path.strip_prefix(r"\\?\UNC\") {
        path = format!(r"\\{rest}");
    } else if let Some(rest) = path.strip_prefix(r"\\?\") {
        path = rest.to_string();
    }
    path.trim_end_matches('\\').to_lowercase()
}

fn windows_path_eq(left: &Path, right: &Path) -> bool {
    normalized_windows_path(left) == normalized_windows_path(right)
}

fn wide_path(path: &Path) -> Result<Vec<u16>> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        bail!("image path contains NUL");
    }
    wide.push(0);
    Ok(wide)
}

fn verify_authenticode(image: &Path, held_image: &OwnedHandle) -> Result<()> {
    let wide = wide_path(image)?;
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: wide.as_ptr(),
        hFile: held_image.as_raw_handle() as HANDLE,
        pgKnownSubject: ptr::null_mut(),
    };
    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 { pFile: &mut file },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
        ..WINTRUST_DATA::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let status = unsafe {
        WinVerifyTrust(
            ptr::null_mut(),
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast(),
        )
    };
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        WinVerifyTrust(
            ptr::null_mut(),
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast(),
        )
    };
    if status != 0 {
        bail!("WinVerifyTrust rejected client image: 0x{status:08x}");
    }
    Ok(())
}

fn signer_thumbprints(image: &Path) -> Result<[String; 2]> {
    let wide = wide_path(image)?;
    let mut encoding = 0;
    let mut store: HCERTSTORE = ptr::null_mut();
    let mut message = ptr::null_mut();
    if unsafe {
        CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            wide.as_ptr().cast(),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            &mut encoding,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut store,
            &mut message,
            ptr::null_mut(),
        )
    } == 0
    {
        bail!(
            "CryptQueryObject failed: {}",
            std::io::Error::last_os_error()
        );
    }
    let resources = CryptResources { store, message };

    let mut signer_size = 0;
    if unsafe {
        CryptMsgGetParam(
            resources.message,
            CMSG_SIGNER_INFO_PARAM,
            0,
            ptr::null_mut(),
            &mut signer_size,
        )
    } == 0
        || signer_size < std::mem::size_of::<CMSG_SIGNER_INFO>() as u32
    {
        bail!("signed image has no valid primary signer information");
    }
    let word_count = (signer_size as usize).div_ceil(std::mem::size_of::<usize>());
    let mut signer_storage = vec![0usize; word_count];
    if unsafe {
        CryptMsgGetParam(
            resources.message,
            CMSG_SIGNER_INFO_PARAM,
            0,
            signer_storage.as_mut_ptr().cast(),
            &mut signer_size,
        )
    } == 0
    {
        bail!(
            "CryptMsgGetParam failed: {}",
            std::io::Error::last_os_error()
        );
    }
    let signer = unsafe { &*signer_storage.as_ptr().cast::<CMSG_SIGNER_INFO>() };
    let mut certificate_info = CERT_INFO {
        Issuer: signer.Issuer,
        SerialNumber: signer.SerialNumber,
        ..CERT_INFO::default()
    };
    let certificate = unsafe {
        CertFindCertificateInStore(
            resources.store,
            encoding,
            0,
            CERT_FIND_SUBJECT_CERT,
            (&mut certificate_info as *mut CERT_INFO).cast(),
            ptr::null(),
        )
    };
    if certificate.is_null() {
        bail!("embedded primary signer certificate was not found");
    }
    let certificate = Certificate(certificate);
    Ok([
        certificate_hash(certificate.0, CERT_SHA1_HASH_PROP_ID)?,
        certificate_hash(certificate.0, CERT_SHA256_HASH_PROP_ID)?,
    ])
}

fn certificate_hash(
    certificate: *const windows_sys::Win32::Security::Cryptography::CERT_CONTEXT,
    property: u32,
) -> Result<String> {
    let mut size = 0;
    if unsafe {
        CertGetCertificateContextProperty(certificate, property, ptr::null_mut(), &mut size)
    } == 0
        || size == 0
        || size > 64
    {
        bail!("query signer certificate hash size failed");
    }
    let mut bytes = vec![0u8; size as usize];
    if unsafe {
        CertGetCertificateContextProperty(
            certificate,
            property,
            bytes.as_mut_ptr().cast(),
            &mut size,
        )
    } == 0
    {
        bail!("read signer certificate hash failed");
    }
    bytes.truncate(size as usize);
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

struct CryptResources {
    store: HCERTSTORE,
    message: *mut c_void,
}

impl Drop for CryptResources {
    fn drop(&mut self) {
        unsafe {
            if !self.message.is_null() {
                CryptMsgClose(self.message);
            }
            if !self.store.is_null() {
                CertCloseStore(self.store, 0);
            }
        }
    }
}

struct Certificate(*const windows_sys::Win32::Security::Cryptography::CERT_CONTEXT);

impl Drop for Certificate {
    fn drop(&mut self) {
        unsafe { CertFreeCertificateContext(self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcessId, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    #[test]
    fn maintenance_roots_are_case_insensitive_and_component_aware() {
        assert!(is_within(
            Path::new(r"C:\Program Files\LocalSandbox\maintenance.exe"),
            Path::new(r"c:\program files\localsandbox")
        ));
        assert!(!is_within(
            Path::new(r"C:\Program Files\LocalSandbox-Evil\maintenance.exe"),
            Path::new(r"C:\Program Files\LocalSandbox")
        ));
    }

    #[test]
    fn handle_and_process_paths_compare_in_normalized_form() {
        assert!(windows_path_eq(
            Path::new(r"\\?\C:\Program Files\SeaWork\client.exe"),
            Path::new(r"c:/program files/seawork/client.exe")
        ));
        assert!(windows_path_eq(
            Path::new(r"\\?\UNC\server\share\client.exe"),
            Path::new(r"\\server\share\client.exe")
        ));
    }

    #[test]
    fn current_process_image_is_pinned_to_its_final_path() {
        let raw =
            unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, GetCurrentProcessId()) };
        assert!(!raw.is_null(), "open current process");
        let process = unsafe { OwnedHandle::from_raw_handle(raw as _) };
        let (reported_path, held_image) = pin_process_image(&process).expect("pin current image");
        let held_path = final_path(&held_image).expect("query held image path");
        assert!(windows_path_eq(&reported_path, &held_path));
    }

    #[test]
    fn missing_maintenance_policy_fails_closed_before_platform_trust() {
        assert!(authorize_maintenance_image(Path::new(r"C:\maintenance.exe"), &[], &[]).is_err());
    }
}
