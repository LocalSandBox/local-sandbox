use std::ffi::c_void;
use std::ffi::CStr;
use std::fs::{File, OpenOptions};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::ptr;

use anyhow::{bail, Context, Result};
use windows_sys::Win32::Foundation::{LocalFree, GENERIC_ALL, GENERIC_WRITE, HANDLE};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetSecurityInfo, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::Cryptography::Catalog::{
    CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2, CryptCATAdminReleaseContext,
};
use windows_sys::Win32::Security::Cryptography::{
    CertCloseStore, CertFindCertificateInStore, CertFreeCertificateContext,
    CertGetCertificateContextProperty, CryptMsgClose, CryptMsgGetParam, CryptQueryObject,
    CERT_FIND_SUBJECT_CERT, CERT_INFO, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY,
    CERT_QUERY_OBJECT_FILE, CERT_SHA256_HASH_PROP_ID, CMSG_SIGNER_INFO, CMSG_SIGNER_INFO_PARAM,
    HCERTSTORE,
};
use windows_sys::Win32::Security::WinTrust::{
    WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA,
    WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG,
    WTD_CHOICE_FILE, WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, WTD_REVOKE_NONE,
    WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};
use windows_sys::Win32::Security::{
    IsValidAcl, IsValidSid, ACE_HEADER, ACE_INHERITED_OBJECT_TYPE_PRESENT, ACE_OBJECT_TYPE_PRESENT,
    DACL_SECURITY_INFORMATION, INHERIT_ONLY_ACE, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    PSID,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_APPEND_DATA, FILE_DELETE_CHILD,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
    FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA, WRITE_DAC, WRITE_OWNER,
};
use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_ALLOWED_COMPOUND_ACE_TYPE,
    ACCESS_ALLOWED_OBJECT_ACE_TYPE,
};

use crate::PackageVerification;

const TRUSTED_INSTALLER_SID: &str =
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
const WRITE_LIKE_ACCESS: u32 = GENERIC_ALL
    | GENERIC_WRITE
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER
    | FILE_ADD_FILE
    | FILE_ADD_SUBDIRECTORY
    | FILE_APPEND_DATA
    | FILE_DELETE_CHILD
    | FILE_WRITE_ATTRIBUTES
    | FILE_WRITE_DATA
    | FILE_WRITE_EA;

pub fn verify_windows_file_publisher(
    path: &Path,
    allowed_publishers_sha256: &[String],
) -> Result<String> {
    validate_publishers(allowed_publishers_sha256)?;
    let file = pin_file(path)?;
    require_protected_handle(&file)?;
    verify_file_trust(path, &file)?;
    let signer = signer_sha256_thumbprint(path, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED)?;
    if !allowed_publishers_sha256
        .iter()
        .any(|allowed| signer.eq_ignore_ascii_case(allowed))
    {
        bail!("signed file publisher is outside the compiled allowlist");
    }
    Ok(signer)
}

pub fn verify_windows_file_protection(path: &Path) -> Result<()> {
    let file = pin_file(path)?;
    require_protected_handle(&file)
}

pub fn verify_windows_directory_protection(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    use std::os::windows::fs::MetadataExt;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.file_attributes() & 0x400 != 0
    {
        bail!("protected package directory is not a regular non-reparse directory");
    }
    let directory = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .with_context(|| format!("pin protected package directory {}", path.display()))?;
    let pinned = directory.metadata()?;
    if !pinned.is_dir() || pinned.file_attributes() & 0x400 != 0 {
        bail!("pinned package directory has an unsafe type or reparse attribute");
    }
    require_protected_handle(&directory)
}

pub fn verify_windows_package(
    root: &Path,
    report: &PackageVerification,
    allowed_publishers_sha256: &[String],
) -> Result<()> {
    validate_publishers(allowed_publishers_sha256)?;
    let expected = &report.publisher.sha256_thumbprint;
    if !allowed_publishers_sha256
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(expected))
    {
        bail!("bundle manifest publisher is outside the compiled allowlist");
    }

    let catalog_path = root.join("manifests/LocalSandboxSeaWork.cat");
    let catalog = pin_file(&catalog_path)?;
    require_protected_handle(&catalog)?;
    verify_file_trust(&catalog_path, &catalog)?;
    require_signer(
        &catalog_path,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
        expected,
        allowed_publishers_sha256,
    )?;

    let admin = CatalogAdmin::sha256()?;
    for relative in &report.catalog_members {
        let member_path = relative
            .split('/')
            .fold(root.to_path_buf(), |path, part| path.join(part));
        let member =
            pin_file(&member_path).with_context(|| format!("pin catalog member {relative}"))?;
        require_protected_handle(&member)?;
        // WinTrust cannot map a zero-length file and returns ERROR_FILE_INVALID even when the
        // empty-file hash is present in the signed catalog. The catalog-authenticated bundle
        // manifest already binds every member's path, size, and SHA-256, and structural
        // verification checked those values before reaching this platform verification step.
        if member.metadata()?.len() == 0 {
            continue;
        }
        verify_catalog_member(&admin, &catalog_path, &member_path, &member)
            .with_context(|| format!("verify signed catalog member {relative}"))?;
    }

    let service_path = root.join("bin/localsandbox-seawork-service.exe");
    let service = pin_file(&service_path)?;
    require_protected_handle(&service)?;
    verify_file_trust(&service_path, &service)?;
    require_signer(
        &service_path,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        expected,
        allowed_publishers_sha256,
    )?;
    Ok(())
}

fn validate_publishers(publishers: &[String]) -> Result<()> {
    if publishers.is_empty()
        || publishers.len() > 2
        || publishers.iter().any(|value| !is_sha256(value))
        || (publishers.len() == 2 && publishers[0].eq_ignore_ascii_case(&publishers[1]))
    {
        bail!("compiled publisher policy is invalid");
    }
    Ok(())
}

fn pin_file(path: &Path) -> Result<File> {
    let metadata = std::fs::symlink_metadata(path)?;
    use std::os::windows::fs::MetadataExt;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.file_attributes() & 0x400 != 0
    {
        bail!("trusted package member is not a regular non-reparse file");
    }
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
        .with_context(|| format!("pin trusted package member {}", path.display()))
}

fn require_protected_handle(file: &File) -> Result<()> {
    let mut owner: PSID = ptr::null_mut();
    let mut dacl = ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 || descriptor.is_null() {
        bail!("query protected package security failed with {status}");
    }
    let _descriptor = LocalSecurityDescriptor(descriptor);
    if owner.is_null() || !is_protected_sid(owner)? {
        bail!("package object owner is not a protected principal");
    }
    if dacl.is_null() || unsafe { IsValidAcl(dacl) } == 0 {
        bail!("package object DACL is null or invalid");
    }
    let ace_count = unsafe { (*dacl).AceCount as u32 };
    for index in 0..ace_count {
        let mut raw = ptr::null_mut();
        if unsafe { windows_sys::Win32::Security::GetAce(dacl, index, &mut raw) } == 0
            || raw.is_null()
        {
            bail!("package DACL contains an unreadable ACE");
        }
        let header = unsafe { &*(raw as *const ACE_HEADER) };
        if header.AceSize < 8 {
            bail!("package DACL contains a short ACE");
        }
        if header.AceFlags as u32 & INHERIT_ONLY_ACE != 0 {
            continue;
        }
        let mask = unsafe { ptr::read_unaligned((raw as *const u8).add(4).cast::<u32>()) };
        if mask & WRITE_LIKE_ACCESS == 0 {
            continue;
        }
        let sid = match header.AceType as u32 {
            ACCESS_ALLOWED_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_ACE_TYPE => ace_sid(raw, header, 8)?,
            ACCESS_ALLOWED_OBJECT_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE => {
                object_ace_sid(raw, header)?
            }
            ACCESS_ALLOWED_COMPOUND_ACE_TYPE => {
                bail!("package DACL contains a compound write grant")
            }
            _ => continue,
        };
        if !is_protected_sid(sid)? {
            bail!("package object is writable by an untrusted principal");
        }
    }
    Ok(())
}

fn object_ace_sid(raw: *mut c_void, header: &ACE_HEADER) -> Result<PSID> {
    if header.AceSize < 12 {
        bail!("package DACL contains a short object ACE");
    }
    let flags = unsafe { ptr::read_unaligned((raw as *const u8).add(8).cast::<u32>()) };
    let mut offset = 12usize;
    if flags & ACE_OBJECT_TYPE_PRESENT != 0 {
        offset += 16;
    }
    if flags & ACE_INHERITED_OBJECT_TYPE_PRESENT != 0 {
        offset += 16;
    }
    ace_sid(raw, header, offset)
}

fn ace_sid(raw: *mut c_void, header: &ACE_HEADER, offset: usize) -> Result<PSID> {
    let ace_size = header.AceSize as usize;
    if offset
        .checked_add(8)
        .is_none_or(|minimum| minimum > ace_size)
    {
        bail!("package DACL contains a short allow ACE");
    }
    let sid_bytes = unsafe { (raw as *mut u8).add(offset) };
    let count = unsafe { *sid_bytes.add(1) as usize };
    let sid_size = 8usize
        .checked_add(count.checked_mul(4).context("package SID size overflow")?)
        .context("package SID size overflow")?;
    if offset
        .checked_add(sid_size)
        .is_none_or(|end| end > ace_size)
    {
        bail!("package DACL contains a truncated SID");
    }
    let sid = sid_bytes.cast();
    if unsafe { IsValidSid(sid) } == 0 {
        bail!("package DACL contains an invalid SID");
    }
    Ok(sid)
}

fn is_protected_sid(sid: PSID) -> Result<bool> {
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        bail!("package descriptor contains an invalid SID");
    }
    let mut raw = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut raw) } == 0 || raw.is_null() {
        return Err(std::io::Error::last_os_error()).context("convert package SID");
    }
    let Some(length) = (0..184usize).find(|index| unsafe { *raw.add(*index) } == 0) else {
        unsafe { LocalFree(raw.cast()) };
        bail!("converted package SID is not bounded");
    };
    let value = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(raw, length) });
    unsafe { LocalFree(raw.cast()) };
    Ok(matches!(
        value.as_str(),
        "S-1-5-18" | "S-1-5-32-544" | TRUSTED_INSTALLER_SID
    ))
}

struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

fn verify_file_trust(path: &Path, held: &File) -> Result<()> {
    let path_wide = wide_path(path)?;
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: path_wide.as_ptr(),
        hFile: held.as_raw_handle() as HANDLE,
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
    verify_and_close(&mut action, &mut data, "file")
}

fn verify_catalog_member(
    admin: &CatalogAdmin,
    catalog_path: &Path,
    member_path: &Path,
    member: &File,
) -> Result<()> {
    let mut hash_size = 0u32;
    unsafe {
        CryptCATAdminCalcHashFromFileHandle2(
            admin.0,
            member.as_raw_handle() as HANDLE,
            &mut hash_size,
            ptr::null_mut(),
            0,
        )
    };
    if hash_size == 0 || hash_size > 128 {
        bail!("catalog member hash size is invalid");
    }
    let mut hash = vec![0u8; hash_size as usize];
    if unsafe {
        CryptCATAdminCalcHashFromFileHandle2(
            admin.0,
            member.as_raw_handle() as HANDLE,
            &mut hash_size,
            hash.as_mut_ptr(),
            0,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error()).context("calculate catalog member hash");
    }
    hash.truncate(hash_size as usize);
    let tag = hash
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<String>();
    let catalog_wide = wide_path(catalog_path)?;
    let member_wide = wide_path(member_path)?;
    let tag_wide = wide_text(&tag)?;
    let mut catalog = WINTRUST_CATALOG_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32,
        dwCatalogVersion: 0,
        pcwszCatalogFilePath: catalog_wide.as_ptr(),
        pcwszMemberTag: tag_wide.as_ptr(),
        pcwszMemberFilePath: member_wide.as_ptr(),
        hMemberFile: member.as_raw_handle() as HANDLE,
        pbCalculatedFileHash: hash.as_mut_ptr(),
        cbCalculatedFileHash: hash.len() as u32,
        pcCatalogContext: ptr::null_mut(),
        hCatAdmin: admin.0,
    };
    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_CATALOG,
        Anonymous: WINTRUST_DATA_0 {
            pCatalog: &mut catalog,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
        ..WINTRUST_DATA::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    verify_and_close(&mut action, &mut data, "catalog member")
}

fn verify_and_close(
    action: &mut windows_sys::core::GUID,
    data: &mut WINTRUST_DATA,
    label: &str,
) -> Result<()> {
    let status =
        unsafe { WinVerifyTrust(ptr::null_mut(), action, (data as *mut WINTRUST_DATA).cast()) };
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe { WinVerifyTrust(ptr::null_mut(), action, (data as *mut WINTRUST_DATA).cast()) };
    if status != 0 {
        bail!("WinVerifyTrust rejected {label}: 0x{status:08x}");
    }
    Ok(())
}

fn require_signer(
    path: &Path,
    content_flag: u32,
    expected: &str,
    allowed: &[String],
) -> Result<()> {
    let signer = signer_sha256_thumbprint(path, content_flag)?;
    if !signer.eq_ignore_ascii_case(expected)
        || !allowed
            .iter()
            .any(|value| signer.eq_ignore_ascii_case(value))
    {
        bail!("signed file publisher differs from bundle and compiled policy");
    }
    Ok(())
}

fn signer_sha256_thumbprint(path: &Path, content_flag: u32) -> Result<String> {
    let wide = wide_path(path)?;
    let mut encoding = 0;
    let mut store: HCERTSTORE = ptr::null_mut();
    let mut message = ptr::null_mut();
    if unsafe {
        CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            wide.as_ptr().cast(),
            content_flag,
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
        return Err(std::io::Error::last_os_error()).context("query signed package object");
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
        bail!("signed package object has no primary signer");
    }
    let words = (signer_size as usize).div_ceil(std::mem::size_of::<usize>());
    let mut storage = vec![0usize; words];
    if unsafe {
        CryptMsgGetParam(
            resources.message,
            CMSG_SIGNER_INFO_PARAM,
            0,
            storage.as_mut_ptr().cast(),
            &mut signer_size,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error()).context("read package signer");
    }
    let signer = unsafe { &*storage.as_ptr().cast::<CMSG_SIGNER_INFO>() };
    require_timestamp_attribute(signer)?;
    let certificate_info = CERT_INFO {
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
            (&certificate_info as *const CERT_INFO).cast(),
            ptr::null(),
        )
    };
    if certificate.is_null() {
        bail!("package signer certificate is missing");
    }
    certificate_sha256(Certificate(certificate).0)
}

fn require_timestamp_attribute(signer: &CMSG_SIGNER_INFO) -> Result<()> {
    let attributes = signer.UnauthAttrs;
    if attributes.cAttr == 0 || attributes.cAttr > 32 || attributes.rgAttr.is_null() {
        bail!("signed package object has no bounded timestamp attribute");
    }
    let values =
        unsafe { std::slice::from_raw_parts(attributes.rgAttr, attributes.cAttr as usize) };
    for attribute in values {
        if attribute.pszObjId.is_null() {
            bail!("signed package object contains a null unauthenticated attribute OID");
        }
        let oid = unsafe { CStr::from_ptr(attribute.pszObjId.cast()) }
            .to_str()
            .context("signed package object attribute OID is not ASCII")?;
        if matches!(oid, "1.2.840.113549.1.9.6" | "1.3.6.1.4.1.311.3.3.1") {
            return Ok(());
        }
    }
    bail!("signed package object has no accepted Authenticode timestamp")
}

fn certificate_sha256(
    certificate: *const windows_sys::Win32::Security::Cryptography::CERT_CONTEXT,
) -> Result<String> {
    let mut size = 0;
    if unsafe {
        CertGetCertificateContextProperty(
            certificate,
            CERT_SHA256_HASH_PROP_ID,
            ptr::null_mut(),
            &mut size,
        )
    } == 0
        || size != 32
    {
        bail!("query signer SHA-256 failed");
    }
    let mut bytes = vec![0u8; size as usize];
    if unsafe {
        CertGetCertificateContextProperty(
            certificate,
            CERT_SHA256_HASH_PROP_ID,
            bytes.as_mut_ptr().cast(),
            &mut size,
        )
    } == 0
    {
        bail!("read signer SHA-256 failed");
    }
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn wide_path(path: &Path) -> Result<Vec<u16>> {
    let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if wide.contains(&0) {
        bail!("trusted package path contains NUL");
    }
    wide.push(0);
    Ok(wide)
}

fn wide_text(value: &str) -> Result<Vec<u16>> {
    let mut wide = value.encode_utf16().collect::<Vec<_>>();
    if wide.contains(&0) {
        bail!("trusted package value contains NUL");
    }
    wide.push(0);
    Ok(wide)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

struct CatalogAdmin(isize);

impl CatalogAdmin {
    fn sha256() -> Result<Self> {
        let mut handle = 0isize;
        let algorithm = wide_text("SHA256")?;
        if unsafe {
            CryptCATAdminAcquireContext2(
                &mut handle,
                ptr::null(),
                algorithm.as_ptr(),
                ptr::null(),
                0,
            )
        } == 0
            || handle == 0
        {
            return Err(std::io::Error::last_os_error()).context("acquire SHA-256 catalog context");
        }
        Ok(Self(handle))
    }
}

impl Drop for CatalogAdmin {
    fn drop(&mut self) {
        unsafe {
            CryptCATAdminReleaseContext(self.0, 0);
        }
    }
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
        unsafe {
            CertFreeCertificateContext(self.0);
        }
    }
}
