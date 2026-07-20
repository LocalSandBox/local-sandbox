use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Security::Cryptography::{
    CertCloseStore, CertFindCertificateInStore, CertFreeCertificateContext,
    CertGetCertificateContextProperty, CryptMsgClose, CryptMsgGetParam, CryptQueryObject,
    CERT_FIND_SUBJECT_CERT, CERT_INFO, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
    CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_OBJECT_FILE, CERT_SHA256_HASH_PROP_ID,
    CMSG_SIGNER_INFO, CMSG_SIGNER_INFO_PARAM, HCERTSTORE,
};
use windows_sys::Win32::Security::WinTrust::{
    WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
    WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE,
    WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
    WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};

use crate::ClientError;

const COMPILED_PUBLISHERS_SHA256: &str = env!("LSB_COMPILED_SEAWORK_PUBLISHERS_SHA256");

pub(crate) fn verify_publisher(image: &Path, held_image: &OwnedHandle) -> Result<(), ClientError> {
    let publishers = parse_publisher_policy(COMPILED_PUBLISHERS_SHA256)
        .ok_or_else(|| untrusted("service publisher policy is not compiled in"))?;
    verify_authenticode(image, held_image)?;
    let signer = signer_sha256_thumbprint(image)?;
    if !publishers
        .iter()
        .any(|publisher| signer.eq_ignore_ascii_case(publisher))
    {
        return Err(untrusted(
            "service signer is not in the compiled publisher allowlist",
        ));
    }
    Ok(())
}

fn verify_authenticode(image: &Path, held_image: &OwnedHandle) -> Result<(), ClientError> {
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
        return Err(untrusted(format!(
            "Authenticode rejected service image: 0x{status:08x}"
        )));
    }
    Ok(())
}

fn signer_sha256_thumbprint(image: &Path) -> Result<String, ClientError> {
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
        return Err(untrusted(format!(
            "query embedded service signature: {}",
            std::io::Error::last_os_error()
        )));
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
        return Err(untrusted("service image has no primary signer"));
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
        return Err(untrusted(format!(
            "read embedded service signer: {}",
            std::io::Error::last_os_error()
        )));
    }
    let signer = unsafe { &*storage.as_ptr().cast::<CMSG_SIGNER_INFO>() };
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
        return Err(untrusted("embedded service signer certificate is missing"));
    }
    certificate_sha256(Certificate(certificate).0)
}

fn certificate_sha256(
    certificate: *const windows_sys::Win32::Security::Cryptography::CERT_CONTEXT,
) -> Result<String, ClientError> {
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
        return Err(untrusted("query service signer SHA-256 failed"));
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
        return Err(untrusted("read service signer SHA-256 failed"));
    }
    bytes.truncate(size as usize);
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn wide_path(path: &Path) -> Result<Vec<u16>, ClientError> {
    let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if wide.contains(&0) {
        return Err(untrusted("service image path contains NUL"));
    }
    wide.push(0);
    Ok(wide)
}

fn valid_sha256_thumbprint(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn parse_publisher_policy(value: &str) -> Option<Vec<&str>> {
    if value.is_empty() {
        return None;
    }
    let publishers = value.split(',').collect::<Vec<_>>();
    if publishers.len() > 2
        || publishers
            .iter()
            .any(|publisher| !valid_sha256_thumbprint(publisher))
        || (publishers.len() == 2 && publishers[0].eq_ignore_ascii_case(publishers[1]))
    {
        return None;
    }
    Some(publishers)
}

fn untrusted(message: impl Into<String>) -> ClientError {
    ClientError::ServerNotTrusted(message.into())
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

    #[test]
    fn publisher_policy_accepts_current_and_one_distinct_overlap() {
        assert!(valid_sha256_thumbprint(&"aB".repeat(32)));
        assert!(!valid_sha256_thumbprint(&"a".repeat(40)));
        assert!(!valid_sha256_thumbprint(&"z".repeat(64)));

        let current = "ab".repeat(32);
        let previous = "cd".repeat(32);
        assert_eq!(
            parse_publisher_policy(&current).unwrap(),
            [current.as_str()]
        );
        assert_eq!(
            parse_publisher_policy(&format!("{current},{previous}")).unwrap(),
            [current.as_str(), previous.as_str()]
        );
        assert!(parse_publisher_policy("").is_none());
        assert!(parse_publisher_policy(&format!("{current},{current}")).is_none());
        assert!(parse_publisher_policy(&format!("{current},{previous},{current}")).is_none());
        assert!(parse_publisher_policy(&format!("{current},")).is_none());
    }
}
