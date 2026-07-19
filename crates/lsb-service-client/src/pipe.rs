use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr;

use tokio::net::windows::named_pipe::NamedPipeClient;
use windows_service::service::{ServiceAccess, ServiceSidType, ServiceState, ServiceType};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_sys::Win32::Foundation::{GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE, WAIT_TIMEOUT};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FileIdInfo, GetFileInformationByHandleEx, FILE_FLAG_OVERLAPPED, FILE_ID_INFO,
    FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_WRITE_DATA, OPEN_EXISTING, SECURITY_IMPERSONATION,
    SECURITY_SQOS_PRESENT, SYNCHRONIZE,
};
use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::{ClientError, PIPE_NAME, SERVICE_NAME};

const DESIRED_ACCESS: u32 = GENERIC_READ | FILE_WRITE_DATA | SYNCHRONIZE;

pub(crate) struct VerifiedPipe {
    pub(crate) client: NamedPipeClient,
    pub(crate) identity: ServerIdentityHandles,
}

pub(crate) struct ServerIdentityHandles {
    _process: OwnedHandle,
    _image: OwnedHandle,
}

pub fn open_verified() -> Result<VerifiedPipe, ClientError> {
    let wide = std::ffi::OsStr::new(PIPE_NAME)
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            DESIRED_ACCESS,
            0,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(ClientError::ServiceUnavailable(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    let client = unsafe { NamedPipeClient::from_raw_handle(handle as _) }?;
    let identity = verify_server(&client)?;
    Ok(VerifiedPipe { client, identity })
}

fn verify_server(client: &NamedPipeClient) -> Result<ServerIdentityHandles, ClientError> {
    let first_pid = pipe_server_pid(client)?;
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|error| ClientError::ServerNotTrusted(error.to_string()))?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_CONFIG | ServiceAccess::QUERY_STATUS,
        )
        .map_err(|error| ClientError::ServerNotTrusted(error.to_string()))?;
    let status = service
        .query_status()
        .map_err(|error| ClientError::ServerNotTrusted(error.to_string()))?;
    if status.current_state != ServiceState::Running
        || status.process_id != Some(first_pid)
        || !status.service_type.contains(ServiceType::OWN_PROCESS)
    {
        return Err(ClientError::ServerNotTrusted(
            "pipe PID is not the running own-process service".to_string(),
        ));
    }
    let config = service
        .query_config()
        .map_err(|error| ClientError::ServerNotTrusted(error.to_string()))?;
    let local_system = config
        .account_name
        .as_deref()
        .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case("LocalSystem"));
    let Some(configured_executable) =
        configured_service_executable(config.executable_path.as_os_str())
    else {
        return Err(ClientError::ServerNotTrusted(
            "service command is not the exact packaged service command".to_string(),
        ));
    };
    let service_sid_type = service
        .get_config_service_sid_info()
        .map_err(|error| ClientError::ServerNotTrusted(error.to_string()))?;
    if config.service_type != ServiceType::OWN_PROCESS
        || !local_system
        || service_sid_type != ServiceSidType::Unrestricted
    {
        return Err(ClientError::ServerNotTrusted(
            "service configuration is not LocalSystem own-process with an unrestricted service SID"
                .to_string(),
        ));
    }

    // Hold both the process and the exact configured image for the connection. The
    // executable handle intentionally omits FILE_SHARE_WRITE and FILE_SHARE_DELETE,
    // preventing replacement or mutation after its identity has been accepted.
    let process = open_server_process(first_pid)?;
    let configured_image = open_image_for_identity(&configured_executable)?;
    let process_image_path = query_process_image(&process)?;
    let process_image = open_image_for_identity(&process_image_path)?;
    if file_identity(&configured_image)? != file_identity(&process_image)? {
        return Err(ClientError::ServerNotTrusted(
            "running service image does not match the configured executable identity".to_string(),
        ));
    }
    let second_pid = pipe_server_pid(client)?;
    let second_status = service
        .query_status()
        .map_err(|error| ClientError::ServerNotTrusted(error.to_string()))?;
    if second_pid != first_pid
        || second_status.current_state != ServiceState::Running
        || second_status.process_id != Some(first_pid)
        || process_has_exited(&process)?
    {
        return Err(ClientError::ServerNotTrusted(
            "service identity changed during verification".to_string(),
        ));
    }
    Ok(ServerIdentityHandles {
        _process: process,
        _image: configured_image,
    })
}

fn open_server_process(pid: u32) -> Result<OwnedHandle, ClientError> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, pid) };
    if handle.is_null() {
        return Err(ClientError::ServerNotTrusted(format!(
            "open service process: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(handle as _) })
}

fn query_process_image(process: &OwnedHandle) -> Result<PathBuf, ClientError> {
    let mut buffer = vec![0u16; 32_768];
    let mut length = buffer.len() as u32;
    if unsafe {
        QueryFullProcessImageNameW(
            process.as_raw_handle() as HANDLE,
            0,
            buffer.as_mut_ptr(),
            &mut length,
        )
    } == 0
        || length == 0
    {
        return Err(ClientError::ServerNotTrusted(format!(
            "query service process image: {}",
            std::io::Error::last_os_error()
        )));
    }
    buffer.truncate(length as usize);
    Ok(PathBuf::from(OsString::from_wide(&buffer)))
}

fn open_image_for_identity(path: &Path) -> Result<OwnedHandle, ClientError> {
    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ,
            ptr::null(),
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(ClientError::ServerNotTrusted(format!(
            "open service image identity: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(handle as _) })
}

fn file_identity(file: &OwnedHandle) -> Result<(u64, [u8; 16]), ClientError> {
    let mut info = FILE_ID_INFO::default();
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle() as HANDLE,
            FileIdInfo,
            (&mut info as *mut FILE_ID_INFO).cast(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    } == 0
    {
        return Err(ClientError::ServerNotTrusted(format!(
            "query service image identity: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok((info.VolumeSerialNumber, info.FileId.Identifier))
}

fn process_has_exited(process: &OwnedHandle) -> Result<bool, ClientError> {
    match unsafe { WaitForSingleObject(process.as_raw_handle() as HANDLE, 0) } {
        WAIT_TIMEOUT => Ok(false),
        0 => Ok(true),
        value => Err(ClientError::ServerNotTrusted(format!(
            "query service process lifetime returned {value}: {}",
            std::io::Error::last_os_error()
        ))),
    }
}

fn configured_service_executable(command: &OsStr) -> Option<PathBuf> {
    let command = command.encode_wide().collect::<Vec<_>>();
    let closing_quote = command
        .get(1..)?
        .iter()
        .position(|unit| *unit == u16::from(b'"'))?
        .checked_add(1)?;
    if command.first() != Some(&u16::from(b'"')) || closing_quote == 1 {
        return None;
    }
    let expected_suffix = " --service".encode_utf16().collect::<Vec<_>>();
    if command.get(closing_quote + 1..)? != expected_suffix {
        return None;
    }

    let executable = PathBuf::from(OsString::from_wide(&command[1..closing_quote]));
    if executable.is_absolute() && has_packaged_layout(&executable) {
        Some(executable)
    } else {
        None
    }
}

fn has_packaged_layout(executable: &Path) -> bool {
    if !file_name_eq(executable, "localsandbox-seawork-service.exe") {
        return false;
    }
    let Some(bin) = executable.parent() else {
        return false;
    };
    let Some(version_root) = bin.parent() else {
        return false;
    };
    let Some(versions) = version_root.parent() else {
        return false;
    };
    let Some(local_sandbox) = versions.parent() else {
        return false;
    };
    let Some(seawork) = local_sandbox.parent() else {
        return false;
    };

    file_name_eq(bin, "bin")
        && version_root
            .file_name()
            .is_some_and(valid_version_component)
        && file_name_eq(versions, "versions")
        && file_name_eq(local_sandbox, "LocalSandbox")
        && file_name_eq(seawork, "SeaWork")
}

fn file_name_eq(path: &Path, expected: &str) -> bool {
    path.file_name()
        .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case(expected))
}

fn valid_version_component(version: &OsStr) -> bool {
    let version = version.to_string_lossy();
    !version.is_empty()
        && version.len() <= 64
        && version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
}

fn pipe_server_pid(client: &NamedPipeClient) -> Result<u32, ClientError> {
    let mut pid = 0;
    if unsafe { GetNamedPipeServerProcessId(client.as_raw_handle() as HANDLE, &mut pid) } == 0
        || pid == 0
    {
        return Err(ClientError::ServerNotTrusted(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    Ok(pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_does_not_request_pipe_instance_creation() {
        const FILE_APPEND_DATA: u32 = 4;
        assert_eq!(DESIRED_ACCESS & FILE_APPEND_DATA, 0);
        assert_ne!(DESIRED_ACCESS & FILE_WRITE_DATA, 0);
        assert_ne!(DESIRED_ACCESS & GENERIC_READ, 0);
    }

    #[test]
    fn parses_exact_packaged_service_command() {
        let command = OsStr::new(
            r#""C:\Program Files\SeaWork\LocalSandbox\versions\0.4.6\bin\localsandbox-seawork-service.exe" --service"#,
        );
        assert_eq!(
            configured_service_executable(command),
            Some(PathBuf::from(
                r"C:\Program Files\SeaWork\LocalSandbox\versions\0.4.6\bin\localsandbox-seawork-service.exe"
            ))
        );
    }

    #[test]
    fn rejects_non_exact_or_non_packaged_service_commands() {
        for command in [
            r"C:\Program Files\SeaWork\LocalSandbox\versions\0.4.6\bin\localsandbox-seawork-service.exe --service",
            r#""C:\Program Files\SeaWork\LocalSandbox\versions\0.4.6\bin\localsandbox-seawork-service.exe""#,
            r#""C:\Program Files\SeaWork\LocalSandbox\versions\0.4.6\bin\localsandbox-seawork-service.exe" --service --extra"#,
            r#""C:\Program Files\SeaWork\LocalSandbox\current\bin\localsandbox-seawork-service.exe" --service"#,
            r#""relative\SeaWork\LocalSandbox\versions\0.4.6\bin\localsandbox-seawork-service.exe" --service"#,
        ] {
            assert_eq!(configured_service_executable(OsStr::new(command)), None);
        }
    }
}
