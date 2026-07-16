use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::ptr;

use tokio::net::windows::named_pipe::NamedPipeClient;
use windows_service::service::{ServiceAccess, ServiceState, ServiceType};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_sys::Win32::Foundation::{GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_OVERLAPPED, FILE_WRITE_DATA, OPEN_EXISTING, SECURITY_IMPERSONATION,
    SECURITY_SQOS_PRESENT, SYNCHRONIZE,
};
use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;

use crate::{ClientError, PIPE_NAME, SERVICE_NAME};

const DESIRED_ACCESS: u32 = GENERIC_READ | FILE_WRITE_DATA | SYNCHRONIZE;

pub fn open_verified() -> Result<NamedPipeClient, ClientError> {
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
    verify_server(&client)?;
    Ok(client)
}

fn verify_server(client: &NamedPipeClient) -> Result<(), ClientError> {
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
    if config.service_type != ServiceType::OWN_PROCESS
        || !local_system
        || !config.executable_path.is_absolute()
    {
        return Err(ClientError::ServerNotTrusted(
            "service configuration is not protected LocalSystem own-process".to_string(),
        ));
    }
    let second_pid = pipe_server_pid(client)?;
    let second_status = service
        .query_status()
        .map_err(|error| ClientError::ServerNotTrusted(error.to_string()))?;
    if second_pid != first_pid || second_status.process_id != Some(first_pid) {
        return Err(ClientError::ServerNotTrusted(
            "service identity changed during verification".to_string(),
        ));
    }
    Ok(())
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
}
