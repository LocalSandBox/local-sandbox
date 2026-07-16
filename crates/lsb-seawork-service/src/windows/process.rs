use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Result};
use windows_sys::Win32::Foundation::{HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, GetExitCodeProcess, ResumeThread, TerminateProcess, WaitForSingleObject,
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION,
    STARTUPINFOW,
};

use super::job::SandboxJob;

pub struct ContainedProcess {
    process: OwnedHandle,
    _primary_thread: OwnedHandle,
    process_id: u32,
}

impl ContainedProcess {
    pub fn spawn_suspended_into_job(
        job: &SandboxJob,
        executable: &Path,
        arguments: &[OsString],
        working_directory: &Path,
    ) -> Result<Self> {
        if !executable.is_absolute() || !working_directory.is_absolute() {
            bail!("contained process executable and working directory must be absolute");
        }
        let application = wide_null(executable.as_os_str());
        let mut command_line = wide_null(&build_command_line(executable.as_os_str(), arguments));
        let current_directory = wide_null(working_directory.as_os_str());
        let environment = [0u16, 0u16];
        let startup = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            ..Default::default()
        };
        let mut process_info = PROCESS_INFORMATION::default();
        let created = unsafe {
            CreateProcessW(
                application.as_ptr(),
                command_line.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                environment.as_ptr().cast(),
                current_directory.as_ptr(),
                &startup,
                &mut process_info,
            )
        };
        if created == 0 {
            bail!("CreateProcessW failed: {}", std::io::Error::last_os_error());
        }

        let process = unsafe { OwnedHandle::from_raw_handle(process_info.hProcess as _) };
        let primary_thread = unsafe { OwnedHandle::from_raw_handle(process_info.hThread as _) };
        if let Err(error) = job.assign_process(process.as_raw_handle()) {
            unsafe { TerminateProcess(process.as_raw_handle() as HANDLE, 1) };
            return Err(error);
        }
        if unsafe { ResumeThread(primary_thread.as_raw_handle() as HANDLE) } == u32::MAX {
            let error = std::io::Error::last_os_error();
            let _ = job.terminate(1);
            bail!("ResumeThread failed: {error}");
        }
        Ok(Self {
            process,
            _primary_thread: primary_thread,
            process_id: process_info.dwProcessId,
        })
    }

    pub fn id(&self) -> u32 {
        self.process_id
    }

    pub fn wait(&self, timeout: Duration) -> Result<Option<u32>> {
        let timeout_ms = timeout.as_millis().min(u32::MAX as u128) as u32;
        match unsafe { WaitForSingleObject(self.raw(), timeout_ms) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => {
                let mut exit_code = 0;
                if unsafe { GetExitCodeProcess(self.raw(), &mut exit_code) } == 0 {
                    bail!(
                        "GetExitCodeProcess failed: {}",
                        std::io::Error::last_os_error()
                    );
                }
                Ok(Some(exit_code))
            }
            WAIT_FAILED => bail!(
                "WaitForSingleObject failed: {}",
                std::io::Error::last_os_error()
            ),
            value => bail!("WaitForSingleObject returned unexpected status {value}"),
        }
    }

    fn raw(&self) -> HANDLE {
        self.process.as_raw_handle() as HANDLE
    }
}

impl std::fmt::Debug for ContainedProcess {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ContainedProcess")
            .field("process_id", &self.process_id)
            .finish_non_exhaustive()
    }
}

fn build_command_line(executable: &OsStr, arguments: &[OsString]) -> OsString {
    let mut command = String::new();
    append_quoted(&mut command, &executable.to_string_lossy());
    for argument in arguments {
        command.push(' ');
        append_quoted(&mut command, &argument.to_string_lossy());
    }
    OsString::from(command)
}

fn append_quoted(output: &mut String, argument: &str) {
    if !argument.is_empty()
        && !argument
            .chars()
            .any(|character| character.is_whitespace() || character == '"')
    {
        output.push_str(argument);
        return;
    }
    output.push('"');
    let mut backslashes = 0usize;
    for character in argument.chars() {
        if character == '\\' {
            backslashes += 1;
        } else if character == '"' {
            output.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
            output.push('"');
            backslashes = 0;
        } else {
            output.extend(std::iter::repeat_n('\\', backslashes));
            output.push(character);
            backslashes = 0;
        }
    }
    output.extend(std::iter::repeat_n('\\', backslashes * 2));
    output.push('"');
}

fn wide_null(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_line_quoting_preserves_spaces_quotes_and_trailing_slashes() {
        let command = build_command_line(
            OsStr::new(r"C:\Program Files\QEMU\qemu-system-x86_64.exe"),
            &[
                OsString::from("plain"),
                OsString::from("two words"),
                OsString::from("quoted\"value"),
                OsString::from("trailing\\"),
            ],
        );
        assert_eq!(
            command.to_string_lossy(),
            r#""C:\Program Files\QEMU\qemu-system-x86_64.exe" plain "two words" "quoted\"value" trailing\"#
        );
    }
}
