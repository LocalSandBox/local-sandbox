use std::process::ExitCode;

use serde::Serialize;

const PROCESS_HANDLE_ARG: &str = "--process-handle";
const OUTPUT_HANDLE_ARG: &str = "--output-handle";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Handles {
    process: usize,
    output: usize,
}

#[derive(Debug, Serialize)]
struct HelperResult {
    schema_version: u32,
    success: bool,
    win32_error: Option<u32>,
}

fn main() -> ExitCode {
    let handles = match parse_args(std::env::args_os().skip(1)) {
        Ok(handles) => handles,
        Err(_) => return ExitCode::from(2),
    };
    let result = write_dump(handles);
    let _ = serde_json::to_writer(std::io::stdout().lock(), &result);
    if result.success {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn parse_args(args: impl IntoIterator<Item = std::ffi::OsString>) -> Result<Handles, ()> {
    let args = args.into_iter().collect::<Vec<_>>();
    if args.len() != 4 || args[0] != PROCESS_HANDLE_ARG || args[2] != OUTPUT_HANDLE_ARG {
        return Err(());
    }
    let process = parse_handle(&args[1])?;
    let output = parse_handle(&args[3])?;
    if process == output {
        return Err(());
    }
    Ok(Handles { process, output })
}

fn parse_handle(value: &std::ffi::OsStr) -> Result<usize, ()> {
    let value = value.to_str().ok_or(())?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(());
    }
    let parsed = value.parse::<usize>().map_err(|_| ())?;
    if parsed == 0 {
        return Err(());
    }
    Ok(parsed)
}

#[cfg(windows)]
fn write_dump(handles: Handles) -> HelperResult {
    use windows_sys::Win32::Storage::FileSystem::{GetFileType, FILE_TYPE_DISK};
    use windows_sys::Win32::System::Diagnostics::Debug::{
        MiniDumpNormal, MiniDumpWithFullMemoryInfo, MiniDumpWithHandleData,
        MiniDumpWithIndirectlyReferencedMemory, MiniDumpWithProcessThreadData,
        MiniDumpWithThreadInfo, MiniDumpWithUnloadedModules, MiniDumpWriteDump,
    };
    use windows_sys::Win32::System::Threading::GetProcessId;

    let process = handles.process as *mut core::ffi::c_void;
    let output = handles.output as *mut core::ffi::c_void;
    let process_id = unsafe { GetProcessId(process) };
    if process_id == 0 || unsafe { GetFileType(output) } != FILE_TYPE_DISK {
        return HelperResult {
            schema_version: 1,
            success: false,
            win32_error: Some(unsafe { windows_sys::Win32::Foundation::GetLastError() }),
        };
    }
    let dump_type = MiniDumpNormal
        | MiniDumpWithThreadInfo
        | MiniDumpWithHandleData
        | MiniDumpWithUnloadedModules
        | MiniDumpWithFullMemoryInfo
        | MiniDumpWithProcessThreadData
        | MiniDumpWithIndirectlyReferencedMemory;
    let success = unsafe {
        MiniDumpWriteDump(
            process,
            process_id,
            output,
            dump_type,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
        )
    } != 0;
    HelperResult {
        schema_version: 1,
        success,
        win32_error: (!success).then(|| unsafe { windows_sys::Win32::Foundation::GetLastError() }),
    }
}

#[cfg(not(windows))]
fn write_dump(_handles: Handles) -> HelperResult {
    HelperResult {
        schema_version: 1,
        success: false,
        win32_error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<std::ffi::OsString> {
        values.iter().map(std::ffi::OsString::from).collect()
    }

    #[test]
    fn accepts_only_two_nonzero_distinct_decimal_handles() {
        assert_eq!(
            parse_args(args(&["--process-handle", "123", "--output-handle", "456"])),
            Ok(Handles {
                process: 123,
                output: 456
            })
        );
        assert!(parse_args(args(&["--process-handle", "0", "--output-handle", "2"])).is_err());
        assert!(parse_args(args(&["--process-handle", "1", "--output-handle", "1"])).is_err());
        assert!(parse_args(args(&["--process-handle", "1", "--output-handle", "../x"])).is_err());
        assert!(parse_args(args(&["--pid", "1", "--path", "dump.dmp"])).is_err());
    }
}
