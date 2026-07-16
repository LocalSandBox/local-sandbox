use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use windows_sys::Win32::Foundation::HANDLE;
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
