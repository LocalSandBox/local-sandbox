use std::ffi::c_void;

use lsb_service_proto::HealthState;
use windows_sys::Win32::Foundation::{FreeLibrary, HMODULE};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
};

const HYPERVISOR_PRESENT_CAPABILITY: i32 = 0;

type WhvGetCapability = unsafe extern "system" fn(
    capability_code: i32,
    capability_buffer: *mut c_void,
    capability_buffer_size: u32,
    written_size: *mut u32,
) -> i32;

pub fn health_state() -> HealthState {
    if hypervisor_present() {
        HealthState::Ready
    } else {
        HealthState::Unavailable
    }
}

fn hypervisor_present() -> bool {
    let library_name = "winhvplatform.dll\0".encode_utf16().collect::<Vec<_>>();
    let module = unsafe {
        LoadLibraryExW(
            library_name.as_ptr(),
            std::ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    };
    if module.is_null() {
        return false;
    }
    let library = LoadedLibrary(module);
    let Some(procedure) =
        (unsafe { GetProcAddress(library.0, c"WHvGetCapability".as_ptr().cast()) })
    else {
        return false;
    };
    let get_capability: WhvGetCapability = unsafe { std::mem::transmute(procedure) };
    let mut present = 0i32;
    let mut written = 0u32;
    let result = unsafe {
        get_capability(
            HYPERVISOR_PRESENT_CAPABILITY,
            (&mut present as *mut i32).cast(),
            std::mem::size_of_val(&present) as u32,
            &mut written,
        )
    };
    capability_is_present(result, written, present)
}

fn capability_is_present(result: i32, written: u32, present: i32) -> bool {
    result >= 0 && written == std::mem::size_of::<i32>() as u32 && present != 0
}

struct LoadedLibrary(HMODULE);

impl Drop for LoadedLibrary {
    fn drop(&mut self) {
        unsafe {
            FreeLibrary(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::capability_is_present;

    #[test]
    fn capability_requires_success_exact_size_and_presence() {
        assert!(capability_is_present(0, 4, 1));
        assert!(!capability_is_present(-1, 4, 1));
        assert!(!capability_is_present(0, 0, 1));
        assert!(!capability_is_present(0, 4, 0));
    }
}
