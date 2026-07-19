#![cfg_attr(
    not(all(target_os = "windows", target_arch = "x86_64")),
    allow(dead_code, unused_imports)
)]

mod backend;
mod config;
mod control;
mod errors;
pub mod fs;
pub mod host_tools;
mod network;
mod qemu;

pub(crate) use backend::create_vm;
pub(crate) use control::mux::MuxSession;

use std::process::Command;

use crate::{PlatformSpec, PlatformStatus};

pub const SPEC: PlatformSpec = PlatformSpec {
    id: "windows-x86_64",
    target_os: "windows",
    target_arch: "x86_64",
    host_target: "x86_64-pc-windows-msvc",
    cli_artifact_suffix: "windows-x86_64",
    os_image_artifact_suffix: "windows-x86_64",
    guest_target: "x86_64-unknown-linux-musl",
    docker_platform: "linux/amd64",
    kernel_arch: "x86",
    debootstrap_arch: "amd64",
    default_data_subdir: "AppData/Local/lsb",
    codesign_entitlements: None,
    status: PlatformStatus::Supported,
};

pub fn apply_qemu_no_window_creation_flags(command: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;

        command.creation_flags(qemu_no_window_creation_flags());
    }

    #[cfg(not(windows))]
    {
        let _ = command;
    }
}

pub fn apply_qemu_contained_creation_flags(command: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;

        command.creation_flags(qemu_contained_creation_flags());
    }

    #[cfg(not(windows))]
    {
        let _ = command;
    }
}

#[cfg(windows)]
pub fn qemu_no_window_creation_flags() -> u32 {
    windows_sys::Win32::System::Threading::CREATE_NO_WINDOW
}

#[cfg(windows)]
pub fn qemu_contained_creation_flags() -> u32 {
    qemu_no_window_creation_flags() | windows_sys::Win32::System::Threading::CREATE_SUSPENDED
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    #[test]
    fn qemu_no_window_creation_flags_include_create_no_window() {
        assert_ne!(
            super::qemu_no_window_creation_flags()
                & windows_sys::Win32::System::Threading::CREATE_NO_WINDOW,
            0,
            "QEMU and qemu-img must be launched with CREATE_NO_WINDOW for GUI parents"
        );
    }

    #[cfg(windows)]
    #[test]
    fn contained_qemu_starts_hidden_and_suspended() {
        let flags = super::qemu_contained_creation_flags();
        assert_ne!(
            flags & windows_sys::Win32::System::Threading::CREATE_NO_WINDOW,
            0
        );
        assert_ne!(
            flags & windows_sys::Win32::System::Threading::CREATE_SUSPENDED,
            0
        );
    }
}
