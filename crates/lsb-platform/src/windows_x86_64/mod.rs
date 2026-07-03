mod backend;
mod config;
mod errors;

pub(crate) use backend::create_vm;

use crate::{PlatformSpec, PlatformStatus};

pub const SPEC: PlatformSpec = PlatformSpec {
    id: "windows-x86_64",
    target_os: "windows",
    target_arch: "x86_64",
    host_target: "x86_64-pc-windows-msvc",
    cli_artifact_suffix: "windows-x86_64",
    os_image_artifact_suffix: "x86_64",
    guest_target: "x86_64-unknown-linux-musl",
    docker_platform: "linux/amd64",
    kernel_arch: "x86",
    debootstrap_arch: "amd64",
    default_data_subdir: "AppData/Local/lsb",
    codesign_entitlements: None,
    status: PlatformStatus::Planned,
};
