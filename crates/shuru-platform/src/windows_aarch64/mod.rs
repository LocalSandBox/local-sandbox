use crate::{PlatformSpec, PlatformStatus};

pub const SPEC: PlatformSpec = PlatformSpec {
    id: "windows-aarch64",
    target_os: "windows",
    target_arch: "aarch64",
    host_target: "aarch64-pc-windows-msvc",
    cli_artifact_suffix: "windows-aarch64",
    os_image_artifact_suffix: "aarch64",
    guest_target: "aarch64-unknown-linux-musl",
    docker_platform: "linux/arm64/v8",
    kernel_arch: "arm64",
    debootstrap_arch: "arm64",
    default_data_subdir: "AppData/Local/shuru",
    codesign_entitlements: None,
    status: PlatformStatus::Planned,
};
