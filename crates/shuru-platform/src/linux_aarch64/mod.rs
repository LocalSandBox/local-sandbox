use crate::{PlatformSpec, PlatformStatus};

pub const SPEC: PlatformSpec = PlatformSpec {
    id: "linux-aarch64",
    target_os: "linux",
    target_arch: "aarch64",
    host_target: "aarch64-unknown-linux-gnu",
    cli_artifact_suffix: "linux-aarch64",
    os_image_artifact_suffix: "aarch64",
    guest_target: "aarch64-unknown-linux-musl",
    docker_platform: "linux/arm64/v8",
    kernel_arch: "arm64",
    debootstrap_arch: "arm64",
    default_data_subdir: ".local/share/shuru",
    codesign_entitlements: None,
    status: PlatformStatus::Planned,
};
