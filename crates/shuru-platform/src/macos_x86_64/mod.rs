use crate::{PlatformSpec, PlatformStatus};

pub const SPEC: PlatformSpec = PlatformSpec {
    id: "macos-x86_64",
    target_os: "macos",
    target_arch: "x86_64",
    host_target: "x86_64-apple-darwin",
    cli_artifact_suffix: "darwin-x86_64",
    os_image_artifact_suffix: "x86_64",
    guest_target: "aarch64-unknown-linux-musl",
    docker_platform: "linux/amd64",
    kernel_arch: "x86_64",
    debootstrap_arch: "amd64",
    default_data_subdir: ".local/share/shuru",
    codesign_entitlements: Some("shuru.entitlements"),
    status: PlatformStatus::Planned,
};
