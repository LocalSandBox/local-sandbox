use anyhow::anyhow;

pub(crate) fn unsupported(capability: &str, milestone: &str) -> anyhow::Error {
    anyhow!(
        "Windows support is in progress: {capability} is not implemented yet ({milestone}); current Windows runtime support is limited to direct QEMU boot diagnostics with M06 virtio-serial control transport plumbing"
    )
}
