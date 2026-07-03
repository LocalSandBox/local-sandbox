use anyhow::anyhow;

pub(crate) fn unsupported(capability: &str, milestone: &str) -> anyhow::Error {
    anyhow!(
        "Windows support is in progress: {capability} is not implemented yet ({milestone}); M01 only provides compile stubs and does not start QEMU/WHPX"
    )
}
