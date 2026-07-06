use anyhow::anyhow;

pub(crate) fn unsupported(capability: &str, detail: &str) -> anyhow::Error {
    anyhow!(
        "Windows backend does not support {capability}. {detail}. Supported Windows runtime operations include direct QEMU boot, guest-ready, non-interactive exec, copy-in/copy-out, mount import/export, loopback port forwarding, policy-mediated proxy networking, and qcow2 checkpoint/store semantics"
    )
}
