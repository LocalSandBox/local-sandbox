use std::fmt;
use std::net::Ipv4Addr;

use crate::{PlatformNetworkAttachment, PlatformQemuStreamNetworkAttachment};

use super::qemu::config::{QemuNetworkConfig, QemuProxyStreamNetworkConfig};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WindowsNetworkError {
    LegacyFileDescriptorAttachment,
    NonLoopbackProxyEndpoint { host: Ipv4Addr },
    InvalidProxyPort,
}

impl fmt::Display for WindowsNetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LegacyFileDescriptorAttachment => write!(
                f,
                "Windows proxy networking requires a QEMU stream proxy attachment from lsb-proxy; fd/socketpair network attachments are macOS-only. No QEMU user networking, hostfwd, TAP, bridged networking, or unrestricted NAT was enabled"
            ),
            Self::NonLoopbackProxyEndpoint { host } => write!(
                f,
                "Windows proxy networking requires a host loopback proxy endpoint, got {host}. No public proxy listener or QEMU user networking was enabled"
            ),
            Self::InvalidProxyPort => write!(
                f,
                "Windows proxy networking requires a nonzero loopback TCP port for the LocalSandbox proxy stream attachment"
            ),
        }
    }
}

impl std::error::Error for WindowsNetworkError {}

pub(crate) fn qemu_network_config(
    attachment: Option<&PlatformNetworkAttachment>,
) -> Result<QemuNetworkConfig, WindowsNetworkError> {
    match attachment {
        None => Ok(QemuNetworkConfig::None),
        Some(PlatformNetworkAttachment::FileDescriptor(_)) => {
            Err(WindowsNetworkError::LegacyFileDescriptorAttachment)
        }
        Some(PlatformNetworkAttachment::QemuStream(stream)) => proxy_stream_config(stream),
    }
}

fn proxy_stream_config(
    stream: &PlatformQemuStreamNetworkAttachment,
) -> Result<QemuNetworkConfig, WindowsNetworkError> {
    if stream.host != Ipv4Addr::LOCALHOST {
        return Err(WindowsNetworkError::NonLoopbackProxyEndpoint { host: stream.host });
    }
    if stream.port == 0 {
        return Err(WindowsNetworkError::InvalidProxyPort);
    }

    Ok(QemuNetworkConfig::ProxyStream(
        QemuProxyStreamNetworkConfig::new(
            stream.host.to_string(),
            stream.port,
            proxy_mac_from_port(stream.port),
        ),
    ))
}

fn proxy_mac_from_port(port: u16) -> String {
    let [hi, lo] = port.to_be_bytes();
    format!("02:4c:53:42:{hi:02x}:{lo:02x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_network_config_has_no_guest_nic() {
        assert_eq!(
            qemu_network_config(None).expect("default network config"),
            QemuNetworkConfig::None
        );
    }

    #[test]
    fn qemu_stream_attachment_translates_to_proxy_network() {
        let attachment =
            PlatformNetworkAttachment::qemu_stream(Ipv4Addr::LOCALHOST, 49152);

        let network = qemu_network_config(Some(&attachment)).expect("proxy stream config");

        assert_eq!(
            network,
            QemuNetworkConfig::ProxyStream(QemuProxyStreamNetworkConfig::new(
                "127.0.0.1",
                49152,
                "02:4c:53:42:c0:00"
            ))
        );
    }

    #[test]
    fn file_descriptor_network_attachment_fails_closed_on_windows() {
        let err = qemu_network_config(Some(&PlatformNetworkAttachment::file_descriptor(7)))
            .expect_err("fd networking should be rejected");

        assert_eq!(err, WindowsNetworkError::LegacyFileDescriptorAttachment);
        assert!(err.to_string().contains("macOS-only"));
        assert!(err.to_string().contains("No QEMU user networking"));
    }

    #[test]
    fn non_loopback_proxy_endpoint_is_rejected() {
        let attachment = PlatformNetworkAttachment::qemu_stream(Ipv4Addr::new(0, 0, 0, 0), 49152);

        let err = qemu_network_config(Some(&attachment))
            .expect_err("public proxy endpoint should fail closed");

        assert_eq!(
            err,
            WindowsNetworkError::NonLoopbackProxyEndpoint {
                host: Ipv4Addr::new(0, 0, 0, 0)
            }
        );
    }
}
