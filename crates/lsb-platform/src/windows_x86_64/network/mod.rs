use std::fmt;
use std::net::Ipv4Addr;

use crate::{PlatformNetworkAttachment, PlatformQemuStreamNetworkAttachment};

use super::qemu::config::{QemuNetworkConfig, QemuProxyStreamNetworkConfig};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WindowsNetworkError {
    LegacyFileDescriptorAttachment,
    NonLoopbackProxyEndpoint { host: Ipv4Addr },
    InvalidProxyPort,
    ProxyMacGeneration,
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
            Self::ProxyMacGeneration => write!(
                f,
                "Windows proxy networking could not generate a private local MAC for the QEMU proxy attachment; no QEMU user networking was enabled"
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
    let mac = random_local_mac().map_err(|_| WindowsNetworkError::ProxyMacGeneration)?;

    Ok(QemuNetworkConfig::ProxyStream(
        QemuProxyStreamNetworkConfig::new(stream.host.to_string(), stream.port, mac),
    ))
}

fn random_local_mac() -> Result<String, getrandom::Error> {
    let mut bytes = [0u8; 6];
    getrandom::fill(&mut bytes)?;
    bytes[0] = (bytes[0] | 0x02) & 0xfe;
    Ok(format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    ))
}

#[cfg(test)]
fn parse_mac(mac: &str) -> [u8; 6] {
    let parts = mac.split(':').collect::<Vec<_>>();
    assert_eq!(parts.len(), 6, "MAC should have six octets: {mac}");
    let mut bytes = [0u8; 6];
    for (index, part) in parts.into_iter().enumerate() {
        bytes[index] = u8::from_str_radix(part, 16).expect("MAC octet should be hex");
    }
    bytes
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
        let attachment = PlatformNetworkAttachment::qemu_stream(Ipv4Addr::LOCALHOST, 49152);

        let network = qemu_network_config(Some(&attachment)).expect("proxy stream config");

        let QemuNetworkConfig::ProxyStream(proxy) = network else {
            panic!("proxy stream attachment should produce proxy stream QEMU config");
        };
        assert_eq!(proxy.host, "127.0.0.1");
        assert_eq!(proxy.port, 49152);
        let mac = parse_mac(&proxy.mac);
        assert_eq!(mac[0] & 0x01, 0, "proxy MAC should be unicast");
        assert_eq!(mac[0] & 0x02, 0x02, "proxy MAC should be local");
        assert_ne!(
            [mac[4], mac[5]],
            49152u16.to_be_bytes(),
            "proxy MAC must not encode the proxy listener port"
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
