use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::PlatformControlStream;

use super::super::qemu::config::QemuControlChannelConfig;

pub(crate) const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const PIPE_PREFIX: &str = "lsb";
const PIPE_SUFFIX: &str = "control";
const MAX_PIPE_NAME_LEN: usize = 200;
const RANDOM_SUFFIX_BYTES: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VirtioSerialControlEndpoint {
    pipe_name: String,
    pipe_path: PathBuf,
    port_name: String,
    connect_timeout: Duration,
}

impl VirtioSerialControlEndpoint {
    pub(crate) fn for_instance(instance_dir: &Path) -> Result<Self, VirtioSerialControlError> {
        let label = instance_label(instance_dir);
        let suffix = random_hex_suffix()?;
        Self::with_pipe_name(pipe_name_from_parts(&label, &suffix))
    }

    pub(crate) fn with_pipe_name(
        pipe_name: impl Into<String>,
    ) -> Result<Self, VirtioSerialControlError> {
        let pipe_name = pipe_name.into();
        validate_pipe_name(&pipe_name)?;
        Ok(Self {
            pipe_path: windows_pipe_path(&pipe_name),
            pipe_name,
            port_name: lsb_proto::VIRTIO_SERIAL_CONTROL_PORT_NAME.to_string(),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        })
    }

    pub(crate) fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    pub(crate) fn pipe_name(&self) -> &str {
        &self.pipe_name
    }

    pub(crate) fn pipe_path(&self) -> &Path {
        &self.pipe_path
    }

    pub(crate) fn port_name(&self) -> &str {
        &self.port_name
    }

    pub(crate) fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    pub(crate) fn qemu_config(&self) -> QemuControlChannelConfig {
        QemuControlChannelConfig {
            pipe_name: self.pipe_name.clone(),
            port_name: self.port_name.clone(),
        }
    }

    pub(crate) fn open(&self) -> Result<PlatformControlStream, VirtioSerialControlError> {
        open_pipe_with_timeout(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VirtioSerialControlError {
    InvalidPipeName {
        pipe_name: String,
        reason: String,
    },
    RandomUnavailable {
        detail: String,
    },
    EndpointUnavailable,
    HostPipeUnsupported,
    ConnectTimeout {
        timeout: Duration,
        last_error: Option<String>,
    },
    OpenFailed {
        detail: String,
    },
}

impl VirtioSerialControlError {
    pub(crate) fn remediation(&self) -> &'static str {
        match self {
            Self::InvalidPipeName { .. } => {
                "Use the LocalSandbox-generated per-instance pipe name; QEMU pipe chardev names cannot contain path separators, commas, or whitespace."
            }
            Self::RandomUnavailable { .. } => {
                "Retry on a host with an available OS random source; LocalSandbox uses random control pipe names to avoid local collisions and guessing."
            }
            Self::EndpointUnavailable => {
                "Start the Windows QEMU VM with M06 control transport enabled before opening the guest control channel."
            }
            Self::HostPipeUnsupported => {
                "Run the Windows QEMU backend on Windows; non-Windows hosts can only run unit tests for this transport."
            }
            Self::ConnectTimeout { .. } => {
                "Confirm QEMU is still running, the generated argv contains the virtio-serial chardev, and the guest can open the virtio-serial port. Inspect serial.log and qemu.stderr.log."
            }
            Self::OpenFailed { .. } => {
                "Inspect qemu.stderr.log for chardev creation errors and verify the current user can open the QEMU-created private named pipe."
            }
        }
    }
}

impl fmt::Display for VirtioSerialControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPipeName { pipe_name, reason } => write!(
                f,
                "invalid Windows virtio-serial control pipe name '{}': {reason}. {}",
                pipe_name,
                self.remediation()
            ),
            Self::RandomUnavailable { detail } => write!(
                f,
                "failed to generate a private Windows virtio-serial control pipe name: {detail}. {}",
                self.remediation()
            ),
            Self::EndpointUnavailable => write!(
                f,
                "Windows virtio-serial control endpoint is not configured for this VM. {}",
                self.remediation()
            ),
            Self::HostPipeUnsupported => write!(
                f,
                "Windows virtio-serial control pipe opening is unavailable on this host. {}",
                self.remediation()
            ),
            Self::ConnectTimeout {
                timeout,
                last_error,
            } => write!(
                f,
                "timed out after {} ms waiting for the Windows virtio-serial control pipe to become available; last error: {}. {}",
                timeout.as_millis(),
                last_error.as_deref().unwrap_or("none"),
                self.remediation()
            ),
            Self::OpenFailed { detail } => write!(
                f,
                "failed to open the Windows virtio-serial control pipe: {detail}. {}",
                self.remediation()
            ),
        }
    }
}

impl std::error::Error for VirtioSerialControlError {}

#[cfg(windows)]
fn open_pipe_with_timeout(
    endpoint: &VirtioSerialControlEndpoint,
) -> Result<PlatformControlStream, VirtioSerialControlError> {
    use std::fs::OpenOptions;
    use std::io;
    use std::time::Instant;

    let deadline = Instant::now() + endpoint.connect_timeout;
    let mut last_error = None;

    loop {
        match OpenOptions::new()
            .read(true)
            .write(true)
            .open(endpoint.pipe_path())
        {
            Ok(file) => return Ok(PlatformControlStream::from_file(file)),
            Err(err) if should_retry_pipe_open(&err) && Instant::now() < deadline => {
                last_error = Some(err.to_string());
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(err) if should_retry_pipe_open(&err) => {
                return Err(VirtioSerialControlError::ConnectTimeout {
                    timeout: endpoint.connect_timeout,
                    last_error: Some(err.to_string()),
                });
            }
            Err(err) => {
                return Err(VirtioSerialControlError::OpenFailed {
                    detail: err.to_string(),
                });
            }
        }
    }
}

#[cfg(not(windows))]
fn open_pipe_with_timeout(
    _endpoint: &VirtioSerialControlEndpoint,
) -> Result<PlatformControlStream, VirtioSerialControlError> {
    Err(VirtioSerialControlError::HostPipeUnsupported)
}

#[cfg_attr(not(windows), allow(dead_code))]
fn should_retry_pipe_open(error: &std::io::Error) -> bool {
    const ERROR_FILE_NOT_FOUND: i32 = 2;
    const ERROR_PIPE_BUSY: i32 = 231;

    matches!(
        error.raw_os_error(),
        Some(ERROR_FILE_NOT_FOUND | ERROR_PIPE_BUSY)
    ) || matches!(
        error.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::WouldBlock
    )
}

fn validate_pipe_name(pipe_name: &str) -> Result<(), VirtioSerialControlError> {
    if pipe_name.is_empty() {
        return Err(invalid_pipe_name(pipe_name, "must not be empty"));
    }
    if pipe_name.len() > MAX_PIPE_NAME_LEN {
        return Err(invalid_pipe_name(pipe_name, "is too long"));
    }
    if !pipe_name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(invalid_pipe_name(
            pipe_name,
            "must contain only ASCII letters, digits, '-' or '_'",
        ));
    }
    Ok(())
}

fn invalid_pipe_name(pipe_name: &str, reason: &str) -> VirtioSerialControlError {
    VirtioSerialControlError::InvalidPipeName {
        pipe_name: pipe_name.to_string(),
        reason: reason.to_string(),
    }
}

fn windows_pipe_path(pipe_name: &str) -> PathBuf {
    PathBuf::from(format!(r"\\.\pipe\{pipe_name}"))
}

fn instance_label(instance_dir: &Path) -> String {
    let raw = instance_dir
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("instance");
    let mut label = String::new();
    for ch in raw.chars().flat_map(char::to_lowercase) {
        if ch.is_ascii_alphanumeric() {
            label.push(ch);
        } else if !label.ends_with('-') {
            label.push('-');
        }
        if label.len() >= 32 {
            break;
        }
    }
    let label = label.trim_matches('-');
    if label.is_empty() {
        "instance".to_string()
    } else {
        label.to_string()
    }
}

fn random_hex_suffix() -> Result<String, VirtioSerialControlError> {
    let mut bytes = [0u8; RANDOM_SUFFIX_BYTES];
    getrandom::fill(&mut bytes).map_err(|err| VirtioSerialControlError::RandomUnavailable {
        detail: err.to_string(),
    })?;
    Ok(hex_bytes(&bytes))
}

fn pipe_name_from_parts(label: &str, suffix: &str) -> String {
    format!("{PIPE_PREFIX}-{label}-{suffix}-{PIPE_SUFFIX}")
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_accepts_private_pipe_name_and_builds_qemu_config() {
        let endpoint = VirtioSerialControlEndpoint::with_pipe_name(
            "lsb-test-00112233445566778899aabbccddeeff-control",
        )
        .expect("pipe name should be valid");

        assert_eq!(
            endpoint.pipe_name(),
            "lsb-test-00112233445566778899aabbccddeeff-control"
        );
        assert_eq!(endpoint.port_name(), "org.localsandbox.control");
        assert_eq!(
            endpoint.pipe_path(),
            Path::new(r"\\.\pipe\lsb-test-00112233445566778899aabbccddeeff-control")
        );

        let qemu = endpoint.qemu_config();
        assert_eq!(qemu.pipe_name, endpoint.pipe_name());
        assert_eq!(qemu.port_name, endpoint.port_name());
    }

    #[test]
    fn generated_pipe_name_has_instance_label_and_random_suffix_shape() {
        let name = pipe_name_from_parts("abc-123", "00112233445566778899aabbccddeeff");

        assert_eq!(name, "lsb-abc-123-00112233445566778899aabbccddeeff-control");
        validate_pipe_name(&name).expect("generated name should be valid");
    }

    #[test]
    fn endpoint_rejects_qemu_suboption_separators_and_path_like_values() {
        for name in [
            "",
            "lsb,control",
            r"lsb\control",
            "lsb/control",
            "lsb control",
            "lsb:control",
        ] {
            let err = VirtioSerialControlEndpoint::with_pipe_name(name)
                .expect_err("invalid pipe name should fail");
            assert!(matches!(
                err,
                VirtioSerialControlError::InvalidPipeName { .. }
            ));
        }
    }

    #[test]
    fn instance_label_is_qemu_pipe_safe() {
        assert_eq!(
            instance_label(Path::new("/tmp/lsb/instances/12345")),
            "12345"
        );
        assert_eq!(
            instance_label(Path::new("/tmp/Local Sandbox/instance,one")),
            "instance-one"
        );
        assert_eq!(instance_label(Path::new("***")), "instance");
    }

    #[test]
    fn pipe_retry_mapping_covers_not_found_and_busy_errors() {
        let not_found = std::io::Error::new(std::io::ErrorKind::NotFound, "missing pipe");
        let busy = std::io::Error::from_raw_os_error(231);
        let permission = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");

        assert!(should_retry_pipe_open(&not_found));
        assert!(should_retry_pipe_open(&busy));
        assert!(!should_retry_pipe_open(&permission));
    }

    #[test]
    fn timeout_error_message_is_actionable_without_endpoint_name() {
        let err = VirtioSerialControlError::ConnectTimeout {
            timeout: Duration::from_millis(1500),
            last_error: Some("missing pipe".to_string()),
        };
        let message = err.to_string();

        assert!(message.contains("1500 ms"));
        assert!(message.contains("generated argv contains the virtio-serial chardev"));
        assert!(!message.contains(r"\\.\pipe\"));
    }

    #[test]
    fn non_windows_open_reports_host_pipe_unsupported() {
        #[cfg(not(windows))]
        {
            let endpoint =
                VirtioSerialControlEndpoint::with_pipe_name("lsb-test-open-control").unwrap();
            let err = endpoint
                .open()
                .expect_err("non-Windows hosts cannot open Windows named pipes");

            assert_eq!(err, VirtioSerialControlError::HostPipeUnsupported);
        }
    }
}
