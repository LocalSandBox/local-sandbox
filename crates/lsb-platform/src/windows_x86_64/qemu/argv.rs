use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};

use super::config::{
    QemuBootConfig, QemuControlChannelConfig, QemuDiskConfig, QemuKernelAppend, QemuQmpEndpoint,
    QemuSerialConfig, CONTROL_BUS_ID, CONTROL_CHARDEV_ID, DEFAULT_CPU_MODEL, DEFAULT_MACHINE_TYPE,
    ROOT_DRIVE_ID,
};
use super::preflight::PRODUCTION_ACCELERATOR;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QemuCommand {
    pub program: PathBuf,
    pub argv: Vec<OsString>,
    diagnostic_argv: Vec<String>,
    diagnostic_label: Option<String>,
}

impl QemuCommand {
    pub(crate) fn sanitized_argv(&self) -> &[String] {
        &self.diagnostic_argv
    }

    pub(crate) fn diagnostic_label(&self) -> Option<&str> {
        self.diagnostic_label.as_deref()
    }

    pub(crate) fn sanitized_display(&self) -> String {
        std::iter::once("<qemu-system-x86_64.exe>".to_string())
            .chain(
                self.diagnostic_argv
                    .iter()
                    .map(|arg| render_diagnostic_arg(arg)),
            )
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QemuArgvBuilder {
    config: QemuBootConfig,
}

impl QemuArgvBuilder {
    pub(crate) fn new(config: QemuBootConfig) -> Self {
        Self { config }
    }

    pub(crate) fn build(&self) -> Result<QemuCommand, QemuArgvError> {
        validate_path("qemu_executable", &self.config.qemu_executable)?;
        validate_path("kernel_image", &self.config.kernel_image)?;
        validate_path("initrd_image", &self.config.initrd_image)?;
        validate_path("root_disk.path", &self.config.root_disk.path)?;
        validate_machine(&self.config)?;

        let mut command = QemuCommandParts::default();
        push_arg(&mut command, "-nodefaults");
        push_pair(
            &mut command,
            "-machine",
            format!("{DEFAULT_MACHINE_TYPE},accel={PRODUCTION_ACCELERATOR}"),
        );
        push_pair(&mut command, "-cpu", DEFAULT_CPU_MODEL);
        push_pair(
            &mut command,
            "-smp",
            self.config.machine.vcpu_count.to_string(),
        );
        push_pair(
            &mut command,
            "-m",
            format!("{}M", self.config.machine.memory_mib),
        );
        push_arg(&mut command, "-no-reboot");
        push_pair(&mut command, "-display", "none");
        push_pair(&mut command, "-monitor", "none");
        push_path_pair(
            &mut command,
            "-kernel",
            &self.config.kernel_image,
            "<kernel>",
        );
        push_path_pair(
            &mut command,
            "-initrd",
            &self.config.initrd_image,
            "<initrd>",
        );
        push_pair(
            &mut command,
            "-append",
            kernel_append(
                &self.config.kernel_append,
                self.config.control_channel.is_some(),
            )?,
        );
        push_pair_redacted(
            &mut command,
            "-drive",
            drive_arg(&self.config.root_disk)?,
            drive_arg_redacted(&self.config.root_disk),
        );
        push_pair(
            &mut command,
            "-device",
            format!("virtio-blk-pci,drive={ROOT_DRIVE_ID}"),
        );
        push_serial(&mut command, &self.config.serial)?;

        if let Some(control_channel) = &self.config.control_channel {
            push_control_channel(&mut command, control_channel)?;
        }

        if let Some(qmp) = &self.config.qmp {
            push_qmp(&mut command, qmp)?;
        }

        push_pair(&mut command, "-nic", "none");

        Ok(QemuCommand {
            program: self.config.qemu_executable.clone(),
            argv: command.argv,
            diagnostic_argv: command.diagnostic_argv,
            diagnostic_label: self.config.diagnostic_label.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum QemuArgvError {
    MissingRequiredInput {
        field: &'static str,
    },
    InvalidNumericInput {
        field: &'static str,
        reason: &'static str,
    },
    InvalidKernelAppend {
        field: &'static str,
        reason: &'static str,
    },
    InvalidQemuOptionValue {
        field: &'static str,
        reason: &'static str,
    },
}

impl fmt::Display for QemuArgvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingRequiredInput { field } => {
                write!(f, "missing required QEMU argv input: {field}")
            }
            Self::InvalidNumericInput { field, reason } => {
                write!(f, "invalid QEMU argv numeric input {field}: {reason}")
            }
            Self::InvalidKernelAppend { field, reason } => {
                write!(f, "invalid QEMU kernel append input {field}: {reason}")
            }
            Self::InvalidQemuOptionValue { field, reason } => {
                write!(f, "invalid QEMU option value {field}: {reason}")
            }
        }
    }
}

impl std::error::Error for QemuArgvError {}

#[derive(Debug, Default)]
struct QemuCommandParts {
    argv: Vec<OsString>,
    diagnostic_argv: Vec<String>,
}

fn validate_machine(config: &QemuBootConfig) -> Result<(), QemuArgvError> {
    if config.machine.vcpu_count == 0 {
        return Err(QemuArgvError::InvalidNumericInput {
            field: "machine.vcpu_count",
            reason: "must be greater than zero",
        });
    }
    if config.machine.memory_mib == 0 {
        return Err(QemuArgvError::InvalidNumericInput {
            field: "machine.memory_mib",
            reason: "must be greater than zero",
        });
    }
    Ok(())
}

fn validate_path(field: &'static str, path: &Path) -> Result<(), QemuArgvError> {
    if path.as_os_str().is_empty() {
        Err(QemuArgvError::MissingRequiredInput { field })
    } else {
        Ok(())
    }
}

fn push_arg(command: &mut QemuCommandParts, value: &'static str) {
    command.argv.push(value.into());
    command.diagnostic_argv.push(value.to_string());
}

fn push_pair(
    command: &mut QemuCommandParts,
    flag: &'static str,
    value: impl Into<OsString> + ToString,
) {
    let value = value.to_string();
    push_pair_redacted(command, flag, value.clone(), value);
}

fn push_pair_redacted(
    command: &mut QemuCommandParts,
    flag: &'static str,
    value: impl Into<OsString>,
    diagnostic_value: impl Into<String>,
) {
    command.argv.push(flag.into());
    command.argv.push(value.into());
    command.diagnostic_argv.push(flag.to_string());
    command.diagnostic_argv.push(diagnostic_value.into());
}

fn push_path_pair(
    command: &mut QemuCommandParts,
    flag: &'static str,
    path: &Path,
    diagnostic_value: &'static str,
) {
    command.argv.push(flag.into());
    command.argv.push(path.as_os_str().to_owned());
    command.diagnostic_argv.push(flag.to_string());
    command.diagnostic_argv.push(diagnostic_value.to_string());
}

fn kernel_append(
    append: &QemuKernelAppend,
    control_channel_enabled: bool,
) -> Result<String, QemuArgvError> {
    validate_kernel_token("kernel_append.console", &append.console)?;
    validate_kernel_token("kernel_append.root_device", &append.root_device)?;

    let mut values = vec![
        format!("console={}", append.console),
        format!("root={}", append.root_device),
        append.root_mode.as_kernel_arg().to_string(),
    ];

    if let Some(timeout) = append.panic_timeout {
        values.push(format!("panic={timeout}"));
    }

    let guest_transport = append.guest_transport.or_else(|| {
        control_channel_enabled.then_some(super::config::QemuGuestTransport::VirtioSerial)
    });
    if let Some(transport) = guest_transport {
        values.push(transport.as_kernel_arg().to_string());
    }

    Ok(values.join(" "))
}

fn validate_kernel_token(field: &'static str, value: &str) -> Result<(), QemuArgvError> {
    if value.is_empty() {
        return Err(QemuArgvError::InvalidKernelAppend {
            field,
            reason: "must not be empty",
        });
    }
    if value.chars().any(char::is_whitespace) {
        return Err(QemuArgvError::InvalidKernelAppend {
            field,
            reason: "must not contain whitespace",
        });
    }
    Ok(())
}

fn drive_arg(disk: &QemuDiskConfig) -> Result<String, QemuArgvError> {
    Ok(format!(
        "if=none,id={ROOT_DRIVE_ID},file={},format={}",
        path_as_qemu_option_value("root_disk.path", &disk.path)?,
        disk.format.as_qemu_arg()
    ))
}

fn drive_arg_redacted(disk: &QemuDiskConfig) -> String {
    format!(
        "if=none,id={ROOT_DRIVE_ID},file=<root-disk>,format={}",
        disk.format.as_qemu_arg()
    )
}

fn push_serial(
    command: &mut QemuCommandParts,
    serial: &QemuSerialConfig,
) -> Result<(), QemuArgvError> {
    match serial {
        QemuSerialConfig::File(path) => {
            validate_path("serial.file", path)?;
            push_pair_redacted(
                command,
                "-serial",
                format!("file:{}", path_as_qemu_string("serial.file", path)?),
                "file:<serial-log>",
            );
        }
        QemuSerialConfig::Null => push_pair(command, "-serial", "null"),
    }
    Ok(())
}

fn push_control_channel(
    command: &mut QemuCommandParts,
    control_channel: &QemuControlChannelConfig,
) -> Result<(), QemuArgvError> {
    validate_qemu_suboption("control_channel.pipe_name", &control_channel.pipe_name)?;
    validate_qemu_suboption("control_channel.port_name", &control_channel.port_name)?;

    push_pair(
        command,
        "-device",
        format!("virtio-serial-pci,id={CONTROL_BUS_ID}"),
    );
    push_pair_redacted(
        command,
        "-chardev",
        format!(
            "pipe,id={CONTROL_CHARDEV_ID},path={}",
            control_channel.pipe_name
        ),
        format!("pipe,id={CONTROL_CHARDEV_ID},path=<control-pipe>"),
    );
    push_pair(
        command,
        "-device",
        format!(
            "virtserialport,chardev={CONTROL_CHARDEV_ID},name={}",
            control_channel.port_name
        ),
    );
    Ok(())
}

fn push_qmp(command: &mut QemuCommandParts, qmp: &QemuQmpEndpoint) -> Result<(), QemuArgvError> {
    match qmp {
        QemuQmpEndpoint::NamedPipe { pipe_name } => {
            validate_qemu_suboption("qmp.pipe_name", pipe_name)?;
            push_pair_redacted(
                command,
                "-qmp",
                format!("pipe:{pipe_name},server=on,wait=off"),
                "pipe:<qmp-pipe>,server=on,wait=off",
            );
        }
    }
    Ok(())
}

fn path_as_qemu_option_value(field: &'static str, path: &Path) -> Result<String, QemuArgvError> {
    let value = path_as_qemu_string(field, path)?;
    Ok(value.replace(',', ",,"))
}

fn path_as_qemu_string(field: &'static str, path: &Path) -> Result<String, QemuArgvError> {
    path.as_os_str()
        .to_str()
        .map(str::to_string)
        .ok_or(QemuArgvError::InvalidQemuOptionValue {
            field,
            reason: "must be valid UTF-8 for QEMU option syntax",
        })
}

fn validate_qemu_suboption(field: &'static str, value: &str) -> Result<(), QemuArgvError> {
    if value.is_empty() {
        return Err(QemuArgvError::MissingRequiredInput { field });
    }
    if value.contains(',') {
        return Err(QemuArgvError::InvalidQemuOptionValue {
            field,
            reason: "must not contain comma separators",
        });
    }
    Ok(())
}

fn render_diagnostic_arg(value: &str) -> String {
    if value.chars().any(char::is_whitespace) {
        format!("\"{}\"", value.replace('"', "\\\""))
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows_x86_64::qemu::config::{
        QemuControlChannelConfig, QemuQmpEndpoint, QemuRootMode,
    };

    fn base_config() -> QemuBootConfig {
        QemuBootConfig::direct_linux_boot(
            r"C:\qemu\qemu-system-x86_64.exe",
            r"C:\lsb\Image",
            r"C:\lsb\initramfs.cpio.gz",
            r"C:\lsb\instances\abc\root.qcow2",
            r"C:\lsb\instances\abc\serial.log",
            2048,
            2,
        )
    }

    fn build(config: QemuBootConfig) -> QemuCommand {
        QemuArgvBuilder::new(config)
            .build()
            .expect("config should build argv")
    }

    fn os_vec(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    fn argv_as_strings(command: &QemuCommand) -> Vec<String> {
        command
            .argv
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn minimal_whpx_direct_linux_boot_argv_matches_golden() {
        let command = build(base_config());

        assert_eq!(
            command.argv,
            os_vec(&[
                "-nodefaults",
                "-machine",
                "q35,accel=whpx",
                "-cpu",
                "Westmere",
                "-smp",
                "2",
                "-m",
                "2048M",
                "-no-reboot",
                "-display",
                "none",
                "-monitor",
                "none",
                "-kernel",
                r"C:\lsb\Image",
                "-initrd",
                r"C:\lsb\initramfs.cpio.gz",
                "-append",
                "console=ttyS0 root=/dev/vda rw panic=-1",
                "-drive",
                r"if=none,id=root,file=C:\lsb\instances\abc\root.qcow2,format=qcow2",
                "-device",
                "virtio-blk-pci,drive=root",
                "-serial",
                r"file:C:\lsb\instances\abc\serial.log",
                "-nic",
                "none",
            ])
        );
    }

    #[test]
    fn raw_rootfs_direct_linux_boot_argv_uses_raw_drive_format() {
        let command = build(QemuBootConfig::direct_linux_boot_raw_rootfs(
            r"C:\qemu\qemu-system-x86_64.exe",
            r"C:\lsb\Image",
            r"C:\lsb\initramfs.cpio.gz",
            r"C:\lsb\instances\abc\rootfs.ext4",
            r"C:\lsb\instances\abc\diagnostics\serial.log",
            2048,
            2,
        ));

        assert!(command.argv.contains(&OsString::from(
            r"if=none,id=root,file=C:\lsb\instances\abc\rootfs.ext4,format=raw"
        )));
        assert!(!command
            .argv
            .iter()
            .any(|arg| arg.to_string_lossy().contains("format=qcow2")));
    }

    #[test]
    fn virtio_serial_control_and_qmp_argv_matches_golden() {
        let mut config = base_config();
        config.control_channel = Some(QemuControlChannelConfig::named_pipe("lsb-abc-control"));
        config.qmp = Some(QemuQmpEndpoint::named_pipe("lsb-abc-qmp"));

        let command = build(config);

        assert_eq!(
            command.argv,
            os_vec(&[
                "-nodefaults",
                "-machine",
                "q35,accel=whpx",
                "-cpu",
                "Westmere",
                "-smp",
                "2",
                "-m",
                "2048M",
                "-no-reboot",
                "-display",
                "none",
                "-monitor",
                "none",
                "-kernel",
                r"C:\lsb\Image",
                "-initrd",
                r"C:\lsb\initramfs.cpio.gz",
                "-append",
                "console=ttyS0 root=/dev/vda rw panic=-1 lsb.transport=virtio-serial",
                "-drive",
                r"if=none,id=root,file=C:\lsb\instances\abc\root.qcow2,format=qcow2",
                "-device",
                "virtio-blk-pci,drive=root",
                "-serial",
                r"file:C:\lsb\instances\abc\serial.log",
                "-device",
                "virtio-serial-pci,id=lsbserial0",
                "-chardev",
                "pipe,id=lsbctl,path=lsb-abc-control",
                "-device",
                "virtserialport,chardev=lsbctl,name=org.localsandbox.control",
                "-qmp",
                "pipe:lsb-abc-qmp,server=on,wait=off",
                "-nic",
                "none",
            ])
        );
    }

    #[test]
    fn windows_paths_with_spaces_preserve_argument_boundaries_and_escape_drive_commas() {
        let config = QemuBootConfig::direct_linux_boot(
            r"C:\Program Files\QEMU\qemu-system-x86_64.exe",
            r"C:\Users\me\AppData\Local\Local Sandbox\Image",
            r"C:\Users\me\AppData\Local\Local Sandbox\initramfs.cpio.gz",
            r"C:\Users\me\AppData\Local\Local Sandbox\instances\abc\root,one.qcow2",
            r"C:\Users\me\AppData\Local\Local Sandbox\instances\abc\serial log.txt",
            1024,
            1,
        );

        let command = build(config);

        assert_eq!(
            command.program,
            PathBuf::from(r"C:\Program Files\QEMU\qemu-system-x86_64.exe")
        );
        assert!(command.argv.contains(&OsString::from(
            r"C:\Users\me\AppData\Local\Local Sandbox\Image"
        )));
        assert!(command.argv.contains(&OsString::from(
            r"if=none,id=root,file=C:\Users\me\AppData\Local\Local Sandbox\instances\abc\root,,one.qcow2,format=qcow2"
        )));
        assert!(command.argv.contains(&OsString::from(
            r"file:C:\Users\me\AppData\Local\Local Sandbox\instances\abc\serial log.txt"
        )));
    }

    #[test]
    fn production_argv_uses_whpx_without_tcg_fallback() {
        let command = build(base_config());
        let argv = argv_as_strings(&command);

        assert!(argv.iter().any(|arg| arg == "q35,accel=whpx"));
        assert!(!argv.iter().any(|arg| arg.contains("tcg")));
        assert!(!argv.iter().any(|arg| arg.contains("whpx:tcg")));
    }

    #[test]
    fn whpx_direct_boot_uses_conservative_cpu_model() {
        let command = build(base_config());
        let argv = argv_as_strings(&command);

        assert!(argv.windows(2).any(|pair| pair == ["-cpu", "Westmere"]));
        assert!(!argv.windows(2).any(|pair| pair == ["-cpu", "max"]));
    }

    #[test]
    fn default_argv_has_no_guest_network_or_host_forwarding() {
        let command = build(base_config());
        let argv = argv_as_strings(&command);

        assert!(argv.windows(2).any(|pair| pair == ["-nic", "none"]));
        assert!(!argv.iter().any(|arg| arg == "-netdev"));
        assert!(!argv.iter().any(|arg| arg.contains("hostfwd")));
        assert!(!argv.iter().any(|arg| arg.contains("virtio-net")));
    }

    #[test]
    fn qmp_endpoint_is_private_pipe_only_in_generated_argv() {
        let mut config = base_config();
        config.qmp = Some(QemuQmpEndpoint::named_pipe("lsb-abc-qmp"));

        let command = build(config);
        let argv = argv_as_strings(&command);
        let qmp_arg = argv
            .windows(2)
            .find(|pair| pair[0] == "-qmp")
            .map(|pair| pair[1].clone())
            .expect("qmp arg should be present");

        assert_eq!(qmp_arg, "pipe:lsb-abc-qmp,server=on,wait=off");
        assert!(!qmp_arg.contains("tcp:"));
        assert!(!qmp_arg.contains("0.0.0.0"));
    }

    #[test]
    fn sanitized_display_redacts_paths_and_pipe_names() {
        let mut config = QemuBootConfig::direct_linux_boot(
            r"C:\TOPSECRET\qemu-system-x86_64.exe",
            r"C:\TOPSECRET\Image",
            r"C:\TOPSECRET\initramfs.cpio.gz",
            r"C:\TOPSECRET\root.qcow2",
            r"C:\TOPSECRET\serial.log",
            2048,
            2,
        );
        config.control_channel = Some(QemuControlChannelConfig::named_pipe(
            "lsb-TOPSECRET-control",
        ));
        config.qmp = Some(QemuQmpEndpoint::named_pipe("lsb-TOPSECRET-qmp"));
        config.diagnostic_label = Some("sandbox-abc".to_string());

        let command = build(config);
        let display = command.sanitized_display();

        assert_eq!(command.diagnostic_label(), Some("sandbox-abc"));
        assert!(!display.contains("TOPSECRET"));
        assert!(display.contains("<qemu-system-x86_64.exe>"));
        assert!(display.contains("-kernel <kernel>"));
        assert!(display.contains("file=<root-disk>"));
        assert!(display.contains("file:<serial-log>"));
        assert!(display.contains("path=<control-pipe>"));
        assert!(display.contains("pipe:<qmp-pipe>,server=on,wait=off"));
        assert!(command.sanitized_argv().contains(&"<initrd>".to_string()));
    }

    #[test]
    fn argument_order_is_deterministic() {
        let mut config = base_config();
        config.control_channel = Some(QemuControlChannelConfig::named_pipe("lsb-abc-control"));
        config.qmp = Some(QemuQmpEndpoint::named_pipe("lsb-abc-qmp"));

        let first = build(config.clone());
        let second = build(config);

        assert_eq!(first.argv, second.argv);
        assert_eq!(first.sanitized_argv(), second.sanitized_argv());
    }

    #[test]
    fn missing_required_inputs_are_reported_before_argv_is_returned() {
        let mut config = base_config();
        config.qemu_executable = PathBuf::new();

        let err = QemuArgvBuilder::new(config)
            .build()
            .expect_err("empty QEMU executable path should fail");

        assert_eq!(
            err,
            QemuArgvError::MissingRequiredInput {
                field: "qemu_executable"
            }
        );
    }

    #[test]
    fn invalid_kernel_append_values_are_rejected() {
        let mut config = base_config();
        config.kernel_append.root_mode = QemuRootMode::ReadOnly;
        config.kernel_append.root_device = "/dev/vda root=/dev/sda".to_string();

        let err = QemuArgvBuilder::new(config)
            .build()
            .expect_err("whitespace in kernel root device should fail");

        assert_eq!(
            err,
            QemuArgvError::InvalidKernelAppend {
                field: "kernel_append.root_device",
                reason: "must not contain whitespace"
            }
        );
    }
}
