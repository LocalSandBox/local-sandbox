#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod control_transport {
    use std::path::{Path, PathBuf};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum GuestControlTransport {
        Vsock,
        VirtioSerial,
    }

    pub(crate) fn from_kernel_cmdline(cmdline: &str) -> GuestControlTransport {
        if cmdline
            .split_ascii_whitespace()
            .any(|arg| arg == "lsb.transport=virtio-serial")
        {
            GuestControlTransport::VirtioSerial
        } else {
            GuestControlTransport::Vsock
        }
    }

    pub(crate) fn ready_message_for_transport(
        transport: GuestControlTransport,
    ) -> Option<lsb_proto::GuestReady> {
        match transport {
            GuestControlTransport::Vsock => None,
            GuestControlTransport::VirtioSerial => {
                let mut ready = lsb_proto::GuestReady::new(
                    lsb_proto::GuestTransport::VirtioSerial,
                    env!("CARGO_PKG_VERSION"),
                );
                ready
                    .capabilities
                    .push(lsb_proto::CAP_FILE_RANGE_IO.to_string());
                ready
                    .capabilities
                    .push(lsb_proto::CAP_PORT_FORWARD.to_string());
                ready
                    .capabilities
                    .push(lsb_proto::CAP_CIFS_MOUNT.to_string());
                ready
                    .capabilities
                    .push(lsb_proto::CAP_SESSION_MUX.to_string());
                Some(ready)
            }
        }
    }

    pub(crate) fn discover_virtio_serial_device(
        dev_root: &Path,
        sys_class_root: &Path,
        port_name: &str,
    ) -> std::io::Result<Option<PathBuf>> {
        let preferred = dev_root.join("virtio-ports").join(port_name);
        if preferred.exists() {
            return Ok(Some(preferred));
        }

        let entries = match std::fs::read_dir(sys_class_root) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err),
        };

        for entry in entries {
            let entry = entry?;
            let name_path = entry.path().join("name");
            let Ok(name) = std::fs::read_to_string(&name_path) else {
                continue;
            };
            if name.trim() == port_name {
                return Ok(Some(dev_root.join(entry.file_name())));
            }
        }

        Ok(None)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn temp_root(label: &str) -> PathBuf {
            std::env::temp_dir().join(format!(
                "lsb-guest-transport-{label}-{}",
                std::process::id()
            ))
        }

        #[test]
        fn cmdline_selects_virtio_serial_only_when_requested() {
            assert_eq!(
                from_kernel_cmdline("console=ttyS0 root=/dev/vda rw"),
                GuestControlTransport::Vsock
            );
            assert_eq!(
                from_kernel_cmdline("console=ttyS0 root=/dev/vda rw lsb.transport=virtio-serial"),
                GuestControlTransport::VirtioSerial
            );
        }

        #[test]
        fn ready_message_is_only_emitted_for_virtio_serial() {
            assert!(ready_message_for_transport(GuestControlTransport::Vsock).is_none());

            let ready = ready_message_for_transport(GuestControlTransport::VirtioSerial)
                .expect("virtio-serial should emit guest ready");
            assert_eq!(ready.protocol_version, lsb_proto::PROTOCOL_VERSION);
            assert_eq!(ready.transport, lsb_proto::GuestTransport::VirtioSerial);
            assert_eq!(ready.guest_version, env!("CARGO_PKG_VERSION"));
            assert_eq!(
                ready.capabilities,
                [
                    lsb_proto::CAP_FILE_RANGE_IO,
                    lsb_proto::CAP_PORT_FORWARD,
                    lsb_proto::CAP_CIFS_MOUNT,
                    lsb_proto::CAP_SESSION_MUX
                ]
            );
        }

        #[test]
        fn virtio_serial_discovery_prefers_dev_virtio_ports_symlink() {
            let root = temp_root("preferred");
            let dev_root = root.join("dev");
            let sys_root = root.join("sys/class/virtio-ports");
            let preferred = dev_root
                .join("virtio-ports")
                .join(lsb_proto::VIRTIO_SERIAL_CONTROL_PORT_NAME);
            std::fs::create_dir_all(preferred.parent().unwrap()).unwrap();
            std::fs::create_dir_all(&sys_root).unwrap();
            std::fs::write(&preferred, b"").unwrap();

            let discovered = discover_virtio_serial_device(
                &dev_root,
                &sys_root,
                lsb_proto::VIRTIO_SERIAL_CONTROL_PORT_NAME,
            )
            .unwrap();

            assert_eq!(discovered, Some(preferred));
            let _ = std::fs::remove_dir_all(root);
        }

        #[test]
        fn virtio_serial_discovery_falls_back_to_sysfs_name() {
            let root = temp_root("sysfs");
            let dev_root = root.join("dev");
            let sys_root = root.join("sys/class/virtio-ports");
            let port = sys_root.join("vport0p1");
            std::fs::create_dir_all(&port).unwrap();
            std::fs::create_dir_all(&dev_root).unwrap();
            std::fs::write(
                port.join("name"),
                format!("{}\n", lsb_proto::VIRTIO_SERIAL_CONTROL_PORT_NAME),
            )
            .unwrap();

            let discovered = discover_virtio_serial_device(
                &dev_root,
                &sys_root,
                lsb_proto::VIRTIO_SERIAL_CONTROL_PORT_NAME,
            )
            .unwrap();

            assert_eq!(discovered, Some(dev_root.join("vport0p1")));
            let _ = std::fs::remove_dir_all(root);
        }

        #[test]
        fn virtio_serial_discovery_reports_absent_port() {
            let root = temp_root("absent");
            let dev_root = root.join("dev");
            let sys_root = root.join("sys/class/virtio-ports");
            std::fs::create_dir_all(&dev_root).unwrap();

            let discovered = discover_virtio_serial_device(
                &dev_root,
                &sys_root,
                lsb_proto::VIRTIO_SERIAL_CONTROL_PORT_NAME,
            )
            .unwrap();

            assert_eq!(discovered, None);
            let _ = std::fs::remove_dir_all(root);
        }
    }
}

#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
mod file_transfer {
    use lsb_proto::{ReadFileRequest, WriteFileRequest};

    pub(crate) fn read_file_range(req: &ReadFileRequest) -> std::io::Result<Vec<u8>> {
        use std::io::{Read, Seek, SeekFrom};

        let len = req
            .len
            .unwrap_or(lsb_proto::FILE_TRANSFER_CHUNK_SIZE as u64);
        if len > lsb_proto::FILE_TRANSFER_CHUNK_SIZE as u64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "read range len {} exceeds max chunk {}",
                    len,
                    lsb_proto::FILE_TRANSFER_CHUNK_SIZE
                ),
            ));
        }

        let mut file = std::fs::File::open(&req.path)?;
        file.seek(SeekFrom::Start(req.offset.unwrap_or(0)))?;

        let mut data = Vec::with_capacity(len as usize);
        let mut limited = file.take(len);
        limited.read_to_end(&mut data)?;
        Ok(data)
    }

    pub(crate) fn write_file_range(req: &WriteFileRequest, data: &[u8]) -> std::io::Result<()> {
        use std::io::{Seek, SeekFrom, Write};

        if data.len() > lsb_proto::FILE_TRANSFER_CHUNK_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "write range len {} exceeds max chunk {}",
                    data.len(),
                    lsb_proto::FILE_TRANSFER_CHUNK_SIZE
                ),
            ));
        }

        if let Some(parent) = std::path::Path::new(&req.path).parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut options = std::fs::OpenOptions::new();
        options.create(true).write(true);
        if req.truncate.unwrap_or(false) {
            options.truncate(true);
        }
        let mut file = options.open(&req.path)?;
        file.seek(SeekFrom::Start(req.offset.unwrap_or(0)))?;
        file.write_all(data)?;
        file.sync_all()
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::path::PathBuf;
        use std::sync::atomic::{AtomicU64, Ordering};

        static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

        #[test]
        fn file_range_write_truncates_then_writes_at_offsets() {
            let root = temp_dir("write-range");
            let path = root.join("out.txt");
            let path_string = path.display().to_string();

            let first = WriteFileRequest {
                path: path_string.clone(),
                len: 5,
                offset: Some(0),
                truncate: Some(true),
            };
            write_file_range(&first, b"hello").expect("first chunk should write");

            let second = WriteFileRequest {
                path: path_string.clone(),
                len: 6,
                offset: Some(5),
                truncate: Some(false),
            };
            write_file_range(&second, b" world").expect("second chunk should write");

            let content = std::fs::read(&path).expect("written file should read");
            assert_eq!(content, b"hello world");

            let _ = std::fs::remove_dir_all(root);
        }

        #[test]
        fn file_range_read_returns_requested_slice() {
            let root = temp_dir("read-range");
            let path = root.join("input.txt");
            std::fs::create_dir_all(&root).expect("fixture root");
            std::fs::write(&path, b"abcdef").expect("fixture file");

            let req = ReadFileRequest {
                path: path.display().to_string(),
                offset: Some(2),
                len: Some(3),
            };

            let content = read_file_range(&req).expect("range should read");
            assert_eq!(content, b"cde");

            let _ = std::fs::remove_dir_all(root);
        }

        #[test]
        fn file_range_read_rejects_oversized_chunk() {
            let req = ReadFileRequest {
                path: "/tmp/missing".to_string(),
                offset: Some(0),
                len: Some(lsb_proto::FILE_TRANSFER_CHUNK_SIZE as u64 + 1),
            };

            let err = read_file_range(&req).expect_err("oversized chunk should fail first");
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        }

        fn temp_dir(label: &str) -> PathBuf {
            let nonce = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "lsb-guest-file-{label}-{}-{nonce}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&root);
            root
        }
    }
}

#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
mod smb_mount {
    use lsb_proto::MountRequest;

    pub(crate) const MOUNT_CIFS: &str = "/sbin/mount.cifs";
    pub(crate) const WINDOWS_SMB_GATEWAY_IP: &str = "10.0.0.1";

    const RESERVED_OPTION_KEYS: &[&str] = &[
        "actimeo",
        "cache",
        "cred",
        "credentials",
        "dir_mode",
        "domain",
        "file_mode",
        "forcegid",
        "forceuid",
        "gid",
        "guest",
        "iocharset",
        "ip",
        "mfsymlinks",
        "noperm",
        "pass",
        "password",
        "password2",
        "passwd",
        "port",
        "ro",
        "rw",
        "sec",
        "serverino",
        "uid",
        "user",
        "username",
        "vers",
    ];

    pub(crate) fn service_path(server: &str, share: &str) -> String {
        format!("//{server}/{share}")
    }

    pub(crate) fn options_for_request(req: &MountRequest) -> Result<Vec<String>, String> {
        let MountRequest::Smb {
            server,
            share,
            username,
            domain,
            read_only,
            uid,
            gid,
            file_mode,
            dir_mode,
            options,
            ..
        } = req
        else {
            return Err("expected SMB mount request".to_string());
        };

        validate_required_component("server", server)?;
        validate_required_component("share", share)?;
        validate_option_value("username", username)?;
        validate_option_value("domain", domain)?;
        validate_mode("file_mode", *file_mode)?;
        validate_mode("dir_mode", *dir_mode)?;

        let mut mount_options = vec![
            "vers=3.1.1".to_string(),
            "sec=ntlmssp".to_string(),
            format!("ip={WINDOWS_SMB_GATEWAY_IP}"),
            format!("username={username}"),
            format!("domain={domain}"),
            "port=445".to_string(),
            format!("uid={uid}"),
            format!("gid={gid}"),
            "forceuid".to_string(),
            "forcegid".to_string(),
            "cache=strict".to_string(),
            "actimeo=1".to_string(),
            "iocharset=utf8".to_string(),
            "serverino".to_string(),
            if *read_only { "ro" } else { "rw" }.to_string(),
            format!("file_mode={file_mode:04o}"),
            format!("dir_mode={dir_mode:04o}"),
        ];

        for option in options {
            validate_extra_option(option)?;
            mount_options.push(option.clone());
        }

        Ok(mount_options)
    }

    pub(crate) fn option_string(options: &[String]) -> String {
        options.join(",")
    }

    pub(crate) fn sanitized_command_stderr(stderr: &[u8]) -> String {
        let text = String::from_utf8_lossy(stderr);
        let mut sanitized = text
            .chars()
            .map(|ch| {
                if ch == '\n' || ch == '\r' || ch == '\t' || !ch.is_control() {
                    ch
                } else {
                    ' '
                }
            })
            .collect::<String>();
        sanitized = sanitized.trim().to_string();
        if sanitized.is_empty() {
            return "<empty>".to_string();
        }
        const MAX_LEN: usize = 512;
        if sanitized.len() > MAX_LEN {
            sanitized.truncate(MAX_LEN);
            sanitized.push_str("...");
        }
        sanitized
    }

    pub(crate) fn sanitized_kernel_cifs_messages(dmesg: &str) -> Option<String> {
        let mut lines = dmesg
            .lines()
            .filter(|line| {
                let lower = line.to_ascii_lowercase();
                lower.contains("cifs") || lower.contains("smb")
            })
            .collect::<Vec<_>>();

        if lines.is_empty() {
            return None;
        }

        const MAX_LINES: usize = 8;
        if lines.len() > MAX_LINES {
            lines = lines.split_off(lines.len() - MAX_LINES);
        }

        Some(sanitized_command_stderr(lines.join(" | ").as_bytes()))
    }

    fn validate_required_component(name: &str, value: &str) -> Result<(), String> {
        if value.is_empty() {
            return Err(format!("SMB mount {name} must not be empty"));
        }
        if value
            .chars()
            .any(|ch| matches!(ch, '/' | '\\' | '\0' | '\n' | '\r'))
        {
            return Err(format!("SMB mount {name} contains unsupported characters"));
        }
        Ok(())
    }

    fn validate_option_value(name: &str, value: &str) -> Result<(), String> {
        if value.is_empty() {
            return Err(format!("SMB mount {name} must not be empty"));
        }
        if contains_option_separator(value) {
            return Err(format!("SMB mount {name} contains unsupported characters"));
        }
        Ok(())
    }

    fn validate_mode(name: &str, mode: u32) -> Result<(), String> {
        if mode > 0o7777 {
            return Err(format!("SMB mount {name} is out of range"));
        }
        Ok(())
    }

    fn validate_extra_option(option: &str) -> Result<(), String> {
        if option.is_empty() {
            return Err("SMB mount option must not be empty".to_string());
        }
        if contains_option_separator(option) {
            return Err("SMB mount option contains unsupported characters".to_string());
        }

        let key = option
            .split_once('=')
            .map_or(option, |(key, _)| key)
            .to_ascii_lowercase();
        if key.is_empty()
            || RESERVED_OPTION_KEYS.contains(&key.as_str())
            || key.starts_with("password")
            || key.starts_with("passwd")
        {
            return Err(format!("SMB mount option '{key}' is not allowed"));
        }

        Ok(())
    }

    fn contains_option_separator(value: &str) -> bool {
        value
            .chars()
            .any(|ch| matches!(ch, ',' | '\0' | '\n' | '\r'))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn smb_request(options: Vec<String>) -> MountRequest {
            MountRequest::Smb {
                server: "localhost".to_string(),
                share: "lsb-test-m0-abcd".to_string(),
                target: "/workspace".to_string(),
                username: "lsb_123456789abc".to_string(),
                password: "SecretPassword123!".to_string(),
                domain: "WINHOST".to_string(),
                read_only: false,
                uid: 0,
                gid: 0,
                file_mode: 0o666,
                dir_mode: 0o777,
                options,
            }
        }

        #[test]
        fn service_path_uses_unc_style_mount_source() {
            assert_eq!(MOUNT_CIFS, "/sbin/mount.cifs");
            assert_eq!(
                service_path("localhost", "lsb-test-m0-abcd"),
                "//localhost/lsb-test-m0-abcd"
            );
        }

        #[test]
        fn smb_options_include_required_mount_cifs_options() {
            let req = smb_request(vec!["echo_interval=30".to_string()]);

            let options = options_for_request(&req).expect("SMB options should build");
            let option_string = option_string(&options);

            assert!(option_string.contains("vers=3.1.1"));
            assert!(option_string.contains("sec=ntlmssp"));
            assert!(option_string.contains("ip=10.0.0.1"));
            assert!(option_string.contains("username=lsb_123456789abc"));
            assert!(option_string.contains("domain=WINHOST"));
            assert!(option_string.contains("port=445"));
            assert!(option_string.contains("uid=0"));
            assert!(option_string.contains("gid=0"));
            assert!(option_string.contains("forceuid"));
            assert!(option_string.contains("forcegid"));
            assert!(option_string.contains("cache=strict"));
            assert!(option_string.contains("actimeo=1"));
            assert!(option_string.contains("iocharset=utf8"));
            assert!(option_string.contains("serverino"));
            assert!(option_string.contains("rw"));
            assert!(option_string.contains("file_mode=0666"));
            assert!(option_string.contains("dir_mode=0777"));
            assert!(option_string.contains("echo_interval=30"));
            assert!(!option_string.contains("SecretPassword123!"));
        }

        #[test]
        fn smb_options_use_read_only_flag_and_modes() {
            let mut req = smb_request(Vec::new());
            let MountRequest::Smb {
                read_only,
                file_mode,
                dir_mode,
                ..
            } = &mut req
            else {
                unreachable!();
            };
            *read_only = true;
            *file_mode = 0o644;
            *dir_mode = 0o755;

            let options = options_for_request(&req).expect("SMB options should build");
            let option_string = option_string(&options);

            assert!(option_string.contains("ro"));
            assert!(option_string.contains("file_mode=0644"));
            assert!(option_string.contains("dir_mode=0755"));
        }

        #[test]
        fn smb_options_reject_secret_bearing_options() {
            for option in [
                "password=secret",
                "passwd=secret",
                "credentials=/tmp/creds",
                "user=someone",
                "username=someone",
                "domain=OTHER",
                "ip=192.0.2.1",
            ] {
                let err = options_for_request(&smb_request(vec![option.to_string()]))
                    .expect_err("secret-bearing option should be rejected");
                assert!(err.contains("not allowed"));
            }
        }

        #[test]
        fn smb_options_reject_disabled_v1_options() {
            for option in ["mfsymlinks", "noperm"] {
                let err = options_for_request(&smb_request(vec![option.to_string()]))
                    .expect_err("disabled SMB option should be rejected");
                assert!(err.contains("not allowed"));
            }
        }

        #[test]
        fn smb_options_reject_comma_injection() {
            let err = options_for_request(&smb_request(vec!["echo_interval=30,password=x".into()]))
                .expect_err("comma injection should be rejected");

            assert!(err.contains("unsupported characters"));
        }

        #[test]
        fn mount_cifs_stderr_is_sanitized_and_bounded() {
            let stderr = b"mount error(13): Permission denied\0\nRefer to mount.cifs(8)";
            let sanitized = sanitized_command_stderr(stderr);

            assert_eq!(
                sanitized,
                "mount error(13): Permission denied \nRefer to mount.cifs(8)"
            );

            let long = sanitized_command_stderr(&vec![b'x'; 600]);
            assert!(long.ends_with("..."));
            assert!(long.len() <= 515);
        }

        #[test]
        fn kernel_cifs_messages_are_filtered_and_bounded() {
            let dmesg = [
                "[0.1] unrelated",
                "[1.1] CIFS: VFS: parse_server_interfaces: malformed interface info",
                "[1.2] smb3: reconnect failed",
            ]
            .join("\n");

            let sanitized =
                sanitized_kernel_cifs_messages(&dmesg).expect("CIFS lines should be kept");

            assert!(sanitized.contains("CIFS: VFS"));
            assert!(sanitized.contains("smb3"));
            assert!(!sanitized.contains("unrelated"));
        }
    }
}

#[cfg(target_os = "linux")]
mod guest {
    use std::fs::{File, OpenOptions};
    use std::io::{self, Read, Write};
    use std::net::TcpListener;
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
    use std::os::unix::process::CommandExt;
    use std::path::Path;
    use std::process::{Child, Command, ExitStatus, Stdio};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::{Duration, Instant};

    use super::control_transport::{self, GuestControlTransport};
    use super::file_transfer;
    use super::smb_mount;
    use lsb_proto::frame;
    use lsb_proto::{mux, mux::MuxFrame};
    use lsb_proto::{
        ChmodRequest, CopyRequest, DirEntry, ExecRequest, ForwardRequest, ForwardResponse,
        FsOkResponse, MkdirRequest, MountRequest, MountResponse, ReadDirRequest, ReadDirResponse,
        ReadFileRequest, RemoveRequest, RenameRequest, StatRequest, StatResponse, WatchEvent,
        WatchRequest, WriteFileRequest, WriteFileResponse,
    };
    use lsb_proto::{VSOCK_PORT, VSOCK_PORT_FORWARD};

    const MOUNT_CIFS_TIMEOUT: Duration = Duration::from_secs(60);
    const MOUNT_CIFS_KILL_GRACE: Duration = Duration::from_secs(2);
    const MOUNT_CIFS_POLL_INTERVAL: Duration = Duration::from_millis(50);

    trait PhysicalControlStream: Read + Write + AsRawFd + IntoRawFd + Send + 'static {
        fn try_clone_stream(&self) -> std::io::Result<Self>
        where
            Self: Sized;

        fn configure_for_lsb(&self) {}
    }

    impl PhysicalControlStream for std::net::TcpStream {
        fn try_clone_stream(&self) -> std::io::Result<Self> {
            self.try_clone()
        }

        fn configure_for_lsb(&self) {
            let _ = self.set_nodelay(true);
        }
    }

    impl PhysicalControlStream for File {
        fn try_clone_stream(&self) -> std::io::Result<Self> {
            self.try_clone()
        }
    }

    fn mount_fs(source: &str, target: &str, fstype: &str, data: Option<&str>) -> bool {
        mount_fs_with_flags(source, target, fstype, 0, data)
    }

    fn mount_fs_with_flags(
        source: &str,
        target: &str,
        fstype: &str,
        flags: libc::c_ulong,
        data: Option<&str>,
    ) -> bool {
        use std::ffi::CString;

        let c_source = CString::new(source).unwrap();
        let c_target = CString::new(target).unwrap();
        let c_fstype = CString::new(fstype).unwrap();

        let data_ptr = data.map(|d| CString::new(d).unwrap());
        let ret = unsafe {
            libc::mount(
                c_source.as_ptr(),
                c_target.as_ptr(),
                c_fstype.as_ptr(),
                flags,
                data_ptr
                    .as_ref()
                    .map_or(std::ptr::null(), |d| d.as_ptr() as *const libc::c_void),
            )
        };
        if ret != 0 {
            eprintln!(
                "lsb-guest: failed to mount {} on {}: {}",
                source,
                target,
                std::io::Error::last_os_error()
            );
            return false;
        }
        true
    }

    fn mount_filesystems() {
        mount_fs("proc", "/proc", "proc", None);
        mount_fs("sysfs", "/sys", "sysfs", None);
        mount_fs("devtmpfs", "/dev", "devtmpfs", None);
        std::fs::create_dir_all("/dev/pts").ok();
        mount_fs(
            "devpts",
            "/dev/pts",
            "devpts",
            Some("newinstance,ptmxmode=0666"),
        );
        mount_fs("tmpfs", "/tmp", "tmpfs", None);
    }

    fn process_mount(req: &MountRequest) -> MountResponse {
        let (source, target) = match req {
            MountRequest::Overlay { source, target } => (source.clone(), target.as_str()),
            MountRequest::Direct { source, target, .. } => (source.clone(), target.as_str()),
            MountRequest::Smb { target, .. } => {
                ("Windows SMB direct mount".to_string(), target.as_str())
            }
        };

        if let Err(e) = std::fs::create_dir_all(target) {
            return MountResponse {
                source,
                target: target.to_string(),
                ok: false,
                error: Some(format!("failed to create mount point {}: {}", target, e)),
            };
        }

        let result = match req {
            MountRequest::Overlay { source, target } => mount_overlay(source, target),
            MountRequest::Direct {
                source,
                target,
                flags,
            } => mount_direct(source, target, *flags),
            MountRequest::Smb { .. } => mount_smb(req),
        };

        match result {
            Ok(()) => MountResponse {
                source,
                target: target.to_string(),
                ok: true,
                error: None,
            },
            Err(msg) => MountResponse {
                source,
                target: target.to_string(),
                ok: false,
                error: Some(msg),
            },
        }
    }

    fn mount_overlay(source: &str, target: &str) -> Result<(), String> {
        if source.starts_with('/') {
            return mount_imported_overlay(source, target);
        }

        let virtiofs_dir = format!("/mnt/.virtiofs/{}", source);
        mount_overlay_lower(source, &virtiofs_dir, target, true)
    }

    fn mount_imported_overlay(source: &str, target: &str) -> Result<(), String> {
        let source_path = Path::new(source);
        if !source_path.is_absolute() {
            return Err(format!(
                "imported mount source '{}' must be absolute",
                source
            ));
        }
        let metadata = std::fs::metadata(source_path).map_err(|e| {
            format!(
                "failed to inspect imported mount source '{}': {}",
                source, e
            )
        })?;
        if !metadata.is_dir() {
            return Err(format!(
                "imported mount source '{}' is not a directory",
                source
            ));
        }

        mount_overlay_lower(source, source, target, false)
    }

    fn mount_overlay_lower(
        source_label: &str,
        lower_dir: &str,
        target: &str,
        mount_virtiofs_lower: bool,
    ) -> Result<(), String> {
        let overlay_dir = format!("/mnt/.overlay/{}", overlay_id(source_label));
        let upper_dir = format!("{}/upper", overlay_dir);
        let work_dir = format!("{}/work", overlay_dir);

        std::fs::create_dir_all(lower_dir)
            .and_then(|_| std::fs::create_dir_all(&upper_dir))
            .and_then(|_| std::fs::create_dir_all(&work_dir))
            .map_err(|e| format!("failed to create staging dirs: {}", e))?;

        if mount_virtiofs_lower && !mount_fs(source_label, lower_dir, "virtiofs", None) {
            return Err(format!(
                "failed to mount virtiofs device '{}'",
                source_label
            ));
        }

        if !mount_fs("tmpfs", &overlay_dir, "tmpfs", None) {
            return Err(format!(
                "failed to mount tmpfs for overlay on '{}'",
                source_label
            ));
        }

        // Re-create upper/work after tmpfs mount
        std::fs::create_dir_all(&upper_dir)
            .and_then(|_| std::fs::create_dir_all(&work_dir))
            .map_err(|e| format!("failed to create overlay dirs after tmpfs: {}", e))?;

        let overlay_opts = format!(
            "lowerdir={},upperdir={},workdir={}",
            lower_dir, upper_dir, work_dir
        );
        if !mount_fs("overlay", target, "overlay", Some(&overlay_opts)) {
            return Err(format!("failed to mount overlay at {}", target));
        }

        eprintln!(
            "lsb-guest: mounted {} -> {} (overlay)",
            source_label, target
        );
        Ok(())
    }

    fn mount_smb(req: &MountRequest) -> Result<(), String> {
        let MountRequest::Smb {
            server,
            share,
            target,
            password,
            ..
        } = req
        else {
            return Err("expected SMB mount request".to_string());
        };

        let service = smb_mount::service_path(server, share);
        let options = smb_mount::options_for_request(req)?;
        run_mount_cifs_with_passwd_fd(&service, target, &options, password)?;

        eprintln!("lsb-guest: mounted SMB share at {}", target);
        Ok(())
    }

    fn run_mount_cifs_with_passwd_fd(
        service: &str,
        target: &str,
        options: &[String],
        password: &str,
    ) -> Result<(), String> {
        let mut pipe_fds = [0; 2];
        if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
            return Err(format!(
                "failed to prepare SMB password pipe for {}: {}",
                target,
                std::io::Error::last_os_error()
            ));
        }

        let read_fd = pipe_fds[0];
        let write_fd = pipe_fds[1];
        let read_file = unsafe { File::from_raw_fd(read_fd) };
        let mut write_file = unsafe { File::from_raw_fd(write_fd) };

        set_fd_cloexec(read_file.as_raw_fd(), false)
            .map_err(|err| format!("failed to prepare SMB password fd for {}: {}", target, err))?;
        set_fd_cloexec(write_file.as_raw_fd(), true).map_err(|err| {
            format!(
                "failed to prepare SMB password writer for {}: {}",
                target, err
            )
        })?;

        write_file
            .write_all(password.as_bytes())
            .and_then(|_| write_file.flush())
            .map_err(|err| format!("failed to write SMB password for {}: {}", target, err))?;
        drop(write_file);

        let stderr_path = mount_cifs_stderr_path();
        let stderr_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&stderr_path)
            .map_err(|err| {
                format!(
                    "failed to prepare mount.cifs stderr capture for {}: {}",
                    target, err
                )
            })?;

        let passwd_fd = read_file.as_raw_fd().to_string();
        let child = match Command::new(smb_mount::MOUNT_CIFS)
            .arg(service)
            .arg(target)
            .arg("-o")
            .arg(smb_mount::option_string(options))
            .env_clear()
            .env("PASSWD_FD", passwd_fd)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr_file))
            .spawn()
        {
            Ok(child) => child,
            Err(err) => {
                let _ = std::fs::remove_file(&stderr_path);
                return Err(format!(
                    "failed to execute mount.cifs for {}: {}",
                    target, err
                ));
            }
        };
        drop(read_file);

        let output = match wait_for_mount_cifs(child, target, MOUNT_CIFS_TIMEOUT) {
            Ok(output) => output,
            Err(error) => {
                let _ = std::fs::remove_file(&stderr_path);
                return Err(error);
            }
        };
        let stderr = std::fs::read(&stderr_path).unwrap_or_default();
        let _ = std::fs::remove_file(&stderr_path);
        if !output.timed_out && output.status.is_some_and(|status| status.success()) {
            return Ok(());
        }

        let stderr = sanitized_mount_cifs_stderr(&stderr);
        let mut message = if output.timed_out {
            format!(
                "failed to mount SMB share at {}: mount.cifs timed out after {} seconds; stderr: {}",
                target,
                MOUNT_CIFS_TIMEOUT.as_secs(),
                stderr
            )
        } else {
            let status = output.status.map_or_else(
                || "unknown status".to_string(),
                mount_cifs_status_description,
            );
            format!(
                "failed to mount SMB share at {}: mount.cifs exited with status {}; stderr: {}",
                target, status, stderr
            )
        };
        if let Some(dmesg) = recent_cifs_dmesg() {
            message.push_str("; dmesg: ");
            message.push_str(&dmesg);
        }
        Err(message)
    }

    struct MountCifsOutput {
        status: Option<ExitStatus>,
        timed_out: bool,
    }

    fn wait_for_mount_cifs(
        mut child: Child,
        target: &str,
        timeout: Duration,
    ) -> Result<MountCifsOutput, String> {
        let deadline = Instant::now() + timeout;

        let (status, timed_out) = loop {
            match child.try_wait() {
                Ok(Some(status)) => break (Some(status), false),
                Ok(None) if Instant::now() >= deadline => {
                    let kill_result = child.kill();
                    let status = poll_child_exit(&mut child, MOUNT_CIFS_KILL_GRACE)
                        .ok()
                        .flatten();
                    if let Err(error) = kill_result {
                        eprintln!(
                            "lsb-guest: failed to kill timed-out mount.cifs for {}: {}",
                            target, error
                        );
                    }
                    if status.is_none() {
                        eprintln!(
                            "lsb-guest: timed-out mount.cifs for {} did not exit within {} seconds after kill",
                            target,
                            MOUNT_CIFS_KILL_GRACE.as_secs()
                        );
                    }
                    break (status, true);
                }
                Ok(None) => std::thread::sleep(MOUNT_CIFS_POLL_INTERVAL),
                Err(error) => {
                    let _ = child.kill();
                    let _ = poll_child_exit(&mut child, MOUNT_CIFS_KILL_GRACE);
                    return Err(format!(
                        "failed to poll mount.cifs for {}: {}",
                        target, error
                    ));
                }
            }
        };

        Ok(MountCifsOutput { status, timed_out })
    }

    fn poll_child_exit(
        child: &mut Child,
        timeout: Duration,
    ) -> std::io::Result<Option<ExitStatus>> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = child.try_wait()? {
                return Ok(Some(status));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            std::thread::sleep(MOUNT_CIFS_POLL_INTERVAL);
        }
    }

    fn mount_cifs_status_description(status: ExitStatus) -> String {
        status.code().map_or_else(
            || "terminated by signal".to_string(),
            |code| code.to_string(),
        )
    }

    fn sanitized_mount_cifs_stderr(stderr: &[u8]) -> String {
        let stderr = smb_mount::sanitized_command_stderr(stderr);
        if stderr.is_empty() {
            "<empty>".to_string()
        } else {
            stderr
        }
    }

    fn mount_cifs_stderr_path() -> String {
        format!(
            "/tmp/lsb-mount-cifs-{}-{}.stderr",
            std::process::id(),
            monotonic_mount_cifs_id()
        )
    }

    fn monotonic_mount_cifs_id() -> u64 {
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    fn set_fd_cloexec(fd: RawFd, enabled: bool) -> std::io::Result<()> {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            return Err(std::io::Error::last_os_error());
        }

        let next_flags = if enabled {
            flags | libc::FD_CLOEXEC
        } else {
            flags & !libc::FD_CLOEXEC
        };
        if unsafe { libc::fcntl(fd, libc::F_SETFD, next_flags) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn recent_cifs_dmesg() -> Option<String> {
        let output = Command::new("/bin/dmesg")
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&output.stdout);
        smb_mount::sanitized_kernel_cifs_messages(&text)
    }

    fn overlay_id(source: &str) -> String {
        source
            .chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                    ch
                } else {
                    '_'
                }
            })
            .collect()
    }

    fn mount_direct(source: &str, target: &str, flags: u64) -> Result<(), String> {
        let mount_flags: libc::c_ulong = flags
            .try_into()
            .map_err(|_| format!("mount flags out of range: {}", flags))?;

        if !mount_fs_with_flags(source, target, "virtiofs", mount_flags, None) {
            return Err(format!(
                "failed to mount virtiofs device '{}' at {}",
                source, target
            ));
        }

        eprintln!(
            "lsb-guest: mounted {} -> {} (direct flags={})",
            source, target, flags
        );
        Ok(())
    }

    fn bring_up_interface(sock: i32, name: &[u8]) {
        unsafe {
            let mut ifr: libc::ifreq = std::mem::zeroed();
            let copy_len = name.len().min(libc::IFNAMSIZ);
            std::ptr::copy_nonoverlapping(
                name.as_ptr(),
                ifr.ifr_name.as_mut_ptr() as *mut u8,
                copy_len,
            );

            let display_name = String::from_utf8_lossy(&name[..name.len().saturating_sub(1)]);
            if libc::ioctl(sock, libc::SIOCGIFFLAGS as _, &mut ifr) < 0 {
                eprintln!("lsb-guest: failed to get {} flags", display_name);
                return;
            }

            ifr.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
            if libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &ifr) < 0 {
                eprintln!("lsb-guest: failed to bring up {}", display_name);
            }
        }
    }

    // --- Networking setup ---
    // Network is configured by initramfs before switch_root (static IP for proxy).
    // By the time we get here, eth0 already has an IP if --allow-net was used.

    fn setup_networking() {
        unsafe {
            let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
            if sock < 0 {
                eprintln!("lsb-guest: failed to create socket for networking setup");
                return;
            }

            bring_up_interface(sock, b"lo\0");

            // Check if eth0 exists (network device present)
            let has_eth0 = {
                let mut ifr: libc::ifreq = std::mem::zeroed();
                std::ptr::copy_nonoverlapping(
                    b"eth0\0".as_ptr(),
                    ifr.ifr_name.as_mut_ptr() as *mut u8,
                    5,
                );
                libc::ioctl(sock, libc::SIOCGIFFLAGS as _, &mut ifr) == 0
            };

            if !has_eth0 {
                libc::close(sock);
                eprintln!("lsb-guest: no network device (sandbox mode)");
                return;
            }

            // Check if eth0 already has an IP (configured by initramfs)
            let has_ip = {
                let mut ifr: libc::ifreq = std::mem::zeroed();
                std::ptr::copy_nonoverlapping(
                    b"eth0\0".as_ptr(),
                    ifr.ifr_name.as_mut_ptr() as *mut u8,
                    5,
                );
                libc::ioctl(sock, libc::SIOCGIFADDR as _, &mut ifr) == 0
            };

            libc::close(sock);

            if has_ip {
                eprintln!("lsb-guest: network already configured (by initramfs)");
            } else {
                eprintln!("lsb-guest: eth0 present but no IP configured");
            }
        }
    }

    fn reap_zombies() {
        loop {
            let ret = unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) };
            if ret <= 0 {
                break;
            }
        }
    }

    fn create_vsock_listener(port: u32) -> i32 {
        unsafe {
            let fd = libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0);
            if fd < 0 {
                panic!(
                    "lsb-guest: failed to create vsock socket: {}",
                    std::io::Error::last_os_error()
                );
            }

            #[repr(C)]
            struct SockaddrVm {
                svm_family: libc::sa_family_t,
                svm_reserved1: u16,
                svm_port: u32,
                svm_cid: u32,
                svm_flags: u8,
                svm_zero: [u8; 3],
            }

            let addr = SockaddrVm {
                svm_family: libc::AF_VSOCK as libc::sa_family_t,
                svm_reserved1: 0,
                svm_port: port,
                svm_cid: libc::VMADDR_CID_ANY,
                svm_flags: 0,
                svm_zero: [0; 3],
            };

            let ret = libc::bind(
                fd,
                &addr as *const SockaddrVm as *const libc::sockaddr,
                std::mem::size_of::<SockaddrVm>() as libc::socklen_t,
            );
            if ret < 0 {
                panic!(
                    "lsb-guest: failed to bind vsock on port {}: {}",
                    port,
                    std::io::Error::last_os_error()
                );
            }

            let ret = libc::listen(fd, 1);
            if ret < 0 {
                panic!(
                    "lsb-guest: failed to listen on vsock: {}",
                    std::io::Error::last_os_error()
                );
            }

            fd
        }
    }

    /// Write a binary frame using `writev` for a single atomic syscall.
    /// Used by the PTY poll loop where we have a raw fd instead of a std Write.
    fn write_frame_fd(fd: i32, msg_type: u8, payload: &[u8]) {
        let len = 1u32 + payload.len() as u32;
        let len_bytes = len.to_be_bytes();
        let type_byte = [msg_type];
        let iov = [
            libc::iovec {
                iov_base: len_bytes.as_ptr() as *mut libc::c_void,
                iov_len: 4,
            },
            libc::iovec {
                iov_base: type_byte.as_ptr() as *mut libc::c_void,
                iov_len: 1,
            },
            libc::iovec {
                iov_base: payload.as_ptr() as *mut libc::c_void,
                iov_len: payload.len(),
            },
        ];
        unsafe {
            libc::writev(fd, iov.as_ptr(), 3);
        }
    }

    fn handle_vsock_connection(fd: RawFd) {
        // SAFETY: fd is a valid socket from accept().
        let stream = unsafe { std::net::TcpStream::from_raw_fd(fd) };
        handle_control_stream(
            stream,
            control_transport::ready_message_for_transport(GuestControlTransport::Vsock),
        );
    }

    fn handle_control_stream<S>(stream: S, ready_message: Option<lsb_proto::GuestReady>)
    where
        S: PhysicalControlStream,
    {
        stream.configure_for_lsb();
        let mut reader = match stream.try_clone_stream() {
            Ok(reader) => reader,
            Err(err) => {
                eprintln!("lsb-guest: failed to clone control stream: {}", err);
                return;
            }
        };
        let mut writer = stream;

        if let Some(ready) = ready_message {
            if let Err(err) = frame::send_json(&mut writer, frame::GUEST_READY, &ready) {
                eprintln!("lsb-guest: failed to send guest ready handshake: {}", err);
                return;
            }
            eprintln!(
                "lsb-guest: sent guest ready handshake over {:?} with protocol version {}",
                ready.transport, ready.protocol_version
            );
        }

        loop {
            let (msg_type, payload) = match frame::read_frame(&mut reader) {
                Ok(Some(f)) => f,
                _ => break, // EOF or error
            };

            match msg_type {
                frame::MOUNT_REQ => {
                    let mount_req: MountRequest = match serde_json::from_slice(&payload) {
                        Ok(r) => r,
                        Err(e) => {
                            let msg = format!("invalid mount request: {}", e);
                            let _ = frame::write_frame(&mut writer, frame::ERROR, msg.as_bytes());
                            continue;
                        }
                    };
                    let resp = process_mount(&mount_req);
                    let _ = frame::send_json(&mut writer, frame::MOUNT_RESP, &resp);
                }
                frame::EXEC_REQ => {
                    let req: ExecRequest = match serde_json::from_slice(&payload) {
                        Ok(r) => r,
                        Err(e) => {
                            let msg = format!("invalid exec request: {}", e);
                            let _ = frame::write_frame(&mut writer, frame::ERROR, msg.as_bytes());
                            continue;
                        }
                    };

                    if req.argv.is_empty() {
                        let _ = frame::write_frame(&mut writer, frame::ERROR, b"empty argv");
                        continue;
                    }

                    if req.tty.unwrap_or(false) {
                        // TTY mode: hand off the raw fd
                        let raw_fd = writer.into_raw_fd();
                        drop(reader);
                        handle_tty_exec(raw_fd, &req);
                        return;
                    }

                    // Non-TTY streaming mode: takes ownership of streams
                    handle_piped_exec(&req, reader, writer);
                    return;
                }
                frame::WATCH_REQ => {
                    let req: WatchRequest = match serde_json::from_slice(&payload) {
                        Ok(r) => r,
                        Err(e) => {
                            let msg = format!("invalid watch request: {}", e);
                            let _ = frame::write_frame(&mut writer, frame::ERROR, msg.as_bytes());
                            continue;
                        }
                    };
                    let control_raw = writer.as_raw_fd();
                    handle_watch(&req, writer, move || control_fd_hung_up(control_raw));
                    return;
                }
                frame::READ_FILE_REQ => {
                    let req: ReadFileRequest = match serde_json::from_slice(&payload) {
                        Ok(r) => r,
                        Err(e) => {
                            let msg = format!("invalid read_file request: {}", e);
                            let _ = frame::write_frame(&mut writer, frame::ERROR, msg.as_bytes());
                            continue;
                        }
                    };
                    handle_read_file(&req, &mut writer);
                }
                frame::WRITE_FILE_REQ => {
                    let req: WriteFileRequest = match serde_json::from_slice(&payload) {
                        Ok(r) => r,
                        Err(e) => {
                            let msg = format!("invalid write_file request: {}", e);
                            let _ = frame::write_frame(&mut writer, frame::ERROR, msg.as_bytes());
                            continue;
                        }
                    };
                    handle_write_file(&req, &mut reader, &mut writer);
                }
                frame::MKDIR_REQ => {
                    let req: MkdirRequest = match serde_json::from_slice(&payload) {
                        Ok(r) => r,
                        Err(e) => {
                            let msg = format!("invalid mkdir request: {}", e);
                            let _ = frame::write_frame(&mut writer, frame::ERROR, msg.as_bytes());
                            continue;
                        }
                    };
                    handle_mkdir(&req, &mut writer);
                }
                frame::READ_DIR_REQ => {
                    let req: ReadDirRequest = match serde_json::from_slice(&payload) {
                        Ok(r) => r,
                        Err(e) => {
                            let msg = format!("invalid read_dir request: {}", e);
                            let _ = frame::write_frame(&mut writer, frame::ERROR, msg.as_bytes());
                            continue;
                        }
                    };
                    handle_read_dir(&req, &mut writer);
                }
                frame::STAT_REQ => {
                    let req: StatRequest = match serde_json::from_slice(&payload) {
                        Ok(r) => r,
                        Err(e) => {
                            let msg = format!("invalid stat request: {}", e);
                            let _ = frame::write_frame(&mut writer, frame::ERROR, msg.as_bytes());
                            continue;
                        }
                    };
                    handle_stat(&req, &mut writer);
                }
                frame::REMOVE_REQ => {
                    let req: RemoveRequest = match serde_json::from_slice(&payload) {
                        Ok(r) => r,
                        Err(e) => {
                            let msg = format!("invalid remove request: {}", e);
                            let _ = frame::write_frame(&mut writer, frame::ERROR, msg.as_bytes());
                            continue;
                        }
                    };
                    handle_remove(&req, &mut writer);
                }
                frame::RENAME_REQ => {
                    let req: RenameRequest = match serde_json::from_slice(&payload) {
                        Ok(r) => r,
                        Err(e) => {
                            let msg = format!("invalid rename request: {}", e);
                            let _ = frame::write_frame(&mut writer, frame::ERROR, msg.as_bytes());
                            continue;
                        }
                    };
                    handle_rename(&req, &mut writer);
                }
                frame::COPY_REQ => {
                    let req: CopyRequest = match serde_json::from_slice(&payload) {
                        Ok(r) => r,
                        Err(e) => {
                            let msg = format!("invalid copy request: {}", e);
                            let _ = frame::write_frame(&mut writer, frame::ERROR, msg.as_bytes());
                            continue;
                        }
                    };
                    handle_copy(&req, &mut writer);
                }
                frame::CHMOD_REQ => {
                    let req: ChmodRequest = match serde_json::from_slice(&payload) {
                        Ok(r) => r,
                        Err(e) => {
                            let msg = format!("invalid chmod request: {}", e);
                            let _ = frame::write_frame(&mut writer, frame::ERROR, msg.as_bytes());
                            continue;
                        }
                    };
                    handle_chmod(&req, &mut writer);
                }
                _ => {} // unknown type, skip
            }
        }
    }

    fn handle_mux_virtual_session(session: MuxVirtualSession) {
        let mut reader = session.clone();
        let mut writer = session;

        loop {
            let (msg_type, payload) = match frame::read_frame(&mut reader) {
                Ok(Some(frame)) => frame,
                Ok(None) => return,
                Err(err) => {
                    eprintln!("lsb-guest: mux virtual session read failed: {}", err);
                    return;
                }
            };

            if handle_simple_control_frame(msg_type, &payload, &mut reader, &mut writer) {
                continue;
            }

            match msg_type {
                frame::EXEC_REQ => {
                    let req: ExecRequest = match serde_json::from_slice(&payload) {
                        Ok(r) => r,
                        Err(e) => {
                            let msg = format!("invalid exec request: {}", e);
                            let _ = frame::write_frame(&mut writer, frame::ERROR, msg.as_bytes());
                            continue;
                        }
                    };

                    if req.argv.is_empty() {
                        let _ = frame::write_frame(&mut writer, frame::ERROR, b"empty argv");
                        continue;
                    }

                    if req.tty.unwrap_or(false) {
                        let _ = frame::write_frame(
                            &mut writer,
                            frame::ERROR,
                            b"tty exec is not supported over virtio-serial mux",
                        );
                        return;
                    }

                    handle_piped_exec(&req, reader, writer);
                    return;
                }
                frame::WATCH_REQ => {
                    let req: WatchRequest = match serde_json::from_slice(&payload) {
                        Ok(r) => r,
                        Err(e) => {
                            let msg = format!("invalid watch request: {}", e);
                            let _ = frame::write_frame(&mut writer, frame::ERROR, msg.as_bytes());
                            continue;
                        }
                    };
                    let close_watcher = writer.clone();
                    handle_watch(&req, writer, move || close_watcher.is_remote_closed());
                    return;
                }
                _ => {}
            }
        }
    }

    fn handle_simple_control_frame<R, W>(
        msg_type: u8,
        payload: &[u8],
        reader: &mut R,
        writer: &mut W,
    ) -> bool
    where
        R: Read,
        W: Write,
    {
        match msg_type {
            frame::MOUNT_REQ => {
                let mount_req: MountRequest = match serde_json::from_slice(payload) {
                    Ok(r) => r,
                    Err(e) => {
                        let msg = format!("invalid mount request: {}", e);
                        let _ = frame::write_frame(writer, frame::ERROR, msg.as_bytes());
                        return true;
                    }
                };
                let resp = process_mount(&mount_req);
                let _ = frame::send_json(writer, frame::MOUNT_RESP, &resp);
                true
            }
            frame::READ_FILE_REQ => {
                let req: ReadFileRequest = match serde_json::from_slice(payload) {
                    Ok(r) => r,
                    Err(e) => {
                        let msg = format!("invalid read_file request: {}", e);
                        let _ = frame::write_frame(writer, frame::ERROR, msg.as_bytes());
                        return true;
                    }
                };
                handle_read_file(&req, writer);
                true
            }
            frame::WRITE_FILE_REQ => {
                let req: WriteFileRequest = match serde_json::from_slice(payload) {
                    Ok(r) => r,
                    Err(e) => {
                        let msg = format!("invalid write_file request: {}", e);
                        let _ = frame::write_frame(writer, frame::ERROR, msg.as_bytes());
                        return true;
                    }
                };
                handle_write_file(&req, reader, writer);
                true
            }
            frame::MKDIR_REQ => {
                let req: MkdirRequest = match serde_json::from_slice(payload) {
                    Ok(r) => r,
                    Err(e) => {
                        let msg = format!("invalid mkdir request: {}", e);
                        let _ = frame::write_frame(writer, frame::ERROR, msg.as_bytes());
                        return true;
                    }
                };
                handle_mkdir(&req, writer);
                true
            }
            frame::READ_DIR_REQ => {
                let req: ReadDirRequest = match serde_json::from_slice(payload) {
                    Ok(r) => r,
                    Err(e) => {
                        let msg = format!("invalid read_dir request: {}", e);
                        let _ = frame::write_frame(writer, frame::ERROR, msg.as_bytes());
                        return true;
                    }
                };
                handle_read_dir(&req, writer);
                true
            }
            frame::STAT_REQ => {
                let req: StatRequest = match serde_json::from_slice(payload) {
                    Ok(r) => r,
                    Err(e) => {
                        let msg = format!("invalid stat request: {}", e);
                        let _ = frame::write_frame(writer, frame::ERROR, msg.as_bytes());
                        return true;
                    }
                };
                handle_stat(&req, writer);
                true
            }
            frame::REMOVE_REQ => {
                let req: RemoveRequest = match serde_json::from_slice(payload) {
                    Ok(r) => r,
                    Err(e) => {
                        let msg = format!("invalid remove request: {}", e);
                        let _ = frame::write_frame(writer, frame::ERROR, msg.as_bytes());
                        return true;
                    }
                };
                handle_remove(&req, writer);
                true
            }
            frame::RENAME_REQ => {
                let req: RenameRequest = match serde_json::from_slice(payload) {
                    Ok(r) => r,
                    Err(e) => {
                        let msg = format!("invalid rename request: {}", e);
                        let _ = frame::write_frame(writer, frame::ERROR, msg.as_bytes());
                        return true;
                    }
                };
                handle_rename(&req, writer);
                true
            }
            frame::COPY_REQ => {
                let req: CopyRequest = match serde_json::from_slice(payload) {
                    Ok(r) => r,
                    Err(e) => {
                        let msg = format!("invalid copy request: {}", e);
                        let _ = frame::write_frame(writer, frame::ERROR, msg.as_bytes());
                        return true;
                    }
                };
                handle_copy(&req, writer);
                true
            }
            frame::CHMOD_REQ => {
                let req: ChmodRequest = match serde_json::from_slice(payload) {
                    Ok(r) => r,
                    Err(e) => {
                        let msg = format!("invalid chmod request: {}", e);
                        let _ = frame::write_frame(writer, frame::ERROR, msg.as_bytes());
                        return true;
                    }
                };
                handle_chmod(&req, writer);
                true
            }
            _ => false,
        }
    }

    fn handle_read_file(req: &ReadFileRequest, writer: &mut impl Write) {
        let result = if req.offset.is_some() || req.len.is_some() {
            file_transfer::read_file_range(req)
        } else {
            std::fs::read(&req.path)
        };

        match result {
            Ok(data) => {
                let _ = frame::write_frame(writer, frame::READ_FILE_RESP, &data);
            }
            Err(e) => {
                let msg = format!("read_file {}: {}", req.path, e);
                let _ = frame::write_frame(writer, frame::ERROR, msg.as_bytes());
            }
        }
    }

    fn handle_write_file(req: &WriteFileRequest, reader: &mut impl Read, writer: &mut impl Write) {
        let data = match frame::read_frame(reader) {
            Ok(Some((frame::WRITE_FILE_DATA, payload))) => payload,
            _ => {
                let resp = WriteFileResponse {
                    ok: false,
                    error: Some("expected WRITE_FILE_DATA frame".into()),
                };
                let _ = frame::send_json(writer, frame::WRITE_FILE_RESP, &resp);
                return;
            }
        };

        if data.len() as u64 != req.len {
            let resp = WriteFileResponse {
                ok: false,
                error: Some(format!(
                    "length mismatch: expected {}, got {}",
                    req.len,
                    data.len()
                )),
            };
            let _ = frame::send_json(writer, frame::WRITE_FILE_RESP, &resp);
            return;
        }

        let result = if req.offset.is_some() || req.truncate.is_some() {
            file_transfer::write_file_range(req, &data)
        } else {
            if let Some(parent) = std::path::Path::new(&req.path).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            std::fs::write(&req.path, &data)
        };

        match result {
            Ok(()) => {
                unsafe {
                    libc::sync();
                }
                let resp = WriteFileResponse {
                    ok: true,
                    error: None,
                };
                let _ = frame::send_json(writer, frame::WRITE_FILE_RESP, &resp);
            }
            Err(e) => {
                let resp = WriteFileResponse {
                    ok: false,
                    error: Some(format!("write_file {}: {}", req.path, e)),
                };
                let _ = frame::send_json(writer, frame::WRITE_FILE_RESP, &resp);
            }
        }
    }

    fn send_fs_ok(writer: &mut impl Write) {
        let resp = FsOkResponse {
            ok: true,
            error: None,
        };
        let _ = frame::send_json(writer, frame::FS_OK_RESP, &resp);
    }

    fn send_fs_err(writer: &mut impl Write, msg: String) {
        let _ = frame::write_frame(writer, frame::ERROR, msg.as_bytes());
    }

    fn handle_mkdir(req: &MkdirRequest, writer: &mut impl Write) {
        let result = if req.recursive {
            std::fs::create_dir_all(&req.path)
        } else {
            std::fs::create_dir(&req.path)
        };
        match result {
            Ok(()) => send_fs_ok(writer),
            Err(e) => send_fs_err(writer, format!("mkdir {}: {}", req.path, e)),
        }
    }

    fn handle_read_dir(req: &ReadDirRequest, writer: &mut impl Write) {
        match std::fs::read_dir(&req.path) {
            Ok(iter) => {
                let mut entries = Vec::new();
                for entry in iter.flatten() {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    let meta = entry.metadata();
                    let (entry_type, size) = match &meta {
                        Ok(m) if m.file_type().is_symlink() => ("symlink", m.len()),
                        Ok(m) if m.is_dir() => ("dir", m.len()),
                        Ok(m) => ("file", m.len()),
                        Err(_) => ("file", 0),
                    };
                    entries.push(DirEntry {
                        name,
                        entry_type: entry_type.to_string(),
                        size,
                    });
                }
                let resp = ReadDirResponse { entries };
                let _ = frame::send_json(writer, frame::READ_DIR_RESP, &resp);
            }
            Err(e) => send_fs_err(writer, format!("read_dir {}: {}", req.path, e)),
        }
    }

    fn handle_stat(req: &StatRequest, writer: &mut impl Write) {
        use std::os::unix::fs::MetadataExt;
        match std::fs::symlink_metadata(&req.path) {
            Ok(m) => {
                let mtime = m
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let resp = StatResponse {
                    size: m.len(),
                    mode: m.mode(),
                    mtime,
                    is_dir: m.is_dir(),
                    is_file: m.is_file(),
                    is_symlink: m.file_type().is_symlink(),
                };
                let _ = frame::send_json(writer, frame::STAT_RESP, &resp);
            }
            Err(e) => send_fs_err(writer, format!("stat {}: {}", req.path, e)),
        }
    }

    fn handle_remove(req: &RemoveRequest, writer: &mut impl Write) {
        let result = if req.recursive {
            std::fs::remove_dir_all(&req.path)
        } else {
            std::fs::remove_file(&req.path).or_else(|_| std::fs::remove_dir(&req.path))
        };
        match result {
            Ok(()) => send_fs_ok(writer),
            Err(e) => send_fs_err(writer, format!("remove {}: {}", req.path, e)),
        }
    }

    fn handle_rename(req: &RenameRequest, writer: &mut impl Write) {
        match std::fs::rename(&req.old_path, &req.new_path) {
            Ok(()) => send_fs_ok(writer),
            Err(e) => send_fs_err(
                writer,
                format!("rename {} -> {}: {}", req.old_path, req.new_path, e),
            ),
        }
    }

    fn handle_copy(req: &CopyRequest, writer: &mut impl Write) {
        let result = if req.recursive {
            copy_dir_recursive(
                std::path::Path::new(&req.src),
                std::path::Path::new(&req.dst),
            )
        } else {
            std::fs::copy(&req.src, &req.dst).map(|_| ())
        };
        match result {
            Ok(()) => send_fs_ok(writer),
            Err(e) => send_fs_err(writer, format!("copy {} -> {}: {}", req.src, req.dst, e)),
        }
    }

    /// Iterative directory copy. Preserves permissions, detects self-copy
    /// via dev+ino to prevent infinite loops.
    /// Inspired by https://github.com/mdunsmuir/copy_dir (MIT).
    fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
        use std::os::unix::fs::MetadataExt;

        // Detect copying a directory into itself (would loop forever).
        let dst_id = if dst.exists() {
            let m = std::fs::metadata(dst)?;
            Some((m.dev(), m.ino()))
        } else {
            std::fs::create_dir_all(dst)?;
            let m = std::fs::metadata(dst)?;
            Some((m.dev(), m.ino()))
        };

        let mut stack = vec![(src.to_path_buf(), dst.to_path_buf())];
        while let Some((s, d)) = stack.pop() {
            let src_meta = std::fs::metadata(&s)?;
            std::fs::create_dir_all(&d)?;

            for entry in std::fs::read_dir(&s)? {
                let entry = entry?;
                let src_child = entry.path();
                let dst_child = d.join(entry.file_name());
                let ft = entry.file_type()?;

                if ft.is_dir() {
                    // Skip if this dir IS the destination (self-copy guard).
                    let child_meta = std::fs::metadata(&src_child)?;
                    let child_id = (child_meta.dev(), child_meta.ino());
                    if dst_id == Some(child_id) {
                        continue;
                    }
                    stack.push((src_child, dst_child));
                } else {
                    std::fs::copy(&src_child, &dst_child)?;
                }
            }

            // Preserve source directory permissions.
            std::fs::set_permissions(&d, src_meta.permissions())?;
        }
        Ok(())
    }

    fn handle_chmod(req: &ChmodRequest, writer: &mut impl Write) {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(req.mode);
        match std::fs::set_permissions(&req.path, perms) {
            Ok(()) => send_fs_ok(writer),
            Err(e) => send_fs_err(writer, format!("chmod {}: {}", req.path, e)),
        }
    }

    fn handle_piped_exec<R, W>(req: &ExecRequest, control_reader: R, control_writer: W)
    where
        R: Read + Send + 'static,
        W: Write + Send + 'static,
    {
        let mut cmd = Command::new(&req.argv[0]);
        if req.argv.len() > 1 {
            cmd.args(&req.argv[1..]);
        }
        for (k, v) in &req.env {
            cmd.env(k, v);
        }
        if let Some(ref cwd) = req.cwd {
            cmd.current_dir(cwd);
        }
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        // Put the child in its own process group so we can kill the
        // entire group (sh + any children) with a single signal.
        unsafe {
            cmd.pre_exec(|| {
                libc::setpgid(0, 0);
                Ok(())
            });
        }

        match cmd.spawn() {
            Ok(mut child) => {
                let child_pid = child.id() as i32;

                enum ExecOutput {
                    Frame(u8, Vec<u8>),
                    Exit(i32),
                }

                // Channel serializes all frame writes to prevent interleaving.
                // EXIT is an explicit terminal message so inherited stdout/stderr
                // handles in grandchildren cannot keep the mux session open forever.
                let (tx, rx) = std::sync::mpsc::channel::<ExecOutput>();
                let (output_done_tx, output_done_rx) = std::sync::mpsc::channel::<()>();

                // Writer thread: drains channel, writes frames to vsock
                let mut frame_writer = control_writer;
                let writer_thread = std::thread::spawn(move || {
                    for output in rx {
                        match output {
                            ExecOutput::Frame(frame_type, payload) => {
                                if frame::write_frame(&mut frame_writer, frame_type, &payload)
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            ExecOutput::Exit(exit_code) => {
                                let _ = frame::write_frame(
                                    &mut frame_writer,
                                    frame::EXIT,
                                    &frame::exit_payload(exit_code),
                                );
                                break;
                            }
                        }
                    }
                });

                // Thread: child stdout -> STDOUT frames
                let child_stdout = child.stdout.take().unwrap();
                let tx_stdout = tx.clone();
                let stdout_done = output_done_tx.clone();
                let stdout_thread = std::thread::spawn(move || {
                    let mut stdout = child_stdout;
                    let mut buf = [0u8; 8192];
                    loop {
                        match stdout.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if tx_stdout
                                    .send(ExecOutput::Frame(frame::STDOUT, buf[..n].to_vec()))
                                    .is_err()
                                {
                                    break;
                                }
                            }
                        }
                    }
                    let _ = stdout_done.send(());
                });

                // Thread: child stderr -> STDERR frames
                let child_stderr = child.stderr.take().unwrap();
                let tx_stderr = tx.clone();
                let stderr_done = output_done_tx.clone();
                let stderr_thread = std::thread::spawn(move || {
                    let mut stderr = child_stderr;
                    let mut buf = [0u8; 8192];
                    loop {
                        match stderr.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if tx_stderr
                                    .send(ExecOutput::Frame(frame::STDERR, buf[..n].to_vec()))
                                    .is_err()
                                {
                                    break;
                                }
                            }
                        }
                    }
                    let _ = stderr_done.send(());
                });
                drop(output_done_tx);

                let input_thread = if req.stdin_closed.unwrap_or(false) {
                    drop(child.stdin.take());
                    None
                } else {
                    // Thread: vsock STDIN/KILL frames -> child stdin
                    let child_stdin = child.stdin.take().unwrap();
                    Some(std::thread::spawn(move || {
                        let mut stdin = child_stdin;
                        let mut reader = control_reader;
                        loop {
                            match frame::read_frame(&mut reader) {
                                Ok(Some((frame::STDIN, data))) => {
                                    if stdin.write_all(&data).is_err() {
                                        break;
                                    }
                                    let _ = stdin.flush();
                                }
                                Ok(Some((frame::KILL, _))) => {
                                    // Kill entire process group (negative pid)
                                    unsafe { libc::kill(-child_pid, libc::SIGTERM) };
                                    break;
                                }
                                _ => break,
                            }
                        }
                    }))
                };

                let status = child.wait().expect("failed to wait on child");
                let exit_code = status.code().unwrap_or(-1);

                unsafe {
                    libc::sync();
                }

                let output_drain_deadline = std::time::Instant::now() + Duration::from_secs(2);
                let mut drained_outputs = 0usize;
                while drained_outputs < 2 {
                    let now = std::time::Instant::now();
                    if now >= output_drain_deadline {
                        break;
                    }
                    match output_done_rx.recv_timeout(output_drain_deadline - now) {
                        Ok(()) => drained_outputs += 1,
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => break,
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }

                let _ = tx.send(ExecOutput::Exit(exit_code));
                drop(tx);
                let _ = writer_thread.join();
                if drained_outputs == 2 {
                    let _ = stdout_thread.join();
                    let _ = stderr_thread.join();
                }

                // Streaming input threads exit when vsock closes or the host sends KILL.
                drop(input_thread);
            }
            Err(e) => {
                let msg = format!("failed to spawn: {}", e);
                let mut w = control_writer;
                let _ = frame::write_frame(&mut w, frame::ERROR, msg.as_bytes());
            }
        }
    }

    #[cfg(test)]
    mod exec_tests {
        use super::*;
        use std::collections::HashMap;
        use std::os::unix::net::UnixStream;
        use std::time::{Duration, Instant};

        #[test]
        fn piped_exec_reports_exit_when_grandchild_keeps_stdout_open() {
            let pid_file =
                std::env::temp_dir().join(format!("lsb-guest-exec-bg-{}", std::process::id()));
            let _ = std::fs::remove_file(&pid_file);

            let mut env = HashMap::new();
            env.insert(
                "LSB_GUEST_EXEC_BG_PID".to_string(),
                pid_file.display().to_string(),
            );
            let req = ExecRequest {
                argv: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "sleep 30 & printf '%s' \"$!\" > \"$LSB_GUEST_EXEC_BG_PID\"; echo child-done"
                        .to_string(),
                ],
                env,
                tty: None,
                rows: None,
                cols: None,
                cwd: None,
                stdin_closed: Some(true),
            };

            let (mut host, guest) = UnixStream::pair().expect("test stream pair");
            host.set_read_timeout(Some(Duration::from_secs(5)))
                .expect("read timeout should be set");
            let guest_reader = guest.try_clone().expect("guest stream should clone");
            let started = Instant::now();
            let handle = std::thread::spawn(move || handle_piped_exec(&req, guest_reader, guest));

            let mut stdout = Vec::new();
            let mut exit_code = None;
            let read_result = loop {
                match frame::read_frame(&mut host) {
                    Ok(Some((frame::STDOUT, data))) => stdout.extend(data),
                    Ok(Some((frame::STDERR, _))) => {}
                    Ok(Some((frame::EXIT, data))) => {
                        exit_code = Some(frame::parse_exit_code(&data).unwrap_or(-1));
                        break Ok(());
                    }
                    Ok(Some((kind, _))) => break Err(format!("unexpected frame type {kind}")),
                    Ok(None) => break Err("exec stream closed before EXIT".to_string()),
                    Err(error) => break Err(format!("reading exec frame failed: {error}")),
                }
            };

            if let Ok(pid_text) = std::fs::read_to_string(&pid_file) {
                if let Ok(pid) = pid_text.trim().parse::<i32>() {
                    unsafe {
                        libc::kill(pid, libc::SIGTERM);
                    }
                }
            }
            let _ = std::fs::remove_file(&pid_file);

            read_result.expect("EXIT frame should arrive before inherited stdout closes");
            assert_eq!(exit_code, Some(0));
            assert_eq!(String::from_utf8_lossy(&stdout), "child-done\n");
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "EXIT was delayed by inherited stdout handles"
            );
            handle.join().expect("exec handler should finish");
        }
    }

    fn handle_watch<S, F>(req: &WatchRequest, mut writer: S, mut should_stop: F)
    where
        S: Write,
        F: FnMut() -> bool,
    {
        use std::collections::HashMap;
        use std::ffi::CString;

        let inotify_fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK) };
        if inotify_fd < 0 {
            let _ = frame::write_frame(&mut writer, frame::ERROR, b"inotify_init failed");
            return;
        }

        let mask = libc::IN_CREATE
            | libc::IN_MODIFY
            | libc::IN_DELETE
            | libc::IN_MOVED_FROM
            | libc::IN_MOVED_TO;

        let mut wd_to_path: HashMap<i32, String> = HashMap::new();

        fn add_watches(
            inotify_fd: i32,
            path: &str,
            mask: u32,
            wd_to_path: &mut HashMap<i32, String>,
            recursive: bool,
        ) {
            let c_path = match CString::new(path) {
                Ok(p) => p,
                Err(_) => return,
            };
            let wd = unsafe { libc::inotify_add_watch(inotify_fd, c_path.as_ptr(), mask) };
            if wd >= 0 {
                wd_to_path.insert(wd, path.to_string());
            }
            if !recursive {
                return;
            }
            let entries = match std::fs::read_dir(path) {
                Ok(e) => e,
                Err(_) => return,
            };
            for entry in entries.flatten() {
                if let Ok(ft) = entry.file_type() {
                    if ft.is_dir() {
                        if let Some(p) = entry.path().to_str() {
                            add_watches(inotify_fd, p, mask, wd_to_path, true);
                        }
                    }
                }
            }
        }

        add_watches(inotify_fd, &req.path, mask, &mut wd_to_path, req.recursive);

        let mut buf = [0u8; 4096];

        loop {
            let mut fds = [libc::pollfd {
                fd: inotify_fd,
                events: libc::POLLIN,
                revents: 0,
            }];
            let ret = unsafe { libc::poll(fds.as_mut_ptr(), 1, 500) };

            if ret > 0 && (fds[0].revents & libc::POLLIN != 0) {
                let n = unsafe {
                    libc::read(inotify_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
                };
                if n <= 0 {
                    continue;
                }

                let mut offset = 0usize;
                while offset < n as usize {
                    if offset + std::mem::size_of::<libc::inotify_event>() > n as usize {
                        break;
                    }
                    let event =
                        unsafe { &*(buf.as_ptr().add(offset) as *const libc::inotify_event) };
                    let name_len = event.len as usize;
                    offset += std::mem::size_of::<libc::inotify_event>() + name_len;

                    let dir = wd_to_path.get(&event.wd).map(|s| s.as_str()).unwrap_or("");
                    let filename = if name_len > 0 {
                        let name_start = offset - name_len;
                        let name_bytes = &buf[name_start..offset];
                        let end = name_bytes
                            .iter()
                            .position(|&b| b == 0)
                            .unwrap_or(name_bytes.len());
                        std::str::from_utf8(&name_bytes[..end]).unwrap_or("")
                    } else {
                        ""
                    };

                    let full_path = if filename.is_empty() {
                        dir.to_string()
                    } else {
                        format!("{}/{}", dir, filename)
                    };

                    let event_type = if event.mask & libc::IN_CREATE != 0 {
                        "create"
                    } else if event.mask & libc::IN_MODIFY != 0 {
                        "modify"
                    } else if event.mask & libc::IN_DELETE != 0 {
                        "delete"
                    } else if event.mask & (libc::IN_MOVED_FROM | libc::IN_MOVED_TO) != 0 {
                        "rename"
                    } else {
                        continue;
                    };

                    // If a new directory was created, add watches
                    if event.mask & libc::IN_CREATE != 0 && event.mask & libc::IN_ISDIR != 0 {
                        add_watches(inotify_fd, &full_path, mask, &mut wd_to_path, req.recursive);
                    }

                    let evt = WatchEvent {
                        path: full_path,
                        event: event_type.to_string(),
                    };
                    if let Ok(payload) = serde_json::to_vec(&evt) {
                        if frame::write_frame(&mut writer, frame::WATCH_EVENT, &payload).is_err() {
                            break;
                        }
                    }
                }
            }

            if should_stop() {
                break;
            }
        }

        unsafe { libc::close(inotify_fd) };
    }

    fn control_fd_hung_up(fd: RawFd) -> bool {
        let mut fds = [libc::pollfd {
            fd,
            events: 0,
            revents: 0,
        }];
        unsafe { libc::poll(fds.as_mut_ptr(), 1, 0) };
        fds[0].revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0
    }

    const MUX_SESSION_RECEIVE_QUEUE_BYTES: usize = 256 * 1024;
    const MUX_SESSION_SEND_QUEUE_BYTES: usize = 256 * 1024;
    const MAX_MUX_CONTROL_QUEUE_FRAMES: usize = 128;

    #[derive(Debug)]
    struct GuestMux {
        inner: Arc<GuestMuxInner>,
    }

    impl GuestMux {
        fn start<R, W>(reader: R, writer: W) -> Self
        where
            R: Read + Send + 'static,
            W: Write + Send + 'static,
        {
            let mux = Self {
                inner: Arc::new(GuestMuxInner::new()),
            };

            let read_inner = Arc::clone(&mux.inner);
            std::thread::Builder::new()
                .name("lsb-guest-mux-reader".to_string())
                .spawn(move || guest_mux_read_loop(read_inner, reader))
                .expect("failed to spawn guest mux reader thread");

            let write_inner = Arc::clone(&mux.inner);
            std::thread::Builder::new()
                .name("lsb-guest-mux-writer".to_string())
                .spawn(move || guest_mux_write_loop(write_inner, writer))
                .expect("failed to spawn guest mux writer thread");

            mux
        }

        fn accept_session(&self) -> Option<MuxVirtualSession> {
            self.inner.accept_session()
        }
    }

    #[derive(Debug)]
    struct GuestMuxInner {
        state: Mutex<GuestMuxState>,
        cv: Condvar,
    }

    impl GuestMuxInner {
        fn new() -> Self {
            Self {
                state: Mutex::new(GuestMuxState::new()),
                cv: Condvar::new(),
            }
        }

        fn accept_session(self: &Arc<Self>) -> Option<MuxVirtualSession> {
            let mut state = self.state.lock().expect("guest mux state lock poisoned");
            loop {
                if state.failed.is_some() {
                    return None;
                }

                if let Some(session_id) = state.accepted_sessions.pop_front() {
                    if state.sessions.contains_key(&session_id) {
                        return Some(MuxVirtualSession::new(Arc::clone(self), session_id));
                    }
                }

                state = self.cv.wait(state).expect("guest mux state lock poisoned");
            }
        }

        fn close_session(&self, session_id: u64) {
            let mut state = self.state.lock().expect("guest mux state lock poisoned");
            if state.failed.is_some() {
                return;
            }

            let Some(session) = state.sessions.get_mut(&session_id) else {
                return;
            };
            if session.local_fin {
                return;
            }

            session.local_fin = true;
            if !session.scheduled {
                session.scheduled = true;
                state.ready_sessions.push_back(session_id);
            }
            self.cv.notify_all();
        }

        fn fail(&self, reason: String) {
            let mut state = self.state.lock().expect("guest mux state lock poisoned");
            state.fail(reason);
            self.cv.notify_all();
        }
    }

    #[derive(Debug)]
    struct GuestMuxState {
        sessions: std::collections::HashMap<u64, GuestMuxSessionState>,
        control_queue: std::collections::VecDeque<MuxFrame>,
        ready_sessions: std::collections::VecDeque<u64>,
        accepted_sessions: std::collections::VecDeque<u64>,
        failed: Option<String>,
    }

    impl GuestMuxState {
        fn new() -> Self {
            Self {
                sessions: std::collections::HashMap::new(),
                control_queue: std::collections::VecDeque::new(),
                ready_sessions: std::collections::VecDeque::new(),
                accepted_sessions: std::collections::VecDeque::new(),
                failed: None,
            }
        }

        fn fail(&mut self, reason: String) {
            if self.failed.is_some() {
                return;
            }
            for session in self.sessions.values_mut() {
                session.reset_reason = Some(reason.clone());
            }
            self.control_queue.clear();
            self.ready_sessions.clear();
            self.accepted_sessions.clear();
            self.failed = Some(reason);
        }
    }

    #[derive(Debug)]
    struct GuestMuxSessionState {
        inbound: std::collections::VecDeque<u8>,
        outbound: std::collections::VecDeque<Vec<u8>>,
        outbound_bytes: usize,
        send_credit: usize,
        remote_fin: bool,
        local_fin: bool,
        fin_sent: bool,
        reset_reason: Option<String>,
        scheduled: bool,
    }

    impl GuestMuxSessionState {
        fn new() -> Self {
            Self {
                inbound: std::collections::VecDeque::new(),
                outbound: std::collections::VecDeque::new(),
                outbound_bytes: 0,
                send_credit: 0,
                remote_fin: false,
                local_fin: false,
                fin_sent: false,
                reset_reason: None,
                scheduled: false,
            }
        }
    }

    #[derive(Debug, Clone)]
    struct MuxVirtualSession {
        handle: Arc<MuxVirtualSessionHandle>,
    }

    impl MuxVirtualSession {
        fn new(mux: Arc<GuestMuxInner>, session_id: u64) -> Self {
            Self {
                handle: Arc::new(MuxVirtualSessionHandle { mux, session_id }),
            }
        }

        fn is_remote_closed(&self) -> bool {
            let state = match self.handle.mux.state.lock() {
                Ok(state) => state,
                Err(_) => return true,
            };
            if state.failed.is_some() {
                return true;
            }
            let Some(session) = state.sessions.get(&self.handle.session_id) else {
                return true;
            };
            session.remote_fin || session.reset_reason.is_some()
        }
    }

    #[derive(Debug)]
    struct MuxVirtualSessionHandle {
        mux: Arc<GuestMuxInner>,
        session_id: u64,
    }

    impl Drop for MuxVirtualSessionHandle {
        fn drop(&mut self) {
            self.mux.close_session(self.session_id);
        }
    }

    impl Read for MuxVirtualSession {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }

            let mux = &self.handle.mux;
            let session_id = self.handle.session_id;
            let mut state = mux.state.lock().map_err(|_| mux_poisoned_lock())?;

            loop {
                if let Some(reason) = state.failed.clone() {
                    return Err(mux_broken_pipe(reason));
                }

                let mut copied = 0usize;
                {
                    let session = state
                        .sessions
                        .get_mut(&session_id)
                        .ok_or_else(|| mux_broken_pipe("mux session no longer exists"))?;

                    if let Some(reason) = session.reset_reason.clone() {
                        return Err(mux_connection_reset(reason));
                    }

                    while copied < buf.len() {
                        let Some(byte) = session.inbound.pop_front() else {
                            break;
                        };
                        buf[copied] = byte;
                        copied += 1;
                    }

                    if copied == 0 && session.remote_fin {
                        return Ok(0);
                    }
                }

                if copied > 0 {
                    let credit = u32::try_from(copied).map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "mux read credit exceeds u32 window range",
                        )
                    })?;
                    state = guest_mux_wait_for_control_capacity(mux, state)?;
                    state
                        .control_queue
                        .push_back(MuxFrame::Window { session_id, credit });
                    mux.cv.notify_all();
                    return Ok(copied);
                }

                state = mux.cv.wait(state).map_err(|_| mux_poisoned_lock())?;
            }
        }
    }

    impl Write for MuxVirtualSession {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }

            let mux = &self.handle.mux;
            let session_id = self.handle.session_id;
            let mut state = mux.state.lock().map_err(|_| mux_poisoned_lock())?;

            loop {
                if let Some(reason) = state.failed.clone() {
                    return Err(mux_broken_pipe(reason));
                }

                let mut should_schedule = false;
                let writable = {
                    let session = state
                        .sessions
                        .get_mut(&session_id)
                        .ok_or_else(|| mux_broken_pipe("mux session no longer exists"))?;

                    if let Some(reason) = session.reset_reason.clone() {
                        return Err(mux_connection_reset(reason));
                    }
                    if session.local_fin {
                        return Err(mux_broken_pipe("mux session local side is closed"));
                    }
                    if session.remote_fin {
                        return Err(mux_broken_pipe("mux session remote side is closed"));
                    }

                    let available_queue =
                        MUX_SESSION_SEND_QUEUE_BYTES.saturating_sub(session.outbound_bytes);
                    let writable = buf
                        .len()
                        .min(mux::MAX_DATA_LEN)
                        .min(session.send_credit)
                        .min(available_queue);

                    if writable > 0 {
                        session.outbound.push_back(buf[..writable].to_vec());
                        session.outbound_bytes += writable;
                        session.send_credit -= writable;
                        if !session.scheduled {
                            session.scheduled = true;
                            should_schedule = true;
                        }
                    }

                    writable
                };

                if writable > 0 {
                    if should_schedule {
                        state.ready_sessions.push_back(session_id);
                    }
                    mux.cv.notify_all();
                    return Ok(writable);
                }

                state = mux.cv.wait(state).map_err(|_| mux_poisoned_lock())?;
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            let mux = &self.handle.mux;
            let session_id = self.handle.session_id;
            let mut state = mux.state.lock().map_err(|_| mux_poisoned_lock())?;

            loop {
                if let Some(reason) = state.failed.clone() {
                    return Err(mux_broken_pipe(reason));
                }

                let session = state
                    .sessions
                    .get(&session_id)
                    .ok_or_else(|| mux_broken_pipe("mux session no longer exists"))?;

                if let Some(reason) = session.reset_reason.clone() {
                    return Err(mux_connection_reset(reason));
                }
                if session.outbound_bytes == 0 {
                    return Ok(());
                }

                state = mux.cv.wait(state).map_err(|_| mux_poisoned_lock())?;
            }
        }
    }

    fn guest_mux_read_loop<R>(inner: Arc<GuestMuxInner>, mut reader: R)
    where
        R: Read,
    {
        loop {
            let mux_frame = match frame::read_frame(&mut reader) {
                Ok(Some((frame_type, payload))) => match mux::decode_frame(frame_type, &payload) {
                    Ok(frame) => frame,
                    Err(error) => {
                        inner.fail(format!("invalid mux frame received from host: {error}"));
                        return;
                    }
                },
                Ok(None) => {
                    inner.fail("virtio-serial mux physical control stream reached EOF".to_string());
                    return;
                }
                Err(error) => {
                    inner.fail(format!(
                        "failed to read virtio-serial mux physical control stream: {error}"
                    ));
                    return;
                }
            };

            if let Err(reason) = guest_mux_handle_incoming_frame(&inner, mux_frame) {
                inner.fail(reason);
                return;
            }
        }
    }

    fn guest_mux_write_loop<W>(inner: Arc<GuestMuxInner>, mut writer: W)
    where
        W: Write,
    {
        while let Some(mux_frame) = guest_mux_next_outgoing_frame(&inner) {
            let (frame_type, payload) = match mux::encode_frame(&mux_frame) {
                Ok(encoded) => encoded,
                Err(error) => {
                    inner.fail(format!("failed to encode mux frame: {error}"));
                    return;
                }
            };

            if let Err(error) = frame::write_frame(&mut writer, frame_type, &payload) {
                inner.fail(format!(
                    "failed to write virtio-serial mux physical control stream: {error}"
                ));
                return;
            }
        }
    }

    fn guest_mux_next_outgoing_frame(inner: &GuestMuxInner) -> Option<MuxFrame> {
        let mut state = inner.state.lock().expect("guest mux state lock poisoned");
        loop {
            if state.failed.is_some() {
                return None;
            }

            if let Some(frame) = state.control_queue.pop_front() {
                inner.cv.notify_all();
                return Some(frame);
            }

            while let Some(session_id) = state.ready_sessions.pop_front() {
                let Some(session) = state.sessions.get_mut(&session_id) else {
                    continue;
                };

                if let Some(bytes) = session.outbound.pop_front() {
                    session.outbound_bytes = session.outbound_bytes.saturating_sub(bytes.len());
                    if session.outbound.is_empty() && !(session.local_fin && !session.fin_sent) {
                        session.scheduled = false;
                    } else {
                        state.ready_sessions.push_back(session_id);
                    }
                    inner.cv.notify_all();
                    return Some(MuxFrame::Data { session_id, bytes });
                }

                if session.local_fin && !session.fin_sent {
                    session.fin_sent = true;
                    session.scheduled = false;
                    inner.cv.notify_all();
                    return Some(MuxFrame::Fin { session_id });
                }

                session.scheduled = false;
            }

            state = inner.cv.wait(state).expect("guest mux state lock poisoned");
        }
    }

    fn guest_mux_handle_incoming_frame(
        inner: &GuestMuxInner,
        mux_frame: MuxFrame,
    ) -> Result<(), String> {
        match mux_frame {
            MuxFrame::Open {
                session_id,
                metadata,
            } => {
                mux::validate_host_session_id(session_id).map_err(|error| error.to_string())?;
                let mut state = inner.state.lock().expect("guest mux state lock poisoned");
                if state.sessions.contains_key(&session_id) {
                    return Err(format!("host opened duplicate mux session {session_id}"));
                }
                if state.control_queue.len() >= MAX_MUX_CONTROL_QUEUE_FRAMES {
                    return Err(format!(
                        "mux control queue was full while accepting session {session_id}"
                    ));
                }

                if !guest_mux_metadata_supported(&metadata) {
                    state.control_queue.push_back(MuxFrame::OpenErr {
                        session_id,
                        reason: "unsupported mux session kind".to_string(),
                    });
                    inner.cv.notify_all();
                    return Ok(());
                }

                state
                    .sessions
                    .insert(session_id, GuestMuxSessionState::new());
                state.control_queue.push_back(MuxFrame::OpenOk {
                    session_id,
                    initial_credit: MUX_SESSION_RECEIVE_QUEUE_BYTES as u32,
                });
                state.accepted_sessions.push_back(session_id);
                inner.cv.notify_all();
                Ok(())
            }
            MuxFrame::OpenOk { .. } | MuxFrame::OpenErr { .. } => {
                Err("host sent an unexpected mux session-open response".to_string())
            }
            MuxFrame::Data { session_id, bytes } => {
                mux::validate_host_session_id(session_id).map_err(|error| error.to_string())?;
                let mut state = inner.state.lock().expect("guest mux state lock poisoned");
                let session = state.sessions.get_mut(&session_id).ok_or_else(|| {
                    format!(
                        "host sent {} bytes for unknown mux session {session_id}",
                        bytes.len()
                    )
                })?;
                let available =
                    MUX_SESSION_RECEIVE_QUEUE_BYTES.saturating_sub(session.inbound.len());
                if bytes.len() > available {
                    return Err(format!(
                        "host exceeded mux receive credit for session {session_id}: {} bytes with {available} bytes available",
                        bytes.len()
                    ));
                }
                session.inbound.extend(bytes);
                inner.cv.notify_all();
                Ok(())
            }
            MuxFrame::Window { session_id, credit } => {
                mux::validate_host_session_id(session_id).map_err(|error| error.to_string())?;
                let mut state = inner.state.lock().expect("guest mux state lock poisoned");
                let session = state.sessions.get_mut(&session_id).ok_or_else(|| {
                    format!("host granted credit for unknown mux session {session_id}")
                })?;
                session.send_credit = session
                    .send_credit
                    .checked_add(credit as usize)
                    .ok_or_else(|| format!("mux session {session_id} send credit overflow"))?;
                inner.cv.notify_all();
                Ok(())
            }
            MuxFrame::Fin { session_id } => {
                mux::validate_host_session_id(session_id).map_err(|error| error.to_string())?;
                let mut state = inner.state.lock().expect("guest mux state lock poisoned");
                let session = state
                    .sessions
                    .get_mut(&session_id)
                    .ok_or_else(|| format!("host closed unknown mux session {session_id}"))?;
                session.remote_fin = true;
                inner.cv.notify_all();
                Ok(())
            }
            MuxFrame::Rst { session_id, reason } => {
                mux::validate_host_session_id(session_id).map_err(|error| error.to_string())?;
                let mut state = inner.state.lock().expect("guest mux state lock poisoned");
                let session = state.sessions.get_mut(&session_id).ok_or_else(|| {
                    format!("host reset unknown mux session {session_id}: {reason}")
                })?;
                session.reset_reason = Some(reason);
                inner.cv.notify_all();
                Ok(())
            }
        }
    }

    fn guest_mux_metadata_supported(metadata: &[u8]) -> bool {
        matches!(metadata, b"exec" | b"watch" | b"file")
    }

    fn guest_mux_wait_for_control_capacity<'a>(
        inner: &'a GuestMuxInner,
        mut state: std::sync::MutexGuard<'a, GuestMuxState>,
    ) -> io::Result<std::sync::MutexGuard<'a, GuestMuxState>> {
        while state.control_queue.len() >= MAX_MUX_CONTROL_QUEUE_FRAMES {
            if let Some(reason) = state.failed.clone() {
                return Err(mux_broken_pipe(reason));
            }
            state = inner.cv.wait(state).map_err(|_| mux_poisoned_lock())?;
        }
        Ok(state)
    }

    fn mux_poisoned_lock() -> io::Error {
        io::Error::other("guest mux state lock poisoned")
    }

    fn mux_broken_pipe(reason: impl Into<String>) -> io::Error {
        io::Error::new(io::ErrorKind::BrokenPipe, reason.into())
    }

    fn mux_connection_reset(reason: impl Into<String>) -> io::Error {
        io::Error::new(io::ErrorKind::ConnectionReset, reason.into())
    }

    #[cfg(test)]
    mod mux_tests {
        use super::*;
        use std::sync::mpsc::{self, Receiver, SyncSender};

        struct ChannelReader {
            rx: Receiver<u8>,
        }

        struct ChannelWriter {
            tx: SyncSender<u8>,
        }

        impl Read for ChannelReader {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if buf.is_empty() {
                    return Ok(0);
                }

                match self.rx.recv() {
                    Ok(byte) => {
                        buf[0] = byte;
                        let mut read = 1usize;
                        while read < buf.len() {
                            match self.rx.try_recv() {
                                Ok(byte) => {
                                    buf[read] = byte;
                                    read += 1;
                                }
                                Err(_) => break,
                            }
                        }
                        Ok(read)
                    }
                    Err(_) => Ok(0),
                }
            }
        }

        impl Write for ChannelWriter {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                for byte in buf {
                    self.tx
                        .send(*byte)
                        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "peer closed"))?;
                }
                Ok(buf.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        struct Endpoint {
            reader: ChannelReader,
            writer: ChannelWriter,
        }

        fn channel_pair(capacity: usize) -> (Endpoint, Endpoint) {
            let (host_tx, peer_rx) = mpsc::sync_channel(capacity);
            let (peer_tx, host_rx) = mpsc::sync_channel(capacity);
            (
                Endpoint {
                    reader: ChannelReader { rx: host_rx },
                    writer: ChannelWriter { tx: host_tx },
                },
                Endpoint {
                    reader: ChannelReader { rx: peer_rx },
                    writer: ChannelWriter { tx: peer_tx },
                },
            )
        }

        fn read_mux(reader: &mut impl Read) -> MuxFrame {
            let (frame_type, payload) = frame::read_frame(reader)
                .expect("physical frame should read")
                .expect("physical frame should be present");
            mux::decode_frame(frame_type, &payload).expect("mux frame should decode")
        }

        fn write_mux(writer: &mut impl Write, mux_frame: MuxFrame) {
            let (frame_type, payload) =
                mux::encode_frame(&mux_frame).expect("mux frame should encode");
            frame::write_frame(writer, frame_type, &payload).expect("mux frame should write");
        }

        #[test]
        fn guest_mux_accepts_host_session_and_exchanges_bytes() {
            let (guest, mut host) = channel_pair(512 * 1024);
            let mux = GuestMux::start(guest.reader, guest.writer);
            let session_id = 1;

            write_mux(
                &mut host.writer,
                MuxFrame::Open {
                    session_id,
                    metadata: b"exec".to_vec(),
                },
            );

            match read_mux(&mut host.reader) {
                MuxFrame::OpenOk {
                    session_id: opened,
                    initial_credit,
                } => {
                    assert_eq!(opened, session_id);
                    assert_eq!(initial_credit, MUX_SESSION_RECEIVE_QUEUE_BYTES as u32);
                }
                frame => panic!("unexpected mux frame while waiting for open ok: {frame:?}"),
            }

            let mut session = mux.accept_session().expect("session should be accepted");

            write_mux(
                &mut host.writer,
                MuxFrame::Window {
                    session_id,
                    credit: 1024,
                },
            );
            write_mux(
                &mut host.writer,
                MuxFrame::Data {
                    session_id,
                    bytes: b"host-to-guest".to_vec(),
                },
            );

            let mut inbound = vec![0; "host-to-guest".len()];
            session.read_exact(&mut inbound).unwrap();
            assert_eq!(inbound, b"host-to-guest");

            session.write_all(b"guest-to-host").unwrap();

            loop {
                match read_mux(&mut host.reader) {
                    MuxFrame::Data {
                        session_id: id,
                        bytes,
                    } if id == session_id => {
                        assert_eq!(bytes, b"guest-to-host");
                        break;
                    }
                    MuxFrame::Window { .. } => {}
                    frame => panic!("unexpected mux frame while waiting for data: {frame:?}"),
                }
            }
        }
    }

    fn handle_tty_exec(vsock_fd: i32, req: &ExecRequest) {
        use std::ffi::CString;

        unsafe {
            // Set up initial winsize
            let ws = libc::winsize {
                ws_row: req.rows.unwrap_or(24),
                ws_col: req.cols.unwrap_or(80),
                ws_xpixel: 0,
                ws_ypixel: 0,
            };

            // Allocate PTY pair
            let mut master: libc::c_int = 0;
            let mut slave: libc::c_int = 0;
            if libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &ws as *const libc::winsize as *mut libc::winsize,
            ) < 0
            {
                write_frame_fd(vsock_fd, frame::ERROR, b"openpty failed");
                libc::close(vsock_fd);
                return;
            }

            let pid = libc::fork();
            if pid < 0 {
                write_frame_fd(vsock_fd, frame::ERROR, b"fork failed");
                libc::close(master);
                libc::close(slave);
                libc::close(vsock_fd);
                return;
            }

            if pid == 0 {
                // === CHILD ===
                libc::close(master);
                libc::close(vsock_fd);
                libc::setsid();
                libc::ioctl(slave, libc::TIOCSCTTY, 0);
                libc::dup2(slave, 0);
                libc::dup2(slave, 1);
                libc::dup2(slave, 2);
                if slave > 2 {
                    libc::close(slave);
                }

                // Close any other inherited fds
                for fd in 3..1024 {
                    libc::close(fd);
                }

                // Change directory if requested
                if let Some(ref cwd) = req.cwd {
                    if let Ok(dir) = CString::new(cwd.as_str()) {
                        libc::chdir(dir.as_ptr());
                    }
                }

                // Set environment
                for (k, v) in &req.env {
                    if let Ok(var) = CString::new(format!("{}={}", k, v)) {
                        libc::putenv(var.into_raw());
                    }
                }
                if !req.env.contains_key("TERM") {
                    let term = CString::new("TERM=xterm-256color").unwrap();
                    libc::putenv(term.into_raw());
                }
                if !req.env.contains_key("PATH") {
                    let path = CString::new(
                        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                    )
                    .unwrap();
                    libc::putenv(path.into_raw());
                }

                // Build argv and exec
                let c_args: Vec<CString> = req
                    .argv
                    .iter()
                    .map(|s| CString::new(s.as_str()).unwrap_or_else(|_| CString::new("").unwrap()))
                    .collect();
                let c_argv: Vec<*const libc::c_char> = c_args
                    .iter()
                    .map(|s| s.as_ptr())
                    .chain(std::iter::once(std::ptr::null()))
                    .collect();

                libc::execvp(c_argv[0], c_argv.as_ptr());

                // If execvp returns, it failed - print error to the PTY
                let err = std::io::Error::last_os_error();
                let msg = format!("lsb: {}: {}\n", req.argv[0], err);
                libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len());
                libc::_exit(127);
            }

            // === PARENT ===
            libc::close(slave);
            pty_poll_loop(vsock_fd, master, pid);
            libc::close(master);
            libc::close(vsock_fd);
        }
    }

    fn pty_poll_loop(vsock_fd: i32, master_fd: i32, child_pid: libc::pid_t) {
        let mut vsock_buf: Vec<u8> = Vec::new();
        let mut read_buf = [0u8; 4096];

        loop {
            let mut fds = [
                libc::pollfd {
                    fd: vsock_fd,
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: master_fd,
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];

            let ret = unsafe { libc::poll(fds.as_mut_ptr(), 2, 200) };
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                break;
            }

            // Check vsock for binary frames (stdin, resize)
            if fds[0].revents & libc::POLLIN != 0 {
                let n = unsafe {
                    libc::read(
                        vsock_fd,
                        read_buf.as_mut_ptr() as *mut libc::c_void,
                        read_buf.len(),
                    )
                };
                if n <= 0 {
                    // Host disconnected — signal child and exit
                    unsafe {
                        libc::kill(child_pid, libc::SIGHUP);
                    }
                    break;
                }
                vsock_buf.extend_from_slice(&read_buf[..n as usize]);

                // Process complete binary frames
                while let Some((msg_type, payload_start, total_len)) = frame::try_parse(&vsock_buf)
                {
                    let payload = &vsock_buf[payload_start..total_len];
                    match msg_type {
                        frame::STDIN => unsafe {
                            libc::write(
                                master_fd,
                                payload.as_ptr() as *const libc::c_void,
                                payload.len(),
                            );
                        },
                        frame::RESIZE => {
                            if let Some((rows, cols)) = frame::parse_resize(payload) {
                                unsafe {
                                    let ws = libc::winsize {
                                        ws_row: rows,
                                        ws_col: cols,
                                        ws_xpixel: 0,
                                        ws_ypixel: 0,
                                    };
                                    libc::ioctl(master_fd, libc::TIOCSWINSZ, &ws);
                                }
                            }
                        }
                        _ => {}
                    }
                    vsock_buf.drain(..total_len);
                }
            }

            if fds[0].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                unsafe {
                    libc::kill(child_pid, libc::SIGHUP);
                }
                break;
            }

            // Check PTY master for output — send raw bytes as STDOUT frames
            if fds[1].revents & libc::POLLIN != 0 {
                let n = unsafe {
                    libc::read(
                        master_fd,
                        read_buf.as_mut_ptr() as *mut libc::c_void,
                        read_buf.len(),
                    )
                };
                if n > 0 {
                    write_frame_fd(vsock_fd, frame::STDOUT, &read_buf[..n as usize]);
                }
            }

            if fds[1].revents & libc::POLLHUP != 0 {
                // Child closed PTY — drain remaining output
                loop {
                    let n = unsafe {
                        libc::read(
                            master_fd,
                            read_buf.as_mut_ptr() as *mut libc::c_void,
                            read_buf.len(),
                        )
                    };
                    if n <= 0 {
                        break;
                    }
                    write_frame_fd(vsock_fd, frame::STDOUT, &read_buf[..n as usize]);
                }
                break;
            }
        }

        // Wait for child and send exit code
        let mut status: libc::c_int = 0;
        unsafe {
            libc::waitpid(child_pid, &mut status, 0);
        }

        // Flush all filesystem writes to disk before reporting exit.
        // Without this, data can be lost if the VM is stopped immediately
        // after the exit code is sent (e.g. during checkpoint create).
        unsafe {
            libc::sync();
        }

        let exit_code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else if libc::WIFSIGNALED(status) {
            128 + libc::WTERMSIG(status)
        } else {
            1
        };

        write_frame_fd(vsock_fd, frame::EXIT, &frame::exit_payload(exit_code));
    }

    fn forward_accept_loop(listener_fd: i32) {
        loop {
            let client_fd =
                unsafe { libc::accept(listener_fd, std::ptr::null_mut(), std::ptr::null_mut()) };

            if client_fd < 0 {
                continue;
            }

            std::thread::spawn(move || {
                handle_forward_connection(client_fd);
            });
        }
    }

    fn handle_forward_connection(fd: i32) {
        let mut stream = unsafe { std::net::TcpStream::from_raw_fd(fd) };
        let _ = stream.set_nodelay(true);

        // Read the forward request frame
        let (_msg_type, payload) = match frame::read_frame(&mut stream) {
            Ok(Some(f)) => f,
            _ => return,
        };

        let req: ForwardRequest = match serde_json::from_slice(&payload) {
            Ok(r) => r,
            Err(e) => {
                let resp = ForwardResponse {
                    status: "error".into(),
                    message: Some(format!("invalid request: {}", e)),
                    session_id: None,
                };
                let _ = frame::send_json(&mut stream, frame::FWD_RESP, &resp);
                return;
            }
        };

        // Connect to the target port on localhost inside the guest
        let tcp_stream = match std::net::TcpStream::connect(("127.0.0.1", req.port)) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("lsb-guest: forward to port {} failed: {}", req.port, e);
                let resp = ForwardResponse {
                    status: "error".into(),
                    message: Some(format!("connection refused: {}", e)),
                    session_id: None,
                };
                let _ = frame::send_json(&mut stream, frame::FWD_RESP, &resp);
                return;
            }
        };

        // Send success response
        let resp = ForwardResponse {
            status: "ok".into(),
            message: None,
            session_id: None,
        };
        if frame::send_json(&mut stream, frame::FWD_RESP, &resp).is_err() {
            return;
        }

        // Bidirectional relay between vsock and TCP
        forward_relay(stream, tcp_stream);
    }

    fn forward_relay(vsock: std::net::TcpStream, tcp: std::net::TcpStream) {
        let mut vsock_read = vsock.try_clone().expect("clone vsock");
        let mut tcp_write = tcp.try_clone().expect("clone tcp");
        let mut tcp_read = tcp;
        let mut vsock_write = vsock;

        let t1 = std::thread::spawn(move || {
            let _ = std::io::copy(&mut vsock_read, &mut tcp_write);
            let _ = tcp_write.shutdown(std::net::Shutdown::Write);
        });
        let t2 = std::thread::spawn(move || {
            let _ = std::io::copy(&mut tcp_read, &mut vsock_write);
            let _ = vsock_write.shutdown(std::net::Shutdown::Write);
        });
        let _ = t1.join();
        let _ = t2.join();
    }

    fn selected_control_transport() -> GuestControlTransport {
        match std::fs::read_to_string("/proc/cmdline") {
            Ok(cmdline) => control_transport::from_kernel_cmdline(&cmdline),
            Err(err) => {
                eprintln!(
                    "lsb-guest: failed to read /proc/cmdline, defaulting to vsock transport: {}",
                    err
                );
                GuestControlTransport::Vsock
            }
        }
    }

    fn open_virtio_serial_stream(port_name: &str, label: &str) -> File {
        loop {
            match control_transport::discover_virtio_serial_device(
                Path::new("/dev"),
                Path::new("/sys/class/virtio-ports"),
                port_name,
            ) {
                Ok(Some(path)) => match OpenOptions::new().read(true).write(true).open(&path) {
                    Ok(file) => {
                        eprintln!(
                            "lsb-guest: virtio-serial {} port opened at {}",
                            label,
                            path.display()
                        );
                        return file;
                    }
                    Err(err) => {
                        eprintln!(
                            "lsb-guest: failed to open virtio-serial {} port at {}: {}",
                            label,
                            path.display(),
                            err
                        );
                    }
                },
                Ok(None) => {
                    eprintln!(
                        "lsb-guest: virtio-serial {} port '{}' not found yet",
                        label, port_name
                    );
                }
                Err(err) => {
                    eprintln!(
                        "lsb-guest: failed to scan virtio-serial {} ports: {}",
                        label, err
                    );
                }
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    fn open_virtio_serial_control_stream() -> File {
        open_virtio_serial_stream(lsb_proto::VIRTIO_SERIAL_CONTROL_PORT_NAME, "control")
    }

    fn open_virtio_serial_forward_stream() -> File {
        open_virtio_serial_stream(lsb_proto::VIRTIO_SERIAL_FORWARD_PORT_NAME, "forward")
    }

    fn handle_virtio_serial_control_stream<S>(stream: S)
    where
        S: PhysicalControlStream,
    {
        stream.configure_for_lsb();
        let reader = match stream.try_clone_stream() {
            Ok(reader) => reader,
            Err(err) => {
                eprintln!("lsb-guest: failed to clone virtio-serial control stream: {err}");
                return;
            }
        };
        let mut writer = stream;

        let Some(ready) =
            control_transport::ready_message_for_transport(GuestControlTransport::VirtioSerial)
        else {
            eprintln!("lsb-guest: missing virtio-serial guest ready payload");
            return;
        };

        if let Err(err) = frame::send_json(&mut writer, frame::GUEST_READY, &ready) {
            eprintln!("lsb-guest: failed to send guest ready handshake: {err}");
            return;
        }
        eprintln!(
            "lsb-guest: sent raw guest ready handshake over {:?} with protocol version {}",
            ready.transport, ready.protocol_version
        );

        let mux = GuestMux::start(reader, writer);
        while let Some(session) = mux.accept_session() {
            std::thread::spawn(move || {
                handle_mux_virtual_session(session);
            });
        }
    }

    fn run_virtio_serial_control_loop() -> ! {
        eprintln!(
            "lsb-guest: using virtio-serial control transport '{}'",
            lsb_proto::VIRTIO_SERIAL_CONTROL_PORT_NAME
        );

        std::thread::spawn(run_virtio_serial_forward_loop);

        loop {
            let stream = open_virtio_serial_control_stream();
            handle_virtio_serial_control_stream(stream);
            eprintln!("lsb-guest: virtio-serial control stream closed; reopening");
            reap_zombies();
        }
    }

    struct ActiveForward {
        session_id: u64,
        guest_tcp: std::net::TcpStream,
        host_closed: bool,
    }

    fn run_virtio_serial_forward_loop() {
        eprintln!(
            "lsb-guest: using virtio-serial forwarding transport '{}'",
            lsb_proto::VIRTIO_SERIAL_FORWARD_PORT_NAME
        );

        loop {
            let stream = open_virtio_serial_forward_stream();
            handle_virtio_serial_forward_stream(stream);
            eprintln!("lsb-guest: virtio-serial forwarding stream closed; reopening");
            reap_zombies();
        }
    }

    fn handle_virtio_serial_forward_stream<S>(stream: S)
    where
        S: PhysicalControlStream,
    {
        stream.configure_for_lsb();
        let mut reader = match stream.try_clone_stream() {
            Ok(reader) => reader,
            Err(err) => {
                eprintln!("lsb-guest: failed to clone forwarding stream: {}", err);
                return;
            }
        };
        let mut writer = stream;
        let mut active: Option<ActiveForward> = None;

        loop {
            let (msg_type, payload) = match frame::read_frame(&mut reader) {
                Ok(Some(frame)) => frame,
                Ok(None) => break,
                Err(err) => {
                    eprintln!("lsb-guest: forwarding frame read failed: {}", err);
                    break;
                }
            };

            match msg_type {
                frame::FWD_REQ => {
                    if active.as_ref().is_some_and(|session| !session.host_closed) {
                        send_forward_open_error(
                            &mut writer,
                            None,
                            "another forwarding session is already active".to_string(),
                        );
                        continue;
                    }
                    active = None;

                    let req: ForwardRequest = match serde_json::from_slice(&payload) {
                        Ok(req) => req,
                        Err(err) => {
                            send_forward_open_error(
                                &mut writer,
                                None,
                                format!("invalid request: {err}"),
                            );
                            continue;
                        }
                    };
                    let Some(session_id) = req.session_id else {
                        send_forward_open_error(
                            &mut writer,
                            None,
                            "missing forwarding session id".to_string(),
                        );
                        continue;
                    };
                    if req.port == 0 {
                        send_forward_open_error(
                            &mut writer,
                            Some(session_id),
                            "invalid guest port 0".to_string(),
                        );
                        continue;
                    }

                    let tcp_stream = match std::net::TcpStream::connect(("127.0.0.1", req.port)) {
                        Ok(stream) => stream,
                        Err(err) => {
                            eprintln!("lsb-guest: forward to port {} failed: {}", req.port, err);
                            send_forward_open_error(
                                &mut writer,
                                Some(session_id),
                                format!("connection refused: {err}"),
                            );
                            continue;
                        }
                    };

                    let _ = tcp_stream.set_nodelay(true);
                    if let Err(err) = send_forward_open_ok(&mut writer, session_id) {
                        eprintln!("lsb-guest: failed to send forward response: {}", err);
                        break;
                    }

                    let tcp_read = match tcp_stream.try_clone() {
                        Ok(stream) => stream,
                        Err(err) => {
                            eprintln!("lsb-guest: failed to clone guest target stream: {}", err);
                            let _ = frame::write_frame(
                                &mut writer,
                                frame::FWD_CLOSE,
                                &lsb_proto::encode_forward_close(session_id),
                            );
                            continue;
                        }
                    };
                    let writer_clone = match writer.try_clone_stream() {
                        Ok(stream) => stream,
                        Err(err) => {
                            eprintln!("lsb-guest: failed to clone forwarding writer: {}", err);
                            break;
                        }
                    };
                    std::thread::spawn(move || {
                        relay_guest_tcp_to_forward(session_id, tcp_read, writer_clone);
                    });

                    active = Some(ActiveForward {
                        session_id,
                        guest_tcp: tcp_stream,
                        host_closed: false,
                    });
                }
                frame::FWD_DATA => {
                    let Ok((session_id, data)) = lsb_proto::decode_forward_payload(&payload) else {
                        eprintln!("lsb-guest: invalid forwarding data frame");
                        continue;
                    };
                    let Some(session) = active.as_mut() else {
                        continue;
                    };
                    if session.session_id != session_id || session.host_closed {
                        continue;
                    }
                    if let Err(err) = session.guest_tcp.write_all(data) {
                        eprintln!("lsb-guest: writing forwarded bytes failed: {}", err);
                        let _ = frame::write_frame(
                            &mut writer,
                            frame::FWD_CLOSE,
                            &lsb_proto::encode_forward_close(session_id),
                        );
                        active = None;
                    }
                }
                frame::FWD_CLOSE => {
                    let Ok(session_id) = lsb_proto::decode_forward_close(&payload) else {
                        eprintln!("lsb-guest: invalid forwarding close frame");
                        continue;
                    };
                    if let Some(session) = active.as_mut() {
                        if session.session_id == session_id {
                            let _ = session.guest_tcp.shutdown(std::net::Shutdown::Write);
                            session.host_closed = true;
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn send_forward_open_ok(writer: &mut impl Write, session_id: u64) -> std::io::Result<()> {
        frame::send_json(
            writer,
            frame::FWD_RESP,
            &ForwardResponse {
                status: "ok".to_string(),
                message: None,
                session_id: Some(session_id),
            },
        )
    }

    fn send_forward_open_error(writer: &mut impl Write, session_id: Option<u64>, message: String) {
        let _ = frame::send_json(
            writer,
            frame::FWD_RESP,
            &ForwardResponse {
                status: "error".to_string(),
                message: Some(message),
                session_id,
            },
        );
    }

    fn relay_guest_tcp_to_forward<S>(
        session_id: u64,
        mut tcp_read: std::net::TcpStream,
        mut writer: S,
    ) where
        S: Write,
    {
        let mut buffer = [0u8; 16 * 1024];
        loop {
            match tcp_read.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    let payload = lsb_proto::encode_forward_payload(session_id, &buffer[..n]);
                    if frame::write_frame(&mut writer, frame::FWD_DATA, &payload).is_err() {
                        return;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = frame::write_frame(
            &mut writer,
            frame::FWD_CLOSE,
            &lsb_proto::encode_forward_close(session_id),
        );
    }

    fn run_vsock_control_loop() -> ! {
        let listener_fd = create_vsock_listener(VSOCK_PORT);
        eprintln!("lsb-guest: vsock listening on port {}", VSOCK_PORT);

        let fwd_listener_fd = create_vsock_listener(VSOCK_PORT_FORWARD);
        eprintln!(
            "lsb-guest: port forward listener on port {}",
            VSOCK_PORT_FORWARD
        );
        std::thread::spawn(move || {
            forward_accept_loop(fwd_listener_fd);
        });

        loop {
            let client_fd =
                unsafe { libc::accept(listener_fd, std::ptr::null_mut(), std::ptr::null_mut()) };

            if client_fd < 0 {
                reap_zombies();
                continue;
            }

            eprintln!("lsb-guest: accepted vsock connection");

            std::thread::spawn(move || {
                handle_vsock_connection(client_fd);
            });

            reap_zombies();
        }
    }

    extern "C" fn sigchld_handler(_: libc::c_int) {
        // Noop — actual reaping happens in the main loop
    }

    extern "C" fn sigterm_handler(_: libc::c_int) {
        unsafe {
            libc::sync();
            libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF);
        }
    }

    fn run_hidden_test_mode() -> Option<i32> {
        let mut args = std::env::args();
        let _program = args.next();
        match args.next().as_deref() {
            Some("--lsb-test-tcp-server") => {
                let result = (|| -> std::io::Result<()> {
                    let port = args
                        .next()
                        .ok_or_else(|| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                "missing test server port",
                            )
                        })?
                        .parse::<u16>()
                        .map_err(|err| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                format!("invalid test server port: {err}"),
                            )
                        })?;
                    if port == 0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "invalid test server port 0",
                        ));
                    }
                    let response = args.next().ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "missing test server response",
                        )
                    })?;
                    let ready_path = args.next();

                    let listener = TcpListener::bind(("127.0.0.1", port))?;
                    if let Some(path) = ready_path {
                        if args.next().is_some() {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                "unexpected extra test server arguments",
                            ));
                        }
                        std::fs::write(path, b"ready\n")?;
                    }
                    let (mut stream, _) = listener.accept()?;
                    stream.write_all(response.as_bytes())?;
                    stream.shutdown(std::net::Shutdown::Write)?;
                    Ok(())
                })();

                match result {
                    Ok(()) => Some(0),
                    Err(err) => {
                        eprintln!("lsb-guest: test tcp server failed: {err}");
                        Some(1)
                    }
                }
            }
            _ => None,
        }
    }

    pub fn run() -> ! {
        if let Some(code) = run_hidden_test_mode() {
            std::process::exit(code);
        }

        eprintln!("lsb-guest: starting as PID 1");

        mount_filesystems();
        eprintln!("lsb-guest: filesystems mounted");

        // Set hostname
        let hostname = b"lsb\0";
        unsafe {
            libc::sethostname(hostname.as_ptr() as *const libc::c_char, 5);
        }

        setup_networking();
        eprintln!("lsb-guest: networking ready");

        // Register signal handlers (PID 1 has no default signal dispositions)
        unsafe {
            libc::signal(
                libc::SIGCHLD,
                sigchld_handler as *const () as libc::sighandler_t,
            );
            libc::signal(
                libc::SIGTERM,
                sigterm_handler as *const () as libc::sighandler_t,
            );
            libc::signal(
                libc::SIGINT,
                sigterm_handler as *const () as libc::sighandler_t,
            );
        }

        match selected_control_transport() {
            GuestControlTransport::Vsock => run_vsock_control_loop(),
            GuestControlTransport::VirtioSerial => run_virtio_serial_control_loop(),
        }
    }
}

fn main() {
    #[cfg(target_os = "linux")]
    guest::run();

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("lsb-guest is a Linux-only binary meant to run inside a VM");
        std::process::exit(1);
    }
}
