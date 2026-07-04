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
            assert_eq!(ready.capabilities, [lsb_proto::CAP_FILE_RANGE_IO]);
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

#[cfg(target_os = "linux")]
mod guest {
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
    use std::os::unix::process::CommandExt;
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    use super::control_transport::{self, GuestControlTransport};
    use super::file_transfer;
    use lsb_proto::frame;
    use lsb_proto::{
        ChmodRequest, CopyRequest, DirEntry, ExecRequest, ForwardRequest, ForwardResponse,
        FsOkResponse, MkdirRequest, MountRequest, MountResponse, ReadDirRequest, ReadDirResponse,
        ReadFileRequest, RemoveRequest, RenameRequest, StatRequest, StatResponse, WatchEvent,
        WatchRequest, WriteFileRequest, WriteFileResponse,
    };
    use lsb_proto::{VSOCK_PORT, VSOCK_PORT_FORWARD};

    trait ControlStream: Read + Write + AsRawFd + IntoRawFd + Send + 'static {
        fn try_clone_stream(&self) -> std::io::Result<Self>
        where
            Self: Sized;

        fn configure_for_lsb(&self) {}
    }

    impl ControlStream for std::net::TcpStream {
        fn try_clone_stream(&self) -> std::io::Result<Self> {
            self.try_clone()
        }

        fn configure_for_lsb(&self) {
            let _ = self.set_nodelay(true);
        }
    }

    impl ControlStream for File {
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
            MountRequest::Overlay { source, target } => (source.as_str(), target.as_str()),
            MountRequest::Direct { source, target, .. } => (source.as_str(), target.as_str()),
        };

        if let Err(e) = std::fs::create_dir_all(target) {
            return MountResponse {
                source: source.to_string(),
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
        };

        match result {
            Ok(()) => MountResponse {
                source: source.to_string(),
                target: target.to_string(),
                ok: true,
                error: None,
            },
            Err(msg) => MountResponse {
                source: source.to_string(),
                target: target.to_string(),
                ok: false,
                error: Some(msg),
            },
        }
    }

    fn mount_overlay(source: &str, target: &str) -> Result<(), String> {
        let virtiofs_dir = format!("/mnt/.virtiofs/{}", source);
        let overlay_dir = format!("/mnt/.overlay/{}", source);
        let upper_dir = format!("{}/upper", overlay_dir);
        let work_dir = format!("{}/work", overlay_dir);

        std::fs::create_dir_all(&virtiofs_dir)
            .and_then(|_| std::fs::create_dir_all(&upper_dir))
            .and_then(|_| std::fs::create_dir_all(&work_dir))
            .map_err(|e| format!("failed to create staging dirs: {}", e))?;

        if !mount_fs(source, &virtiofs_dir, "virtiofs", None) {
            return Err(format!("failed to mount virtiofs device '{}'", source));
        }

        if !mount_fs("tmpfs", &overlay_dir, "tmpfs", None) {
            return Err(format!("failed to mount tmpfs for overlay on '{}'", source));
        }

        // Re-create upper/work after tmpfs mount
        std::fs::create_dir_all(&upper_dir)
            .and_then(|_| std::fs::create_dir_all(&work_dir))
            .map_err(|e| format!("failed to create overlay dirs after tmpfs: {}", e))?;

        let overlay_opts = format!(
            "lowerdir={},upperdir={},workdir={}",
            virtiofs_dir, upper_dir, work_dir
        );
        if !mount_fs("overlay", target, "overlay", Some(&overlay_opts)) {
            return Err(format!("failed to mount overlay at {}", target));
        }

        eprintln!("lsb-guest: mounted {} -> {} (overlay)", source, target);
        Ok(())
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
        S: ControlStream,
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
                    handle_watch(&req, writer);
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

    fn handle_piped_exec<S>(req: &ExecRequest, control_reader: S, control_writer: S)
    where
        S: ControlStream,
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

                // Channel serializes all frame writes to prevent interleaving
                let (tx, rx) = std::sync::mpsc::channel::<(u8, Vec<u8>)>();

                // Writer thread: drains channel, writes frames to vsock
                let mut frame_writer = control_writer;
                let writer_thread = std::thread::spawn(move || {
                    for (frame_type, payload) in rx {
                        if frame::write_frame(&mut frame_writer, frame_type, &payload).is_err() {
                            break;
                        }
                    }
                });

                // Thread: child stdout -> STDOUT frames
                let child_stdout = child.stdout.take().unwrap();
                let tx_stdout = tx.clone();
                let stdout_thread = std::thread::spawn(move || {
                    let mut stdout = child_stdout;
                    let mut buf = [0u8; 8192];
                    loop {
                        match stdout.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if tx_stdout.send((frame::STDOUT, buf[..n].to_vec())).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });

                // Thread: child stderr -> STDERR frames
                let child_stderr = child.stderr.take().unwrap();
                let tx_stderr = tx.clone();
                let stderr_thread = std::thread::spawn(move || {
                    let mut stderr = child_stderr;
                    let mut buf = [0u8; 8192];
                    loop {
                        match stderr.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if tx_stderr.send((frame::STDERR, buf[..n].to_vec())).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });

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

                // Wait for output to drain, then wait for child
                let _ = stdout_thread.join();
                let _ = stderr_thread.join();
                let status = child.wait().expect("failed to wait on child");
                let exit_code = status.code().unwrap_or(-1);

                unsafe {
                    libc::sync();
                }

                let _ = tx.send((frame::EXIT, frame::exit_payload(exit_code).to_vec()));
                drop(tx);
                let _ = writer_thread.join();

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

    fn handle_watch<S>(req: &WatchRequest, mut writer: S)
    where
        S: ControlStream,
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

        let control_raw = writer.as_raw_fd();
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

            // Check if vsock peer hung up (host closed connection = stop watching)
            let mut vfds = [libc::pollfd {
                fd: control_raw,
                events: 0,
                revents: 0,
            }];
            unsafe { libc::poll(vfds.as_mut_ptr(), 1, 0) };
            if vfds[0].revents & libc::POLLHUP != 0 {
                break;
            }
        }

        unsafe { libc::close(inotify_fd) };
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
                };
                let _ = frame::send_json(&mut stream, frame::FWD_RESP, &resp);
                return;
            }
        };

        // Send success response
        let resp = ForwardResponse {
            status: "ok".into(),
            message: None,
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

    fn open_virtio_serial_control_stream() -> File {
        loop {
            match control_transport::discover_virtio_serial_device(
                Path::new("/dev"),
                Path::new("/sys/class/virtio-ports"),
                lsb_proto::VIRTIO_SERIAL_CONTROL_PORT_NAME,
            ) {
                Ok(Some(path)) => match OpenOptions::new().read(true).write(true).open(&path) {
                    Ok(file) => {
                        eprintln!(
                            "lsb-guest: virtio-serial control port opened at {}",
                            path.display()
                        );
                        return file;
                    }
                    Err(err) => {
                        eprintln!(
                            "lsb-guest: failed to open virtio-serial control port at {}: {}",
                            path.display(),
                            err
                        );
                    }
                },
                Ok(None) => {
                    eprintln!(
                        "lsb-guest: virtio-serial control port '{}' not found yet",
                        lsb_proto::VIRTIO_SERIAL_CONTROL_PORT_NAME
                    );
                }
                Err(err) => {
                    eprintln!(
                        "lsb-guest: failed to scan virtio-serial control ports: {}",
                        err
                    );
                }
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    fn run_virtio_serial_control_loop() -> ! {
        eprintln!(
            "lsb-guest: using virtio-serial control transport '{}'",
            lsb_proto::VIRTIO_SERIAL_CONTROL_PORT_NAME
        );
        eprintln!("lsb-guest: port forwarding over virtio-serial is deferred until M11");

        loop {
            let stream = open_virtio_serial_control_stream();
            handle_control_stream(
                stream,
                control_transport::ready_message_for_transport(GuestControlTransport::VirtioSerial),
            );
            eprintln!("lsb-guest: virtio-serial control stream closed; reopening");
            reap_zombies();
        }
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

    pub fn run() -> ! {
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
