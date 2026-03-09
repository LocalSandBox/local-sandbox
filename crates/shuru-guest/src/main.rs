#[cfg(target_os = "linux")]
mod guest {
    use std::io::{Read, Write};
    use std::os::unix::io::FromRawFd;
    use std::process::{Command, Stdio};

    use shuru_proto::frame;
    use shuru_proto::{
        ExecRequest, ForwardRequest, ForwardResponse, MountRequest, MountResponse,
        ReadFileRequest, WriteFileRequest, WriteFileResponse,
    };
    use shuru_proto::{VSOCK_PORT, VSOCK_PORT_FORWARD};

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
                "shuru-guest: failed to mount {} on {}: {}",
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
        mount_fs("devpts", "/dev/pts", "devpts", Some("newinstance,ptmxmode=0666"));
        mount_fs("tmpfs", "/tmp", "tmpfs", None);
    }

    fn process_mount(req: &MountRequest) -> MountResponse {
        if let Err(e) = std::fs::create_dir_all(&req.guest_path) {
            return MountResponse {
                tag: req.tag.clone(),
                ok: false,
                error: Some(format!("failed to create mount point {}: {}", req.guest_path, e)),
            };
        }

        match mount_overlay(&req.tag, &req.guest_path) {
            Ok(()) => MountResponse {
                tag: req.tag.clone(),
                ok: true,
                error: None,
            },
            Err(msg) => MountResponse {
                tag: req.tag.clone(),
                ok: false,
                error: Some(msg),
            },
        }
    }

    fn mount_overlay(tag: &str, guest_path: &str) -> Result<(), String> {
        let virtiofs_dir = format!("/mnt/.virtiofs/{}", tag);
        let overlay_dir = format!("/mnt/.overlay/{}", tag);
        let upper_dir = format!("{}/upper", overlay_dir);
        let work_dir = format!("{}/work", overlay_dir);

        std::fs::create_dir_all(&virtiofs_dir)
            .and_then(|_| std::fs::create_dir_all(&upper_dir))
            .and_then(|_| std::fs::create_dir_all(&work_dir))
            .map_err(|e| format!("failed to create staging dirs: {}", e))?;

        if !mount_fs(tag, &virtiofs_dir, "virtiofs", None) {
            return Err(format!("failed to mount virtiofs device '{}'", tag));
        }

        if !mount_fs("tmpfs", &overlay_dir, "tmpfs", None) {
            return Err(format!("failed to mount tmpfs for overlay on '{}'", tag));
        }

        // Re-create upper/work after tmpfs mount
        std::fs::create_dir_all(&upper_dir)
            .and_then(|_| std::fs::create_dir_all(&work_dir))
            .map_err(|e| format!("failed to create overlay dirs after tmpfs: {}", e))?;

        let overlay_opts = format!(
            "lowerdir={},upperdir={},workdir={}",
            virtiofs_dir, upper_dir, work_dir
        );
        if !mount_fs("overlay", guest_path, "overlay", Some(&overlay_opts)) {
            return Err(format!("failed to mount overlay at {}", guest_path));
        }

        eprintln!("shuru-guest: mounted {} -> {} (overlay)", tag, guest_path);
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
                eprintln!("shuru-guest: failed to get {} flags", display_name);
                return;
            }

            ifr.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
            if libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &ifr) < 0 {
                eprintln!("shuru-guest: failed to bring up {}", display_name);
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
                eprintln!("shuru-guest: failed to create socket for networking setup");
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
                eprintln!("shuru-guest: no network device (sandbox mode)");
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
                eprintln!("shuru-guest: network already configured (by initramfs)");
            } else {
                eprintln!("shuru-guest: eth0 present but no IP configured");
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
                    "shuru-guest: failed to create vsock socket: {}",
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
                    "shuru-guest: failed to bind vsock on port {}: {}",
                    port,
                    std::io::Error::last_os_error()
                );
            }

            let ret = libc::listen(fd, 1);
            if ret < 0 {
                panic!(
                    "shuru-guest: failed to listen on vsock: {}",
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

    fn handle_connection(fd: i32) {
        // SAFETY: fd is a valid socket from accept()
        let stream = unsafe { std::net::TcpStream::from_raw_fd(fd) };
        let _ = stream.set_nodelay(true);
        let mut reader = stream.try_clone().expect("failed to clone stream");
        let mut writer = stream;

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
                        let raw_fd = std::os::unix::io::AsRawFd::as_raw_fd(&writer);
                        // Prevent TcpStream from closing the fd on drop
                        std::mem::forget(writer);
                        std::mem::forget(reader);
                        handle_tty_exec(raw_fd, &req);
                        return;
                    }

                    // Non-TTY mode: piped exec
                    handle_piped_exec(&req, &mut writer);
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
                _ => {} // unknown type, skip
            }
        }
    }

    fn handle_read_file(req: &ReadFileRequest, writer: &mut impl Write) {
        match std::fs::read(&req.path) {
            Ok(data) => {
                let _ = frame::write_frame(writer, frame::READ_FILE_RESP, &data);
            }
            Err(e) => {
                let msg = format!("read_file {}: {}", req.path, e);
                let _ = frame::write_frame(writer, frame::ERROR, msg.as_bytes());
            }
        }
    }

    fn handle_write_file(
        req: &WriteFileRequest,
        reader: &mut impl Read,
        writer: &mut impl Write,
    ) {
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

        if let Some(parent) = std::path::Path::new(&req.path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        match std::fs::write(&req.path, &data) {
            Ok(()) => {
                unsafe { libc::sync(); }
                let resp = WriteFileResponse { ok: true, error: None };
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

    fn handle_piped_exec(req: &ExecRequest, writer: &mut impl Write) {
        let mut cmd = Command::new(&req.argv[0]);
        if req.argv.len() > 1 {
            cmd.args(&req.argv[1..]);
        }
        for (k, v) in &req.env {
            cmd.env(k, v);
        }
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        match cmd.spawn() {
            Ok(mut child) => {
                let mut stdout_data = Vec::new();
                let mut stderr_data = Vec::new();

                if let Some(mut stdout) = child.stdout.take() {
                    let _ = stdout.read_to_end(&mut stdout_data);
                }
                if let Some(mut stderr) = child.stderr.take() {
                    let _ = stderr.read_to_end(&mut stderr_data);
                }

                let status = child.wait().expect("failed to wait on child");
                let exit_code = status.code().unwrap_or(-1);

                // Flush all filesystem writes to disk before reporting exit.
                // Without this, data can be lost if the VM is stopped immediately
                // after the exit code is sent (e.g. during checkpoint create).
                unsafe {
                    libc::sync();
                }

                if !stdout_data.is_empty() {
                    let _ = frame::write_frame(writer, frame::STDOUT, &stdout_data);
                }

                if !stderr_data.is_empty() {
                    let _ = frame::write_frame(writer, frame::STDERR, &stderr_data);
                }

                let _ = frame::write_frame(writer, frame::EXIT, &frame::exit_payload(exit_code));
            }
            Err(e) => {
                let msg = format!("failed to spawn: {}", e);
                let _ = frame::write_frame(writer, frame::ERROR, msg.as_bytes());
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
                let msg = format!("shuru: {}: {}\n", req.argv[0], err);
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
                while let Some((msg_type, payload_start, total_len)) =
                    frame::try_parse(&vsock_buf)
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
            let client_fd = unsafe {
                libc::accept(listener_fd, std::ptr::null_mut(), std::ptr::null_mut())
            };

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
                eprintln!("shuru-guest: forward to port {} failed: {}", req.port, e);
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

    extern "C" fn sigchld_handler(_: libc::c_int) {
        // Noop — actual reaping happens in the main loop
    }

    extern "C" fn sigterm_handler(_: libc::c_int) {
        unsafe {
            libc::sync();
            libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF);
        }
    }

    fn sync_clock() {
        let cmdline = match std::fs::read_to_string("/proc/cmdline") {
            Ok(s) => s,
            Err(_) => return,
        };
        for param in cmdline.split_whitespace() {
            if let Some(val) = param.strip_prefix("shuru.epoch=") {
                if let Ok(epoch) = val.parse::<i64>() {
                    let tv = libc::timeval {
                        tv_sec: epoch,
                        tv_usec: 0,
                    };
                    unsafe {
                        libc::settimeofday(&tv, std::ptr::null());
                    }
                    eprintln!("shuru-guest: clock set to {}", epoch);
                }
                break;
            }
        }
    }

    pub fn run() -> ! {
        eprintln!("shuru-guest: starting as PID 1");

        mount_filesystems();
        eprintln!("shuru-guest: filesystems mounted");

        sync_clock();

        // Set hostname
        let hostname = b"shuru\0";
        unsafe {
            libc::sethostname(hostname.as_ptr() as *const libc::c_char, 5);
        }

        setup_networking();
        eprintln!("shuru-guest: networking ready");

        // Register signal handlers (PID 1 has no default signal dispositions)
        unsafe {
            libc::signal(libc::SIGCHLD, sigchld_handler as *const () as libc::sighandler_t);
            libc::signal(libc::SIGTERM, sigterm_handler as *const () as libc::sighandler_t);
            libc::signal(libc::SIGINT, sigterm_handler as *const () as libc::sighandler_t);
        }

        let listener_fd = create_vsock_listener(VSOCK_PORT);
        eprintln!("shuru-guest: vsock listening on port {}", VSOCK_PORT);

        let fwd_listener_fd = create_vsock_listener(VSOCK_PORT_FORWARD);
        eprintln!(
            "shuru-guest: port forward listener on port {}",
            VSOCK_PORT_FORWARD
        );
        std::thread::spawn(move || {
            forward_accept_loop(fwd_listener_fd);
        });

        loop {
            let client_fd = unsafe {
                libc::accept(listener_fd, std::ptr::null_mut(), std::ptr::null_mut())
            };

            if client_fd < 0 {
                reap_zombies();
                continue;
            }

            eprintln!("shuru-guest: accepted vsock connection");

            std::thread::spawn(move || {
                handle_connection(client_fd);
            });

            reap_zombies();
        }
    }
}

fn main() {
    #[cfg(target_os = "linux")]
    guest::run();

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("shuru-guest is a Linux-only binary meant to run inside a VM");
        std::process::exit(1);
    }
}
