use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::TcpStream;
#[cfg(unix)]
use std::os::unix::io::RawFd;
use std::sync::{Arc, Mutex};

use smoltcp::phy::{self, Checksum, Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant;
use tracing::debug;

const MTU: usize = 1514; // 14-byte Ethernet header + 1500-byte IP payload
const MAX_PENDING_FRAMES: usize = 256;
#[cfg_attr(not(windows), allow(dead_code))]
const MAX_STREAM_FRAME: usize = 65536;
#[cfg_attr(not(windows), allow(dead_code))]
const STREAM_TX_BACKPRESSURE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

pub trait FrameDevice: Device {
    fn drain_recv(&mut self);
    fn visit_pending_frames(&self, visitor: &mut dyn FnMut(&[u8]));
}

/// smoltcp Device backed by a Unix datagram socketpair fd.
///
/// One end of the socketpair is given to VZFileHandleNetworkDeviceAttachment
/// (the VM side). This Device reads/writes the other end (the host side),
/// giving us raw L2 Ethernet frames from/to the guest.
#[cfg(unix)]
pub struct VZDevice {
    fd: RawFd,
    recv_buf: Vec<u8>,
    /// Frames pre-read by `drain_recv()`, waiting to be consumed by smoltcp.
    pending_rx: VecDeque<Vec<u8>>,
}

#[cfg(unix)]
impl VZDevice {
    pub fn new(fd: RawFd) -> Self {
        VZDevice {
            fd,
            recv_buf: vec![0u8; MTU + 64], // slack for oversized frames
            pending_rx: VecDeque::new(),
        }
    }

    /// Non-blocking read of a single frame from the socketpair.
    fn recv_one_frame(&mut self) -> Option<Vec<u8>> {
        let n = unsafe {
            libc::recv(
                self.fd,
                self.recv_buf.as_mut_ptr() as *mut libc::c_void,
                self.recv_buf.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if n <= 0 {
            return None;
        }
        Some(self.recv_buf[..n as usize].to_vec())
    }

    /// Drain all available frames from the socketpair (non-blocking).
    /// Call this before `Interface::poll()` so we can inspect frames
    /// (e.g. to detect TCP SYN and dynamically add listening sockets).
    fn drain_recv_inner(&mut self) {
        while self.pending_rx.len() < MAX_PENDING_FRAMES {
            match self.recv_one_frame() {
                Some(frame) => self.pending_rx.push_back(frame),
                None => break,
            }
        }
    }

    // Pending frames are exposed through FrameDevice::visit_pending_frames.
}

#[cfg(unix)]
impl FrameDevice for VZDevice {
    fn drain_recv(&mut self) {
        self.drain_recv_inner();
    }

    fn visit_pending_frames(&self, visitor: &mut dyn FnMut(&[u8])) {
        for frame in &self.pending_rx {
            visitor(frame);
        }
    }
}

#[cfg(unix)]
pub struct VZRxToken {
    buffer: Vec<u8>,
}

#[cfg(unix)]
impl phy::RxToken for VZRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

#[cfg(unix)]
pub struct VZTxToken {
    fd: RawFd,
}

#[cfg(unix)]
impl phy::TxToken for VZTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        let sent = unsafe {
            libc::send(
                self.fd,
                buffer.as_ptr() as *const libc::c_void,
                buffer.len(),
                0,
            )
        };
        if sent < 0 {
            tracing::debug!("TX {len} bytes failed: sent={sent}");
        }
        result
    }
}

#[cfg(unix)]
impl Device for VZDevice {
    type RxToken<'a> = VZRxToken;
    type TxToken<'a> = VZTxToken;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // First drain pre-read frames, then try reading directly from the
        // socketpair for frames that arrived during poll.
        let buffer = self
            .pending_rx
            .pop_front()
            .or_else(|| self.recv_one_frame())?;
        Some((VZRxToken { buffer }, VZTxToken { fd: self.fd }))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(VZTxToken { fd: self.fd })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = MTU;
        // The guest VirtIO NIC offloads checksum calculation, so incoming
        // frames may have partial/invalid checksums. Tell smoltcp to only
        // generate checksums on TX (for the guest to verify), not verify on RX.
        caps.checksum.ipv4 = Checksum::Tx;
        caps.checksum.tcp = Checksum::Tx;
        caps.checksum.udp = Checksum::Tx;
        caps.checksum.icmpv4 = Checksum::Tx;
        caps
    }
}

#[cfg_attr(not(windows), allow(dead_code))]
pub struct QemuStreamDevice {
    stream: Arc<Mutex<TcpStream>>,
    read_buf: Vec<u8>,
    pending_rx: VecDeque<Vec<u8>>,
}

impl QemuStreamDevice {
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn new(stream: TcpStream) -> std::io::Result<Self> {
        stream.set_nonblocking(true)?;
        stream.set_nodelay(true)?;
        Ok(Self {
            stream: Arc::new(Mutex::new(stream)),
            read_buf: Vec::new(),
            pending_rx: VecDeque::new(),
        })
    }

    #[cfg_attr(not(windows), allow(dead_code))]
    fn drain_stream(&mut self) {
        let mut scratch = [0u8; 8192];
        loop {
            let read = {
                let mut stream = match self.stream.lock() {
                    Ok(stream) => stream,
                    Err(_) => return,
                };
                stream.read(&mut scratch)
            };

            match read {
                Ok(0) => break,
                Ok(n) => self.read_buf.extend_from_slice(&scratch[..n]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    debug!("QEMU stream netdev RX failed: {error}");
                    break;
                }
            }
        }

        self.parse_stream_frames();
    }

    #[cfg_attr(not(windows), allow(dead_code))]
    fn parse_stream_frames(&mut self) {
        while self.pending_rx.len() < MAX_PENDING_FRAMES {
            if self.read_buf.len() < 4 {
                break;
            }
            let frame_len = u32::from_be_bytes([
                self.read_buf[0],
                self.read_buf[1],
                self.read_buf[2],
                self.read_buf[3],
            ]) as usize;
            if frame_len > MAX_STREAM_FRAME {
                debug!("QEMU stream netdev frame too large: {frame_len} bytes");
                self.read_buf.clear();
                break;
            }
            let total_len = 4 + frame_len;
            if self.read_buf.len() < total_len {
                break;
            }
            let frame = self.read_buf[4..total_len].to_vec();
            self.read_buf.drain(..total_len);
            self.pending_rx.push_back(frame);
        }
    }
}

impl FrameDevice for QemuStreamDevice {
    fn drain_recv(&mut self) {
        self.drain_stream();
    }

    fn visit_pending_frames(&self, visitor: &mut dyn FnMut(&[u8])) {
        for frame in &self.pending_rx {
            visitor(frame);
        }
    }
}

#[cfg_attr(not(windows), allow(dead_code))]
pub struct QemuStreamRxToken {
    buffer: Vec<u8>,
}

impl phy::RxToken for QemuStreamRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

#[cfg_attr(not(windows), allow(dead_code))]
pub struct QemuStreamTxToken {
    stream: Arc<Mutex<TcpStream>>,
}

impl phy::TxToken for QemuStreamTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut frame = vec![0u8; len];
        let result = f(&mut frame);

        let mut payload = Vec::with_capacity(4 + frame.len());
        payload.extend_from_slice(&(frame.len() as u32).to_be_bytes());
        payload.extend_from_slice(&frame);

        match self.stream.lock() {
            Ok(mut stream) => write_all_nonblocking(&mut stream, &payload),
            Err(_) => debug!("QEMU stream netdev TX failed: stream lock poisoned"),
        }

        result
    }
}

impl Device for QemuStreamDevice {
    type RxToken<'a> = QemuStreamRxToken;
    type TxToken<'a> = QemuStreamTxToken;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let buffer = self.pending_rx.pop_front()?;
        Some((
            QemuStreamRxToken { buffer },
            QemuStreamTxToken {
                stream: Arc::clone(&self.stream),
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(QemuStreamTxToken {
            stream: Arc::clone(&self.stream),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        ethernet_capabilities()
    }
}

#[cfg_attr(not(windows), allow(dead_code))]
fn write_all_nonblocking(stream: &mut TcpStream, mut payload: &[u8]) {
    let started = std::time::Instant::now();
    while !payload.is_empty() {
        match stream.write(payload) {
            Ok(0) => {
                debug!("QEMU stream netdev TX closed while writing frame");
                return;
            }
            Ok(n) => payload = &payload[n..],
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if started.elapsed() >= STREAM_TX_BACKPRESSURE_TIMEOUT {
                    debug!(
                        "QEMU stream netdev TX timed out after {:?} while writing frame",
                        STREAM_TX_BACKPRESSURE_TIMEOUT
                    );
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => {
                debug!("QEMU stream netdev TX failed: {error}");
                return;
            }
        }
    }
}

#[cfg_attr(not(windows), allow(dead_code))]
fn ethernet_capabilities() -> DeviceCapabilities {
    let mut caps = DeviceCapabilities::default();
    caps.medium = Medium::Ethernet;
    caps.max_transmission_unit = MTU;
    caps.checksum.ipv4 = Checksum::Tx;
    caps.checksum.tcp = Checksum::Tx;
    caps.checksum.udp = Checksum::Tx;
    caps.checksum.icmpv4 = Checksum::Tx;
    caps
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, TcpListener};

    use smoltcp::phy::{Device, RxToken, TxToken};

    use super::*;

    fn connected_streams() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let client = TcpStream::connect(addr).expect("connect client");
        let (server, _) = listener.accept().expect("accept server");
        (client, server)
    }

    #[test]
    fn qemu_stream_device_reads_length_prefixed_frames() {
        let (mut qemu_side, proxy_side) = connected_streams();
        let mut device = QemuStreamDevice::new(proxy_side).expect("stream device");
        let frame = b"ethernet-frame";

        qemu_side
            .write_all(&(frame.len() as u32).to_be_bytes())
            .expect("write length");
        qemu_side.write_all(frame).expect("write frame");
        qemu_side.flush().expect("flush frame");
        for _ in 0..50 {
            device.drain_recv();
            if device
                .receive(Instant::from_millis(0))
                .map(|(rx, _)| {
                    let received = rx.consume(|buffer| buffer.to_vec());
                    assert_eq!(received, frame);
                })
                .is_some()
            {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        panic!("frame should be available");
    }

    #[test]
    fn qemu_stream_device_writes_length_prefixed_frames() {
        let (mut qemu_side, proxy_side) = connected_streams();
        let mut device = QemuStreamDevice::new(proxy_side).expect("stream device");
        let tx = device.transmit(Instant::from_millis(0)).expect("tx token");

        tx.consume(5, |buffer| buffer.copy_from_slice(b"hello"));

        let mut len = [0u8; 4];
        qemu_side.read_exact(&mut len).expect("read length");
        assert_eq!(u32::from_be_bytes(len), 5);
        let mut frame = [0u8; 5];
        qemu_side.read_exact(&mut frame).expect("read frame");
        assert_eq!(&frame, b"hello");
    }
}
