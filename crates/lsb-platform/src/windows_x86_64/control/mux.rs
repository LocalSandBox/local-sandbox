use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

use lsb_proto::frame;
use lsb_proto::mux::{self, MuxFrame};

use crate::PlatformControlStream;

const SESSION_RECEIVE_QUEUE_BYTES: usize = 256 * 1024;
const SESSION_SEND_QUEUE_BYTES: usize = 256 * 1024;
const MAX_CONTROL_QUEUE_FRAMES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MuxSessionKind {
    Exec,
    Watch,
    File,
}

impl MuxSessionKind {
    fn metadata(self) -> &'static [u8] {
        match self {
            Self::Exec => b"exec",
            Self::Watch => b"watch",
            Self::File => b"file",
        }
    }
}

#[derive(Debug)]
pub(crate) struct MuxManager {
    inner: Arc<MuxManagerInner>,
}

impl MuxManager {
    pub(crate) fn start(stream: PlatformControlStream) -> Result<Self, MuxManagerError> {
        let reader = stream
            .try_clone()
            .map_err(|error| MuxManagerError::PhysicalClone {
                detail: error.to_string(),
            })?;
        Ok(Self::start_with_split(reader, stream))
    }

    fn start_with_split<R, W>(reader: R, writer: W) -> Self
    where
        R: Read + Send + 'static,
        W: Write + Send + 'static,
    {
        let manager = Self {
            inner: Arc::new(MuxManagerInner::new()),
        };

        let read_inner = Arc::clone(&manager.inner);
        thread::Builder::new()
            .name("lsb-windows-mux-reader".to_string())
            .spawn(move || read_loop(read_inner, reader))
            .expect("failed to spawn Windows mux reader thread");

        let write_inner = Arc::clone(&manager.inner);
        thread::Builder::new()
            .name("lsb-windows-mux-writer".to_string())
            .spawn(move || write_loop(write_inner, writer))
            .expect("failed to spawn Windows mux writer thread");

        manager
    }

    pub(crate) fn open_session(&self, kind: MuxSessionKind) -> Result<MuxSession, MuxSessionError> {
        self.inner.open_session(kind)
    }

    #[cfg(test)]
    fn start_for_test<R, W>(reader: R, writer: W) -> Self
    where
        R: Read + Send + 'static,
        W: Write + Send + 'static,
    {
        Self::start_with_split(reader, writer)
    }
}

impl Drop for MuxManager {
    fn drop(&mut self) {
        if self.inner.handle_count.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.inner
                .fail("Windows mux manager was dropped".to_string());
        }
    }
}

impl Clone for MuxManager {
    fn clone(&self) -> Self {
        self.inner.handle_count.fetch_add(1, Ordering::Relaxed);
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct MuxSession {
    inner: Arc<MuxManagerInner>,
    session_id: u64,
}

impl MuxSession {
    #[cfg(test)]
    fn session_id(&self) -> u64 {
        self.session_id
    }

    pub(crate) fn close(&self) -> io::Result<()> {
        self.inner.close_session(self.session_id);
        Ok(())
    }

    pub(crate) fn reset(&self, reason: impl Into<String>) -> io::Result<()> {
        self.inner.reset_session(self.session_id, reason.into());
        Ok(())
    }
}

impl Drop for MuxSession {
    fn drop(&mut self) {
        self.inner.close_session(self.session_id);
    }
}

impl Read for MuxSession {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let mut state = self.inner.state.lock().map_err(|_| poisoned_lock())?;
        loop {
            if let Some(reason) = state.failed.clone() {
                return Err(broken_pipe(reason));
            }

            let session = state
                .sessions
                .get_mut(&self.session_id)
                .ok_or_else(|| broken_pipe("mux session no longer exists"))?;

            if let Some(reason) = session.reset_reason.clone() {
                return Err(connection_reset(reason));
            }

            if !session.inbound.is_empty() {
                let mut copied = 0usize;
                while copied < buf.len() {
                    let Some(byte) = session.inbound.pop_front() else {
                        break;
                    };
                    buf[copied] = byte;
                    copied += 1;
                }

                if copied > 0 {
                    let credit = u32::try_from(copied).map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "mux read credit exceeds u32 window range",
                        )
                    })?;
                    state = wait_for_control_queue_capacity(&self.inner, state)?;
                    state.control_queue.push_back(MuxFrame::Window {
                        session_id: self.session_id,
                        credit,
                    });
                    self.inner.cv.notify_all();
                    return Ok(copied);
                }
            }

            if session.remote_fin {
                return Ok(0);
            }

            state = self.inner.cv.wait(state).map_err(|_| poisoned_lock())?;
        }
    }
}

impl Write for MuxSession {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let mut state = self.inner.state.lock().map_err(|_| poisoned_lock())?;
        loop {
            if let Some(reason) = state.failed.clone() {
                return Err(broken_pipe(reason));
            }

            let session = state
                .sessions
                .get_mut(&self.session_id)
                .ok_or_else(|| broken_pipe("mux session no longer exists"))?;

            if let Some(reason) = session.reset_reason.clone() {
                return Err(connection_reset(reason));
            }
            if session.local_fin {
                return Err(broken_pipe("mux session local side is closed"));
            }
            if session.remote_fin {
                return Err(broken_pipe("mux session remote side is closed"));
            }
            if session.open_state != SessionOpenState::Open {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "mux session is not open yet",
                ));
            }

            let available_queue = SESSION_SEND_QUEUE_BYTES.saturating_sub(session.outbound_bytes);
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
                    state.ready_sessions.push_back(self.session_id);
                }
                self.inner.cv.notify_all();
                return Ok(writable);
            }

            state = self.inner.cv.wait(state).map_err(|_| poisoned_lock())?;
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut state = self.inner.state.lock().map_err(|_| poisoned_lock())?;
        loop {
            if let Some(reason) = state.failed.clone() {
                return Err(broken_pipe(reason));
            }

            let session = state
                .sessions
                .get(&self.session_id)
                .ok_or_else(|| broken_pipe("mux session no longer exists"))?;

            if let Some(reason) = session.reset_reason.clone() {
                return Err(connection_reset(reason));
            }
            if session.outbound_bytes == 0 {
                return Ok(());
            }

            state = self.inner.cv.wait(state).map_err(|_| poisoned_lock())?;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MuxManagerError {
    PhysicalClone { detail: String },
}

impl fmt::Display for MuxManagerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PhysicalClone { detail } => write!(
                f,
                "failed to clone the established Windows virtio-serial control pipe for mux-owned split I/O: {detail}"
            ),
        }
    }
}

impl std::error::Error for MuxManagerError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MuxSessionError {
    ManagerClosed { reason: String },
    Rejected { reason: String },
    SessionIdExhausted,
}

impl fmt::Display for MuxSessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ManagerClosed { reason } => {
                write!(f, "Windows mux manager is closed: {reason}")
            }
            Self::Rejected { reason } => {
                write!(f, "guest rejected Windows mux session: {reason}")
            }
            Self::SessionIdExhausted => {
                f.write_str("Windows mux manager exhausted host session ids")
            }
        }
    }
}

impl std::error::Error for MuxSessionError {}

#[derive(Debug)]
struct MuxManagerInner {
    handle_count: AtomicUsize,
    state: Mutex<MuxManagerState>,
    cv: Condvar,
}

impl MuxManagerInner {
    fn new() -> Self {
        Self {
            handle_count: AtomicUsize::new(1),
            state: Mutex::new(MuxManagerState::new()),
            cv: Condvar::new(),
        }
    }

    fn open_session(self: &Arc<Self>, kind: MuxSessionKind) -> Result<MuxSession, MuxSessionError> {
        let mut state = self.state.lock().expect("Windows mux state lock poisoned");
        if let Some(reason) = state.failed.clone() {
            return Err(MuxSessionError::ManagerClosed { reason });
        }

        let session_id = state.next_host_session_id;
        state.next_host_session_id = state
            .next_host_session_id
            .checked_add(2)
            .ok_or(MuxSessionError::SessionIdExhausted)?;

        state.sessions.insert(session_id, SessionState::new(kind));

        loop {
            if let Some(reason) = state.failed.clone() {
                state.sessions.remove(&session_id);
                return Err(MuxSessionError::ManagerClosed { reason });
            }
            if state.control_queue.len() < MAX_CONTROL_QUEUE_FRAMES {
                break;
            }
            state = self
                .cv
                .wait(state)
                .expect("Windows mux state lock poisoned");
        }

        state.control_queue.push_back(MuxFrame::Open {
            session_id,
            metadata: kind.metadata().to_vec(),
        });
        self.cv.notify_all();

        loop {
            if let Some(reason) = state.failed.clone() {
                state.sessions.remove(&session_id);
                return Err(MuxSessionError::ManagerClosed { reason });
            }

            match state
                .sessions
                .get(&session_id)
                .map(|session| session.open_state.clone())
            {
                Some(SessionOpenState::Open) => {
                    return Ok(MuxSession {
                        inner: Arc::clone(self),
                        session_id,
                    });
                }
                Some(SessionOpenState::Rejected(reason)) => {
                    state.sessions.remove(&session_id);
                    return Err(MuxSessionError::Rejected { reason });
                }
                Some(SessionOpenState::Opening) => {
                    state = self
                        .cv
                        .wait(state)
                        .expect("Windows mux state lock poisoned");
                }
                None => {
                    return Err(MuxSessionError::ManagerClosed {
                        reason: "mux session disappeared while opening".to_string(),
                    });
                }
            }
        }
    }

    fn close_session(&self, session_id: u64) {
        let mut state = self.state.lock().expect("Windows mux state lock poisoned");
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

    fn reset_session(&self, session_id: u64, reason: String) {
        let mut state = self.state.lock().expect("Windows mux state lock poisoned");
        if state.failed.is_some() {
            return;
        }
        if !state.sessions.contains_key(&session_id) {
            return;
        }
        if state.control_queue.len() >= MAX_CONTROL_QUEUE_FRAMES {
            state.fail(format!(
                "mux control queue was full while resetting session {session_id}"
            ));
            self.cv.notify_all();
            return;
        }

        if let Some(session) = state.sessions.get_mut(&session_id) {
            session.outbound.clear();
            session.outbound_bytes = 0;
            session.reset_reason = Some(reason.clone());
            session.local_fin = true;
            session.fin_sent = true;
            session.scheduled = false;
        }
        state.ready_sessions.retain(|queued| *queued != session_id);
        state
            .control_queue
            .push_back(MuxFrame::Rst { session_id, reason });
        self.cv.notify_all();
    }

    fn fail(&self, reason: String) {
        let mut state = self.state.lock().expect("Windows mux state lock poisoned");
        state.fail(reason);
        self.cv.notify_all();
    }
}

#[derive(Debug)]
struct MuxManagerState {
    next_host_session_id: u64,
    sessions: HashMap<u64, SessionState>,
    control_queue: VecDeque<MuxFrame>,
    ready_sessions: VecDeque<u64>,
    failed: Option<String>,
}

impl MuxManagerState {
    fn new() -> Self {
        Self {
            next_host_session_id: 1,
            sessions: HashMap::new(),
            control_queue: VecDeque::new(),
            ready_sessions: VecDeque::new(),
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
        self.failed = Some(reason);
    }
}

#[derive(Debug)]
struct SessionState {
    open_state: SessionOpenState,
    inbound: VecDeque<u8>,
    outbound: VecDeque<Vec<u8>>,
    outbound_bytes: usize,
    send_credit: usize,
    remote_fin: bool,
    local_fin: bool,
    fin_sent: bool,
    reset_reason: Option<String>,
    scheduled: bool,
}

impl SessionState {
    fn new(_kind: MuxSessionKind) -> Self {
        Self {
            open_state: SessionOpenState::Opening,
            inbound: VecDeque::new(),
            outbound: VecDeque::new(),
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum SessionOpenState {
    Opening,
    Open,
    Rejected(String),
}

fn read_loop<R>(inner: Arc<MuxManagerInner>, mut reader: R)
where
    R: Read,
{
    loop {
        let frame = match frame::read_frame(&mut reader) {
            Ok(Some((frame_type, payload))) => match mux::decode_frame(frame_type, &payload) {
                Ok(frame) => frame,
                Err(error) => {
                    inner.fail(format!("invalid mux frame received from guest: {error}"));
                    return;
                }
            },
            Ok(None) => {
                inner.fail("Windows mux physical control stream reached EOF".to_string());
                return;
            }
            Err(error) => {
                inner.fail(format!(
                    "failed to read Windows mux physical control stream: {error}"
                ));
                return;
            }
        };

        if let Err(reason) = handle_incoming_frame(&inner, frame) {
            inner.fail(reason);
            return;
        }
    }
}

fn write_loop<W>(inner: Arc<MuxManagerInner>, mut writer: W)
where
    W: Write,
{
    while let Some(frame) = next_outgoing_frame(&inner) {
        let (frame_type, payload) = match mux::encode_frame(&frame) {
            Ok(encoded) => encoded,
            Err(error) => {
                inner.fail(format!("failed to encode mux frame: {error}"));
                return;
            }
        };

        if let Err(error) = frame::write_frame(&mut writer, frame_type, &payload) {
            inner.fail(format!(
                "failed to write Windows mux physical control stream: {error}"
            ));
            return;
        }
    }
}

fn next_outgoing_frame(inner: &MuxManagerInner) -> Option<MuxFrame> {
    let mut state = inner.state.lock().expect("Windows mux state lock poisoned");
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

        state = inner
            .cv
            .wait(state)
            .expect("Windows mux state lock poisoned");
    }
}

fn handle_incoming_frame(inner: &MuxManagerInner, frame: MuxFrame) -> Result<(), String> {
    match frame {
        MuxFrame::Open {
            session_id,
            metadata: _,
        } => {
            mux::validate_guest_session_id(session_id).map_err(|error| error.to_string())?;
            let mut state = inner.state.lock().expect("Windows mux state lock poisoned");
            if state.control_queue.len() >= MAX_CONTROL_QUEUE_FRAMES {
                return Err(format!(
                    "mux control queue was full while rejecting guest-opened session {session_id}"
                ));
            }
            state.control_queue.push_back(MuxFrame::OpenErr {
                session_id,
                reason: "guest-opened sessions are not accepted by the Windows host mux manager"
                    .to_string(),
            });
            inner.cv.notify_all();
            Ok(())
        }
        MuxFrame::OpenOk {
            session_id,
            initial_credit,
        } => {
            mux::validate_host_session_id(session_id).map_err(|error| error.to_string())?;
            let mut state = inner.state.lock().expect("Windows mux state lock poisoned");
            let session = state
                .sessions
                .get_mut(&session_id)
                .ok_or_else(|| format!("guest acknowledged unknown mux session {session_id}"))?;
            if session.open_state != SessionOpenState::Opening {
                return Err(format!(
                    "guest acknowledged mux session {session_id} after it was already open"
                ));
            }
            session.open_state = SessionOpenState::Open;
            session.send_credit = session
                .send_credit
                .checked_add(initial_credit as usize)
                .ok_or_else(|| format!("mux session {session_id} send credit overflow"))?;
            if state.control_queue.len() >= MAX_CONTROL_QUEUE_FRAMES {
                return Err(format!(
                    "mux control queue was full while granting initial receive credit for session {session_id}"
                ));
            }
            state.control_queue.push_back(MuxFrame::Window {
                session_id,
                credit: SESSION_RECEIVE_QUEUE_BYTES as u32,
            });
            inner.cv.notify_all();
            Ok(())
        }
        MuxFrame::OpenErr { session_id, reason } => {
            mux::validate_host_session_id(session_id).map_err(|error| error.to_string())?;
            let mut state = inner.state.lock().expect("Windows mux state lock poisoned");
            let session = state.sessions.get_mut(&session_id).ok_or_else(|| {
                format!("guest rejected unknown mux session {session_id}: {reason}")
            })?;
            session.open_state = SessionOpenState::Rejected(reason);
            inner.cv.notify_all();
            Ok(())
        }
        MuxFrame::Data { session_id, bytes } => {
            mux::validate_host_session_id(session_id).map_err(|error| error.to_string())?;
            let mut state = inner.state.lock().expect("Windows mux state lock poisoned");
            let session = state.sessions.get_mut(&session_id).ok_or_else(|| {
                format!(
                    "guest sent {} bytes for unknown mux session {session_id}",
                    bytes.len()
                )
            })?;
            if session.open_state != SessionOpenState::Open {
                return Err(format!(
                    "guest sent data for mux session {session_id} before it was open"
                ));
            }
            let available = SESSION_RECEIVE_QUEUE_BYTES.saturating_sub(session.inbound.len());
            if bytes.len() > available {
                return Err(format!(
                    "guest exceeded mux receive credit for session {session_id}: {} bytes with {available} bytes available",
                    bytes.len()
                ));
            }
            session.inbound.extend(bytes);
            inner.cv.notify_all();
            Ok(())
        }
        MuxFrame::Window { session_id, credit } => {
            mux::validate_host_session_id(session_id).map_err(|error| error.to_string())?;
            let mut state = inner.state.lock().expect("Windows mux state lock poisoned");
            let session = state.sessions.get_mut(&session_id).ok_or_else(|| {
                format!("guest granted credit for unknown mux session {session_id}")
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
            let mut state = inner.state.lock().expect("Windows mux state lock poisoned");
            let session = state
                .sessions
                .get_mut(&session_id)
                .ok_or_else(|| format!("guest closed unknown mux session {session_id}"))?;
            session.remote_fin = true;
            inner.cv.notify_all();
            Ok(())
        }
        MuxFrame::Rst { session_id, reason } => {
            mux::validate_host_session_id(session_id).map_err(|error| error.to_string())?;
            let mut state = inner.state.lock().expect("Windows mux state lock poisoned");
            let session = state
                .sessions
                .get_mut(&session_id)
                .ok_or_else(|| format!("guest reset unknown mux session {session_id}: {reason}"))?;
            session.reset_reason = Some(reason);
            inner.cv.notify_all();
            Ok(())
        }
    }
}

fn wait_for_control_queue_capacity<'a>(
    inner: &'a MuxManagerInner,
    mut state: std::sync::MutexGuard<'a, MuxManagerState>,
) -> io::Result<std::sync::MutexGuard<'a, MuxManagerState>> {
    while state.control_queue.len() >= MAX_CONTROL_QUEUE_FRAMES {
        if let Some(reason) = state.failed.clone() {
            return Err(broken_pipe(reason));
        }
        state = inner.cv.wait(state).map_err(|_| poisoned_lock())?;
    }
    Ok(state)
}

fn poisoned_lock() -> io::Error {
    io::Error::other("Windows mux state lock poisoned")
}

fn broken_pipe(reason: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, reason.into())
}

fn connection_reset(reason: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionReset, reason.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::{self, Receiver, SyncSender};
    use std::time::{Duration, Instant};

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
        let (frame_type, payload) = mux::encode_frame(&mux_frame).expect("mux frame should encode");
        frame::write_frame(writer, frame_type, &payload).expect("mux frame should write");
    }

    fn read_until_open(reader: &mut impl Read, kind: MuxSessionKind) -> u64 {
        loop {
            match read_mux(reader) {
                MuxFrame::Open {
                    session_id,
                    metadata,
                } => {
                    assert_eq!(metadata, kind.metadata());
                    return session_id;
                }
                MuxFrame::Window { .. } => {}
                frame => panic!("unexpected mux frame while waiting for open: {frame:?}"),
            }
        }
    }

    fn accept_open(
        reader: &mut impl Read,
        writer: &mut impl Write,
        kind: MuxSessionKind,
        credit: u32,
    ) -> u64 {
        let session_id = read_until_open(reader, kind);
        write_mux(
            writer,
            MuxFrame::OpenOk {
                session_id,
                initial_credit: credit,
            },
        );
        session_id
    }

    #[test]
    fn mux_sessions_exchange_framed_bytes_without_cross_session_corruption() {
        let (host, mut peer) = channel_pair(512 * 1024);
        let manager = MuxManager::start_for_test(host.reader, host.writer);

        let open_one = {
            let manager = manager.clone();
            thread::spawn(move || manager.open_session(MuxSessionKind::Exec).unwrap())
        };
        let session_one_id = accept_open(
            &mut peer.reader,
            &mut peer.writer,
            MuxSessionKind::Exec,
            1024,
        );
        let mut session_one = open_one.join().expect("open session thread should finish");

        let open_two = {
            let manager = manager.clone();
            thread::spawn(move || manager.open_session(MuxSessionKind::Watch).unwrap())
        };
        let session_two_id = accept_open(
            &mut peer.reader,
            &mut peer.writer,
            MuxSessionKind::Watch,
            1024,
        );
        let mut session_two = open_two.join().expect("open session thread should finish");

        assert_ne!(session_one_id, session_two_id);
        assert_eq!(session_one.session_id(), session_one_id);
        assert_eq!(session_two.session_id(), session_two_id);

        session_one.write_all(b"alpha").unwrap();
        session_two.write_all(b"bravo").unwrap();

        let mut delivered = HashMap::new();
        while delivered.len() < 2 {
            match read_mux(&mut peer.reader) {
                MuxFrame::Data { session_id, bytes } => {
                    delivered.insert(session_id, bytes);
                }
                MuxFrame::Window { .. } => {}
                frame => panic!("unexpected mux frame while waiting for data: {frame:?}"),
            }
        }

        assert_eq!(delivered.remove(&session_one_id), Some(b"alpha".to_vec()));
        assert_eq!(delivered.remove(&session_two_id), Some(b"bravo".to_vec()));

        write_mux(
            &mut peer.writer,
            MuxFrame::Data {
                session_id: session_two_id,
                bytes: b"guest-two".to_vec(),
            },
        );
        write_mux(
            &mut peer.writer,
            MuxFrame::Data {
                session_id: session_one_id,
                bytes: b"guest-one".to_vec(),
            },
        );
        write_mux(
            &mut peer.writer,
            MuxFrame::Fin {
                session_id: session_one_id,
            },
        );
        write_mux(
            &mut peer.writer,
            MuxFrame::Fin {
                session_id: session_two_id,
            },
        );

        let mut first = vec![0; "guest-one".len()];
        let mut second = vec![0; "guest-two".len()];
        session_one.read_exact(&mut first).unwrap();
        session_two.read_exact(&mut second).unwrap();

        assert_eq!(first, b"guest-one");
        assert_eq!(second, b"guest-two");
    }

    #[test]
    fn exhausted_session_credit_does_not_block_another_session() {
        let (host, mut peer) = channel_pair(512 * 1024);
        let manager = MuxManager::start_for_test(host.reader, host.writer);

        let open_one = {
            let manager = manager.clone();
            thread::spawn(move || manager.open_session(MuxSessionKind::Exec).unwrap())
        };
        let session_one_id =
            accept_open(&mut peer.reader, &mut peer.writer, MuxSessionKind::Exec, 1);
        let mut session_one = open_one.join().expect("open session thread should finish");

        let open_two = {
            let manager = manager.clone();
            thread::spawn(move || manager.open_session(MuxSessionKind::Watch).unwrap())
        };
        let session_two_id = accept_open(
            &mut peer.reader,
            &mut peer.writer,
            MuxSessionKind::Watch,
            1024,
        );
        let mut session_two = open_two.join().expect("open session thread should finish");

        let stalled_writer = thread::spawn(move || {
            session_one.write_all(&vec![b'x'; 1024]).unwrap();
        });

        let mut saw_first_byte = false;
        while !saw_first_byte {
            match read_mux(&mut peer.reader) {
                MuxFrame::Data { session_id, bytes } if session_id == session_one_id => {
                    assert_eq!(bytes, b"x");
                    saw_first_byte = true;
                }
                MuxFrame::Window { .. } => {}
                frame => panic!("unexpected mux frame before stalled data: {frame:?}"),
            }
        }

        session_two.write_all(b"ok").unwrap();
        loop {
            match read_mux(&mut peer.reader) {
                MuxFrame::Data { session_id, bytes } if session_id == session_two_id => {
                    assert_eq!(bytes, b"ok");
                    break;
                }
                MuxFrame::Window { .. } => {}
                frame => panic!("unexpected mux frame while waiting for second session: {frame:?}"),
            }
        }

        write_mux(
            &mut peer.writer,
            MuxFrame::Window {
                session_id: session_one_id,
                credit: 2048,
            },
        );
        let mut remaining = 1023usize;
        while remaining > 0 {
            match read_mux(&mut peer.reader) {
                MuxFrame::Data { session_id, bytes } if session_id == session_one_id => {
                    remaining -= bytes.len();
                }
                MuxFrame::Window { .. } => {}
                frame => panic!("unexpected mux frame while draining stalled session: {frame:?}"),
            }
        }

        stalled_writer
            .join()
            .expect("stalled writer should finish after credit");
    }

    #[test]
    fn inbound_reads_replenish_window_credit() {
        let (host, mut peer) = channel_pair(512 * 1024);
        let manager = MuxManager::start_for_test(host.reader, host.writer);

        let open = {
            let manager = manager.clone();
            thread::spawn(move || manager.open_session(MuxSessionKind::File).unwrap())
        };
        let session_id = accept_open(
            &mut peer.reader,
            &mut peer.writer,
            MuxSessionKind::File,
            1024,
        );
        let mut session = open.join().expect("open session thread should finish");

        loop {
            match read_mux(&mut peer.reader) {
                MuxFrame::Window {
                    session_id: window_session,
                    credit,
                } if window_session == session_id => {
                    assert_eq!(credit, SESSION_RECEIVE_QUEUE_BYTES as u32);
                    break;
                }
                frame => panic!("unexpected mux frame while waiting for initial window: {frame:?}"),
            }
        }

        write_mux(
            &mut peer.writer,
            MuxFrame::Data {
                session_id,
                bytes: b"hello".to_vec(),
            },
        );
        let mut buf = [0u8; 5];
        session.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hello");

        loop {
            match read_mux(&mut peer.reader) {
                MuxFrame::Window {
                    session_id: window_session,
                    credit,
                } if window_session == session_id => {
                    assert_eq!(credit, 5);
                    break;
                }
                frame => panic!("unexpected mux frame while waiting for read window: {frame:?}"),
            }
        }
    }

    #[test]
    fn protocol_violation_fails_open_sessions() {
        let (host, mut peer) = channel_pair(512 * 1024);
        let manager = MuxManager::start_for_test(host.reader, host.writer);

        let open = {
            let manager = manager.clone();
            thread::spawn(move || manager.open_session(MuxSessionKind::Exec).unwrap())
        };
        let session_id = accept_open(
            &mut peer.reader,
            &mut peer.writer,
            MuxSessionKind::Exec,
            1024,
        );
        let mut session = open.join().expect("open session thread should finish");

        write_mux(
            &mut peer.writer,
            MuxFrame::Window {
                session_id: session_id + 2,
                credit: 1,
            },
        );

        let deadline = Instant::now() + Duration::from_secs(1);
        let err = loop {
            match session.write(b"x") {
                Ok(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                Ok(written) => panic!("mux should fail after violation, wrote {written} bytes"),
                Err(error) => break error,
            }
        };
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);

        let _ = peer.reader.rx.recv_timeout(Duration::from_millis(10));
    }
}
