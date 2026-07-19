use std::collections::HashMap;
use std::ffi::c_void;
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use lsb_service_proto::frame::HEADER_VERSION;
use lsb_service_proto::limits::{HEADER_LEN, MAX_STREAM_PAYLOAD, STREAM_SEQUENCE_LEN};
use lsb_service_proto::{
    encode_stream_payload, negotiate, parse_control, Cancel, CapabilityHealth, Correlation,
    ErrorCode, ErrorEnvelope, Event, FrameHeader, FrameKind, Health, HealthState, Hello,
    HelloReply, HexU64, ProtocolRange, Request, RequestOp, Response, ResponseValue, ServiceInfo,
    WindowUpdate, CLIENT_FEATURE_BITS, CURRENT, SUPPORTED,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};
use windows_sys::Win32::Foundation::{WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::Threading::WaitForSingleObject;
use zeroize::Zeroize;

use crate::ipc::connection::{
    ConnectionState, RateLimiter, RequestDeadline, DEFAULT_BOOT_DEADLINE,
    DEFAULT_TRANSFER_DEADLINE, DEFAULT_UNARY_DEADLINE, MAX_REQUEST_DEADLINE,
};
use crate::maintenance::MaintenanceManager;
use crate::resource::process::{GuestProcessResource, ManagedProcessOutput};
use crate::resource::watch::WatchResource;
use crate::security::client_image::authorize_maintenance_image;
use crate::security::descriptor::SecurityDescriptor;
use crate::security::ClientIdentity;
use crate::session::{
    CancellationToken, ClientIdentityKey, QuotaLimits, ResourceHandle, SessionManager,
};
use crate::{engine::ServiceEngineConfig, rpc};
use crate::{LEDGER_SCHEMA_VERSION, PIPE_NAME, PIPE_SDDL};

const OUTPUT_BACKPRESSURE_TIMEOUT: Duration = Duration::from_secs(30);
const SERVICE_FEATURE_BITS: u64 = CLIENT_FEATURE_BITS;
#[cfg(test)]
static TEST_HEALTH_DELAY_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

struct OutboundFrame {
    bytes: Vec<u8>,
    _permit: OwnedSemaphorePermit,
}

#[derive(Clone)]
struct OutboundWriter {
    frames: mpsc::Sender<OutboundFrame>,
    bytes: Arc<Semaphore>,
}

impl OutboundWriter {
    fn start<W>(mut pipe: W) -> (Self, tokio::task::JoinHandle<Result<()>>)
    where
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let (frames, mut receiver) = mpsc::channel(crate::ipc::writer::MAX_WRITER_FRAMES);
        let writer = Self {
            frames,
            bytes: Arc::new(Semaphore::new(crate::ipc::writer::MAX_WRITER_BYTES)),
        };
        let task = tokio::spawn(async move {
            while let Some(frame) = receiver.recv().await {
                pipe.write_all(&frame.bytes).await?;
                pipe.flush().await?;
            }
            Ok(())
        });
        (writer, task)
    }

    async fn send(&self, bytes: Vec<u8>) -> Result<()> {
        let length = u32::try_from(bytes.len()).context("outbound frame length overflow")?;
        let permit = tokio::time::timeout(
            Duration::from_secs(5),
            self.bytes.clone().acquire_many_owned(length),
        )
        .await
        .context("outbound writer byte quota deadline exceeded")?
        .context("outbound writer closed")?;
        tokio::time::timeout(
            Duration::from_secs(5),
            self.frames.send(OutboundFrame {
                bytes,
                _permit: permit,
            }),
        )
        .await
        .context("outbound writer frame quota deadline exceeded")?
        .map_err(|_| anyhow::anyhow!("outbound writer closed"))
    }
}

#[derive(Clone)]
struct EventSequence {
    epoch: u64,
    next: Arc<tokio::sync::Mutex<u64>>,
}

impl EventSequence {
    fn new(epoch: u64) -> Self {
        Self {
            epoch,
            next: Arc::new(tokio::sync::Mutex::new(1)),
        }
    }

    async fn write(
        &self,
        writer: &OutboundWriter,
        protocol: lsb_service_proto::ProtocolVersion,
        event: &Event,
    ) -> Result<()> {
        self.write_value(writer, FrameKind::Event, protocol, event)
            .await
    }

    async fn write_value(
        &self,
        writer: &OutboundWriter,
        kind: FrameKind,
        protocol: lsb_service_proto::ProtocolVersion,
        value: &impl serde::Serialize,
    ) -> Result<()> {
        let mut sequence = self.next.lock().await;
        if *sequence == 0 || *sequence == u64::MAX {
            bail!("server event sequence exhausted");
        }
        write_control(
            writer,
            kind,
            protocol,
            Correlation {
                high: self.epoch,
                low: *sequence,
            },
            value,
        )
        .await?;
        *sequence = sequence
            .checked_add(1)
            .context("server event sequence exhausted")?;
        Ok(())
    }
}

#[derive(Clone)]
struct StreamCredit {
    credit: Arc<Semaphore>,
}

impl StreamCredit {
    fn initial() -> Self {
        Self {
            credit: Arc::new(Semaphore::new(
                lsb_service_proto::limits::INITIAL_STREAM_CREDIT,
            )),
        }
    }

    fn grant(&self, bytes: u32) -> Result<()> {
        let bytes = bytes as usize;
        if self.credit.available_permits().saturating_add(bytes) > 4 * 1024 * 1024 {
            bail!("stream credit exceeds maximum window");
        }
        self.credit.add_permits(bytes);
        Ok(())
    }

    async fn consume(&self, bytes: usize) -> Result<()> {
        let bytes = u32::try_from(bytes).context("stream chunk length overflow")?;
        let permit = tokio::time::timeout(
            OUTPUT_BACKPRESSURE_TIMEOUT,
            self.credit.clone().acquire_many_owned(bytes),
        )
        .await
        .context("stream output backpressure timeout")?
        .context("stream credit closed")?;
        permit.forget();
        Ok(())
    }
}

#[derive(Clone, Default)]
struct StreamRegistry {
    streams: Arc<Mutex<HashMap<String, StreamCredit>>>,
}

impl StreamRegistry {
    fn register(&self, stream_id: String) -> Result<StreamCredit> {
        let credit = StreamCredit::initial();
        let mut streams = self
            .streams
            .lock()
            .map_err(|_| anyhow::anyhow!("stream registry poisoned"))?;
        if streams.insert(stream_id, credit.clone()).is_some() {
            bail!("duplicate stream id");
        }
        Ok(credit)
    }

    fn grant(&self, update: &WindowUpdate) -> Result<()> {
        let streams = self
            .streams
            .lock()
            .map_err(|_| anyhow::anyhow!("stream registry poisoned"))?;
        match streams.get(&update.stream_id) {
            Some(stream) => stream.grant(update.credit_bytes),
            None => Ok(()),
        }
    }

    fn remove(&self, stream_id: &str) {
        if let Ok(mut streams) = self.streams.lock() {
            streams.remove(stream_id);
        }
    }
}

struct FrameReader {
    frames: mpsc::Receiver<Result<WireFrame>>,
    task: tokio::task::JoinHandle<()>,
}

impl FrameReader {
    fn start<R>(mut pipe: R) -> Self
    where
        R: AsyncRead + Unpin + Send + 'static,
    {
        let (sender, frames) = mpsc::channel(crate::ipc::pipe::MAX_DISPATCH_FRAMES);
        let task = tokio::spawn(async move {
            loop {
                let frame = read_frame(&mut pipe).await;
                let failed = frame.is_err();
                if sender.send(frame).await.is_err() || failed {
                    break;
                }
            }
        });
        Self { frames, task }
    }

    async fn recv(&mut self) -> Result<WireFrame> {
        self.frames
            .recv()
            .await
            .context("authenticated pipe reader stopped")?
    }
}

impl Drop for FrameReader {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct UploadBuffer {
    correlation: Correlation,
    length: usize,
    bytes: Vec<u8>,
    expected_sequence: u64,
    remaining_credit: usize,
}

impl UploadBuffer {
    fn new(stream_id: &str, length: u32) -> Result<Self> {
        Ok(Self {
            correlation: stream_correlation(stream_id)?,
            length: length as usize,
            bytes: Vec::new(),
            expected_sequence: 0,
            remaining_credit: lsb_service_proto::limits::INITIAL_STREAM_CREDIT,
        })
    }

    fn push(
        &mut self,
        frame: WireFrame,
        protocol: lsb_service_proto::ProtocolVersion,
    ) -> Result<()> {
        if frame.header.kind != FrameKind::StreamData
            || frame.header.protocol != protocol
            || frame.header.correlation != self.correlation
        {
            bail!("write stream correlation/version mismatch");
        }
        let (sequence, chunk) = lsb_service_proto::decode_stream_payload(&frame.payload)?;
        if sequence != self.expected_sequence
            || chunk.is_empty()
            || self.bytes.len().saturating_add(chunk.len()) > self.length
            || chunk.len() > self.remaining_credit
        {
            bail!("write stream sequence/length mismatch");
        }
        self.expected_sequence = self
            .expected_sequence
            .checked_add(1)
            .context("write stream sequence exhausted")?;
        self.bytes.extend_from_slice(chunk);
        self.remaining_credit -= chunk.len();
        Ok(())
    }

    fn is_complete(&self) -> bool {
        self.bytes.len() == self.length
    }

    fn replenish(&mut self, bytes: usize) -> Result<()> {
        self.remaining_credit = self
            .remaining_credit
            .checked_add(bytes)
            .context("write stream credit overflow")?;
        Ok(())
    }
}

struct PendingUpload {
    request: Request,
    request_correlation: Correlation,
    cancellation: CancellationToken,
    deadline: RequestDeadline,
    request_permit: OwnedSemaphorePermit,
    stream_id: String,
    buffer: UploadBuffer,
}

#[derive(Clone)]
pub struct HealthContext {
    admissions_open: Arc<AtomicBool>,
    whpx: HealthState,
    sessions: SessionManager,
    engine: Option<ServiceEngineConfig>,
    requests: Arc<Semaphore>,
    maintenance: Option<MaintenanceManager>,
    client_roots: Vec<String>,
    maintenance_roots: Vec<String>,
    publisher_thumbprints: Vec<String>,
    protected_egress_allow: Vec<String>,
}

impl HealthContext {
    pub fn new(admissions_open: bool, quota_limits: QuotaLimits) -> Self {
        Self {
            admissions_open: Arc::new(AtomicBool::new(admissions_open)),
            whpx: HealthState::Unknown,
            sessions: SessionManager::new(quota_limits),
            engine: None,
            requests: Arc::new(Semaphore::new(crate::ipc::pipe::MAX_REQUESTS_GLOBAL)),
            maintenance: None,
            client_roots: Vec::new(),
            maintenance_roots: Vec::new(),
            publisher_thumbprints: Vec::new(),
            protected_egress_allow: Vec::new(),
        }
    }

    pub fn with_engine(mut self, engine: Option<ServiceEngineConfig>) -> Self {
        self.engine = engine;
        self
    }

    pub fn with_whpx(mut self, whpx: HealthState) -> Self {
        self.whpx = whpx;
        self
    }

    pub fn with_client_policy(
        mut self,
        maintenance: MaintenanceManager,
        client_roots: Vec<String>,
        maintenance_roots: Vec<String>,
        publisher_thumbprints: Vec<String>,
        protected_egress_allow: Vec<String>,
    ) -> Self {
        self.admissions_open = maintenance.admissions();
        self.maintenance = Some(maintenance);
        self.client_roots = client_roots;
        self.maintenance_roots = maintenance_roots;
        self.publisher_thumbprints = publisher_thumbprints;
        self.protected_egress_allow = protected_egress_allow;
        self
    }

    fn admissions_open(&self) -> bool {
        self.admissions_open.load(Ordering::Acquire)
            && self.engine.is_some()
            && self.whpx == HealthState::Ready
            && !self.client_roots.is_empty()
            && !self.publisher_thumbprints.is_empty()
    }

    pub fn begin_shutdown(&self) -> Result<usize> {
        self.admissions_open.store(false, Ordering::Release);
        self.sessions.drain_all()
    }

    fn maintenance_authorized(&self, identity: &ClientIdentity) -> bool {
        identity.elevated
            && identity.administrator
            && authorize_maintenance_image(
                &identity.process_image,
                &self.maintenance_roots,
                &self.publisher_thumbprints,
            )
            .is_ok()
    }

    fn client_authorized(&self, identity: &ClientIdentity) -> bool {
        authorize_maintenance_image(
            &identity.process_image,
            &self.client_roots,
            &self.publisher_thumbprints,
        )
        .is_ok()
    }

    fn health(&self) -> Health {
        Health {
            ready: self.admissions_open(),
            admissions_open: self.admissions_open(),
            stable_code: if self.client_roots.is_empty() || self.publisher_thumbprints.is_empty() {
                "CLIENT_POLICY_INVALID"
            } else if self.engine.is_none() {
                "BUNDLE_INVALID"
            } else if self.whpx != HealthState::Ready {
                "WHPX_UNAVAILABLE"
            } else if self.admissions_open() {
                "READY"
            } else if let Some(maintenance) = &self.maintenance {
                maintenance.stable_code()
            } else {
                "HEALTH_ONLY_QUARANTINE"
            }
            .to_string(),
            whpx: self.whpx.clone(),
            smb: HealthState::Unknown,
            wfp: HealthState::Unavailable,
            bundle: if self.engine.is_some() {
                HealthState::Ready
            } else {
                HealthState::Unavailable
            },
        }
    }

    fn capabilities(&self) -> CapabilityHealth {
        CapabilityHealth {
            direct_mount: false,
            direct_mount_backends: Vec::new(),
            watch: self.engine.is_some(),
            ports: false,
        }
    }

    fn service_info(&self) -> ServiceInfo {
        ServiceInfo {
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            bundle_version: self
                .engine
                .as_ref()
                .map(|engine| engine.bundle_version().to_string())
                .unwrap_or_else(|| "unavailable".to_string()),
            protocol: SUPPORTED,
            ledger_schema: ProtocolRange {
                major: LEDGER_SCHEMA_VERSION as u16,
                min_minor: 0,
                max_minor: 0,
            },
            feature_bits_hex: HexU64(SERVICE_FEATURE_BITS),
            capabilities: self.capabilities(),
        }
    }
}

pub struct HealthPipe {
    server: NamedPipeServer,
    context: HealthContext,
    preauth: PreAuthGate,
}

#[derive(Clone)]
struct PreAuthGate {
    global: Arc<Semaphore>,
    by_pid: Arc<Mutex<HashMap<u32, usize>>>,
    accepts: Arc<Mutex<RateLimiter>>,
}

struct PreAuthPidPermit {
    by_pid: Arc<Mutex<HashMap<u32, usize>>>,
    process_id: u32,
}

struct PreAuthAdmission {
    _global: OwnedSemaphorePermit,
    _pid: PreAuthPidPermit,
}

#[derive(Clone, Copy)]
struct ConnectionAuthorization {
    client: bool,
    maintenance: bool,
}

impl PreAuthGate {
    fn new() -> Self {
        Self {
            global: Arc::new(Semaphore::new(crate::ipc::pipe::MAX_UNAUTHENTICATED_GLOBAL)),
            by_pid: Arc::new(Mutex::new(HashMap::new())),
            accepts: Arc::new(Mutex::new(RateLimiter::new(
                crate::ipc::pipe::ACCEPTS_PER_SECOND,
                crate::ipc::pipe::ACCEPT_BURST,
                Instant::now(),
            ))),
        }
    }

    fn admit_accept(&self, now: Instant) -> Result<()> {
        if !self
            .accepts
            .lock()
            .map_err(|_| anyhow::anyhow!("accept rate limiter poisoned"))?
            .try_acquire(now)
        {
            bail!("pipe accept rate exceeded");
        }
        Ok(())
    }

    fn try_global(&self) -> Result<OwnedSemaphorePermit> {
        self.global
            .clone()
            .try_acquire_owned()
            .context("global unauthenticated connection quota exceeded")
    }

    fn admit_pid(&self, process_id: u32, global: OwnedSemaphorePermit) -> Result<PreAuthAdmission> {
        let mut by_pid = self
            .by_pid
            .lock()
            .map_err(|_| anyhow::anyhow!("pre-auth PID quota poisoned"))?;
        let count = by_pid.entry(process_id).or_default();
        if *count >= crate::ipc::pipe::MAX_UNAUTHENTICATED_PER_PID {
            bail!("per-PID unauthenticated connection quota exceeded");
        }
        *count += 1;
        drop(by_pid);
        Ok(PreAuthAdmission {
            _global: global,
            _pid: PreAuthPidPermit {
                by_pid: self.by_pid.clone(),
                process_id,
            },
        })
    }
}

impl Drop for PreAuthPidPermit {
    fn drop(&mut self) {
        if let Ok(mut by_pid) = self.by_pid.lock() {
            if let Some(count) = by_pid.get_mut(&self.process_id) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    by_pid.remove(&self.process_id);
                }
            }
        }
    }
}

impl HealthPipe {
    pub fn bind(context: HealthContext) -> Result<Self> {
        Ok(Self {
            server: create_server(true)?,
            context,
            preauth: PreAuthGate::new(),
        })
    }

    pub async fn run(mut self, mut shutdown: oneshot::Receiver<()>) -> Result<()> {
        loop {
            tokio::select! {
                _ = &mut shutdown => return Ok(()),
                connected = self.server.connect() => connected.context("accept health pipe client")?,
            }
            let connected = self.server;
            self.server = create_server(false)?;
            if self.preauth.admit_accept(Instant::now()).is_err() {
                continue;
            }
            let global = match self.preauth.try_global() {
                Ok(permit) => permit,
                Err(_) => continue,
            };
            let context = self.context.clone();
            let preauth = self.preauth.clone();
            tokio::spawn(async move {
                let _ = handle_client(connected, context, preauth, global).await;
            });
        }
    }
}

fn create_server(first: bool) -> Result<NamedPipeServer> {
    let descriptor = SecurityDescriptor::from_sddl(PIPE_SDDL)?;
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.as_ptr(),
        bInheritHandle: 0,
    };
    let mut options = ServerOptions::new();
    options
        .pipe_mode(PipeMode::Byte)
        .first_pipe_instance(first)
        .reject_remote_clients(true)
        .max_instances(32)
        .in_buffer_size(64 * 1024)
        .out_buffer_size(64 * 1024);
    let server = unsafe {
        options.create_with_security_attributes_raw(
            PIPE_NAME,
            (&mut attributes as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
        )
    }
    .context("create health-only named pipe with explicit security descriptor")?;
    Ok(server)
}

async fn handle_client(
    pipe: NamedPipeServer,
    context: HealthContext,
    preauth: PreAuthGate,
    global: OwnedSemaphorePermit,
) -> Result<()> {
    let identity = ClientIdentity::from_named_pipe(pipe.as_raw_handle())?;
    let preauth = preauth.admit_pid(identity.process_id, global)?;
    let authorization = ConnectionAuthorization {
        client: context.client_authorized(&identity),
        maintenance: context.maintenance_authorized(&identity),
    };
    if !authorization.client && !authorization.maintenance {
        bail!("client image is not authorized by a protected publisher policy");
    }
    let process = identity.duplicate_process_handle()?;
    let session_id = context.sessions.open(identity.key.clone())?;
    let (reader, pipe_writer) = tokio::io::split(pipe);
    let (writer, writer_task) = OutboundWriter::start(pipe_writer);
    let result = handle_authenticated_client(
        reader,
        &writer,
        &context,
        session_id,
        &identity.key,
        authorization,
        Some(preauth),
        Some(process),
    )
    .await;
    let _ = context.sessions.close(session_id, &identity.key);
    drop(writer);
    let writer_result = tokio::time::timeout(Duration::from_secs(5), writer_task).await;
    result?;
    match writer_result {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => Err(anyhow::anyhow!("outbound writer task failed: {error}")),
        Err(_) => Err(anyhow::anyhow!("outbound writer drain deadline exceeded")),
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_authenticated_client<R>(
    mut pipe: R,
    writer: &OutboundWriter,
    context: &HealthContext,
    session_id: ResourceHandle,
    identity: &ClientIdentityKey,
    authorization: ConnectionAuthorization,
    preauth: Option<PreAuthAdmission>,
    process: Option<OwnedHandle>,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let process_exit = wait_for_process_exit(process);
    tokio::pin!(process_exit);
    let hello_frame = tokio::select! {
        exited = &mut process_exit => {
            exited?;
            return Ok(());
        }
        frame = tokio::time::timeout(crate::ipc::pipe::HELLO_TIMEOUT, read_frame(&mut pipe)) => {
            frame.context("Hello deadline exceeded")??
        }
    };
    if hello_frame.header.kind != FrameKind::Hello
        || hello_frame.header.correlation != Correlation::default()
        || hello_frame.header.protocol.major != CURRENT.major
    {
        bail!("first frame is not a valid Hello");
    }
    let hello: Hello = parse_control(&hello_frame.payload)?;
    hello.validate()?;
    let selected = negotiate(SUPPORTED, hello.range(hello_frame.header.protocol.major))?;
    let selected_feature_bits = hello.feature_bits_hex.0 & SERVICE_FEATURE_BITS;
    let epoch = random_epoch()?;
    let events = EventSequence::new(epoch);
    let streams = StreamRegistry::default();
    let reply = HelloReply {
        selected_minor: selected.minor,
        connection_epoch_hex: HexU64(epoch),
        service_version: env!("CARGO_PKG_VERSION").to_string(),
        bundle_version: env!("CARGO_PKG_VERSION").to_string(),
        ledger_schema: context.service_info().ledger_schema,
        selected_feature_bits_hex: HexU64(selected_feature_bits),
        health: context.health(),
    };
    write_control(
        writer,
        FrameKind::Hello,
        selected,
        Correlation {
            high: epoch,
            low: 0,
        },
        &reply,
    )
    .await?;
    drop(preauth);

    let connection = Arc::new(Mutex::new(ConnectionState::new(epoch)?));
    let mut reader = FrameReader::start(pipe);
    let mut pending_upload: Option<PendingUpload> = None;
    loop {
        let upload_timeout = pending_upload
            .as_ref()
            .map(|upload| upload.deadline.remaining(Instant::now()))
            .unwrap_or(MAX_REQUEST_DEADLINE);
        let mut frame = match tokio::select! {
            biased;
            exited = &mut process_exit => {
                exited?;
                if let Ok(state) = connection.lock() {
                    state.cancel_all();
                }
                return Ok(());
            }
            _ = tokio::time::sleep(upload_timeout), if pending_upload.is_some() => {
                let upload = pending_upload.take().context("pending upload disappeared")?;
                upload.cancellation.cancel();
                connection
                    .lock()
                    .map_err(|_| anyhow::anyhow!("connection state poisoned"))?
                    .finish(upload.request_correlation.low);
                write_error(
                    writer,
                    selected,
                    upload.request_correlation,
                    ErrorCode::DeadlineExceeded,
                )
                .await?;
                continue;
            }
            frame = reader.recv() => frame,
        } {
            Ok(frame) => frame,
            Err(_) => {
                if let Ok(state) = connection.lock() {
                    state.cancel_all();
                }
                return Ok(());
            }
        };
        if frame.header.protocol != selected
            || !matches!(
                frame.header.kind,
                FrameKind::Request
                    | FrameKind::StreamData
                    | FrameKind::WindowUpdate
                    | FrameKind::Cancel
            )
        {
            bail!("invalid health request direction, version, or sequence");
        }
        if frame.header.kind == FrameKind::StreamData {
            let upload = pending_upload
                .as_mut()
                .context("stream data has no pending upload")?;
            let previous_length = upload.buffer.bytes.len();
            if upload.buffer.push(frame, selected).is_err() {
                let upload = pending_upload
                    .take()
                    .context("pending upload disappeared")?;
                connection
                    .lock()
                    .map_err(|_| anyhow::anyhow!("connection state poisoned"))?
                    .finish(upload.request_correlation.low);
                write_error(
                    writer,
                    selected,
                    upload.request_correlation,
                    ErrorCode::ProtocolError,
                )
                .await?;
                return Ok(());
            }
            let consumed = upload.buffer.bytes.len() - previous_length;
            if !upload.buffer.is_complete() {
                let credit_bytes = u32::try_from(consumed)?;
                events
                    .write_value(
                        writer,
                        FrameKind::WindowUpdate,
                        selected,
                        &WindowUpdate {
                            stream_id: upload.stream_id.clone(),
                            credit_bytes,
                        },
                    )
                    .await?;
                upload.buffer.replenish(consumed)?;
                continue;
            }
            let upload = pending_upload
                .take()
                .context("pending upload disappeared")?;
            tokio::spawn(run_request(
                upload.request,
                Some(upload.buffer.bytes),
                upload.request_correlation,
                selected,
                writer.clone(),
                context.clone(),
                session_id,
                identity.clone(),
                authorization.maintenance,
                events.clone(),
                streams.clone(),
                connection.clone(),
                upload.cancellation,
                upload.deadline,
                upload.request_permit,
            ));
            continue;
        }
        connection
            .lock()
            .map_err(|_| anyhow::anyhow!("connection state poisoned"))?
            .accept_sequence(frame.header.correlation.high, frame.header.correlation.low)?;
        if frame.header.kind == FrameKind::WindowUpdate {
            let update: WindowUpdate = parse_control(&frame.payload)?;
            update.validate()?;
            streams.grant(&update)?;
            continue;
        }
        if frame.header.kind == FrameKind::Cancel {
            let cancel: Cancel = parse_control(&frame.payload)?;
            cancel.validate()?;
            let target = stream_correlation(&cancel.request_id)?;
            let found = target.high == epoch
                && connection
                    .lock()
                    .map_err(|_| anyhow::anyhow!("connection state poisoned"))?
                    .cancel(target.low);
            if found {
                if pending_upload
                    .as_ref()
                    .is_some_and(|upload| upload.request_correlation == target)
                {
                    let upload = pending_upload
                        .take()
                        .context("pending upload disappeared")?;
                    connection
                        .lock()
                        .map_err(|_| anyhow::anyhow!("connection state poisoned"))?
                        .finish(target.low);
                    write_error(writer, selected, target, ErrorCode::Cancelled).await?;
                    drop(upload);
                }
                write_control(
                    writer,
                    FrameKind::Response,
                    selected,
                    frame.header.correlation,
                    &Response::Ok {
                        result: ResponseValue::Empty {},
                    },
                )
                .await?;
            } else {
                write_error(
                    writer,
                    selected,
                    frame.header.correlation,
                    ErrorCode::RequestNotActive,
                )
                .await?;
            }
            continue;
        }
        if connection
            .lock()
            .map_err(|_| anyhow::anyhow!("connection state poisoned"))?
            .admit_request(Instant::now())
            .is_err()
        {
            write_error(
                writer,
                selected,
                frame.header.correlation,
                ErrorCode::QuotaExceeded,
            )
            .await?;
            continue;
        }
        let parsed_request = parse_control(&frame.payload);
        frame.payload.zeroize();
        let request: Request = parsed_request?;
        if request.validate().is_err() {
            write_error(
                writer,
                selected,
                frame.header.correlation,
                ErrorCode::InvalidRequest,
            )
            .await?;
            continue;
        }
        if let RequestOp::StartSandbox {
            network: Some(network),
            ..
        } = &request.op
        {
            let required = network.required_feature_bits();
            if selected_feature_bits & required != required {
                write_error(
                    writer,
                    selected,
                    frame.header.correlation,
                    ErrorCode::IncompatibleProtocol,
                )
                .await?;
                continue;
            }
        }
        if matches!(request.op, RequestOp::CloseSession {}) {
            connection
                .lock()
                .map_err(|_| anyhow::anyhow!("connection state poisoned"))?
                .cancel_all();
            write_control(
                writer,
                FrameKind::Response,
                selected,
                frame.header.correlation,
                &Response::Ok {
                    result: ResponseValue::Empty {},
                },
            )
            .await?;
            return Ok(());
        }
        if !context.admissions_open() && !is_health_or_maintenance(&request.op) {
            write_error(
                writer,
                selected,
                frame.header.correlation,
                ErrorCode::ServiceDraining,
            )
            .await?;
            continue;
        }
        if !authorization.client && !is_health_or_maintenance(&request.op) {
            write_error(
                writer,
                selected,
                frame.header.correlation,
                ErrorCode::AccessDenied,
            )
            .await?;
            continue;
        }
        if matches!(request.op, RequestOp::WriteFile { .. }) && pending_upload.is_some() {
            write_error(
                writer,
                selected,
                frame.header.correlation,
                ErrorCode::QuotaExceeded,
            )
            .await?;
            continue;
        }
        let maximum = request_maximum(&request.op);
        let deadline = RequestDeadline::from_client(Instant::now(), request.deadline_ms, maximum);
        let request_permit = match context.requests.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                write_error(
                    writer,
                    selected,
                    frame.header.correlation,
                    ErrorCode::QuotaExceeded,
                )
                .await?;
                continue;
            }
        };
        let admission = {
            let mut state = connection
                .lock()
                .map_err(|_| anyhow::anyhow!("connection state poisoned"))?;
            state.begin_request(frame.header.correlation.low, deadline)
        };
        let cancellation = match admission {
            Ok(cancellation) => cancellation,
            Err(_) => {
                write_error(
                    writer,
                    selected,
                    frame.header.correlation,
                    ErrorCode::QuotaExceeded,
                )
                .await?;
                continue;
            }
        };
        let upload = match &request.op {
            RequestOp::WriteFile {
                stream_id, length, ..
            } => Some((stream_id.clone(), *length)),
            _ => None,
        };
        let write_bytes = if let Some((stream_id, length)) = upload {
            let buffer = UploadBuffer::new(&stream_id, length)?;
            if !buffer.is_complete() {
                pending_upload = Some(PendingUpload {
                    request,
                    request_correlation: frame.header.correlation,
                    cancellation,
                    deadline,
                    request_permit,
                    stream_id,
                    buffer,
                });
                continue;
            }
            Some(Vec::new())
        } else {
            None
        };
        tokio::spawn(run_request(
            request,
            write_bytes,
            frame.header.correlation,
            selected,
            writer.clone(),
            context.clone(),
            session_id,
            identity.clone(),
            authorization.maintenance,
            events.clone(),
            streams.clone(),
            connection.clone(),
            cancellation,
            deadline,
            request_permit,
        ));
    }
}

async fn wait_for_process_exit(process: Option<OwnedHandle>) -> Result<()> {
    let Some(process) = process else {
        return std::future::pending().await;
    };
    loop {
        match unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } {
            WAIT_OBJECT_0 => return Ok(()),
            WAIT_TIMEOUT => tokio::time::sleep(Duration::from_millis(100)).await,
            WAIT_FAILED => {
                bail!(
                    "WaitForSingleObject failed: {}",
                    std::io::Error::last_os_error()
                )
            }
            status => bail!("WaitForSingleObject returned unexpected status {status}"),
        }
    }
}

fn is_health_or_maintenance(op: &RequestOp) -> bool {
    matches!(
        op,
        RequestOp::GetServiceInfo {}
            | RequestOp::HealthCheck {}
            | RequestOp::PrepareUpdate { .. }
            | RequestOp::CommitUpdate { .. }
            | RequestOp::AbortUpdate { .. }
            | RequestOp::PrepareUninstall {}
    )
}

#[allow(clippy::too_many_arguments)]
async fn run_request(
    request: Request,
    write_bytes: Option<Vec<u8>>,
    correlation: Correlation,
    protocol: lsb_service_proto::ProtocolVersion,
    writer: OutboundWriter,
    context: HealthContext,
    session_id: ResourceHandle,
    identity: ClientIdentityKey,
    maintenance_authorized: bool,
    events: EventSequence,
    streams: StreamRegistry,
    connection: Arc<Mutex<ConnectionState>>,
    cancellation: CancellationToken,
    deadline: RequestDeadline,
    _request_permit: OwnedSemaphorePermit,
) {
    let operation = dispatch_request(
        request,
        write_bytes,
        correlation,
        protocol,
        writer.clone(),
        context,
        session_id,
        identity,
        maintenance_authorized,
        cancellation.clone(),
        events,
        streams,
    );
    tokio::pin!(operation);
    tokio::select! {
        biased;
        result = &mut operation => {
            if result.is_err() {
                let _ = write_error(&writer, protocol, correlation, ErrorCode::InternalError).await;
            }
        }
        _ = wait_cancelled(cancellation.clone()) => {
            let _ = write_error(&writer, protocol, correlation, ErrorCode::Cancelled).await;
        }
        _ = tokio::time::sleep(deadline.remaining(Instant::now())) => {
            cancellation.cancel();
            let _ = write_error(&writer, protocol, correlation, ErrorCode::DeadlineExceeded).await;
        }
    }
    if let Ok(mut state) = connection.lock() {
        state.finish(correlation.low);
    }
}

async fn wait_cancelled(cancellation: CancellationToken) {
    while !cancellation.is_cancelled() {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn request_maximum(op: &RequestOp) -> Duration {
    match op {
        RequestOp::StartSandbox { .. } => DEFAULT_BOOT_DEADLINE,
        RequestOp::ReadFile { .. } | RequestOp::WriteFile { .. } | RequestOp::Copy { .. } => {
            DEFAULT_TRANSFER_DEADLINE
        }
        _ => DEFAULT_UNARY_DEADLINE,
    }
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_request(
    request: Request,
    write_bytes: Option<Vec<u8>>,
    correlation: Correlation,
    protocol: lsb_service_proto::ProtocolVersion,
    writer: OutboundWriter,
    context: HealthContext,
    session_id: ResourceHandle,
    identity: ClientIdentityKey,
    maintenance_authorized: bool,
    request_cancellation: CancellationToken,
    events: EventSequence,
    streams: StreamRegistry,
) -> Result<()> {
    #[cfg(test)]
    if matches!(request.op, RequestOp::HealthCheck {}) {
        let delay = TEST_HEALTH_DELAY_MS.load(std::sync::atomic::Ordering::Acquire);
        if delay != 0 {
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
    }
    let deadline_ms = request.deadline_ms;
    macro_rules! rpc_value {
        ($future:expr) => {
            match $future.await {
                Ok(result) => result,
                Err(code) => {
                    write_error(&writer, protocol, correlation, code).await?;
                    return Ok(());
                }
            }
        };
    }

    macro_rules! maintenance_value {
        ($value:expr) => {
            match $value {
                Ok(result) => result,
                Err(_) => {
                    write_error(&writer, protocol, correlation, ErrorCode::InternalError).await?;
                    return Ok(());
                }
            }
        };
    }

    if matches!(
        request.op,
        RequestOp::PrepareUpdate { .. }
            | RequestOp::CommitUpdate { .. }
            | RequestOp::AbortUpdate { .. }
            | RequestOp::PrepareUninstall {}
    ) && !maintenance_authorized
    {
        write_error(&writer, protocol, correlation, ErrorCode::AccessDenied).await?;
        return Ok(());
    }

    let result = match request.op {
        RequestOp::GetServiceInfo {} => ResponseValue::ServiceInfo {
            info: context.service_info(),
        },
        RequestOp::HealthCheck {} => ResponseValue::Health {
            health: context.health(),
        },
        RequestOp::StartSandbox {
            client_instance_id,
            from,
            cpus,
            memory_mib,
            disk_mib,
            mounts,
            ports,
            network,
        } => rpc_value!(rpc::sandbox::start(
            context.admissions_open(),
            context.engine.clone(),
            context.sessions.clone(),
            session_id,
            identity.clone(),
            context.protected_egress_allow.clone(),
            client_instance_id,
            from,
            cpus,
            memory_mib,
            disk_mib,
            mounts,
            ports,
            network,
            request_cancellation.clone(),
        )),
        RequestOp::StopSandbox { sandbox_id } => rpc_value!(rpc::sandbox::stop(
            context.sessions.clone(),
            session_id,
            identity.clone(),
            sandbox_id,
            deadline_ms,
        )),
        RequestOp::Exec {
            sandbox_id,
            command,
            cwd,
            env,
        } => rpc_value!(rpc::process::exec(
            context.sessions.clone(),
            session_id,
            identity.clone(),
            sandbox_id,
            command,
            cwd,
            env,
            deadline_ms,
            request_cancellation.clone(),
        )),
        RequestOp::Spawn {
            sandbox_id,
            command,
            cwd,
            env,
        } => {
            let process = rpc_value!(rpc::process::spawn(
                context.sessions.clone(),
                session_id,
                identity.clone(),
                sandbox_id,
                command,
                cwd,
                env,
                deadline_ms,
                request_cancellation.clone(),
            ));
            let stdout_credit = streams.register(process.stdout_stream.to_string())?;
            let stderr_credit = streams.register(process.stderr_stream.to_string())?;
            write_control(
                &writer,
                FrameKind::Response,
                protocol,
                correlation,
                &Response::Ok {
                    result: ResponseValue::ProcessStarted {
                        process_id: process.id.to_string(),
                        stdout_stream_id: process.stdout_stream.to_string(),
                        stderr_stream_id: process.stderr_stream.to_string(),
                    },
                },
            )
            .await?;
            tokio::spawn(pump_process_output(
                context.sessions.clone(),
                session_id,
                identity,
                process,
                protocol,
                writer,
                events,
                streams,
                stdout_credit,
                stderr_credit,
            ));
            return Ok(());
        }
        RequestOp::KillProcess { process_id } => rpc_value!(rpc::process::kill(
            context.sessions.clone(),
            session_id,
            identity.clone(),
            process_id,
        )),
        RequestOp::Watch {
            sandbox_id,
            path,
            recursive,
        } => {
            let watch = rpc_value!(rpc::watch::start(
                context.sessions.clone(),
                session_id,
                identity.clone(),
                sandbox_id,
                path,
                recursive,
                deadline_ms,
                request_cancellation.clone(),
            ));
            write_control(
                &writer,
                FrameKind::Response,
                protocol,
                correlation,
                &Response::Ok {
                    result: ResponseValue::WatchStarted {
                        watch_id: watch.id.to_string(),
                    },
                },
            )
            .await?;
            tokio::spawn(pump_watch_events(
                context.sessions.clone(),
                session_id,
                identity,
                watch,
                protocol,
                writer,
                events,
            ));
            return Ok(());
        }
        RequestOp::StopWatch { watch_id } => rpc_value!(rpc::watch::stop(
            context.sessions.clone(),
            session_id,
            identity.clone(),
            watch_id,
        )),
        RequestOp::Mkdir {
            sandbox_id,
            path,
            recursive,
        } => rpc_value!(file_request(
            &context,
            session_id,
            &identity,
            sandbox_id,
            crate::resource::vm::ManagedFileOp::Mkdir { path, recursive },
            deadline_ms,
            request_cancellation.clone(),
        )),
        RequestOp::ReadDir { sandbox_id, path } => rpc_value!(file_request(
            &context,
            session_id,
            &identity,
            sandbox_id,
            crate::resource::vm::ManagedFileOp::ReadDir { path },
            deadline_ms,
            request_cancellation.clone(),
        )),
        RequestOp::Stat { sandbox_id, path } => rpc_value!(file_request(
            &context,
            session_id,
            &identity,
            sandbox_id,
            crate::resource::vm::ManagedFileOp::Stat { path },
            deadline_ms,
            request_cancellation.clone(),
        )),
        RequestOp::Remove {
            sandbox_id,
            path,
            recursive,
        } => rpc_value!(file_request(
            &context,
            session_id,
            &identity,
            sandbox_id,
            crate::resource::vm::ManagedFileOp::Remove { path, recursive },
            deadline_ms,
            request_cancellation.clone(),
        )),
        RequestOp::Rename {
            sandbox_id,
            old_path,
            new_path,
        } => rpc_value!(file_request(
            &context,
            session_id,
            &identity,
            sandbox_id,
            crate::resource::vm::ManagedFileOp::Rename { old_path, new_path },
            deadline_ms,
            request_cancellation.clone(),
        )),
        RequestOp::Copy {
            sandbox_id,
            src,
            dst,
            recursive,
        } => rpc_value!(file_request(
            &context,
            session_id,
            &identity,
            sandbox_id,
            crate::resource::vm::ManagedFileOp::Copy {
                src,
                dst,
                recursive,
            },
            deadline_ms,
            request_cancellation.clone(),
        )),
        RequestOp::Chmod {
            sandbox_id,
            path,
            mode,
        } => rpc_value!(file_request(
            &context,
            session_id,
            &identity,
            sandbox_id,
            crate::resource::vm::ManagedFileOp::Chmod { path, mode },
            deadline_ms,
            request_cancellation.clone(),
        )),
        RequestOp::Exists { sandbox_id, path } => rpc_value!(file_request(
            &context,
            session_id,
            &identity,
            sandbox_id,
            crate::resource::vm::ManagedFileOp::Exists { path },
            deadline_ms,
            request_cancellation.clone(),
        )),
        RequestOp::ReadFile { sandbox_id, path } => {
            let bytes = rpc_value!(rpc::file::read(
                context.sessions.clone(),
                session_id,
                identity,
                sandbox_id,
                path,
                deadline_ms,
                request_cancellation.clone(),
            ));
            let stream_id = ResourceHandle::random()?.to_string();
            let credit = streams.register(stream_id.clone())?;
            let transfer = async {
                write_control(
                    &writer,
                    FrameKind::Response,
                    protocol,
                    correlation,
                    &Response::Ok {
                        result: ResponseValue::FileRead {
                            stream_id: stream_id.clone(),
                            length: bytes.len().try_into().context("file length overflow")?,
                        },
                    },
                )
                .await?;
                write_stream(&writer, protocol, &stream_id, &bytes, &credit).await
            }
            .await;
            streams.remove(&stream_id);
            transfer?;
            return Ok(());
        }
        RequestOp::WriteFile {
            sandbox_id, path, ..
        } => rpc_value!(file_request(
            &context,
            session_id,
            &identity,
            sandbox_id,
            crate::resource::vm::ManagedFileOp::WriteFile {
                path,
                bytes: write_bytes.context("WriteFile bytes were not collected")?,
            },
            deadline_ms,
            request_cancellation.clone(),
        )),
        RequestOp::PrepareUpdate {
            target_bundle,
            target_protocol_range,
        } => {
            let maintenance = context
                .maintenance
                .as_ref()
                .context("maintenance manager is unavailable")?;
            let update_id = maintenance_value!(maintenance.prepare_update(
                &context.sessions,
                target_bundle,
                target_protocol_range,
            ));
            ResponseValue::UpdatePrepared { update_id }
        }
        RequestOp::CommitUpdate { update_id } => {
            let maintenance = context
                .maintenance
                .as_ref()
                .context("maintenance manager is unavailable")?;
            let running_bundle = context
                .engine
                .as_ref()
                .context("service engine is unavailable")?
                .bundle_version();
            maintenance_value!(maintenance.commit_update(&update_id, running_bundle, SUPPORTED,));
            ResponseValue::Empty {}
        }
        RequestOp::AbortUpdate { update_id } => {
            let maintenance = context
                .maintenance
                .as_ref()
                .context("maintenance manager is unavailable")?;
            maintenance_value!(maintenance.abort_update(&update_id));
            ResponseValue::Empty {}
        }
        RequestOp::PrepareUninstall {} => {
            let maintenance = context
                .maintenance
                .as_ref()
                .context("maintenance manager is unavailable")?;
            let clean = maintenance_value!(maintenance.prepare_uninstall(&context.sessions));
            ResponseValue::UninstallPrepared {
                clean,
                quarantine_ids: Vec::new(),
            }
        }
        RequestOp::CloseSession {} => return Ok(()),
    };
    write_control(
        &writer,
        FrameKind::Response,
        protocol,
        correlation,
        &Response::Ok { result },
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn pump_process_output(
    sessions: SessionManager,
    session_id: ResourceHandle,
    identity: ClientIdentityKey,
    process: GuestProcessResource,
    protocol: lsb_service_proto::ProtocolVersion,
    writer: OutboundWriter,
    events: EventSequence,
    streams: StreamRegistry,
    stdout_credit: StreamCredit,
    stderr_credit: StreamCredit,
) {
    let mut stdout_sequence = 0u64;
    let mut stderr_sequence = 0u64;
    let exit_code = loop {
        let output = tokio::task::spawn_blocking({
            let sessions = sessions.clone();
            let identity = identity.clone();
            move || {
                sessions.managed_process_output(
                    session_id,
                    &identity,
                    process.id,
                    Duration::from_secs(1),
                )
            }
        })
        .await;
        match output {
            Ok(Ok(Some(ManagedProcessOutput::Stdout(bytes)))) => {
                if stdout_credit.consume(bytes.len()).await.is_err()
                    || write_stream_frame(
                        &writer,
                        protocol,
                        process.stdout_stream,
                        stdout_sequence,
                        &bytes,
                    )
                    .await
                    .is_err()
                {
                    break 1;
                }
                let Some(next) = stdout_sequence.checked_add(1) else {
                    break 1;
                };
                stdout_sequence = next;
            }
            Ok(Ok(Some(ManagedProcessOutput::Stderr(bytes)))) => {
                if stderr_credit.consume(bytes.len()).await.is_err()
                    || write_stream_frame(
                        &writer,
                        protocol,
                        process.stderr_stream,
                        stderr_sequence,
                        &bytes,
                    )
                    .await
                    .is_err()
                {
                    break 1;
                }
                let Some(next) = stderr_sequence.checked_add(1) else {
                    break 1;
                };
                stderr_sequence = next;
            }
            Ok(Ok(Some(ManagedProcessOutput::Exited(code)))) => break code,
            Ok(Ok(None)) => {
                if !sessions.owns_managed_process(session_id, &identity, process.id)
                    || sessions.managed_process_closed(session_id, &identity, process.id)
                {
                    break 1;
                }
            }
            _ => break 1,
        }
    };

    let _ = events
        .write(
            &writer,
            protocol,
            &Event::StreamClosed {
                stream_id: process.stdout_stream.to_string(),
            },
        )
        .await;
    let _ = events
        .write(
            &writer,
            protocol,
            &Event::StreamClosed {
                stream_id: process.stderr_stream.to_string(),
            },
        )
        .await;
    let _ = events
        .write(
            &writer,
            protocol,
            &Event::ProcessExited {
                process_id: process.id.to_string(),
                exit_code,
            },
        )
        .await;
    streams.remove(&process.stdout_stream.to_string());
    streams.remove(&process.stderr_stream.to_string());
    let _ = sessions.retire_managed_process(session_id, &identity, process.id);
}

#[allow(clippy::too_many_arguments)]
async fn pump_watch_events(
    sessions: SessionManager,
    session_id: ResourceHandle,
    identity: ClientIdentityKey,
    watch: WatchResource,
    protocol: lsb_service_proto::ProtocolVersion,
    writer: OutboundWriter,
    events: EventSequence,
) {
    loop {
        let output = tokio::task::spawn_blocking({
            let sessions = sessions.clone();
            let identity = identity.clone();
            move || {
                sessions.managed_watch_event(
                    session_id,
                    &identity,
                    watch.id,
                    Duration::from_secs(1),
                )
            }
        })
        .await;
        match output {
            Ok(Ok(Some(event))) => {
                let event = Event::WatchChanged {
                    watch_id: watch.id.to_string(),
                    path: event.path,
                    change: event.change,
                };
                if event.validate().is_err()
                    || events.write(&writer, protocol, &event).await.is_err()
                {
                    break;
                }
            }
            Ok(Ok(None)) => {
                if sessions.managed_watch_closed(session_id, &identity, watch.id) {
                    break;
                }
            }
            _ => break,
        }
    }
    let _ = events
        .write(
            &writer,
            protocol,
            &Event::StreamClosed {
                stream_id: watch.id.to_string(),
            },
        )
        .await;
    let _ = sessions.retire_managed_watch(session_id, &identity, watch.id);
}

async fn write_stream_frame(
    writer: &OutboundWriter,
    protocol: lsb_service_proto::ProtocolVersion,
    stream_id: ResourceHandle,
    sequence: u64,
    bytes: &[u8],
) -> Result<()> {
    let payload = encode_stream_payload(sequence, bytes)?;
    let header = FrameHeader {
        kind: FrameKind::StreamData,
        flags: 0,
        protocol,
        payload_len: payload.len().try_into()?,
        correlation: stream_correlation(&stream_id.to_string())?,
    }
    .encode()?;
    writer.send(encode_frame(header, &payload)?).await
}

async fn write_stream(
    writer: &OutboundWriter,
    protocol: lsb_service_proto::ProtocolVersion,
    stream_id: &str,
    bytes: &[u8],
    credit: &StreamCredit,
) -> Result<()> {
    let correlation = stream_correlation(stream_id)?;
    let chunk_size = MAX_STREAM_PAYLOAD - STREAM_SEQUENCE_LEN;
    for (sequence, chunk) in bytes.chunks(chunk_size).enumerate() {
        credit.consume(chunk.len()).await?;
        let payload = encode_stream_payload(sequence.try_into()?, chunk)?;
        let header = FrameHeader {
            kind: FrameKind::StreamData,
            flags: 0,
            protocol,
            payload_len: payload.len().try_into()?,
            correlation,
        }
        .encode()?;
        writer.send(encode_frame(header, &payload)?).await?;
    }
    Ok(())
}

fn stream_correlation(stream_id: &str) -> Result<Correlation> {
    if stream_id.len() != 32 {
        bail!("invalid stream id");
    }
    Ok(Correlation {
        high: u64::from_str_radix(&stream_id[..16], 16)?,
        low: u64::from_str_radix(&stream_id[16..], 16)?,
    })
}

async fn file_request(
    context: &HealthContext,
    session_id: ResourceHandle,
    identity: &ClientIdentityKey,
    sandbox_id: String,
    op: crate::resource::vm::ManagedFileOp,
    deadline_ms: Option<u32>,
    cancellation: CancellationToken,
) -> std::result::Result<ResponseValue, ErrorCode> {
    rpc::file::run(
        context.sessions.clone(),
        session_id,
        identity.clone(),
        sandbox_id,
        op,
        deadline_ms,
        cancellation,
    )
    .await
}

async fn write_error(
    writer: &OutboundWriter,
    protocol: lsb_service_proto::ProtocolVersion,
    correlation: Correlation,
    code: ErrorCode,
) -> Result<()> {
    write_control(
        writer,
        FrameKind::Response,
        protocol,
        correlation,
        &Response::Err {
            error: ErrorEnvelope::safe(
                code,
                format!("{:016x}{:016x}", correlation.high, correlation.low),
            ),
        },
    )
    .await
}

struct WireFrame {
    header: FrameHeader,
    payload: Vec<u8>,
}

async fn read_frame<R>(pipe: &mut R) -> Result<WireFrame>
where
    R: AsyncRead + Unpin,
{
    read_frame_with_timeouts(
        pipe,
        crate::ipc::pipe::HEADER_TIMEOUT,
        crate::ipc::pipe::PAYLOAD_TIMEOUT,
    )
    .await
}

async fn read_frame_with_timeouts<R>(
    pipe: &mut R,
    header_timeout: Duration,
    payload_timeout: Duration,
) -> Result<WireFrame>
where
    R: AsyncRead + Unpin,
{
    let mut bytes = [0u8; HEADER_LEN];
    pipe.read_exact(&mut bytes[..1]).await?;
    tokio::time::timeout(header_timeout, pipe.read_exact(&mut bytes[1..]))
        .await
        .context("frame header deadline exceeded after first byte")??;
    if bytes[4] != HEADER_VERSION {
        bail!("unsupported frame header version");
    }
    let header = FrameHeader::decode(bytes)?;
    let mut payload = vec![0u8; header.payload_len as usize];
    tokio::time::timeout(payload_timeout, pipe.read_exact(&mut payload))
        .await
        .context("frame payload deadline exceeded")??;
    Ok(WireFrame { header, payload })
}

async fn write_control(
    writer: &OutboundWriter,
    kind: FrameKind,
    protocol: lsb_service_proto::ProtocolVersion,
    correlation: Correlation,
    value: &impl serde::Serialize,
) -> Result<()> {
    let payload = serde_json::to_vec(value)?;
    let header = FrameHeader {
        kind,
        flags: 0,
        protocol,
        payload_len: payload
            .len()
            .try_into()
            .context("control payload length overflow")?,
        correlation,
    }
    .encode()?;
    writer.send(encode_frame(header, &payload)?).await
}

fn encode_frame(header: [u8; HEADER_LEN], payload: &[u8]) -> Result<Vec<u8>> {
    let capacity = HEADER_LEN
        .checked_add(payload.len())
        .context("wire frame length overflow")?;
    let mut frame = Vec::with_capacity(capacity);
    frame.extend_from_slice(&header);
    frame.extend_from_slice(payload);
    Ok(frame)
}

fn random_epoch() -> Result<u64> {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes)
        .map_err(|error| anyhow::anyhow!("generate connection epoch: {error}"))?;
    let epoch = u64::from_le_bytes(bytes);
    if epoch == 0 {
        bail!("random connection epoch was zero");
    }
    Ok(epoch)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn send_test_control<W: AsyncWrite + Unpin>(
        writer: &mut W,
        kind: FrameKind,
        protocol: lsb_service_proto::ProtocolVersion,
        correlation: Correlation,
        value: &impl serde::Serialize,
    ) {
        let payload = serde_json::to_vec(value).unwrap();
        let header = FrameHeader {
            kind,
            flags: 0,
            protocol,
            payload_len: payload.len() as u32,
            correlation,
        }
        .encode()
        .unwrap();
        writer.write_all(&header).await.unwrap();
        writer.write_all(&payload).await.unwrap();
        writer.flush().await.unwrap();
    }

    fn start_test_server(
        server: tokio::io::DuplexStream,
        context: HealthContext,
    ) -> tokio::task::JoinHandle<Result<()>> {
        tokio::spawn(async move {
            let identity = ClientIdentityKey::for_test("user", "logon", 1);
            let session_id = context.sessions.open(identity.clone()).unwrap();
            let (reader, pipe_writer) = tokio::io::split(server);
            let (writer, writer_task) = OutboundWriter::start(pipe_writer);
            let result = handle_authenticated_client(
                reader,
                &writer,
                &context,
                session_id,
                &identity,
                ConnectionAuthorization {
                    client: true,
                    maintenance: false,
                },
                None,
                None,
            )
            .await;
            drop(writer);
            let writer_result = writer_task.await.context("join test pipe writer")?;
            result?;
            writer_result
        })
    }

    #[test]
    fn health_surface_is_fail_closed() {
        let context = HealthContext::new(true, QuotaLimits::default());
        let info = context.service_info();
        assert!(!info.capabilities.ports);
        assert!(!info.capabilities.direct_mount);
        assert_eq!(context.health().wfp, HealthState::Unavailable);
        assert_eq!(context.health().bundle, HealthState::Unavailable);
        assert!(!context.health().ready);
    }

    #[test]
    fn preauth_gate_bounds_global_and_per_pid_and_releases() {
        let gate = PreAuthGate::new();
        let first = gate.admit_pid(7, gate.try_global().unwrap()).unwrap();
        let second = gate.admit_pid(7, gate.try_global().unwrap()).unwrap();
        assert!(gate.admit_pid(7, gate.try_global().unwrap()).is_err());

        drop(first);
        let replacement = gate.admit_pid(7, gate.try_global().unwrap()).unwrap();
        let mut other = Vec::new();
        for process_id in 10..16 {
            other.push(
                gate.admit_pid(process_id, gate.try_global().unwrap())
                    .unwrap(),
            );
        }
        assert!(gate.try_global().is_err());

        drop(second);
        drop(replacement);
        drop(other);
        assert!(gate.by_pid.lock().unwrap().is_empty());
        assert_eq!(
            gate.global.available_permits(),
            crate::ipc::pipe::MAX_UNAUTHENTICATED_GLOBAL
        );
    }

    #[test]
    fn shutdown_closes_admissions_and_drains_sessions() {
        let context = HealthContext::new(true, QuotaLimits::default());
        let identity = ClientIdentityKey::for_test("user", "logon", 1);
        context.sessions.open(identity).unwrap();

        assert_eq!(context.begin_shutdown().unwrap(), 1);
        assert!(context.sessions.is_empty());
        assert!(!context.admissions_open.load(Ordering::Acquire));
    }

    #[test]
    fn maintenance_only_clients_cannot_start_sandboxes() {
        assert!(is_health_or_maintenance(&RequestOp::HealthCheck {}));
        assert!(is_health_or_maintenance(&RequestOp::PrepareUninstall {}));
        assert!(!is_health_or_maintenance(&RequestOp::StartSandbox {
            client_instance_id: None,
            from: None,
            cpus: 1,
            memory_mib: 512,
            disk_mib: 1024,
            mounts: Vec::new(),
            ports: Vec::new(),
            network: None,
        }));
    }

    #[test]
    fn pipe_security_descriptor_is_valid() {
        SecurityDescriptor::from_sddl(PIPE_SDDL).unwrap();
    }

    #[tokio::test]
    async fn stream_credit_is_consumed_and_replenished_with_a_hard_cap() {
        let credit = StreamCredit::initial();
        credit
            .consume(lsb_service_proto::limits::INITIAL_STREAM_CREDIT)
            .await
            .unwrap();
        assert_eq!(credit.credit.available_permits(), 0);
        credit.grant(64 * 1024).unwrap();
        credit.consume(64 * 1024).await.unwrap();
        assert_eq!(credit.credit.available_permits(), 0);
        assert!(credit.grant(4 * 1024 * 1024 + 1).is_err());
    }

    #[tokio::test]
    async fn reader_task_uses_the_bounded_dispatch_queue() {
        let (_client, server) = tokio::io::duplex(1024);
        let reader = FrameReader::start(server);

        assert_eq!(
            reader.frames.capacity(),
            crate::ipc::pipe::MAX_DISPATCH_FRAMES
        );
    }

    #[tokio::test]
    async fn authenticated_frame_timeout_starts_after_the_first_byte() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let read = tokio::spawn(async move {
            read_frame_with_timeouts(
                &mut server,
                Duration::from_millis(10),
                Duration::from_millis(10),
            )
            .await
        });

        tokio::time::sleep(Duration::from_millis(30)).await;
        let header = FrameHeader {
            kind: FrameKind::Request,
            flags: 0,
            protocol: CURRENT,
            payload_len: 0,
            correlation: Correlation::default(),
        }
        .encode()
        .unwrap();
        client.write_all(&header).await.unwrap();

        assert_eq!(read.await.unwrap().unwrap().header.kind, FrameKind::Request);
    }

    #[tokio::test]
    async fn incomplete_upload_does_not_block_requests_or_cancel() {
        let bundle = std::path::PathBuf::from(
            r"C:\Program Files\SeaWork\LocalSandbox\versions\dispatch-test",
        );
        let paths = crate::paths::ServicePaths::for_test(
            std::env::temp_dir().join("lsbsw-pipe-dispatch-test"),
        );
        let engine = ServiceEngineConfig::from_verified_bundle(
            bundle.clone(),
            bundle.join("tools/qemu/qemu-system-x86_64.exe"),
            bundle.join("runtime/Image"),
            bundle.join("runtime/initramfs.cpio.gz"),
            bundle.join("runtime/rootfs.ext4"),
            &paths,
        )
        .unwrap();
        let mut context = HealthContext::new(true, QuotaLimits::default())
            .with_engine(Some(engine))
            .with_whpx(HealthState::Ready);
        context
            .client_roots
            .push(r"C:\Program Files\SeaWork".to_string());
        context.publisher_thumbprints.push("test".to_string());

        let (mut client, server) = tokio::io::duplex(1024 * 1024);
        let server_task = start_test_server(server, context);
        send_test_control(
            &mut client,
            FrameKind::Hello,
            CURRENT,
            Correlation::default(),
            &Hello {
                min_minor: SUPPORTED.min_minor,
                max_minor: SUPPORTED.max_minor,
                client_version: "test".to_string(),
                feature_bits_hex: HexU64(0),
            },
        )
        .await;
        let hello = read_frame(&mut client).await.unwrap();
        let epoch = hello.header.correlation.high;
        let protocol = hello.header.protocol;
        let sandbox_id = "0123456789abcdef0123456789abcdef";
        let stream_id = "fedcba9876543210fedcba9876543210";

        send_test_control(
            &mut client,
            FrameKind::Request,
            protocol,
            Correlation {
                high: epoch,
                low: 1,
            },
            &Request {
                deadline_ms: None,
                op: RequestOp::WriteFile {
                    sandbox_id: sandbox_id.to_string(),
                    path: "/workspace/output".to_string(),
                    stream_id: stream_id.to_string(),
                    length: 2,
                },
            },
        )
        .await;
        send_test_control(
            &mut client,
            FrameKind::Request,
            protocol,
            Correlation {
                high: epoch,
                low: 2,
            },
            &Request {
                deadline_ms: None,
                op: RequestOp::GetServiceInfo {},
            },
        )
        .await;

        let service_info = read_frame(&mut client).await.unwrap();
        assert_eq!(service_info.header.correlation.low, 2);
        assert!(matches!(
            parse_control::<Response>(&service_info.payload).unwrap(),
            Response::Ok {
                result: ResponseValue::ServiceInfo { .. }
            }
        ));

        send_test_control(
            &mut client,
            FrameKind::Cancel,
            protocol,
            Correlation {
                high: epoch,
                low: 3,
            },
            &Cancel {
                request_id: format!("{epoch:016x}{:016x}", 1),
            },
        )
        .await;
        let upload_terminal = read_frame(&mut client).await.unwrap();
        let cancel_terminal = read_frame(&mut client).await.unwrap();
        let mut terminal = [upload_terminal, cancel_terminal];
        terminal.sort_by_key(|frame| frame.header.correlation.low);
        assert_eq!(terminal[0].header.correlation.low, 1);
        assert!(matches!(
            parse_control::<Response>(&terminal[0].payload).unwrap(),
            Response::Err {
                error: ErrorEnvelope {
                    code: ErrorCode::Cancelled,
                    ..
                }
            }
        ));
        assert_eq!(terminal[1].header.correlation.low, 3);

        send_test_control(
            &mut client,
            FrameKind::Request,
            protocol,
            Correlation {
                high: epoch,
                low: 4,
            },
            &Request {
                deadline_ms: None,
                op: RequestOp::CloseSession {},
            },
        )
        .await;
        assert_eq!(
            read_frame(&mut client)
                .await
                .unwrap()
                .header
                .correlation
                .low,
            4
        );
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn requests_complete_out_of_order_and_cancel_by_correlation() {
        TEST_HEALTH_DELAY_MS.store(10_000, std::sync::atomic::Ordering::Release);
        let (mut client, server) = tokio::io::duplex(1024 * 1024);
        let context = HealthContext::new(true, QuotaLimits::default());
        let server_task = start_test_server(server, context);

        send_test_control(
            &mut client,
            FrameKind::Hello,
            CURRENT,
            Correlation::default(),
            &Hello {
                min_minor: SUPPORTED.min_minor,
                max_minor: SUPPORTED.max_minor,
                client_version: "test".to_string(),
                feature_bits_hex: HexU64(0),
            },
        )
        .await;
        let hello = read_frame(&mut client).await.unwrap();
        let epoch = hello.header.correlation.high;
        let protocol = hello.header.protocol;

        send_test_control(
            &mut client,
            FrameKind::Request,
            protocol,
            Correlation {
                high: epoch,
                low: 1,
            },
            &Request {
                deadline_ms: None,
                op: RequestOp::HealthCheck {},
            },
        )
        .await;
        send_test_control(
            &mut client,
            FrameKind::Request,
            protocol,
            Correlation {
                high: epoch,
                low: 2,
            },
            &Request {
                deadline_ms: None,
                op: RequestOp::GetServiceInfo {},
            },
        )
        .await;

        let second = read_frame(&mut client).await.unwrap();
        assert_eq!(second.header.correlation.low, 2);
        assert!(matches!(
            parse_control::<Response>(&second.payload).unwrap(),
            Response::Ok {
                result: ResponseValue::ServiceInfo { .. }
            }
        ));

        send_test_control(
            &mut client,
            FrameKind::Cancel,
            protocol,
            Correlation {
                high: epoch,
                low: 3,
            },
            &Cancel {
                request_id: format!("{epoch:016x}{:016x}", 1),
            },
        )
        .await;
        let first_terminal = read_frame(&mut client).await.unwrap();
        let second_terminal = read_frame(&mut client).await.unwrap();
        let mut terminal = [first_terminal, second_terminal];
        terminal.sort_by_key(|frame| frame.header.correlation.low);
        assert_eq!(terminal[0].header.correlation.low, 1);
        assert!(matches!(
            parse_control::<Response>(&terminal[0].payload).unwrap(),
            Response::Err {
                error: ErrorEnvelope {
                    code: ErrorCode::Cancelled,
                    ..
                }
            }
        ));
        assert_eq!(terminal[1].header.correlation.low, 3);
        assert!(matches!(
            parse_control::<Response>(&terminal[1].payload).unwrap(),
            Response::Ok {
                result: ResponseValue::Empty {}
            }
        ));

        send_test_control(
            &mut client,
            FrameKind::Request,
            protocol,
            Correlation {
                high: epoch,
                low: 4,
            },
            &Request {
                deadline_ms: None,
                op: RequestOp::CloseSession {},
            },
        )
        .await;
        let close = read_frame(&mut client).await.unwrap();
        assert_eq!(close.header.correlation.low, 4);
        server_task.await.unwrap().unwrap();
        TEST_HEALTH_DELAY_MS.store(0, std::sync::atomic::Ordering::Release);
    }
}
