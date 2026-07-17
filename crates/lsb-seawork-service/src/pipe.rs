use std::collections::HashMap;
use std::ffi::c_void;
use std::os::windows::io::AsRawHandle;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use lsb_service_proto::frame::HEADER_VERSION;
use lsb_service_proto::limits::{HEADER_LEN, MAX_STREAM_PAYLOAD, STREAM_SEQUENCE_LEN};
use lsb_service_proto::{
    encode_stream_payload, negotiate, parse_control, CapabilityHealth, Correlation, ErrorCode,
    ErrorEnvelope, Event, FrameHeader, FrameKind, Health, HealthState, Hello, HelloReply, HexU64,
    ProtocolRange, Request, RequestOp, Response, ResponseValue, ServiceInfo, WindowUpdate, CURRENT,
    SUPPORTED,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

use crate::resource::process::{GuestProcessResource, ManagedProcessOutput};
use crate::security::descriptor::SecurityDescriptor;
use crate::security::ClientIdentity;
use crate::session::{ClientIdentityKey, QuotaLimits, ResourceHandle, SessionManager};
use crate::{engine::ServiceEngineConfig, rpc};
use crate::{LEDGER_SCHEMA_VERSION, PIPE_NAME, PIPE_SDDL};

const OUTPUT_BACKPRESSURE_TIMEOUT: Duration = Duration::from_secs(30);

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
        let mut sequence = self.next.lock().await;
        if *sequence == 0 || *sequence == u64::MAX {
            bail!("server event sequence exhausted");
        }
        write_control(
            writer,
            FrameKind::Event,
            protocol,
            Correlation {
                high: self.epoch,
                low: *sequence,
            },
            event,
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

#[derive(Clone)]
pub struct HealthContext {
    pub admissions_open: bool,
    sessions: SessionManager,
    engine: Option<ServiceEngineConfig>,
}

impl HealthContext {
    pub fn new(admissions_open: bool, quota_limits: QuotaLimits) -> Self {
        Self {
            admissions_open,
            sessions: SessionManager::new(quota_limits),
            engine: None,
        }
    }

    pub fn with_engine(mut self, engine: Option<ServiceEngineConfig>) -> Self {
        self.engine = engine;
        self
    }

    fn health(&self) -> Health {
        Health {
            ready: self.admissions_open && self.engine.is_some(),
            admissions_open: self.admissions_open && self.engine.is_some(),
            stable_code: if self.engine.is_none() {
                "BUNDLE_INVALID"
            } else if self.admissions_open {
                "READY"
            } else {
                "HEALTH_ONLY_QUARANTINE"
            }
            .to_string(),
            whpx: HealthState::Unknown,
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
            watch: false,
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
            feature_bits_hex: HexU64(0),
            capabilities: self.capabilities(),
        }
    }
}

pub struct HealthPipe {
    server: NamedPipeServer,
    context: HealthContext,
}

impl HealthPipe {
    pub fn bind(context: HealthContext) -> Result<Self> {
        Ok(Self {
            server: create_server(true)?,
            context,
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
            let context = self.context.clone();
            tokio::spawn(async move {
                let _ = handle_client(connected, context).await;
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

async fn handle_client(pipe: NamedPipeServer, context: HealthContext) -> Result<()> {
    let identity = ClientIdentity::from_named_pipe(pipe.as_raw_handle())?;
    let session_id = context.sessions.open(identity.key.clone())?;
    let (mut reader, pipe_writer) = tokio::io::split(pipe);
    let (writer, writer_task) = OutboundWriter::start(pipe_writer);
    let result =
        handle_authenticated_client(&mut reader, &writer, &context, session_id, &identity.key)
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

async fn handle_authenticated_client<R>(
    pipe: &mut R,
    writer: &OutboundWriter,
    context: &HealthContext,
    session_id: ResourceHandle,
    identity: &ClientIdentityKey,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let hello_frame = read_frame(pipe).await?;
    if hello_frame.header.kind != FrameKind::Hello
        || hello_frame.header.correlation != Correlation::default()
        || hello_frame.header.protocol.major != CURRENT.major
    {
        bail!("first frame is not a valid Hello");
    }
    let hello: Hello = parse_control(&hello_frame.payload)?;
    hello.validate()?;
    let selected = negotiate(SUPPORTED, hello.range(hello_frame.header.protocol.major))?;
    let epoch = random_epoch()?;
    let events = EventSequence::new(epoch);
    let streams = StreamRegistry::default();
    let reply = HelloReply {
        selected_minor: selected.minor,
        connection_epoch_hex: HexU64(epoch),
        service_version: env!("CARGO_PKG_VERSION").to_string(),
        bundle_version: env!("CARGO_PKG_VERSION").to_string(),
        ledger_schema: context.service_info().ledger_schema,
        selected_feature_bits_hex: HexU64(0),
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

    let mut expected_sequence = 1u64;
    loop {
        let frame = match read_frame(pipe).await {
            Ok(frame) => frame,
            Err(_) => return Ok(()),
        };
        if frame.header.protocol != selected
            || frame.header.correlation.high != epoch
            || frame.header.correlation.low != expected_sequence
            || !matches!(
                frame.header.kind,
                FrameKind::Request | FrameKind::WindowUpdate
            )
        {
            bail!("invalid health request direction, version, or sequence");
        }
        expected_sequence = expected_sequence
            .checked_add(1)
            .context("health request sequence exhausted")?;
        if frame.header.kind == FrameKind::WindowUpdate {
            let update: WindowUpdate = parse_control(&frame.payload)?;
            update.validate()?;
            streams.grant(&update)?;
            continue;
        }
        let request: Request = parse_control(&frame.payload)?;
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
        let deadline_ms = request.deadline_ms;
        macro_rules! file_result {
            ($future:expr) => {
                match $future.await {
                    Ok(result) => result,
                    Err(code) => {
                        write_error(writer, selected, frame.header.correlation, code).await?;
                        continue;
                    }
                }
            };
        }
        let result = match request.op {
            RequestOp::GetServiceInfo {} => ResponseValue::ServiceInfo {
                info: context.service_info(),
            },
            RequestOp::HealthCheck {} => ResponseValue::Health {
                health: context.health(),
            },
            RequestOp::StartSandbox {
                cpus,
                memory_mib,
                disk_mib,
                mounts,
                ports,
                network,
            } => match rpc::sandbox::start(
                context.admissions_open,
                context.engine.clone(),
                context.sessions.clone(),
                session_id,
                identity.clone(),
                cpus,
                memory_mib,
                disk_mib,
                mounts,
                ports,
                network,
            )
            .await
            {
                Ok(result) => result,
                Err(code) => {
                    write_error(writer, selected, frame.header.correlation, code).await?;
                    continue;
                }
            },
            RequestOp::StopSandbox { sandbox_id } => match rpc::sandbox::stop(
                context.sessions.clone(),
                session_id,
                identity.clone(),
                sandbox_id,
                deadline_ms,
            )
            .await
            {
                Ok(result) => result,
                Err(code) => {
                    write_error(writer, selected, frame.header.correlation, code).await?;
                    continue;
                }
            },
            RequestOp::Exec {
                sandbox_id,
                command,
                cwd,
                env,
            } => match rpc::process::exec(
                context.sessions.clone(),
                session_id,
                identity.clone(),
                sandbox_id,
                command,
                cwd,
                env,
                deadline_ms,
            )
            .await
            {
                Ok(result) => result,
                Err(code) => {
                    write_error(writer, selected, frame.header.correlation, code).await?;
                    continue;
                }
            },
            RequestOp::Spawn {
                sandbox_id,
                command,
                cwd,
                env,
            } => {
                let process = match rpc::process::spawn(
                    context.sessions.clone(),
                    session_id,
                    identity.clone(),
                    sandbox_id,
                    command,
                    cwd,
                    env,
                    deadline_ms,
                )
                .await
                {
                    Ok(process) => process,
                    Err(code) => {
                        write_error(writer, selected, frame.header.correlation, code).await?;
                        continue;
                    }
                };
                let stdout_credit = streams.register(process.stdout_stream.to_string())?;
                let stderr_credit = streams.register(process.stderr_stream.to_string())?;
                write_control(
                    writer,
                    FrameKind::Response,
                    selected,
                    frame.header.correlation,
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
                    identity.clone(),
                    process,
                    selected,
                    writer.clone(),
                    events.clone(),
                    streams.clone(),
                    stdout_credit,
                    stderr_credit,
                ));
                continue;
            }
            RequestOp::KillProcess { process_id } => match rpc::process::kill(
                context.sessions.clone(),
                session_id,
                identity.clone(),
                process_id,
            )
            .await
            {
                Ok(result) => result,
                Err(code) => {
                    write_error(writer, selected, frame.header.correlation, code).await?;
                    continue;
                }
            },
            RequestOp::Mkdir {
                sandbox_id,
                path,
                recursive,
            } => file_result!(file_request(
                context,
                session_id,
                identity,
                sandbox_id,
                crate::resource::vm::ManagedFileOp::Mkdir { path, recursive },
                deadline_ms,
            )),
            RequestOp::ReadDir { sandbox_id, path } => file_result!(file_request(
                context,
                session_id,
                identity,
                sandbox_id,
                crate::resource::vm::ManagedFileOp::ReadDir { path },
                deadline_ms,
            )),
            RequestOp::Stat { sandbox_id, path } => file_result!(file_request(
                context,
                session_id,
                identity,
                sandbox_id,
                crate::resource::vm::ManagedFileOp::Stat { path },
                deadline_ms,
            )),
            RequestOp::Remove {
                sandbox_id,
                path,
                recursive,
            } => file_result!(file_request(
                context,
                session_id,
                identity,
                sandbox_id,
                crate::resource::vm::ManagedFileOp::Remove { path, recursive },
                deadline_ms,
            )),
            RequestOp::Rename {
                sandbox_id,
                old_path,
                new_path,
            } => file_result!(file_request(
                context,
                session_id,
                identity,
                sandbox_id,
                crate::resource::vm::ManagedFileOp::Rename { old_path, new_path },
                deadline_ms,
            )),
            RequestOp::Copy {
                sandbox_id,
                src,
                dst,
                recursive,
            } => file_result!(file_request(
                context,
                session_id,
                identity,
                sandbox_id,
                crate::resource::vm::ManagedFileOp::Copy {
                    src,
                    dst,
                    recursive,
                },
                deadline_ms,
            )),
            RequestOp::Chmod {
                sandbox_id,
                path,
                mode,
            } => file_result!(file_request(
                context,
                session_id,
                identity,
                sandbox_id,
                crate::resource::vm::ManagedFileOp::Chmod { path, mode },
                deadline_ms,
            )),
            RequestOp::Exists { sandbox_id, path } => file_result!(file_request(
                context,
                session_id,
                identity,
                sandbox_id,
                crate::resource::vm::ManagedFileOp::Exists { path },
                deadline_ms,
            )),
            RequestOp::ReadFile { sandbox_id, path } => {
                let bytes = match rpc::file::read(
                    context.sessions.clone(),
                    session_id,
                    identity.clone(),
                    sandbox_id,
                    path,
                    deadline_ms,
                )
                .await
                {
                    Ok(bytes) => bytes,
                    Err(code) => {
                        write_error(writer, selected, frame.header.correlation, code).await?;
                        continue;
                    }
                };
                let stream_id = ResourceHandle::random()?.to_string();
                write_control(
                    writer,
                    FrameKind::Response,
                    selected,
                    frame.header.correlation,
                    &Response::Ok {
                        result: ResponseValue::FileRead {
                            stream_id: stream_id.clone(),
                            length: bytes.len().try_into().context("file length overflow")?,
                        },
                    },
                )
                .await?;
                write_stream(writer, selected, &stream_id, &bytes).await?;
                continue;
            }
            RequestOp::WriteFile {
                sandbox_id,
                path,
                stream_id,
                length,
            } => {
                let bytes = match read_stream(pipe, selected, &stream_id, length).await {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        write_error(
                            writer,
                            selected,
                            frame.header.correlation,
                            ErrorCode::ProtocolError,
                        )
                        .await?;
                        return Ok(());
                    }
                };
                file_result!(file_request(
                    context,
                    session_id,
                    identity,
                    sandbox_id,
                    crate::resource::vm::ManagedFileOp::WriteFile { path, bytes },
                    deadline_ms,
                ))
            }
            RequestOp::CloseSession {} => {
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
        };
        write_control(
            writer,
            FrameKind::Response,
            selected,
            frame.header.correlation,
            &Response::Ok { result },
        )
        .await?;
    }
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
                if !sessions.owns_managed_process(session_id, &identity, process.id) {
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
) -> Result<()> {
    let correlation = stream_correlation(stream_id)?;
    let chunk_size = MAX_STREAM_PAYLOAD - STREAM_SEQUENCE_LEN;
    for (sequence, chunk) in bytes.chunks(chunk_size).enumerate() {
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

async fn read_stream<R>(
    pipe: &mut R,
    protocol: lsb_service_proto::ProtocolVersion,
    stream_id: &str,
    length: u32,
) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let correlation = stream_correlation(stream_id)?;
    let mut bytes = Vec::with_capacity(length as usize);
    let mut expected_sequence = 0u64;
    while bytes.len() < length as usize {
        let frame = read_frame(pipe).await?;
        if frame.header.kind != FrameKind::StreamData
            || frame.header.protocol != protocol
            || frame.header.correlation != correlation
        {
            bail!("write stream correlation/version mismatch");
        }
        let (sequence, chunk) = lsb_service_proto::decode_stream_payload(&frame.payload)?;
        if sequence != expected_sequence
            || bytes.len().saturating_add(chunk.len()) > length as usize
        {
            bail!("write stream sequence/length mismatch");
        }
        expected_sequence = expected_sequence
            .checked_add(1)
            .context("write stream sequence exhausted")?;
        bytes.extend_from_slice(chunk);
    }
    Ok(bytes)
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
) -> std::result::Result<ResponseValue, ErrorCode> {
    rpc::file::run(
        context.sessions.clone(),
        session_id,
        identity.clone(),
        sandbox_id,
        op,
        deadline_ms,
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
    let mut bytes = [0u8; HEADER_LEN];
    tokio::time::timeout(Duration::from_secs(5), pipe.read_exact(&mut bytes))
        .await
        .context("health frame header deadline exceeded")??;
    if bytes[4] != HEADER_VERSION {
        bail!("unsupported frame header version");
    }
    let header = FrameHeader::decode(bytes)?;
    let mut payload = vec![0u8; header.payload_len as usize];
    tokio::time::timeout(Duration::from_secs(10), pipe.read_exact(&mut payload))
        .await
        .context("health frame payload deadline exceeded")??;
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
}
