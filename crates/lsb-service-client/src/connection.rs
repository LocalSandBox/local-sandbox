use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use lsb_service_proto::limits::HEADER_LEN;
use lsb_service_proto::{
    decode_stream_payload, parse_control, Cancel, Correlation, ErrorEnvelope, Event, FrameHeader,
    FrameKind, Health, Hello, HelloReply, HexU64, ProtocolVersion, Request, RequestOp, Response,
    ResponseValue, ServiceInfo, WindowUpdate, CURRENT, SUPPORTED,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::windows::named_pipe::NamedPipeClient;
use tokio::sync::{mpsc, oneshot, watch, Mutex, Semaphore};

use crate::pipe::open_verified;
use crate::{ClientError, ConnectOptions};

pub struct ServiceClient {
    core: Arc<ConnectionCore>,
    info: ServiceInfo,
}

struct ConnectionCore {
    writer: Mutex<tokio::io::WriteHalf<NamedPipeClient>>,
    protocol: ProtocolVersion,
    epoch: u64,
    next_sequence: AtomicU64,
    pending: Mutex<HashMap<u64, PendingRequest>>,
    outbound_streams: Mutex<HashMap<(u64, u64), Arc<Semaphore>>>,
    closed: AtomicBool,
    _shutdown: watch::Sender<()>,
}

enum PendingRequest {
    Unary(oneshot::Sender<Response>),
    ReadFile(oneshot::Sender<Result<Vec<u8>, ErrorEnvelope>>),
    Spawn(oneshot::Sender<Result<SpawnChannels, ErrorEnvelope>>),
    Watch(oneshot::Sender<Result<WatchChannels, ErrorEnvelope>>),
    StopWatch {
        watch_id: String,
        completion: oneshot::Sender<Response>,
    },
}

struct SpawnChannels {
    process_id: String,
    stdout_stream_id: String,
    stderr_stream_id: String,
    stdout: mpsc::Receiver<Vec<u8>>,
    stderr: mpsc::Receiver<Vec<u8>>,
    exited: watch::Receiver<Option<i32>>,
}

struct WatchChannels {
    watch_id: String,
    events: watch::Receiver<Option<RemoteWatchEvent>>,
}

enum IncomingStream {
    File {
        sequence: u64,
        length: usize,
        bytes: Vec<u8>,
        completion: Option<oneshot::Sender<Result<Vec<u8>, ErrorEnvelope>>>,
    },
    Process {
        sequence: u64,
        chunks: mpsc::Sender<Vec<u8>>,
    },
}

impl ServiceClient {
    pub async fn connect(options: ConnectOptions) -> Result<Self, ClientError> {
        tokio::time::timeout(options.timeout, Self::connect_inner())
            .await
            .map_err(|_| ClientError::ServiceUnavailable("connect timeout".to_string()))?
    }

    async fn connect_inner() -> Result<Self, ClientError> {
        let mut pipe = open_verified()?;
        let hello = Hello {
            min_minor: SUPPORTED.min_minor,
            max_minor: SUPPORTED.max_minor,
            client_version: env!("CARGO_PKG_VERSION").to_string(),
            feature_bits_hex: HexU64(0),
        };
        write_control(
            &mut pipe,
            FrameKind::Hello,
            CURRENT,
            Correlation::default(),
            &hello,
        )
        .await?;
        let frame = read_frame(&mut pipe).await?;
        if frame.header.kind != FrameKind::Hello
            || frame.header.protocol.major != CURRENT.major
            || frame.header.correlation.low != 0
            || frame.header.correlation.high == 0
        {
            return Err(ClientError::Protocol("invalid Hello reply".to_string()));
        }
        let reply: HelloReply = parse_control(&frame.payload)?;
        let epoch = frame.header.correlation.high;
        if reply.connection_epoch_hex.0 != epoch
            || reply.selected_minor != frame.header.protocol.minor
        {
            return Err(ClientError::Protocol(
                "Hello reply epoch/version mismatch".to_string(),
            ));
        }
        let protocol = ProtocolVersion {
            major: CURRENT.major,
            minor: reply.selected_minor,
        };
        let (reader, writer) = tokio::io::split(pipe);
        let (shutdown, shutdown_rx) = watch::channel(());
        let core = Arc::new(ConnectionCore {
            writer: Mutex::new(writer),
            protocol,
            epoch,
            next_sequence: AtomicU64::new(1),
            pending: Mutex::new(HashMap::new()),
            outbound_streams: Mutex::new(HashMap::new()),
            closed: AtomicBool::new(false),
            _shutdown: shutdown,
        });
        tokio::spawn(read_loop(reader, Arc::downgrade(&core), shutdown_rx));
        let mut client = Self {
            core,
            info: ServiceInfo {
                service_version: reply.service_version,
                bundle_version: reply.bundle_version,
                protocol: SUPPORTED,
                ledger_schema: reply.ledger_schema,
                feature_bits_hex: reply.selected_feature_bits_hex,
                capabilities: lsb_service_proto::CapabilityHealth {
                    direct_mount: false,
                    direct_mount_backends: Vec::new(),
                    watch: false,
                    ports: false,
                },
            },
        };
        client.info = client.get_service_info().await?;
        Ok(client)
    }

    pub fn negotiated_service_info(&self) -> &ServiceInfo {
        &self.info
    }

    pub fn negotiated_protocol(&self) -> ProtocolVersion {
        self.core.protocol
    }

    pub async fn get_service_info(&self) -> Result<ServiceInfo, ClientError> {
        match self.request(RequestOp::GetServiceInfo {}).await? {
            ResponseValue::ServiceInfo { info } => Ok(info),
            _ => Err(ClientError::Protocol(
                "GetServiceInfo returned a mismatched result".to_string(),
            )),
        }
    }

    pub async fn health_check(&self) -> Result<Health, ClientError> {
        match self.request(RequestOp::HealthCheck {}).await? {
            ResponseValue::Health { health } => Ok(health),
            _ => Err(ClientError::Protocol(
                "HealthCheck returned a mismatched result".to_string(),
            )),
        }
    }

    pub async fn prepare_update(
        &self,
        target_bundle: impl Into<String>,
        target_protocol_range: lsb_service_proto::ProtocolRange,
    ) -> Result<String, ClientError> {
        match self
            .request(RequestOp::PrepareUpdate {
                target_bundle: target_bundle.into(),
                target_protocol_range,
            })
            .await?
        {
            ResponseValue::UpdatePrepared { update_id } => Ok(update_id),
            _ => Err(mismatched("PrepareUpdate")),
        }
    }

    pub async fn commit_update(&self, update_id: impl Into<String>) -> Result<(), ClientError> {
        match self
            .request(RequestOp::CommitUpdate {
                update_id: update_id.into(),
            })
            .await?
        {
            ResponseValue::Empty {} => Ok(()),
            _ => Err(mismatched("CommitUpdate")),
        }
    }

    pub async fn abort_update(&self, update_id: impl Into<String>) -> Result<(), ClientError> {
        match self
            .request(RequestOp::AbortUpdate {
                update_id: update_id.into(),
            })
            .await?
        {
            ResponseValue::Empty {} => Ok(()),
            _ => Err(mismatched("AbortUpdate")),
        }
    }

    pub async fn prepare_uninstall(&self) -> Result<UninstallPreparation, ClientError> {
        match self.request(RequestOp::PrepareUninstall {}).await? {
            ResponseValue::UninstallPrepared {
                clean,
                quarantine_ids,
            } => Ok(UninstallPreparation {
                clean,
                quarantine_ids,
            }),
            _ => Err(mismatched("PrepareUninstall")),
        }
    }

    pub async fn start_sandbox(
        &self,
        options: StartSandboxOptions,
    ) -> Result<RemoteSandbox, ClientError> {
        match self
            .request(RequestOp::StartSandbox {
                cpus: options.cpus,
                memory_mib: options.memory_mib,
                disk_mib: options.disk_mib,
                mounts: options.mounts,
                ports: options.ports,
                network: options.network,
            })
            .await?
        {
            ResponseValue::SandboxStarted { sandbox_id, .. } => Ok(RemoteSandbox { sandbox_id }),
            _ => Err(ClientError::Protocol(
                "StartSandbox returned a mismatched result".to_string(),
            )),
        }
    }

    pub async fn stop_sandbox(&self, sandbox: &RemoteSandbox) -> Result<(), ClientError> {
        match self
            .request(RequestOp::StopSandbox {
                sandbox_id: sandbox.sandbox_id.clone(),
            })
            .await?
        {
            ResponseValue::Empty {} => Ok(()),
            _ => Err(ClientError::Protocol(
                "StopSandbox returned a mismatched result".to_string(),
            )),
        }
    }

    pub async fn exec(
        &self,
        sandbox: &RemoteSandbox,
        command: RemoteCommand,
        options: ExecOptions,
    ) -> Result<RemoteExecResult, ClientError> {
        self.begin_exec(sandbox, command, options)
            .await?
            .complete()
            .await
    }

    pub async fn begin_exec(
        &self,
        sandbox: &RemoteSandbox,
        command: RemoteCommand,
        options: ExecOptions,
    ) -> Result<RemoteExecOperation, ClientError> {
        let (sender, receiver) = oneshot::channel();
        let correlation = self
            .core
            .send_request(
                RequestOp::Exec {
                    sandbox_id: sandbox.sandbox_id.clone(),
                    command: service_command(command),
                    cwd: options.cwd,
                    env: options.env,
                },
                PendingRequest::Unary(sender),
            )
            .await?;
        Ok(RemoteExecOperation {
            core: self.core.clone(),
            request_id: correlation_id(correlation),
            response: Mutex::new(Some(receiver)),
        })
    }

    pub async fn mkdir(
        &self,
        sandbox: &RemoteSandbox,
        path: impl Into<String>,
        recursive: bool,
    ) -> Result<(), ClientError> {
        self.empty_file_request(RequestOp::Mkdir {
            sandbox_id: sandbox.sandbox_id.clone(),
            path: path.into(),
            recursive,
        })
        .await
    }

    pub async fn read_dir(
        &self,
        sandbox: &RemoteSandbox,
        path: impl Into<String>,
    ) -> Result<Vec<lsb_service_proto::ServiceDirEntry>, ClientError> {
        match self
            .request(RequestOp::ReadDir {
                sandbox_id: sandbox.sandbox_id.clone(),
                path: path.into(),
            })
            .await?
        {
            ResponseValue::Directory { entries } => Ok(entries),
            _ => Err(mismatched("ReadDir")),
        }
    }

    pub async fn stat(
        &self,
        sandbox: &RemoteSandbox,
        path: impl Into<String>,
    ) -> Result<lsb_service_proto::ServiceFileStat, ClientError> {
        match self
            .request(RequestOp::Stat {
                sandbox_id: sandbox.sandbox_id.clone(),
                path: path.into(),
            })
            .await?
        {
            ResponseValue::FileStat { stat } => Ok(stat),
            _ => Err(mismatched("Stat")),
        }
    }

    pub async fn remove(
        &self,
        sandbox: &RemoteSandbox,
        path: impl Into<String>,
        recursive: bool,
    ) -> Result<(), ClientError> {
        self.empty_file_request(RequestOp::Remove {
            sandbox_id: sandbox.sandbox_id.clone(),
            path: path.into(),
            recursive,
        })
        .await
    }

    pub async fn rename(
        &self,
        sandbox: &RemoteSandbox,
        old_path: impl Into<String>,
        new_path: impl Into<String>,
    ) -> Result<(), ClientError> {
        self.empty_file_request(RequestOp::Rename {
            sandbox_id: sandbox.sandbox_id.clone(),
            old_path: old_path.into(),
            new_path: new_path.into(),
        })
        .await
    }

    pub async fn copy(
        &self,
        sandbox: &RemoteSandbox,
        src: impl Into<String>,
        dst: impl Into<String>,
        recursive: bool,
    ) -> Result<(), ClientError> {
        self.empty_file_request(RequestOp::Copy {
            sandbox_id: sandbox.sandbox_id.clone(),
            src: src.into(),
            dst: dst.into(),
            recursive,
        })
        .await
    }

    pub async fn chmod(
        &self,
        sandbox: &RemoteSandbox,
        path: impl Into<String>,
        mode: u32,
    ) -> Result<(), ClientError> {
        self.empty_file_request(RequestOp::Chmod {
            sandbox_id: sandbox.sandbox_id.clone(),
            path: path.into(),
            mode,
        })
        .await
    }

    pub async fn exists(
        &self,
        sandbox: &RemoteSandbox,
        path: impl Into<String>,
    ) -> Result<bool, ClientError> {
        match self
            .request(RequestOp::Exists {
                sandbox_id: sandbox.sandbox_id.clone(),
                path: path.into(),
            })
            .await?
        {
            ResponseValue::Exists { exists } => Ok(exists),
            _ => Err(mismatched("Exists")),
        }
    }

    pub async fn read_file(
        &self,
        sandbox: &RemoteSandbox,
        path: impl Into<String>,
    ) -> Result<Vec<u8>, ClientError> {
        self.core
            .read_file(RequestOp::ReadFile {
                sandbox_id: sandbox.sandbox_id.clone(),
                path: path.into(),
            })
            .await
    }

    pub async fn write_file(
        &self,
        sandbox: &RemoteSandbox,
        path: impl Into<String>,
        bytes: &[u8],
    ) -> Result<(), ClientError> {
        if bytes.len() > lsb_service_proto::limits::MAX_FILE_TRANSFER_BYTES {
            return Err(ClientError::Protocol(
                "WriteFile exceeds compiled transfer limit".to_string(),
            ));
        }
        self.core
            .write_file(
                RequestOp::WriteFile {
                    sandbox_id: sandbox.sandbox_id.clone(),
                    path: path.into(),
                    stream_id: random_id()?,
                    length: bytes
                        .len()
                        .try_into()
                        .map_err(|_| ClientError::Protocol("file length overflow".to_string()))?,
                },
                bytes,
            )
            .await
    }

    pub async fn spawn(
        &self,
        sandbox: &RemoteSandbox,
        command: RemoteCommand,
        options: ExecOptions,
    ) -> Result<RemoteProcess, ClientError> {
        let channels = self
            .core
            .spawn(RequestOp::Spawn {
                sandbox_id: sandbox.sandbox_id.clone(),
                command: service_command(command),
                cwd: options.cwd,
                env: options.env,
            })
            .await?;
        Ok(RemoteProcess {
            core: self.core.clone(),
            process_id: channels.process_id,
            stdout_stream_id: channels.stdout_stream_id,
            stderr_stream_id: channels.stderr_stream_id,
            stdout: Arc::new(Mutex::new(channels.stdout)),
            stderr: Arc::new(Mutex::new(channels.stderr)),
            exited: channels.exited,
        })
    }

    pub async fn watch(
        &self,
        sandbox: &RemoteSandbox,
        path: impl Into<String>,
        recursive: bool,
    ) -> Result<RemoteWatch, ClientError> {
        let channels = self
            .core
            .watch(RequestOp::Watch {
                sandbox_id: sandbox.sandbox_id.clone(),
                path: path.into(),
                recursive,
            })
            .await?;
        Ok(RemoteWatch {
            core: self.core.clone(),
            watch_id: channels.watch_id,
            events: Mutex::new(channels.events),
        })
    }

    async fn empty_file_request(&self, op: RequestOp) -> Result<(), ClientError> {
        match self.request(op).await? {
            ResponseValue::Empty {} => Ok(()),
            _ => Err(mismatched("guest file operation")),
        }
    }

    pub async fn close_session(&self) -> Result<(), ClientError> {
        match self.request(RequestOp::CloseSession {}).await? {
            ResponseValue::Empty {} => Ok(()),
            _ => Err(ClientError::Protocol(
                "CloseSession returned a mismatched result".to_string(),
            )),
        }
    }

    async fn request(&self, op: RequestOp) -> Result<ResponseValue, ClientError> {
        match self.core.unary(op).await? {
            Response::Ok { result } => Ok(result),
            Response::Err { error }
                if error.code == lsb_service_proto::ErrorCode::IncompatibleProtocol =>
            {
                Err(ClientError::IncompatibleProtocol)
            }
            Response::Err { error } => Err(map_service_error(error)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UninstallPreparation {
    pub clean: bool,
    pub quarantine_ids: Vec<String>,
}

impl ConnectionCore {
    async fn unary(&self, op: RequestOp) -> Result<Response, ClientError> {
        let (sender, receiver) = oneshot::channel();
        self.send_request(op, PendingRequest::Unary(sender)).await?;
        receiver
            .await
            .map_err(|_| ClientError::Protocol("connection closed before response".to_string()))
    }

    async fn read_file(&self, op: RequestOp) -> Result<Vec<u8>, ClientError> {
        let (sender, receiver) = oneshot::channel();
        self.send_request(op, PendingRequest::ReadFile(sender))
            .await?;
        match receiver
            .await
            .map_err(|_| ClientError::Protocol("connection closed during ReadFile".to_string()))?
        {
            Ok(bytes) => Ok(bytes),
            Err(error) => Err(map_service_error(error)),
        }
    }

    async fn spawn(&self, op: RequestOp) -> Result<SpawnChannels, ClientError> {
        let (sender, receiver) = oneshot::channel();
        self.send_request(op, PendingRequest::Spawn(sender)).await?;
        match receiver
            .await
            .map_err(|_| ClientError::Protocol("connection closed during Spawn".to_string()))?
        {
            Ok(channels) => Ok(channels),
            Err(error) => Err(map_service_error(error)),
        }
    }

    async fn watch(&self, op: RequestOp) -> Result<WatchChannels, ClientError> {
        let (sender, receiver) = oneshot::channel();
        self.send_request(op, PendingRequest::Watch(sender)).await?;
        match receiver
            .await
            .map_err(|_| ClientError::Protocol("connection closed during Watch".to_string()))?
        {
            Ok(channels) => Ok(channels),
            Err(error) => Err(map_service_error(error)),
        }
    }

    async fn stop_watch(&self, watch_id: String) -> Result<Response, ClientError> {
        let (completion, receiver) = oneshot::channel();
        self.send_request(
            RequestOp::StopWatch {
                watch_id: watch_id.clone(),
            },
            PendingRequest::StopWatch {
                watch_id,
                completion,
            },
        )
        .await?;
        receiver
            .await
            .map_err(|_| ClientError::Protocol("connection closed during StopWatch".to_string()))
    }

    async fn write_file(&self, op: RequestOp, bytes: &[u8]) -> Result<(), ClientError> {
        self.ensure_open()?;
        let stream_id = match &op {
            RequestOp::WriteFile { stream_id, .. } => stream_correlation(stream_id)?,
            _ => {
                return Err(ClientError::Protocol(
                    "invalid WriteFile request".to_string(),
                ))
            }
        };
        let (sender, receiver) = oneshot::channel();
        let mut writer = self.writer.lock().await;
        let correlation = {
            let mut pending = self.pending.lock().await;
            if pending.len() >= 16 {
                return Err(ClientError::Protocol(
                    "active request quota exceeded".to_string(),
                ));
            }
            let correlation = self.next_correlation()?;
            pending.insert(correlation.low, PendingRequest::Unary(sender));
            correlation
        };
        let stream_key = correlation_key(stream_id);
        let credit = Arc::new(Semaphore::new(
            lsb_service_proto::limits::INITIAL_STREAM_CREDIT,
        ));
        if self
            .outbound_streams
            .lock()
            .await
            .insert(stream_key, credit.clone())
            .is_some()
        {
            self.pending.lock().await.remove(&correlation.low);
            return Err(ClientError::Protocol("duplicate stream id".to_string()));
        }
        let request = Request {
            deadline_ms: None,
            op,
        };
        let request_written = write_control(
            &mut *writer,
            FrameKind::Request,
            self.protocol,
            correlation,
            &request,
        )
        .await;
        drop(writer);
        let written = match request_written {
            Ok(()) => write_stream(&self.writer, self.protocol, stream_id, bytes, &credit).await,
            Err(error) => Err(error),
        };
        self.outbound_streams.lock().await.remove(&stream_key);
        if let Err(error) = written {
            self.closed.store(true, Ordering::Release);
            self.pending.lock().await.remove(&correlation.low);
            return Err(error);
        }
        let response = receiver
            .await
            .map_err(|_| ClientError::Protocol("connection closed during WriteFile".to_string()))?;
        match response {
            Response::Ok {
                result: ResponseValue::Empty {},
            } => Ok(()),
            Response::Ok { .. } => Err(mismatched("WriteFile")),
            Response::Err { error } => Err(map_service_error(error)),
        }
    }

    async fn send_request(
        &self,
        op: RequestOp,
        pending: PendingRequest,
    ) -> Result<Correlation, ClientError> {
        self.ensure_open()?;
        let mut writer = self.writer.lock().await;
        let correlation = {
            let mut active = self.pending.lock().await;
            if active.len() >= 16 {
                return Err(ClientError::Protocol(
                    "active request quota exceeded".to_string(),
                ));
            }
            let correlation = self.next_correlation()?;
            active.insert(correlation.low, pending);
            correlation
        };
        let result = write_control(
            &mut *writer,
            FrameKind::Request,
            self.protocol,
            correlation,
            &Request {
                deadline_ms: None,
                op,
            },
        )
        .await;
        if result.is_err() {
            self.closed.store(true, Ordering::Release);
            self.pending.lock().await.remove(&correlation.low);
        }
        result?;
        Ok(correlation)
    }

    async fn cancel_request(&self, request_id: String) -> Result<(), ClientError> {
        let target = stream_correlation(&request_id)?;
        if target.high != self.epoch {
            return Err(ClientError::Protocol(
                "cancel request epoch mismatch".to_string(),
            ));
        }
        let (sender, receiver) = oneshot::channel();
        self.ensure_open()?;
        let mut writer = self.writer.lock().await;
        let correlation = {
            let mut active = self.pending.lock().await;
            if active.len() >= 16 {
                return Err(ClientError::Protocol(
                    "active request quota exceeded".to_string(),
                ));
            }
            let correlation = self.next_correlation()?;
            active.insert(correlation.low, PendingRequest::Unary(sender));
            correlation
        };
        let result = write_control(
            &mut *writer,
            FrameKind::Cancel,
            self.protocol,
            correlation,
            &Cancel { request_id },
        )
        .await;
        if result.is_err() {
            self.closed.store(true, Ordering::Release);
            self.pending.lock().await.remove(&correlation.low);
        }
        result?;
        match receiver
            .await
            .map_err(|_| ClientError::Protocol("connection closed during Cancel".to_string()))?
        {
            Response::Ok {
                result: ResponseValue::Empty {},
            } => Ok(()),
            Response::Ok { .. } => Err(mismatched("Cancel")),
            Response::Err { error } => Err(map_service_error(error)),
        }
    }

    async fn window_update(&self, stream_id: &str, bytes: usize) -> Result<(), ClientError> {
        self.ensure_open()?;
        let credit_bytes = u32::try_from(bytes)
            .map_err(|_| ClientError::Protocol("stream credit overflow".to_string()))?;
        let update = WindowUpdate {
            stream_id: stream_id.to_string(),
            credit_bytes,
        };
        update.validate()?;
        let mut writer = self.writer.lock().await;
        let correlation = self.next_correlation()?;
        let result = write_control(
            &mut *writer,
            FrameKind::WindowUpdate,
            self.protocol,
            correlation,
            &update,
        )
        .await;
        if result.is_err() {
            self.closed.store(true, Ordering::Release);
        }
        result
    }

    async fn grant_outbound(&self, update: WindowUpdate) -> Result<(), ClientError> {
        update.validate()?;
        let key = correlation_key(stream_correlation(&update.stream_id)?);
        let streams = self.outbound_streams.lock().await;
        let Some(credit) = streams.get(&key) else {
            return Ok(());
        };
        let bytes = update.credit_bytes as usize;
        if credit.available_permits().saturating_add(bytes) > 4 * 1024 * 1024 {
            return Err(ClientError::Protocol(
                "outbound stream credit exceeds maximum window".to_string(),
            ));
        }
        credit.add_permits(bytes);
        Ok(())
    }

    fn next_correlation(&self) -> Result<Correlation, ClientError> {
        let sequence = self.next_sequence.fetch_add(1, Ordering::Relaxed);
        if sequence == 0 || sequence == u64::MAX {
            return Err(ClientError::Protocol(
                "request sequence exhausted".to_string(),
            ));
        }
        Ok(Correlation {
            high: self.epoch,
            low: sequence,
        })
    }

    fn ensure_open(&self) -> Result<(), ClientError> {
        if self.closed.load(Ordering::Acquire) {
            Err(ClientError::Protocol(
                "service connection is closed".to_string(),
            ))
        } else {
            Ok(())
        }
    }
}

fn service_command(command: RemoteCommand) -> lsb_service_proto::ServiceCommand {
    match command {
        RemoteCommand::Argv(argv) => {
            lsb_service_proto::ServiceCommand::Argv(lsb_service_proto::ArgvCommand { argv })
        }
        RemoteCommand::Shell(shell) => {
            lsb_service_proto::ServiceCommand::Shell(lsb_service_proto::ShellCommand { shell })
        }
    }
}

fn mismatched(operation: &str) -> ClientError {
    ClientError::Protocol(format!("{operation} returned a mismatched result"))
}

fn map_service_error(error: lsb_service_proto::ErrorEnvelope) -> ClientError {
    if error.code == lsb_service_proto::ErrorCode::IncompatibleProtocol {
        ClientError::IncompatibleProtocol
    } else {
        ClientError::Service(error)
    }
}

fn stream_correlation(stream_id: &str) -> Result<Correlation, ClientError> {
    if stream_id.len() != 32 {
        return Err(ClientError::Protocol("invalid stream id".to_string()));
    }
    Ok(Correlation {
        high: u64::from_str_radix(&stream_id[..16], 16)
            .map_err(|_| ClientError::Protocol("invalid stream id".to_string()))?,
        low: u64::from_str_radix(&stream_id[16..], 16)
            .map_err(|_| ClientError::Protocol("invalid stream id".to_string()))?,
    })
}

fn random_id() -> Result<String, ClientError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|error| ClientError::Protocol(format!("generate stream id: {error}")))?;
    if bytes == [0; 16] {
        return Err(ClientError::Protocol(
            "generated zero stream id".to_string(),
        ));
    }
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

async fn write_stream<W>(
    writer: &Mutex<W>,
    protocol: ProtocolVersion,
    correlation: Correlation,
    bytes: &[u8],
    credit: &Arc<Semaphore>,
) -> Result<(), ClientError>
where
    W: AsyncWrite + Unpin,
{
    let chunk_size = lsb_service_proto::limits::MAX_STREAM_PAYLOAD
        - lsb_service_proto::limits::STREAM_SEQUENCE_LEN;
    for (sequence, chunk) in bytes.chunks(chunk_size).enumerate() {
        let permits = u32::try_from(chunk.len())
            .map_err(|_| ClientError::Protocol("stream chunk length overflow".to_string()))?;
        let permit = tokio::time::timeout(
            Duration::from_secs(60),
            credit.clone().acquire_many_owned(permits),
        )
        .await
        .map_err(|_| ClientError::Protocol("stream credit timeout".to_string()))?
        .map_err(|_| ClientError::Protocol("stream credit closed".to_string()))?;
        permit.forget();
        let payload = lsb_service_proto::encode_stream_payload(
            sequence
                .try_into()
                .map_err(|_| ClientError::Protocol("stream sequence overflow".to_string()))?,
            chunk,
        )?;
        let header = FrameHeader {
            kind: FrameKind::StreamData,
            flags: 0,
            protocol,
            payload_len: payload
                .len()
                .try_into()
                .map_err(|_| ClientError::Protocol("payload length overflow".to_string()))?,
            correlation,
        }
        .encode()?;
        let mut pipe = writer.lock().await;
        pipe.write_all(&header).await?;
        pipe.write_all(&payload).await?;
        pipe.flush().await?;
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct StartSandboxOptions {
    pub cpus: u16,
    pub memory_mib: u32,
    pub disk_mib: u32,
    pub mounts: Vec<lsb_service_proto::ServiceMountSpec>,
    pub ports: Vec<lsb_service_proto::ServicePortSpec>,
    pub network: Option<lsb_service_proto::ServiceNetworkSpec>,
}

impl Default for StartSandboxOptions {
    fn default() -> Self {
        Self {
            cpus: 2,
            memory_mib: 2048,
            disk_mib: 4096,
            mounts: Vec::new(),
            ports: Vec::new(),
            network: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSandbox {
    sandbox_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteCommand {
    Argv(Vec<String>),
    Shell(String),
}

#[derive(Debug, Clone, Default)]
pub struct ExecOptions {
    pub cwd: Option<String>,
    pub env: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteExecResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

pub struct RemoteProcess {
    core: Arc<ConnectionCore>,
    process_id: String,
    stdout_stream_id: String,
    stderr_stream_id: String,
    stdout: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
    stderr: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
    exited: watch::Receiver<Option<i32>>,
}

pub struct RemoteExecOperation {
    core: Arc<ConnectionCore>,
    request_id: String,
    response: Mutex<Option<oneshot::Receiver<Response>>>,
}

impl RemoteExecOperation {
    pub fn id(&self) -> &str {
        &self.request_id
    }

    pub async fn cancel(&self) -> Result<(), ClientError> {
        self.core.cancel_request(self.request_id.clone()).await
    }

    pub async fn complete(&self) -> Result<RemoteExecResult, ClientError> {
        let receiver = self.response.lock().await.take().ok_or_else(|| {
            ClientError::Protocol("exec operation was already completed".to_string())
        })?;
        match receiver
            .await
            .map_err(|_| ClientError::Protocol("connection closed during Exec".to_string()))?
        {
            Response::Ok {
                result:
                    ResponseValue::ExecCompleted {
                        stdout,
                        stderr,
                        exit_code,
                    },
            } => Ok(RemoteExecResult {
                stdout,
                stderr,
                exit_code,
            }),
            Response::Ok { .. } => Err(mismatched("Exec")),
            Response::Err { error } => Err(map_service_error(error)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteWatchEvent {
    pub path: String,
    pub change: lsb_service_proto::WatchChange,
}

pub struct RemoteWatch {
    core: Arc<ConnectionCore>,
    watch_id: String,
    events: Mutex<watch::Receiver<Option<RemoteWatchEvent>>>,
}

impl RemoteWatch {
    pub fn id(&self) -> &str {
        &self.watch_id
    }

    pub async fn next(&self) -> Result<Option<RemoteWatchEvent>, ClientError> {
        let mut events = self.events.lock().await;
        if events.changed().await.is_err() {
            return Ok(None);
        }
        let event = events.borrow_and_update().clone();
        Ok(event)
    }

    pub async fn stop(&self) -> Result<(), ClientError> {
        match self.core.stop_watch(self.watch_id.clone()).await? {
            Response::Ok {
                result: ResponseValue::Empty {},
            } => Ok(()),
            Response::Ok { .. } => Err(mismatched("StopWatch")),
            Response::Err { error } => Err(map_service_error(error)),
        }
    }
}

impl RemoteProcess {
    pub fn id(&self) -> &str {
        &self.process_id
    }

    pub async fn next_stdout(&self) -> Result<Option<Vec<u8>>, ClientError> {
        let Some(bytes) = self.stdout.lock().await.recv().await else {
            return Ok(None);
        };
        self.core
            .window_update(&self.stdout_stream_id, bytes.len())
            .await?;
        Ok(Some(bytes))
    }

    pub async fn next_stderr(&self) -> Result<Option<Vec<u8>>, ClientError> {
        let Some(bytes) = self.stderr.lock().await.recv().await else {
            return Ok(None);
        };
        self.core
            .window_update(&self.stderr_stream_id, bytes.len())
            .await?;
        Ok(Some(bytes))
    }

    pub async fn kill(&self) -> Result<(), ClientError> {
        match self
            .core
            .unary(RequestOp::KillProcess {
                process_id: self.process_id.clone(),
            })
            .await?
        {
            Response::Ok {
                result: ResponseValue::Empty {},
            } => Ok(()),
            Response::Ok { .. } => Err(mismatched("KillProcess")),
            Response::Err { error } => Err(map_service_error(error)),
        }
    }

    pub async fn exited(&self) -> Result<i32, ClientError> {
        let mut exited = self.exited.clone();
        if let Some(code) = *exited.borrow() {
            return Ok(code);
        }
        loop {
            exited.changed().await.map_err(|_| {
                ClientError::Protocol("connection closed before process exit".to_string())
            })?;
            if let Some(code) = *exited.borrow() {
                return Ok(code);
            }
        }
    }
}

impl RemoteSandbox {
    pub fn id(&self) -> &str {
        &self.sandbox_id
    }
}

async fn read_loop(
    mut reader: tokio::io::ReadHalf<NamedPipeClient>,
    core: Weak<ConnectionCore>,
    mut shutdown: watch::Receiver<()>,
) {
    let _ = dispatch_frames(&mut reader, &core, &mut shutdown).await;
    if let Some(core) = core.upgrade() {
        core.closed.store(true, Ordering::Release);
        core.pending.lock().await.clear();
        core.outbound_streams.lock().await.clear();
    }
}

async fn dispatch_frames<R>(
    reader: &mut R,
    core: &Weak<ConnectionCore>,
    shutdown: &mut watch::Receiver<()>,
) -> Result<(), ClientError>
where
    R: AsyncRead + Unpin,
{
    let mut streams = HashMap::<(u64, u64), IncomingStream>::new();
    let mut processes = HashMap::<String, watch::Sender<Option<i32>>>::new();
    let mut watches = HashMap::<String, watch::Sender<Option<RemoteWatchEvent>>>::new();
    let mut next_server_sequence = 1u64;
    loop {
        let frame = tokio::select! {
            frame = read_frame(reader) => frame?,
            _ = shutdown.changed() => return Ok(()),
        };
        let Some(core) = core.upgrade() else {
            return Ok(());
        };
        if frame.header.protocol != core.protocol {
            return Err(ClientError::Protocol(
                "incoming frame protocol mismatch".to_string(),
            ));
        }
        if matches!(
            frame.header.kind,
            FrameKind::Event | FrameKind::WindowUpdate
        ) {
            if frame.header.correlation.high != core.epoch
                || frame.header.correlation.low != next_server_sequence
            {
                return Err(ClientError::Protocol(
                    "server control sequence mismatch".to_string(),
                ));
            }
            next_server_sequence = next_server_sequence.checked_add(1).ok_or_else(|| {
                ClientError::Protocol("server control sequence exhausted".to_string())
            })?;
        }
        match frame.header.kind {
            FrameKind::Response => {
                if frame.header.correlation.high != core.epoch {
                    return Err(ClientError::Protocol("response epoch mismatch".to_string()));
                }
                let pending = core
                    .pending
                    .lock()
                    .await
                    .remove(&frame.header.correlation.low)
                    .ok_or_else(|| {
                        ClientError::Protocol("response request is not active".to_string())
                    })?;
                let response: Response = parse_control(&frame.payload)?;
                dispatch_response(
                    pending,
                    response,
                    &mut streams,
                    &mut processes,
                    &mut watches,
                )?;
            }
            FrameKind::StreamData => {
                if let Some((stream_id, consumed)) = dispatch_stream(frame, &mut streams)? {
                    core.window_update(&stream_id, consumed).await?;
                }
            }
            FrameKind::WindowUpdate => {
                let update: WindowUpdate = parse_control(&frame.payload)?;
                core.grant_outbound(update).await?;
            }
            FrameKind::Event => {
                let event: Event = parse_control(&frame.payload)?;
                event.validate()?;
                match event {
                    Event::ProcessExited {
                        process_id,
                        exit_code,
                    } => {
                        let exited = processes.remove(&process_id).ok_or_else(|| {
                            ClientError::Protocol("process exit handle is unknown".to_string())
                        })?;
                        let _ = exited.send(Some(exit_code));
                    }
                    Event::StreamClosed { stream_id } => {
                        streams.remove(&correlation_key(stream_correlation(&stream_id)?));
                        watches.remove(&stream_id);
                    }
                    Event::WatchChanged {
                        watch_id,
                        path,
                        change,
                    } => {
                        let events = watches.get(&watch_id).ok_or_else(|| {
                            ClientError::Protocol("watch event handle is unknown".to_string())
                        })?;
                        let _ = events.send(Some(RemoteWatchEvent { path, change }));
                    }
                }
            }
            _ => {
                return Err(ClientError::Protocol(
                    "unexpected server frame direction".to_string(),
                ));
            }
        }
    }
}

fn dispatch_response(
    pending: PendingRequest,
    response: Response,
    streams: &mut HashMap<(u64, u64), IncomingStream>,
    processes: &mut HashMap<String, watch::Sender<Option<i32>>>,
    watches: &mut HashMap<String, watch::Sender<Option<RemoteWatchEvent>>>,
) -> Result<(), ClientError> {
    match pending {
        PendingRequest::Unary(sender) => {
            let _ = sender.send(response);
        }
        PendingRequest::ReadFile(sender) => match response {
            Response::Err { error } => {
                let _ = sender.send(Err(error));
            }
            Response::Ok {
                result: ResponseValue::FileRead { stream_id, length },
            } => {
                let length = length as usize;
                if length > lsb_service_proto::limits::MAX_FILE_TRANSFER_BYTES {
                    return Err(ClientError::Protocol(
                        "ReadFile exceeded compiled transfer limit".to_string(),
                    ));
                }
                if length == 0 {
                    let _ = sender.send(Ok(Vec::new()));
                } else {
                    let key = correlation_key(stream_correlation(&stream_id)?);
                    if streams
                        .insert(
                            key,
                            IncomingStream::File {
                                sequence: 0,
                                length,
                                bytes: Vec::with_capacity(length),
                                completion: Some(sender),
                            },
                        )
                        .is_some()
                    {
                        return Err(ClientError::Protocol("duplicate stream id".to_string()));
                    }
                }
            }
            Response::Ok { .. } => return Err(mismatched("ReadFile")),
        },
        PendingRequest::Spawn(sender) => match response {
            Response::Err { error } => {
                let _ = sender.send(Err(error));
            }
            Response::Ok {
                result:
                    ResponseValue::ProcessStarted {
                        process_id,
                        stdout_stream_id,
                        stderr_stream_id,
                    },
            } => {
                let stdout_key = correlation_key(stream_correlation(&stdout_stream_id)?);
                let stderr_key = correlation_key(stream_correlation(&stderr_stream_id)?);
                if stdout_key == stderr_key
                    || streams.contains_key(&stdout_key)
                    || streams.contains_key(&stderr_key)
                    || processes.contains_key(&process_id)
                {
                    return Err(ClientError::Protocol(
                        "duplicate process or stream id".to_string(),
                    ));
                }
                let (stdout_tx, stdout) = mpsc::channel(8);
                let (stderr_tx, stderr) = mpsc::channel(8);
                let (exited_tx, exited) = watch::channel(None);
                streams.insert(
                    stdout_key,
                    IncomingStream::Process {
                        sequence: 0,
                        chunks: stdout_tx,
                    },
                );
                streams.insert(
                    stderr_key,
                    IncomingStream::Process {
                        sequence: 0,
                        chunks: stderr_tx,
                    },
                );
                processes.insert(process_id.clone(), exited_tx);
                let _ = sender.send(Ok(SpawnChannels {
                    process_id,
                    stdout_stream_id,
                    stderr_stream_id,
                    stdout,
                    stderr,
                    exited,
                }));
            }
            Response::Ok { .. } => return Err(mismatched("Spawn")),
        },
        PendingRequest::Watch(sender) => match response {
            Response::Err { error } => {
                let _ = sender.send(Err(error));
            }
            Response::Ok {
                result: ResponseValue::WatchStarted { watch_id },
            } => {
                if watches.contains_key(&watch_id) {
                    return Err(ClientError::Protocol("duplicate watch id".to_string()));
                }
                let (events_tx, events) = watch::channel(None);
                watches.insert(watch_id.clone(), events_tx);
                let _ = sender.send(Ok(WatchChannels { watch_id, events }));
            }
            Response::Ok { .. } => return Err(mismatched("Watch")),
        },
        PendingRequest::StopWatch {
            watch_id,
            completion,
        } => {
            if matches!(response, Response::Ok { .. }) {
                watches.remove(&watch_id);
            }
            let _ = completion.send(response);
        }
    }
    Ok(())
}

fn dispatch_stream(
    frame: WireFrame,
    streams: &mut HashMap<(u64, u64), IncomingStream>,
) -> Result<Option<(String, usize)>, ClientError> {
    let key = correlation_key(frame.header.correlation);
    let stream_id = correlation_id(frame.header.correlation);
    let (received_sequence, chunk) = decode_stream_payload(&frame.payload)?;
    let mut completed_file = None;
    let mut replenish = None;
    match streams
        .get_mut(&key)
        .ok_or_else(|| ClientError::Protocol("stream id is unknown".to_string()))?
    {
        IncomingStream::File {
            sequence,
            length,
            bytes,
            completion,
        } => {
            if received_sequence != *sequence
                || chunk.is_empty()
                || bytes.len().saturating_add(chunk.len()) > *length
            {
                return Err(ClientError::Protocol(
                    "file stream sequence/length mismatch".to_string(),
                ));
            }
            *sequence = sequence
                .checked_add(1)
                .ok_or_else(|| ClientError::Protocol("stream sequence exhausted".to_string()))?;
            bytes.extend_from_slice(chunk);
            if bytes.len() == *length {
                completed_file = Some((
                    completion.take().ok_or_else(|| {
                        ClientError::Protocol("file stream completed twice".to_string())
                    })?,
                    std::mem::take(bytes),
                ));
            } else {
                replenish = Some((stream_id, chunk.len()));
            }
        }
        IncomingStream::Process { sequence, chunks } => {
            if received_sequence != *sequence {
                return Err(ClientError::Protocol(
                    "process stream sequence mismatch".to_string(),
                ));
            }
            *sequence = sequence
                .checked_add(1)
                .ok_or_else(|| ClientError::Protocol("stream sequence exhausted".to_string()))?;
            match chunks.try_send(chunk.to_vec()) {
                Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    return Err(ClientError::Protocol(
                        "process stream exceeded client buffer".to_string(),
                    ));
                }
            }
        }
    }
    if let Some((completion, bytes)) = completed_file {
        streams.remove(&key);
        let _ = completion.send(Ok(bytes));
    }
    Ok(replenish)
}

fn correlation_key(correlation: Correlation) -> (u64, u64) {
    (correlation.high, correlation.low)
}

fn correlation_id(correlation: Correlation) -> String {
    format!("{:016x}{:016x}", correlation.high, correlation.low)
}

struct WireFrame {
    header: FrameHeader,
    payload: Vec<u8>,
}

async fn read_frame<R>(pipe: &mut R) -> Result<WireFrame, ClientError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; HEADER_LEN];
    tokio::time::timeout(Duration::from_secs(65), pipe.read_exact(&mut header))
        .await
        .map_err(|_| ClientError::Protocol("frame header timeout".to_string()))??;
    let header = FrameHeader::decode(header)?;
    let mut payload = vec![0u8; header.payload_len as usize];
    tokio::time::timeout(Duration::from_secs(10), pipe.read_exact(&mut payload))
        .await
        .map_err(|_| ClientError::Protocol("frame payload timeout".to_string()))??;
    Ok(WireFrame { header, payload })
}

async fn write_control<W>(
    pipe: &mut W,
    kind: FrameKind,
    protocol: ProtocolVersion,
    correlation: Correlation,
    value: &impl serde::Serialize,
) -> Result<(), ClientError>
where
    W: AsyncWrite + Unpin,
{
    let payload = serde_json::to_vec(value)?;
    let header = FrameHeader {
        kind,
        flags: 0,
        protocol,
        payload_len: payload
            .len()
            .try_into()
            .map_err(|_| ClientError::Protocol("payload length overflow".to_string()))?,
        correlation,
    }
    .encode()?;
    pipe.write_all(&header).await?;
    pipe.write_all(&payload).await?;
    pipe.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIRST: &str = "0123456789abcdef0123456789abcdef";
    const SECOND: &str = "fedcba9876543210fedcba9876543210";
    const THIRD: &str = "00112233445566778899aabbccddeeff";

    #[test]
    fn service_client_is_shareable_across_concurrent_callers() {
        fn assert_send_sync<T: Send + Sync>() {}

        assert_send_sync::<ServiceClient>();
    }

    #[tokio::test]
    async fn upload_credit_wait_does_not_hold_the_transport_writer() {
        let (pipe, _peer) = tokio::io::duplex(1024);
        let writer = Arc::new(Mutex::new(pipe));
        let credit = Arc::new(Semaphore::new(0));
        let upload = tokio::spawn({
            let writer = writer.clone();
            let credit = credit.clone();
            async move { write_stream(&writer, CURRENT, Correlation::default(), b"x", &credit).await }
        });

        tokio::task::yield_now().await;
        let guard = tokio::time::timeout(Duration::from_millis(100), writer.lock())
            .await
            .expect("credit wait must not retain the transport writer");
        drop(guard);
        upload.abort();
    }

    #[test]
    fn read_file_route_exists_before_stream_data_arrives() {
        let (sender, mut receiver) = oneshot::channel();
        let mut streams = HashMap::new();
        let mut processes = HashMap::new();
        let mut watches = HashMap::new();
        dispatch_response(
            PendingRequest::ReadFile(sender),
            Response::Ok {
                result: ResponseValue::FileRead {
                    stream_id: FIRST.to_string(),
                    length: 3,
                },
            },
            &mut streams,
            &mut processes,
            &mut watches,
        )
        .unwrap();
        assert_eq!(streams.len(), 1);

        let payload = lsb_service_proto::encode_stream_payload(0, b"abc").unwrap();
        let replenished = dispatch_stream(
            WireFrame {
                header: FrameHeader {
                    kind: FrameKind::StreamData,
                    flags: 0,
                    protocol: CURRENT,
                    payload_len: payload.len() as u32,
                    correlation: stream_correlation(FIRST).unwrap(),
                },
                payload,
            },
            &mut streams,
        )
        .unwrap();
        assert!(replenished.is_none());
        assert_eq!(receiver.try_recv().unwrap().unwrap(), b"abc".to_vec());
        assert!(streams.is_empty());
    }

    #[test]
    fn read_file_replenishes_credit_before_the_final_chunk() {
        let (sender, mut receiver) = oneshot::channel();
        let mut streams = HashMap::new();
        let mut processes = HashMap::new();
        let mut watches = HashMap::new();
        dispatch_response(
            PendingRequest::ReadFile(sender),
            Response::Ok {
                result: ResponseValue::FileRead {
                    stream_id: FIRST.to_string(),
                    length: 4,
                },
            },
            &mut streams,
            &mut processes,
            &mut watches,
        )
        .unwrap();

        let payload = lsb_service_proto::encode_stream_payload(0, b"abc").unwrap();
        let replenished = dispatch_stream(
            WireFrame {
                header: FrameHeader {
                    kind: FrameKind::StreamData,
                    flags: 0,
                    protocol: CURRENT,
                    payload_len: payload.len() as u32,
                    correlation: stream_correlation(FIRST).unwrap(),
                },
                payload,
            },
            &mut streams,
        )
        .unwrap();
        assert_eq!(replenished, Some((FIRST.to_string(), 3)));
        assert!(receiver.try_recv().is_err());
        assert_eq!(streams.len(), 1);
    }

    #[test]
    fn spawn_installs_both_bounded_stream_routes_before_reply() {
        let (sender, mut receiver) = oneshot::channel();
        let mut streams = HashMap::new();
        let mut processes = HashMap::new();
        let mut watches = HashMap::new();
        dispatch_response(
            PendingRequest::Spawn(sender),
            Response::Ok {
                result: ResponseValue::ProcessStarted {
                    process_id: FIRST.to_string(),
                    stdout_stream_id: SECOND.to_string(),
                    stderr_stream_id: THIRD.to_string(),
                },
            },
            &mut streams,
            &mut processes,
            &mut watches,
        )
        .unwrap();
        assert_eq!(streams.len(), 2);
        assert_eq!(processes.len(), 1);
        let mut channels = receiver.try_recv().unwrap().unwrap();

        let payload = lsb_service_proto::encode_stream_payload(0, b"out").unwrap();
        let replenished = dispatch_stream(
            WireFrame {
                header: FrameHeader {
                    kind: FrameKind::StreamData,
                    flags: 0,
                    protocol: CURRENT,
                    payload_len: payload.len() as u32,
                    correlation: stream_correlation(SECOND).unwrap(),
                },
                payload,
            },
            &mut streams,
        )
        .unwrap();
        assert!(replenished.is_none());
        assert_eq!(channels.stdout.try_recv().unwrap(), b"out".to_vec());
    }

    #[test]
    fn watch_route_is_installed_before_start_reply() {
        let (sender, mut receiver) = oneshot::channel();
        let mut streams = HashMap::new();
        let mut processes = HashMap::new();
        let mut watches = HashMap::new();
        dispatch_response(
            PendingRequest::Watch(sender),
            Response::Ok {
                result: ResponseValue::WatchStarted {
                    watch_id: FIRST.to_string(),
                },
            },
            &mut streams,
            &mut processes,
            &mut watches,
        )
        .unwrap();
        assert!(watches.contains_key(FIRST));
        let channels = receiver.try_recv().unwrap().unwrap();
        assert_eq!(channels.watch_id, FIRST);
    }

    #[test]
    fn cancellable_request_id_round_trips_full_correlation() {
        let correlation = Correlation {
            high: 0x0123_4567_89ab_cdef,
            low: 0xfedc_ba98_7654_3210,
        };
        let request_id = correlation_id(correlation);
        assert_eq!(request_id, "0123456789abcdeffedcba9876543210");
        assert_eq!(stream_correlation(&request_id).unwrap(), correlation);
    }
}
