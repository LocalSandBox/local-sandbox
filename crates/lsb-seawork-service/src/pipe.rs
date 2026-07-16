use std::ffi::c_void;
use std::os::windows::io::AsRawHandle;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use lsb_service_proto::frame::HEADER_VERSION;
use lsb_service_proto::limits::HEADER_LEN;
use lsb_service_proto::{
    negotiate, parse_control, CapabilityHealth, Correlation, ErrorCode, ErrorEnvelope, FrameHeader,
    FrameKind, Health, HealthState, Hello, HelloReply, HexU64, ProtocolRange, Request, RequestOp,
    Response, ResponseValue, ServiceInfo, CURRENT, SUPPORTED,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};
use tokio::sync::oneshot;
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

use crate::security::descriptor::SecurityDescriptor;
use crate::security::ClientIdentity;
use crate::session::{ClientIdentityKey, QuotaLimits, ResourceHandle, SessionManager};
use crate::{engine::ServiceEngineConfig, rpc};
use crate::{LEDGER_SCHEMA_VERSION, PIPE_NAME, PIPE_SDDL};

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

async fn handle_client(mut pipe: NamedPipeServer, context: HealthContext) -> Result<()> {
    let identity = ClientIdentity::from_named_pipe(pipe.as_raw_handle())?;
    let session_id = context.sessions.open(identity.key.clone())?;
    let result = handle_authenticated_client(&mut pipe, &context, session_id, &identity.key).await;
    let _ = context.sessions.close(session_id, &identity.key);
    result
}

async fn handle_authenticated_client(
    pipe: &mut NamedPipeServer,
    context: &HealthContext,
    session_id: ResourceHandle,
    identity: &ClientIdentityKey,
) -> Result<()> {
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
        pipe,
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
        if frame.header.kind != FrameKind::Request
            || frame.header.protocol != selected
            || frame.header.correlation.high != epoch
            || frame.header.correlation.low != expected_sequence
        {
            bail!("invalid health request direction, version, or sequence");
        }
        expected_sequence = expected_sequence
            .checked_add(1)
            .context("health request sequence exhausted")?;
        let request: Request = parse_control(&frame.payload)?;
        if request.validate().is_err() {
            write_error(
                pipe,
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
                        write_error(pipe, selected, frame.header.correlation, code).await?;
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
                    write_error(pipe, selected, frame.header.correlation, code).await?;
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
                    write_error(pipe, selected, frame.header.correlation, code).await?;
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
                    write_error(pipe, selected, frame.header.correlation, code).await?;
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
            RequestOp::CloseSession {} => {
                write_control(
                    pipe,
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
            pipe,
            FrameKind::Response,
            selected,
            frame.header.correlation,
            &Response::Ok { result },
        )
        .await?;
    }
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
    pipe: &mut NamedPipeServer,
    protocol: lsb_service_proto::ProtocolVersion,
    correlation: Correlation,
    code: ErrorCode,
) -> Result<()> {
    write_control(
        pipe,
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

async fn read_frame(pipe: &mut NamedPipeServer) -> Result<WireFrame> {
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
    pipe: &mut NamedPipeServer,
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
    pipe.write_all(&header).await?;
    pipe.write_all(&payload).await?;
    pipe.flush().await?;
    Ok(())
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
}
