use std::time::Duration;

use lsb_service_proto::limits::HEADER_LEN;
use lsb_service_proto::{
    parse_control, Correlation, FrameHeader, FrameKind, Health, Hello, HelloReply, HexU64,
    ProtocolVersion, Request, RequestOp, Response, ResponseValue, ServiceInfo, CURRENT, SUPPORTED,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::NamedPipeClient;

use crate::pipe::open_verified;
use crate::{ClientError, ConnectOptions};

pub struct ServiceClient {
    pipe: NamedPipeClient,
    protocol: ProtocolVersion,
    epoch: u64,
    next_sequence: u64,
    info: ServiceInfo,
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
        let mut client = Self {
            pipe,
            protocol,
            epoch,
            next_sequence: 1,
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

    pub async fn get_service_info(&mut self) -> Result<ServiceInfo, ClientError> {
        match self.request(RequestOp::GetServiceInfo {}).await? {
            ResponseValue::ServiceInfo { info } => Ok(info),
            _ => Err(ClientError::Protocol(
                "GetServiceInfo returned a mismatched result".to_string(),
            )),
        }
    }

    pub async fn health_check(&mut self) -> Result<Health, ClientError> {
        match self.request(RequestOp::HealthCheck {}).await? {
            ResponseValue::Health { health } => Ok(health),
            _ => Err(ClientError::Protocol(
                "HealthCheck returned a mismatched result".to_string(),
            )),
        }
    }

    pub async fn start_sandbox(
        &mut self,
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

    pub async fn stop_sandbox(&mut self, sandbox: &RemoteSandbox) -> Result<(), ClientError> {
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

    pub async fn close_session(&mut self) -> Result<(), ClientError> {
        match self.request(RequestOp::CloseSession {}).await? {
            ResponseValue::Empty {} => Ok(()),
            _ => Err(ClientError::Protocol(
                "CloseSession returned a mismatched result".to_string(),
            )),
        }
    }

    async fn request(&mut self, op: RequestOp) -> Result<ResponseValue, ClientError> {
        let sequence = self.next_sequence;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| ClientError::Protocol("request sequence exhausted".to_string()))?;
        let correlation = Correlation {
            high: self.epoch,
            low: sequence,
        };
        write_control(
            &mut self.pipe,
            FrameKind::Request,
            self.protocol,
            correlation,
            &Request {
                deadline_ms: None,
                op,
            },
        )
        .await?;
        let frame = read_frame(&mut self.pipe).await?;
        if frame.header.kind != FrameKind::Response
            || frame.header.protocol != self.protocol
            || frame.header.correlation != correlation
        {
            return Err(ClientError::Protocol(
                "response correlation/version mismatch".to_string(),
            ));
        }
        match parse_control::<Response>(&frame.payload)? {
            Response::Ok { result } => Ok(result),
            Response::Err { error }
                if error.code == lsb_service_proto::ErrorCode::IncompatibleProtocol =>
            {
                Err(ClientError::IncompatibleProtocol)
            }
            Response::Err { error } => Err(ClientError::Protocol(error.message)),
        }
    }
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

impl RemoteSandbox {
    pub fn id(&self) -> &str {
        &self.sandbox_id
    }
}

struct WireFrame {
    header: FrameHeader,
    payload: Vec<u8>,
}

async fn read_frame(pipe: &mut NamedPipeClient) -> Result<WireFrame, ClientError> {
    let mut header = [0u8; HEADER_LEN];
    tokio::time::timeout(Duration::from_secs(5), pipe.read_exact(&mut header))
        .await
        .map_err(|_| ClientError::Protocol("frame header timeout".to_string()))??;
    let header = FrameHeader::decode(header)?;
    let mut payload = vec![0u8; header.payload_len as usize];
    tokio::time::timeout(Duration::from_secs(10), pipe.read_exact(&mut payload))
        .await
        .map_err(|_| ClientError::Protocol("frame payload timeout".to_string()))??;
    Ok(WireFrame { header, payload })
}

async fn write_control(
    pipe: &mut NamedPipeClient,
    kind: FrameKind,
    protocol: ProtocolVersion,
    correlation: Correlation,
    value: &impl serde::Serialize,
) -> Result<(), ClientError> {
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
