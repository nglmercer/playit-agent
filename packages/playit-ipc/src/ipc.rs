//! IPC protocol for communication between CLI and background service.

use std::io;

use futures_util::{SinkExt, StreamExt};
use interprocess::local_socket::{
    GenericFilePath, GenericNamespaced, ToFsName, ToNsName,
    tokio::{Stream, prelude::*},
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{FramedRead, FramedWrite, LinesCodec, LinesCodecError};

use crate::endpoint::IpcEndpoint;
use crate::model::{
    AccountLoginUrlResponse, AccountResponse, AccountTunnelListResponse, AgentLifecycle,
    ClaimResponse, CommandResponse, ProtocolInfo, SecretPathResponse, ServiceError, ServiceStatus,
    ServiceUpdate, SubscribeResponse, TunnelCreateResponse, TunnelListResponse, TunnelProtocol,
};

pub const IPC_VERSION: u32 = 3;

const UPDATE_STATUS: &str = "status";
const UPDATE_LIFECYCLE: &str = "lifecycle";
const UPDATE_STATS: &str = "stats";
const UPDATE_LOG: &str = "log";

#[derive(Debug)]
pub enum IpcError {
    AlreadyRunning,
    BindFailed(io::Error),
    ConnectionFailed(io::Error),
    IoError(io::Error),
    JsonError(serde_json::Error),
    NotRunning,
    ProtocolMismatch { expected: u32, actual: u32 },
    ProtocolError(String),
    Service(ServiceError),
}

impl std::fmt::Display for IpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyRunning => write!(f, "Another instance is already running"),
            Self::BindFailed(e) => write!(f, "Failed to bind to socket: {e}"),
            Self::ConnectionFailed(e) => write!(f, "Failed to connect to socket: {e}"),
            Self::IoError(e) => write!(f, "IO error: {e}"),
            Self::JsonError(e) => write!(f, "JSON error: {e}"),
            Self::NotRunning => write!(f, "Service is not running"),
            Self::ProtocolMismatch { expected, actual } => {
                write!(
                    f,
                    "IPC protocol mismatch: expected version {expected}, got {actual}"
                )
            }
            Self::ProtocolError(msg) => write!(f, "{msg}"),
            Self::Service(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for IpcError {}

impl IpcError {
    pub fn is_connection_closed(&self) -> bool {
        match self {
            Self::IoError(error) => is_connection_closed_error(error),
            _ => false,
        }
    }
}

impl From<io::Error> for IpcError {
    fn from(e: io::Error) -> Self {
        Self::IoError(e)
    }
}

impl From<serde_json::Error> for IpcError {
    fn from(e: serde_json::Error) -> Self {
        Self::JsonError(e)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestEnvelope {
    pub ipc_version: u32,
    pub request_id: u64,
    pub request: ServiceRequest,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IncomingRequestEnvelope {
    pub ipc_version: u32,
    pub request_id: u64,
    pub request: ServiceRequestOrUnknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServiceRequest {
    Subscribe,
    GetStatus,
    GetState,
    GetTunnels,
    GetAccountTunnels,
    CreateTunnel {
        local_port: u16,
        #[serde(default)]
        protocol: TunnelProtocol,
        #[serde(default)]
        local_address: Option<String>,
        #[serde(default)]
        name: Option<String>,
    },
    CreateMinecraftJavaTunnel {
        local_port: u16,
        #[serde(default)]
        local_address: Option<String>,
        #[serde(default)]
        name: Option<String>,
    },
    DeleteTunnel {
        tunnel_id: String,
    },
    ReassignTunnel {
        tunnel_id: String,
        local_port: u16,
        #[serde(default)]
        local_address: Option<String>,
    },
    GetAccount,
    StartClaim,
    Stop,
    SetSecret {
        secret: String,
    },
    ResetSecret,
    GetSecretPath,
    GetAccountLoginUrl,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ServiceRequestOrUnknown {
    Known(ServiceRequest),
    Unknown(UnknownTaggedMessage),
}

#[derive(Debug, Clone, Deserialize)]
pub struct UnknownTaggedMessage {
    #[serde(rename = "type")]
    pub type_name: String,
    #[serde(flatten)]
    pub rest: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloEnvelope {
    pub protocol: ProtocolInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseEnvelope {
    pub ipc_version: u32,
    pub request_id: u64,
    pub response: ServiceResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub ipc_version: u32,
    pub event: ServiceUpdate,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IncomingEventEnvelope {
    pub ipc_version: u32,
    pub event: ServiceUpdateOrUnknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum ServiceResponse {
    Subscribe(SubscribeResponse),
    Status(ServiceStatus),
    State(AgentLifecycle),
    Tunnels(TunnelListResponse),
    AccountTunnels(AccountTunnelListResponse),
    CreateTunnel(TunnelCreateResponse),
    DeleteTunnel(CommandResponse),
    ReassignTunnel(CommandResponse),
    Account(AccountResponse),
    Claim(ClaimResponse),
    Stop(CommandResponse),
    SetSecret(CommandResponse),
    ResetSecret(CommandResponse),
    SecretPath(SecretPathResponse),
    AccountLoginUrl(AccountLoginUrlResponse),
    Error(ServiceError),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "message_kind", content = "data", rename_all = "snake_case")]
pub enum ServerEnvelope {
    Hello(HelloEnvelope),
    Response(ResponseEnvelope),
    Event(EventEnvelope),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "message_kind", content = "data", rename_all = "snake_case")]
enum IncomingServerEnvelope {
    Hello(HelloEnvelope),
    Response(ResponseEnvelope),
    Event(IncomingEventEnvelope),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ServiceUpdateOrUnknown {
    Known(ServiceUpdate),
    Unknown(UnknownTaggedEvent),
}

#[derive(Debug, Clone, Deserialize)]
pub struct UnknownTaggedEvent {
    #[serde(rename = "type")]
    pub type_name: String,
    #[serde(default)]
    pub data: Option<Value>,
}

pub fn protocol_info() -> ProtocolInfo {
    ProtocolInfo {
        ipc_version: IPC_VERSION,
        capabilities: vec![
            "structured_responses".to_string(),
            "stream_events".to_string(),
            "lifecycle_state".to_string(),
            "rich_status".to_string(),
            "secret_provisioning".to_string(),
            "tunnel_management".to_string(),
            "account_tunnel_management".to_string(),
            "semantic_tunnel_types".to_string(),
            "account_state".to_string(),
            "control_reconnect_state".to_string(),
            "claim_provisioning".to_string(),
        ],
    }
}

pub fn get_default_socket_path() -> &'static str {
    crate::paths::default_socket_path_static()
}

pub fn get_default_endpoint() -> IpcEndpoint {
    IpcEndpoint::default()
}

pub async fn try_connect(endpoint: &IpcEndpoint) -> Result<Stream, IpcError> {
    match endpoint {
        IpcEndpoint::Namespaced(name) => {
            let name = name
                .clone()
                .to_ns_name::<GenericNamespaced>()
                .map_err(|e| {
                    IpcError::ConnectionFailed(io::Error::new(io::ErrorKind::InvalidInput, e))
                })?;
            Stream::connect(name)
                .await
                .map_err(IpcError::ConnectionFailed)
        }
        IpcEndpoint::Filesystem(path) => {
            let name = path.clone().to_fs_name::<GenericFilePath>().map_err(|e| {
                IpcError::ConnectionFailed(io::Error::new(io::ErrorKind::InvalidInput, e))
            })?;
            Stream::connect(name)
                .await
                .map_err(IpcError::ConnectionFailed)
        }
    }
}

pub struct IpcFrameReader<R> {
    reader: FramedRead<R, LinesCodec>,
}

pub struct IpcFrameWriter<W> {
    writer: FramedWrite<W, LinesCodec>,
}

pub struct IpcTransport<R, W> {
    reader: IpcFrameReader<R>,
    writer: IpcFrameWriter<W>,
}

impl<R> IpcFrameReader<R>
where
    R: AsyncRead + Unpin,
{
    pub fn new(reader: R) -> Self {
        Self {
            reader: FramedRead::new(reader, LinesCodec::new()),
        }
    }

    pub async fn read_json<T>(&mut self) -> Result<T, IpcError>
    where
        T: DeserializeOwned,
    {
        let line = self.read_line().await?;
        Ok(serde_json::from_str(&line)?)
    }

    async fn read_line(&mut self) -> Result<String, IpcError> {
        self.reader
            .next()
            .await
            .transpose()
            .map_err(line_codec_error)?
            .ok_or_else(|| {
                IpcError::IoError(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Connection closed",
                ))
            })
    }
}

impl<W> IpcFrameWriter<W>
where
    W: AsyncWrite + Unpin,
{
    pub fn new(writer: W) -> Self {
        Self {
            writer: FramedWrite::new(writer, LinesCodec::new()),
        }
    }

    pub async fn write_json<T>(&mut self, value: &T) -> Result<(), IpcError>
    where
        T: Serialize,
    {
        let json = serde_json::to_string(value)?;
        self.writer.send(json).await.map_err(line_codec_error)
    }
}

impl<R, W> IpcTransport<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader: IpcFrameReader::new(reader),
            writer: IpcFrameWriter::new(writer),
        }
    }

    pub async fn read_json<T>(&mut self) -> Result<T, IpcError>
    where
        T: DeserializeOwned,
    {
        self.reader.read_json().await
    }

    pub async fn write_json<T>(&mut self, value: &T) -> Result<(), IpcError>
    where
        T: Serialize,
    {
        self.writer.write_json(value).await
    }
}

pub fn framed_parts<R, W>(reader: R, writer: W) -> (IpcFrameReader<R>, IpcFrameWriter<W>)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    (IpcFrameReader::new(reader), IpcFrameWriter::new(writer))
}

fn line_codec_error(error: LinesCodecError) -> IpcError {
    match error {
        LinesCodecError::Io(error) => IpcError::IoError(error),
        LinesCodecError::MaxLineLengthExceeded => {
            IpcError::ProtocolError("IPC frame exceeded maximum line length".to_string())
        }
    }
}

fn is_connection_closed_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::NotConnected
    )
}

pub struct IpcClient {
    transport: IpcTransport<
        interprocess::local_socket::tokio::RecvHalf,
        interprocess::local_socket::tokio::SendHalf,
    >,
    next_request_id: u64,
    server_protocol: ProtocolInfo,
}

impl IpcClient {
    pub async fn connect() -> Result<Self, IpcError> {
        Self::connect_with_path(get_default_socket_path()).await
    }

    pub async fn connect_with_path(socket_path: &str) -> Result<Self, IpcError> {
        let endpoint = IpcEndpoint::parse(socket_path);
        let stream = try_connect(&endpoint).await?;
        let (reader, writer) = stream.split();
        let mut client = Self {
            transport: IpcTransport::new(reader, writer),
            next_request_id: 1,
            server_protocol: ProtocolInfo::default(),
        };

        let hello = client.recv_hello().await?;
        client.ensure_ipc_version(hello.protocol.ipc_version)?;
        client.server_protocol = hello.protocol;

        Ok(client)
    }

    pub async fn is_running(socket_path: &str) -> bool {
        let endpoint = IpcEndpoint::parse(socket_path);
        try_connect(&endpoint).await.is_ok()
    }

    pub fn server_protocol(&self) -> &ProtocolInfo {
        &self.server_protocol
    }

    pub async fn subscribe(&mut self) -> Result<SubscribeResponse, IpcError> {
        expect_response(
            self.request(ServiceRequest::Subscribe).await?,
            "subscribe response",
            |response| match response {
                ServiceResponse::Subscribe(response) => Some(response),
                _ => None,
            },
        )
    }

    pub async fn recv_update(&mut self) -> Result<ServiceUpdate, IpcError> {
        loop {
            match self.recv_incoming_server_envelope().await? {
                IncomingServerEnvelope::Event(event) => {
                    self.ensure_ipc_version(event.ipc_version)?;
                    match event.event {
                        ServiceUpdateOrUnknown::Known(update) => return Ok(update),
                        ServiceUpdateOrUnknown::Unknown(unknown) => {
                            tracing::debug!(
                                "Ignoring unknown IPC event type: {}",
                                unknown.type_name
                            );
                        }
                    }
                }
                IncomingServerEnvelope::Response(response) => {
                    let response_type = service_response_name(&response.response);
                    return Err(IpcError::ProtocolError(format!(
                        "received {response_type} RPC response while waiting for stream event"
                    )));
                }
                IncomingServerEnvelope::Hello(_) => {
                    return Err(IpcError::ProtocolError(
                        "received duplicate hello while waiting for stream event".to_string(),
                    ));
                }
            }
        }
    }

    pub async fn status(&mut self) -> Result<ServiceStatus, IpcError> {
        expect_response(
            self.request(ServiceRequest::GetStatus).await?,
            "status response",
            |response| match response {
                ServiceResponse::Status(status) => Some(status),
                _ => None,
            },
        )
    }

    pub async fn lifecycle(&mut self) -> Result<AgentLifecycle, IpcError> {
        expect_response(
            self.request(ServiceRequest::GetState).await?,
            "lifecycle response",
            |response| match response {
                ServiceResponse::State(state) => Some(state),
                _ => None,
            },
        )
    }

    pub async fn list_tunnels(&mut self) -> Result<TunnelListResponse, IpcError> {
        expect_response(
            self.request(ServiceRequest::GetTunnels).await?,
            "tunnel list response",
            |response| match response {
                ServiceResponse::Tunnels(response) => Some(response),
                _ => None,
            },
        )
    }

    pub async fn list_account_tunnels(&mut self) -> Result<AccountTunnelListResponse, IpcError> {
        expect_response(
            self.request(ServiceRequest::GetAccountTunnels).await?,
            "account tunnel list response",
            |response| match response {
                ServiceResponse::AccountTunnels(response) => Some(response),
                _ => None,
            },
        )
    }

    pub async fn create_tunnel(
        &mut self,
        local_port: u16,
        protocol: TunnelProtocol,
        local_address: Option<String>,
        name: Option<String>,
    ) -> Result<TunnelCreateResponse, IpcError> {
        expect_response(
            self.request(ServiceRequest::CreateTunnel {
                local_port,
                protocol,
                local_address,
                name,
            })
            .await?,
            "tunnel create response",
            |response| match response {
                ServiceResponse::CreateTunnel(response) => Some(response),
                _ => None,
            },
        )
    }

    pub async fn create_minecraft_java_tunnel(
        &mut self,
        local_port: u16,
        local_address: Option<String>,
        name: Option<String>,
    ) -> Result<TunnelCreateResponse, IpcError> {
        expect_response(
            self.request(ServiceRequest::CreateMinecraftJavaTunnel {
                local_port,
                local_address,
                name,
            })
            .await?,
            "Minecraft Java tunnel create response",
            |response| match response {
                ServiceResponse::CreateTunnel(response) => Some(response),
                _ => None,
            },
        )
    }

    pub async fn delete_tunnel(&mut self, tunnel_id: &str) -> Result<CommandResponse, IpcError> {
        expect_response(
            self.request(ServiceRequest::DeleteTunnel {
                tunnel_id: tunnel_id.to_string(),
            })
            .await?,
            "tunnel delete response",
            |response| match response {
                ServiceResponse::DeleteTunnel(response) => Some(response),
                _ => None,
            },
        )
    }

    pub async fn reassign_tunnel(
        &mut self,
        tunnel_id: &str,
        local_port: u16,
        local_address: Option<String>,
    ) -> Result<CommandResponse, IpcError> {
        expect_response(
            self.request(ServiceRequest::ReassignTunnel {
                tunnel_id: tunnel_id.to_string(),
                local_port,
                local_address,
            })
            .await?,
            "tunnel reassignment response",
            |response| match response {
                ServiceResponse::ReassignTunnel(response) => Some(response),
                _ => None,
            },
        )
    }

    pub async fn account(&mut self) -> Result<AccountResponse, IpcError> {
        expect_response(
            self.request(ServiceRequest::GetAccount).await?,
            "account response",
            |response| match response {
                ServiceResponse::Account(response) => Some(response),
                _ => None,
            },
        )
    }

    pub async fn start_claim(&mut self) -> Result<ClaimResponse, IpcError> {
        expect_response(
            self.request(ServiceRequest::StartClaim).await?,
            "claim response",
            |response| match response {
                ServiceResponse::Claim(response) => Some(response),
                _ => None,
            },
        )
    }

    pub async fn stop(&mut self) -> Result<CommandResponse, IpcError> {
        expect_response(
            self.request(ServiceRequest::Stop).await?,
            "stop response",
            |response| match response {
                ServiceResponse::Stop(response) => Some(response),
                _ => None,
            },
        )
    }

    pub async fn set_secret(&mut self, secret: &str) -> Result<CommandResponse, IpcError> {
        expect_response(
            self.request(ServiceRequest::SetSecret {
                secret: secret.to_string(),
            })
            .await?,
            "secret provisioning response",
            |response| match response {
                ServiceResponse::SetSecret(response) => Some(response),
                _ => None,
            },
        )
    }

    pub async fn reset_secret(&mut self) -> Result<CommandResponse, IpcError> {
        expect_response(
            self.request(ServiceRequest::ResetSecret).await?,
            "reset secret response",
            |response| match response {
                ServiceResponse::ResetSecret(response) => Some(response),
                _ => None,
            },
        )
    }

    pub async fn get_secret_path(&mut self) -> Result<SecretPathResponse, IpcError> {
        expect_response(
            self.request(ServiceRequest::GetSecretPath).await?,
            "secret path response",
            |response| match response {
                ServiceResponse::SecretPath(response) => Some(response),
                _ => None,
            },
        )
    }

    pub async fn get_account_login_url(&mut self) -> Result<AccountLoginUrlResponse, IpcError> {
        expect_response(
            self.request(ServiceRequest::GetAccountLoginUrl).await?,
            "account login URL response",
            |response| match response {
                ServiceResponse::AccountLoginUrl(response) => Some(response),
                _ => None,
            },
        )
    }

    pub async fn request(&mut self, request: ServiceRequest) -> Result<ServiceResponse, IpcError> {
        let request_id = self.send_request(request).await?;
        let response = self.recv_response().await?;

        self.ensure_ipc_version(response.ipc_version)?;
        if response.request_id != request_id {
            return Err(IpcError::ProtocolError(format!(
                "mismatched response id: expected {request_id}, got {}",
                response.request_id
            )));
        }
        Ok(response.response)
    }

    async fn send_request(&mut self, request: ServiceRequest) -> Result<u64, IpcError> {
        let request_id = self.next_request_id;
        self.next_request_id += 1;

        self.transport
            .write_json(&RequestEnvelope {
                ipc_version: IPC_VERSION,
                request_id,
                request,
            })
            .await?;
        Ok(request_id)
    }

    async fn recv_hello(&mut self) -> Result<HelloEnvelope, IpcError> {
        match self.recv_server_envelope().await? {
            ServerEnvelope::Hello(hello) => Ok(hello),
            ServerEnvelope::Response(response) => {
                let response_type = service_response_name(&response.response);
                Err(IpcError::ProtocolError(format!(
                    "expected hello frame, got {response_type} RPC response"
                )))
            }
            ServerEnvelope::Event(event) => {
                let event_type = service_update_name(&event.event);
                Err(IpcError::ProtocolError(format!(
                    "expected hello frame, got {event_type} stream event"
                )))
            }
        }
    }

    async fn recv_response(&mut self) -> Result<ResponseEnvelope, IpcError> {
        match self.recv_server_envelope().await? {
            ServerEnvelope::Response(response) => Ok(response),
            ServerEnvelope::Event(event) => {
                let event_type = service_update_name(&event.event);
                Err(IpcError::ProtocolError(format!(
                    "received {event_type} stream event while waiting for RPC response"
                )))
            }
            ServerEnvelope::Hello(_) => Err(IpcError::ProtocolError(
                "received duplicate hello while waiting for RPC response".to_string(),
            )),
        }
    }

    async fn recv_server_envelope(&mut self) -> Result<ServerEnvelope, IpcError> {
        self.transport.read_json().await
    }

    async fn recv_incoming_server_envelope(&mut self) -> Result<IncomingServerEnvelope, IpcError> {
        let envelope = self.transport.read_json::<IncomingServerEnvelope>().await?;
        validate_incoming_server_envelope(&envelope)?;
        Ok(envelope)
    }

    fn ensure_ipc_version(&self, actual: u32) -> Result<(), IpcError> {
        if actual == IPC_VERSION {
            Ok(())
        } else {
            Err(IpcError::ProtocolMismatch {
                expected: IPC_VERSION,
                actual,
            })
        }
    }
}

fn expect_response<T>(
    response: ServiceResponse,
    expected: &str,
    extract: impl FnOnce(ServiceResponse) -> Option<T>,
) -> Result<T, IpcError> {
    if let ServiceResponse::Error(error) = &response {
        return Err(IpcError::Service(error.clone()));
    }

    let response_type = service_response_name(&response);
    extract(response)
        .ok_or_else(|| IpcError::ProtocolError(format!("expected {expected}, got {response_type}")))
}

fn service_response_name(response: &ServiceResponse) -> &'static str {
    match response {
        ServiceResponse::Subscribe(_) => "subscribe",
        ServiceResponse::Status(_) => "status",
        ServiceResponse::State(_) => "state",
        ServiceResponse::Tunnels(_) => "tunnels",
        ServiceResponse::AccountTunnels(_) => "account_tunnels",
        ServiceResponse::CreateTunnel(_) => "create_tunnel",
        ServiceResponse::DeleteTunnel(_) => "delete_tunnel",
        ServiceResponse::ReassignTunnel(_) => "reassign_tunnel",
        ServiceResponse::Account(_) => "account",
        ServiceResponse::Claim(_) => "claim",
        ServiceResponse::Stop(_) => "stop",
        ServiceResponse::SetSecret(_) => "set_secret",
        ServiceResponse::ResetSecret(_) => "reset_secret",
        ServiceResponse::SecretPath(_) => "secret_path",
        ServiceResponse::AccountLoginUrl(_) => "account_login_url",
        ServiceResponse::Error(_) => "error",
    }
}

fn service_update_name(update: &ServiceUpdate) -> &'static str {
    match update {
        ServiceUpdate::Status(_) => UPDATE_STATUS,
        ServiceUpdate::Lifecycle(_) => UPDATE_LIFECYCLE,
        ServiceUpdate::Stats(_) => UPDATE_STATS,
        ServiceUpdate::Log(_) => UPDATE_LOG,
    }
}

#[cfg(test)]
fn decode_incoming_server_envelope(line: &str) -> Result<IncomingServerEnvelope, IpcError> {
    let envelope = serde_json::from_str::<IncomingServerEnvelope>(line.trim())?;
    validate_incoming_server_envelope(&envelope)?;
    Ok(envelope)
}

fn validate_incoming_server_envelope(envelope: &IncomingServerEnvelope) -> Result<(), IpcError> {
    match &envelope {
        IncomingServerEnvelope::Hello(hello) => {
            let _ = hello;
        }
        IncomingServerEnvelope::Response(_) => {}
        IncomingServerEnvelope::Event(event) => {
            if let ServiceUpdateOrUnknown::Unknown(unknown) = &event.event {
                if is_known_update_type(&unknown.type_name) {
                    return Err(IpcError::ProtocolError(format!(
                        "invalid IPC event payload for {}",
                        unknown.type_name
                    )));
                }
            }
        }
    }
    Ok(())
}

pub fn is_known_request_type(type_name: &str) -> bool {
    matches!(
        type_name,
        "subscribe"
            | "get_status"
            | "get_state"
            | "get_tunnels"
            | "get_account_tunnels"
            | "create_tunnel"
            | "create_minecraft_java_tunnel"
            | "delete_tunnel"
            | "reassign_tunnel"
            | "get_account"
            | "start_claim"
            | "stop"
            | "set_secret"
            | "reset_secret"
            | "get_secret_path"
            | "get_account_login_url"
    )
}

fn is_known_update_type(event_type: &str) -> bool {
    matches!(
        event_type,
        UPDATE_STATUS | UPDATE_LIFECYCLE | UPDATE_STATS | UPDATE_LOG
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use interprocess::local_socket::{GenericFilePath, ListenerOptions, ToFsName};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    fn test_socket_path(name: &str) -> String {
        let unique = format!(
            "playit-ipc-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        #[cfg(target_os = "windows")]
        {
            // Windows local sockets are named pipes, not filesystem sockets.
            format!(r"\\.\pipe\{unique}")
        }

        #[cfg(not(target_os = "windows"))]
        {
            std::env::temp_dir()
                .join(format!("{unique}.sock"))
                .display()
                .to_string()
        }
    }

    async fn spawn_server<F, Fut>(name: &str, handler: F) -> String
    where
        F: FnOnce(Stream) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let path = test_socket_path(name);
        let listener = ListenerOptions::new()
            .name(path.clone().to_fs_name::<GenericFilePath>().unwrap())
            .create_tokio()
            .unwrap();

        tokio::spawn(async move {
            let stream = listener.accept().await.unwrap();
            handler(stream).await;
        });

        path
    }

    fn hello_json(ipc_version: u32) -> String {
        serde_json::to_string(&ServerEnvelope::Hello(HelloEnvelope {
            protocol: ProtocolInfo {
                ipc_version,
                capabilities: vec!["stream_events".to_string()],
            },
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn connect_succeeds_after_valid_hello() {
        let socket_path = spawn_server("hello-ok", |mut stream| async move {
            stream
                .write_all(hello_json(IPC_VERSION).as_bytes())
                .await
                .unwrap();
            stream.write_all(b"\n").await.unwrap();
        })
        .await;

        let client = IpcClient::connect_with_path(&socket_path).await.unwrap();
        assert_eq!(client.server_protocol().ipc_version, IPC_VERSION);
        assert_eq!(client.server_protocol().capabilities, vec!["stream_events"]);
    }

    #[tokio::test]
    async fn connect_fails_on_ipc_mismatch() {
        let socket_path = spawn_server("hello-mismatch", |mut stream| async move {
            stream
                .write_all(hello_json(IPC_VERSION + 1).as_bytes())
                .await
                .unwrap();
            stream.write_all(b"\n").await.unwrap();
        })
        .await;

        let error = match IpcClient::connect_with_path(&socket_path).await {
            Ok(_) => panic!("expected version mismatch"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            IpcError::ProtocolMismatch {
                expected: IPC_VERSION,
                actual
            } if actual == IPC_VERSION + 1
        ));
    }

    #[tokio::test]
    async fn connect_fails_when_first_frame_is_not_hello() {
        let socket_path = spawn_server("hello-missing", |mut stream| async move {
            let json = serde_json::to_string(&ServerEnvelope::Response(ResponseEnvelope {
                ipc_version: IPC_VERSION,
                request_id: 1,
                response: ServiceResponse::State(AgentLifecycle::Starting),
            }))
            .unwrap();

            stream.write_all(json.as_bytes()).await.unwrap();
            stream.write_all(b"\n").await.unwrap();
        })
        .await;

        let error = match IpcClient::connect_with_path(&socket_path).await {
            Ok(_) => panic!("expected protocol error"),
            Err(error) => error,
        };
        assert!(matches!(error, IpcError::ProtocolError(_)));
    }

    #[tokio::test]
    async fn recv_update_ignores_unknown_event_types() {
        let socket_path = spawn_server("unknown-event", |stream| async move {
            let (reader, mut writer) = stream.split();
            let mut reader = BufReader::new(reader);

            writer
                .write_all(hello_json(IPC_VERSION).as_bytes())
                .await
                .unwrap();
            writer.write_all(b"\n").await.unwrap();

            let unknown_event = serde_json::json!({
                "message_kind": "event",
                "data": {
                    "ipc_version": IPC_VERSION,
                    "event": {
                        "type": "future_event",
                        "data": {"hello": "world"}
                    }
                }
            });
            writer
                .write_all(serde_json::to_string(&unknown_event).unwrap().as_bytes())
                .await
                .unwrap();
            writer.write_all(b"\n").await.unwrap();

            let known_event = serde_json::to_string(&ServerEnvelope::Event(EventEnvelope {
                ipc_version: IPC_VERSION,
                event: ServiceUpdate::Stats(Default::default()),
            }))
            .unwrap();
            writer.write_all(known_event.as_bytes()).await.unwrap();
            writer.write_all(b"\n").await.unwrap();

            let mut line = String::new();
            let _ = reader.read_line(&mut line).await;
        })
        .await;

        let mut client = IpcClient::connect_with_path(&socket_path).await.unwrap();
        let update = client.recv_update().await.unwrap();
        assert!(matches!(update, ServiceUpdate::Stats(_)));
    }

    #[test]
    fn request_fallback_parses_unknown_type_name() {
        let request = serde_json::json!({
            "type": "future_request",
            "data": { "flag": true }
        });

        let parsed = serde_json::from_value::<ServiceRequestOrUnknown>(request).unwrap();
        match parsed {
            ServiceRequestOrUnknown::Unknown(unknown) => {
                assert_eq!(unknown.type_name, "future_request");
                assert_eq!(unknown.rest["data"], serde_json::json!({ "flag": true }));
            }
            other => panic!("expected unknown request fallback, got {other:?}"),
        }
    }

    #[test]
    fn event_fallback_parses_unknown_type_name_without_manual_tag_read() {
        let event = serde_json::json!({
            "type": "future_event",
            "data": { "flag": true }
        });

        let parsed = serde_json::from_value::<ServiceUpdateOrUnknown>(event).unwrap();
        match parsed {
            ServiceUpdateOrUnknown::Unknown(unknown) => {
                assert_eq!(unknown.type_name, "future_event");
                assert_eq!(unknown.data, Some(serde_json::json!({ "flag": true })));
            }
            other => panic!("expected unknown event fallback, got {other:?}"),
        }
    }

    #[test]
    fn event_fallback_accepts_missing_data_for_unknown_type() {
        let event = serde_json::json!({
            "type": "future_event"
        });

        let parsed = serde_json::from_value::<ServiceUpdateOrUnknown>(event).unwrap();
        match parsed {
            ServiceUpdateOrUnknown::Unknown(unknown) => {
                assert_eq!(unknown.type_name, "future_event");
                assert_eq!(unknown.data, None);
            }
            other => panic!("expected unknown event fallback, got {other:?}"),
        }
    }

    #[test]
    fn malformed_known_event_payload_remains_an_error() {
        let line = serde_json::json!({
            "message_kind": "event",
            "data": {
                "ipc_version": IPC_VERSION,
                "event": {
                    "type": "stats",
                    "data": { "bytes_in": "not-a-number" }
                }
            }
        });

        let error = decode_incoming_server_envelope(&serde_json::to_string(&line).unwrap())
            .err()
            .expect("malformed known event should fail");
        assert!(matches!(error, IpcError::ProtocolError(_)));
    }

    #[test]
    fn tunnel_management_requests_use_stable_json_names() {
        let request = RequestEnvelope {
            ipc_version: IPC_VERSION,
            request_id: 7,
            request: ServiceRequest::CreateTunnel {
                local_port: 25565,
                protocol: TunnelProtocol::Udp,
                local_address: Some("127.0.0.1".to_string()),
                name: Some("minecraft".to_string()),
            },
        };

        let json = serde_json::to_value(request).unwrap();
        assert_eq!(json["request"]["type"], "create_tunnel");
        assert_eq!(json["request"]["protocol"], "udp");
        assert_eq!(json["request"]["local_port"], 25565);
        assert!(is_known_request_type("create_tunnel"));

        let minecraft_request = serde_json::to_value(ServiceRequest::CreateMinecraftJavaTunnel {
            local_port: 25565,
            local_address: Some("127.0.0.1".to_string()),
            name: Some("minecraft".to_string()),
        })
        .unwrap();
        assert_eq!(minecraft_request["type"], "create_minecraft_java_tunnel");
        assert_eq!(minecraft_request["local_port"], 25565);
        assert!(is_known_request_type("create_minecraft_java_tunnel"));
    }

    #[test]
    fn service_errors_preserve_structured_codes() {
        let error = expect_response::<()>(
            ServiceResponse::Error(ServiceError {
                code: crate::model::ServiceErrorCode::InvalidTunnelRequest,
                message: "bad request".to_string(),
                retryable: false,
                details: None,
            }),
            "test response",
            |_| None,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            IpcError::Service(ServiceError {
                code: crate::model::ServiceErrorCode::InvalidTunnelRequest,
                ..
            })
        ));
    }

    #[test]
    fn ipc_operation_and_response_names_are_stable() {
        let requests = [
            ServiceRequest::GetTunnels,
            ServiceRequest::CreateTunnel {
                local_port: 1,
                protocol: TunnelProtocol::Tcp,
                local_address: None,
                name: None,
            },
            ServiceRequest::DeleteTunnel {
                tunnel_id: "00000000-0000-0000-0000-000000000000".to_string(),
            },
            ServiceRequest::GetAccount,
            ServiceRequest::StartClaim,
        ];
        let expected_requests = [
            "get_tunnels",
            "create_tunnel",
            "delete_tunnel",
            "get_account",
            "start_claim",
        ];

        for (request, expected) in requests.into_iter().zip(expected_requests) {
            assert_eq!(serde_json::to_value(request).unwrap()["type"], expected);
        }

        let responses = [
            ServiceResponse::Tunnels(TunnelListResponse::default()),
            ServiceResponse::CreateTunnel(TunnelCreateResponse::default()),
            ServiceResponse::DeleteTunnel(CommandResponse::default()),
            ServiceResponse::Account(AccountResponse::default()),
            ServiceResponse::Claim(ClaimResponse::default()),
        ];
        let expected_responses = [
            "tunnels",
            "create_tunnel",
            "delete_tunnel",
            "account",
            "claim",
        ];

        for (response, expected) in responses.into_iter().zip(expected_responses) {
            assert_eq!(serde_json::to_value(response).unwrap()["type"], expected);
        }
    }

    #[tokio::test]
    async fn request_fails_on_unknown_response_variant() {
        let socket_path = spawn_server("unknown-response", |stream| async move {
            let (reader, mut writer) = stream.split();
            let mut reader = BufReader::new(reader);

            writer
                .write_all(hello_json(IPC_VERSION).as_bytes())
                .await
                .unwrap();
            writer.write_all(b"\n").await.unwrap();

            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();

            let raw_response = serde_json::json!({
                "message_kind": "response",
                "data": {
                    "ipc_version": IPC_VERSION,
                    "request_id": 1,
                    "response": {
                        "type": "future_response",
                        "data": {"ok": true}
                    }
                }
            });
            writer
                .write_all(serde_json::to_string(&raw_response).unwrap().as_bytes())
                .await
                .unwrap();
            writer.write_all(b"\n").await.unwrap();
        })
        .await;

        let mut client = IpcClient::connect_with_path(&socket_path).await.unwrap();
        let error = client.status().await.unwrap_err();
        assert!(matches!(error, IpcError::JsonError(_)));
    }
}
