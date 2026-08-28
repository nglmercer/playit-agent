use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use interprocess::local_socket::{
    GenericFilePath, GenericNamespaced, ListenerOptions, ToFsName, ToNsName,
    tokio::{Listener, Stream, prelude::*},
};
#[cfg(unix)]
use interprocess::os::unix::local_socket::ListenerOptionsExt;
#[cfg(target_os = "windows")]
use interprocess::os::windows::local_socket::ListenerOptionsExt;
use playit_ipc::endpoint::IpcEndpoint;
use playit_ipc::ipc::{
    EventEnvelope, HelloEnvelope, IPC_VERSION, IncomingRequestEnvelope, IpcError, IpcFrameWriter,
    ResponseEnvelope, ServerEnvelope, ServiceRequest, ServiceRequestOrUnknown, ServiceResponse,
    framed_parts, get_default_socket_path, is_known_request_type, protocol_info, try_connect,
};
use playit_ipc::model::{
    CommandResponse, SecretPathResponse, ServiceError, ServiceErrorCode, ServiceStatus,
    ServiceUpdate,
};
use playit_runtime::{PlayitHandle, RuntimeError};
use serde_json::json;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

/// IPC transport adapter over the reusable Playit runtime.
pub struct IpcServer {
    runtime: PlayitHandle,
    socket_path: String,
    host_shutdown: CancellationToken,
}

impl IpcServer {
    pub async fn new(
        runtime: PlayitHandle,
        socket_path: Option<String>,
        host_shutdown: CancellationToken,
    ) -> Result<Self, IpcError> {
        let socket_path = socket_path.unwrap_or_else(|| get_default_socket_path().to_string());
        let endpoint = IpcEndpoint::parse(socket_path.clone());

        if try_connect(&endpoint).await.is_ok() {
            return Err(IpcError::AlreadyRunning);
        }

        if !endpoint.is_windows_named_pipe() {
            if let Some(parent) = endpoint
                .filesystem_path()
                .and_then(Path::parent)
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Some(path) = endpoint.filesystem_path() {
                let _ = std::fs::remove_file(path);
            }
        }

        Ok(Self {
            runtime,
            socket_path,
            host_shutdown,
        })
    }

    pub async fn bind_listener(&self) -> Result<Listener, IpcError> {
        let listener = self.create_listener()?;

        #[cfg(unix)]
        crate::unix::configure_socket_permissions(&self.socket_path)?;

        Ok(listener)
    }

    pub async fn run(self: Arc<Self>, listener: Listener) -> Result<(), IpcError> {
        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok(stream) => {
                            let server = self.clone();
                            tokio::spawn(async move {
                                if let Err(error) = server.handle_client(stream).await {
                                    if error.is_connection_closed() {
                                        tracing::debug!("Client disconnected: {error}");
                                    } else {
                                        tracing::warn!("Client connection error: {error}");
                                    }
                                }
                            });
                        }
                        Err(error) => {
                            tracing::error!("Accept error: {error}");
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
                _ = self.host_shutdown.cancelled() => {
                    tracing::info!("IPC server shutting down");
                    break;
                }
            }
        }

        Ok(())
    }

    fn create_listener(&self) -> Result<Listener, IpcError> {
        let endpoint = IpcEndpoint::parse(self.socket_path.clone());
        match endpoint {
            IpcEndpoint::Namespaced(name) => {
                let name = name
                    .clone()
                    .to_ns_name::<GenericNamespaced>()
                    .map_err(|error| {
                        IpcError::BindFailed(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            error,
                        ))
                    })?;
                let listener = ListenerOptions::new().name(name);
                #[cfg(target_os = "windows")]
                let listener = listener
                    .security_descriptor(crate::windows::restricted_pipe_security_descriptor()?);
                listener.create_tokio().map_err(IpcError::BindFailed)
            }
            IpcEndpoint::Filesystem(path) => {
                let name = path
                    .clone()
                    .to_fs_name::<GenericFilePath>()
                    .map_err(|error| {
                        IpcError::BindFailed(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            error,
                        ))
                    })?;

                #[cfg(unix)]
                {
                    match ListenerOptions::new()
                        .name(name.clone())
                        .mode(crate::unix::socket_mode())
                        .create_tokio()
                    {
                        Ok(listener) => return Ok(listener),
                        Err(error) if error.kind() == std::io::ErrorKind::Unsupported => {
                            tracing::debug!(
                                "filesystem IPC listener does not support creation-time mode; applying permissions after bind"
                            );
                        }
                        Err(error) => return Err(IpcError::BindFailed(error)),
                    }
                }

                let listener = ListenerOptions::new().name(name);
                #[cfg(target_os = "windows")]
                let listener = listener
                    .security_descriptor(crate::windows::restricted_pipe_security_descriptor()?);
                listener.create_tokio().map_err(IpcError::BindFailed)
            }
        }
    }

    async fn handle_client(&self, stream: Stream) -> Result<(), IpcError> {
        let (reader, writer) = stream.split();
        let (mut reader, mut writer) = framed_parts(reader, writer);
        let mut event_rx = self.runtime.subscribe();
        let mut subscribed = false;

        self.send_hello(&mut writer).await?;

        loop {
            tokio::select! {
                read_result = reader.read_json::<IncomingRequestEnvelope>() => {
                    let envelope = read_result?;
                    let request_id = envelope.request_id;
                    let outcome = self.handle_request_envelope(envelope).await;

                    if outcome.subscribed {
                        subscribed = true;
                    }

                    self.send_response(&mut writer, request_id, outcome.response).await?;
                }
                event_result = event_rx.recv(), if subscribed => {
                    match event_result {
                        Ok(event) => self.send_event(&mut writer, event).await?,
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            tracing::debug!("Client lagged behind, some events dropped");
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
            }
        }

        Ok(())
    }

    async fn handle_request_envelope(&self, envelope: IncomingRequestEnvelope) -> RequestOutcome {
        match Self::validate_request_envelope(envelope) {
            Ok(request) => self.handle_service_request(request).await,
            Err(response) => RequestOutcome::respond(response),
        }
    }

    fn validate_request_envelope(
        envelope: IncomingRequestEnvelope,
    ) -> Result<ServiceRequest, ServiceResponse> {
        if envelope.ipc_version != IPC_VERSION {
            return Err(ServiceResponse::Error(protocol_error(
                ServiceErrorCode::UnsupportedProtocol,
                format!(
                    "unsupported IPC version {} (expected {})",
                    envelope.ipc_version, IPC_VERSION
                ),
                false,
            )));
        }

        match envelope.request {
            ServiceRequestOrUnknown::Known(request) => Ok(request),
            ServiceRequestOrUnknown::Unknown(unknown)
                if is_known_request_type(&unknown.type_name) =>
            {
                Err(ServiceResponse::Error(protocol_error(
                    ServiceErrorCode::InvalidRequest,
                    format!("invalid IPC request payload for {}", unknown.type_name),
                    false,
                )))
            }
            ServiceRequestOrUnknown::Unknown(unknown) => Err(ServiceResponse::Error(
                invalid_request_type_error(&unknown.type_name),
            )),
        }
    }

    async fn handle_service_request(&self, request: ServiceRequest) -> RequestOutcome {
        match request {
            ServiceRequest::Subscribe => RequestOutcome {
                response: ServiceResponse::Subscribe(self.subscribe_response().await),
                subscribed: true,
            },
            ServiceRequest::GetStatus => {
                RequestOutcome::respond(ServiceResponse::Status(self.status_response().await))
            }
            ServiceRequest::GetState => {
                RequestOutcome::respond(ServiceResponse::State(self.runtime.lifecycle().await))
            }
            ServiceRequest::GetTunnels => RequestOutcome::respond(
                self.runtime
                    .list_tunnels()
                    .await
                    .map(ServiceResponse::Tunnels)
                    .unwrap_or_else(runtime_error_response),
            ),
            ServiceRequest::CreateTunnel {
                local_port,
                protocol,
                local_address,
                name,
            } => RequestOutcome::respond(
                self.runtime
                    .create_tunnel(local_port, protocol, local_address, name)
                    .await
                    .map(ServiceResponse::CreateTunnel)
                    .unwrap_or_else(runtime_error_response),
            ),
            ServiceRequest::CreateMinecraftJavaTunnel {
                local_port,
                local_address,
                name,
            } => RequestOutcome::respond(
                self.runtime
                    .create_minecraft_java_tunnel(local_port, local_address, name)
                    .await
                    .map(ServiceResponse::CreateTunnel)
                    .unwrap_or_else(runtime_error_response),
            ),
            ServiceRequest::DeleteTunnel { tunnel_id } => RequestOutcome::respond(
                self.runtime
                    .delete_tunnel(&tunnel_id)
                    .await
                    .map(ServiceResponse::DeleteTunnel)
                    .unwrap_or_else(runtime_error_response),
            ),
            ServiceRequest::GetAccount => RequestOutcome::respond(
                self.runtime
                    .account()
                    .await
                    .map(ServiceResponse::Account)
                    .unwrap_or_else(runtime_error_response),
            ),
            ServiceRequest::StartClaim => RequestOutcome::respond(
                self.runtime
                    .start_claim()
                    .await
                    .map(ServiceResponse::Claim)
                    .unwrap_or_else(runtime_error_response),
            ),
            ServiceRequest::Stop => {
                tracing::info!("Stop request received, initiating daemon shutdown");
                self.host_shutdown.cancel();
                RequestOutcome::respond(ServiceResponse::Stop(CommandResponse {
                    accepted: true,
                    message: Some("shutdown requested".to_string()),
                }))
            }
            ServiceRequest::SetSecret { secret } => RequestOutcome::respond(
                self.runtime
                    .set_secret(secret)
                    .await
                    .map(ServiceResponse::SetSecret)
                    .unwrap_or_else(runtime_error_response),
            ),
            ServiceRequest::ResetSecret => RequestOutcome::respond(
                self.runtime
                    .reset_secret()
                    .await
                    .map(ServiceResponse::ResetSecret)
                    .unwrap_or_else(runtime_error_response),
            ),
            ServiceRequest::GetSecretPath => {
                RequestOutcome::respond(ServiceResponse::SecretPath(SecretPathResponse {
                    secret_path: self
                        .runtime
                        .secret_path()
                        .map(|path| path.display().to_string()),
                }))
            }
            ServiceRequest::GetAccountLoginUrl => RequestOutcome::respond(
                self.runtime
                    .account_login_url()
                    .await
                    .map(ServiceResponse::AccountLoginUrl)
                    .unwrap_or_else(runtime_error_response),
            ),
        }
    }

    async fn subscribe_response(&self) -> playit_ipc::model::SubscribeResponse {
        let mut response = self.runtime.subscription_snapshot().await;
        response.snapshot.status.socket_path = self.socket_path.clone();
        response
    }

    async fn status_response(&self) -> ServiceStatus {
        let mut status = self.runtime.status().await;
        status.socket_path = self.socket_path.clone();
        status
    }

    async fn send_response<W: tokio::io::AsyncWrite + Unpin>(
        &self,
        writer: &mut IpcFrameWriter<W>,
        request_id: u64,
        response: ServiceResponse,
    ) -> Result<(), IpcError> {
        writer
            .write_json(&ServerEnvelope::Response(ResponseEnvelope {
                ipc_version: IPC_VERSION,
                request_id,
                response,
            }))
            .await
    }

    async fn send_hello<W: tokio::io::AsyncWrite + Unpin>(
        &self,
        writer: &mut IpcFrameWriter<W>,
    ) -> Result<(), IpcError> {
        writer
            .write_json(&ServerEnvelope::Hello(HelloEnvelope {
                protocol: protocol_info(),
            }))
            .await
    }

    async fn send_event<W: tokio::io::AsyncWrite + Unpin>(
        &self,
        writer: &mut IpcFrameWriter<W>,
        event: ServiceUpdate,
    ) -> Result<(), IpcError> {
        writer
            .write_json(&ServerEnvelope::Event(EventEnvelope {
                ipc_version: IPC_VERSION,
                event: self.transport_event(event),
            }))
            .await
    }

    fn transport_event(&self, event: ServiceUpdate) -> ServiceUpdate {
        match event {
            ServiceUpdate::Status(mut status) => {
                status.socket_path = self.socket_path.clone();
                ServiceUpdate::Status(status)
            }
            event => event,
        }
    }
}

struct RequestOutcome {
    response: ServiceResponse,
    subscribed: bool,
}

impl RequestOutcome {
    fn respond(response: ServiceResponse) -> Self {
        Self {
            response,
            subscribed: false,
        }
    }
}

fn runtime_error_response(error: RuntimeError) -> ServiceResponse {
    ServiceResponse::Error(error.as_service_error())
}

fn protocol_error(code: ServiceErrorCode, message: String, retryable: bool) -> ServiceError {
    ServiceError {
        code,
        message,
        retryable,
        details: None,
    }
}

fn invalid_request_type_error(request_type: &str) -> ServiceError {
    ServiceError {
        code: ServiceErrorCode::InvalidRequestType,
        message: format!("unknown IPC request type: {request_type}"),
        retryable: false,
        details: Some(json!({ "request_type": request_type })),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use playit_ipc::ipc::{IpcClient, RequestEnvelope, ServerEnvelope};
    use playit_ipc::model::{AgentLifecycle, ServicePhase};
    use playit_runtime::{PlayitHandle, PlayitRuntime, RuntimeOptions};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};

    fn unique_socket_path(name: &str) -> String {
        let suffix = unique_test_suffix();
        #[cfg(target_os = "windows")]
        {
            format!(
                r"\\.\pipe\playitd-adapter-{name}-{}-{suffix}",
                std::process::id()
            )
        }
        #[cfg(not(target_os = "windows"))]
        {
            std::env::temp_dir()
                .join(format!(
                    "playitd-adapter-{name}-{}-{suffix}.sock",
                    std::process::id()
                ))
                .display()
                .to_string()
        }
    }

    async fn waiting_runtime() -> (PlayitRuntime, PlayitHandle) {
        let secret_path = std::env::temp_dir().join(format!(
            "playitd-adapter-secret-{}-{}.toml",
            std::process::id(),
            unique_test_suffix()
        ));
        let (runtime, handle) = PlayitRuntime::start(RuntimeOptions {
            secret_path,
            ..RuntimeOptions::default()
        })
        .await
        .unwrap();

        for _ in 0..50 {
            if matches!(handle.lifecycle().await, AgentLifecycle::WaitingForSecret) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(matches!(
            handle.lifecycle().await,
            AgentLifecycle::WaitingForSecret
        ));
        (runtime, handle)
    }

    async fn start_server(
        name: &str,
    ) -> (
        PlayitRuntime,
        PlayitHandle,
        Arc<IpcServer>,
        CancellationToken,
        tokio::task::JoinHandle<()>,
        String,
    ) {
        let (runtime, handle) = waiting_runtime().await;
        let socket_path = unique_socket_path(name);
        let host_shutdown = CancellationToken::new();
        let server = Arc::new(
            IpcServer::new(
                handle.clone(),
                Some(socket_path.clone()),
                host_shutdown.clone(),
            )
            .await
            .unwrap(),
        );
        let listener = server.bind_listener().await.unwrap();
        let server_task = {
            let server = server.clone();
            tokio::spawn(async move {
                let _ = server.run(listener).await;
            })
        };
        (
            runtime,
            handle,
            server,
            host_shutdown,
            server_task,
            socket_path,
        )
    }

    async fn stop_server(
        runtime: PlayitRuntime,
        host_shutdown: CancellationToken,
        server_task: tokio::task::JoinHandle<()>,
        socket_path: &str,
    ) {
        host_shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), server_task).await;
        let _ = runtime.shutdown().await;
        let _ = std::fs::remove_file(socket_path);
    }

    async fn read_server_envelope<R: tokio::io::AsyncBufRead + Unpin>(
        reader: &mut R,
    ) -> ServerEnvelope {
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        serde_json::from_str(&line).unwrap()
    }

    #[tokio::test]
    async fn ipc_server_delegates_status_and_lifecycle_to_runtime() {
        let (runtime, _handle, server, host_shutdown, server_task, socket_path) =
            start_server("delegation").await;
        let mut client = IpcClient::connect_with_path(&socket_path).await.unwrap();

        let status = client.status().await.unwrap();
        assert!(matches!(status.phase, ServicePhase::WaitingForSecret));
        assert_eq!(status.socket_path, socket_path);
        assert!(matches!(
            client.lifecycle().await.unwrap(),
            AgentLifecycle::WaitingForSecret
        ));

        assert!(matches!(
            server.transport_event(ServiceUpdate::Status(ServiceStatus::default())),
            ServiceUpdate::Status(status) if status.socket_path == socket_path
        ));

        stop_server(runtime, host_shutdown, server_task, &socket_path).await;
    }

    #[tokio::test]
    async fn ipc_server_delegates_runtime_operations_and_errors() {
        let (runtime, _handle, server, host_shutdown, server_task, socket_path) =
            start_server("operations").await;

        let account = server
            .handle_service_request(ServiceRequest::GetAccount)
            .await
            .response;
        assert!(matches!(
            account,
            ServiceResponse::Account(account)
                if matches!(account.status, playit_ipc::model::AccountStatus::Unknown)
                    && account.agent_id.is_none()
        ));

        let tunnels = server
            .handle_service_request(ServiceRequest::GetTunnels)
            .await
            .response;
        assert!(matches!(
            tunnels,
            ServiceResponse::Error(ServiceError {
                code: ServiceErrorCode::ProvisioningUnavailable,
                ..
            })
        ));

        let create = server
            .handle_service_request(ServiceRequest::CreateTunnel {
                local_port: 0,
                protocol: Default::default(),
                local_address: None,
                name: None,
            })
            .await
            .response;
        assert!(matches!(
            create,
            ServiceResponse::Error(ServiceError {
                code: ServiceErrorCode::InvalidTunnelRequest,
                ..
            })
        ));

        let delete = server
            .handle_service_request(ServiceRequest::DeleteTunnel {
                tunnel_id: "not-a-uuid".to_string(),
            })
            .await
            .response;
        assert!(matches!(
            delete,
            ServiceResponse::Error(ServiceError {
                code: ServiceErrorCode::InvalidTunnelRequest,
                ..
            })
        ));

        let login = server
            .handle_service_request(ServiceRequest::GetAccountLoginUrl)
            .await
            .response;
        assert!(matches!(
            login,
            ServiceResponse::Error(ServiceError {
                code: ServiceErrorCode::ApiUnavailable,
                ..
            })
        ));

        let secret_path = server
            .handle_service_request(ServiceRequest::GetSecretPath)
            .await
            .response;
        assert!(matches!(secret_path, ServiceResponse::SecretPath(_)));

        let subscribe = server
            .handle_service_request(ServiceRequest::Subscribe)
            .await;
        assert!(subscribe.subscribed);
        assert_eq!(
            match subscribe.response {
                ServiceResponse::Subscribe(response) => response.snapshot.status.socket_path,
                other => panic!("expected subscription response, got {other:?}"),
            },
            socket_path
        );

        let claim = server
            .handle_service_request(ServiceRequest::StartClaim)
            .await
            .response;
        let claim_url = match claim {
            ServiceResponse::Claim(response) => response.claim_url,
            other => panic!("expected claim response, got {other:?}"),
        };
        let repeated_claim = server
            .handle_service_request(ServiceRequest::StartClaim)
            .await
            .response;
        assert!(matches!(
            repeated_claim,
            ServiceResponse::Claim(response) if response.claim_url == claim_url
        ));

        let set_secret = server
            .handle_service_request(ServiceRequest::SetSecret {
                secret: "not-hex".to_string(),
            })
            .await
            .response;
        assert!(matches!(
            set_secret,
            ServiceResponse::Error(ServiceError {
                code: ServiceErrorCode::SecretWriteFailed,
                ..
            })
        ));

        let reset_secret = server
            .handle_service_request(ServiceRequest::ResetSecret)
            .await
            .response;
        assert!(matches!(
            reset_secret,
            ServiceResponse::ResetSecret(CommandResponse { accepted: true, .. })
        ));

        stop_server(runtime, host_shutdown, server_task, &socket_path).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_ipc_socket_keeps_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let (runtime, _handle, _server, host_shutdown, server_task, socket_path) =
            start_server("socket-permissions").await;
        let mode = std::fs::metadata(&socket_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let expected_mode = if cfg!(target_os = "linux") {
            0o660
        } else {
            0o600
        };
        assert_eq!(mode, expected_mode);
        stop_server(runtime, host_shutdown, server_task, &socket_path).await;
    }

    #[tokio::test]
    async fn ipc_server_preserves_protocol_validation_and_connection_liveness() {
        let (runtime, _handle, _server, host_shutdown, server_task, socket_path) =
            start_server("validation").await;
        let stream = playit_ipc::ipc::try_connect(&IpcEndpoint::parse(socket_path.clone()))
            .await
            .unwrap();
        let (read_half, write_half) = stream.split();
        let mut reader = BufReader::new(read_half);
        let mut writer = BufWriter::new(write_half);
        assert!(matches!(
            read_server_envelope(&mut reader).await,
            ServerEnvelope::Hello(_)
        ));

        let unknown = serde_json::json!({
            "ipc_version": IPC_VERSION,
            "request_id": 1,
            "request": {"type": "future_request", "data": {"flag": true}}
        });
        writer
            .write_all(serde_json::to_string(&unknown).unwrap().as_bytes())
            .await
            .unwrap();
        writer.write_all(b"\n").await.unwrap();
        writer.flush().await.unwrap();

        let response = read_server_envelope(&mut reader).await;
        assert!(matches!(
            response,
            ServerEnvelope::Response(ResponseEnvelope {
                response: ServiceResponse::Error(ServiceError {
                    code: ServiceErrorCode::InvalidRequestType,
                    ..
                }),
                ..
            })
        ));

        let valid = serde_json::to_string(&RequestEnvelope {
            ipc_version: IPC_VERSION,
            request_id: 2,
            request: ServiceRequest::GetState,
        })
        .unwrap();
        writer.write_all(valid.as_bytes()).await.unwrap();
        writer.write_all(b"\n").await.unwrap();
        writer.flush().await.unwrap();
        let response = read_server_envelope(&mut reader).await;
        assert!(matches!(
            response,
            ServerEnvelope::Response(ResponseEnvelope {
                request_id: 2,
                response: ServiceResponse::State(AgentLifecycle::WaitingForSecret),
                ..
            })
        ));

        drop(writer);
        stop_server(runtime, host_shutdown, server_task, &socket_path).await;
    }

    #[tokio::test]
    async fn ipc_stop_requests_host_shutdown_without_exposing_runtime_shutdown() {
        let (runtime, handle, _server, host_shutdown, server_task, socket_path) =
            start_server("stop").await;
        let mut client = IpcClient::connect_with_path(&socket_path).await.unwrap();
        let response = client.stop().await.unwrap();
        assert!(response.accepted);
        assert!(host_shutdown.is_cancelled());
        assert!(!matches!(
            handle.lifecycle().await,
            AgentLifecycle::Stopping
        ));

        let _ = tokio::time::timeout(Duration::from_secs(2), server_task).await;
        let _ = runtime.shutdown().await;
        let _ = std::fs::remove_file(socket_path);
    }

    fn unique_test_suffix() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock must be after the Unix epoch")
            .as_nanos()
    }
}
