use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
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
use playit_agent_core::utils::now_milli;
use playit_api_client::PlayitApi;
use playit_api_client::api::{
    ApiError, ApiResponseError, AssignedAgentCreate, ClaimAgentType, ClaimExchangeError,
    ClaimSetupError, ClaimSetupResponse, DeleteError, PortType, ReqClaimExchange, ReqClaimSetup,
    ReqTunnelsCreate, ReqTunnelsDelete, TunnelCreateError, TunnelOriginCreate,
};
use playit_api_client::http_client::HttpClientError;
use playit_ipc::endpoint::IpcEndpoint;
use playit_ipc::ipc::{
    EventEnvelope, HelloEnvelope, IPC_VERSION, IncomingRequestEnvelope, IpcError, IpcFrameWriter,
    ResponseEnvelope, ServerEnvelope, ServiceRequest, ServiceRequestOrUnknown, ServiceResponse,
    framed_parts, get_default_socket_path, is_known_request_type, protocol_info, try_connect,
};
use playit_ipc::model::{
    AccountLoginUrlResponse, AccountResponse, AccountStatus, AgentLifecycle, ClaimResponse,
    CommandResponse, ConnectionStats, SecretPathResponse, ServiceError, ServiceErrorCode,
    ServiceStatus, ServiceUpdate, SubscribeResponse, SubscriptionSnapshot, TunnelCreateResponse,
    TunnelListResponse, TunnelProtocol,
};
use rand::Rng;
use serde_json::json;
use tokio::sync::{RwLock, broadcast, mpsc, oneshot};
use tokio_util::sync::CancellationToken;

const ACCOUNT_AGENTS_URL: &str = "https://playit.gg/account/agents";
const ACCOUNT_UPGRADE_URL: &str = "https://playit.gg/account/upgrade";

#[derive(Default)]
pub struct StateCache {
    lifecycle: RwLock<AgentLifecycle>,
    status: RwLock<ServiceStatus>,
    stats: RwLock<ConnectionStats>,
}

impl StateCache {
    pub async fn set_lifecycle(&self, lifecycle: AgentLifecycle) {
        *self.lifecycle.write().await = lifecycle;
    }

    pub async fn lifecycle(&self) -> AgentLifecycle {
        self.lifecycle.read().await.clone()
    }

    pub async fn set_status(&self, status: ServiceStatus) {
        *self.status.write().await = status;
    }

    pub async fn status(&self) -> ServiceStatus {
        self.status.read().await.clone()
    }

    pub async fn set_stats(&self, stats: ConnectionStats) {
        *self.stats.write().await = stats;
    }

    pub async fn stats(&self) -> ConnectionStats {
        self.stats.read().await.clone()
    }

    pub async fn subscription_snapshot(&self) -> SubscriptionSnapshot {
        SubscriptionSnapshot {
            status: self.status().await,
            lifecycle: self.lifecycle().await,
            stats: self.stats().await,
        }
    }
}

pub struct SecretProvisionRequest {
    pub secret: String,
    pub response_tx: oneshot::Sender<Result<(), String>>,
}

pub struct IpcServer {
    event_tx: broadcast::Sender<ServiceUpdate>,
    socket_path: String,
    start_time: u64,
    cancel_token: CancellationToken,
    state_cache: Arc<StateCache>,
    secret_path: Option<PathBuf>,
    secret_provision_tx: Option<mpsc::Sender<SecretProvisionRequest>>,
    secret_provision_error: ServiceError,
    secret_reset_error: ServiceError,
    api: RwLock<Option<PlayitApi>>,
    guest_login_cache: RwLock<Option<(String, u64)>>,
    claim_code: Arc<RwLock<Option<String>>>,
}

impl IpcServer {
    pub async fn new_with_sender(
        socket_path: Option<String>,
        cancel_token: CancellationToken,
        event_tx: broadcast::Sender<ServiceUpdate>,
        secret_path: Option<PathBuf>,
        secret_provision_tx: Option<mpsc::Sender<SecretProvisionRequest>>,
        secret_provision_error: ServiceError,
        secret_reset_error: ServiceError,
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
            event_tx,
            socket_path,
            start_time: now_milli(),
            cancel_token,
            state_cache: Arc::new(StateCache::default()),
            secret_path,
            secret_provision_tx,
            secret_provision_error,
            secret_reset_error,
            api: RwLock::new(None),
            guest_login_cache: RwLock::new(None),
            claim_code: Arc::new(RwLock::new(None)),
        })
    }

    pub fn event_sender(&self) -> broadcast::Sender<ServiceUpdate> {
        self.event_tx.clone()
    }

    pub fn state_cache(&self) -> Arc<StateCache> {
        self.state_cache.clone()
    }

    pub async fn set_api(&self, api: PlayitApi) {
        *self.api.write().await = Some(api);
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
                                if let Err(e) = server.handle_client(stream).await {
                                    if e.is_connection_closed() {
                                        tracing::debug!("Client disconnected: {e}");
                                    } else {
                                        tracing::warn!("Client connection error: {e}");
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            tracing::error!("Accept error: {e}");
                            // Avoid tight-loop logging if the listener enters a persistent failure state.
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
                _ = self.cancel_token.cancelled() => {
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
                    .map_err(|e| {
                        IpcError::BindFailed(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            e,
                        ))
                    })?;
                let listener = ListenerOptions::new().name(name);
                #[cfg(target_os = "windows")]
                let listener = listener
                    .security_descriptor(crate::windows::restricted_pipe_security_descriptor()?);
                listener.create_tokio().map_err(IpcError::BindFailed)
            }
            IpcEndpoint::Filesystem(path) => {
                let name = path.clone().to_fs_name::<GenericFilePath>().map_err(|e| {
                    IpcError::BindFailed(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
                })?;

                // Interprocess can apply the Unix mode before bind on platforms that support
                // fchmod(2). That closes the creation-time permission window. macOS may report
                // this operation as unsupported, so retain the shared post-bind chmod fallback
                // in bind_listener for that platform.
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
        let mut event_rx = self.event_tx.subscribe();
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
        match self.validate_request_envelope(envelope) {
            Ok(request) => self.handle_service_request(request).await,
            Err(response) => RequestOutcome::respond(response),
        }
    }

    fn validate_request_envelope(
        &self,
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
                response: self.subscribe_response().await,
                subscribed: true,
            },
            ServiceRequest::GetStatus => RequestOutcome::respond(self.status_response().await),
            ServiceRequest::GetState => {
                RequestOutcome::respond(ServiceResponse::State(self.state_cache.lifecycle().await))
            }
            ServiceRequest::GetTunnels => {
                RequestOutcome::respond(self.tunnel_list_response().await)
            }
            ServiceRequest::CreateTunnel {
                local_port,
                protocol,
                local_address,
                name,
            } => RequestOutcome::respond(
                self.create_tunnel_response(local_port, protocol, local_address, name)
                    .await,
            ),
            ServiceRequest::DeleteTunnel { tunnel_id } => {
                RequestOutcome::respond(self.delete_tunnel_response(tunnel_id).await)
            }
            ServiceRequest::GetAccount => RequestOutcome::respond(self.account_response().await),
            ServiceRequest::StartClaim => {
                RequestOutcome::respond(self.start_claim_response().await)
            }
            ServiceRequest::Stop => {
                tracing::info!("Stop request received, initiating shutdown");
                self.cancel_token.cancel();
                RequestOutcome::respond(ServiceResponse::Stop(CommandResponse {
                    accepted: true,
                    message: Some("shutdown requested".to_string()),
                }))
            }
            ServiceRequest::SetSecret { secret } => {
                RequestOutcome::respond(self.set_secret_response(secret).await)
            }
            ServiceRequest::ResetSecret => {
                RequestOutcome::respond(self.reset_secret_response().await)
            }
            ServiceRequest::GetSecretPath => {
                RequestOutcome::respond(ServiceResponse::SecretPath(SecretPathResponse {
                    secret_path: self
                        .secret_path
                        .as_ref()
                        .map(|path| path.display().to_string()),
                }))
            }
            ServiceRequest::GetAccountLoginUrl => {
                RequestOutcome::respond(self.account_login_url_response().await)
            }
        }
    }

    async fn tunnel_list_response(&self) -> ServiceResponse {
        match self.state_cache.lifecycle().await {
            AgentLifecycle::Running(state) => ServiceResponse::Tunnels(TunnelListResponse {
                tunnels: state.tunnels,
                pending_tunnels: state.pending_tunnels,
            }),
            lifecycle => {
                ServiceResponse::Error(service_not_ready_error("list tunnels", &lifecycle))
            }
        }
    }

    async fn create_tunnel_response(
        &self,
        local_port: u16,
        protocol: TunnelProtocol,
        local_address: Option<String>,
        name: Option<String>,
    ) -> ServiceResponse {
        if local_port == 0 {
            return ServiceResponse::Error(protocol_error(
                ServiceErrorCode::InvalidTunnelRequest,
                "local_port must be between 1 and 65535".to_string(),
                false,
            ));
        }

        let local_address = local_address.unwrap_or_else(|| "127.0.0.1".to_string());
        let local_ip = match IpAddr::from_str(local_address.trim()) {
            Ok(local_ip) => local_ip,
            Err(_) => {
                return ServiceResponse::Error(protocol_error(
                    ServiceErrorCode::InvalidTunnelRequest,
                    format!("local_address is not a valid IP address: {local_address}"),
                    false,
                ));
            }
        };

        let agent_id = match self.state_cache.lifecycle().await {
            AgentLifecycle::Running(state) => match uuid::Uuid::parse_str(&state.agent_id) {
                Ok(agent_id) => agent_id,
                Err(_) => {
                    return ServiceResponse::Error(protocol_error(
                        ServiceErrorCode::ApiUnavailable,
                        "The running agent has not reported a valid agent ID yet".to_string(),
                        true,
                    ));
                }
            },
            lifecycle => {
                return ServiceResponse::Error(service_not_ready_error(
                    "create a tunnel",
                    &lifecycle,
                ));
            }
        };

        let Some(api) = self.api.read().await.clone() else {
            return ServiceResponse::Error(protocol_error(
                ServiceErrorCode::ApiUnavailable,
                "The playit API is not ready yet".to_string(),
                true,
            ));
        };

        let request = ReqTunnelsCreate {
            name: name.filter(|value| !value.trim().is_empty()),
            tunnel_type: None,
            port_type: match protocol {
                TunnelProtocol::Tcp => PortType::Tcp,
                TunnelProtocol::Udp => PortType::Udp,
                TunnelProtocol::Both => PortType::Both,
            },
            port_count: 1,
            origin: TunnelOriginCreate::Agent(AssignedAgentCreate {
                agent_id,
                local_ip,
                local_port: Some(local_port),
            }),
            enabled: true,
            alloc: None,
            firewall_id: None,
            proxy_protocol: None,
        };

        match api.tunnels_create(request).await {
            Ok(tunnel_id) => ServiceResponse::CreateTunnel(TunnelCreateResponse {
                tunnel_id: tunnel_id.id.to_string(),
                message: Some("Tunnel creation accepted".to_string()),
            }),
            Err(error) => ServiceResponse::Error(map_tunnel_create_error(error)),
        }
    }

    async fn delete_tunnel_response(&self, tunnel_id: String) -> ServiceResponse {
        let tunnel_id = match uuid::Uuid::parse_str(tunnel_id.trim()) {
            Ok(tunnel_id) => tunnel_id,
            Err(_) => {
                return ServiceResponse::Error(protocol_error(
                    ServiceErrorCode::InvalidTunnelRequest,
                    "tunnel_id must be a valid UUID".to_string(),
                    false,
                ));
            }
        };

        let Some(api) = self.api.read().await.clone() else {
            return ServiceResponse::Error(protocol_error(
                ServiceErrorCode::ApiUnavailable,
                "The playit API is not ready yet".to_string(),
                true,
            ));
        };

        match api.tunnels_delete(ReqTunnelsDelete { tunnel_id }).await {
            Ok(()) => ServiceResponse::DeleteTunnel(CommandResponse {
                accepted: true,
                message: Some("Tunnel deletion accepted".to_string()),
            }),
            Err(error) => ServiceResponse::Error(map_tunnel_delete_error(error)),
        }
    }

    async fn account_response(&self) -> ServiceResponse {
        let claim_url = self.claim_url().await;
        let account = match self.state_cache.lifecycle().await {
            AgentLifecycle::Running(state) => AccountResponse {
                status: state.account_status,
                agent_id: (!state.agent_id.is_empty()).then_some(state.agent_id),
                login_link: state.login_link,
                claim_url,
            },
            _ => AccountResponse {
                status: AccountStatus::Unknown,
                agent_id: None,
                login_link: None,
                claim_url,
            },
        };
        ServiceResponse::Account(account)
    }

    async fn start_claim_response(&self) -> ServiceResponse {
        if self.cancel_token.is_cancelled() {
            return ServiceResponse::Error(protocol_error(
                ServiceErrorCode::ApiUnavailable,
                "The playit service is shutting down and cannot start an agent claim.".to_string(),
                true,
            ));
        }

        let lifecycle = self.state_cache.lifecycle().await;
        if !matches!(lifecycle, AgentLifecycle::WaitingForSecret) {
            return ServiceResponse::Error(secret_provisioning_state_error(&lifecycle));
        }

        let Some(secret_provision_tx) = self.secret_provision_tx.clone() else {
            return ServiceResponse::Error(self.secret_provision_error.clone());
        };

        let mut claim_code = self.claim_code.write().await;
        if let Some(code) = claim_code.as_ref() {
            return ServiceResponse::Claim(ClaimResponse {
                claim_url: format!("https://playit.gg/claim/{code}"),
            });
        }

        let code = generate_claim_code();
        *claim_code = Some(code.clone());
        drop(claim_code);

        let claim_code_state = self.claim_code.clone();
        let cancel_token = self.cancel_token.clone();
        let claim_code_for_task = code.clone();
        tokio::spawn(async move {
            run_claim_flow(
                claim_code_for_task,
                secret_provision_tx,
                claim_code_state,
                cancel_token,
            )
            .await;
        });

        ServiceResponse::Claim(ClaimResponse {
            claim_url: format!("https://playit.gg/claim/{code}"),
        })
    }

    async fn claim_url(&self) -> Option<String> {
        self.claim_code
            .read()
            .await
            .as_ref()
            .map(|code| format!("https://playit.gg/claim/{code}"))
    }

    async fn subscribe_response(&self) -> ServiceResponse {
        let snapshot = self.state_cache.subscription_snapshot().await;
        ServiceResponse::Subscribe(SubscribeResponse {
            protocol: protocol_info(),
            snapshot,
        })
    }

    async fn status_response(&self) -> ServiceResponse {
        let mut status = self.state_cache.status().await;
        let uptime_ms = now_milli().saturating_sub(self.start_time);
        status.uptime_secs = uptime_ms / 1000;
        ServiceResponse::Status(status)
    }

    async fn set_secret_response(&self, secret: String) -> ServiceResponse {
        let lifecycle = self.state_cache.lifecycle().await;
        if !matches!(lifecycle, AgentLifecycle::WaitingForSecret) {
            return ServiceResponse::Error(secret_provisioning_state_error(&lifecycle));
        }

        let Some(secret_provision_tx) = &self.secret_provision_tx else {
            return ServiceResponse::Error(self.secret_provision_error.clone());
        };

        let (response_tx, response_rx) = oneshot::channel();
        if secret_provision_tx
            .send(SecretProvisionRequest {
                secret,
                response_tx,
            })
            .await
            .is_err()
        {
            return ServiceResponse::Error(provisioning_unavailable_error());
        }

        match response_rx.await {
            Ok(Ok(())) => ServiceResponse::SetSecret(CommandResponse {
                accepted: true,
                message: Some("secret provisioned".to_string()),
            }),
            Ok(Err(message)) => ServiceResponse::Error(protocol_error(
                ServiceErrorCode::SecretWriteFailed,
                message,
                true,
            )),
            Err(_) => ServiceResponse::Error(provisioning_unavailable_error()),
        }
    }

    async fn reset_secret_response(&self) -> ServiceResponse {
        match self.reset_secret().await {
            Ok(message) => {
                tracing::info!("Secret reset, initiating shutdown");
                self.cancel_token.cancel();
                ServiceResponse::ResetSecret(CommandResponse {
                    accepted: true,
                    message: Some(message),
                })
            }
            Err(error) => ServiceResponse::Error(error),
        }
    }

    async fn account_login_url_response(&self) -> ServiceResponse {
        match self.get_account_login_url().await {
            Ok(login_url) => {
                ServiceResponse::AccountLoginUrl(AccountLoginUrlResponse { login_url })
            }
            Err(error) => ServiceResponse::Error(error),
        }
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
                event,
            }))
            .await
    }

    async fn reset_secret(&self) -> Result<String, ServiceError> {
        let Some(secret_path) = &self.secret_path else {
            return Err(self.secret_reset_error.clone());
        };

        match tokio::fs::remove_file(secret_path).await {
            Ok(()) => Ok(format!(
                "Deleted secret file at {}. Restart playitd to reprovision a new secret.",
                secret_path.display()
            )),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(format!(
                "Secret file was already absent at {}.",
                secret_path.display()
            )),
            Err(error) => Err(protocol_error(
                ServiceErrorCode::SecretWriteFailed,
                format!(
                    "Failed to delete secret file {}: {error}",
                    secret_path.display()
                ),
                true,
            )),
        }
    }

    async fn get_account_login_url(&self) -> Result<String, ServiceError> {
        {
            let cache = self.guest_login_cache.read().await;
            if let Some((link, ts)) = &*cache {
                if now_milli().saturating_sub(*ts) < 15_000 {
                    return Ok(link.clone());
                }
            }
        }

        let api = self.api.read().await.clone().ok_or_else(|| {
            protocol_error(
                ServiceErrorCode::ApiUnavailable,
                "playitd is not ready to generate a login URL yet".to_string(),
                true,
            )
        })?;

        let session = api
            .login_guest()
            .await
            .map_err(|error| map_generic_api_error("guest login", error))?;

        let link = format!(
            "https://playit.gg/login/guest-account/{}",
            session.session_key
        );
        *self.guest_login_cache.write().await = Some((link.clone(), now_milli()));
        Ok(link)
    }
}

fn generate_claim_code() -> String {
    let mut buffer = [0u8; 5];
    rand::rng().fill(&mut buffer);
    hex::encode(buffer)
}

fn lifecycle_name(lifecycle: &AgentLifecycle) -> &'static str {
    match lifecycle {
        AgentLifecycle::WaitingForSecret => "waiting_for_secret",
        AgentLifecycle::HasInvalidSecret(_) => "has_invalid_secret",
        AgentLifecycle::DisabledOverLimit(_) => "disabled_over_limit",
        AgentLifecycle::Starting => "starting",
        AgentLifecycle::Running(_) => "running",
        AgentLifecycle::Stopping => "stopping",
        AgentLifecycle::Error(_) => "error",
    }
}

fn service_not_ready_error(operation: &str, lifecycle: &AgentLifecycle) -> ServiceError {
    match lifecycle {
        AgentLifecycle::WaitingForSecret => protocol_error(
            ServiceErrorCode::ProvisioningUnavailable,
            format!("Cannot {operation} while the service is waiting for an agent secret."),
            true,
        ),
        AgentLifecycle::HasInvalidSecret(error) => protocol_error(
            ServiceErrorCode::InvalidSecret,
            format!("Cannot {operation}: {}", error.message),
            false,
        ),
        AgentLifecycle::DisabledOverLimit(error) => protocol_error(
            ServiceErrorCode::AgentDisabledOverLimit,
            format!("Cannot {operation}: {}", error.message),
            false,
        ),
        AgentLifecycle::Starting | AgentLifecycle::Stopping => protocol_error(
            ServiceErrorCode::ApiUnavailable,
            format!(
                "Cannot {operation} while the service is {}.",
                lifecycle_name(lifecycle)
            ),
            true,
        ),
        AgentLifecycle::Error(error) => protocol_error(
            error.code.clone(),
            format!("Cannot {operation}: {}", error.message),
            error.retryable,
        ),
        AgentLifecycle::Running(_) => protocol_error(
            ServiceErrorCode::Internal,
            format!("Cannot {operation} because the running state changed unexpectedly."),
            false,
        ),
    }
}

fn map_generic_api_error<F>(operation: &str, error: ApiError<F, HttpClientError>) -> ServiceError {
    match error {
        ApiError::Fail(_) => protocol_error(
            ServiceErrorCode::ApiRejected,
            format!("The playit API rejected {operation}."),
            false,
        ),
        ApiError::ApiError(error) => {
            map_api_response_error(operation, error, ServiceErrorCode::ApiRejected)
        }
        ApiError::ClientError(error) => map_http_client_error(operation, error),
    }
}

fn map_tunnel_create_error(error: ApiError<TunnelCreateError, HttpClientError>) -> ServiceError {
    match error {
        ApiError::Fail(failure) => map_tunnel_create_failure(failure),
        ApiError::ApiError(error) => map_api_response_error(
            "tunnel creation",
            error,
            ServiceErrorCode::InvalidTunnelRequest,
        ),
        ApiError::ClientError(error) => map_http_client_error("tunnel creation", error),
    }
}

fn map_tunnel_create_failure(failure: TunnelCreateError) -> ServiceError {
    let (code, reason) = match failure {
        TunnelCreateError::DefaultAgentNotSupported => (
            ServiceErrorCode::ApiRejected,
            "the default agent cannot be used for this request",
        ),
        TunnelCreateError::AgentNotFound => {
            (ServiceErrorCode::ApiRejected, "the agent was not found")
        }
        TunnelCreateError::InvalidAgentId => (
            ServiceErrorCode::InvalidTunnelRequest,
            "the agent ID is invalid",
        ),
        TunnelCreateError::AgentVersionTooOld => (
            ServiceErrorCode::ApiRejected,
            "the agent version is too old for this tunnel",
        ),
        TunnelCreateError::DedicatedIpNotFound => (
            ServiceErrorCode::ApiRejected,
            "the requested dedicated IP was not found",
        ),
        TunnelCreateError::DedicatedIpPortNotAvailable => (
            ServiceErrorCode::ApiRejected,
            "the requested dedicated IP port is unavailable",
        ),
        TunnelCreateError::DedicatedIpNotEnoughSpace => (
            ServiceErrorCode::ApiRejected,
            "the requested dedicated IP does not have enough space",
        ),
        TunnelCreateError::PortAllocNotFound => (
            ServiceErrorCode::ApiRejected,
            "the requested port allocation was not found",
        ),
        TunnelCreateError::InvalidIpHostname => (
            ServiceErrorCode::InvalidTunnelRequest,
            "the local IP or hostname is invalid",
        ),
        TunnelCreateError::ManagedMissingAgentId => (
            ServiceErrorCode::InvalidTunnelRequest,
            "the managed tunnel is missing an agent ID",
        ),
        TunnelCreateError::InvalidPortCount => (
            ServiceErrorCode::InvalidTunnelRequest,
            "the requested port count is invalid",
        ),
        TunnelCreateError::RequiresVerifiedAccount => (
            ServiceErrorCode::PermissionDenied,
            "a verified account is required",
        ),
        TunnelCreateError::InvalidTunnelName => (
            ServiceErrorCode::InvalidTunnelRequest,
            "the tunnel name is invalid",
        ),
        TunnelCreateError::FirewallNotFound => (
            ServiceErrorCode::ApiRejected,
            "the requested firewall was not found",
        ),
        TunnelCreateError::AllocInvalid => (
            ServiceErrorCode::InvalidTunnelRequest,
            "the allocation request is invalid",
        ),
        TunnelCreateError::InvalidOrigin => (
            ServiceErrorCode::InvalidTunnelRequest,
            "the tunnel origin is invalid",
        ),
        TunnelCreateError::RequiresPlayitPremium => (
            ServiceErrorCode::PermissionDenied,
            "a Playit Premium account is required",
        ),
        TunnelCreateError::Other => (
            ServiceErrorCode::ApiRejected,
            "the API rejected the request",
        ),
    };

    protocol_error(
        code,
        format!("The playit API rejected tunnel creation: {reason}."),
        false,
    )
}

fn map_tunnel_delete_error(error: ApiError<DeleteError, HttpClientError>) -> ServiceError {
    match error {
        ApiError::Fail(DeleteError::TunnelNotFound) => protocol_error(
            ServiceErrorCode::TunnelNotFound,
            "The requested tunnel does not exist.".to_string(),
            false,
        ),
        ApiError::ApiError(error) => map_api_response_error(
            "tunnel deletion",
            error,
            ServiceErrorCode::InvalidTunnelRequest,
        ),
        ApiError::ClientError(error) => map_http_client_error("tunnel deletion", error),
    }
}

fn map_api_response_error(
    operation: &str,
    error: ApiResponseError,
    validation_code: ServiceErrorCode,
) -> ServiceError {
    match error {
        ApiResponseError::Validation(message) => protocol_error(
            validation_code,
            format!(
                "The playit API rejected {operation}: {}.",
                bounded_message(&message)
            ),
            false,
        ),
        ApiResponseError::PathNotFound(_) => protocol_error(
            ServiceErrorCode::ApiRejected,
            format!("The playit API does not support {operation}."),
            false,
        ),
        ApiResponseError::Auth(_) => protocol_error(
            ServiceErrorCode::PermissionDenied,
            format!("The playit API did not authorize {operation}."),
            false,
        ),
        ApiResponseError::Internal(internal) => protocol_error(
            ServiceErrorCode::ApiUnavailable,
            format!(
                "The playit API reported a temporary internal error while performing {operation} (reference {}).",
                bounded_message(&internal.trace_id)
            ),
            true,
        ),
    }
}

fn map_http_client_error(operation: &str, error: HttpClientError) -> ServiceError {
    let retryable = error.is_transient();
    let (code, message) = match error {
        HttpClientError::TooManyRequests => (
            ServiceErrorCode::ApiUnavailable,
            format!("The playit API is rate limiting {operation}; try again later."),
        ),
        HttpClientError::RequestError(_) if retryable => (
            ServiceErrorCode::ApiUnavailable,
            format!("Could not reach the playit API while performing {operation}."),
        ),
        HttpClientError::RequestError(_) => (
            ServiceErrorCode::Internal,
            format!("The playit API request for {operation} could not be sent."),
        ),
        HttpClientError::ParseError(_, status) if retryable => (
            ServiceErrorCode::ApiUnavailable,
            format!("The playit API returned an invalid response for {operation} ({status})."),
        ),
        HttpClientError::ParseError(_, status) => (
            ServiceErrorCode::ApiRejected,
            format!("The playit API returned an invalid response for {operation} ({status})."),
        ),
        HttpClientError::SerializeError(_) => (
            ServiceErrorCode::Internal,
            format!("Could not prepare the playit API request for {operation}."),
        ),
    };

    protocol_error(code, message, retryable)
}

fn bounded_message(message: &str) -> String {
    const MAX_MESSAGE_CHARS: usize = 512;
    let mut chars = message.trim().chars();
    let bounded: String = chars.by_ref().take(MAX_MESSAGE_CHARS).collect();
    if chars.next().is_some() {
        format!("{bounded}…")
    } else if bounded.is_empty() {
        "no additional details".to_string()
    } else {
        bounded
    }
}

async fn run_claim_flow(
    code: String,
    secret_provision_tx: mpsc::Sender<SecretProvisionRequest>,
    claim_code_state: Arc<RwLock<Option<String>>>,
    cancel_token: CancellationToken,
) {
    run_claim_flow_with_api(
        PlayitApi::create(api_base(), None),
        code,
        secret_provision_tx,
        claim_code_state,
        cancel_token,
    )
    .await;
}

async fn run_claim_flow_with_api(
    api: PlayitApi,
    code: String,
    secret_provision_tx: mpsc::Sender<SecretProvisionRequest>,
    claim_code_state: Arc<RwLock<Option<String>>>,
    cancel_token: CancellationToken,
) {
    const CLAIM_TIMEOUT: Duration = Duration::from_secs(10 * 60);

    let timed_out = tokio::time::timeout(
        CLAIM_TIMEOUT,
        run_claim_flow_inner(api, code.clone(), secret_provision_tx, cancel_token),
    )
    .await
    .is_err();

    if timed_out {
        tracing::warn!("Agent claim flow timed out");
    }

    let mut claim_code_lock = claim_code_state.write().await;
    if claim_code_lock.as_deref() == Some(code.as_str()) {
        *claim_code_lock = None;
    }
}

async fn run_claim_flow_inner(
    api: PlayitApi,
    code: String,
    secret_provision_tx: mpsc::Sender<SecretProvisionRequest>,
    cancel_token: CancellationToken,
) {
    const CLAIM_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

    'setup: loop {
        if cancel_token.is_cancelled() {
            break;
        }

        let setup_result = tokio::select! {
            _ = cancel_token.cancelled() => None,
            result = tokio::time::timeout(
                CLAIM_REQUEST_TIMEOUT,
                api.claim_setup(ReqClaimSetup {
                    code: code.clone(),
                    agent_type: ClaimAgentType::SelfManaged,
                    version: format!("playit {}", env!("CARGO_PKG_VERSION")),
                }),
            ) => result.ok(),
        };

        let Some(setup_result) = setup_result else {
            tracing::debug!("Agent claim setup stopped before receiving a response");
            break;
        };

        match setup_result {
            Ok(ClaimSetupResponse::WaitingForUserVisit)
            | Ok(ClaimSetupResponse::WaitingForUser) => {
                if !claim_poll_delay(&cancel_token, Duration::from_millis(250)).await {
                    break;
                }
            }
            Ok(ClaimSetupResponse::UserRejected) => {
                tracing::warn!("Agent claim was rejected in the browser");
                break;
            }
            Ok(ClaimSetupResponse::UserAccepted) => {
                let exchange_result = tokio::select! {
                    _ = cancel_token.cancelled() => None,
                    result = tokio::time::timeout(
                        CLAIM_REQUEST_TIMEOUT,
                        api.claim_exchange(ReqClaimExchange { code: code.clone() }),
                    ) => result.ok(),
                };

                let Some(exchange_result) = exchange_result else {
                    tracing::debug!("Agent claim exchange stopped before receiving a response");
                    break 'setup;
                };

                match exchange_result {
                    Ok(secret) => {
                        let (response_tx, response_rx) = oneshot::channel();
                        let request = SecretProvisionRequest {
                            secret: secret.secret_key,
                            response_tx,
                        };
                        let sent = tokio::select! {
                            _ = cancel_token.cancelled() => false,
                            result = tokio::time::timeout(
                                CLAIM_REQUEST_TIMEOUT,
                                secret_provision_tx.send(request),
                            ) => matches!(result, Ok(Ok(()))),
                        };

                        if !sent {
                            tracing::warn!(
                                "Secret provisioning stopped before the claimed agent secret could be saved"
                            );
                        } else {
                            let provisioned = tokio::select! {
                                _ = cancel_token.cancelled() => false,
                                result = tokio::time::timeout(CLAIM_REQUEST_TIMEOUT, response_rx) => {
                                    matches!(result, Ok(Ok(Ok(()))))
                                },
                            };
                            if !provisioned {
                                tracing::warn!("Claimed agent secret could not be provisioned");
                            }
                        }
                        break 'setup;
                    }
                    Err(ApiError::Fail(ClaimExchangeError::NotAccepted)) => {
                        if !claim_poll_delay(&cancel_token, Duration::from_secs(1)).await {
                            break 'setup;
                        }
                    }
                    Err(ApiError::Fail(_)) => {
                        tracing::warn!("The agent claim exchange was rejected by the API");
                        break 'setup;
                    }
                    Err(ApiError::ApiError(ApiResponseError::Internal(_))) => {
                        tracing::warn!(
                            "The API failed during agent claim exchange; the claim was not retried because its result is ambiguous"
                        );
                        break 'setup;
                    }
                    Err(ApiError::ApiError(_)) => {
                        tracing::warn!("The agent claim exchange was rejected by the API");
                        break 'setup;
                    }
                    Err(ApiError::ClientError(_)) => {
                        tracing::warn!(
                            "The API connection failed during agent claim exchange; the claim was not retried because its result is ambiguous"
                        );
                        break 'setup;
                    }
                }
            }
            Err(ApiError::Fail(ClaimSetupError::InvalidCode | ClaimSetupError::CodeExpired)) => {
                tracing::warn!("The agent claim code is no longer valid");
                break;
            }
            Err(ApiError::Fail(ClaimSetupError::VersionTextTooLong)) => {
                tracing::warn!("The agent claim could not be started with the current version");
                break;
            }
            Err(ApiError::ApiError(ApiResponseError::Internal(_))) => {
                tracing::warn!(
                    "The API failed during agent claim setup; the claim was not retried"
                );
                break;
            }
            Err(ApiError::ApiError(_)) => {
                tracing::warn!("The agent claim setup was rejected by the API");
                break;
            }
            Err(ApiError::ClientError(_)) => {
                tracing::warn!("The API connection failed during agent claim setup");
                break;
            }
        }
    }
}

async fn claim_poll_delay(cancel_token: &CancellationToken, delay: Duration) -> bool {
    tokio::select! {
        _ = cancel_token.cancelled() => false,
        _ = tokio::time::sleep(delay) => true,
    }
}

fn api_base() -> String {
    dotenv::var("API_BASE").unwrap_or_else(|_| "https://api.playit.gg".to_string())
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

fn protocol_error(code: ServiceErrorCode, message: String, retryable: bool) -> ServiceError {
    ServiceError {
        code,
        message,
        retryable,
        details: None,
    }
}

fn provisioning_unavailable_error() -> ServiceError {
    protocol_error(
        ServiceErrorCode::ProvisioningUnavailable,
        "playitd is no longer waiting for secret provisioning".to_string(),
        true,
    )
}

fn invalid_request_type_error(request_type: &str) -> ServiceError {
    ServiceError {
        code: ServiceErrorCode::InvalidRequestType,
        message: format!("unknown IPC request type: {request_type}"),
        retryable: false,
        details: Some(json!({ "request_type": request_type })),
    }
}

fn over_limit_guidance() -> String {
    format!(
        "Delete unused agents: {ACCOUNT_AGENTS_URL}\nIncrease your agent limit: {ACCOUNT_UPGRADE_URL}"
    )
}

fn secret_provisioning_state_error(lifecycle: &AgentLifecycle) -> ServiceError {
    match lifecycle {
        AgentLifecycle::WaitingForSecret => protocol_error(
            ServiceErrorCode::ProvisioningUnavailable,
            "The playit service is not ready to save a secret yet. Try setup again in a few seconds."
                .to_string(),
            true,
        ),
        AgentLifecycle::HasInvalidSecret(error) => protocol_error(
            ServiceErrorCode::ProvisioningUnavailable,
            format!(
                "The playit service is not waiting for a new secret because its current secret is invalid: {}",
                error.message
            ),
            false,
        ),
        AgentLifecycle::DisabledOverLimit(error) => protocol_error(
            ServiceErrorCode::ProvisioningUnavailable,
            format!(
                "Setup is unavailable because this account is over the agent limit.\n{}\nReason: {}",
                over_limit_guidance(),
                error.message
            ),
            false,
        ),
        AgentLifecycle::Starting => protocol_error(
            ServiceErrorCode::ProvisioningUnavailable,
            "The playit service is still starting. Try setup again in a few seconds.".to_string(),
            true,
        ),
        AgentLifecycle::Running(_) => protocol_error(
            ServiceErrorCode::ProvisioningUnavailable,
            "The playit service already has a configured secret. Run `playit reset` before provisioning a new one."
                .to_string(),
            false,
        ),
        AgentLifecycle::Stopping => protocol_error(
            ServiceErrorCode::ProvisioningUnavailable,
            "The playit service is stopping and cannot accept setup right now.".to_string(),
            true,
        ),
        AgentLifecycle::Error(error) => protocol_error(
            ServiceErrorCode::ProvisioningUnavailable,
            format!(
                "The playit service reported an error and cannot accept setup right now: {}",
                error.message
            ),
            true,
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use playit_api_client::PlayitApi;
    use playit_api_client::api::{ApiError, ApiResponseError, DeleteError, TunnelCreateError};
    use playit_ipc::endpoint::IpcEndpoint;
    use playit_ipc::ipc::{
        IPC_VERSION, IpcClient, IpcError, RequestEnvelope, ServerEnvelope, ServiceRequest,
        ServiceResponse,
    };
    use playit_ipc::model::{
        AgentLifecycle, AgentState, ServiceError, ServiceErrorCode, TunnelProtocol,
    };
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::{Mutex, broadcast, mpsc};
    use tokio_util::sync::CancellationToken;

    fn test_socket_path(name: &str) -> String {
        let unique = format!(
            "playitd-ipc-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
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

    async fn spawn_test_server(
        name: &str,
    ) -> (
        Arc<IpcServer>,
        CancellationToken,
        tokio::task::JoinHandle<Result<(), IpcError>>,
        String,
    ) {
        let socket_path = test_socket_path(name);
        let cancel_token = CancellationToken::new();
        let (event_tx, _) = broadcast::channel(8);
        let server = Arc::new(
            IpcServer::new_with_sender(
                Some(socket_path.clone()),
                cancel_token.clone(),
                event_tx,
                None,
                None,
                protocol_error(
                    ServiceErrorCode::ProvisioningUnavailable,
                    "provisioning unavailable".to_string(),
                    false,
                ),
                protocol_error(
                    ServiceErrorCode::SecretWriteFailed,
                    "secret reset unavailable".to_string(),
                    false,
                ),
            )
            .await
            .unwrap(),
        );
        let listener = server.bind_listener().await.unwrap();
        let handle = tokio::spawn(server.clone().run(listener));

        (server, cancel_token, handle, socket_path)
    }

    async fn shutdown_server(
        cancel_token: CancellationToken,
        handle: tokio::task::JoinHandle<Result<(), IpcError>>,
    ) {
        cancel_token.cancel();
        let _ = handle.await.unwrap();
    }

    async fn connect_raw(
        socket_path: &str,
    ) -> (
        BufReader<interprocess::local_socket::tokio::RecvHalf>,
        BufWriter<interprocess::local_socket::tokio::SendHalf>,
    ) {
        let endpoint = IpcEndpoint::parse(socket_path);
        let stream = try_connect(&endpoint).await.unwrap();
        let (reader, writer) = stream.split();
        (BufReader::new(reader), BufWriter::new(writer))
    }

    async fn read_server_envelope<R: tokio::io::AsyncBufRead + Unpin>(
        reader: &mut R,
    ) -> ServerEnvelope {
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        serde_json::from_str(line.trim()).unwrap()
    }

    struct ApiMockResponse {
        status: &'static str,
        body: &'static str,
    }

    async fn spawn_api_server(
        responses: Vec<ApiMockResponse>,
    ) -> (
        String,
        Arc<Mutex<Vec<serde_json::Value>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let requests_for_task = requests.clone();

        let task = tokio::spawn(async move {
            for response in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request = read_http_request(&mut stream).await;
                if let Some(body) = http_request_body(&request) {
                    requests_for_task.lock().await.push(body);
                }

                let response = format!(
                    "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response.status,
                    response.body.len(),
                    response.body,
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });

        (format!("http://{address}"), requests, task)
    }

    async fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
        let mut request = Vec::new();
        let mut chunk = [0u8; 4096];

        loop {
            let read = stream.read(&mut chunk).await.unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);

            let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n")
            else {
                continue;
            };
            let body_start = header_end + 4;
            let body_length = http_content_length(&request[..header_end]).unwrap_or(0);
            if request.len() >= body_start + body_length {
                break;
            }
        }

        request
    }

    fn http_content_length(headers: &[u8]) -> Option<usize> {
        std::str::from_utf8(headers)
            .ok()?
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().ok())
            })
            .flatten()
    }

    fn http_request_body(request: &[u8]) -> Option<serde_json::Value> {
        let header_end = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")?;
        let body_start = header_end + 4;
        let body_length = http_content_length(&request[..header_end])?;
        serde_json::from_slice(&request[body_start..body_start + body_length]).ok()
    }

    async fn new_direct_server(
        secret_provision_tx: Option<mpsc::Sender<SecretProvisionRequest>>,
    ) -> Arc<IpcServer> {
        let socket_path = test_socket_path("direct");
        let cancel_token = CancellationToken::new();
        let (event_tx, _) = broadcast::channel(8);
        Arc::new(
            IpcServer::new_with_sender(
                Some(socket_path),
                cancel_token,
                event_tx,
                None,
                secret_provision_tx,
                protocol_error(
                    ServiceErrorCode::ProvisioningUnavailable,
                    "provisioning unavailable".to_string(),
                    false,
                ),
                protocol_error(
                    ServiceErrorCode::SecretWriteFailed,
                    "secret reset unavailable".to_string(),
                    false,
                ),
            )
            .await
            .unwrap(),
        )
    }

    async fn running_server() -> Arc<IpcServer> {
        let server = new_direct_server(None).await;
        server
            .state_cache()
            .set_lifecycle(AgentLifecycle::Running(AgentState {
                agent_id: uuid::Uuid::nil().to_string(),
                ..AgentState::default()
            }))
            .await;
        server
    }

    fn service_error(response: ServiceResponse) -> ServiceError {
        match response {
            ServiceResponse::Error(error) => error,
            other => panic!("expected service error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn server_writes_hello_immediately() {
        let (_server, cancel_token, handle, socket_path) = spawn_test_server("hello").await;
        let mut client = IpcClient::connect_with_path(&socket_path).await.unwrap();
        assert_eq!(client.server_protocol().ipc_version, IPC_VERSION);
        assert!(!client.server_protocol().capabilities.is_empty());
        let lifecycle = client.lifecycle().await.unwrap();
        assert!(matches!(lifecycle, AgentLifecycle::Starting));
        shutdown_server(cancel_token, handle).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_socket_has_restricted_permissions() {
        let (_server, cancel_token, handle, socket_path) =
            spawn_test_server("socket-permissions").await;
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
        shutdown_server(cancel_token, handle).await;
    }

    #[tokio::test]
    async fn malformed_request_does_not_stop_the_server() {
        let (_server, cancel_token, handle, socket_path) =
            spawn_test_server("malformed-request").await;
        let (mut reader, mut writer) = connect_raw(&socket_path).await;
        let _ = read_server_envelope(&mut reader).await;

        writer.write_all(b"{not-json}\n").await.unwrap();
        writer.flush().await.unwrap();
        let mut response = String::new();
        let _ = reader.read_line(&mut response).await;

        let mut client = IpcClient::connect_with_path(&socket_path).await.unwrap();
        assert!(matches!(
            client.lifecycle().await.unwrap(),
            AgentLifecycle::Starting
        ));
        shutdown_server(cancel_token, handle).await;
    }

    #[tokio::test]
    async fn create_tunnel_accepts_all_protocols_and_uses_structured_origin_fields() {
        let success_body =
            r#"{"status":"success","data":{"id":"00000000-0000-0000-0000-000000000001"}}"#;
        let (api_base, requests, api_task) = spawn_api_server(vec![
            ApiMockResponse {
                status: "200 OK",
                body: success_body,
            },
            ApiMockResponse {
                status: "200 OK",
                body: success_body,
            },
            ApiMockResponse {
                status: "200 OK",
                body: success_body,
            },
        ])
        .await;
        let server = running_server().await;
        server.set_api(PlayitApi::create(api_base, None)).await;

        for protocol in [
            TunnelProtocol::Tcp,
            TunnelProtocol::Udp,
            TunnelProtocol::Both,
        ] {
            let response = server
                .create_tunnel_response(25565, protocol, None, Some("".to_string()))
                .await;
            let ServiceResponse::CreateTunnel(response) = response else {
                panic!("expected successful tunnel creation");
            };
            assert_eq!(response.tunnel_id, "00000000-0000-0000-0000-000000000001");
        }

        api_task.await.unwrap();
        let requests = requests.lock().await;
        assert_eq!(requests.len(), 3);
        for (request, protocol) in requests.iter().zip(["tcp", "udp", "both"]) {
            assert!(request["name"].is_null());
            assert_eq!(request["port_type"], protocol);
            assert_eq!(request["port_count"], 1);
            assert_eq!(request["origin"]["type"], "agent");
            assert_eq!(request["origin"]["data"]["local_ip"], "127.0.0.1");
            assert_eq!(request["origin"]["data"]["local_port"], 25565);
        }
    }

    #[tokio::test]
    async fn create_tunnel_rejects_invalid_input_and_unready_service() {
        let server = new_direct_server(None).await;

        let error = service_error(
            server
                .create_tunnel_response(0, TunnelProtocol::Tcp, None, None)
                .await,
        );
        assert!(matches!(error.code, ServiceErrorCode::InvalidTunnelRequest));
        assert!(!error.retryable);

        let error = service_error(
            server
                .create_tunnel_response(
                    25565,
                    TunnelProtocol::Tcp,
                    Some("not-an-ip".to_string()),
                    None,
                )
                .await,
        );
        assert!(matches!(error.code, ServiceErrorCode::InvalidTunnelRequest));
        assert!(!error.retryable);

        let error = service_error(
            server
                .create_tunnel_response(25565, TunnelProtocol::Tcp, None, None)
                .await,
        );
        assert!(matches!(error.code, ServiceErrorCode::ApiUnavailable));
        assert!(error.retryable);
    }

    #[tokio::test]
    async fn create_tunnel_maps_api_validation_to_non_retryable_error() {
        let (api_base, _requests, api_task) = spawn_api_server(vec![ApiMockResponse {
            status: "200 OK",
            body: r#"{"status":"error","data":{"type":"validation","message":"invalid tunnel request"}}"#,
        }])
        .await;
        let server = running_server().await;
        server.set_api(PlayitApi::create(api_base, None)).await;

        let error = service_error(
            server
                .create_tunnel_response(25565, TunnelProtocol::Tcp, None, None)
                .await,
        );
        assert!(matches!(error.code, ServiceErrorCode::InvalidTunnelRequest));
        assert!(!error.retryable);
        assert!(error.message.contains("invalid tunnel request"));
        api_task.await.unwrap();
    }

    #[tokio::test]
    async fn create_tunnel_maps_transport_failure_to_retryable_api_unavailable() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let server = running_server().await;
        server
            .set_api(PlayitApi::create(format!("http://127.0.0.1:{port}"), None))
            .await;

        let error = service_error(
            server
                .create_tunnel_response(25565, TunnelProtocol::Tcp, None, None)
                .await,
        );
        assert!(matches!(error.code, ServiceErrorCode::ApiUnavailable));
        assert!(error.retryable);
    }

    #[tokio::test]
    async fn delete_tunnel_validates_uuid_and_maps_typed_failures() {
        let server = new_direct_server(None).await;
        let error = service_error(
            server
                .delete_tunnel_response("not-a-uuid".to_string())
                .await,
        );
        assert!(matches!(error.code, ServiceErrorCode::InvalidTunnelRequest));
        assert!(!error.retryable);

        let error = map_tunnel_delete_error(ApiError::Fail(DeleteError::TunnelNotFound));
        assert!(matches!(error.code, ServiceErrorCode::TunnelNotFound));
        assert!(!error.retryable);
        assert!(error.message.contains("does not exist"));
    }

    #[tokio::test]
    async fn delete_tunnel_maps_success_and_temporary_api_failure() {
        let (api_base, _requests, api_task) = spawn_api_server(vec![ApiMockResponse {
            status: "200 OK",
            body: r#"{"status":"success","data":null}"#,
        }])
        .await;
        let server = running_server().await;
        server.set_api(PlayitApi::create(api_base, None)).await;

        let response = server
            .delete_tunnel_response("00000000-0000-0000-0000-000000000001".to_string())
            .await;
        assert!(matches!(response, ServiceResponse::DeleteTunnel(_)));
        api_task.await.unwrap();

        let (api_base, _requests, api_task) = spawn_api_server(vec![ApiMockResponse {
            status: "500 Internal Server Error",
            body: r#"{"status":"error","data":{"type":"internal","message":{"trace_id":"test-trace"}}}"#,
        }])
        .await;
        server.set_api(PlayitApi::create(api_base, None)).await;

        let error = service_error(
            server
                .delete_tunnel_response("00000000-0000-0000-0000-000000000001".to_string())
                .await,
        );
        assert!(matches!(error.code, ServiceErrorCode::ApiUnavailable));
        assert!(error.retryable);
        assert!(error.message.contains("test-trace"));
        api_task.await.unwrap();
    }

    #[test]
    fn typed_business_failures_are_not_reported_as_outages() {
        let error =
            map_tunnel_create_error(ApiError::Fail(TunnelCreateError::RequiresVerifiedAccount));
        assert!(matches!(error.code, ServiceErrorCode::PermissionDenied));
        assert!(!error.retryable);

        let error = map_api_response_error(
            "tunnel creation",
            ApiResponseError::Validation("bad local address".to_string()),
            ServiceErrorCode::InvalidTunnelRequest,
        );
        assert!(matches!(error.code, ServiceErrorCode::InvalidTunnelRequest));
        assert!(!error.retryable);
    }

    #[tokio::test]
    async fn start_claim_returns_existing_url_without_starting_duplicate_flow() {
        let (secret_tx, _secret_rx) = mpsc::channel(1);
        let server = new_direct_server(Some(secret_tx)).await;
        server
            .state_cache()
            .set_lifecycle(AgentLifecycle::WaitingForSecret)
            .await;
        *server.claim_code.write().await = Some("active-code".to_string());

        let response = server.start_claim_response().await;
        assert!(matches!(
            response,
            ServiceResponse::Claim(ClaimResponse { claim_url })
                if claim_url == "https://playit.gg/claim/active-code"
        ));
    }

    #[tokio::test]
    async fn start_claim_rejects_new_flow_during_shutdown() {
        let (secret_tx, _secret_rx) = mpsc::channel(1);
        let server = new_direct_server(Some(secret_tx)).await;
        server
            .state_cache()
            .set_lifecycle(AgentLifecycle::WaitingForSecret)
            .await;
        server.cancel_token.cancel();

        let error = service_error(server.start_claim_response().await);
        assert!(matches!(error.code, ServiceErrorCode::ApiUnavailable));
        assert!(error.retryable);
        assert!(server.claim_code.read().await.is_none());
    }

    #[tokio::test]
    async fn account_response_reports_running_agent_and_active_claim() {
        let server = new_direct_server(None).await;
        server
            .state_cache()
            .set_lifecycle(AgentLifecycle::Running(AgentState {
                agent_id: "agent-id".to_string(),
                account_status: playit_ipc::model::AccountStatus::Verified,
                login_link: Some("https://playit.gg/login/example".to_string()),
                ..AgentState::default()
            }))
            .await;
        *server.claim_code.write().await = Some("active-code".to_string());

        let ServiceResponse::Account(account) = server.account_response().await else {
            panic!("expected account response");
        };
        assert!(matches!(
            account.status,
            playit_ipc::model::AccountStatus::Verified
        ));
        assert_eq!(account.agent_id.as_deref(), Some("agent-id"));
        assert_eq!(
            account.login_link.as_deref(),
            Some("https://playit.gg/login/example")
        );
        assert_eq!(
            account.claim_url.as_deref(),
            Some("https://playit.gg/claim/active-code")
        );
    }

    #[tokio::test]
    async fn account_response_omits_agent_id_until_the_agent_is_configured() {
        let server = new_direct_server(None).await;
        server
            .state_cache()
            .set_lifecycle(AgentLifecycle::WaitingForSecret)
            .await;

        let ServiceResponse::Account(account) = server.account_response().await else {
            panic!("expected account response");
        };

        assert!(matches!(
            account.status,
            playit_ipc::model::AccountStatus::Unknown
        ));
        assert!(account.agent_id.is_none());
        assert!(account.login_link.is_none());
        assert!(account.claim_url.is_none());
    }

    #[tokio::test]
    async fn account_response_omits_an_empty_agent_id() {
        let server = new_direct_server(None).await;
        server
            .state_cache()
            .set_lifecycle(AgentLifecycle::Running(AgentState::default()))
            .await;

        let ServiceResponse::Account(account) = server.account_response().await else {
            panic!("expected account response");
        };

        assert!(account.agent_id.is_none());
    }

    #[tokio::test]
    async fn claim_flow_clears_state_after_failure_and_cancellation() {
        let (api_base, _requests, api_task) = spawn_api_server(vec![ApiMockResponse {
            status: "200 OK",
            body: r#"{"status":"fail","data":"InvalidCode"}"#,
        }])
        .await;
        let (secret_tx, _secret_rx) = mpsc::channel(1);
        let claim_code_state = Arc::new(RwLock::new(Some("failed-code".to_string())));
        run_claim_flow_with_api(
            PlayitApi::create(api_base, None),
            "failed-code".to_string(),
            secret_tx,
            claim_code_state.clone(),
            CancellationToken::new(),
        )
        .await;
        assert!(claim_code_state.read().await.is_none());
        api_task.await.unwrap();

        let (secret_tx, _secret_rx) = mpsc::channel(1);
        let claim_code_state = Arc::new(RwLock::new(Some("cancelled-code".to_string())));
        let cancel_token = CancellationToken::new();
        cancel_token.cancel();
        run_claim_flow_with_api(
            PlayitApi::create("http://127.0.0.1:1".to_string(), None),
            "cancelled-code".to_string(),
            secret_tx,
            claim_code_state.clone(),
            cancel_token,
        )
        .await;
        assert!(claim_code_state.read().await.is_none());
    }

    #[tokio::test]
    async fn successful_claim_provisions_secret_internally_and_clears_state() {
        let (api_base, _requests, api_task) = spawn_api_server(vec![
            ApiMockResponse {
                status: "200 OK",
                body: r#"{"status":"success","data":"UserAccepted"}"#,
            },
            ApiMockResponse {
                status: "200 OK",
                body: r#"{"status":"success","data":{"secret_key":"deadbeef"}}"#,
            },
        ])
        .await;
        let (secret_tx, mut secret_rx) = mpsc::channel(1);
        let claim_code_state = Arc::new(RwLock::new(Some("successful-code".to_string())));
        let flow = tokio::spawn(run_claim_flow_with_api(
            PlayitApi::create(api_base, None),
            "successful-code".to_string(),
            secret_tx,
            claim_code_state.clone(),
            CancellationToken::new(),
        ));

        let request = secret_rx.recv().await.unwrap();
        assert_eq!(request.secret, "deadbeef");
        request.response_tx.send(Ok(())).unwrap();
        flow.await.unwrap();

        assert!(claim_code_state.read().await.is_none());
        api_task.await.unwrap();
    }

    #[tokio::test]
    async fn unknown_request_type_returns_error_and_connection_stays_open() {
        let (_server, cancel_token, handle, socket_path) = spawn_test_server("unknown-type").await;
        let (mut reader, mut writer) = connect_raw(&socket_path).await;

        let hello = read_server_envelope(&mut reader).await;
        assert!(matches!(hello, ServerEnvelope::Hello(_)));

        let unknown_request = serde_json::json!({
            "ipc_version": IPC_VERSION,
            "request_id": 1,
            "request": {
                "type": "future_request",
                "data": {"flag": true}
            }
        });
        writer
            .write_all(serde_json::to_string(&unknown_request).unwrap().as_bytes())
            .await
            .unwrap();
        writer.write_all(b"\n").await.unwrap();
        writer.flush().await.unwrap();

        let response = read_server_envelope(&mut reader).await;
        match response {
            ServerEnvelope::Response(response) => match response.response {
                ServiceResponse::Error(error) => {
                    assert!(matches!(error.code, ServiceErrorCode::InvalidRequestType));
                    assert_eq!(
                        error.details.unwrap()["request_type"],
                        serde_json::Value::String("future_request".to_string())
                    );
                }
                other => panic!("expected error response, got {other:?}"),
            },
            other => panic!("expected response frame, got {other:?}"),
        }

        let valid_request = serde_json::to_string(&RequestEnvelope {
            ipc_version: IPC_VERSION,
            request_id: 2,
            request: ServiceRequest::GetState,
        })
        .unwrap();
        writer.write_all(valid_request.as_bytes()).await.unwrap();
        writer.write_all(b"\n").await.unwrap();
        writer.flush().await.unwrap();

        let response = read_server_envelope(&mut reader).await;
        match response {
            ServerEnvelope::Response(response) => {
                assert_eq!(response.request_id, 2);
                assert!(matches!(
                    response.response,
                    ServiceResponse::State(AgentLifecycle::Starting)
                ));
            }
            other => panic!("expected response frame, got {other:?}"),
        }

        shutdown_server(cancel_token, handle).await;
    }

    #[tokio::test]
    async fn invalid_payload_for_known_request_returns_invalid_request() {
        let (_server, cancel_token, handle, socket_path) =
            spawn_test_server("invalid-payload").await;
        let (mut reader, mut writer) = connect_raw(&socket_path).await;

        let _ = read_server_envelope(&mut reader).await;

        let invalid_request = serde_json::json!({
            "ipc_version": IPC_VERSION,
            "request_id": 1,
            "request": {
                "type": "set_secret"
            }
        });
        writer
            .write_all(serde_json::to_string(&invalid_request).unwrap().as_bytes())
            .await
            .unwrap();
        writer.write_all(b"\n").await.unwrap();
        writer.flush().await.unwrap();

        let response = read_server_envelope(&mut reader).await;
        match response {
            ServerEnvelope::Response(response) => match response.response {
                ServiceResponse::Error(error) => {
                    assert!(matches!(error.code, ServiceErrorCode::InvalidRequest));
                    assert!(error.message.contains("set_secret"));
                }
                other => panic!("expected error response, got {other:?}"),
            },
            other => panic!("expected response frame, got {other:?}"),
        }

        shutdown_server(cancel_token, handle).await;
    }

    #[tokio::test]
    async fn mismatched_ipc_version_returns_unsupported_protocol() {
        let (_server, cancel_token, handle, socket_path) =
            spawn_test_server("version-mismatch").await;
        let (mut reader, mut writer) = connect_raw(&socket_path).await;

        let _ = read_server_envelope(&mut reader).await;

        let request = serde_json::to_string(&RequestEnvelope {
            ipc_version: IPC_VERSION + 1,
            request_id: 1,
            request: ServiceRequest::GetState,
        })
        .unwrap();
        writer.write_all(request.as_bytes()).await.unwrap();
        writer.write_all(b"\n").await.unwrap();
        writer.flush().await.unwrap();

        let response = read_server_envelope(&mut reader).await;
        match response {
            ServerEnvelope::Response(response) => match response.response {
                ServiceResponse::Error(error) => {
                    assert!(matches!(error.code, ServiceErrorCode::UnsupportedProtocol));
                }
                other => panic!("expected error response, got {other:?}"),
            },
            other => panic!("expected response frame, got {other:?}"),
        }

        shutdown_server(cancel_token, handle).await;
    }
}
