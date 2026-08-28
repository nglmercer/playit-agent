use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use playit_api_client::PlayitApi;
use playit_api_client::api::Platform;
use playit_ipc::model::{
    AccountLoginUrlResponse, AccountResponse, AccountStatus, AgentLifecycle, ClaimResponse,
    CommandResponse, ServiceErrorCode, ServiceStatus, ServiceUpdate, SubscribeResponse,
    TunnelCreateResponse, TunnelListResponse, TunnelProtocol,
};
use tokio::sync::{Mutex as AsyncMutex, RwLock, broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::claim::{claim_url, generate_claim_code, run_claim_flow};
use crate::error::RuntimeError;
use crate::options::{VersionDetails, platform_for_options};
use crate::secret::{SecretProvisionRequest, SecretSource, reset_secret_file};
use crate::state::{StateCache, StatusContext};
use crate::tunnels::{
    create_request, map_generic_api_error, map_tunnel_create_error, map_tunnel_delete_error,
    parse_tunnel_id, secret_provisioning_state_error, tunnel_list,
};

pub(crate) struct RuntimeInner {
    pub(crate) state_cache: Arc<StateCache>,
    pub(crate) event_tx: broadcast::Sender<ServiceUpdate>,
    pub(crate) cancel_token: CancellationToken,
    pub(crate) status_context: StatusContext,
    pub(crate) secret_source: SecretSource,
    pub(crate) secret_provision_tx: Option<mpsc::Sender<SecretProvisionRequest>>,
    pub(crate) api: RwLock<Option<PlayitApi>>,
    pub(crate) guest_login_cache: Arc<RwLock<Option<(String, u64)>>>,
    pub(crate) claim_code: Arc<RwLock<Option<String>>>,
    pub(crate) claim_tasks: AsyncMutex<Vec<JoinHandle<()>>>,
    pub(crate) agent_cancel: Mutex<Option<CancellationToken>>,
    pub(crate) api_base: String,
    pub(crate) version: VersionDetails,
    pub(crate) agent_version: playit_api_client::api::AgentVersion,
    pub(crate) platform: Platform,
}

impl RuntimeInner {
    pub(crate) fn request_shutdown(&self) {
        self.cancel_token.cancel();
        if let Some(agent_cancel) = self
            .agent_cancel
            .lock()
            .expect("agent cancellation mutex poisoned")
            .as_ref()
        {
            agent_cancel.cancel();
        }
    }

    pub(crate) fn set_agent_cancel(&self, token: Option<CancellationToken>) {
        *self
            .agent_cancel
            .lock()
            .expect("agent cancellation mutex poisoned") = token;
    }

    pub(crate) async fn set_api(&self, api: Option<PlayitApi>) {
        *self.api.write().await = api;
    }

    pub(crate) async fn publish_state(&self, status: ServiceStatus, lifecycle: AgentLifecycle) {
        self.state_cache.set_status(status.clone()).await;
        self.state_cache.set_lifecycle(lifecycle.clone()).await;
        let _ = self.event_tx.send(ServiceUpdate::Status(status));
        let _ = self.event_tx.send(ServiceUpdate::Lifecycle(lifecycle));
    }

    pub(crate) async fn join_claim_tasks(&self) {
        let tasks = std::mem::take(&mut *self.claim_tasks.lock().await);
        for task in tasks {
            if let Err(error) = task.await
                && !error.is_cancelled()
            {
                tracing::debug!(?error, "claim task ended with an error");
            }
        }
    }
}

/// Cloneable direct-control handle for a running Playit runtime.
#[derive(Clone)]
pub struct PlayitHandle {
    pub(crate) inner: Arc<RuntimeInner>,
}

impl PlayitHandle {
    pub(crate) fn new(inner: Arc<RuntimeInner>) -> Self {
        Self { inner }
    }

    /// Return the current runtime status.
    pub async fn status(&self) -> ServiceStatus {
        let mut status = self.inner.state_cache.status().await;
        status.uptime_secs = playit_agent_core::utils::now_milli()
            .saturating_sub(self.inner.status_context.start_time)
            / 1000;
        status
    }

    /// Return the current lifecycle state.
    pub async fn lifecycle(&self) -> AgentLifecycle {
        self.inner.state_cache.lifecycle().await
    }

    /// Return the current connection statistics.
    pub async fn stats(&self) -> playit_ipc::model::ConnectionStats {
        self.inner.state_cache.stats().await
    }

    /// Subscribe to status, lifecycle, and statistics updates.
    pub fn subscribe(&self) -> broadcast::Receiver<ServiceUpdate> {
        self.inner.event_tx.subscribe()
    }

    /// Return a current snapshot suitable for initializing an event consumer.
    pub async fn subscription_snapshot(&self) -> SubscribeResponse {
        let mut snapshot = self.inner.state_cache.subscription_snapshot().await;
        snapshot.status = self.status().await;
        SubscribeResponse {
            protocol: playit_ipc::ipc::protocol_info(),
            snapshot,
        }
    }

    /// Return the dedicated secret path, if this runtime uses file-backed
    /// secret storage.
    pub fn secret_path(&self) -> Option<PathBuf> {
        self.inner.secret_source.secret_path().map(PathBuf::from)
    }

    /// Return the event sender for a host-owned logging adapter.
    ///
    /// Most consumers should use subscribe instead. The daemon uses this
    /// sender to preserve its existing IPC log stream.
    pub fn event_sender(&self) -> broadcast::Sender<ServiceUpdate> {
        self.inner.event_tx.clone()
    }

    /// Read the account state without exposing the account secret.
    pub async fn account(&self) -> Result<AccountResponse, RuntimeError> {
        self.ensure_running_or_waiting()?;

        let claim_url = self.claim_url().await;
        match self.inner.state_cache.lifecycle().await {
            AgentLifecycle::Running(state) => Ok(AccountResponse {
                status: state.account_status,
                agent_id: (!state.agent_id.is_empty()).then_some(state.agent_id),
                login_link: state.login_link,
                claim_url,
            }),
            _ => Ok(AccountResponse {
                status: AccountStatus::Unknown,
                agent_id: None,
                login_link: None,
                claim_url,
            }),
        }
    }

    /// Create or return the short-lived guest account login URL.
    pub async fn account_login_url(&self) -> Result<AccountLoginUrlResponse, RuntimeError> {
        self.ensure_running_or_waiting()?;

        {
            let cache = self.inner.guest_login_cache.read().await;
            if let Some((link, timestamp)) = &*cache
                && playit_agent_core::utils::now_milli().saturating_sub(*timestamp) < 15_000
            {
                return Ok(AccountLoginUrlResponse {
                    login_url: link.clone(),
                });
            }
        }

        let api = self.inner.api.read().await.clone().ok_or_else(|| {
            RuntimeError::api(
                ServiceErrorCode::ApiUnavailable,
                "The Playit API is not ready yet.",
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
        *self.inner.guest_login_cache.write().await =
            Some((link.clone(), playit_agent_core::utils::now_milli()));

        Ok(AccountLoginUrlResponse { login_url: link })
    }

    /// Start the browser claim flow and return its URL.
    ///
    /// Calling this while an existing claim is active is idempotent and
    /// returns the existing URL.
    pub async fn start_claim(&self) -> Result<ClaimResponse, RuntimeError> {
        if self.inner.cancel_token.is_cancelled() {
            return Err(RuntimeError::stopped());
        }

        let lifecycle = self.inner.state_cache.lifecycle().await;
        if !matches!(lifecycle, AgentLifecycle::WaitingForSecret) {
            return Err(secret_provisioning_state_error(&lifecycle));
        }

        let Some(secret_provision_tx) = self.inner.secret_provision_tx.clone() else {
            return Err(self.inner.secret_source.provisioning_error());
        };

        let mut claim_code = self.inner.claim_code.write().await;
        if let Some(code) = claim_code.as_ref() {
            return Ok(ClaimResponse {
                claim_url: claim_url(code),
            });
        }

        let code = generate_claim_code();
        *claim_code = Some(code.clone());
        drop(claim_code);

        let task = tokio::spawn(run_claim_flow(
            self.inner.api_base.clone(),
            self.inner.version.clone(),
            code.clone(),
            secret_provision_tx,
            self.inner.claim_code.clone(),
            self.inner.cancel_token.child_token(),
        ));
        self.inner.claim_tasks.lock().await.push(task);

        Ok(ClaimResponse {
            claim_url: claim_url(&code),
        })
    }

    /// List materialized and pending tunnels from the authoritative state.
    pub async fn list_tunnels(&self) -> Result<TunnelListResponse, RuntimeError> {
        self.ensure_running()?;
        tunnel_list(self.inner.state_cache.lifecycle().await)
    }

    /// Create a TCP, UDP, or dual-protocol tunnel for this agent.
    pub async fn create_tunnel(
        &self,
        local_port: u16,
        protocol: TunnelProtocol,
        local_address: Option<String>,
        name: Option<String>,
    ) -> Result<TunnelCreateResponse, RuntimeError> {
        self.ensure_running()?;
        let request = create_request(
            self.inner.state_cache.lifecycle().await,
            local_port,
            protocol,
            local_address,
            name,
        )?;
        let api = self.inner.api.read().await.clone().ok_or_else(|| {
            RuntimeError::api(
                ServiceErrorCode::ApiUnavailable,
                "The Playit API is not ready yet.",
                true,
            )
        })?;

        let tunnel_id = api
            .tunnels_create(request)
            .await
            .map_err(map_tunnel_create_error)?;
        Ok(TunnelCreateResponse {
            tunnel_id: tunnel_id.id.to_string(),
            message: Some("Tunnel creation accepted".to_string()),
        })
    }

    /// Delete a tunnel by UUID.
    pub async fn delete_tunnel(&self, tunnel_id: &str) -> Result<CommandResponse, RuntimeError> {
        self.ensure_running()?;
        let tunnel_id = parse_tunnel_id(tunnel_id)?;
        let api = self.inner.api.read().await.clone().ok_or_else(|| {
            RuntimeError::api(
                ServiceErrorCode::ApiUnavailable,
                "The Playit API is not ready yet.",
                true,
            )
        })?;

        api.tunnels_delete(playit_api_client::api::ReqTunnelsDelete { tunnel_id })
            .await
            .map_err(map_tunnel_delete_error)?;
        Ok(CommandResponse {
            accepted: true,
            message: Some("Tunnel deletion accepted".to_string()),
        })
    }

    /// Validate, persist, and activate a file-backed secret.
    pub async fn set_secret(&self, secret: String) -> Result<CommandResponse, RuntimeError> {
        if self.inner.cancel_token.is_cancelled() {
            return Err(RuntimeError::stopped());
        }

        let lifecycle = self.inner.state_cache.lifecycle().await;
        if !matches!(lifecycle, AgentLifecycle::WaitingForSecret) {
            return Err(secret_provisioning_state_error(&lifecycle));
        }

        let Some(secret_provision_tx) = self.inner.secret_provision_tx.clone() else {
            return Err(self.inner.secret_source.provisioning_error());
        };

        let (response_tx, response_rx) = oneshot::channel();
        let send_result = tokio::select! {
            _ = self.inner.cancel_token.cancelled() => None,
            result = secret_provision_tx.send(SecretProvisionRequest {
                secret,
                response_tx,
            }) => Some(result),
        };
        match send_result {
            Some(Ok(())) => {}
            Some(Err(_)) | None => return Err(RuntimeError::stopped()),
        }

        let response = tokio::select! {
            _ = self.inner.cancel_token.cancelled() => None,
            result = response_rx => Some(result),
        };
        match response {
            Some(Ok(Ok(()))) => Ok(CommandResponse {
                accepted: true,
                message: Some("secret provisioned".to_string()),
            }),
            Some(Ok(Err(message))) => Err(RuntimeError::secret(
                ServiceErrorCode::SecretWriteFailed,
                message,
                true,
            )),
            Some(Err(_)) | None => Err(RuntimeError::stopped()),
        }
    }

    /// Remove the dedicated secret file and stop this runtime.
    pub async fn reset_secret(&self) -> Result<CommandResponse, RuntimeError> {
        self.ensure_running()?;

        let Some(secret_path) = self.inner.secret_source.secret_path() else {
            return Err(self.inner.secret_source.reset_error());
        };

        let message = reset_secret_file(secret_path).await?;
        self.inner.request_shutdown();
        Ok(CommandResponse {
            accepted: true,
            message: Some(message),
        })
    }

    pub(crate) async fn claim_url(&self) -> Option<String> {
        self.inner.claim_code.read().await.as_deref().map(claim_url)
    }

    pub(crate) fn ensure_running(&self) -> Result<(), RuntimeError> {
        if self.inner.cancel_token.is_cancelled() {
            Err(RuntimeError::stopped())
        } else {
            Ok(())
        }
    }

    fn ensure_running_or_waiting(&self) -> Result<(), RuntimeError> {
        self.ensure_running()
    }
}

pub(crate) fn make_inner(
    options: &crate::options::RuntimeOptions,
    source: SecretSource,
    state_cache: Arc<StateCache>,
    event_tx: broadcast::Sender<ServiceUpdate>,
    cancel_token: CancellationToken,
    status_context: StatusContext,
    secret_provision_tx: Option<mpsc::Sender<SecretProvisionRequest>>,
) -> Result<Arc<RuntimeInner>, RuntimeError> {
    let agent_version = options
        .version
        .agent_version()
        .map_err(|error| RuntimeError::setup(error, false))?;

    Ok(Arc::new(RuntimeInner {
        state_cache,
        event_tx,
        cancel_token,
        status_context,
        secret_source: source,
        secret_provision_tx,
        api: RwLock::new(None),
        guest_login_cache: Arc::new(RwLock::new(None)),
        claim_code: Arc::new(RwLock::new(None)),
        claim_tasks: AsyncMutex::new(Vec::new()),
        agent_cancel: Mutex::new(None),
        api_base: options.api_base.clone(),
        version: options.version.clone(),
        agent_version,
        platform: platform_for_options(options),
    }))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use playit_ipc::model::{AccountStatus, AgentLifecycle, AgentState};
    use tokio::sync::broadcast;
    use tokio_util::sync::CancellationToken;

    use super::{PlayitHandle, SecretSource, StatusContext, make_inner};
    use crate::options::RuntimeOptions;
    use crate::state::StateCache;

    fn test_handle() -> PlayitHandle {
        let options = RuntimeOptions {
            secret_path: PathBuf::from("test-secret.toml"),
            ..RuntimeOptions::default()
        };
        let (event_tx, _) = broadcast::channel(8);
        let inner = make_inner(
            &options,
            SecretSource::from_options(&options),
            Arc::new(StateCache::default()),
            event_tx,
            CancellationToken::new(),
            StatusContext::new(
                Some("test-secret.toml".to_string()),
                options.version.version_string(),
                playit_agent_core::utils::now_milli(),
            ),
            None,
        )
        .unwrap();
        PlayitHandle::new(inner)
    }

    #[tokio::test]
    async fn account_normalizes_running_state_without_exposing_empty_agent_ids() {
        let handle = test_handle();
        handle
            .inner
            .state_cache
            .set_lifecycle(AgentLifecycle::Running(AgentState {
                account_status: AccountStatus::Verified,
                agent_id: "agent-id".to_string(),
                login_link: Some("https://playit.gg/login/example".to_string()),
                ..AgentState::default()
            }))
            .await;
        *handle.inner.claim_code.write().await = Some("active-code".to_string());

        let account = handle.account().await.unwrap();
        assert!(matches!(account.status, AccountStatus::Verified));
        assert_eq!(account.agent_id.as_deref(), Some("agent-id"));
        assert_eq!(
            account.login_link.as_deref(),
            Some("https://playit.gg/login/example")
        );
        assert_eq!(
            account.claim_url.as_deref(),
            Some("https://playit.gg/claim/active-code")
        );

        handle
            .inner
            .state_cache
            .set_lifecycle(AgentLifecycle::Running(AgentState::default()))
            .await;
        let account = handle.account().await.unwrap();
        assert!(account.agent_id.is_none());
    }

    #[tokio::test]
    async fn operations_after_shutdown_report_stopped() {
        let handle = test_handle();
        handle.inner.request_shutdown();

        assert!(matches!(
            handle.account().await,
            Err(crate::error::RuntimeError::Stopped)
        ));
        assert!(matches!(
            handle.reset_secret().await,
            Err(crate::error::RuntimeError::Stopped)
        ));
    }
}
