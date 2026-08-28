use std::sync::Arc;
use std::time::Duration;

use playit_agent_core::agent_control::errors::SetupError;
use playit_agent_core::agent_control::maintained_control::ControlConnectionState;
use playit_agent_core::network::origin_lookup::OriginLookup;
use playit_agent_core::network::tcp::tcp_settings::TcpSettings;
use playit_agent_core::network::udp::udp_settings::UdpSettings;
use playit_agent_core::playit_agent::{PlayitAgent, PlayitAgentSettings};
use playit_agent_core::stats::AgentStats;
use playit_agent_core::utils::now_milli;
use playit_api_client::PlayitApi;
use playit_api_client::api::{ApiResponseError, AuthError, Platform, ProtoRegisterError};
use playit_ipc::model::{AgentLifecycle, ServiceErrorCode, ServicePhase, ServiceUpdate};
use tokio::sync::{broadcast, mpsc, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::error::RuntimeError;
use crate::handle::{PlayitHandle, RuntimeInner, make_inner};
use crate::options::RuntimeOptions;
use crate::secret::{
    LoadedSecret, SecretProvisionRequest, SecretSource, wait_for_provisioned_secret,
};
use crate::state::{
    AgentStateBroadcastContext, StateCache, StatusContext, broadcast_agent_state, broadcast_stats,
};

const AGENT_LIMIT_RETRY_INTERVAL: Duration = Duration::from_secs(30);
const TRANSIENT_RETRY_DELAYS: [Duration; 6] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
    Duration::from_secs(15),
    Duration::from_secs(30),
];

/// Owns the Playit background tasks and their cancellation lifecycle.
///
/// The runtime must be started and used from an existing Tokio runtime. It
/// does not create a Tokio runtime of its own, install signal handlers, or
/// initialize global tracing.
pub struct PlayitRuntime {
    inner: Arc<RuntimeInner>,
    supervisor: Option<JoinHandle<Result<(), RuntimeError>>>,
}

impl PlayitRuntime {
    /// Start a direct Playit runtime and return its owner plus cloneable handle.
    pub async fn start(options: RuntimeOptions) -> Result<(Self, PlayitHandle), RuntimeError> {
        let (event_tx, _) = broadcast::channel::<ServiceUpdate>(256);
        Self::start_with_event_sender(options, event_tx).await
    }

    /// Start a runtime using a host-provided event sender.
    ///
    /// A host can use this when it must install logging or event forwarding
    /// before the runtime supervisor is spawned. The sender is also returned
    /// by [`PlayitHandle::event_sender`](crate::PlayitHandle::event_sender).
    pub async fn start_with_event_sender(
        options: RuntimeOptions,
        event_tx: broadcast::Sender<ServiceUpdate>,
    ) -> Result<(Self, PlayitHandle), RuntimeError> {
        validate_options(&options)?;

        let source = SecretSource::from_options(&options);
        if let Some(secret) = &options.secret {
            crate::secret::validate_secret(secret.trim()).map_err(|error| {
                RuntimeError::secret(ServiceErrorCode::InvalidSecret, error, false)
            })?;
        }

        let (secret_provision_tx, secret_rx) = if source.allows_provisioning() {
            let (tx, rx) = mpsc::channel::<SecretProvisionRequest>(8);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };

        let state_cache = Arc::new(StateCache::default());
        let cancel_token = CancellationToken::new();
        let start_time = now_milli();
        let version_string = options.version.version_string();
        let status_context = StatusContext::new(
            source.secret_path().map(|path| path.display().to_string()),
            version_string,
            start_time,
        );
        let inner = make_inner(
            &options,
            source,
            state_cache,
            event_tx,
            cancel_token,
            status_context,
            secret_provision_tx,
        )?;

        inner
            .publish_state(
                inner
                    .status_context
                    .status(ServicePhase::Starting, false, None),
                AgentLifecycle::Starting,
            )
            .await;

        let supervisor_inner = inner.clone();
        let supervisor = tokio::spawn(async move { supervise(supervisor_inner, secret_rx).await });

        let runtime = Self {
            inner: inner.clone(),
            supervisor: Some(supervisor),
        };
        Ok((runtime, PlayitHandle::new(inner)))
    }

    /// Wait for the runtime supervisor to finish.
    ///
    /// This is useful to a process host such as playitd, which must also stop
    /// when the agent exits unexpectedly. Most embedding applications should
    /// call shutdown when their own host shutdown begins.
    pub async fn wait(&mut self) -> Result<(), RuntimeError> {
        if self.supervisor.is_none() {
            return Ok(());
        }

        let result = self
            .supervisor
            .as_mut()
            .expect("supervisor was checked above")
            .await
            .map_err(|error| RuntimeError::setup(format!("runtime task failed: {error}"), false));
        self.supervisor.take();
        result?
    }

    /// Request cancellation and wait for all runtime tasks to terminate.
    pub async fn shutdown(mut self) -> Result<(), RuntimeError> {
        self.inner.request_shutdown();
        let result = self.wait().await;
        self.inner.join_claim_tasks().await;
        result
    }
}

impl Drop for PlayitRuntime {
    fn drop(&mut self) {
        self.inner.request_shutdown();
    }
}

async fn supervise(
    inner: Arc<RuntimeInner>,
    secret_rx: Option<mpsc::Receiver<SecretProvisionRequest>>,
) -> Result<(), RuntimeError> {
    let result = run_supervisor(&inner, secret_rx).await;
    inner.request_shutdown();
    inner.join_claim_tasks().await;
    result
}

async fn run_supervisor(
    inner: &Arc<RuntimeInner>,
    mut secret_rx: Option<mpsc::Receiver<SecretProvisionRequest>>,
) -> Result<(), RuntimeError> {
    let secret = match inner.secret_source.load().await {
        LoadedSecret::Ready(secret) => {
            publish_starting(inner, true).await;
            secret
        }
        LoadedSecret::Missing => {
            let Some(secret) = wait_for_secret(inner, &mut secret_rx, None).await? else {
                return Ok(());
            };
            secret
        }
        LoadedSecret::Invalid(message) => {
            let error = RuntimeError::secret(
                ServiceErrorCode::InvalidSecret,
                message,
                inner.secret_source.allows_provisioning(),
            );
            let service_error = error.as_service_error();
            inner
                .publish_state(
                    inner.inner_status(
                        ServicePhase::HasInvalidSecret,
                        false,
                        Some(service_error.clone()),
                    ),
                    AgentLifecycle::HasInvalidSecret(service_error),
                )
                .await;

            if !inner.secret_source.allows_provisioning() {
                return Err(error);
            }

            let Some(secret) =
                wait_for_secret(inner, &mut secret_rx, Some(error.as_service_error())).await?
            else {
                return Ok(());
            };
            secret
        }
    };

    build_agent_with_reprovisioning(inner, secret, &mut secret_rx).await
}

async fn wait_for_secret(
    inner: &Arc<RuntimeInner>,
    secret_rx: &mut Option<mpsc::Receiver<SecretProvisionRequest>>,
    last_error: Option<playit_ipc::model::ServiceError>,
) -> Result<Option<String>, RuntimeError> {
    let Some(secret_path) = inner.secret_source.secret_path() else {
        return Err(RuntimeError::secret(
            ServiceErrorCode::ProvisioningUnavailable,
            "No file-backed secret source is available for provisioning.",
            false,
        ));
    };
    let Some(secret_rx) = secret_rx.as_mut() else {
        return Err(inner.secret_source.provisioning_error());
    };

    inner
        .publish_state(
            inner.inner_status(ServicePhase::WaitingForSecret, false, last_error),
            AgentLifecycle::WaitingForSecret,
        )
        .await;

    match wait_for_provisioned_secret(secret_path, secret_rx, &inner.cancel_token).await? {
        Some(secret) => {
            publish_starting(inner, true).await;
            Ok(Some(secret))
        }
        None => {
            publish_stopping(inner, false).await;
            Ok(None)
        }
    }
}

async fn build_agent_with_reprovisioning(
    inner: &Arc<RuntimeInner>,
    mut secret_code: String,
    secret_rx: &mut Option<mpsc::Receiver<SecretProvisionRequest>>,
) -> Result<(), RuntimeError> {
    let lookup = Arc::new(OriginLookup::default());
    let mut retry_attempt = 0;

    loop {
        if inner.cancel_token.is_cancelled() {
            publish_stopping(inner, true).await;
            return Ok(());
        }

        let api = PlayitApi::create(inner.api_base.clone(), Some(secret_code.clone()));
        inner.set_api(Some(api.clone())).await;

        if let Ok(data) = api.v1_agents_rundata().await {
            lookup.update_from_run_data(&data).await;
        }

        let settings = PlayitAgentSettings {
            udp_settings: UdpSettings::default(),
            tcp_settings: TcpSettings::default(),
            api_url: inner.api_base.clone(),
            secret_key: secret_code.clone(),
        };

        publish_starting(inner, true).await;
        match PlayitAgent::new_with_identity(
            settings,
            lookup.clone(),
            inner.agent_version.clone(),
            platform_for_options_from_inner(inner),
        )
        .await
        {
            Ok(agent) => {
                let stats = agent.stats();
                let control_state = agent.subscribe_control_state();
                inner
                    .publish_state(
                        inner.inner_status(ServicePhase::Running, true, None),
                        AgentLifecycle::Starting,
                    )
                    .await;
                match run_agent(
                    inner,
                    AgentRuntime {
                        api,
                        runner: agent,
                        stats,
                        control_state,
                        lookup: lookup.clone(),
                    },
                )
                .await
                {
                    Ok(()) => return Ok(()),
                    Err(error) if !inner.cancel_token.is_cancelled() => {
                        let message = error.to_string();
                        tracing::warn!(?error, "playit agent stopped; retrying");
                        publish_reconnecting(
                            inner,
                            true,
                            Some(RuntimeError::setup(message, true).as_service_error()),
                        )
                        .await;
                        if !wait_for_retry(inner, retry_attempt).await {
                            publish_stopping(inner, true).await;
                            return Ok(());
                        }
                        retry_attempt = retry_attempt.saturating_add(1);
                    }
                    Err(_) => {
                        publish_stopping(inner, true).await;
                        return Ok(());
                    }
                }
            }
            Err(error)
                if inner.secret_source.allows_provisioning()
                    && is_invalid_agent_secret_error(&error) =>
            {
                tracing::warn!(?error, "configured agent secret is no longer valid");
                let service_error = RuntimeError::secret(
                    ServiceErrorCode::InvalidSecret,
                    "The configured playit secret is no longer valid. Run playit setup to provision a new secret.",
                    true,
                )
                .as_service_error();
                inner.set_api(None).await;
                let Some(secret) = wait_for_secret(inner, secret_rx, Some(service_error)).await?
                else {
                    return Ok(());
                };
                secret_code = secret;
            }
            Err(error) if is_agent_disabled_over_limit_error(&error) => {
                tracing::warn!(
                    ?error,
                    "agent disabled because the account is over the agent limit"
                );
                let service_error = RuntimeError::setup_with_code(
                    ServiceErrorCode::AgentDisabledOverLimit,
                    agent_disabled_over_limit_message(),
                    true,
                )
                .as_service_error();
                inner
                    .publish_state(
                        inner.inner_status(
                            ServicePhase::DisabledOverLimit,
                            true,
                            Some(service_error.clone()),
                        ),
                        AgentLifecycle::DisabledOverLimit(service_error),
                    )
                    .await;

                tokio::select! {
                    _ = inner.cancel_token.cancelled() => {
                        publish_stopping(inner, true).await;
                        return Ok(());
                    }
                    _ = tokio::time::sleep(AGENT_LIMIT_RETRY_INTERVAL) => {}
                }
            }
            Err(error) if is_transient_setup_error(&error) => {
                let message = setup_error_user_message(&error);
                let delay = retry_delay(retry_attempt);
                tracing::warn!(
                    ?error,
                    delay_secs = delay.as_secs(),
                    "playit agent is unavailable; retrying automatically"
                );
                publish_reconnecting(
                    inner,
                    true,
                    Some(RuntimeError::setup(message, true).as_service_error()),
                )
                .await;
                if !wait_for_retry(inner, retry_attempt).await {
                    publish_stopping(inner, true).await;
                    return Ok(());
                }
                retry_attempt = retry_attempt.saturating_add(1);
            }
            Err(error) => {
                let message = setup_error_user_message(&error);
                tracing::error!(?error, %message, "failed to start playit agent");
                let service_error = RuntimeError::setup(message.clone(), true).as_service_error();
                inner
                    .publish_state(
                        inner.inner_status(ServicePhase::Error, true, Some(service_error.clone())),
                        AgentLifecycle::Error(service_error),
                    )
                    .await;
                return Err(RuntimeError::setup(message, true));
            }
        }
    }
}

fn retry_delay(attempt: u32) -> Duration {
    TRANSIENT_RETRY_DELAYS[(attempt as usize).min(TRANSIENT_RETRY_DELAYS.len() - 1)]
}

async fn wait_for_retry(inner: &Arc<RuntimeInner>, attempt: u32) -> bool {
    tokio::select! {
        _ = inner.cancel_token.cancelled() => false,
        _ = tokio::time::sleep(retry_delay(attempt)) => true,
    }
}

fn is_transient_setup_error(error: &SetupError) -> bool {
    matches!(
        error,
        SetupError::FailedToConnect
            | SetupError::RequestError(_)
            | SetupError::Timeout(_)
            | SetupError::IoError(_)
            | SetupError::AttemptingToAuthWithOldFlow
            | SetupError::NoResponseFromAuthenticate
            | SetupError::RegisterUnauthorized
            | SetupError::ApiError(ApiResponseError::Internal(_))
            | SetupError::ApiError(ApiResponseError::Auth(AuthError::SessionExpired))
    )
}

struct AgentRuntime {
    api: PlayitApi,
    runner: PlayitAgent,
    stats: AgentStats,
    control_state: watch::Receiver<ControlConnectionState>,
    lookup: Arc<OriginLookup>,
}

enum AgentStop {
    Requested,
    Unexpected(Result<(), tokio::task::JoinError>),
}

fn classify_agent_completion(
    runtime_cancelled: bool,
    result: Result<(), tokio::task::JoinError>,
) -> AgentStop {
    if runtime_cancelled {
        AgentStop::Requested
    } else {
        AgentStop::Unexpected(result)
    }
}

async fn run_agent(inner: &Arc<RuntimeInner>, agent: AgentRuntime) -> Result<(), RuntimeError> {
    let AgentRuntime {
        api,
        runner,
        stats,
        control_state,
        lookup,
    } = agent;
    let agent_cancel = runner.cancellation_token();
    inner.set_agent_cancel(Some(agent_cancel.clone()));

    let mut agent_handle = tokio::spawn(runner.run());
    let stats_handle = {
        let event_tx = inner.event_tx.clone();
        let cache = inner.state_cache.clone();
        let token = agent_cancel.clone();
        tokio::spawn(broadcast_stats(stats, event_tx, cache, token))
    };
    let state_handle = {
        let event_tx = inner.event_tx.clone();
        let cache = inner.state_cache.clone();
        let token = agent_cancel.clone();
        let guest_login_cache = inner.guest_login_cache.clone();
        tokio::spawn(broadcast_agent_state(
            api,
            lookup,
            AgentStateBroadcastContext {
                event_tx,
                state_cache: cache,
                guest_login_cache,
                cancel_token: token,
                start_time: inner.status_context.start_time,
                version_string: inner.status_context.version.clone(),
            },
        ))
    };
    let control_state_handle = tokio::spawn(broadcast_control_state(
        inner.clone(),
        control_state,
        agent_cancel.clone(),
    ));

    let stop = tokio::select! {
        _ = inner.cancel_token.cancelled() => AgentStop::Requested,
        result = &mut agent_handle => {
            classify_agent_completion(inner.cancel_token.is_cancelled(), result)
        }
    };
    let unexpected = matches!(stop, AgentStop::Unexpected(_));

    agent_cancel.cancel();
    if matches!(stop, AgentStop::Requested) {
        publish_stopping(inner, true).await;
    }

    let mut stats_handle = stats_handle;
    let mut state_handle = state_handle;
    let mut control_state_handle = control_state_handle;
    let cleanup = tokio::time::timeout(Duration::from_secs(5), async {
        if !unexpected {
            let _ = (&mut agent_handle).await;
        }
        let _ = (&mut stats_handle).await;
        let _ = (&mut state_handle).await;
        let _ = (&mut control_state_handle).await;
    })
    .await;
    if cleanup.is_err() {
        agent_handle.abort();
        stats_handle.abort();
        state_handle.abort();
        control_state_handle.abort();
        let _ = agent_handle.await;
        let _ = stats_handle.await;
        let _ = state_handle.await;
        let _ = control_state_handle.await;
    }

    inner.set_agent_cancel(None);

    match stop {
        AgentStop::Requested => Ok(()),
        AgentStop::Unexpected(Ok(())) => Err(RuntimeError::setup(
            "playit agent task stopped unexpectedly",
            true,
        )),
        AgentStop::Unexpected(Err(error)) => Err(RuntimeError::setup(
            format!("playit agent task failed: {error}"),
            true,
        )),
    }
}

async fn broadcast_control_state(
    inner: Arc<RuntimeInner>,
    mut control_state: watch::Receiver<ControlConnectionState>,
    cancel_token: CancellationToken,
) {
    let mut last_state = None;

    loop {
        let state = *control_state.borrow();
        if last_state != Some(state) {
            let phase = match state {
                ControlConnectionState::Connected => ServicePhase::Running,
                ControlConnectionState::Reconnecting => ServicePhase::Reconnecting,
            };
            let has_secret = inner.state_cache.status().await.has_secret;
            inner
                .publish_status(inner.inner_status(phase, has_secret, None))
                .await;
            last_state = Some(state);
        }

        tokio::select! {
            _ = cancel_token.cancelled() => break,
            changed = control_state.changed() => {
                if changed.is_err() {
                    break;
                }
            }
        }
    }
}

fn platform_for_options_from_inner(inner: &RuntimeInner) -> Platform {
    inner.platform
}

fn validate_options(options: &RuntimeOptions) -> Result<(), RuntimeError> {
    if options.secret_path.as_os_str().is_empty() {
        return Err(RuntimeError::setup(
            "RuntimeOptions.secret_path must not be empty",
            false,
        ));
    }
    if options.api_base.trim().is_empty() {
        return Err(RuntimeError::setup(
            "RuntimeOptions.api_base must not be empty",
            false,
        ));
    }
    Ok(())
}

async fn publish_starting(inner: &Arc<RuntimeInner>, has_secret: bool) {
    inner
        .publish_state(
            inner.inner_status(ServicePhase::Starting, has_secret, None),
            AgentLifecycle::Starting,
        )
        .await;
}

async fn publish_reconnecting(
    inner: &Arc<RuntimeInner>,
    has_secret: bool,
    last_error: Option<playit_ipc::model::ServiceError>,
) {
    inner
        .publish_state(
            inner.inner_status(ServicePhase::Reconnecting, has_secret, last_error),
            AgentLifecycle::Starting,
        )
        .await;
}

async fn publish_stopping(inner: &Arc<RuntimeInner>, has_secret: bool) {
    inner
        .publish_state(
            inner.inner_status(ServicePhase::Stopping, has_secret, None),
            AgentLifecycle::Stopping,
        )
        .await;
}

trait RuntimeStatus {
    fn inner_status(
        &self,
        phase: ServicePhase,
        has_secret: bool,
        last_error: Option<playit_ipc::model::ServiceError>,
    ) -> playit_ipc::model::ServiceStatus;
}

impl RuntimeStatus for RuntimeInner {
    fn inner_status(
        &self,
        phase: ServicePhase,
        has_secret: bool,
        last_error: Option<playit_ipc::model::ServiceError>,
    ) -> playit_ipc::model::ServiceStatus {
        self.status_context.status(phase, has_secret, last_error)
    }
}

/// Turn low-level agent setup failures into messages suitable for a host UI.
pub fn setup_error_user_message(error: &SetupError) -> String {
    match error {
        SetupError::FailedToConnect => {
            "Could not connect to Playit tunnel servers. The service will retry automatically; check your internet connection, firewall, VPN, or DNS settings.".to_string()
        }
        SetupError::RequestError(_) => {
            "Could not reach the Playit API. The service will retry automatically; check your internet connection or try again later.".to_string()
        }
        SetupError::ApiError(ApiResponseError::Auth(
            AuthError::InvalidAgentKey | AuthError::NoLongerValid,
        )) => {
            "The configured playit secret is no longer valid. Run playit setup to provision a new secret.".to_string()
        }
        SetupError::ApiError(error) => {
            format!("The playit API rejected the agent startup request: {error}")
        }
        SetupError::ApiFail(payload)
            if matches!(
                serde_json::from_str::<ProtoRegisterError>(payload),
                Ok(ProtoRegisterError::AgentDisabledOverLimit)
            ) =>
        {
            agent_disabled_over_limit_message()
        }
        SetupError::ApiFail(_) => {
            "The playit API rejected the agent registration request. Check your account and tunnel configuration, then try again.".to_string()
        }
        SetupError::Timeout(_) => {
            "Timed out while connecting to Playit. The service will retry automatically; check your network or firewall.".to_string()
        }
        SetupError::IoError(error) => {
            format!("Could not open a required network socket: {error}. The service will retry automatically.")
        }
        SetupError::AttemptingToAuthWithOldFlow
        | SetupError::FailedToDecodeSignedAgentRegisterHex
        | SetupError::NoResponseFromAuthenticate
        | SetupError::RegisterInvalidSignature
        | SetupError::RegisterUnauthorized => {
            format!("Failed to start the playit agent: {error}")
        }
    }
}

fn is_invalid_agent_secret_error(error: &SetupError) -> bool {
    matches!(
        error,
        SetupError::ApiError(ApiResponseError::Auth(
            AuthError::InvalidAgentKey | AuthError::NoLongerValid
        ))
    )
}

fn parse_proto_register_error(error: &SetupError) -> Option<ProtoRegisterError> {
    match error {
        SetupError::ApiFail(payload) => serde_json::from_str(payload).ok(),
        _ => None,
    }
}

fn is_agent_disabled_over_limit_error(error: &SetupError) -> bool {
    matches!(
        parse_proto_register_error(error),
        Some(ProtoRegisterError::AgentDisabledOverLimit)
    )
}

fn agent_disabled_over_limit_message() -> String {
    "This account is over the agent limit. Delete an unused agent or upgrade the account, then the service will retry.".to_string()
}

#[cfg(test)]
mod tests {
    use playit_agent_core::agent_control::errors::SetupError;

    use super::{AgentStop, classify_agent_completion, is_transient_setup_error, retry_delay};

    #[tokio::test]
    async fn agent_self_completion_is_unexpected_without_runtime_shutdown() {
        let agent_task = tokio::spawn(async {});
        let result = agent_task.await;

        assert!(matches!(
            classify_agent_completion(false, result),
            AgentStop::Unexpected(Ok(()))
        ));
    }

    #[tokio::test]
    async fn completed_agent_is_requested_only_after_runtime_shutdown() {
        let agent_task = tokio::spawn(async {});
        let result = agent_task.await;

        assert!(matches!(
            classify_agent_completion(true, result),
            AgentStop::Requested
        ));
    }

    #[test]
    fn transient_setup_failures_are_retried() {
        assert!(is_transient_setup_error(&SetupError::FailedToConnect));
        assert!(!is_transient_setup_error(
            &SetupError::RegisterInvalidSignature
        ));
    }

    #[test]
    fn transient_retry_backoff_is_capped() {
        assert_eq!(retry_delay(0), std::time::Duration::from_secs(1));
        assert_eq!(retry_delay(4), std::time::Duration::from_secs(15));
        assert_eq!(retry_delay(100), std::time::Duration::from_secs(30));
    }
}
