use std::sync::Arc;
use std::time::Duration;

use playit_agent_core::network::origin_lookup::{OriginLookup, OriginResource, OriginTarget};
use playit_agent_core::stats::AgentStats;
use playit_agent_core::utils::now_milli;
use playit_api_client::PlayitApi;
use playit_api_client::api::{AccountStatus, PortType};
use playit_ipc::ipc::protocol_info;
use playit_ipc::model::{
    AccountStatus as ServiceAccountStatus, AgentLifecycle, AgentState, ConnectionStats,
    NoticeState, PendingTunnelState, ServiceError, ServicePhase, ServiceStatus, ServiceUpdate,
    SubscriptionSnapshot, TunnelProtocol, TunnelState,
};
use tokio::sync::{RwLock, broadcast};
use tokio_util::sync::CancellationToken;

/// Authoritative state shared by direct handles and the daemon's IPC adapter.
#[derive(Default)]
pub(crate) struct StateCache {
    lifecycle: RwLock<AgentLifecycle>,
    status: RwLock<ServiceStatus>,
    stats: RwLock<ConnectionStats>,
}

impl StateCache {
    pub(crate) async fn set_lifecycle(&self, lifecycle: AgentLifecycle) {
        *self.lifecycle.write().await = lifecycle;
    }

    pub(crate) async fn lifecycle(&self) -> AgentLifecycle {
        self.lifecycle.read().await.clone()
    }

    pub(crate) async fn set_status(&self, status: ServiceStatus) {
        *self.status.write().await = status;
    }

    pub(crate) async fn status(&self) -> ServiceStatus {
        self.status.read().await.clone()
    }

    pub(crate) async fn set_stats(&self, stats: ConnectionStats) {
        *self.stats.write().await = stats;
    }

    pub(crate) async fn stats(&self) -> ConnectionStats {
        self.stats.read().await.clone()
    }

    pub(crate) async fn subscription_snapshot(&self) -> SubscriptionSnapshot {
        SubscriptionSnapshot {
            status: self.status().await,
            lifecycle: self.lifecycle().await,
            stats: self.stats().await,
        }
    }
}

pub(crate) struct StatusContext {
    pub(crate) secret_path: Option<String>,
    pub(crate) version: String,
    pub(crate) start_time: u64,
}

impl StatusContext {
    pub(crate) fn new(secret_path: Option<String>, version: String, start_time: u64) -> Self {
        Self {
            secret_path,
            version,
            start_time,
        }
    }

    pub(crate) fn status(
        &self,
        phase: ServicePhase,
        has_secret: bool,
        last_error: Option<ServiceError>,
    ) -> ServiceStatus {
        ServiceStatus {
            phase,
            pid: std::process::id(),
            uptime_secs: now_milli().saturating_sub(self.start_time) / 1000,
            version: self.version.clone(),
            // This is deliberately empty in the reusable runtime. An IPC
            // adapter may fill its own transport endpoint into this field.
            socket_path: String::new(),
            secret_path: self.secret_path.clone(),
            has_secret,
            protocol: protocol_info(),
            last_error,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RunningSummary {
    tunnel_count: usize,
    pending_tunnel_count: usize,
    disabled_tunnel_count: usize,
    account_status: &'static str,
}

impl RunningSummary {
    fn from_state(state: &AgentState) -> Self {
        Self {
            tunnel_count: state.tunnels.len(),
            pending_tunnel_count: state.pending_tunnels.len(),
            disabled_tunnel_count: state
                .tunnels
                .iter()
                .filter(|tunnel| tunnel.is_disabled)
                .count(),
            account_status: service_account_status_label(&state.account_status),
        }
    }
}

pub(crate) async fn broadcast_stats(
    stats: AgentStats,
    event_tx: broadcast::Sender<ServiceUpdate>,
    state_cache: Arc<StateCache>,
    cancel_token: CancellationToken,
) {
    let mut interval = tokio::time::interval(Duration::from_millis(100));

    loop {
        tokio::select! {
            _ = interval.tick() => {
                let snapshot = stats.snapshot();
                let stats = ConnectionStats {
                    bytes_in: snapshot.bytes_in,
                    bytes_out: snapshot.bytes_out,
                    active_tcp: snapshot.active_tcp,
                    active_udp: snapshot.active_udp,
                };
                state_cache.set_stats(stats.clone()).await;
                let _ = event_tx.send(ServiceUpdate::Stats(stats));
            }
            _ = cancel_token.cancelled() => break,
        }
    }
}

pub(crate) struct AgentStateBroadcastContext {
    pub(crate) event_tx: broadcast::Sender<ServiceUpdate>,
    pub(crate) state_cache: Arc<StateCache>,
    pub(crate) guest_login_cache: Arc<RwLock<Option<(String, u64)>>>,
    pub(crate) cancel_token: CancellationToken,
    pub(crate) start_time: u64,
    pub(crate) version_string: String,
}

pub(crate) async fn broadcast_agent_state(
    api: PlayitApi,
    lookup: Arc<OriginLookup>,
    context: AgentStateBroadcastContext,
) {
    let AgentStateBroadcastContext {
        event_tx,
        state_cache,
        guest_login_cache,
        cancel_token,
        start_time,
        version_string,
    } = context;
    let mut interval = tokio::time::interval(Duration::from_secs(3));
    let mut last_running_summary: Option<RunningSummary> = None;
    let mut api_available = false;

    loop {
        tokio::select! {
            _ = interval.tick() => {
                match api.v1_agents_rundata().await {
                    Ok(mut api_data) => {
                        if !api_available && last_running_summary.is_some() {
                            tracing::info!("playit account state polling recovered");
                        }
                        api_available = true;
                        lookup.update_from_run_data(&api_data).await;

                        let login_link = match api_data.permissions.account_status {
                            AccountStatus::Guest => {
                                get_cached_guest_login_link(&api, &guest_login_cache).await
                            }
                            _ => None,
                        };

                        api_data.notices.sort_by_key(|n| n.priority);

                        let state = AgentState {
                            version: version_string.clone(),
                            tunnels: api_data
                                .tunnels
                                .iter()
                                .filter_map(|tunnel| {
                                    let origin = OriginResource::from_agent_tunnel(tunnel)?;
                                    let destination = match &origin.target {
                                        OriginTarget::Https {
                                            ip,
                                            http_port,
                                            https_port,
                                        } => format!("{ip} (http: {http_port}, https: {https_port})"),
                                        OriginTarget::Port { ip, port } => format!("{ip}:{port}"),
                                    };

                                    Some(TunnelState {
                                        id: tunnel.id.to_string(),
                                        name: (!tunnel.name.trim().is_empty())
                                            .then_some(tunnel.name.clone()),
                                        display_address: tunnel.display_address.clone(),
                                        destination,
                                        protocol: match tunnel.port_type {
                                            PortType::Tcp => TunnelProtocol::Tcp,
                                            PortType::Udp => TunnelProtocol::Udp,
                                            PortType::Both => TunnelProtocol::Both,
                                        },
                                        port_count: tunnel.port_count,
                                        local_address: Some(match &origin.target {
                                            OriginTarget::Https { ip, .. }
                                            | OriginTarget::Port { ip, .. } => ip.to_string(),
                                        }),
                                        local_port: match &origin.target {
                                            OriginTarget::Https { .. } => None,
                                            OriginTarget::Port { port, .. } => Some(*port),
                                        },
                                        is_disabled: tunnel.disabled_reason.is_some(),
                                        disabled_reason: tunnel
                                            .disabled_reason
                                            .as_ref()
                                            .map(|s| s.to_string()),
                                    })
                                })
                                .collect(),
                            pending_tunnels: api_data
                                .pending
                                .iter()
                                .map(|p| PendingTunnelState {
                                    id: p.id.to_string(),
                                    status_msg: p.status_msg.clone(),
                                })
                                .collect(),
                            notices: api_data
                                .notices
                                .iter()
                                .map(|n| NoticeState {
                                    priority: format!("{:?}", n.priority),
                                    message: n.message.to_string(),
                                    resolve_link: n.resolve_link.clone(),
                                })
                                .collect(),
                            account_status: match api_data.permissions.account_status {
                                AccountStatus::Guest => ServiceAccountStatus::Guest,
                                AccountStatus::EmailNotVerified => {
                                    ServiceAccountStatus::EmailNotVerified
                                }
                                AccountStatus::Verified => ServiceAccountStatus::Verified,
                            },
                            agent_id: api_data.agent_id.to_string(),
                            login_link,
                            start_time,
                        };

                        let summary = RunningSummary::from_state(&state);
                        if last_running_summary.as_ref() != Some(&summary) {
                            if last_running_summary.is_none() {
                                tracing::info!(
                                    agent_id = %state.agent_id,
                                    tunnel_count = summary.tunnel_count,
                                    pending_tunnel_count = summary.pending_tunnel_count,
                                    disabled_tunnel_count = summary.disabled_tunnel_count,
                                    account_status = summary.account_status,
                                    "playit account state loaded; tunnels available"
                                );
                            } else {
                                tracing::info!(
                                    agent_id = %state.agent_id,
                                    tunnel_count = summary.tunnel_count,
                                    pending_tunnel_count = summary.pending_tunnel_count,
                                    disabled_tunnel_count = summary.disabled_tunnel_count,
                                    account_status = summary.account_status,
                                    "playit account tunnel state updated"
                                );
                            }
                            last_running_summary = Some(summary);
                        }

                        let lifecycle = AgentLifecycle::Running(state);
                        state_cache.set_lifecycle(lifecycle.clone()).await;
                        let _ = event_tx.send(ServiceUpdate::Lifecycle(lifecycle));
                    }
                    Err(error) => {
                        if api_available {
                            tracing::warn!(?error, "playit account state polling is unavailable");
                        } else {
                            tracing::debug!(?error, "playit account state polling is unavailable");
                        }
                        api_available = false;
                    }
                }
            }
            _ = cancel_token.cancelled() => break,
        }
    }
}

async fn get_cached_guest_login_link(
    api: &PlayitApi,
    guest_login_cache: &Arc<RwLock<Option<(String, u64)>>>,
) -> Option<String> {
    let now = now_milli();
    {
        let cache = guest_login_cache.read().await;
        if let Some((link, ts)) = &*cache
            && now.saturating_sub(*ts) < 15_000
        {
            return Some(link.clone());
        }
    }

    match api.login_guest().await {
        Ok(session) => {
            let link = format!(
                "https://playit.gg/login/guest-account/{}",
                session.session_key
            );
            *guest_login_cache.write().await = Some((link.clone(), now));
            Some(link)
        }
        Err(_) => None,
    }
}

fn service_account_status_label(status: &ServiceAccountStatus) -> &'static str {
    match status {
        ServiceAccountStatus::Unknown => "unknown",
        ServiceAccountStatus::Guest => "guest",
        ServiceAccountStatus::EmailNotVerified => "email_not_verified",
        ServiceAccountStatus::Verified => "verified",
    }
}

#[cfg(test)]
mod tests {
    use super::{RunningSummary, StateCache};
    use playit_ipc::model::{AccountStatus, AgentState, TunnelState};

    #[test]
    fn running_summary_counts_tunnel_state() {
        let state = AgentState {
            account_status: AccountStatus::Verified,
            tunnels: vec![
                TunnelState {
                    is_disabled: false,
                    ..TunnelState::default()
                },
                TunnelState {
                    is_disabled: true,
                    ..TunnelState::default()
                },
            ],
            pending_tunnels: vec![Default::default()],
            ..AgentState::default()
        };

        let summary = RunningSummary::from_state(&state);
        assert_eq!(summary.tunnel_count, 2);
        assert_eq!(summary.pending_tunnel_count, 1);
        assert_eq!(summary.disabled_tunnel_count, 1);
        assert_eq!(summary.account_status, "verified");
    }

    #[tokio::test]
    async fn state_cache_exposes_one_subscription_snapshot() {
        let cache = StateCache::default();
        let snapshot = cache.subscription_snapshot().await;
        assert_eq!(snapshot.stats.bytes_in, 0);
        assert!(matches!(snapshot.lifecycle, AgentLifecycle::Starting));
    }

    use playit_ipc::model::AgentLifecycle;
}
