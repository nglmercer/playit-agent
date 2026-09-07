use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AccountStatus {
    #[default]
    Unknown,
    Guest,
    EmailNotVerified,
    Verified,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProtocolInfo {
    pub ipc_version: u32,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ServicePhase {
    WaitingForSecret,
    HasInvalidSecret,
    DisabledOverLimit,
    #[default]
    Starting,
    Reconnecting,
    Running,
    Stopping,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ServiceErrorCode {
    #[default]
    Internal,
    UnsupportedProtocol,
    InvalidRequest,
    InvalidRequestType,
    AgentDisabledOverLimit,
    InvalidSecret,
    SecretPinned,
    ProvisioningUnavailable,
    SecretWriteFailed,
    ApiUnavailable,
    InvalidTunnelRequest,
    TunnelNotFound,
    ApiRejected,
    PermissionDenied,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServiceError {
    pub code: ServiceErrorCode,
    pub message: String,
    pub retryable: bool,
    pub details: Option<serde_json::Value>,
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TunnelState {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    pub display_address: String,
    pub destination: String,
    #[serde(default)]
    pub protocol: TunnelProtocol,
    #[serde(default)]
    pub port_count: u16,
    #[serde(default)]
    pub local_address: Option<String>,
    #[serde(default)]
    pub local_port: Option<u16>,
    pub is_disabled: bool,
    pub disabled_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TunnelProtocol {
    #[default]
    Tcp,
    Udp,
    Both,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PendingTunnelState {
    pub id: String,
    pub status_msg: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NoticeState {
    pub priority: String,
    pub message: String,
    pub resolve_link: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentState {
    pub version: String,
    pub tunnels: Vec<TunnelState>,
    pub pending_tunnels: Vec<PendingTunnelState>,
    pub notices: Vec<NoticeState>,
    pub account_status: AccountStatus,
    pub agent_id: String,
    pub login_link: Option<String>,
    pub start_time: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(tag = "state", content = "data", rename_all = "snake_case")]
pub enum AgentLifecycle {
    WaitingForSecret,
    HasInvalidSecret(ServiceError),
    DisabledOverLimit(ServiceError),
    #[default]
    Starting,
    Running(AgentState),
    Stopping,
    Error(ServiceError),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConnectionStats {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub active_tcp: u32,
    pub active_udp: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServiceStatus {
    pub phase: ServicePhase,
    pub pid: u32,
    pub uptime_secs: u64,
    pub version: String,
    pub socket_path: String,
    pub secret_path: Option<String>,
    pub has_secret: bool,
    pub protocol: ProtocolInfo,
    pub last_error: Option<ServiceError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LogEntry {
    pub level: LogLevel,
    pub target: String,
    pub message: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SubscriptionSnapshot {
    pub status: ServiceStatus,
    pub lifecycle: AgentLifecycle,
    pub stats: ConnectionStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum ServiceUpdate {
    Status(ServiceStatus),
    Lifecycle(AgentLifecycle),
    Stats(ConnectionStats),
    Log(LogEntry),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CommandResponse {
    pub accepted: bool,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecretPathResponse {
    pub secret_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AccountLoginUrlResponse {
    pub login_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SubscribeResponse {
    pub protocol: ProtocolInfo,
    pub snapshot: SubscriptionSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TunnelListResponse {
    pub tunnels: Vec<TunnelState>,
    pub pending_tunnels: Vec<PendingTunnelState>,
}

/// An account-wide view of a Playit tunnel.
///
/// Unlike [`TunnelState`], this can include tunnels assigned to another
/// agent, tunnels whose origin is not currently configured, and tunnels that
/// are still waiting for a public allocation.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AccountTunnelListResponse {
    pub tunnels: Vec<AccountTunnelState>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AccountTunnelState {
    pub id: String,
    pub name: Option<String>,
    pub display_address: String,
    pub destination: String,
    pub protocol: TunnelProtocol,
    pub tunnel_type: Option<String>,
    pub local_address: Option<String>,
    pub local_port: Option<u16>,
    pub agent_id: Option<String>,
    pub is_disabled: bool,
    pub disabled_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TunnelCreateResponse {
    pub tunnel_id: String,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AccountResponse {
    pub status: AccountStatus,
    pub agent_id: Option<String>,
    pub login_link: Option<String>,
    pub claim_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClaimResponse {
    pub claim_url: String,
}

#[cfg(test)]
mod tests {
    use super::{TunnelProtocol, TunnelState};

    #[test]
    fn tunnel_state_uses_separate_local_address_and_port_fields() {
        let tunnel = TunnelState {
            local_address: Some("127.0.0.1".to_string()),
            local_port: Some(25565),
            ..TunnelState::default()
        };

        let json = serde_json::to_value(tunnel).unwrap();
        assert_eq!(json["local_address"], "127.0.0.1");
        assert_eq!(json["local_port"], 25565);
        assert!(!json["local_address"].as_str().unwrap().contains(':'));
    }

    #[test]
    fn tunnel_protocol_has_stable_wire_names() {
        assert_eq!(
            serde_json::to_string(&TunnelProtocol::Tcp).unwrap(),
            "\"tcp\""
        );
        assert_eq!(
            serde_json::to_string(&TunnelProtocol::Udp).unwrap(),
            "\"udp\""
        );
        assert_eq!(
            serde_json::to_string(&TunnelProtocol::Both).unwrap(),
            "\"both\""
        );
    }
}
