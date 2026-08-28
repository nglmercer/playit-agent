use std::net::IpAddr;
use std::str::FromStr;

use playit_api_client::api::{
    ApiError, ApiResponseError, AssignedAgentCreate, PortType, ReqTunnelsCreate, TunnelCreateError,
    TunnelOriginCreate,
};
use playit_api_client::http_client::HttpClientError;
use playit_ipc::model::{AgentLifecycle, ServiceErrorCode, TunnelProtocol};
use uuid::Uuid;

use crate::error::RuntimeError;

pub(crate) fn tunnel_list(
    lifecycle: AgentLifecycle,
) -> Result<playit_ipc::model::TunnelListResponse, RuntimeError> {
    match lifecycle {
        AgentLifecycle::Running(state) => Ok(playit_ipc::model::TunnelListResponse {
            tunnels: state.tunnels,
            pending_tunnels: state.pending_tunnels,
        }),
        lifecycle => Err(service_not_ready_error("list tunnels", &lifecycle)),
    }
}

pub(crate) fn create_request(
    lifecycle: AgentLifecycle,
    local_port: u16,
    protocol: TunnelProtocol,
    local_address: Option<String>,
    name: Option<String>,
) -> Result<ReqTunnelsCreate, RuntimeError> {
    if local_port == 0 {
        return Err(RuntimeError::invalid(
            ServiceErrorCode::InvalidTunnelRequest,
            "local_port must be between 1 and 65535",
            false,
        ));
    }

    let local_address = local_address.unwrap_or_else(|| "127.0.0.1".to_string());
    let local_ip = IpAddr::from_str(local_address.trim()).map_err(|_| {
        RuntimeError::invalid(
            ServiceErrorCode::InvalidTunnelRequest,
            format!("local_address is not a valid IP address: {local_address}"),
            false,
        )
    })?;

    let agent_id = match lifecycle {
        AgentLifecycle::Running(state) => Uuid::parse_str(&state.agent_id).map_err(|_| {
            RuntimeError::api(
                ServiceErrorCode::ApiUnavailable,
                "The running agent has not reported a valid agent ID yet",
                true,
            )
        })?,
        lifecycle => return Err(service_not_ready_error("create a tunnel", &lifecycle)),
    };

    Ok(ReqTunnelsCreate {
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
    })
}

pub(crate) fn parse_tunnel_id(tunnel_id: &str) -> Result<Uuid, RuntimeError> {
    Uuid::parse_str(tunnel_id.trim()).map_err(|_| {
        RuntimeError::invalid(
            ServiceErrorCode::InvalidTunnelRequest,
            "tunnel_id must be a valid UUID",
            false,
        )
    })
}

pub(crate) fn map_tunnel_create_error(
    error: ApiError<TunnelCreateError, HttpClientError>,
) -> RuntimeError {
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

fn map_tunnel_create_failure(failure: TunnelCreateError) -> RuntimeError {
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

    RuntimeError::api(
        code,
        format!("The playit API rejected tunnel creation: {reason}."),
        false,
    )
}

pub(crate) fn map_tunnel_delete_error(
    error: ApiError<playit_api_client::api::DeleteError, HttpClientError>,
) -> RuntimeError {
    match error {
        ApiError::Fail(playit_api_client::api::DeleteError::TunnelNotFound) => RuntimeError::api(
            ServiceErrorCode::TunnelNotFound,
            "The requested tunnel does not exist.",
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

pub(crate) fn map_generic_api_error<F>(
    operation: &str,
    error: ApiError<F, HttpClientError>,
) -> RuntimeError {
    match error {
        ApiError::Fail(_) => RuntimeError::api(
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

fn map_api_response_error(
    operation: &str,
    error: ApiResponseError,
    validation_code: ServiceErrorCode,
) -> RuntimeError {
    match error {
        ApiResponseError::Validation(message) => RuntimeError::invalid(
            validation_code,
            format!(
                "The playit API rejected {operation}: {}.",
                bounded_message(&message)
            ),
            false,
        ),
        ApiResponseError::PathNotFound(_) => RuntimeError::api(
            ServiceErrorCode::ApiRejected,
            format!("The playit API does not support {operation}."),
            false,
        ),
        ApiResponseError::Auth(_) => RuntimeError::api(
            ServiceErrorCode::PermissionDenied,
            format!("The playit API did not authorize {operation}."),
            false,
        ),
        ApiResponseError::Internal(internal) => RuntimeError::api(
            ServiceErrorCode::ApiUnavailable,
            format!(
                "The playit API reported a temporary internal error while performing {operation} (reference {}).",
                bounded_message(&internal.trace_id)
            ),
            true,
        ),
    }
}

fn map_http_client_error(operation: &str, error: HttpClientError) -> RuntimeError {
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

    RuntimeError::api(code, message, retryable)
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

pub(crate) fn service_not_ready_error(operation: &str, lifecycle: &AgentLifecycle) -> RuntimeError {
    match lifecycle {
        AgentLifecycle::WaitingForSecret => RuntimeError::invalid(
            ServiceErrorCode::ProvisioningUnavailable,
            format!("Cannot {operation} while the service is waiting for an agent secret."),
            true,
        ),
        AgentLifecycle::HasInvalidSecret(error) => RuntimeError::invalid(
            ServiceErrorCode::InvalidSecret,
            format!("Cannot {operation}: {}", error.message),
            false,
        ),
        AgentLifecycle::DisabledOverLimit(error) => RuntimeError::invalid(
            ServiceErrorCode::AgentDisabledOverLimit,
            format!("Cannot {operation}: {}", error.message),
            false,
        ),
        AgentLifecycle::Starting | AgentLifecycle::Stopping => RuntimeError::invalid(
            ServiceErrorCode::ApiUnavailable,
            format!(
                "Cannot {operation} while the service is {}.",
                lifecycle_name(lifecycle)
            ),
            true,
        ),
        AgentLifecycle::Error(error) => RuntimeError::invalid(
            error.code.clone(),
            format!("Cannot {operation}: {}", error.message),
            error.retryable,
        ),
        AgentLifecycle::Running(_) => RuntimeError::invalid(
            ServiceErrorCode::Internal,
            format!("Cannot {operation} because the running state changed unexpectedly."),
            false,
        ),
    }
}

pub(crate) fn secret_provisioning_state_error(lifecycle: &AgentLifecycle) -> RuntimeError {
    match lifecycle {
        AgentLifecycle::WaitingForSecret => RuntimeError::invalid(
            ServiceErrorCode::ProvisioningUnavailable,
            "The Playit service is not ready to save a secret yet. Try setup again in a few seconds.",
            true,
        ),
        AgentLifecycle::HasInvalidSecret(error) => RuntimeError::invalid(
            ServiceErrorCode::ProvisioningUnavailable,
            format!(
                "The Playit service is not waiting for a new secret because its current secret is invalid: {}",
                error.message
            ),
            false,
        ),
        AgentLifecycle::DisabledOverLimit(error) => RuntimeError::invalid(
            ServiceErrorCode::ProvisioningUnavailable,
            format!(
                "Setup is unavailable because this account is over the agent limit.\n{}\nReason: {}",
                over_limit_guidance(),
                error.message
            ),
            false,
        ),
        AgentLifecycle::Starting => RuntimeError::invalid(
            ServiceErrorCode::ProvisioningUnavailable,
            "The Playit service is still starting. Try setup again in a few seconds.",
            true,
        ),
        AgentLifecycle::Running(_) => RuntimeError::invalid(
            ServiceErrorCode::ProvisioningUnavailable,
            "The Playit service already has a configured secret. Run playit reset before provisioning a new one.",
            false,
        ),
        AgentLifecycle::Stopping => RuntimeError::invalid(
            ServiceErrorCode::ProvisioningUnavailable,
            "The Playit service is stopping and cannot accept setup right now.",
            true,
        ),
        AgentLifecycle::Error(error) => RuntimeError::invalid(
            ServiceErrorCode::ProvisioningUnavailable,
            format!(
                "The Playit service reported an error and cannot accept setup right now: {}",
                error.message
            ),
            true,
        ),
    }
}

fn over_limit_guidance() -> String {
    "Delete unused agents: https://playit.gg/account/agents\nIncrease your agent limit: https://playit.gg/account/upgrade".to_string()
}

#[cfg(test)]
mod tests {
    use super::{
        create_request, map_tunnel_create_error, map_tunnel_delete_error, parse_tunnel_id,
        service_not_ready_error,
    };
    use playit_api_client::api::{ApiError, ApiResponseError, DeleteError, TunnelCreateError};
    use playit_ipc::model::{AgentLifecycle, AgentState, ServiceErrorCode, TunnelProtocol};

    #[test]
    fn typed_business_failures_are_not_reported_as_outages() {
        let error =
            map_tunnel_create_error(ApiError::Fail(TunnelCreateError::RequiresVerifiedAccount));
        assert!(matches!(
            error.as_service_error().code,
            ServiceErrorCode::PermissionDenied
        ));
        assert!(!error.as_service_error().retryable);

        let error = super::map_api_response_error(
            "tunnel creation",
            ApiResponseError::Validation("bad local address".to_string()),
            ServiceErrorCode::InvalidTunnelRequest,
        );
        assert!(matches!(
            error.as_service_error().code,
            ServiceErrorCode::InvalidTunnelRequest
        ));
        assert!(!error.as_service_error().retryable);
    }

    #[test]
    fn delete_not_found_is_a_specific_non_retryable_error() {
        let error = map_tunnel_delete_error(ApiError::Fail(DeleteError::TunnelNotFound));
        assert!(matches!(
            error.as_service_error().code,
            ServiceErrorCode::TunnelNotFound
        ));
        assert!(!error.as_service_error().retryable);
    }

    #[test]
    fn tunnel_request_validation_preserves_defaults_and_protocols() {
        let lifecycle = AgentLifecycle::Running(AgentState {
            agent_id: "00000000-0000-0000-0000-000000000001".to_string(),
            ..AgentState::default()
        });

        for (protocol, expected) in [
            (TunnelProtocol::Tcp, playit_api_client::api::PortType::Tcp),
            (TunnelProtocol::Udp, playit_api_client::api::PortType::Udp),
            (TunnelProtocol::Both, playit_api_client::api::PortType::Both),
        ] {
            let request = create_request(
                lifecycle.clone(),
                25565,
                protocol,
                Some(" 127.0.0.1 ".to_string()),
                Some("  ".to_string()),
            )
            .unwrap();
            assert_eq!(request.port_type, expected);
            assert_eq!(request.name, None);
            assert_eq!(request.port_count, 1);
            assert!(matches!(
                request.origin,
                playit_api_client::api::TunnelOriginCreate::Agent(origin)
                    if origin.local_ip == "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
                        && origin.local_port == Some(25565)
            ));
        }
    }

    #[test]
    fn tunnel_request_validation_rejects_bad_input_and_unready_state() {
        let running = AgentLifecycle::Running(AgentState {
            agent_id: "00000000-0000-0000-0000-000000000001".to_string(),
            ..AgentState::default()
        });

        assert!(matches!(
            create_request(running.clone(), 0, TunnelProtocol::Tcp, None, None)
                .unwrap_err()
                .as_service_error()
                .code,
            ServiceErrorCode::InvalidTunnelRequest
        ));
        assert!(matches!(
            create_request(
                running.clone(),
                25565,
                TunnelProtocol::Tcp,
                Some("localhost".to_string()),
                None
            )
            .unwrap_err()
            .as_service_error()
            .code,
            ServiceErrorCode::InvalidTunnelRequest
        ));
        assert!(matches!(
            service_not_ready_error("list tunnels", &AgentLifecycle::WaitingForSecret)
                .as_service_error()
                .code,
            ServiceErrorCode::ProvisioningUnavailable
        ));
        assert!(parse_tunnel_id("not-a-uuid").is_err());
    }
}
