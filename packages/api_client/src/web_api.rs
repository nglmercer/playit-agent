//! Typed wrappers for normal account/dashboard operations.
//!
//! The generated [`crate::api`] client owns the endpoint paths and models;
//! this module adds the account-session perspective: which authenticated
//! client to call with, what auth policy applies, and whether the call is
//! safe to retry. Only endpoints verified against
//! `packages/api_client/src/api.rs` (and, where noted, replayed live — see
//! `docs/api-inventory.md`) are wrapped.
//!
//! Nothing here invents endpoint paths: every route was recovered from the
//! official web client's API surface and replayed live before wrapping
//! (see `docs/auth-flow.md` and `docs/api-inventory.md`). TOTP submit lives
//! in [`crate::auth::complete_totp`].

use std::panic::Location;

use serde::{Serialize, de::DeserializeOwned};
use uuid::Uuid;

use crate::api::{
    AccountTunnels, ApiErrorNoFail, ApiResponseError, ApiResult, AuthError, ClaimAgentType,
    DeleteError, Domains, ObjectId, PlayitHttpClient, ReqTunnelsCreate, ReqTunnelsDelete,
    ReqTunnelsList, TunnelCreateError,
};
use crate::auth::AccountSession;
use crate::http_client::AuthPolicy;
use crate::{PlayitApi, PlayitApiBuilder};

/// The auth policy for every read-only account wrapper in this module.
pub const ACCOUNT_READ_POLICY: AuthPolicy = AuthPolicy::Account;

/// The auth policy for account-side mutations in this module.
pub const ACCOUNT_WRITE_POLICY: AuthPolicy = AuthPolicy::Account;

/// POST a JSON body to `path` with an already-authenticated client.
///
/// This mirrors the generated client's envelope handling without inventing
/// anything: typed `Fail` failures are returned (not mapped away) so
/// callers can react to variants like `WaitingForAgent`.
async fn post<Req, Res, Fail>(
    api: &PlayitApi,
    path: &str,
    req: Req,
) -> Result<ApiResult<Res, Fail>, WebApiError>
where
    Req: Serialize + Send,
    Res: DeserializeOwned,
    Fail: DeserializeOwned,
{
    let caller = Location::caller();
    api.get_client()
        .call(caller, path, req)
        .await
        .map_err(|error| WebApiError::Transport(format!("{error:?}")))
}

/// A failed account web-API call.
///
/// Secrets never appear in these values: session keys stay in the request
/// layer and are mapped away from transport errors.
#[derive(Debug)]
pub enum WebApiError {
    /// The account session is no longer accepted; sign in again.
    ///
    /// This never implies the agent secret is invalid: account sessions and
    /// agent secrets have independent lifecycles.
    SessionExpired,
    /// The API answered with a structured error.
    Api(String),
    /// The request could not be completed (network, TLS, parse failure).
    Transport(String),
}

impl std::fmt::Display for WebApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SessionExpired => {
                write!(
                    f,
                    "account session expired; run `playit account login` again"
                )
            }
            Self::Api(error) => write!(f, "playit.gg API error: {error}"),
            Self::Transport(error) => write!(f, "playit.gg request failed: {error}"),
        }
    }
}

impl std::error::Error for WebApiError {}

fn map_no_fail<E: std::fmt::Debug>(error: ApiErrorNoFail<E>) -> WebApiError {
    match error {
        ApiErrorNoFail::UnexpectedFail => WebApiError::Api("unexpected fail response".to_string()),
        ApiErrorNoFail::ApiError(api) => match &api {
            ApiResponseError::Auth(AuthError::SessionExpired)
            | ApiResponseError::Auth(AuthError::AuthRequired)
            | ApiResponseError::Auth(AuthError::NoLongerValid)
            | ApiResponseError::Auth(AuthError::InvalidToken) => WebApiError::SessionExpired,
            other => WebApiError::Api(format!("{other:?}")),
        },
        ApiErrorNoFail::ClientError(error) => WebApiError::Transport(format!("{error:?}")),
    }
}

async fn check_account_read(api: &PlayitApi) -> Result<(), WebApiError> {
    api.tunnels_list(ReqTunnelsList {
        tunnel_id: None,
        agent_id: None,
    })
    .await
    .map_err(map_no_fail)?;
    Ok(())
}

/// Validate an account session with a harmless read (`POST /tunnels/list`).
///
/// Auth policy: [`AuthPolicy::Account`]. Retry: transient-safe (read-only).
pub async fn validate_session(session: &AccountSession) -> Result<(), WebApiError> {
    check_account_read(&session.account_client()).await
}

/// Validate a stored session without rebuilding the full session token.
///
/// This takes only the API base URL and session key persisted by
/// [`crate::session::PersistedSession`].
pub async fn validate_with_key(api_base: &str, session_key: &str) -> Result<(), WebApiError> {
    let api = PlayitApiBuilder::new(api_base.to_owned())
        .bearer(session_key.to_owned())
        .build();
    check_account_read(&api).await
}

/// List the tunnels visible to the account (`POST /tunnels/list`).
///
/// Auth policy: [`AuthPolicy::Account`]. Retry: transient-safe (read-only).
/// Replayed live with `Authorization: Bearer <session_key>`; see
/// `docs/auth-flow.md`.
pub async fn list_tunnels(session: &AccountSession) -> Result<AccountTunnels, WebApiError> {
    session
        .account_client()
        .tunnels_list(ReqTunnelsList {
            tunnel_id: None,
            agent_id: None,
        })
        .await
        .map_err(map_no_fail)
}

/// List the domains visible to the account (`POST /domains/list`).
///
/// Auth policy: [`AuthPolicy::Account`]. Retry: transient-safe (read-only).
pub async fn list_domains(session: &AccountSession) -> Result<Domains, WebApiError> {
    session
        .account_client()
        .domains_list()
        .await
        .map_err(map_no_fail)
}

/// A `POST /claim/details` request: the machine-side claim code.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct ReqClaimDetails {
    pub code: String,
}

/// What the account side sees for a pending claim (`POST /claim/details`).
///
/// Observed live 2026-09-07 against the official web client flow.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct ClaimDetails {
    pub agent_type: ClaimAgentType,
    pub name: String,
    pub remote_ip: String,
    pub version: String,
}

/// Why `POST /claim/details` did not return details.
///
/// Fail strings taken from the official web client's error map.
#[derive(
    serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Hash,
)]
pub enum ClaimDetailsFail {
    AlreadyClaimed,
    AlreadyRejected,
    ClaimExpired,
    DifferentOwner,
    WaitingForAgent,
    InvalidCode,
    #[serde(other)]
    Other,
}

/// Look up a pending claim as the account (`POST /claim/details`).
///
/// Auth policy: [`AuthPolicy::Account`]. Retry: transient-safe while the
/// outcome is `WaitingForAgent` (read-only poll); any other failure is
/// terminal for this code.
pub async fn claim_details(
    api: &PlayitApi,
    code: &str,
) -> Result<ApiResult<ClaimDetails, ClaimDetailsFail>, WebApiError> {
    post(
        api,
        "/claim/details",
        ReqClaimDetails {
            code: code.to_owned(),
        },
    )
    .await
}

/// A `POST /claim/accept` request: approve the code under this account.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct ReqClaimAccept {
    pub code: String,
    pub name: String,
    pub agent_type: ClaimAgentType,
}

/// A successful `POST /claim/accept`: the newly created agent.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct ClaimAccepted {
    pub agent_id: Uuid,
}

/// Why `POST /claim/accept` refused the approval.
///
/// Fail strings taken from the official web client's error map.
#[derive(
    serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Hash,
)]
pub enum ClaimAcceptFail {
    InvalidCode,
    AgentNotReady,
    CodeNotFound,
    InvalidAgentType,
    ClaimAlreadyAccepted,
    ClaimRejected,
    CodeExpired,
    InvalidName,
    #[serde(other)]
    Other,
}

/// Approve a claim as the account (`POST /claim/accept`), creating the agent.
///
/// Auth policy: [`AuthPolicy::Account`]. Retry: never (creates an agent).
/// After success, `/claim/setup` reports `UserAccepted` and
/// `/claim/exchange` issues the agent secret.
pub async fn accept_claim(
    api: &PlayitApi,
    code: &str,
    name: &str,
    agent_type: ClaimAgentType,
) -> Result<ApiResult<ClaimAccepted, ClaimAcceptFail>, WebApiError> {
    post(
        api,
        "/claim/accept",
        ReqClaimAccept {
            code: code.to_owned(),
            name: name.to_owned(),
            agent_type,
        },
    )
    .await
}

/// A `POST /claim/reject` request.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct ReqClaimReject {
    pub code: String,
}

/// Why `POST /claim/reject` refused the rejection.
///
/// Fail strings taken from the official web client's error map.
#[derive(
    serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Hash,
)]
pub enum ClaimRejectFail {
    InvalidCode,
    CodeNotFound,
    ClaimAccepted,
    ClaimAlreadyRejected,
    #[serde(other)]
    Other,
}

/// Reject a claim as the account (`POST /claim/reject`).
///
/// Auth policy: [`AuthPolicy::Account`]. Retry: never (state change).
/// After success, `/claim/details` fails with `AlreadyRejected` and
/// `/claim/setup` reports `UserRejected`.
pub async fn reject_claim(
    api: &PlayitApi,
    code: &str,
) -> Result<ApiResult<(), ClaimRejectFail>, WebApiError> {
    post(
        api,
        "/claim/reject",
        ReqClaimReject {
            code: code.to_owned(),
        },
    )
    .await
}

/// One entry of `POST /agents/list`.
///
/// Only the stable identity fields are modeled; the dashboard-only detail
/// fields are ignored so the parser survives site evolution.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct AgentListEntry {
    pub id: Uuid,
    pub name: String,
}

/// `POST /agents/list` response.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct AgentsList {
    pub agents: Vec<AgentListEntry>,
}

/// List the account's agents (`POST /agents/list`).
///
/// Auth policy: [`AuthPolicy::Account`]. Retry: transient-safe (read-only).
/// Replayed live 2026-09-07.
pub async fn list_agents(
    api: &PlayitApi,
) -> Result<ApiResult<AgentsList, serde_json::Value>, WebApiError> {
    post(api, "/agents/list", serde_json::json!({})).await
}

/// Where an agent's tunnels go when the agent is deleted.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct AgentDeleteMoveDetails {
    pub agent_id: Option<Uuid>,
    pub disable_tunnels: bool,
}

/// The `tunnels_strategy` of `POST /agents/delete`.
///
/// Only the observed `move_to_agent` strategy is modeled (`agent_id: null`
/// unassigns the tunnels instead of moving them).
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(tag = "type", content = "details")]
pub enum TunnelsStrategy {
    #[serde(rename = "move_to_agent")]
    MoveToAgent(AgentDeleteMoveDetails),
}

/// A `POST /agents/delete` request.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct ReqAgentsDelete {
    pub agent_id: Uuid,
    pub tunnels_strategy: TunnelsStrategy,
}

/// Delete an agent (`POST /agents/delete`).
///
/// Auth policy: [`AuthPolicy::Account`]. Retry: never (destructive).
/// Replayed live 2026-09-07.
pub async fn delete_agent(
    api: &PlayitApi,
    req: ReqAgentsDelete,
) -> Result<ApiResult<(), serde_json::Value>, WebApiError> {
    post(api, "/agents/delete", req).await
}

/// Create a tunnel as the account (`POST /tunnels/create`).
///
/// Auth policy: [`AuthPolicy::Account`]. Retry: never (creates a resource).
/// Creation requires an agent-bound origin and a concrete `tunnel_type`
/// (`fail InvalidAgentId` / `fail TunnelTypeRequiresDescription`
/// otherwise); replayed live 2026-09-07.
pub async fn create_tunnel(
    api: &PlayitApi,
    req: ReqTunnelsCreate,
) -> Result<ApiResult<ObjectId, TunnelCreateError>, WebApiError> {
    post(api, "/tunnels/create", req).await
}

/// Delete a tunnel as the account (`POST /tunnels/delete`).
///
/// Auth policy: [`AuthPolicy::Account`]. Retry: never (destructive).
/// Replayed live 2026-09-07.
pub async fn delete_tunnel(
    api: &PlayitApi,
    tunnel_id: Uuid,
) -> Result<ApiResult<(), DeleteError>, WebApiError> {
    post(api, "/tunnels/delete", ReqTunnelsDelete { tunnel_id }).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{AccountStatus, TotpStatus, WebAuthToken, WebSession};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    const TUNNELS_EMPTY_BODY: &str = concat!(
        r#"{"status":"success","data":{"tunnels":[],"#,
        r#""tcp_alloc":{"allowed":0,"claimed":0,"desired":0},"#,
        r#""udp_alloc":{"allowed":0,"claimed":0,"desired":0}}}"#,
    );
    const DOMAINS_EMPTY_BODY: &str = r#"{"status":"success","data":{"domains":[]}}"#;
    const SESSION_EXPIRED_BODY: &str =
        r#"{"status":"error","data":{"type":"auth","message":"SessionExpired"}}"#;
    const UNEXPECTED_FAIL_BODY: &str = r#"{"status":"fail","data":null}"#;

    async fn spawn_server(
        bodies: Vec<&'static str>,
        seen_auth: Arc<Mutex<Vec<String>>>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            for body in bodies {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let mut request = [0u8; 16 * 1024];
                let Ok(read) = stream.read(&mut request).await else {
                    return;
                };
                let text = String::from_utf8_lossy(&request[..read]);
                for line in text.lines().skip(1) {
                    let line = line.trim_end_matches('\r');
                    if line.is_empty() {
                        break;
                    }
                    if let Some(value) = line.strip_prefix("authorization:") {
                        seen_auth.lock().await.push(value.trim().to_owned());
                    }
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
        (base, task)
    }

    fn fixture_session(api_base: String) -> AccountSession {
        AccountSession::new(
            api_base,
            WebSession {
                session_key: "fixture-account-credential".to_owned(),
                auth: WebAuthToken {
                    update_version: 1,
                    account_id: 123,
                    timestamp: 456,
                    account_status: AccountStatus::Verified,
                    totp_status: TotpStatus::NotSetup,
                    admin_id: None,
                    admin_review_id: None,
                    read_only: false,
                    show_admin: false,
                },
            },
        )
    }

    #[tokio::test]
    async fn list_tunnels_returns_empty_list() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (base, task) = spawn_server(vec![TUNNELS_EMPTY_BODY], seen).await;
        let tunnels = list_tunnels(&fixture_session(base)).await.unwrap();
        assert!(tunnels.tunnels.is_empty());
        task.abort();
    }

    #[tokio::test]
    async fn list_domains_returns_empty_list() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (base, task) = spawn_server(vec![DOMAINS_EMPTY_BODY], seen).await;
        let domains = list_domains(&fixture_session(base)).await.unwrap();
        assert!(domains.domains.is_empty());
        task.abort();
    }

    #[tokio::test]
    async fn session_expired_maps_to_reauthentication() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (base, task) = spawn_server(vec![SESSION_EXPIRED_BODY], seen).await;
        let error = list_tunnels(&fixture_session(base)).await.unwrap_err();
        assert!(matches!(error, WebApiError::SessionExpired));
        task.abort();
    }

    #[tokio::test]
    async fn unexpected_fail_maps_to_api_error() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (base, task) = spawn_server(vec![UNEXPECTED_FAIL_BODY], seen).await;
        let error = list_tunnels(&fixture_session(base)).await.unwrap_err();
        assert!(matches!(error, WebApiError::Api(_)));
        task.abort();
    }

    #[tokio::test]
    async fn validate_with_key_reports_session_expired() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (base, task) = spawn_server(vec![SESSION_EXPIRED_BODY], seen).await;
        let error = validate_with_key(&base, "fixture-account-credential")
            .await
            .unwrap_err();
        assert!(matches!(error, WebApiError::SessionExpired));
        task.abort();
    }

    use uuid::Uuid;

    const DETAILS_BODY: &str = concat!(
        r#"{"status":"success","data":{"agent_type":"self-managed","#,
        r#""name":"fixture-agent","remote_ip":"::1","version":"fixture"}}"#,
    );
    const DETAILS_WAITING_BODY: &str = r#"{"status":"fail","data":"WaitingForAgent"}"#;
    const ACCEPT_BODY: &str = concat!(
        r#"{"status":"success","data":{"agent_id":"#,
        r#""00000000-0000-0000-0000-000000000001"}}"#,
    );
    const REJECT_OK_BODY: &str = r#"{"status":"success","data":null}"#;
    const REJECT_DONE_BODY: &str = r#"{"status":"fail","data":"ClaimAlreadyRejected"}"#;
    const AGENTS_BODY: &str = concat!(
        r#"{"status":"success","data":{"agents":[{"id":"#,
        r#""00000000-0000-0000-0000-000000000002","name":"fixture-agent","#,
        r#""created_at":"2026-01-01T00:00:00Z","self_managed":true,"#,
        r#""status":{"state":"offline"},"routing":{"type":"Automatic"}}]}}"#,
    );
    const CREATE_FAIL_BODY: &str = r#"{"status":"fail","data":"InvalidAgentId"}"#;

    async fn account_api(bodies: Vec<&'static str>) -> (PlayitApi, tokio::task::JoinHandle<()>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (base, task) = spawn_server(bodies, seen).await;
        let api = fixture_session(base).account_client();
        (api, task)
    }

    #[tokio::test]
    async fn claim_details_success() {
        let (api, task) = account_api(vec![DETAILS_BODY]).await;
        let outcome = claim_details(&api, "fixture-code").await.unwrap();
        match outcome {
            ApiResult::Success(details) => {
                assert_eq!(details.name, "fixture-agent");
                assert!(matches!(
                    details.agent_type,
                    crate::api::ClaimAgentType::SelfManaged
                ));
            }
            other => panic!("expected details, got {other:?}"),
        }
        task.abort();
    }

    #[tokio::test]
    async fn claim_details_waiting_for_agent() {
        let (api, task) = account_api(vec![DETAILS_WAITING_BODY]).await;
        let outcome = claim_details(&api, "fixture-code").await.unwrap();
        assert!(matches!(
            outcome,
            ApiResult::Fail(ClaimDetailsFail::WaitingForAgent)
        ));
        task.abort();
    }

    #[tokio::test]
    async fn claim_accept_success_returns_agent_id() {
        let (api, task) = account_api(vec![ACCEPT_BODY]).await;
        let outcome = accept_claim(
            &api,
            "fixture-code",
            "fixture-agent",
            crate::api::ClaimAgentType::SelfManaged,
        )
        .await
        .unwrap();
        let accepted = match outcome {
            ApiResult::Success(accepted) => accepted,
            other => panic!("expected acceptance, got {other:?}"),
        };
        assert_eq!(
            accepted.agent_id,
            Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap()
        );
        task.abort();
    }

    #[tokio::test]
    async fn claim_reject_success() {
        let (api, task) = account_api(vec![REJECT_OK_BODY]).await;
        let outcome = reject_claim(&api, "fixture-code").await.unwrap();
        assert!(matches!(outcome, ApiResult::Success(())));
        task.abort();
    }

    #[tokio::test]
    async fn claim_reject_already_rejected() {
        let (api, task) = account_api(vec![REJECT_DONE_BODY]).await;
        let outcome = reject_claim(&api, "fixture-code").await.unwrap();
        assert!(matches!(
            outcome,
            ApiResult::Fail(ClaimRejectFail::ClaimAlreadyRejected)
        ));
        task.abort();
    }

    #[tokio::test]
    async fn agents_list_ignores_dashboard_extras() {
        let (api, task) = account_api(vec![AGENTS_BODY]).await;
        let outcome = list_agents(&api).await.unwrap();
        let list = match outcome {
            ApiResult::Success(list) => list,
            other => panic!("expected agent list, got {other:?}"),
        };
        assert_eq!(list.agents.len(), 1);
        assert_eq!(list.agents[0].name, "fixture-agent");
        task.abort();
    }

    #[tokio::test]
    async fn tunnel_create_fail_maps_variant() {
        let (api, task) = account_api(vec![CREATE_FAIL_BODY]).await;
        let outcome = create_tunnel(
            &api,
            crate::api::ReqTunnelsCreate {
                name: Some("fixture".to_string()),
                tunnel_type: None,
                port_type: crate::api::PortType::Tcp,
                port_count: 1,
                origin: crate::api::TunnelOriginCreate::Default(
                    crate::api::AssignedDefaultCreate {
                        local_ip: "127.0.0.1".parse().unwrap(),
                        local_port: Some(1),
                    },
                ),
                enabled: true,
                alloc: None,
                firewall_id: None,
                proxy_protocol: None,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            outcome,
            ApiResult::Fail(crate::api::TunnelCreateError::InvalidAgentId)
        ));
        task.abort();
    }
}
