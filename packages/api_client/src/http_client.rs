use std::panic::Location;
use std::time::{Duration, SystemTime};

use reqwest::{StatusCode, header::HeaderValue};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::RwLock;

use crate::api::{ApiResult, PlayitHttpClient, RetryPolicy};

/// Structured authentication state for Playit API requests.
///
/// Call sites declare *which* credential they use instead of formatting an
/// `Authorization` header by hand. The secret is exposed only when building
/// the header value for a request: `Debug` is redacted, and tracing should
/// use [`AuthState::kind`] (or `HttpClient::auth_kind`) rather than the
/// header value.
#[derive(Clone)]
pub enum AuthState {
    /// No credential; only `AuthPolicy::Anonymous` endpoints accept this.
    Anonymous,
    /// A long-lived agent secret, sent as `Authorization: Agent-Key <secret>`.
    AgentKey(String),
    /// A playit.gg account session key, sent as `Authorization: Bearer <key>`.
    Bearer(String),
}

impl AuthState {
    /// No credential.
    pub fn anonymous() -> Self {
        Self::Anonymous
    }

    /// An agent secret credential (surrounding whitespace is trimmed).
    pub fn agent_key(secret: impl Into<String>) -> Self {
        Self::AgentKey(secret.into().trim().to_owned())
    }

    /// An account session credential.
    pub fn bearer(token: impl Into<String>) -> Self {
        Self::Bearer(token.into())
    }

    /// The `Authorization` header value for this state, if any.
    pub fn header_value(&self) -> Option<String> {
        match self {
            Self::Anonymous => None,
            Self::AgentKey(secret) => Some(format!("Agent-Key {secret}")),
            Self::Bearer(token) => Some(format!("Bearer {token}")),
        }
    }

    /// The credential family, safe to log and trace.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Anonymous => "anonymous",
            Self::AgentKey(_) => "agent",
            Self::Bearer(_) => "account",
        }
    }
}

impl std::fmt::Debug for AuthState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Anonymous => f.write_str("Anonymous"),
            Self::AgentKey(_) => f.write_str("AgentKey(<redacted>)"),
            Self::Bearer(_) => f.write_str("Bearer(<redacted>)"),
        }
    }
}

/// Which credential families an endpoint accepts.
///
/// This documents intent per endpoint in the `web_api` wrappers so account
/// credentials are never attached where they are not needed. The transport
/// always sends whatever the `HttpClient` holds; policy enforcement at the
/// call site is a follow-up once every endpoint's auth mode is inventoried
/// in `docs/api-inventory.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthPolicy {
    Anonymous,
    Agent,
    Account,
    AgentOrAccount,
}

impl AuthPolicy {
    /// Whether `auth` satisfies this policy.
    pub fn allows(&self, auth: &AuthState) -> bool {
        matches!(
            (self, auth),
            (Self::Anonymous, AuthState::Anonymous)
                | (Self::Agent, AuthState::AgentKey(_))
                | (Self::Account, AuthState::Bearer(_))
                | (Self::AgentOrAccount, AuthState::AgentKey(_))
                | (Self::AgentOrAccount, AuthState::Bearer(_))
        )
    }
}

pub struct HttpClient {
    api_base: String,
    auth_header: RwLock<Option<String>>,
    client: reqwest::Client,
}

const MAX_REQUEST_ATTEMPTS: usize = 3;
const RETRY_DELAY: Duration = Duration::from_millis(250);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(5);

impl Clone for HttpClient {
    fn clone(&self) -> Self {
        Self {
            api_base: self.api_base.clone(),
            auth_header: match self.auth_header.try_read() {
                Ok(v) => RwLock::new(v.clone()),
                _ => RwLock::new(None),
            },
            client: self.client.clone(),
        }
    }
}

impl HttpClient {
    pub fn new(api_base: String, auth_header: Option<String>) -> Self {
        HttpClient {
            api_base,
            auth_header: RwLock::new(auth_header),
            client: reqwest::Client::new(),
        }
    }

    pub fn api_base(&self) -> &str {
        &self.api_base
    }

    pub async fn remove_auth(&self) {
        let mut lock = self.auth_header.write().await;
        let _ = lock.take();
    }

    /// Build a client from a structured [`AuthState`].
    pub fn new_with_auth(api_base: String, auth: AuthState) -> Self {
        Self::new(api_base, auth.header_value())
    }

    /// Replace the credential used for subsequent requests.
    pub async fn set_auth(&self, auth: AuthState) {
        *self.auth_header.write().await = auth.header_value();
    }

    /// The credential family currently configured, safe to log and trace.
    ///
    /// This inspects the stored header prefix only; the secret itself is
    /// never exposed.
    pub async fn auth_kind(&self) -> &'static str {
        match self.auth_header.read().await.as_deref() {
            None => "anonymous",
            Some(value) if value.starts_with("Agent-Key ") => "agent",
            Some(value) if value.starts_with("Bearer ") => "account",
            _ => "unknown",
        }
    }
}

impl std::fmt::Debug for HttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpClient")
            .field("api_base", &self.api_base)
            .field("auth", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl PlayitHttpClient for HttpClient {
    type Error = HttpClientError;

    async fn call<Req: Serialize + Send, Res: DeserializeOwned, Err: DeserializeOwned>(
        &self,
        caller: &'static Location<'static>,
        path: &str,
        req: Req,
    ) -> Result<ApiResult<Res, Err>, Self::Error> {
        self.call_with_policy(caller, path, req, RetryPolicy::Never)
            .await
    }

    async fn call_with_policy<
        Req: Serialize + Send,
        Res: DeserializeOwned,
        Err: DeserializeOwned,
    >(
        &self,
        _caller: &'static Location<'static>,
        path: &str,
        req: Req,
        retry_policy: RetryPolicy,
    ) -> Result<ApiResult<Res, Err>, Self::Error> {
        let body = serde_json::to_value(req).map_err(HttpClientError::SerializeError)?;
        let res = async move {
            let max_attempts = match retry_policy {
                RetryPolicy::Never => 1,
                RetryPolicy::Transient => MAX_REQUEST_ATTEMPTS,
            };

            for attempt in 0..max_attempts {
                let mut builder = self.client.post(format!("{}{}", self.api_base, path));

                {
                    let lock = self.auth_header.read().await;

                    if let Some(auth_header) = &*lock {
                        builder = builder.header(reqwest::header::AUTHORIZATION, auth_header);
                    }
                }

                let request = builder.json(&body).build()?;
                let response = match self.client.execute(request).await {
                    Ok(response) => response,
                    Err(error)
                        if retry_policy == RetryPolicy::Transient
                            && attempt + 1 < max_attempts
                            && is_retryable_request_error(&error) =>
                    {
                        tracing::debug!(
                            attempt = attempt + 1,
                            max_attempts = MAX_REQUEST_ATTEMPTS,
                            ?error,
                            "retrying transient API request failure"
                        );
                        tokio::time::sleep(retry_delay(attempt, None)).await;
                        continue;
                    }
                    Err(error) => return Err(HttpClientError::RequestError(error)),
                };

                let response_status = response.status();
                let retry_after = response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .cloned();
                let response_txt = match response.text().await {
                    Ok(response_txt) => response_txt,
                    Err(error)
                        if retry_policy == RetryPolicy::Transient
                            && attempt + 1 < max_attempts
                            && is_retryable_request_error(&error) =>
                    {
                        tracing::debug!(
                            attempt = attempt + 1,
                            max_attempts = MAX_REQUEST_ATTEMPTS,
                            ?error,
                            "retrying transient API response read failure"
                        );
                        tokio::time::sleep(retry_delay(attempt, retry_after.as_ref())).await;
                        continue;
                    }
                    Err(error) => return Err(HttpClientError::RequestError(error)),
                };

                if retry_policy == RetryPolicy::Transient
                    && (response_status == StatusCode::TOO_MANY_REQUESTS
                        || response_status.is_server_error())
                    && attempt + 1 < max_attempts
                {
                    tracing::debug!(
                        attempt = attempt + 1,
                        max_attempts = MAX_REQUEST_ATTEMPTS,
                        status = %response_status,
                        "retrying transient API response"
                    );
                    tokio::time::sleep(retry_delay(attempt, retry_after.as_ref())).await;
                    continue;
                }

                if response_status == StatusCode::TOO_MANY_REQUESTS {
                    return Err(HttpClientError::TooManyRequests);
                }

                let mut deserializer = serde_json::Deserializer::from_str(&response_txt);
                let result: ApiResult<Res, Err> =
                    serde_path_to_error::deserialize(&mut deserializer).map_err(|error| {
                        tracing::error!(
                            path = %error.path(),
                            error = %error.inner(),
                            status = %response_status,
                            "failed to parse API JSON response"
                        );
                        HttpClientError::ParseError(error.into_inner(), response_status)
                    })?;
                deserializer.end().map_err(|error| {
                    tracing::error!(
                        path = "<root>",
                        error = %error,
                        status = %response_status,
                        "failed to parse trailing API JSON data"
                    );
                    HttpClientError::ParseError(error, response_status)
                })?;

                return Ok(result);
            }

            unreachable!("request loop always returns after the final attempt")
        }
        .await;

        if let Err(error) = &res {
            tracing::error!(?error, request = %std::any::type_name::<Req>(), "API call failed");
        }

        res
    }
}

pub enum HttpClientError {
    SerializeError(serde_json::Error),
    ParseError(serde_json::Error, StatusCode),
    RequestError(reqwest::Error),
    TooManyRequests,
}

impl std::fmt::Display for HttpClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SerializeError(error) => write!(f, "failed to serialize API request: {error}"),
            Self::ParseError(error, status) => {
                write!(f, "failed to parse API response ({status}): {error}")
            }
            Self::RequestError(error) if error.is_timeout() => {
                write!(f, "API request timed out")
            }
            Self::RequestError(error) if error.is_connect() => {
                write!(f, "could not connect to the API")
            }
            Self::RequestError(_) => write!(f, "API request failed"),
            Self::TooManyRequests => write!(f, "API rate limit exceeded"),
        }
    }
}

impl std::fmt::Debug for HttpClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SerializeError(error) => f.debug_tuple("SerializeError").field(error).finish(),
            Self::ParseError(error, status) => f
                .debug_struct("ParseError")
                .field("error", error)
                .field("status", status)
                .finish(),
            Self::RequestError(error) => f
                .debug_struct("RequestError")
                .field("connect", &error.is_connect())
                .field("timeout", &error.is_timeout())
                .field("request", &error.is_request())
                .finish(),
            Self::TooManyRequests => f.write_str("TooManyRequests"),
        }
    }
}

impl std::error::Error for HttpClientError {}

impl From<reqwest::Error> for HttpClientError {
    fn from(value: reqwest::Error) -> Self {
        HttpClientError::RequestError(value)
    }
}

impl HttpClientError {
    pub fn is_transient(&self) -> bool {
        match self {
            Self::RequestError(error) => is_retryable_request_error(error),
            Self::ParseError(_, status) => {
                *status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
            }
            Self::TooManyRequests => true,
            Self::SerializeError(_) => false,
        }
    }
}

fn is_retryable_request_error(error: &reqwest::Error) -> bool {
    error.is_connect() || error.is_timeout() || error.is_request() || error.is_body()
}

fn retry_delay(attempt: usize, retry_after: Option<&HeaderValue>) -> Duration {
    retry_after
        .and_then(parse_retry_after)
        .unwrap_or_else(|| RETRY_DELAY.saturating_mul((attempt as u32).saturating_add(1)))
        .min(MAX_RETRY_DELAY)
}

fn parse_retry_after(value: &HeaderValue) -> Option<Duration> {
    let value = value.to_str().ok()?.trim();

    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }

    let retry_at = httpdate::parse_http_date(value).ok()?;
    Some(
        retry_at
            .duration_since(SystemTime::now())
            .unwrap_or_default(),
    )
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Instant;

    use super::*;
    use crate::api::ApiResult;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    struct TestResponse {
        status: u16,
        headers: &'static str,
        body: &'static str,
        close_without_response: bool,
    }

    async fn spawn_test_server(
        responses: Vec<TestResponse>,
    ) -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let count_for_task = count.clone();

        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let index = count_for_task.fetch_add(1, Ordering::SeqCst);
                let mut request = [0u8; 16 * 1024];
                let _ = stream.read(&mut request).await;
                let Some(response) = responses.get(index) else {
                    continue;
                };
                if response.close_without_response {
                    continue;
                }
                let response = format!(
                    "HTTP/1.1 {} Test\r\nContent-Length: {}\r\nConnection: close\r\n{}\r\n{}",
                    response.status,
                    response.body.len(),
                    response.headers,
                    response.body,
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });

        (format!("http://{address}"), count, task)
    }

    fn success_body() -> &'static str {
        r#"{"status":"success","data":{"ok":true}}"#
    }

    fn success_body_with_trailing_data() -> &'static str {
        r#"{"status":"success","data":{"ok":true}} trailing"#
    }

    fn server_error_body() -> &'static str {
        r#"{"status":"error","data":{"type":"internal","message":{"trace_id":"test"}}}"#
    }

    #[tokio::test]
    async fn read_only_policy_retries_transient_network_failure() {
        let (base, count, task) = spawn_test_server(vec![
            TestResponse {
                status: 200,
                headers: "",
                body: "",
                close_without_response: true,
            },
            TestResponse {
                status: 200,
                headers: "",
                body: success_body(),
                close_without_response: false,
            },
        ])
        .await;
        let client = HttpClient::new(base, None);

        let result: Result<ApiResult<serde_json::Value, serde_json::Value>, HttpClientError> =
            client
                .call_with_policy(
                    Location::caller(),
                    "/read",
                    serde_json::json!({}),
                    RetryPolicy::Transient,
                )
                .await;

        assert!(
            matches!(result, Ok(ApiResult::Success(_))),
            "result: {result:?}"
        );
        assert_eq!(count.load(Ordering::SeqCst), 2);
        task.abort();
    }

    #[tokio::test]
    async fn mutation_policy_does_not_retry_ambiguous_network_failure() {
        let (base, count, task) = spawn_test_server(vec![TestResponse {
            status: 200,
            headers: "",
            body: "",
            close_without_response: true,
        }])
        .await;
        let client = HttpClient::new(base, None);

        let result: Result<ApiResult<serde_json::Value, serde_json::Value>, HttpClientError> =
            client
                .call_with_policy(
                    Location::caller(),
                    "/mutation",
                    serde_json::json!({}),
                    RetryPolicy::Never,
                )
                .await;

        assert!(matches!(result, Err(HttpClientError::RequestError(_))));
        assert_eq!(count.load(Ordering::SeqCst), 1);
        task.abort();
    }

    #[tokio::test]
    async fn mutation_policy_does_not_retry_server_error() {
        let (base, count, task) = spawn_test_server(vec![TestResponse {
            status: 500,
            headers: "",
            body: server_error_body(),
            close_without_response: false,
        }])
        .await;
        let client = HttpClient::new(base, None);

        let result: Result<ApiResult<serde_json::Value, serde_json::Value>, HttpClientError> =
            client
                .call_with_policy(
                    Location::caller(),
                    "/mutation",
                    serde_json::json!({}),
                    RetryPolicy::Never,
                )
                .await;

        assert!(matches!(result, Ok(ApiResult::Error(_))));
        assert_eq!(count.load(Ordering::SeqCst), 1);
        task.abort();
    }

    #[tokio::test]
    async fn json_parser_rejects_trailing_data() {
        let (base, count, task) = spawn_test_server(vec![TestResponse {
            status: 200,
            headers: "",
            body: success_body_with_trailing_data(),
            close_without_response: false,
        }])
        .await;
        let client = HttpClient::new(base, None);

        let result: Result<ApiResult<serde_json::Value, serde_json::Value>, HttpClientError> =
            client
                .call_with_policy(
                    Location::caller(),
                    "/malformed",
                    serde_json::json!({}),
                    RetryPolicy::Never,
                )
                .await;

        assert!(matches!(
            result,
            Err(HttpClientError::ParseError(_, status))
                if status == reqwest::StatusCode::OK
        ));
        assert_eq!(count.load(Ordering::SeqCst), 1);
        task.abort();
    }

    #[tokio::test]
    async fn rate_limit_uses_retry_after_header() {
        let (base, count, task) = spawn_test_server(vec![
            TestResponse {
                status: 429,
                headers: "Retry-After: 1\r\n",
                body: server_error_body(),
                close_without_response: false,
            },
            TestResponse {
                status: 200,
                headers: "",
                body: success_body(),
                close_without_response: false,
            },
        ])
        .await;
        let client = HttpClient::new(base, None);
        let started = Instant::now();

        let result: Result<ApiResult<serde_json::Value, serde_json::Value>, HttpClientError> =
            client
                .call_with_policy(
                    Location::caller(),
                    "/read",
                    serde_json::json!({}),
                    RetryPolicy::Transient,
                )
                .await;

        assert!(matches!(result, Ok(ApiResult::Success(_))));
        assert!(started.elapsed() >= Duration::from_millis(900));
        assert_eq!(count.load(Ordering::SeqCst), 2);
        task.abort();
    }

    #[tokio::test]
    async fn transient_retry_attempts_are_bounded() {
        let responses = (0..MAX_REQUEST_ATTEMPTS)
            .map(|_| TestResponse {
                status: 503,
                headers: "",
                body: server_error_body(),
                close_without_response: false,
            })
            .collect();
        let (base, count, task) = spawn_test_server(responses).await;
        let client = HttpClient::new(base, None);

        let result: Result<ApiResult<serde_json::Value, serde_json::Value>, HttpClientError> =
            client
                .call_with_policy(
                    Location::caller(),
                    "/read",
                    serde_json::json!({}),
                    RetryPolicy::Transient,
                )
                .await;

        assert!(matches!(result, Ok(ApiResult::Error(_))));
        assert_eq!(count.load(Ordering::SeqCst), MAX_REQUEST_ATTEMPTS);
        task.abort();
    }

    #[test]
    fn auth_state_header_values_and_kinds() {
        assert_eq!(AuthState::anonymous().header_value(), None);
        assert_eq!(AuthState::anonymous().kind(), "anonymous");
        assert_eq!(
            AuthState::agent_key("  padded-credential  ")
                .header_value()
                .as_deref(),
            Some("Agent-Key padded-credential")
        );
        assert_eq!(AuthState::agent_key("padded-credential").kind(), "agent");
        assert_eq!(
            AuthState::bearer("account-credential")
                .header_value()
                .as_deref(),
            Some("Bearer account-credential")
        );
        assert_eq!(AuthState::bearer("account-credential").kind(), "account");
    }

    #[test]
    fn auth_state_debug_never_exposes_credentials() {
        for state in [
            AuthState::agent_key("agent-credential-value"),
            AuthState::bearer("account-credential-value"),
        ] {
            let rendered = format!("{state:?}");
            assert!(!rendered.contains("agent-credential-value"));
            assert!(!rendered.contains("account-credential-value"));
        }
        let client = HttpClient::new(
            "http://127.0.0.1:1".to_string(),
            AuthState::agent_key("agent-credential-value").header_value(),
        );
        let rendered = format!("{client:?}");
        assert!(!rendered.contains("agent-credential-value"));
    }

    #[test]
    fn auth_policy_allows_expected_families() {
        let anonymous = AuthState::anonymous();
        let agent = AuthState::agent_key("agent-credential-value");
        let account = AuthState::bearer("account-credential-value");
        assert!(AuthPolicy::Anonymous.allows(&anonymous));
        assert!(!AuthPolicy::Anonymous.allows(&agent));
        assert!(AuthPolicy::Agent.allows(&agent));
        assert!(!AuthPolicy::Agent.allows(&account));
        assert!(AuthPolicy::Account.allows(&account));
        assert!(!AuthPolicy::Account.allows(&anonymous));
        assert!(AuthPolicy::AgentOrAccount.allows(&agent));
        assert!(AuthPolicy::AgentOrAccount.allows(&account));
        assert!(!AuthPolicy::AgentOrAccount.allows(&anonymous));
    }

    #[tokio::test]
    async fn auth_kind_reports_family_without_leaking_secret() {
        let client = HttpClient::new_with_auth(
            "http://127.0.0.1:1".to_string(),
            AuthState::bearer("account-credential-value"),
        );
        assert_eq!(client.auth_kind().await, "account");
        client
            .set_auth(AuthState::agent_key("agent-credential-value"))
            .await;
        assert_eq!(client.auth_kind().await, "agent");
        client.remove_auth().await;
        assert_eq!(client.auth_kind().await, "anonymous");
    }
}
