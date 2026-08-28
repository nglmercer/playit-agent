use std::panic::Location;
use std::time::{Duration, SystemTime};

use reqwest::{StatusCode, header::HeaderValue};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::RwLock;

use crate::api::{ApiResult, PlayitHttpClient, RetryPolicy};

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
                let retry_after = response.headers().get(reqwest::header::RETRY_AFTER).cloned();
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

                let result: ApiResult<Res, Err> =
                    serde_json::from_str(&response_txt).map_err(|e| {
                        tracing::error!(?e, status = %response_status, "failed to parse API JSON response");
                        HttpClientError::ParseError(e, response_status)
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
}
