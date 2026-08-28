use std::sync::Arc;
use std::time::Duration;

use playit_api_client::PlayitApi;
use playit_api_client::api::{
    ApiError, ApiResponseError, ClaimAgentType, ClaimExchangeError, ClaimSetupError,
    ClaimSetupResponse, ReqClaimExchange, ReqClaimSetup,
};
use rand::Rng;
use tokio::sync::{RwLock, mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::options::VersionDetails;
use crate::secret::SecretProvisionRequest;

pub(crate) fn claim_url(code: &str) -> String {
    format!("https://playit.gg/claim/{code}")
}

pub(crate) fn generate_claim_code() -> String {
    let mut buffer = [0u8; 5];
    rand::rng().fill(&mut buffer);
    hex::encode(buffer)
}

pub(crate) async fn run_claim_flow(
    api_base: String,
    version: VersionDetails,
    code: String,
    secret_provision_tx: mpsc::Sender<SecretProvisionRequest>,
    claim_code_state: Arc<RwLock<Option<String>>>,
    cancel_token: CancellationToken,
) {
    run_claim_flow_with_api(
        PlayitApi::create(api_base, None),
        version,
        code,
        secret_provision_tx,
        claim_code_state,
        cancel_token,
    )
    .await;
}

pub(crate) async fn run_claim_flow_with_api(
    api: PlayitApi,
    version: VersionDetails,
    code: String,
    secret_provision_tx: mpsc::Sender<SecretProvisionRequest>,
    claim_code_state: Arc<RwLock<Option<String>>>,
    cancel_token: CancellationToken,
) {
    const CLAIM_TIMEOUT: Duration = Duration::from_secs(10 * 60);

    let timed_out = tokio::time::timeout(
        CLAIM_TIMEOUT,
        run_claim_flow_inner(
            api,
            version,
            code.clone(),
            secret_provision_tx,
            cancel_token,
        ),
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
    version: VersionDetails,
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
                    version: format!("playit {}", version.version_string()),
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

#[cfg(test)]
mod tests {
    use super::{claim_url, run_claim_flow_with_api};
    use crate::options::{DEFAULT_VARIANT_ID, VersionDetails};
    use playit_api_client::PlayitApi;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::{RwLock, mpsc};
    use tokio_util::sync::CancellationToken;

    #[test]
    fn claim_urls_are_stable() {
        assert_eq!(claim_url("abc123"), "https://playit.gg/claim/abc123");
    }

    #[tokio::test]
    async fn successful_claim_provisions_the_secret_and_clears_state() {
        let (api_base, api_task) = spawn_api_server(vec![
            r#"{"status":"success","data":"UserAccepted"}"#,
            r#"{"status":"success","data":{"secret_key":"deadbeef"}}"#,
        ])
        .await;
        let (secret_tx, mut secret_rx) = mpsc::channel(1);
        let claim_code_state =
            std::sync::Arc::new(RwLock::new(Some("successful-code".to_string())));
        let flow = tokio::spawn(run_claim_flow_with_api(
            PlayitApi::create(api_base, None),
            VersionDetails::from_version_string("1.2.3", DEFAULT_VARIANT_ID).unwrap(),
            "successful-code".to_string(),
            secret_tx,
            claim_code_state.clone(),
            CancellationToken::new(),
        ));

        let request = secret_rx.recv().await.unwrap();
        assert_eq!(request.secret, "deadbeef");
        request.response_tx.send(Ok(())).unwrap();
        flow.await.unwrap();
        api_task.await.unwrap();

        assert!(claim_code_state.read().await.is_none());
    }

    #[tokio::test]
    async fn claim_failure_and_cancellation_clear_active_claim_state() {
        let (api_base, api_task) =
            spawn_api_server(vec![r#"{"status":"fail","data":"InvalidCode"}"#]).await;
        let (secret_tx, _secret_rx) = mpsc::channel(1);
        let claim_code_state = std::sync::Arc::new(RwLock::new(Some("failed-code".to_string())));
        run_claim_flow_with_api(
            PlayitApi::create(api_base, None),
            VersionDetails::from_version_string("1.2.3", DEFAULT_VARIANT_ID).unwrap(),
            "failed-code".to_string(),
            secret_tx,
            claim_code_state.clone(),
            CancellationToken::new(),
        )
        .await;
        api_task.await.unwrap();
        assert!(claim_code_state.read().await.is_none());

        let (secret_tx, _secret_rx) = mpsc::channel(1);
        let claim_code_state = std::sync::Arc::new(RwLock::new(Some("cancelled-code".to_string())));
        let cancel_token = CancellationToken::new();
        cancel_token.cancel();
        run_claim_flow_with_api(
            PlayitApi::create("http://127.0.0.1:1".to_string(), None),
            VersionDetails::from_version_string("1.2.3", DEFAULT_VARIANT_ID).unwrap(),
            "cancelled-code".to_string(),
            secret_tx,
            claim_code_state.clone(),
            cancel_token,
        )
        .await;
        assert!(claim_code_state.read().await.is_none());
    }

    async fn spawn_api_server(
        responses: Vec<&'static str>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            for body in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                read_http_request(&mut stream).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        (format!("http://{address}"), task)
    }

    async fn read_http_request(stream: &mut TcpStream) {
        let mut request = Vec::new();
        let mut chunk = [0u8; 2048];
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
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                })
                .flatten()
                .unwrap_or(0);
            if request.len() >= header_end + 4 + content_length {
                break;
            }
        }
    }
}
