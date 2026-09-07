//! Direct account authentication over HTTPS.
//!
//! Covers `POST /login/signin` plus the session carrier observed against the
//! live API: follow-up account calls send `Authorization: Bearer <session_key>`
//! (see `docs/auth-flow.md`). Passwords are sent only in the sign-in request
//! body and are never stored, logged, or included in errors.

use std::time::{Duration, Instant};

use std::panic::Location;

use crate::PlayitApi;
use crate::api::{
    AccountStatus, ApiError, ApiResponseError, ApiResult, AuthError as ApiAuthError,
    LoginCredentials, PlayitHttpClient, SigninFail, TotpStatus, WebSession,
};
use crate::http_client::AuthState;

pub use crate::http_client::AuthPolicy;
pub use crate::web_api::{WebApiError, validate_session};

/// An authenticated playit.gg account session from direct email/password login.
///
/// This bundles the [`WebSession`] returned by [`sign_in`] with the API base
/// URL it was issued against and a local creation timestamp. It performs no
/// refresh, persistence, or logout; discarding it ends the local session.
/// See [`crate::session`] for storage backends.
pub struct AccountSession {
    session: WebSession,
    api_base: String,
    created_at: Instant,
}

impl AccountSession {
    /// Wrap a freshly returned [`WebSession`].
    pub fn new(api_base: impl Into<String>, session: WebSession) -> Self {
        Self {
            session,
            api_base: api_base.into(),
            created_at: Instant::now(),
        }
    }

    /// The underlying web session. Handling the return value means handling
    /// the `session_key` secret: never log or persist it in plaintext.
    pub fn session(&self) -> &WebSession {
        &self.session
    }

    /// Consume the wrapper and return the underlying web session.
    pub fn into_session(self) -> WebSession {
        self.session
    }

    /// The API base URL this session was issued against.
    pub fn api_base(&self) -> &str {
        &self.api_base
    }

    /// How long ago this session was created locally.
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// The playit.gg account id from the session token.
    pub fn account_id(&self) -> u64 {
        self.session.auth.account_id
    }

    /// The account status from the session token.
    pub fn account_status(&self) -> AccountStatus {
        self.session.auth.account_status
    }

    /// The TOTP state from the session token.
    pub fn totp_status(&self) -> &TotpStatus {
        &self.session.auth.totp_status
    }

    /// Whether the session reports that a TOTP code must still be submitted.
    ///
    /// No TOTP-submit endpoint exists in the generated client, so a `true`
    /// value currently means direct login cannot proceed further.
    pub fn requires_totp(&self) -> bool {
        matches!(self.session.auth.totp_status, TotpStatus::Required)
    }

    /// Whether the session token is marked read-only.
    pub fn is_read_only(&self) -> bool {
        self.session.auth.read_only
    }

    /// The structured credential for this session.
    pub fn auth_state(&self) -> AuthState {
        AuthState::bearer(self.session.session_key.clone())
    }

    /// Build the authenticated typed API client for this session.
    ///
    /// The client sends `Authorization: Bearer <session_key>` on every call,
    /// which the live API accepts for account operations such as
    /// `/tunnels/list`. Keep the client as scoped as the session itself.
    pub fn account_client(&self) -> PlayitApi {
        PlayitApi::from_bearer(self.api_base.clone(), self.session.session_key.clone())
    }

    /// Validate the session with a harmless read (`POST /tunnels/list`).
    ///
    /// A [`WebApiError::SessionExpired`] outcome means re-authentication is
    /// required; it never implies the agent secret is invalid.
    pub async fn validate(&self) -> Result<(), WebApiError> {
        validate_session(self).await
    }
}

impl std::fmt::Debug for AccountSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountSession")
            .field("account_id", &self.session.auth.account_id)
            .field("account_status", &self.session.auth.account_status)
            .field("totp_status", &self.session.auth.totp_status)
            .field("read_only", &self.session.auth.read_only)
            .field("api_base", &self.api_base)
            .field("age", &self.created_at.elapsed())
            // `session_key` is intentionally never shown.
            .finish_non_exhaustive()
    }
}

/// Sign in with an email + password, returning the account session.
///
/// Credentials travel only in the request body and never appear in the
/// returned value or in error messages.
pub async fn sign_in(
    api_base: &str,
    email: &str,
    password: &str,
) -> Result<AccountSession, SigninError> {
    if email.trim().is_empty() || password.is_empty() {
        return Err(SigninError::EmptyCredentials);
    }
    let api = PlayitApi::create(api_base.to_owned(), None);
    match api
        .login_signin(LoginCredentials {
            email: email.to_owned(),
            password: password.to_owned(),
        })
        .await
    {
        Ok(session) => Ok(AccountSession::new(api_base, session)),
        Err(ApiError::Fail(SigninFail::IncorrectCredentials)) => {
            Err(SigninError::IncorrectCredentials)
        }
        Err(ApiError::Fail(SigninFail::AccountBanned)) => Err(SigninError::AccountBanned),
        Err(ApiError::ApiError(error)) => Err(SigninError::Api(error.to_string())),
        Err(ApiError::ClientError(error)) => Err(SigninError::Transport(error.to_string())),
    }
}

/// A failed email + password sign-in.
#[derive(Debug)]
pub enum SigninError {
    /// The caller passed an empty email or password; no request was sent.
    EmptyCredentials,
    /// The API rejected the credentials.
    IncorrectCredentials,
    /// The account is banned.
    AccountBanned,
    /// The API answered with a structured error.
    Api(String),
    /// The request could not be completed (network, TLS, parse failure).
    Transport(String),
}

impl std::fmt::Display for SigninError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyCredentials => write!(f, "email and password must not be empty"),
            Self::IncorrectCredentials => write!(f, "incorrect email or password"),
            Self::AccountBanned => write!(f, "playit.gg account is banned"),
            Self::Api(error) => write!(f, "playit.gg API error: {error}"),
            Self::Transport(error) => write!(f, "playit.gg request failed: {error}"),
        }
    }
}

impl std::error::Error for SigninError {}

/// A TOTP code submission attempt.
///
/// No TOTP-submit endpoint exists in the generated client yet — only the
/// `TotpStatus` states and the `TotpRequred` auth error variant — so this
/// type models the outcome ahead of the capture work, letting the CLI state
/// machine and the future typed endpoint share one vocabulary. See
/// `docs/auth-flow.md` and `docs/reverse-engineering.md`.
#[derive(Debug)]
pub enum TotpError {
    /// Reserved: kept for API stability, no longer returned now that
    /// `POST /login/totp` is implemented.
    NotSupported,
    /// The code was rejected by the server.
    InvalidCode,
    /// The session is no longer valid; sign in again.
    SessionExpired,
    /// Transport or structured API failure detail (never contains the code).
    Failed(String),
}

impl std::fmt::Display for TotpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotSupported => write!(
                f,
                "TOTP completion is not available in this build; \
                run `playit account login` again"
            ),
            Self::InvalidCode => write!(f, "the TOTP code was rejected"),
            Self::SessionExpired => {
                write!(
                    f,
                    "account session expired; run `playit account login` again"
                )
            }
            Self::Failed(error) => write!(f, "playit.gg request failed: {error}"),
        }
    }
}

impl std::error::Error for TotpError {}

/// A `POST /login/totp` request: the one-time code from the authenticator.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct ReqLoginTotp {
    pub code: String,
}

/// Why `POST /login/totp` rejected the code.
///
/// Fail strings taken from the official web client's error map; the `fail
/// TotpNotSetup` path was replayed live 2026-09-07.
#[derive(
    serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Hash,
)]
pub enum TotpSubmitFail {
    InvalidCode,
    TotpNotSetup,
    #[serde(other)]
    Other,
}

/// Submit a TOTP code for a session reporting `TotpStatus::Required`
/// (`POST /login/totp`).
///
/// The code travels only in the request body and is never logged, stored,
/// or included in the error. On success the returned session replaces the
/// pending one. The `fail` path was replayed live; the `success` path still
/// needs a TOTP-enabled test account to confirm the exact session shape.
pub async fn complete_totp(
    session: &AccountSession,
    code: &str,
) -> Result<AccountSession, TotpError> {
    let caller = Location::caller();
    let outcome: Result<ApiResult<WebSession, TotpSubmitFail>, _> = session
        .account_client()
        .get_client()
        .call(
            caller,
            "/login/totp",
            ReqLoginTotp {
                code: code.to_owned(),
            },
        )
        .await;
    match outcome {
        Err(error) => Err(TotpError::Failed(format!("{error:?}"))),
        Ok(ApiResult::Success(web_session)) => {
            Ok(AccountSession::new(session.api_base(), web_session))
        }
        Ok(ApiResult::Fail(TotpSubmitFail::InvalidCode)) => Err(TotpError::InvalidCode),
        Ok(ApiResult::Fail(other)) => Err(TotpError::Failed(format!("{other:?}"))),
        Ok(ApiResult::Error(api)) => match &api {
            ApiResponseError::Auth(
                ApiAuthError::SessionExpired
                | ApiAuthError::AuthRequired
                | ApiAuthError::NoLongerValid
                | ApiAuthError::InvalidToken,
            ) => Err(TotpError::SessionExpired),
            other => Err(TotpError::Failed(format!("{other:?}"))),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{SignedEpoch, WebAuthToken};
    use std::num::NonZeroU64;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    const SESSION_BODY: &str = concat!(
        r#"{"status":"success","data":{"session_key":"test-session-key","auth":{"#,
        r#""update_version":1,"account_id":123,"timestamp":456,"#,
        r#""account_status":"verified","totp_status":{"status":"not-setup"},"#,
        r#""admin_id":null,"admin_review_id":null,"read_only":false,"show_admin":false}}}"#,
    );
    const INCORRECT_BODY: &str = r#"{"status":"fail","data":"IncorrectCredentials"}"#;

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

    fn test_session(totp_status: TotpStatus) -> AccountSession {
        AccountSession::new(
            "http://127.0.0.1:1",
            WebSession {
                session_key: "super-secret-session-key".into(),
                auth: WebAuthToken {
                    update_version: 1,
                    account_id: 123,
                    timestamp: 456,
                    account_status: AccountStatus::Verified,
                    totp_status,
                    admin_id: None,
                    admin_review_id: NonZeroU64::new(7),
                    read_only: false,
                    show_admin: false,
                },
            },
        )
    }

    #[tokio::test]
    async fn rejects_empty_credentials_without_network() {
        assert!(matches!(
            sign_in("http://127.0.0.1:1", "", "password").await,
            Err(SigninError::EmptyCredentials)
        ));
        assert!(matches!(
            sign_in("http://127.0.0.1:1", "   ", "password").await,
            Err(SigninError::EmptyCredentials)
        ));
        assert!(matches!(
            sign_in("http://127.0.0.1:1", "user@example.com", "").await,
            Err(SigninError::EmptyCredentials)
        ));
    }

    #[tokio::test]
    async fn returns_session_on_success() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (base, task) = spawn_server(vec![SESSION_BODY], seen).await;
        let session = sign_in(&base, "user@example.com", "secret").await.unwrap();
        assert_eq!(session.session().session_key, "test-session-key");
        assert!(matches!(
            session.session().auth.totp_status,
            TotpStatus::NotSetup
        ));
        assert_eq!(session.account_id(), 123);
        assert!(!session.requires_totp());
        task.abort();
    }

    #[tokio::test]
    async fn maps_incorrect_credentials() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (base, task) = spawn_server(vec![INCORRECT_BODY], seen).await;
        let error = sign_in(&base, "user@example.com", "wrong")
            .await
            .unwrap_err();
        assert!(matches!(error, SigninError::IncorrectCredentials));
        task.abort();
    }

    #[tokio::test]
    async fn account_client_sends_bearer_session_key() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (base, task) =
            spawn_server(vec![r#"{"status":"success","data":{}}"#], seen.clone()).await;
        let session = AccountSession::new(
            base,
            WebSession {
                session_key: "test-session-key".into(),
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
        );
        session.account_client().login_clearcookie().await.unwrap();
        assert_eq!(*seen.lock().await, vec!["Bearer test-session-key"]);
        task.abort();
    }

    #[test]
    fn debug_never_exposes_the_session_key() {
        let rendered = format!("{:?}", test_session(TotpStatus::NotSetup));
        assert!(
            !rendered.contains("super-secret-session-key"),
            "Debug must not leak the session key: {rendered}"
        );
        assert!(rendered.contains("123"));
    }

    #[test]
    fn totp_required_is_reported() {
        assert!(!test_session(TotpStatus::NotSetup).requires_totp());
        assert!(test_session(TotpStatus::Required).requires_totp());
        assert!(!test_session(TotpStatus::Signed(SignedEpoch { epoch_sec: 1 })).requires_totp());
    }

    #[tokio::test]
    async fn totp_invalid_code_maps_without_leaking_code() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (base, task) =
            spawn_server(vec![r#"{"status":"fail","data":"InvalidCode"}"#], seen).await;
        let session = AccountSession::new(
            base,
            WebSession {
                session_key: "fixture-pending-credential".to_owned(),
                auth: WebAuthToken {
                    update_version: 1,
                    account_id: 123,
                    timestamp: 456,
                    account_status: AccountStatus::Verified,
                    totp_status: TotpStatus::Required,
                    admin_id: None,
                    admin_review_id: None,
                    read_only: false,
                    show_admin: false,
                },
            },
        );
        let error = complete_totp(&session, "123456").await.unwrap_err();
        assert!(matches!(error, TotpError::InvalidCode));
        assert!(!error.to_string().contains("123456"));
        task.abort();
    }

    #[test]
    fn auth_state_kind_is_log_safe() {
        let session = test_session(TotpStatus::NotSetup);
        assert_eq!(session.auth_state().kind(), "account");
        assert!(AuthPolicy::Account.allows(&session.auth_state()));
        assert!(!AuthPolicy::Agent.allows(&session.auth_state()));
    }

    /// Live verification of sign-in plus an authenticated read.
    ///
    /// Ignored by default and never run in CI. To run with a disposable
    /// test account:
    ///
    /// ```sh
    /// PLAYIT_LIVE_TESTS=1 PLAYIT_TEST_EMAIL=you@example.com \
    ///   PLAYIT_TEST_PASSWORD=... cargo test -p playit-api-client live_signin -- --ignored
    /// ```
    ///
    /// Credentials come from the environment only and are never persisted,
    /// logged, or included in errors.
    #[tokio::test]
    #[ignore = "live test: needs PLAYIT_LIVE_TESTS=1 with test-account credentials"]
    async fn live_signin_and_validate() {
        if std::env::var("PLAYIT_LIVE_TESTS").as_deref() != Ok("1") {
            return;
        }
        let email = std::env::var("PLAYIT_TEST_EMAIL")
            .expect("PLAYIT_TEST_EMAIL must be set for live tests");
        let password = std::env::var("PLAYIT_TEST_PASSWORD")
            .expect("PLAYIT_TEST_PASSWORD must be set for live tests");
        let api_base = std::env::var("PLAYIT_TEST_API_BASE")
            .unwrap_or_else(|_| "https://api.playit.gg".to_string());
        let session = sign_in(&api_base, &email, &password)
            .await
            .expect("live sign-in succeeds");
        assert!(
            !session.requires_totp(),
            "live test account must not require TOTP"
        );
        crate::web_api::validate_session(&session)
            .await
            .expect("live session validates");
    }
}
