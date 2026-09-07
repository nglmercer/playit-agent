use crate::api::PlayitApiClient;
use crate::http_client::{AuthState, HttpClient};

// mod api is auto generated
pub mod api;
pub mod auth;
pub mod http_client;
pub mod ip_resource;
pub mod session;
pub mod web_api;

pub type PlayitApi = PlayitApiClient<HttpClient>;

/// Builder for [`PlayitApi`] with explicit authentication state.
///
/// `PlayitApi::create` remains as a compatibility helper for the
/// agent-key case.
pub struct PlayitApiBuilder {
    api_base: String,
    auth: AuthState,
}

impl PlayitApiBuilder {
    /// Start from an anonymous client for `api_base`.
    pub fn new(api_base: String) -> Self {
        Self {
            api_base,
            auth: AuthState::Anonymous,
        }
    }

    /// Use an explicit [`AuthState`].
    pub fn auth(mut self, auth: AuthState) -> Self {
        self.auth = auth;
        self
    }

    /// Authenticate with an agent secret (`Authorization: Agent-Key ...`).
    pub fn agent_key(mut self, secret: impl Into<String>) -> Self {
        self.auth = AuthState::agent_key(secret);
        self
    }

    /// Authenticate with an account session key (`Authorization: Bearer ...`).
    pub fn bearer(mut self, token: impl Into<String>) -> Self {
        self.auth = AuthState::bearer(token);
        self
    }

    /// Build the typed client.
    pub fn build(self) -> PlayitApi {
        PlayitApiClient::new(HttpClient::new_with_auth(self.api_base, self.auth))
    }
}

impl PlayitApi {
    pub fn create(api_base: String, secret: Option<String>) -> Self {
        match secret {
            Some(secret) => PlayitApiBuilder::new(api_base).agent_key(secret).build(),
            None => PlayitApiBuilder::new(api_base).build(),
        }
    }

    /// An account-authenticated client for a session key from direct login.
    pub fn from_bearer(api_base: String, token: impl Into<String>) -> Self {
        PlayitApiBuilder::new(api_base).bearer(token).build()
    }
}

impl api::PortType {
    pub fn matches(&self, port: api::PortType) -> bool {
        match *self {
            api::PortType::Both => true,
            other => other == port,
        }
    }
}

impl api::PortRange {
    pub fn contains(&self, port: u16) -> bool {
        self.from <= port && port < self.to
    }
}
