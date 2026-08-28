use serde_json::Value;
use thiserror::Error;

use playit_ipc::model::{ServiceError, ServiceErrorCode};

/// Errors returned by direct runtime operations.
///
/// The error contains a semantic service code so an IPC adapter can preserve
/// the existing wire-level error response without making direct callers deal
/// with transport errors.
#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("secret error: {message}")]
    Secret {
        code: ServiceErrorCode,
        message: String,
        retryable: bool,
        details: Option<Value>,
    },

    #[error("runtime setup error: {message}")]
    Setup {
        code: ServiceErrorCode,
        message: String,
        retryable: bool,
        details: Option<Value>,
    },

    #[error("Playit API error: {message}")]
    Api {
        code: ServiceErrorCode,
        message: String,
        retryable: bool,
        details: Option<Value>,
    },

    #[error("invalid runtime state: {message}")]
    InvalidState {
        code: ServiceErrorCode,
        message: String,
        retryable: bool,
        details: Option<Value>,
    },

    #[error("runtime I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("the Playit runtime has stopped")]
    Stopped,
}

impl RuntimeError {
    pub(crate) fn secret(
        code: ServiceErrorCode,
        message: impl Into<String>,
        retryable: bool,
    ) -> Self {
        Self::Secret {
            code,
            message: message.into(),
            retryable,
            details: None,
        }
    }

    pub(crate) fn setup(message: impl Into<String>, retryable: bool) -> Self {
        Self::setup_with_code(ServiceErrorCode::Internal, message, retryable)
    }

    pub(crate) fn setup_with_code(
        code: ServiceErrorCode,
        message: impl Into<String>,
        retryable: bool,
    ) -> Self {
        Self::Setup {
            code,
            message: message.into(),
            retryable,
            details: None,
        }
    }

    pub(crate) fn api(code: ServiceErrorCode, message: impl Into<String>, retryable: bool) -> Self {
        Self::Api {
            code,
            message: message.into(),
            retryable,
            details: None,
        }
    }

    pub(crate) fn invalid(
        code: ServiceErrorCode,
        message: impl Into<String>,
        retryable: bool,
    ) -> Self {
        Self::InvalidState {
            code,
            message: message.into(),
            retryable,
            details: None,
        }
    }

    pub(crate) fn stopped() -> Self {
        Self::Stopped
    }

    /// Convert the semantic runtime error to the existing IPC error model.
    pub fn as_service_error(&self) -> ServiceError {
        match self {
            Self::Secret {
                code,
                message,
                retryable,
                details,
            }
            | Self::Setup {
                code,
                message,
                retryable,
                details,
            }
            | Self::Api {
                code,
                message,
                retryable,
                details,
            }
            | Self::InvalidState {
                code,
                message,
                retryable,
                details,
            } => ServiceError {
                code: code.clone(),
                message: message.clone(),
                retryable: *retryable,
                details: details.clone(),
            },
            Self::Io(error) => ServiceError {
                code: ServiceErrorCode::Internal,
                message: error.to_string(),
                retryable: true,
                details: None,
            },
            Self::Stopped => ServiceError {
                code: ServiceErrorCode::ApiUnavailable,
                message: "The Playit runtime has stopped.".to_string(),
                retryable: true,
                details: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RuntimeError;
    use playit_ipc::model::ServiceErrorCode;

    #[test]
    fn setup_errors_can_preserve_specific_wire_codes() {
        let error = RuntimeError::setup_with_code(
            ServiceErrorCode::AgentDisabledOverLimit,
            "over limit",
            true,
        );

        assert!(matches!(
            error.as_service_error().code,
            ServiceErrorCode::AgentDisabledOverLimit
        ));
    }
}
