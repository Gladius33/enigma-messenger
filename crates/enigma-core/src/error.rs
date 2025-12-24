use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("storage")]
    Storage,
    #[error("validation {0}")]
    Validation(String),
    #[error("transport {0}")]
    Transport(String),
    #[error("relay {0}")]
    Relay(String),
    #[error("crypto")]
    Crypto,
    #[error("not found")]
    NotFound,
    #[error("{0}")]
    External(#[from] ExternalError),
}

#[derive(Debug, Clone, Error)]
#[error("{code}: {message}")]
pub struct ExternalError {
    pub code: String,
    pub message: String,
    pub details: Option<Value>,
    pub retryable: bool,
}

impl ExternalError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        ExternalError {
            code: code.into(),
            message: message.into(),
            details: None,
            retryable: false,
        }
    }

    pub fn with_retryable(mut self, retryable: bool) -> Self {
        self.retryable = retryable;
        self
    }

    pub fn with_details(mut self, details: Option<Value>) -> Self {
        self.details = details;
        self
    }
}
