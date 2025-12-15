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
}
