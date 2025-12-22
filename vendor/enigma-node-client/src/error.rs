use thiserror::Error;

pub type Result<T> = std::result::Result<T, EnigmaNodeClientError>;

#[derive(Debug, Error)]
pub enum EnigmaNodeClientError {
    #[error("invalid base url")]
    InvalidBaseUrl,
    #[error("invalid user id hex")]
    InvalidUserIdHex,
    #[error("http error")]
    Http(#[from] reqwest::Error),
    #[error("unexpected status {0}")]
    Status(u16),
    #[error("json error")]
    Json(#[from] serde_json::Error),
    #[error("response too large")]
    ResponseTooLarge,
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),
}
