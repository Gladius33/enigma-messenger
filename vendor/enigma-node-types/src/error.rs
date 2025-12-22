use thiserror::Error;

#[derive(Debug, Error)]
pub enum EnigmaNodeTypesError {
    #[error("invalid username")]
    InvalidUsername,
    #[error("invalid hex input")]
    InvalidHex,
    #[error("invalid base64 input")]
    InvalidBase64,
    #[error("invalid field: {0}")]
    InvalidField(&'static str),
    #[error("json error")]
    JsonError,
    #[error("utf8 error")]
    Utf8Error,
}

pub type Result<T> = std::result::Result<T, EnigmaNodeTypesError>;

impl From<serde_json::Error> for EnigmaNodeTypesError {
    fn from(_: serde_json::Error) -> Self {
        EnigmaNodeTypesError::JsonError
    }
}

impl From<std::str::Utf8Error> for EnigmaNodeTypesError {
    fn from(_: std::str::Utf8Error) -> Self {
        EnigmaNodeTypesError::Utf8Error
    }
}

impl From<base64::DecodeError> for EnigmaNodeTypesError {
    fn from(_: base64::DecodeError) -> Self {
        EnigmaNodeTypesError::InvalidBase64
    }
}

impl From<hex::FromHexError> for EnigmaNodeTypesError {
    fn from(_: hex::FromHexError) -> Self {
        EnigmaNodeTypesError::InvalidHex
    }
}
