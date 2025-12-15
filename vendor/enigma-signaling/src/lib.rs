use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalMessage {
    pub from: String,
    pub to: String,
    pub payload: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum SignalingError {
    #[error("unavailable")] 
    Unavailable,
}
