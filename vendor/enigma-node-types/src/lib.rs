use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicIdentity {
    pub user_id: String,
    pub device_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeRecord {
    pub base_url: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum EnvelopePayload {
    Message(Vec<u8>),
    AttachmentChunk(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayEnvelope {
    pub id: Uuid,
    pub recipient: String,
    pub payload: EnvelopePayload,
}

impl RelayEnvelope {
    pub fn new(recipient: String, payload: EnvelopePayload) -> Self {
        Self {
            id: Uuid::new_v4(),
            recipient,
            payload,
        }
    }
}
