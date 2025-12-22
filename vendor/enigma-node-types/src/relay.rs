use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{EnigmaNodeTypesError, Result};
use crate::user_id::UserId;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RelayEnvelope {
    pub id: Uuid,
    pub to: UserId,
    pub from: Option<UserId>,
    pub created_at_ms: u64,
    pub expires_at_ms: Option<u64>,
    pub kind: RelayKind,
}

impl RelayEnvelope {
    pub fn validate(&self) -> Result<()> {
        if self.created_at_ms == 0 {
            return Err(EnigmaNodeTypesError::InvalidField("created_at_ms"));
        }
        if let Some(expires) = self.expires_at_ms {
            if expires <= self.created_at_ms {
                return Err(EnigmaNodeTypesError::InvalidField("expires_at_ms"));
            }
        }
        match &self.kind {
            RelayKind::OpaqueMessage(message) => {
                validate_blob(&message.blob_b64)?;
                if let Some(ct) = &message.content_type {
                    if ct.len() > 128 {
                        return Err(EnigmaNodeTypesError::InvalidField("content_type"));
                    }
                }
            }
            RelayKind::OpaqueSignaling(signaling) => {
                validate_blob(&signaling.blob_b64)?;
            }
            RelayKind::OpaqueAttachmentChunk(chunk) => {
                validate_blob(&chunk.blob_b64)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RelayKind {
    OpaqueMessage(OpaqueMessage),
    OpaqueSignaling(OpaqueSignaling),
    OpaqueAttachmentChunk(OpaqueAttachmentChunk),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OpaqueMessage {
    pub blob_b64: String,
    pub content_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OpaqueSignaling {
    pub blob_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OpaqueAttachmentChunk {
    pub blob_b64: String,
    pub attachment_id: Uuid,
    pub index: u32,
    pub total: Option<u32>,
}

fn validate_blob(blob_b64: &str) -> Result<()> {
    let decoded = STANDARD.decode(blob_b64.as_bytes())?;
    if decoded.is_empty() {
        return Err(EnigmaNodeTypesError::InvalidBase64);
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RelayPushRequest {
    pub envelopes: Vec<RelayEnvelope>,
}

impl RelayPushRequest {
    pub fn validate(&self) -> Result<()> {
        for envelope in &self.envelopes {
            envelope.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RelayPushResponse {
    pub accepted: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RelayPullResponse {
    pub envelopes: Vec<RelayEnvelope>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RelayAckRequest {
    pub ids: Vec<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RelayAckResponse {
    pub removed: usize,
}
