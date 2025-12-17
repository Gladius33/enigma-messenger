use crate::error::CoreError;
use enigma_aead::AeadKey;
use enigma_api::types::{AttachmentDescriptor, MessageKind};
use enigma_packet::{AttachmentChunk, MessageFrame};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlainMessage {
    pub conversation_id: String,
    pub message_id: Uuid,
    pub sender: String,
    pub kind: MessageKind,
    pub text: Option<String>,
    pub attachment: Option<AttachmentDescriptor>,
    pub timestamp: u64,
    pub edited: bool,
    pub deleted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum WireEnvelope {
    Message(MessageFrame),
    Attachment(AttachmentChunk),
}

pub fn build_frame(message: PlainMessage, key: &AeadKey) -> Result<MessageFrame, CoreError> {
    let associated = format!(
        "{}:{}:{}",
        message.conversation_id, message.message_id, message.sender
    );
    let plaintext = serde_json::to_vec(&message).map_err(|_| CoreError::Crypto)?;
    let ciphertext = key.seal(&plaintext, associated.as_bytes());
    Ok(MessageFrame {
        conversation_id: message.conversation_id,
        message_id: message.message_id,
        kind: format_kind(&message.kind),
        ciphertext,
        associated_data: associated.as_bytes().to_vec(),
    })
}

pub fn decode_frame(frame: &MessageFrame, key: &AeadKey) -> Result<PlainMessage, CoreError> {
    let plaintext = key
        .open(&frame.ciphertext, frame.associated_data.len())
        .map_err(|_| CoreError::Crypto)?;
    serde_json::from_slice(&plaintext).map_err(|_| CoreError::Crypto)
}

pub fn serialize_envelope(envelope: &WireEnvelope) -> Result<Vec<u8>, CoreError> {
    serde_json::to_vec(envelope).map_err(|_| CoreError::Crypto)
}

pub fn deserialize_envelope(bytes: &[u8]) -> Result<WireEnvelope, CoreError> {
    serde_json::from_slice(bytes).map_err(|_| CoreError::Crypto)
}

fn format_kind(kind: &MessageKind) -> String {
    match kind {
        MessageKind::Text => "Text",
        MessageKind::File => "File",
        MessageKind::Image => "Image",
        MessageKind::Video => "Video",
        MessageKind::Voice => "Voice",
        MessageKind::System => "System",
        MessageKind::CallSignal => "CallSignal",
        MessageKind::ChannelPost => "ChannelPost",
        MessageKind::GroupEvent => "GroupEvent",
    }
    .to_string()
}
