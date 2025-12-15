use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageFrame {
    pub conversation_id: String,
    pub message_id: Uuid,
    pub kind: String,
    pub ciphertext: Vec<u8>,
    pub associated_data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentChunk {
    pub attachment_id: Uuid,
    pub sequence: u64,
    pub is_last: bool,
    pub bytes: Vec<u8>,
    pub content_type: String,
    pub filename: Option<String>,
    pub total_size: u64,
}

#[derive(Debug, Error)]
pub enum PacketError {
    #[error("invalid chunk size")]
    InvalidChunk,
}

pub fn chunk_attachment(
    attachment_id: Uuid,
    data: &[u8],
    content_type: String,
    filename: Option<String>,
    chunk_size: usize,
) -> Result<Vec<AttachmentChunk>, PacketError> {
    if chunk_size == 0 {
        return Err(PacketError::InvalidChunk);
    }
    let mut chunks = Vec::new();
    let mut offset: usize = 0;
    let total_size = data.len() as u64;
    let mut sequence: u64 = 0;
    while offset < data.len() {
        let end = usize::min(offset + chunk_size, data.len());
        let slice = data[offset..end].to_vec();
        offset = end;
        sequence += 1;
        let is_last = offset >= data.len();
        chunks.push(AttachmentChunk {
            attachment_id,
            sequence,
            is_last,
            bytes: slice,
            content_type: content_type.clone(),
            filename: filename.clone(),
            total_size,
        });
    }
    if chunks.is_empty() {
        chunks.push(AttachmentChunk {
            attachment_id,
            sequence: 1,
            is_last: true,
            bytes: Vec::new(),
            content_type,
            filename,
            total_size,
        });
    }
    Ok(chunks)
}

pub fn reassemble_attachment(chunks: &[AttachmentChunk]) -> Option<Vec<u8>> {
    if chunks.is_empty() {
        return Some(Vec::new());
    }
    let mut ordered = chunks.to_vec();
    ordered.sort_by_key(|c| c.sequence);
    let mut data = Vec::new();
    for chunk in ordered.iter() {
        data.extend_from_slice(&chunk.bytes);
    }
    Some(data)
}
