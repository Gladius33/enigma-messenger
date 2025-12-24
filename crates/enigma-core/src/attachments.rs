use crate::error::CoreError;
use crate::policy::Policy;
use enigma_api::types::AttachmentDescriptor;
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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

pub fn prepare_chunks(
    descriptor: &AttachmentDescriptor,
    bytes: &[u8],
    policy: &Policy,
) -> Result<Vec<AttachmentChunk>, CoreError> {
    let size = usize::max(1, policy.max_attachment_chunk_bytes);
    chunk_attachment(
        descriptor.id.value,
        bytes,
        descriptor.content_type.clone(),
        descriptor.filename.clone(),
        size,
    )
    .ok_or(CoreError::Crypto)
}

pub struct AttachmentAssembler {
    pending: HashMap<Uuid, Vec<AttachmentChunk>>,
}

impl AttachmentAssembler {
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
        }
    }

    pub fn ingest(&mut self, chunk: AttachmentChunk) -> Option<Vec<u8>> {
        let entry = self.pending.entry(chunk.attachment_id).or_default();
        entry.push(chunk.clone());
        if entry.iter().any(|c| c.is_last) {
            if let Some(data) = reassemble_attachment(entry) {
                self.pending.remove(&chunk.attachment_id);
                return Some(data);
            }
            None
        } else {
            None
        }
    }
}

fn chunk_attachment(
    attachment_id: Uuid,
    data: &[u8],
    content_type: String,
    filename: Option<String>,
    chunk_size: usize,
) -> Option<Vec<AttachmentChunk>> {
    if chunk_size == 0 {
        return None;
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
    Some(chunks)
}

fn reassemble_attachment(chunks: &[AttachmentChunk]) -> Option<Vec<u8>> {
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

impl Default for AttachmentAssembler {
    fn default() -> Self {
        Self::new()
    }
}
