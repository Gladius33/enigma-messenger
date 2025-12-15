use crate::error::CoreError;
use crate::policy::Policy;
use enigma_api::types::AttachmentDescriptor;
use enigma_packet::{chunk_attachment, reassemble_attachment, AttachmentChunk};
use std::collections::HashMap;
use uuid::Uuid;

pub fn prepare_chunks(
    descriptor: &AttachmentDescriptor,
    bytes: &[u8],
    policy: &Policy,
) -> Result<Vec<AttachmentChunk>, CoreError> {
    let size = if policy.max_attachment_chunk_bytes == 0 {
        1
    } else {
        policy.max_attachment_chunk_bytes
    };
    chunk_attachment(
        descriptor.id.value,
        bytes,
        descriptor.content_type.clone(),
        descriptor.filename.clone(),
        size,
    )
    .map_err(|_| CoreError::Crypto)
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
        let entry = self.pending.entry(chunk.attachment_id).or_insert_with(Vec::new);
        entry.push(chunk.clone());
        if entry.iter().any(|c| c.is_last) {
            let data = reassemble_attachment(entry)?;
            self.pending.remove(&chunk.attachment_id);
            Some(data)
        } else {
            None
        }
    }
}
