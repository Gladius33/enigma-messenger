use crate::attachments::{prepare_chunks, AttachmentAssembler};
use crate::policy::Policy;
use enigma_api::types::{AttachmentDescriptor, AttachmentId};

#[test]
fn chunking_reassembles_large_payloads() {
    let policy = Policy::default();
    let descriptor = AttachmentDescriptor {
        id: AttachmentId::random(),
        filename: Some("file.bin".to_string()),
        content_type: "application/octet-stream".to_string(),
        total_size: 3 * policy.max_attachment_chunk_bytes as u64 + 10,
    };
    let data: Vec<u8> = (0..(descriptor.total_size as usize)).map(|i| (i % 255) as u8).collect();
    let chunks = prepare_chunks(&descriptor, &data, &policy).expect("chunks");
    let mut assembler = AttachmentAssembler::new();
    let mut last = None;
    for chunk in chunks.into_iter() {
        last = assembler.ingest(chunk);
    }
    let rebuilt = last.expect("assembled");
    assert_eq!(rebuilt.len(), data.len());
    assert_eq!(rebuilt, data);
}
