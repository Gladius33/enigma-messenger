use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub max_text_bytes: usize,
    pub max_message_rate_per_minute: u32,
    pub max_inline_media_bytes: usize,
    pub max_attachment_chunk_bytes: usize,
    pub max_attachment_parallel_chunks: usize,
    pub max_group_name_len: usize,
    pub max_channel_name_len: usize,
    pub max_membership_changes_per_minute: u32,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            max_text_bytes: 256 * 1024,
            max_message_rate_per_minute: 600,
            max_inline_media_bytes: 64 * 1024 * 1024,
            max_attachment_chunk_bytes: 1 * 1024 * 1024,
            max_attachment_parallel_chunks: 4,
            max_group_name_len: 64,
            max_channel_name_len: 64,
            max_membership_changes_per_minute: 120,
        }
    }
}
