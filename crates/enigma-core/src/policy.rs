use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub enum GroupCryptoMode {
    Fanout,
    SenderKeys,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub enum ReceiptAggregation {
    Any,
    All,
}

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
    pub max_retry_window_secs: u64,
    pub backoff_initial_ms: u64,
    pub backoff_max_ms: u64,
    pub outbox_batch_send: usize,
    pub directory_ttl_secs: u64,
    pub directory_refresh_on_send: bool,
    pub receipt_aggregation: ReceiptAggregation,
    pub group_crypto_mode: GroupCryptoMode,
    pub sender_keys_rotate_every_msgs: u32,
    pub sender_keys_rotate_on_membership_change: bool,
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
            max_retry_window_secs: 3600,
            backoff_initial_ms: 500,
            backoff_max_ms: 60000,
            outbox_batch_send: 32,
            directory_ttl_secs: 3600,
            directory_refresh_on_send: true,
            receipt_aggregation: ReceiptAggregation::Any,
            group_crypto_mode: GroupCryptoMode::Fanout,
            sender_keys_rotate_every_msgs: 1000,
            sender_keys_rotate_on_membership_change: true,
        }
    }
}
