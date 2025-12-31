pub mod attachments_tests;
pub mod directory_tests;
pub mod envelope_tests;
pub mod groups_channels_tests;
pub mod hybrid_fallback_tests;
pub mod identity_tests;
pub mod identity_v2_tests;
#[cfg(feature = "dev")]
pub mod introspection_tests;
pub mod messaging_tests;
pub mod multidevice_tests;
pub mod negative_tests;
pub mod offline_relay_tests;
pub mod outbox_retry_tests;
pub mod relay_ack_persistence_tests;
#[cfg(feature = "sender-keys")]
pub mod sender_keys_tests;
pub mod transport_unit_tests;

use crate::config::{CoreConfig, TransportMode};
use enigma_api::types::OutgoingRecipient;
use enigma_storage::key_provider::{KeyProvider, MasterKey};
use enigma_storage::EnigmaStorageError;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub struct TestKeyProvider;

impl KeyProvider for TestKeyProvider {
    fn get_or_create_master_key(&self) -> Result<MasterKey, EnigmaStorageError> {
        Ok(MasterKey::new([7u8; 32]))
    }

    fn get_master_key(&self) -> Result<MasterKey, EnigmaStorageError> {
        Ok(MasterKey::new([7u8; 32]))
    }
}

pub fn temp_path(label: &str) -> String {
    format!("/tmp/{}-{}", label, Uuid::new_v4())
}

pub fn base_config(path: String, mode: TransportMode) -> CoreConfig {
    CoreConfig {
        storage_path: path,
        namespace: "test".to_string(),
        user_handle: format!("user-{}", Uuid::new_v4()),
        node_base_urls: Vec::new(),
        relay_base_urls: Vec::new(),
        device_name: None,
        enable_read_receipts: true,
        enable_typing: true,
        enable_ephemeral: true,
        default_ephemeral_secs: None,
        allow_attachments: true,
        transport_mode: mode,
        polling_interval_ms: 50,
    }
}

pub fn key_provider() -> Arc<TestKeyProvider> {
    Arc::new(TestKeyProvider)
}

pub fn recipient_user(user: &str) -> OutgoingRecipient {
    OutgoingRecipient {
        recipient_user_id: Some(user.to_string()),
        recipient_handle: None,
    }
}

pub fn recipient_handle(handle: &str) -> OutgoingRecipient {
    OutgoingRecipient {
        recipient_user_id: None,
        recipient_handle: Some(handle.to_string()),
    }
}
