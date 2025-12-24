use super::{base_config, key_provider, recipient_user, temp_path};
use crate::config::TransportMode;
use crate::directory::InMemoryRegistry;
use crate::error::CoreError;
use crate::messaging::MockTransport;
use crate::policy::Policy;
use crate::relay::{RelayAck, RelayAckResponse, RelayClient, RelayPullItem, RelayPullResult};
use crate::Core;
use async_trait::async_trait;
use enigma_api::types::{
    ConversationId, MessageId, MessageKind, OutgoingMessageRequest, UserIdHex,
};
use enigma_node_types::RelayEnvelope;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone, Default)]
struct TrackingRelay {
    entries: Arc<Mutex<Vec<RelayPullItem>>>,
    acked: Arc<Mutex<Vec<RelayAck>>>,
}

impl TrackingRelay {
    async fn acked(&self) -> Vec<RelayAck> {
        self.acked.lock().await.clone()
    }

    async fn entries_for(&self, recipient: &str) -> Vec<RelayPullItem> {
        self.entries
            .lock()
            .await
            .iter()
            .filter(|env| env.envelope.to.to_hex() == recipient)
            .cloned()
            .collect()
    }
}

#[async_trait]
impl RelayClient for TrackingRelay {
    async fn push(&self, envelope: RelayEnvelope) -> Result<(), CoreError> {
        let chunk_index = match &envelope.kind {
            enigma_node_types::RelayKind::OpaqueAttachmentChunk(chunk) => chunk.index,
            _ => 0,
        };
        self.entries.lock().await.push(RelayPullItem {
            envelope,
            chunk_index,
        });
        Ok(())
    }

    async fn pull(
        &self,
        recipient: &str,
        _cursor: Option<String>,
    ) -> Result<RelayPullResult, CoreError> {
        Ok(RelayPullResult {
            items: self.entries_for(recipient).await,
            cursor: None,
        })
    }

    async fn ack(&self, recipient: &str, ack: &[RelayAck]) -> Result<RelayAckResponse, CoreError> {
        let mut acked = self.acked.lock().await;
        acked.extend_from_slice(ack);
        drop(acked);
        let mut guard = self.entries.lock().await;
        let before = guard.len() as u64;
        guard.retain(|env| {
            if env.envelope.to.to_hex() != recipient {
                return true;
            }
            !ack.iter().any(|entry| {
                entry.message_id == env.envelope.id && entry.chunk_index == env.chunk_index
            })
        });
        let deleted = before.saturating_sub(guard.len() as u64);
        Ok(RelayAckResponse {
            deleted,
            missing: ack.len().saturating_sub(deleted as usize) as u64,
            remaining: guard.len() as u64,
        })
    }
}

#[tokio::test]
async fn relay_ack_waits_for_persistence() {
    let relay = Arc::new(TrackingRelay::default());
    let registry = Arc::new(InMemoryRegistry::new());
    let transport = MockTransport::new();
    let policy = Policy::default();
    let core_a = Core::init(
        base_config(temp_path("ack-a"), TransportMode::RelayOnly),
        policy.clone(),
        key_provider(),
        registry.clone(),
        relay.clone(),
        Arc::new(transport.clone()),
    )
    .await
    .expect("core a");
    let core_b = Core::init(
        base_config(temp_path("ack-b"), TransportMode::RelayOnly),
        policy,
        key_provider(),
        registry,
        relay.clone(),
        Arc::new(transport.clone()),
    )
    .await
    .expect("core b");
    let conv = core_a.dm_conversation(&core_b.local_identity().user_id);
    let mut rx_b = core_b.subscribe();
    let req = OutgoingMessageRequest {
        client_message_id: MessageId::random(),
        conversation_id: ConversationId {
            value: conv.value.clone(),
        },
        sender: UserIdHex {
            value: core_a.local_identity().user_id.to_hex(),
        },
        recipients: vec![recipient_user(&core_b.local_identity().user_id.to_hex())],
        kind: MessageKind::Text,
        text: Some("persist".to_string()),
        attachment: None,
        attachment_bytes: None,
        ephemeral_expiry_secs: None,
        metadata: None,
    };
    core_b.persist_fail.store(true, Ordering::SeqCst);
    core_a.send_message(req).await.expect("send");
    core_b.poll_once().await.expect("poll");
    assert!(rx_b.try_recv().is_err());
    let acked = relay.acked().await;
    assert!(acked.is_empty());
    let remaining = relay
        .entries_for(&core_b.local_identity().user_id.to_hex())
        .await;
    assert!(!remaining.is_empty());
}
