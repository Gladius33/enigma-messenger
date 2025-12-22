use super::{base_config, key_provider, temp_path};
use crate::config::TransportMode;
use crate::directory::InMemoryRegistry;
use crate::error::CoreError;
use crate::messaging::MockTransport;
use crate::policy::Policy;
use crate::relay::RelayClient;
use crate::Core;
use async_trait::async_trait;
use enigma_api::types::{
    ConversationId, MessageId, MessageKind, OutgoingMessageRequest, UserIdHex,
};
use enigma_node_types::RelayEnvelope;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Clone, Default)]
struct TrackingRelay {
    entries: Arc<Mutex<Vec<RelayEnvelope>>>,
    acked: Arc<Mutex<Vec<Uuid>>>,
}

impl TrackingRelay {
    async fn acked(&self) -> Vec<Uuid> {
        self.acked.lock().await.clone()
    }

    async fn entries_for(&self, recipient: &str) -> Vec<RelayEnvelope> {
        self.entries
            .lock()
            .await
            .iter()
            .filter(|env| env.to.to_hex() == recipient)
            .cloned()
            .collect()
    }
}

#[async_trait]
impl RelayClient for TrackingRelay {
    async fn push(&self, envelope: RelayEnvelope) -> Result<(), CoreError> {
        self.entries.lock().await.push(envelope);
        Ok(())
    }

    async fn pull(&self, recipient: &str) -> Result<Vec<RelayEnvelope>, CoreError> {
        Ok(self.entries_for(recipient).await)
    }

    async fn ack(&self, recipient: &str, ids: &[Uuid]) -> Result<(), CoreError> {
        let mut acked = self.acked.lock().await;
        acked.extend_from_slice(ids);
        drop(acked);
        let mut guard = self.entries.lock().await;
        guard.retain(|env| env.to.to_hex() != recipient || !ids.contains(&env.id));
        Ok(())
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
        recipients: vec![UserIdHex {
            value: core_b.local_identity().user_id.to_hex(),
        }],
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
