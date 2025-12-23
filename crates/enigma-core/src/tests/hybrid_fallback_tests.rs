use super::{base_config, key_provider, recipient_user, temp_path};
use crate::config::TransportMode;
use crate::directory::InMemoryRegistry;
use crate::messaging::MockTransport;
use crate::policy::Policy;
use crate::relay::{InMemoryRelay, RelayClient};
use crate::Core;
use enigma_api::types::{
    ConversationId, MessageId, MessageKind, OutgoingMessageRequest, UserIdHex,
};
use std::sync::Arc;

#[tokio::test]
async fn hybrid_falls_back_to_relay_when_p2p_fails() {
    let transport = MockTransport::new();
    transport.fail_p2p_times(1).await;
    let relay = Arc::new(InMemoryRelay::new());
    let registry = Arc::new(InMemoryRegistry::new());
    let policy = Policy::default();
    let core_a = Core::init(
        base_config(temp_path("hybrid-a"), TransportMode::Hybrid),
        policy.clone(),
        key_provider(),
        registry.clone(),
        relay.clone(),
        Arc::new(transport.clone()),
    )
    .await
    .expect("core a");
    let core_b = Core::init(
        base_config(temp_path("hybrid-b"), TransportMode::Hybrid),
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
        text: Some("fallback".to_string()),
        attachment: None,
        attachment_bytes: None,
        ephemeral_expiry_secs: None,
        metadata: None,
    };
    core_a.send_message(req).await.expect("send");
    let relay_entries = relay
        .pull(&core_b.local_identity().user_id.to_hex(), None)
        .await
        .expect("pull");
    assert!(!relay_entries.envelopes.is_empty());
    core_b.poll_once().await.expect("poll");
    let event = rx_b.recv().await.expect("event");
    assert_eq!(event.text.as_deref(), Some("fallback"));
    let remaining = relay
        .pull(&core_b.local_identity().user_id.to_hex(), None)
        .await
        .expect("pull again");
    assert!(remaining.envelopes.is_empty());
    let pending = core_a
        .outbox
        .load_all_due(crate::time::now_ms(), 4)
        .await
        .expect("outbox");
    assert!(pending.is_empty());
}
