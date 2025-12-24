use super::{base_config, key_provider, recipient_user, temp_path};
use crate::config::TransportMode;
use crate::directory::InMemoryRegistry;
use crate::error::CoreError;
use crate::messaging::MockTransport;
use crate::policy::Policy;
use crate::relay::{InMemoryRelay, RelayAck, RelayAckResponse, RelayClient, RelayPullResult};
use crate::Core;
use async_trait::async_trait;
use enigma_api::types::{
    ConversationId, MessageId, MessageKind, OutgoingMessageRequest, UserIdHex,
};
use enigma_node_types::RelayEnvelope;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};

#[derive(Clone)]
struct FlakyRelay {
    inner: Arc<InMemoryRelay>,
    fail_push: Arc<Mutex<usize>>,
}

impl FlakyRelay {
    fn new(fail_push: usize) -> Self {
        Self {
            inner: Arc::new(InMemoryRelay::new()),
            fail_push: Arc::new(Mutex::new(fail_push)),
        }
    }
}

#[async_trait]
impl RelayClient for FlakyRelay {
    async fn push(&self, envelope: RelayEnvelope) -> Result<(), CoreError> {
        let mut guard = self.fail_push.lock().await;
        if *guard > 0 {
            *guard -= 1;
            return Err(CoreError::Relay("push".to_string()));
        }
        drop(guard);
        self.inner.push(envelope).await
    }

    async fn pull(
        &self,
        recipient: &str,
        cursor: Option<String>,
    ) -> Result<RelayPullResult, CoreError> {
        self.inner.pull(recipient, cursor).await
    }

    async fn ack(&self, recipient: &str, ack: &[RelayAck]) -> Result<RelayAckResponse, CoreError> {
        self.inner.ack(recipient, ack).await
    }
}

#[tokio::test]
async fn outbox_retries_after_relay_failure() {
    let transport = MockTransport::new();
    let registry = Arc::new(InMemoryRegistry::new());
    let relay = Arc::new(FlakyRelay::new(1));

    let policy = Policy {
        backoff_initial_ms: 10,
        backoff_max_ms: 50,
        outbox_batch_send: 4,
        ..Policy::default()
    };

    let core_a = Core::init(
        base_config(temp_path("outbox-retry-a"), TransportMode::RelayOnly),
        policy.clone(),
        key_provider(),
        registry.clone(),
        relay.clone(),
        Arc::new(transport.clone()),
    )
    .await
    .expect("core a");

    let core_b = Core::init(
        base_config(temp_path("outbox-retry-b"), TransportMode::RelayOnly),
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
        text: Some("retry".to_string()),
        attachment: None,
        attachment_bytes: None,
        ephemeral_expiry_secs: None,
        metadata: None,
    };

    core_a.send_message(req).await.expect("send");

    sleep(Duration::from_millis(700)).await;
    core_b.poll_once().await.expect("poll");

    let event = rx_b.recv().await.expect("event");
    assert_eq!(event.text.as_deref(), Some("retry"));

    let pending = core_a
        .outbox
        .load_all_due(crate::time::now_ms(), 8)
        .await
        .expect("outbox");

    assert!(pending.is_empty());
}
