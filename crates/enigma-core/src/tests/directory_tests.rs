use super::{base_config, key_provider, temp_path};
use crate::config::TransportMode;
use crate::directory::InMemoryRegistry;
use crate::error::CoreError;
use crate::messaging::MockTransport;
use crate::node::DirectoryResolver;
use crate::policy::Policy;
use crate::relay::InMemoryRelay;
use crate::time::now_ms;
use crate::Core;
use async_trait::async_trait;
use enigma_api::types::{
    ConversationId, MessageId, MessageKind, OutgoingMessageRequest, OutgoingRecipient, UserIdHex,
};
use enigma_node_types::{PublicIdentity, UserId as NodeUserId};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone, Default)]
struct MockDirectoryResolver {
    calls: Arc<Mutex<usize>>,
}

impl MockDirectoryResolver {
    fn new() -> Self {
        Self::default()
    }

    async fn count(&self) -> usize {
        *self.calls.lock().await
    }
}

#[async_trait]
impl DirectoryResolver for MockDirectoryResolver {
    async fn resolve_handle(&self, handle: &str) -> Result<(String, PublicIdentity), CoreError> {
        let mut guard = self.calls.lock().await;
        *guard += 1;
        drop(guard);
        let username = handle.trim().trim_start_matches('@');
        let user_id = NodeUserId::from_username(username)
            .map_err(|_| CoreError::Validation("handle".to_string()))?;
        let identity = PublicIdentity {
            user_id,
            username_hint: Some(username.to_string()),
            signing_public_key: vec![1],
            encryption_public_key: vec![1],
            signature: vec![1],
            created_at_ms: now_ms(),
        };
        Ok((user_id.to_hex(), identity))
    }

    async fn check_user(&self, _handle: &str) -> Result<bool, CoreError> {
        Ok(true)
    }

    async fn announce_presence(&self, _identity: &PublicIdentity) -> Result<(), CoreError> {
        Ok(())
    }
}

fn handle_recipient(handle: &str) -> OutgoingRecipient {
    OutgoingRecipient {
        recipient_user_id: None,
        recipient_handle: Some(handle.to_string()),
    }
}

#[tokio::test]
async fn directory_resolves_and_caches_handles() {
    let mut policy = Policy::default();
    policy.directory_ttl_secs = 1;
    let transport = MockTransport::new();
    let registry = Arc::new(InMemoryRegistry::new());
    let relay = Arc::new(InMemoryRelay::new());
    let mut core = Core::init(
        base_config(temp_path("dir-cache"), TransportMode::Hybrid),
        policy,
        key_provider(),
        registry,
        relay,
        Arc::new(transport),
    )
    .await
    .expect("core");
    let resolver = Arc::new(MockDirectoryResolver::new());
    core.set_resolver(resolver.clone());
    let handle = "@alice";
    let conv = ConversationId {
        value: "conv-handle".to_string(),
    };
    let req = OutgoingMessageRequest {
        client_message_id: MessageId::random(),
        conversation_id: conv.clone(),
        sender: UserIdHex {
            value: core.local_identity().user_id.to_hex(),
        },
        recipients: vec![handle_recipient(handle)],
        kind: MessageKind::Text,
        text: Some("hi".to_string()),
        attachment: None,
        attachment_bytes: None,
        ephemeral_expiry_secs: None,
        metadata: None,
    };
    core.send_message(req).await.expect("send one");
    assert_eq!(resolver.count().await, 1);
    let cached = core.directory.get_by_handle(handle).await.expect("cached");
    assert_eq!(cached.user_id.len(), 64);
    let second = OutgoingMessageRequest {
        client_message_id: MessageId::random(),
        conversation_id: conv.clone(),
        sender: UserIdHex {
            value: core.local_identity().user_id.to_hex(),
        },
        recipients: vec![handle_recipient(handle)],
        kind: MessageKind::Text,
        text: Some("again".to_string()),
        attachment: None,
        attachment_bytes: None,
        ephemeral_expiry_secs: None,
        metadata: None,
    };
    core.send_message(second).await.expect("send cached");
    assert_eq!(resolver.count().await, 1);
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let third = OutgoingMessageRequest {
        client_message_id: MessageId::random(),
        conversation_id: conv,
        sender: UserIdHex {
            value: core.local_identity().user_id.to_hex(),
        },
        recipients: vec![handle_recipient(handle)],
        kind: MessageKind::Text,
        text: Some("refresh".to_string()),
        attachment: None,
        attachment_bytes: None,
        ephemeral_expiry_secs: None,
        metadata: None,
    };
    core.send_message(third).await.expect("send refresh");
    assert_eq!(resolver.count().await, 2);
}
