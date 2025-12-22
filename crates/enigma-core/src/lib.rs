pub mod attachments;
pub mod channels;
pub mod config;
pub mod directory;
pub mod error;
pub mod event;
pub mod extensions;
pub mod groups;
pub mod identity;
pub mod ids;
pub mod messaging;
pub mod node;
pub mod outbox;
pub mod packet;
pub mod policy;
pub mod ratchet;
pub mod relay;
pub mod session;
pub mod sync;
pub mod time;

#[cfg(feature = "dev")]
mod introspection;

#[cfg(feature = "dev")]
pub use introspection::{CoreStats, RegistryStatus, StoreHealth};

use attachments::{prepare_chunks, AttachmentAssembler};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use channels::ChannelState;
use config::{CoreConfig, TransportMode};
use directory::{register_identity, ContactDirectory, RegistryClient};
use enigma_api::types::{
    ConversationId as ApiConversationId, IncomingMessageEvent, MessageId, OutgoingMessageRequest,
    OutgoingRecipient, ReceiptStatus, UserIdHex, ValidationLimits,
};
use enigma_node_types::{OpaqueMessage, RelayEnvelope, RelayKind, UserId as NodeUserId};
use enigma_storage::key_provider::KeyProvider;
use enigma_storage::EncryptedStore;
use error::CoreError;
use event::{EventBus, EventReceiver};
use groups::{GroupState, NullGroupCryptoProvider};
use identity::LocalIdentity;
use ids::{conversation_id_for_dm, ConversationId, UserId};
use messaging::{MockTransport, Transport};
use node::{DirectoryResolver, NodeDirectoryResolver};
use outbox::{Outbox, OutboxItem};
use packet::{
    build_frame, decode_frame, deserialize_envelope, serialize_envelope, PlainMessage, WireEnvelope,
};
use policy::Policy;
use relay::{RelayClient, RelayGateway};
use session::SessionManager;
use std::collections::HashMap;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use time::now_ms;
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Clone)]
pub struct Core {
    config: CoreConfig,
    policy: Policy,
    store: Arc<Mutex<EncryptedStore>>,
    identity: LocalIdentity,
    sessions: Arc<Mutex<SessionManager>>,
    attachments: Arc<Mutex<AttachmentAssembler>>,
    attachment_store: Arc<Mutex<HashMap<Uuid, Vec<u8>>>>,
    registry: Arc<dyn RegistryClient>,
    relay: RelayGateway,
    transport: Arc<dyn Transport>,
    resolver: Arc<dyn DirectoryResolver>,
    directory: ContactDirectory,
    events: EventBus,
    groups: GroupState,
    channels: ChannelState,
    outbox: Outbox,
    #[cfg(test)]
    persist_fail: Arc<AtomicBool>,
}

impl Core {
    pub async fn init(
        config: CoreConfig,
        policy: Policy,
        key_provider: Arc<dyn KeyProvider>,
        registry: Arc<dyn RegistryClient>,
        relay_client: Arc<dyn RelayClient>,
        transport: Arc<dyn Transport>,
    ) -> Result<Self, CoreError> {
        let store = EncryptedStore::open(
            &config.storage_path,
            &config.namespace,
            key_provider.as_ref(),
        )
        .map_err(|_| CoreError::Storage)?;
        let identity = LocalIdentity::load_or_create(&store, config.device_name.clone())?;
        let sessions = SessionManager::new(identity.user_id.clone());
        let store_arc = Arc::new(Mutex::new(store));
        let directory = ContactDirectory::new(store_arc.clone());
        let resolver: Arc<dyn DirectoryResolver> =
            Arc::new(NodeDirectoryResolver::new(&config.node_base_urls));
        let core = Self {
            config: config.clone(),
            policy: policy.clone(),
            store: store_arc.clone(),
            identity: identity.clone(),
            sessions: Arc::new(Mutex::new(sessions)),
            attachments: Arc::new(Mutex::new(AttachmentAssembler::new())),
            attachment_store: Arc::new(Mutex::new(HashMap::new())),
            registry: registry.clone(),
            relay: RelayGateway::new(relay_client.clone()),
            transport,
            resolver,
            directory,
            events: EventBus::new(256),
            groups: GroupState::new(policy.clone(), Arc::new(NullGroupCryptoProvider)),
            channels: ChannelState::new(policy.clone()),
            outbox: Outbox::new(store_arc),
            #[cfg(test)]
            persist_fail: Arc::new(AtomicBool::new(false)),
        };
        register_identity(core.registry.clone(), &identity).await?;
        if core.config.polling_interval_ms > 0 {
            core.start_relay_poller();
        }
        if core.policy.outbox_batch_send > 0 {
            core.start_outbox_worker();
        }
        core.start_presence_announcer();
        Ok(core)
    }

    pub fn subscribe(&self) -> EventReceiver {
        self.events.subscribe()
    }

    pub fn local_identity(&self) -> LocalIdentity {
        self.identity.clone()
    }

    pub async fn send_message(
        &self,
        request: OutgoingMessageRequest,
    ) -> Result<MessageId, CoreError> {
        let limits = ValidationLimits {
            max_text_bytes: self.policy.max_text_bytes,
            max_name_len: self.policy.max_group_name_len,
        };
        enigma_api::validation::validate_message_request(&request, &limits)
            .map_err(|e| CoreError::Validation(format!("{:?}", e)))?;
        let conversation = ConversationId::new(request.conversation_id.value.clone());
        if matches!(request.kind, enigma_api::types::MessageKind::ChannelPost) {
            let channel = self
                .channels
                .get(&conversation)
                .await
                .ok_or(CoreError::Validation("channel_unknown".to_string()))?;
            if !channel
                .admins
                .iter()
                .any(|a| a.value == request.sender.value)
            {
                return Err(CoreError::Validation("channel_post_denied".to_string()));
            }
        }
        if let Some(group) = self.groups.get(&conversation).await {
            let allowed = group
                .members
                .iter()
                .find(|m| m.user_id.value == request.sender.value)
                .map(|m| !matches!(m.role, enigma_api::types::GroupRole::ReadOnly))
                .unwrap_or(false);
            if !allowed {
                return Err(CoreError::Validation("group_member_missing".to_string()));
            }
        }
        if !self.config.allow_attachments && request.attachment.is_some() {
            return Err(CoreError::Validation("attachments_disabled".to_string()));
        }
        let sender_hex = request.sender.value.clone();
        for recipient in request.recipients.iter() {
            let recipient_hex = self.resolve_recipient(recipient).await?;
            let recipient_user = UserId::from_hex(&recipient_hex)
                .ok_or(CoreError::Validation("recipient".to_string()))?;
            let key = {
                let mut sessions = self.sessions.lock().await;
                sessions.next_key(&recipient_user)?
            };
            let edited = request
                .metadata
                .as_ref()
                .and_then(|m| m.get("edited"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let deleted = request
                .metadata
                .as_ref()
                .and_then(|m| m.get("deleted"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let plain = PlainMessage {
                conversation_id: request.conversation_id.value.clone(),
                message_id: request.client_message_id.value,
                sender: sender_hex.clone(),
                kind: request.kind.clone(),
                text: request.text.clone(),
                attachment: request.attachment.clone(),
                timestamp: now_ms(),
                edited,
                deleted,
            };
            let frame = build_frame(plain, &key)?;
            let envelope = WireEnvelope::Message(frame);
            let bytes = serialize_envelope(&envelope)?;
            let outbox_id = Uuid::new_v4();
            let item = OutboxItem {
                id: outbox_id,
                message_id: request.client_message_id.value.to_string(),
                created_at_ms: now_ms(),
                next_retry_ms: now_ms(),
                tries: 0,
                recipient_user_id: recipient_hex.clone(),
                conversation_id: request.conversation_id.value.clone(),
                packet: bytes.clone(),
            };
            let _ = self.outbox.put(item).await;
            let sent = self.send_outbox_item_bytes(&recipient_hex, &bytes).await;
            if sent.is_ok() {
                let _ = self.outbox.mark_sent(&outbox_id).await;
            } else {
                let _ = self.outbox.bump_retry(&outbox_id, &self.policy).await;
            }
            if let Some(descriptor) = request.attachment.as_ref() {
                if let Some(data) = request.attachment_bytes.as_ref() {
                    let chunks = prepare_chunks(descriptor, data, &self.policy)?;
                    for chunk in chunks {
                        let chunk_env = WireEnvelope::Attachment(chunk);
                        let payload = serialize_envelope(&chunk_env)?;
                        let att_id = Uuid::new_v4();
                        let att_item = OutboxItem {
                            id: att_id,
                            message_id: request.client_message_id.value.to_string(),
                            created_at_ms: now_ms(),
                            next_retry_ms: now_ms(),
                            tries: 0,
                            recipient_user_id: recipient_hex.clone(),
                            conversation_id: request.conversation_id.value.clone(),
                            packet: payload.clone(),
                        };
                        let _ = self.outbox.put(att_item).await;
                        let att_sent = self.send_outbox_item_bytes(&recipient_hex, &payload).await;
                        if att_sent.is_ok() {
                            let _ = self.outbox.mark_sent(&att_id).await;
                        } else {
                            let _ = self.outbox.bump_retry(&att_id, &self.policy).await;
                        }
                    }
                }
            }
        }
        Ok(request.client_message_id.clone())
    }

    async fn send_outbox_item_bytes(&self, recipient: &str, bytes: &[u8]) -> Result<(), CoreError> {
        let is_attachment = deserialize_envelope(bytes)
            .map(|env| matches!(env, WireEnvelope::Attachment(_)))
            .unwrap_or(false);
        match self.config.transport_mode {
            TransportMode::RelayOnly => {
                let env = build_relay_envelope(
                    &self.identity.user_id,
                    recipient,
                    bytes.to_vec(),
                    is_attachment,
                )?;
                self.relay.push(env).await
            }
            TransportMode::P2PWebRTC => self.transport.send_p2p(recipient, bytes).await,
            TransportMode::Hybrid => {
                if self.transport.p2p_ready(recipient).await {
                    if self.transport.send_p2p(recipient, bytes).await.is_ok() {
                        return Ok(());
                    }
                }
                let env = build_relay_envelope(
                    &self.identity.user_id,
                    recipient,
                    bytes.to_vec(),
                    is_attachment,
                )?;
                self.relay.push(env).await
            }
        }
    }

    pub async fn poll_once(&self) -> Result<(), CoreError> {
        self.process_transport().await?;
        self.process_relay().await?;
        Ok(())
    }

    async fn process_transport(&self) -> Result<(), CoreError> {
        let messages = self
            .transport
            .receive(&self.identity.user_id.to_hex())
            .await?;
        for msg in messages {
            self.handle_incoming_bytes(msg.bytes, false).await?;
        }
        Ok(())
    }

    async fn process_relay(&self) -> Result<(), CoreError> {
        let pulled = self.relay.pull(&self.identity.user_id.to_hex()).await?;
        let mut ack_ids = Vec::new();
        for env in pulled.iter() {
            match &env.kind {
                RelayKind::OpaqueMessage(msg) => {
                    if let Ok(bytes) = STANDARD.decode(&msg.blob_b64) {
                        if self.persist_incoming(env.id, &bytes).await.is_ok() {
                            if self.handle_incoming_bytes(bytes, true).await.is_ok() {
                                ack_ids.push(env.id);
                            }
                        }
                    }
                }
                RelayKind::OpaqueAttachmentChunk(chunk) => {
                    if let Ok(bytes) = STANDARD.decode(&chunk.blob_b64) {
                        if self.persist_incoming(env.id, &bytes).await.is_ok() {
                            if self.handle_incoming_bytes(bytes, true).await.is_ok() {
                                ack_ids.push(env.id);
                            }
                        }
                    }
                }
                RelayKind::OpaqueSignaling(_) => {}
            }
        }
        if !ack_ids.is_empty() {
            self.relay
                .ack(&self.identity.user_id.to_hex(), &ack_ids)
                .await?;
        }
        Ok(())
    }

    async fn handle_incoming_bytes(
        &self,
        bytes: Vec<u8>,
        _from_relay: bool,
    ) -> Result<(), CoreError> {
        let envelope = deserialize_envelope(&bytes)?;
        match envelope {
            WireEnvelope::Message(frame) => {
                if let Some(sender_hex) = parse_sender(&frame.associated_data) {
                    if let Some(sender_user) = UserId::from_hex(&sender_hex) {
                        let mut sessions = self.sessions.lock().await;
                        let key = sessions.next_key(&sender_user)?;
                        let message = decode_frame(&frame, &key)?;
                        let event = IncomingMessageEvent {
                            message_id: MessageId {
                                value: message.message_id,
                            },
                            conversation_id: ApiConversationId {
                                value: message.conversation_id.clone(),
                            },
                            sender: UserIdHex {
                                value: message.sender.clone(),
                            },
                            device_id: None,
                            kind: message.kind.clone(),
                            text: message.text.clone(),
                            attachment: message.attachment.clone(),
                            timestamp: message.timestamp,
                            receipt: ReceiptStatus::Delivered,
                            edited: message.edited,
                            deleted: message.deleted,
                        };
                        self.events.publish(event);
                    }
                }
            }
            WireEnvelope::Attachment(chunk) => {
                let mut assembler = self.attachments.lock().await;
                if let Some(data) = assembler.ingest(chunk.clone()) {
                    self.attachment_store
                        .lock()
                        .await
                        .insert(chunk.attachment_id, data);
                }
            }
        }
        Ok(())
    }

    async fn persist_incoming(&self, id: Uuid, bytes: &[u8]) -> Result<(), CoreError> {
        #[cfg(test)]
        if self.persist_fail.load(Ordering::SeqCst) {
            return Err(CoreError::Storage);
        }
        let guard = self.store.lock().await;
        let key = format!("inbox:{}", id);
        guard.put(&key, bytes).map_err(|_| CoreError::Storage)
    }

    fn start_relay_poller(&self) {
        let cloned = self.clone();
        let interval_ms = self.config.polling_interval_ms;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_millis(interval_ms));
            loop {
                ticker.tick().await;
                let _ = cloned.poll_once().await;
            }
        });
    }

    fn start_presence_announcer(&self) {
        let cloned = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(60));
            loop {
                ticker.tick().await;
                let _ = cloned
                    .resolver
                    .announce_presence(&cloned.identity.public_identity)
                    .await;
            }
        });
    }

    fn start_outbox_worker(&self) {
        let cloned = self.clone();
        let batch = self.policy.outbox_batch_send;
        let window_ms = self.policy.max_retry_window_secs.saturating_mul(1000);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_millis(250));
            loop {
                ticker.tick().await;
                let now = now_ms();
                if let Ok(items) = cloned.outbox.load_all_due(now, batch).await {
                    for item in items {
                        if now.saturating_sub(item.created_at_ms) > window_ms {
                            let _ = cloned.outbox.mark_sent(&item.id).await;
                            continue;
                        }
                        match cloned.send_outbox_item(&item).await {
                            Ok(_) => {
                                let _ = cloned.outbox.mark_sent(&item.id).await;
                            }
                            Err(_) => {
                                let _ = cloned.outbox.bump_retry(&item.id, &cloned.policy).await;
                            }
                        }
                    }
                }
            }
        });
    }

    async fn send_outbox_item(&self, item: &OutboxItem) -> Result<(), CoreError> {
        self.send_outbox_item_bytes(&item.recipient_user_id, &item.packet)
            .await
    }

    #[cfg(test)]
    pub fn set_resolver(&mut self, resolver: Arc<dyn DirectoryResolver>) {
        self.resolver = resolver;
    }

    async fn resolve_recipient(&self, recipient: &OutgoingRecipient) -> Result<String, CoreError> {
        if let Some(user) = recipient.recipient_user_id.as_ref() {
            let trimmed = user.trim();
            if trimmed.is_empty() {
                return Err(CoreError::Validation("recipient".to_string()));
            }
            return Ok(trimmed.to_string());
        }
        if let Some(handle) = recipient.recipient_handle.as_ref() {
            let handle_trimmed = handle.trim();
            let now = now_ms();
            let ttl_ms = self.policy.directory_ttl_secs.saturating_mul(1000);
            if let Some(contact) = self.directory.get_by_handle(handle_trimmed).await {
                let fresh = now.saturating_sub(contact.last_resolved_ms) <= ttl_ms;
                if fresh || !self.policy.directory_refresh_on_send {
                    return Ok(contact.user_id);
                }
            }
            let (user_id, identity) = self.resolver.resolve_handle(handle_trimmed).await?;
            let _ = self
                .directory
                .add_or_update_contact(handle_trimmed, &user_id, None, now)
                .await;
            let _ = identity;
            return Ok(user_id);
        }
        Err(CoreError::Validation("recipient".to_string()))
    }

    pub async fn create_group(&self, name: String) -> Result<ConversationId, CoreError> {
        let owner = UserIdHex {
            value: self.identity.user_id.to_hex(),
        };
        let group = self.groups.create(name, owner).await?;
        Ok(ConversationId::new(group.id.value))
    }

    pub async fn create_channel(&self, name: String) -> Result<ConversationId, CoreError> {
        let admin = UserIdHex {
            value: self.identity.user_id.to_hex(),
        };
        let channel = self.channels.create(name, admin).await?;
        Ok(ConversationId::new(channel.id.value))
    }

    pub async fn add_channel_admin(
        &self,
        id: &ConversationId,
        user: UserIdHex,
    ) -> Result<(), CoreError> {
        self.channels.add_admin(id, user).await
    }

    pub async fn add_group_member(
        &self,
        id: &ConversationId,
        member: UserIdHex,
    ) -> Result<(), CoreError> {
        let member = enigma_api::types::GroupMember {
            user_id: member,
            role: enigma_api::types::GroupRole::Member,
        };
        self.groups.add_member(id, member).await
    }

    pub async fn get_attachment(&self, id: Uuid) -> Option<Vec<u8>> {
        self.attachment_store.lock().await.get(&id).cloned()
    }

    pub fn mock_transport() -> MockTransport {
        MockTransport::new()
    }

    pub fn dm_conversation(&self, other: &UserId) -> ConversationId {
        conversation_id_for_dm(&self.identity.user_id, other)
    }
}

fn parse_sender(bytes: &[u8]) -> Option<String> {
    String::from_utf8(bytes.to_vec())
        .ok()
        .and_then(|value| value.split(':').last().map(|s| s.to_string()))
}

fn build_relay_envelope(
    sender: &UserId,
    recipient: &str,
    bytes: Vec<u8>,
    _is_attachment: bool,
) -> Result<RelayEnvelope, CoreError> {
    let to = NodeUserId::from_hex(recipient)
        .map_err(|_| CoreError::Transport("relay_to".to_string()))?;
    let from = NodeUserId::from_hex(&sender.to_hex()).ok();
    let blob_b64 = STANDARD.encode(&bytes);
    let kind = RelayKind::OpaqueMessage(OpaqueMessage {
        blob_b64,
        content_type: None,
    });
    Ok(RelayEnvelope {
        id: Uuid::new_v4(),
        to,
        from,
        created_at_ms: now_ms(),
        expires_at_ms: None,
        kind,
    })
}

#[cfg(test)]
mod tests;
