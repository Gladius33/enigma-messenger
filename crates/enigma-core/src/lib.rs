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
use channels::ChannelState;
use config::{CoreConfig, TransportMode};
use directory::{register_identity, ContactDirectory};
use enigma_api::types::{
    ConversationId as ApiConversationId, IncomingMessageEvent, MessageId, OutgoingMessageRequest,
    ReceiptStatus, UserIdHex, ValidationLimits,
};
use enigma_node_client::RegistryClient;
use enigma_node_types::{EnvelopePayload, RelayEnvelope};
use enigma_relay::RelayClient;
use enigma_storage::{EncryptedStore, KeyProvider};
use error::CoreError;
use event::{EventBus, EventReceiver};
use groups::{GroupState, NullGroupCryptoProvider};
use identity::LocalIdentity;
use ids::{conversation_id_for_dm, ConversationId, UserId};
use messaging::{MockTransport, Transport};
use packet::{
    build_frame, decode_frame, deserialize_envelope, serialize_envelope, PlainMessage, WireEnvelope,
};
use policy::Policy;
use relay::RelayGateway;
use session::SessionManager;
use std::collections::HashMap;
use std::sync::Arc;
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
    directory: ContactDirectory,
    events: EventBus,
    groups: GroupState,
    channels: ChannelState,
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
        let mut store = EncryptedStore::open_or_create(
            &config.storage_path,
            &config.namespace,
            key_provider.as_ref(),
        )
        .map_err(|_| CoreError::Storage)?;
        let identity = LocalIdentity::load_or_create(&mut store, config.device_name.clone())?;
        let sessions = SessionManager::new(identity.user_id.clone());
        let core = Self {
            config: config.clone(),
            policy: policy.clone(),
            store: Arc::new(Mutex::new(store)),
            identity: identity.clone(),
            sessions: Arc::new(Mutex::new(sessions)),
            attachments: Arc::new(Mutex::new(AttachmentAssembler::new())),
            attachment_store: Arc::new(Mutex::new(HashMap::new())),
            registry: registry.clone(),
            relay: RelayGateway::new(relay_client.clone()),
            transport,
            directory: ContactDirectory::new(),
            events: EventBus::new(256),
            groups: GroupState::new(policy.clone(), Arc::new(NullGroupCryptoProvider)),
            channels: ChannelState::new(policy.clone()),
        };
        {
            let guard = core.store.lock().await;
            let _ = guard.get("identity");
        }
        let _ = core.directory.lookup(&identity.user_id.to_hex());
        register_identity(core.registry.clone(), &identity).await?;
        core.start_relay_poller();
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
            let recipient_user = UserId::from_hex(&recipient.value)
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
            self.route_bytes(recipient, bytes.clone(), false).await?;
            if let Some(descriptor) = request.attachment.as_ref() {
                if let Some(data) = request.attachment_bytes.as_ref() {
                    let chunks = prepare_chunks(descriptor, data, &self.policy)?;
                    for chunk in chunks {
                        let chunk_env = WireEnvelope::Attachment(chunk);
                        let payload = serialize_envelope(&chunk_env)?;
                        self.route_bytes(recipient, payload, true).await?;
                    }
                }
            }
        }
        Ok(request.client_message_id.clone())
    }

    async fn route_bytes(
        &self,
        recipient: &UserIdHex,
        bytes: Vec<u8>,
        is_attachment: bool,
    ) -> Result<(), CoreError> {
        let payload = if is_attachment {
            EnvelopePayload::AttachmentChunk(bytes.clone())
        } else {
            EnvelopePayload::Message(bytes.clone())
        };
        match self.config.transport_mode {
            TransportMode::RelayOnly => {
                let env = RelayEnvelope::new(recipient.value.clone(), payload);
                self.relay.push(env).await?
            }
            TransportMode::P2PWebRTC => self.transport.send(recipient.value.clone(), bytes).await?,
            TransportMode::Hybrid => {
                let send_result = self
                    .transport
                    .send(recipient.value.clone(), bytes.clone())
                    .await;
                if send_result.is_err() {
                    let env = RelayEnvelope::new(recipient.value.clone(), payload);
                    self.relay.push(env).await?;
                }
            }
        }
        Ok(())
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
            match &env.payload {
                EnvelopePayload::Message(bytes) => {
                    self.handle_incoming_bytes(bytes.clone(), true).await?;
                    ack_ids.push(env.id);
                }
                EnvelopePayload::AttachmentChunk(bytes) => {
                    self.handle_incoming_bytes(bytes.clone(), true).await?;
                    ack_ids.push(env.id);
                }
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

#[cfg(test)]
mod tests;
