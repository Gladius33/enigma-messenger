use crate::envelope_crypto::encrypt_identity_envelope;
use crate::error::CoreError;
use crate::identity::LocalIdentity;
use crate::ids::DeviceId;
use crate::time::now_ms;
use enigma_node_registry::envelope::{EnvelopePublicKey, IdentityEnvelope};
use enigma_node_registry::store::Store;
use enigma_node_types::{Presence, UserId};
use enigma_storage::EncryptedStore;
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_id: DeviceId,
    pub last_seen_ms: u64,
    pub hints: Option<serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contact {
    pub handle: String,
    pub user_id: String,
    pub alias: Option<String>,
    pub added_at_ms: u64,
    pub last_resolved_ms: u64,
    #[serde(default)]
    pub devices: Vec<DeviceInfo>,
}

#[async_trait::async_trait]
pub trait RegistryClient: Send + Sync {
    async fn envelope_key(&self) -> Result<EnvelopePublicKey, CoreError>;
    async fn register(&self, handle: &str, envelope: IdentityEnvelope) -> Result<(), CoreError>;
    async fn resolve(
        &self,
        handle: &str,
        requester_ephemeral_public_key: [u8; 32],
    ) -> Result<Option<IdentityEnvelope>, CoreError>;
    async fn check_user(&self, handle: &str) -> Result<bool, CoreError>;
    async fn announce_presence(&self, presence: Presence) -> Result<(), CoreError>;
    fn envelope_pepper(&self) -> Option<[u8; 32]>;
    fn endpoints(&self) -> Vec<String>;
}

#[derive(Clone)]
pub struct ContactDirectory {
    store: Arc<Mutex<EncryptedStore>>,
}

impl ContactDirectory {
    pub fn new(store: Arc<Mutex<EncryptedStore>>) -> Self {
        Self { store }
    }

    pub async fn add_or_update_contact(
        &self,
        handle: &str,
        user_id: &str,
        alias: Option<String>,
        now_ms: u64,
    ) -> Result<Contact, CoreError> {
        let mut guard = self.store.lock().await;
        let mut index = self.index(&mut guard)?;
        index.insert(handle.to_string());
        let mut contact = self.load_contact(&mut guard, handle).unwrap_or(Contact {
            handle: handle.to_string(),
            user_id: user_id.to_string(),
            alias: alias.clone(),
            added_at_ms: now_ms,
            last_resolved_ms: now_ms,
            devices: Vec::new(),
        });
        contact.user_id = user_id.to_string();
        if alias.is_some() {
            contact.alias = alias;
        }
        if contact.added_at_ms == 0 {
            contact.added_at_ms = now_ms;
        }
        contact.last_resolved_ms = now_ms;
        let data = serde_json::to_vec(&contact).map_err(|_| CoreError::Storage)?;
        guard
            .put(&Self::handle_key(handle), &data)
            .map_err(|_| CoreError::Storage)?;
        guard
            .put(&Self::uid_key(user_id), &data)
            .map_err(|_| CoreError::Storage)?;
        self.persist_index(&mut guard, &index)?;
        Ok(contact)
    }

    pub async fn get_by_handle(&self, handle: &str) -> Option<Contact> {
        let mut guard = self.store.lock().await;
        self.load_contact(&mut guard, handle)
    }

    pub async fn get_by_user_id(&self, user_id: &str) -> Option<Contact> {
        let mut guard = self.store.lock().await;
        self.load_by_user_id(&mut guard, user_id)
    }

    pub async fn list(&self) -> Vec<Contact> {
        let mut guard = self.store.lock().await;
        let index = self.index(&mut guard).unwrap_or_default();
        let mut contacts = Vec::new();
        for handle in index.iter() {
            if let Some(contact) = self.load_contact(&mut guard, handle) {
                contacts.push(contact);
            }
        }
        contacts
    }

    pub async fn mark_resolved(&self, handle: &str, now_ms: u64) -> Result<(), CoreError> {
        let mut guard = self.store.lock().await;
        if let Some(mut contact) = self.load_contact(&mut guard, handle) {
            contact.last_resolved_ms = now_ms;
            let data = serde_json::to_vec(&contact).map_err(|_| CoreError::Storage)?;
            guard
                .put(&Self::handle_key(handle), &data)
                .map_err(|_| CoreError::Storage)?;
            guard
                .put(&Self::uid_key(&contact.user_id), &data)
                .map_err(|_| CoreError::Storage)?;
        }
        Ok(())
    }

    pub async fn len(&self) -> usize {
        let mut guard = self.store.lock().await;
        self.index(&mut guard).map(|i| i.len()).unwrap_or(0)
    }

    pub async fn get_devices(&self, user_id: &str) -> Vec<DeviceInfo> {
        let guard = self.store.lock().await;
        guard
            .get(&Self::devices_key(user_id))
            .ok()
            .flatten()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    pub async fn set_devices(
        &self,
        user_id: &str,
        devices: Vec<DeviceInfo>,
    ) -> Result<(), CoreError> {
        let guard = self.store.lock().await;
        let bytes = serde_json::to_vec(&devices).map_err(|_| CoreError::Storage)?;
        guard
            .put(&Self::devices_key(user_id), &bytes)
            .map_err(|_| CoreError::Storage)
    }

    fn index(&self, store: &mut EncryptedStore) -> Result<HashSet<String>, CoreError> {
        if let Ok(Some(bytes)) = store.get("dir:index") {
            serde_json::from_slice(&bytes).map_err(|_| CoreError::Storage)
        } else {
            Ok(HashSet::new())
        }
    }

    fn persist_index(
        &self,
        store: &mut EncryptedStore,
        index: &HashSet<String>,
    ) -> Result<(), CoreError> {
        let bytes = serde_json::to_vec(index).map_err(|_| CoreError::Storage)?;
        store
            .put("dir:index", &bytes)
            .map_err(|_| CoreError::Storage)
    }

    fn load_contact(&self, store: &mut EncryptedStore, handle: &str) -> Option<Contact> {
        store
            .get(&Self::handle_key(handle))
            .ok()
            .flatten()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    }

    fn load_by_user_id(&self, store: &mut EncryptedStore, user_id: &str) -> Option<Contact> {
        store
            .get(&Self::uid_key(user_id))
            .ok()
            .flatten()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    }

    fn handle_key(handle: &str) -> String {
        format!("dir:handle:{}", handle)
    }

    fn uid_key(user_id: &str) -> String {
        format!("dir:uid:{}", user_id)
    }

    fn devices_key(user_id: &str) -> String {
        format!("dir:devices:{}", user_id)
    }
}

pub async fn register_identity(
    client: Arc<dyn RegistryClient>,
    identity: &LocalIdentity,
) -> Result<(), CoreError> {
    let pepper = client.envelope_pepper().ok_or(CoreError::Crypto)?;
    let key_info = client.envelope_key().await?;
    let envelope = encrypt_identity_envelope(pepper, &key_info, &identity.public_identity)
        .map_err(|_| CoreError::Crypto)?;
    client
        .register(&identity.user_id.to_hex(), envelope)
        .await
        .map_err(|e| CoreError::Transport(format!("register:{:?}", e)))
}

#[derive(Clone)]
pub struct InMemoryRegistry {
    store: Store,
    key: enigma_node_registry::envelope::EnvelopeKey,
    pepper: [u8; 32],
    endpoints: Vec<String>,
}

impl Default for InMemoryRegistry {
    fn default() -> Self {
        let pepper = [9u8; 32];
        let private = [7u8; 32];
        let key = enigma_node_registry::envelope::EnvelopeKey {
            kid: [1u8; 8],
            private,
            public: PublicKey::from(&StaticSecret::from(private)).to_bytes(),
            active: true,
            not_after: None,
        };
        Self {
            store: Store::new_in_memory(pepper, 1024),
            key,
            pepper,
            endpoints: Vec::new(),
        }
    }
}

impl InMemoryRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_endpoints(endpoints: Vec<String>) -> Self {
        Self {
            endpoints,
            ..Self::default()
        }
    }
}

#[async_trait::async_trait]
impl RegistryClient for InMemoryRegistry {
    async fn envelope_key(&self) -> Result<EnvelopePublicKey, CoreError> {
        Ok(EnvelopePublicKey {
            kid_hex: hex::encode(self.key.kid),
            x25519_public_key_hex: hex::encode(self.key.public),
            active: true,
            not_after_epoch_ms: self.key.not_after,
        })
    }

    async fn register(&self, handle: &str, envelope: IdentityEnvelope) -> Result<(), CoreError> {
        let user_id =
            UserId::from_hex(handle).map_err(|_| CoreError::Validation("handle".to_string()))?;
        let crypto = enigma_node_registry::envelope::EnvelopeCrypto::new(self.pepper);
        let identity = crypto
            .decrypt_identity(&envelope, &self.key, &user_id, now_ms())
            .map_err(|_| CoreError::Crypto)?;
        if identity.user_id != user_id {
            return Err(CoreError::Validation("handle".to_string()));
        }
        if self
            .store
            .check_user(&user_id)
            .await
            .map_err(|_| CoreError::Storage)?
        {
            return Ok(());
        }
        self.store
            .register(identity)
            .await
            .map_err(|_| CoreError::Storage)
    }

    async fn resolve(
        &self,
        handle: &str,
        requester_ephemeral_public_key: [u8; 32],
    ) -> Result<Option<IdentityEnvelope>, CoreError> {
        let user_id =
            UserId::from_hex(handle).map_err(|_| CoreError::Validation("handle".to_string()))?;
        let identity = self
            .store
            .resolve(&user_id)
            .await
            .map_err(|_| CoreError::Storage)?;
        if let Some(identity) = identity {
            let crypto = enigma_node_registry::envelope::EnvelopeCrypto::new(self.pepper);
            let envelope = crypto
                .encrypt_identity_for_peer(
                    &self.key,
                    &user_id,
                    &identity,
                    requester_ephemeral_public_key,
                    None,
                    now_ms(),
                )
                .map_err(|_| CoreError::Crypto)?;
            return Ok(Some(envelope));
        }
        Ok(None)
    }

    async fn check_user(&self, handle: &str) -> Result<bool, CoreError> {
        let user_id =
            UserId::from_hex(handle).map_err(|_| CoreError::Validation("handle".to_string()))?;
        self.store
            .check_user(&user_id)
            .await
            .map_err(|_| CoreError::Storage)
    }

    async fn announce_presence(&self, presence: Presence) -> Result<(), CoreError> {
        self.store
            .announce(presence)
            .await
            .map_err(|_| CoreError::Storage)
    }

    fn envelope_pepper(&self) -> Option<[u8; 32]> {
        Some(self.pepper)
    }

    fn endpoints(&self) -> Vec<String> {
        self.endpoints.clone()
    }
}
