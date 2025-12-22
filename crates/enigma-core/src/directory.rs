use crate::envelope_crypto::{decrypt_identity_envelope, encrypt_identity_envelope};
use crate::error::CoreError;
use crate::identity::LocalIdentity;
use crate::ids::DeviceId;
use enigma_node_types::{
    compute_blind_index, EnvelopePubKey, IdentityEnvelope, PublicIdentity, RegistryEnvelopePublicKey,
    MAX_IDENTITY_CIPHERTEXT,
};
use enigma_storage::EncryptedStore;
use rand::RngCore;
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
    async fn envelope_key(&self) -> Result<EnvelopePubKey, CoreError>;
    async fn register(&self, handle: &str, envelope: IdentityEnvelope) -> Result<(), CoreError>;
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
    let key_info = client.envelope_key().await?;
    key_info.validate().map_err(|_| CoreError::Crypto)?;
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let raw_handle = identity
        .username_hint
        .clone()
        .unwrap_or_else(|| identity.user_id.to_hex());
    let handle = enigma_node_types::canonical_handle(&raw_handle);
    if handle.is_empty() {
        return Err(CoreError::Validation("handle".to_string()));
    }
    let blind_salt = key_info.blind_salt.unwrap_or([0u8; 32]);
    let blind_index = compute_blind_index(&handle, &blind_salt);
    let bytes = serde_json::to_vec(&identity.public_identity).map_err(|_| CoreError::Crypto)?;
    let envelope = encrypt_identity_envelope(
        key_info.public_key.0,
        key_info.kid.clone(),
        blind_index,
        nonce,
        &handle,
        &bytes,
        None,
    )
    .map_err(|_| CoreError::Crypto)?;
    client
        .register(&handle, envelope)
        .await
        .map_err(|_| CoreError::Transport("register".to_string()))
}

#[derive(Clone)]
struct StoredIdentity {
    handle: String,
    blind_index: enigma_node_types::BlindIndex,
    identity: PublicIdentity,
    envelope: IdentityEnvelope,
}

#[derive(Clone)]
struct EnvelopeKeyPair {
    kid: enigma_node_types::KeyId,
    private_key: [u8; 32],
    public_key: RegistryEnvelopePublicKey,
}

#[derive(Clone)]
pub struct InMemoryRegistry {
    identities: Arc<Mutex<Vec<StoredIdentity>>>,
    endpoints: Vec<String>,
    keys: Arc<Mutex<Vec<EnvelopeKeyPair>>>,
    active_kid: enigma_node_types::KeyId,
    blind_pepper: [u8; 32],
    blind_salt: [u8; 32],
}

impl Default for InMemoryRegistry {
    fn default() -> Self {
        let private_key = [7u8; 32];
        let kid = enigma_node_types::KeyId([1u8; 8]);
        let public_key =
            RegistryEnvelopePublicKey(PublicKey::from(&StaticSecret::from(private_key)).to_bytes());
        Self {
            identities: Arc::new(Mutex::new(Vec::new())),
            endpoints: Vec::new(),
            keys: Arc::new(Mutex::new(vec![EnvelopeKeyPair {
                kid: kid.clone(),
                private_key,
                public_key,
            }])),
            active_kid: kid,
            blind_pepper: [9u8; 32],
            blind_salt: [9u8; 32],
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

    async fn active_key(&self) -> EnvelopeKeyPair {
        let guard = self.keys.lock().await;
        guard
            .iter()
            .find(|k| k.kid == self.active_kid)
            .cloned()
            .or_else(|| guard.get(0).cloned())
            .unwrap_or(EnvelopeKeyPair {
                kid: self.active_kid.clone(),
                private_key: [0u8; 32],
                public_key: RegistryEnvelopePublicKey([0u8; 32]),
            })
    }

    pub async fn list(&self) -> Vec<PublicIdentity> {
        self.identities
            .lock()
            .await
            .iter()
            .map(|s| s.identity.clone())
            .collect()
    }

    pub async fn stored_envelopes(&self) -> Vec<IdentityEnvelope> {
        self.identities
            .lock()
            .await
            .iter()
            .map(|s| s.envelope.clone())
            .collect()
    }

    pub async fn issue_envelope_for(
        &self,
        handle: &str,
        requester_ephemeral_public_key: [u8; 32],
    ) -> Option<IdentityEnvelope> {
        let canonical = enigma_node_types::canonical_handle(handle);
        if canonical.is_empty() {
            return None;
        }
        let stored = {
            let guard = self.identities.lock().await;
            guard.iter().find(|s| s.handle == canonical).cloned()
        }?;
        let mut nonce = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let bytes = serde_json::to_vec(&stored.identity).ok()?;
        let key = self.active_key().await;
        encrypt_identity_envelope(
            requester_ephemeral_public_key,
            key.kid,
            stored.blind_index,
            nonce,
            &canonical,
            &bytes,
            None,
        )
        .ok()
    }
}

#[async_trait::async_trait]
impl RegistryClient for InMemoryRegistry {
    async fn envelope_key(&self) -> Result<EnvelopePubKey, CoreError> {
        let key = self.active_key().await;
        Ok(EnvelopePubKey {
            kid: key.kid,
            public_key: key.public_key,
            blind_salt: Some(self.blind_salt),
        })
    }

    async fn register(&self, handle: &str, envelope: IdentityEnvelope) -> Result<(), CoreError> {
        let canonical = enigma_node_types::canonical_handle(handle);
        if canonical.is_empty() {
            return Err(CoreError::Validation("handle".to_string()));
        }
        let key = {
            let guard = self.keys.lock().await;
            guard
                .iter()
                .find(|k| k.kid == envelope.kid)
                .cloned()
                .ok_or(CoreError::Crypto)?
        };
        let plaintext = decrypt_identity_envelope(
            key.private_key,
            Some(&key.kid),
            &envelope,
            &canonical,
            MAX_IDENTITY_CIPHERTEXT,
            None,
        )
        .map_err(|_| CoreError::Crypto)?;
        let identity: PublicIdentity =
            serde_json::from_slice(&plaintext).map_err(|_| CoreError::Crypto)?;
        identity.validate().map_err(|_| CoreError::Crypto)?;
        let blind_index = compute_blind_index(&canonical, &self.blind_pepper);
        let mut guard = self.identities.lock().await;
        if !guard.iter().any(|item| item.identity.user_id == identity.user_id) {
            guard.push(StoredIdentity {
                handle: canonical,
                blind_index,
                identity,
                envelope,
            });
        }
        Ok(())
    }

    fn endpoints(&self) -> Vec<String> {
        self.endpoints.clone()
    }
}
