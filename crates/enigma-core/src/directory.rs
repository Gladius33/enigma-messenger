use crate::error::CoreError;
use crate::identity::LocalIdentity;
use enigma_node_types::PublicIdentity;
use enigma_storage::EncryptedStore;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contact {
    pub handle: String,
    pub user_id: String,
    pub alias: Option<String>,
    pub added_at_ms: u64,
    pub last_resolved_ms: u64,
}

#[async_trait::async_trait]
pub trait RegistryClient: Send + Sync {
    async fn register(&self, identity: PublicIdentity) -> Result<(), CoreError>;
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
}

pub async fn register_identity(
    client: Arc<dyn RegistryClient>,
    identity: &LocalIdentity,
) -> Result<(), CoreError> {
    client
        .register(identity.public_identity.clone())
        .await
        .map_err(|_| CoreError::Transport("register".to_string()))
}

#[derive(Clone, Default)]
pub struct InMemoryRegistry {
    identities: Arc<Mutex<Vec<PublicIdentity>>>,
    endpoints: Vec<String>,
}

impl InMemoryRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_endpoints(endpoints: Vec<String>) -> Self {
        Self {
            identities: Arc::new(Mutex::new(Vec::new())),
            endpoints,
        }
    }

    pub async fn list(&self) -> Vec<PublicIdentity> {
        self.identities.lock().await.clone()
    }
}

#[async_trait::async_trait]
impl RegistryClient for InMemoryRegistry {
    async fn register(&self, identity: PublicIdentity) -> Result<(), CoreError> {
        let mut guard = self.identities.lock().await;
        if !guard.iter().any(|item| item.user_id == identity.user_id) {
            guard.push(identity);
        }
        Ok(())
    }

    fn endpoints(&self) -> Vec<String> {
        self.endpoints.clone()
    }
}
