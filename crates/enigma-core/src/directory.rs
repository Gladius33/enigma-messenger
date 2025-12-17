use crate::error::CoreError;
use crate::identity::LocalIdentity;
use crate::ids::UserId;
use enigma_node_types::PublicIdentity;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[async_trait::async_trait]
pub trait RegistryClient: Send + Sync {
    async fn register(&self, identity: PublicIdentity) -> Result<(), CoreError>;
    fn endpoints(&self) -> Vec<String>;
}

#[derive(Clone)]
pub struct ContactDirectory {
    entries: Arc<Mutex<HashMap<String, UserId>>>,
}

impl ContactDirectory {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn add(&self, handle: String, user_id: UserId) {
        if let Ok(mut guard) = self.entries.lock() {
            guard.insert(handle, user_id);
        }
    }

    pub fn lookup(&self, handle: &str) -> Option<UserId> {
        self.entries
            .lock()
            .ok()
            .and_then(|guard| guard.get(handle).cloned())
    }

    pub fn len(&self) -> usize {
        self.entries.lock().map(|guard| guard.len()).unwrap_or(0)
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
        Self {
            identities: Arc::new(Mutex::new(Vec::new())),
            endpoints: Vec::new(),
        }
    }

    pub fn with_endpoints(endpoints: Vec<String>) -> Self {
        Self {
            identities: Arc::new(Mutex::new(Vec::new())),
            endpoints,
        }
    }

    pub async fn list(&self) -> Vec<PublicIdentity> {
        self.identities
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }
}

#[async_trait::async_trait]
impl RegistryClient for InMemoryRegistry {
    async fn register(&self, identity: PublicIdentity) -> Result<(), CoreError> {
        if let Ok(mut guard) = self.identities.lock() {
            if !guard.iter().any(|item| item.user_id == identity.user_id) {
                guard.push(identity);
            }
        }
        Ok(())
    }

    fn endpoints(&self) -> Vec<String> {
        self.endpoints.clone()
    }
}
