use crate::error::CoreError;
use crate::ids::UserId;
use crate::identity::LocalIdentity;
use enigma_node_client::RegistryClient;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

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

    pub async fn add(&self, handle: String, user_id: UserId) {
        let mut guard = self.entries.lock().await;
        guard.insert(handle, user_id);
    }

    pub async fn lookup(&self, handle: &str) -> Option<UserId> {
        let guard = self.entries.lock().await;
        guard.get(handle).cloned()
    }
}

pub async fn register_identity(client: Arc<dyn RegistryClient>, identity: &LocalIdentity) -> Result<(), CoreError> {
    client
        .register(identity.public_identity.clone())
        .await
        .map_err(|_| CoreError::Transport("register".to_string()))
}
