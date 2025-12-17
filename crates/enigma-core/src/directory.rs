use crate::error::CoreError;
use crate::identity::LocalIdentity;
use crate::ids::UserId;
use enigma_node_client::RegistryClient;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

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
