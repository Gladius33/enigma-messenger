use async_trait::async_trait;
use enigma_node_types::PublicIdentity;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("network")]
    Network,
}

#[async_trait]
pub trait RegistryClient: Send + Sync {
    async fn register(&self, identity: PublicIdentity) -> Result<(), ClientError>;
    fn endpoints(&self) -> Vec<String>;
}

#[derive(Clone, Default)]
pub struct InMemoryRegistry {
    identities: Arc<Mutex<Vec<PublicIdentity>>>,
}

impl InMemoryRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn list(&self) -> Vec<PublicIdentity> {
        self.identities.lock().await.clone()
    }
}

#[async_trait]
impl RegistryClient for InMemoryRegistry {
    async fn register(&self, identity: PublicIdentity) -> Result<(), ClientError> {
        let mut guard = self.identities.lock().await;
        if !guard
            .iter()
            .any(|item| item.user_id == identity.user_id && item.device_id == identity.device_id)
        {
            guard.push(identity);
        }
        Ok(())
    }

    fn endpoints(&self) -> Vec<String> {
        Vec::new()
    }
}
