use async_trait::async_trait;
use enigma_node_types::RelayEnvelope;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;

#[derive(Debug, Error)]
pub enum RelayError {
    #[error("network")] 
    Network,
}

#[async_trait]
pub trait RelayClient: Send + Sync {
    async fn push(&self, envelope: RelayEnvelope) -> Result<(), RelayError>;
    async fn pull(&self, recipient: &str) -> Result<Vec<RelayEnvelope>, RelayError>;
    async fn ack(&self, recipient: &str, ids: &[uuid::Uuid]) -> Result<(), RelayError>;
}

#[derive(Clone, Default)]
pub struct InMemoryRelay {
    entries: Arc<Mutex<HashMap<String, Vec<RelayEnvelope>>>>,
}

impl InMemoryRelay {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl RelayClient for InMemoryRelay {
    async fn push(&self, envelope: RelayEnvelope) -> Result<(), RelayError> {
        let mut guard = self.entries.lock().await;
        guard.entry(envelope.recipient.clone()).or_default().push(envelope);
        Ok(())
    }

    async fn pull(&self, recipient: &str) -> Result<Vec<RelayEnvelope>, RelayError> {
        let guard = self.entries.lock().await;
        Ok(guard.get(recipient).cloned().unwrap_or_default())
    }

    async fn ack(&self, recipient: &str, ids: &[uuid::Uuid]) -> Result<(), RelayError> {
        let mut guard = self.entries.lock().await;
        if let Some(list) = guard.get_mut(recipient) {
            list.retain(|env| !ids.contains(&env.id));
        }
        Ok(())
    }
}
