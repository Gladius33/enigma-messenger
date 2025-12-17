use crate::error::CoreError;
use enigma_node_types::RelayEnvelope;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

#[async_trait::async_trait]
pub trait RelayClient: Send + Sync {
    async fn push(&self, envelope: RelayEnvelope) -> Result<(), CoreError>;
    async fn pull(&self, recipient: &str) -> Result<Vec<RelayEnvelope>, CoreError>;
    async fn ack(&self, recipient: &str, ids: &[Uuid]) -> Result<(), CoreError>;
}

#[derive(Clone)]
pub struct RelayGateway {
    client: Arc<dyn RelayClient>,
    pending: Arc<Mutex<Vec<RelayEnvelope>>>,
}

impl RelayGateway {
    pub fn new(client: Arc<dyn RelayClient>) -> Self {
        Self {
            client,
            pending: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub async fn push(&self, envelope: RelayEnvelope) -> Result<(), CoreError> {
        self.client
            .push(envelope)
            .await
            .map_err(|e| CoreError::Relay(format!("{:?}", e)))
    }

    pub async fn pull(&self, recipient: &str) -> Result<Vec<RelayEnvelope>, CoreError> {
        let pulled = self
            .client
            .pull(recipient)
            .await
            .map_err(|e| CoreError::Relay(format!("{:?}", e)))?;
        Ok(pulled)
    }

    pub async fn ack(&self, recipient: &str, ids: &[Uuid]) -> Result<(), CoreError> {
        self.client
            .ack(recipient, ids)
            .await
            .map_err(|e| CoreError::Relay(format!("{:?}", e)))
    }

    pub async fn queue_local(&self, envelope: RelayEnvelope) {
        let mut guard = self.pending.lock().await;
        guard.push(envelope);
    }

    pub async fn take_local(&self) -> Vec<RelayEnvelope> {
        let mut guard = self.pending.lock().await;
        let out = guard.clone();
        guard.clear();
        out
    }

    pub async fn pending_len(&self) -> usize {
        self.pending.lock().await.len()
    }
}

#[derive(Clone, Default)]
pub struct InMemoryRelay {
    entries: Arc<Mutex<Vec<RelayEnvelope>>>,
}

impl InMemoryRelay {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait::async_trait]
impl RelayClient for InMemoryRelay {
    async fn push(&self, envelope: RelayEnvelope) -> Result<(), CoreError> {
        let mut guard = self.entries.lock().await;
        guard.push(envelope);
        Ok(())
    }

    async fn pull(&self, recipient: &str) -> Result<Vec<RelayEnvelope>, CoreError> {
        let guard = self.entries.lock().await;
        let list = guard
            .iter()
            .filter(|env| env.to.to_hex() == recipient)
            .cloned()
            .collect();
        Ok(list)
    }

    async fn ack(&self, recipient: &str, ids: &[Uuid]) -> Result<(), CoreError> {
        let mut guard = self.entries.lock().await;
        guard.retain(|env| env.to.to_hex() != recipient || !ids.contains(&env.id));
        Ok(())
    }
}
