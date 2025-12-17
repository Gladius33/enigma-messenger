use crate::error::CoreError;
use enigma_node_types::RelayEnvelope;
use enigma_relay::RelayClient;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

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
