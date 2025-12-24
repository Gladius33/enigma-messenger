use crate::error::CoreError;
use enigma_node_types::{RelayEnvelope, RelayKind};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

#[async_trait::async_trait]
pub trait RelayClient: Send + Sync {
    async fn push(&self, envelope: RelayEnvelope) -> Result<(), CoreError>;
    async fn pull(
        &self,
        recipient: &str,
        cursor: Option<String>,
    ) -> Result<RelayPullResult, CoreError>;
    async fn ack(&self, recipient: &str, ack: &[RelayAck]) -> Result<RelayAckResponse, CoreError>;
}

#[derive(Clone, Debug, Default)]
pub struct RelayPullResult {
    pub items: Vec<RelayPullItem>,
    pub cursor: Option<String>,
}

#[derive(Clone, Debug)]
pub struct RelayPullItem {
    pub envelope: RelayEnvelope,
    pub chunk_index: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RelayAck {
    pub message_id: Uuid,
    pub chunk_index: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RelayAckResponse {
    pub deleted: u64,
    pub missing: u64,
    pub remaining: u64,
}

#[derive(Clone)]
pub struct RelayGateway {
    client: Arc<dyn RelayClient>,
    pending: Arc<Mutex<Vec<RelayEnvelope>>>,
    cursors: Arc<Mutex<HashMap<String, Option<String>>>>,
}

impl RelayGateway {
    pub fn new(client: Arc<dyn RelayClient>) -> Self {
        Self {
            client,
            pending: Arc::new(Mutex::new(Vec::new())),
            cursors: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn push(&self, envelope: RelayEnvelope) -> Result<(), CoreError> {
        self.client.push(envelope).await
    }

    pub async fn pull(&self, recipient: &str) -> Result<RelayPullResult, CoreError> {
        let cursor = {
            let guard = self.cursors.lock().await;
            guard.get(recipient).cloned().flatten()
        };
        let pulled = self.client.pull(recipient, cursor).await?;
        let mut guard = self.cursors.lock().await;
        guard.insert(recipient.to_string(), pulled.cursor.clone());
        Ok(pulled)
    }

    pub async fn ack(
        &self,
        recipient: &str,
        ack: &[RelayAck],
    ) -> Result<RelayAckResponse, CoreError> {
        self.client.ack(recipient, ack).await
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
    entries: Arc<Mutex<Vec<RelayPullItem>>>,
}

impl InMemoryRelay {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait::async_trait]
impl RelayClient for InMemoryRelay {
    async fn push(&self, envelope: RelayEnvelope) -> Result<(), CoreError> {
        let chunk_index = match &envelope.kind {
            RelayKind::OpaqueAttachmentChunk(chunk) => chunk.index,
            _ => 0,
        };
        let mut guard = self.entries.lock().await;
        guard.push(RelayPullItem {
            envelope,
            chunk_index,
        });
        Ok(())
    }

    async fn pull(
        &self,
        recipient: &str,
        _cursor: Option<String>,
    ) -> Result<RelayPullResult, CoreError> {
        let guard = self.entries.lock().await;
        let items = guard
            .iter()
            .filter(|env| env.envelope.to.to_hex() == recipient)
            .cloned()
            .collect();
        Ok(RelayPullResult {
            items,
            cursor: None,
        })
    }

    async fn ack(&self, recipient: &str, ack: &[RelayAck]) -> Result<RelayAckResponse, CoreError> {
        let mut guard = self.entries.lock().await;
        let before = guard.len() as u64;
        guard.retain(|env| {
            if env.envelope.to.to_hex() != recipient {
                return true;
            }
            !ack.iter().any(|ack_entry| {
                ack_entry.message_id == env.envelope.id && ack_entry.chunk_index == env.chunk_index
            })
        });
        let after = guard.len() as u64;
        Ok(RelayAckResponse {
            deleted: before.saturating_sub(after),
            missing: ack
                .len()
                .saturating_sub(before.saturating_sub(after) as usize) as u64,
            remaining: after,
        })
    }
}
