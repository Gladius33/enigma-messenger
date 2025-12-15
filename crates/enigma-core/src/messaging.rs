use crate::error::CoreError;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone, Debug)]
pub struct TransportMessage {
    pub sender: String,
    pub bytes: Vec<u8>,
}

#[async_trait]
pub trait Transport: Send + Sync {
    async fn send(&self, recipient: String, bytes: Vec<u8>) -> Result<(), CoreError>;
    async fn receive(&self, recipient: &str) -> Result<Vec<TransportMessage>, CoreError>;
}

#[derive(Clone, Default)]
pub struct MockTransport {
    inner: Arc<Mutex<HashMap<String, Vec<TransportMessage>>>>,
}

impl MockTransport {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Transport for MockTransport {
    async fn send(&self, recipient: String, bytes: Vec<u8>) -> Result<(), CoreError> {
        let mut guard = self.inner.lock().await;
        guard.entry(recipient).or_default().push(TransportMessage {
            sender: String::from("peer"),
            bytes,
        });
        Ok(())
    }

    async fn receive(&self, recipient: &str) -> Result<Vec<TransportMessage>, CoreError> {
        let mut guard = self.inner.lock().await;
        let out = guard.remove(recipient).unwrap_or_default();
        Ok(out)
    }
}
