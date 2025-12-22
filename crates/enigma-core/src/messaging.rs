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
    async fn p2p_ready(&self, recipient: &str) -> bool;
    async fn send_p2p(&self, recipient: &str, bytes: &[u8]) -> Result<(), CoreError>;
    async fn send_relay(&self, recipient: &str, bytes: &[u8]) -> Result<(), CoreError>;
    async fn receive(&self, recipient: &str) -> Result<Vec<TransportMessage>, CoreError>;
}

#[derive(Clone, Default)]
pub struct MockTransport {
    inner: Arc<Mutex<HashMap<String, Vec<TransportMessage>>>>,
    fail_p2p: Arc<Mutex<usize>>,
    fail_relay: Arc<Mutex<usize>>,
    ready: Arc<Mutex<HashMap<String, bool>>>,
}

impl MockTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn set_p2p_ready(&self, recipient: &str, ready: bool) {
        let mut guard = self.ready.lock().await;
        guard.insert(recipient.to_string(), ready);
    }

    pub async fn fail_p2p_times(&self, count: usize) {
        *self.fail_p2p.lock().await = count;
    }

    pub async fn fail_relay_times(&self, count: usize) {
        *self.fail_relay.lock().await = count;
    }
}

#[async_trait]
impl Transport for MockTransport {
    async fn p2p_ready(&self, recipient: &str) -> bool {
        *self.ready.lock().await.get(recipient).unwrap_or(&true)
    }

    async fn send_p2p(&self, recipient: &str, bytes: &[u8]) -> Result<(), CoreError> {
        let mut fail = self.fail_p2p.lock().await;
        if *fail > 0 {
            *fail -= 1;
            return Err(CoreError::Transport("p2p".to_string()));
        }
        let mut guard = self.inner.lock().await;
        guard
            .entry(recipient.to_string())
            .or_default()
            .push(TransportMessage {
                sender: String::from("peer"),
                bytes: bytes.to_vec(),
            });
        Ok(())
    }

    async fn send_relay(&self, recipient: &str, bytes: &[u8]) -> Result<(), CoreError> {
        let mut fail = self.fail_relay.lock().await;
        if *fail > 0 {
            *fail -= 1;
            return Err(CoreError::Transport("relay".to_string()));
        }
        let mut guard = self.inner.lock().await;
        guard
            .entry(recipient.to_string())
            .or_default()
            .push(TransportMessage {
                sender: String::from("relay"),
                bytes: bytes.to_vec(),
            });
        Ok(())
    }

    async fn receive(&self, recipient: &str) -> Result<Vec<TransportMessage>, CoreError> {
        let mut guard = self.inner.lock().await;
        let out = guard.remove(recipient).unwrap_or_default();
        Ok(out)
    }
}
