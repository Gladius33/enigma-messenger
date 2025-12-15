use async_trait::async_trait;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WebRtcError {
    #[error("disconnected")]
    Disconnected,
}

#[async_trait]
pub trait WebRtcTransport: Send + Sync {
    async fn send(&self, peer: String, data: Vec<u8>) -> Result<(), WebRtcError>;
}

#[derive(Clone, Default)]
pub struct MockWebRtc {
    pub sent: std::sync::Arc<tokio::sync::Mutex<Vec<(String, Vec<u8>)>>>,
}

#[async_trait]
impl WebRtcTransport for MockWebRtc {
    async fn send(&self, peer: String, data: Vec<u8>) -> Result<(), WebRtcError> {
        let mut guard = self.sent.lock().await;
        guard.push((peer, data));
        Ok(())
    }
}
