use crate::error::CoreError;
use async_trait::async_trait;

#[async_trait]
pub trait MiniAppHost: Send + Sync {
    async fn install(&self, _app_id: &str) -> Result<(), CoreError>;
}

#[async_trait]
pub trait EmailGateway: Send + Sync {
    async fn send_mail(&self, _to: &str, _subject: &str, _body: &str) -> Result<(), CoreError>;
}

#[async_trait]
pub trait CloudSyncBackend: Send + Sync {
    async fn push_blob(&self, _key: &str, _data: Vec<u8>) -> Result<(), CoreError>;
}

pub struct NullExtensions;

#[async_trait]
impl MiniAppHost for NullExtensions {
    async fn install(&self, _app_id: &str) -> Result<(), CoreError> {
        Ok(())
    }
}

#[async_trait]
impl EmailGateway for NullExtensions {
    async fn send_mail(&self, _to: &str, _subject: &str, _body: &str) -> Result<(), CoreError> {
        Ok(())
    }
}

#[async_trait]
impl CloudSyncBackend for NullExtensions {
    async fn push_blob(&self, _key: &str, _data: Vec<u8>) -> Result<(), CoreError> {
        Ok(())
    }
}
