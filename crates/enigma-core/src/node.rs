use crate::directory::DeviceInfo;
use crate::error::CoreError;
use crate::time::now_ms;
use async_trait::async_trait;
use enigma_node_client::{NodeClient, NodeClientConfig};
use enigma_node_types::{Presence, PublicIdentity, UserId as NodeUserId};
use std::sync::Arc;

#[async_trait]
pub trait DirectoryResolver: Send + Sync {
    async fn resolve_handle(&self, handle: &str) -> Result<(String, PublicIdentity), CoreError>;
    async fn check_user(&self, handle: &str) -> Result<bool, CoreError>;
    async fn announce_presence(&self, identity: &PublicIdentity) -> Result<(), CoreError>;
    async fn resolve_devices(&self, _user_id: &str) -> Result<Vec<DeviceInfo>, CoreError> {
        Ok(Vec::new())
    }
}

#[derive(Clone)]
pub struct NodeDirectoryResolver {
    clients: Vec<Arc<NodeClient>>,
}

impl NodeDirectoryResolver {
    pub fn new(base_urls: &[String]) -> Self {
        let cfg = NodeClientConfig::default();
        let mut clients = Vec::new();
        for url in base_urls.iter() {
            if let Ok(client) = NodeClient::new(url.clone(), cfg.clone()) {
                clients.push(Arc::new(client));
            }
        }
        Self { clients }
    }

    fn client(&self) -> Option<Arc<NodeClient>> {
        self.clients.get(0).cloned()
    }

    fn normalize_handle(handle: &str) -> Result<String, CoreError> {
        let trimmed = handle.trim();
        let value = trimmed.strip_prefix('@').unwrap_or(trimmed);
        if value.is_empty() {
            return Err(CoreError::Validation("handle".to_string()));
        }
        Ok(value.to_string())
    }
}

#[async_trait]
impl DirectoryResolver for NodeDirectoryResolver {
    async fn resolve_handle(&self, handle: &str) -> Result<(String, PublicIdentity), CoreError> {
        let username = Self::normalize_handle(handle)?;
        let user_id = NodeUserId::from_username(&username)
            .map_err(|_| CoreError::Validation("handle".to_string()))?;
        let user_hex = user_id.to_hex();
        if let Some(client) = self.client() {
            let resp = client
                .resolve(&user_hex)
                .await
                .map_err(|e| CoreError::Transport(format!("{:?}", e)))?;
            if let Some(identity) = resp.identity {
                return Ok((user_hex, identity));
            }
        }
        Err(CoreError::NotFound)
    }

    async fn check_user(&self, handle: &str) -> Result<bool, CoreError> {
        let username = Self::normalize_handle(handle)?;
        let user_id = NodeUserId::from_username(&username)
            .map_err(|_| CoreError::Validation("handle".to_string()))?;
        if let Some(client) = self.client() {
            let resp = client
                .check_user(&user_id.to_hex())
                .await
                .map_err(|e| CoreError::Transport(format!("{:?}", e)))?;
            return Ok(resp.exists);
        }
        Ok(false)
    }

    async fn announce_presence(&self, identity: &PublicIdentity) -> Result<(), CoreError> {
        if let Some(client) = self.client() {
            let payload = Presence {
                user_id: identity.user_id,
                addr: client.base_url().to_string(),
                ts_ms: now_ms(),
            };
            let _ = client
                .announce(payload)
                .await
                .map_err(|e| CoreError::Transport(format!("{:?}", e)))?;
        }
        Ok(())
    }

    async fn resolve_devices(&self, _user_id: &str) -> Result<Vec<DeviceInfo>, CoreError> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn normalize_handle_strips_at() {
        let resolver = NodeDirectoryResolver::new(&[]);
        assert_eq!(
            NodeDirectoryResolver::normalize_handle("@alice").unwrap(),
            "alice"
        );
        assert!(resolver.check_user("").await.is_err());
    }
}
