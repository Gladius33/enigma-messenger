use crate::directory::DeviceInfo;
use crate::envelope_crypto::decrypt_identity_envelope;
use crate::error::CoreError;
use crate::time::now_ms;
use async_trait::async_trait;
use enigma_node_client::{NodeClient, NodeClientConfig};
use enigma_node_types::{canonical_handle, Presence, PublicIdentity, ResolveRequest, MAX_IDENTITY_CIPHERTEXT};
use x25519_dalek::{PublicKey, StaticSecret};
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
        let canonical = canonical_handle(handle);
        if canonical.is_empty() {
            return Err(CoreError::Validation("handle".to_string()));
        }
        Ok(canonical)
    }
}

#[async_trait]
impl DirectoryResolver for NodeDirectoryResolver {
    async fn resolve_handle(&self, handle: &str) -> Result<(String, PublicIdentity), CoreError> {
        let username = Self::normalize_handle(handle)?;
        if let Some(client) = self.client() {
            let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
            let requester = PublicKey::from(&secret).to_bytes();
            let req = ResolveRequest {
                handle: username.clone(),
                requester_ephemeral_public_key: requester,
            };
            let resp = client
                .resolve(req)
                .await
                .map_err(|e| CoreError::Transport(format!("{:?}", e)))?;
            if let Some(envelope) = resp.envelope {
                let plaintext = decrypt_identity_envelope(
                    secret.to_bytes(),
                    None,
                    &envelope,
                    &username,
                    MAX_IDENTITY_CIPHERTEXT,
                    None,
                )
                .map_err(|_| CoreError::Crypto)?;
                let identity: PublicIdentity =
                    serde_json::from_slice(&plaintext).map_err(|_| CoreError::Crypto)?;
                identity
                    .validate()
                    .map_err(|_| CoreError::Validation("identity".to_string()))?;
                return Ok((identity.user_id.to_hex(), identity));
            }
        }
        Err(CoreError::NotFound)
    }

    async fn check_user(&self, handle: &str) -> Result<bool, CoreError> {
        let username = Self::normalize_handle(handle)?;
        if let Some(client) = self.client() {
            let resp = client
                .check_user(&username)
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
