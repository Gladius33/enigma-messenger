use crate::directory::RegistryClient;
use crate::envelope_crypto::{decrypt_identity_envelope, requester_keypair};
use crate::error::CoreError;
use crate::time::now_ms;
use async_trait::async_trait;
use enigma_node_types::{Presence, PublicIdentity, UserId};
use std::sync::Arc;

#[async_trait]
pub trait DirectoryResolver: Send + Sync {
    async fn resolve_handle(&self, handle: &str) -> Result<(String, PublicIdentity), CoreError>;
    async fn check_user(&self, handle: &str) -> Result<bool, CoreError>;
    async fn announce_presence(&self, identity: &PublicIdentity) -> Result<(), CoreError>;
    async fn resolve_devices(
        &self,
        _user_id: &str,
    ) -> Result<Vec<crate::directory::DeviceInfo>, CoreError> {
        Ok(Vec::new())
    }
}

#[derive(Clone)]
pub struct RegistryDirectoryResolver {
    registry: Arc<dyn RegistryClient>,
    pepper: [u8; 32],
}

impl RegistryDirectoryResolver {
    pub fn new(registry: Arc<dyn RegistryClient>, pepper: [u8; 32]) -> Self {
        Self { registry, pepper }
    }

    fn normalize_handle(handle: &str) -> Result<String, CoreError> {
        enigma_node_types::normalize_username(handle)
            .map_err(|_| CoreError::Validation("handle".to_string()))
    }

    fn user_id_for(handle: &str) -> Result<UserId, CoreError> {
        let normalized = Self::normalize_handle(handle)?;
        UserId::from_username(&normalized).map_err(|_| CoreError::Validation("handle".to_string()))
    }

    fn resolve_handle_to_user_id(handle: &str) -> Result<UserId, CoreError> {
        if let Ok(id) = UserId::from_hex(handle) {
            return Ok(id);
        }
        Self::user_id_for(handle)
    }
}

#[async_trait]
impl DirectoryResolver for RegistryDirectoryResolver {
    async fn resolve_handle(&self, handle: &str) -> Result<(String, PublicIdentity), CoreError> {
        let user_id = Self::resolve_handle_to_user_id(handle)?;
        let (secret, pubkey) = requester_keypair();
        let envelope = self
            .registry
            .resolve(&user_id.to_hex(), pubkey)
            .await
            .map_err(|_| CoreError::Transport("resolve".to_string()))?;
        let Some(env) = envelope else {
            return Err(CoreError::NotFound);
        };
        let identity = decrypt_identity_envelope(self.pepper, &env, secret, &user_id)
            .map_err(|_| CoreError::Crypto)?;
        Ok((user_id.to_hex(), identity))
    }

    async fn check_user(&self, handle: &str) -> Result<bool, CoreError> {
        let user_id = Self::resolve_handle_to_user_id(handle)?;
        self.registry
            .check_user(&user_id.to_hex())
            .await
            .map_err(|_| CoreError::Transport("check_user".to_string()))
    }

    async fn announce_presence(&self, identity: &PublicIdentity) -> Result<(), CoreError> {
        let addr = self
            .registry
            .endpoints()
            .get(0)
            .cloned()
            .unwrap_or_else(|| "local".to_string());
        let presence = Presence {
            user_id: identity.user_id,
            addr,
            ts_ms: now_ms(),
        };
        self.registry
            .announce_presence(presence)
            .await
            .map_err(|_| CoreError::Transport("announce".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::InMemoryRegistry;

    #[tokio::test]
    async fn normalizes_handle_and_checks_user() {
        let registry = Arc::new(InMemoryRegistry::new());
        let resolver =
            RegistryDirectoryResolver::new(registry.clone(), registry.envelope_pepper().unwrap());
        assert!(resolver.check_user("").await.is_err());
        let user_id = UserId::from_username("alice").unwrap();
        let envelope = crate::envelope_crypto::encrypt_identity_envelope(
            registry.envelope_pepper().unwrap(),
            &registry.envelope_key().await.unwrap(),
            &PublicIdentity {
                user_id,
                username_hint: Some("alice".to_string()),
                signing_public_key: vec![1],
                encryption_public_key: vec![1],
                signature: vec![1],
                created_at_ms: now_ms(),
            },
        )
        .unwrap();
        let _ = registry
            .register(&user_id.to_hex(), envelope)
            .await
            .unwrap();
        assert!(resolver.check_user("alice").await.unwrap());
    }
}
