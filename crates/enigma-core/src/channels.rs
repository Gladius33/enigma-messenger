use crate::error::CoreError;
use crate::ids::ConversationId as CoreConversationId;
use crate::policy::Policy;
use enigma_api::types::{ChannelDto, ConversationId as ApiConversationId, UserIdHex};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Clone)]
pub struct ChannelState {
    channels: Arc<Mutex<HashMap<String, ChannelDto>>>,
    policy: Policy,
}

impl ChannelState {
    pub fn new(policy: Policy) -> Self {
        Self {
            channels: Arc::new(Mutex::new(HashMap::new())),
            policy,
        }
    }

    pub async fn create(&self, name: String, admin: UserIdHex) -> Result<ChannelDto, CoreError> {
        if name.len() > self.policy.max_channel_name_len {
            return Err(CoreError::Validation("channel_name".to_string()));
        }

        let id = ApiConversationId {
            value: Uuid::new_v4().to_string(),
        };

        let dto = ChannelDto {
            id,
            name,
            admins: vec![admin.clone()],
            subscribers: vec![admin],
        };

        self.channels
            .lock()
            .await
            .insert(dto.id.value.clone(), dto.clone());

        Ok(dto)
    }

    pub async fn add_subscriber(
        &self,
        id: &CoreConversationId,
        user: UserIdHex,
    ) -> Result<(), CoreError> {
        let mut guard = self.channels.lock().await;
        let channel = guard.get_mut(&id.value).ok_or(CoreError::NotFound)?;
        if !channel.subscribers.iter().any(|m| m == &user) {
            channel.subscribers.push(user);
        }
        Ok(())
    }

    pub async fn add_admin(
        &self,
        id: &CoreConversationId,
        user: UserIdHex,
    ) -> Result<(), CoreError> {
        let mut guard = self.channels.lock().await;
        let channel = guard.get_mut(&id.value).ok_or(CoreError::NotFound)?;

        if !channel.admins.iter().any(|m| m == &user) {
            channel.admins.push(user.clone());
        }
        if !channel.subscribers.iter().any(|m| m == &user) {
            channel.subscribers.push(user);
        }
        Ok(())
    }

    pub async fn can_post(&self, id: &CoreConversationId, user: &UserIdHex) -> bool {
        let guard = self.channels.lock().await;
        guard
            .get(&id.value)
            .map(|c| c.admins.iter().any(|a| a == user))
            .unwrap_or(false)
    }

    pub async fn get(&self, id: &CoreConversationId) -> Option<ChannelDto> {
        let guard = self.channels.lock().await;
        guard.get(&id.value).cloned()
    }

    pub async fn len(&self) -> usize {
        self.channels.lock().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }
}
