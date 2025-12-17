use crate::error::CoreError;
use crate::ids::ConversationId as CoreConversationId;
use crate::policy::Policy;
use enigma_api::types::{
    ConversationId as ApiConversationId, GroupDto, GroupMember, GroupRole, UserIdHex,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

#[async_trait::async_trait]
pub trait GroupCryptoProvider: Send + Sync {
    async fn distribute(&self, _group: &GroupDto) -> Result<(), CoreError>;
}

pub struct NullGroupCryptoProvider;

#[async_trait::async_trait]
impl GroupCryptoProvider for NullGroupCryptoProvider {
    async fn distribute(&self, _group: &GroupDto) -> Result<(), CoreError> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct GroupState {
    groups: Arc<Mutex<HashMap<String, GroupDto>>>,
    policy: Policy,
    crypto: Arc<dyn GroupCryptoProvider>,
}

impl GroupState {
    pub fn new(policy: Policy, crypto: Arc<dyn GroupCryptoProvider>) -> Self {
        Self {
            groups: Arc::new(Mutex::new(HashMap::new())),
            policy,
            crypto,
        }
    }

    pub async fn create(&self, name: String, owner: UserIdHex) -> Result<GroupDto, CoreError> {
        if name.len() > self.policy.max_group_name_len {
            return Err(CoreError::Validation("group_name".to_string()));
        }
        let id = ApiConversationId {
            value: Uuid::new_v4().to_string(),
        };
        let dto = GroupDto {
            id,
            name,
            members: vec![GroupMember {
                user_id: owner,
                role: GroupRole::Owner,
            }],
        };
        self.groups
            .lock()
            .await
            .insert(dto.id.value.clone(), dto.clone());
        self.crypto.distribute(&dto).await?;
        Ok(dto)
    }

    pub async fn add_member(
        &self,
        id: &CoreConversationId,
        member: GroupMember,
    ) -> Result<(), CoreError> {
        let mut guard = self.groups.lock().await;
        let group = guard.get_mut(&id.value).ok_or(CoreError::NotFound)?;
        if group.members.len() as u32 >= self.policy.max_membership_changes_per_minute {
            return Err(CoreError::Validation("membership_limit".to_string()));
        }
        if !group.members.iter().any(|m| m.user_id == member.user_id) {
            group.members.push(member);
        }
        Ok(())
    }

    pub async fn remove_member(
        &self,
        id: &CoreConversationId,
        user_id: &UserIdHex,
    ) -> Result<(), CoreError> {
        let mut guard = self.groups.lock().await;
        let group = guard.get_mut(&id.value).ok_or(CoreError::NotFound)?;
        group.members.retain(|m| &m.user_id != user_id);
        Ok(())
    }

    pub async fn get(&self, id: &CoreConversationId) -> Option<GroupDto> {
        let guard = self.groups.lock().await;
        guard.get(&id.value).cloned()
    }

    pub async fn len(&self) -> usize {
        self.groups.lock().await.len()
    }
}
