use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserHandle {
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserIdHex {
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationId {
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageId {
    pub value: Uuid,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentId {
    pub value: Uuid,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentDescriptor {
    pub id: AttachmentId,
    pub filename: Option<String>,
    pub content_type: String,
    pub total_size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum MessageKind {
    Text,
    File,
    Image,
    Video,
    Voice,
    System,
    CallSignal,
    ChannelPost,
    GroupEvent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ReceiptStatus {
    Pending,
    Delivered,
    Read,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutgoingRecipient {
    pub recipient_user_id: Option<String>,
    pub recipient_handle: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutgoingMessageRequest {
    pub client_message_id: MessageId,
    pub conversation_id: ConversationId,
    pub sender: UserIdHex,
    pub recipients: Vec<OutgoingRecipient>,
    pub kind: MessageKind,
    pub text: Option<String>,
    pub attachment: Option<AttachmentDescriptor>,
    pub attachment_bytes: Option<Vec<u8>>,
    pub ephemeral_expiry_secs: Option<u64>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncomingMessageEvent {
    pub message_id: MessageId,
    pub conversation_id: ConversationId,
    pub sender: UserIdHex,
    pub device_id: Option<String>,
    pub kind: MessageKind,
    pub text: Option<String>,
    pub attachment: Option<AttachmentDescriptor>,
    pub timestamp: u64,
    pub receipt: ReceiptStatus,
    pub edited: bool,
    pub deleted: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum GroupRole {
    Owner,
    Admin,
    Member,
    ReadOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupMember {
    pub user_id: UserIdHex,
    pub role: GroupRole,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupDto {
    pub id: ConversationId,
    pub name: String,
    pub members: Vec<GroupMember>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelDto {
    pub id: ConversationId,
    pub name: String,
    pub admins: Vec<UserIdHex>,
    pub subscribers: Vec<UserIdHex>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationLimits {
    pub max_text_bytes: usize,
    pub max_name_len: usize,
}

impl Default for ValidationLimits {
    fn default() -> Self {
        Self {
            max_text_bytes: 256 * 1024,
            max_name_len: 64,
        }
    }
}

impl UserHandle {
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
        }
    }
}

impl UserIdHex {
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
        }
    }
}

impl ConversationId {
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
        }
    }
}

impl MessageId {
    pub fn random() -> Self {
        Self {
            value: Uuid::new_v4(),
        }
    }
}

impl AttachmentId {
    pub fn random() -> Self {
        Self {
            value: Uuid::new_v4(),
        }
    }
}
