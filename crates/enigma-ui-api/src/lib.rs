use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const API_VERSION: u16 = 1;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ApiMeta {
    pub api_version: u16,
    pub request_id: Uuid,
    pub timestamp_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ApiError {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ApiResponse<T> {
    pub meta: ApiMeta,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiError>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct IdentityInfo {
    pub user_id: String,
    pub handle: Option<String>,
    pub devices: Vec<DeviceInfo>,
    pub has_bundle_v2: bool,
    pub created_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DeviceInfo {
    pub device_id: String,
    pub last_seen_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ContactDto {
    pub user_id: String,
    pub handle: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub last_seen_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum ConversationKind {
    Direct,
    Group,
    Channel,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ConversationDto {
    pub id: String,
    pub kind: ConversationKind,
    pub title: Option<String>,
    #[serde(default)]
    pub members: Vec<String>,
    pub unread_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_message: Option<MessageDto>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MessageDto {
    pub id: String,
    pub conversation_id: String,
    pub sender: String,
    pub sent_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edited_ms: Option<u64>,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_preview: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachments_meta: Option<serde_json::Value>,
    pub status: MessageStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum MessageStatus {
    Pending,
    Sent,
    Delivered,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SendMessageRequest {
    pub conversation_id: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SendMessageResponse {
    pub message_id: String,
    pub status: MessageStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SyncRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SyncResponse {
    pub events: Vec<Event>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum Event {
    Message(MessageDto),
    ContactAdded(ContactDto),
}
