use crate::types::*;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("empty field {0}")]
    Empty(&'static str),
    #[error("too long {0}")]
    TooLong(&'static str),
    #[error("invalid size {0}")]
    InvalidSize(&'static str),
    #[error("missing content for kind")]
    MissingContent,
}

pub fn validate_user_handle(
    handle: &UserHandle,
    limits: &ValidationLimits,
) -> Result<(), ValidationError> {
    if handle.value.trim().is_empty() {
        return Err(ValidationError::Empty("handle"));
    }
    if handle.value.len() > limits.max_name_len {
        return Err(ValidationError::TooLong("handle"));
    }
    Ok(())
}

pub fn validate_user_id(user: &UserIdHex) -> Result<(), ValidationError> {
    if user.value.trim().is_empty() {
        return Err(ValidationError::Empty("user_id"));
    }
    Ok(())
}

pub fn validate_message_request(
    req: &OutgoingMessageRequest,
    limits: &ValidationLimits,
) -> Result<(), ValidationError> {
    validate_user_id(&req.sender)?;
    if req.recipients.is_empty() {
        return Err(ValidationError::Empty("recipients"));
    }
    for recipient in req.recipients.iter() {
        let has_user = recipient
            .recipient_user_id
            .as_ref()
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false);
        let has_handle = recipient
            .recipient_handle
            .as_ref()
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false);
        if has_user == has_handle {
            return Err(ValidationError::InvalidSize("recipient_selector"));
        }
        if let Some(handle) = recipient.recipient_handle.as_ref() {
            if !handle.starts_with('@') {
                return Err(ValidationError::InvalidSize("recipient_handle"));
            }
            let len = handle.len();
            if !(2..=64).contains(&len) {
                return Err(ValidationError::InvalidSize("recipient_handle"));
            }
        }
    }
    if req.text.as_deref().unwrap_or("").len() > limits.max_text_bytes {
        return Err(ValidationError::TooLong("text"));
    }
    match req.kind {
        MessageKind::Text => {
            if req.text.as_ref().map(|v| v.is_empty()).unwrap_or(true) {
                return Err(ValidationError::MissingContent);
            }
        }
        MessageKind::File | MessageKind::Image | MessageKind::Video | MessageKind::Voice => {
            let attachment = req
                .attachment
                .as_ref()
                .ok_or(ValidationError::MissingContent)?;
            if attachment.total_size == 0 {
                return Err(ValidationError::InvalidSize("attachment_size"));
            }
            if req
                .attachment_bytes
                .as_ref()
                .map(|b| b.is_empty())
                .unwrap_or(true)
            {
                return Err(ValidationError::MissingContent);
            }
        }
        _ => {}
    }
    Ok(())
}

pub fn validate_group(group: &GroupDto, limits: &ValidationLimits) -> Result<(), ValidationError> {
    if group.name.trim().is_empty() {
        return Err(ValidationError::Empty("group_name"));
    }
    if group.name.len() > limits.max_name_len {
        return Err(ValidationError::TooLong("group_name"));
    }
    Ok(())
}

pub fn validate_channel(
    channel: &ChannelDto,
    limits: &ValidationLimits,
) -> Result<(), ValidationError> {
    if channel.name.trim().is_empty() {
        return Err(ValidationError::Empty("channel_name"));
    }
    if channel.name.len() > limits.max_name_len {
        return Err(ValidationError::TooLong("channel_name"));
    }
    Ok(())
}
