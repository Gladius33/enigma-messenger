use crate::error::{EnigmaNodeClientError, Result};

pub fn validated_base(base_url: &str) -> Result<String> {
    let trimmed = base_url.trim();
    if !(trimmed.starts_with("http://") || trimmed.starts_with("https://")) {
        return Err(EnigmaNodeClientError::InvalidBaseUrl);
    }
    if trimmed.len() < 8 {
        return Err(EnigmaNodeClientError::InvalidBaseUrl);
    }
    Ok(trimmed.trim_end_matches('/').to_string())
}

pub fn register(base_url: &str) -> Result<String> {
    Ok(format!("{}/register", validated_base(base_url)?))
}

pub fn envelope_pubkey(base_url: &str) -> Result<String> {
    Ok(format!("{}/envelope_pubkey", validated_base(base_url)?))
}

pub fn resolve(base_url: &str) -> Result<String> {
    Ok(format!("{}/resolve", validated_base(base_url)?))
}

pub fn check_user(base_url: &str, handle: &str) -> Result<String> {
    Ok(format!("{}/check_user/{}", validated_base(base_url)?, handle))
}

pub fn announce(base_url: &str) -> Result<String> {
    Ok(format!("{}/announce", validated_base(base_url)?))
}

pub fn sync(base_url: &str) -> Result<String> {
    Ok(format!("{}/sync", validated_base(base_url)?))
}

pub fn nodes_get(base_url: &str) -> Result<String> {
    Ok(format!("{}/nodes", validated_base(base_url)?))
}

pub fn nodes_post(base_url: &str) -> Result<String> {
    Ok(format!("{}/nodes", validated_base(base_url)?))
}
