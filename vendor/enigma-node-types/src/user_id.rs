use blake3::Hasher;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{EnigmaNodeTypesError, Result};

#[derive(Clone, Copy, Eq, PartialEq, Hash, Debug)]
pub struct UserId(pub [u8; 32]);

impl UserId {
    pub fn from_username(username: &str) -> Result<Self> {
        let normalized = normalize_username(username)?;
        let mut hasher = Hasher::new();
        hasher.update(b"enigma:user_id:v1");
        hasher.update(normalized.as_bytes());
        let hash = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(hash.as_bytes());
        Ok(UserId(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        let decoded = hex::decode(s)?;
        if decoded.len() != 32 {
            return Err(EnigmaNodeTypesError::InvalidHex);
        }
        let mut bytes = [0u8; 32];
        for (i, b) in decoded.into_iter().enumerate() {
            bytes[i] = b;
        }
        Ok(UserId(bytes))
    }
}

pub fn normalize_username(username: &str) -> Result<String> {
    if username.chars().any(|c| c.is_control()) {
        return Err(EnigmaNodeTypesError::InvalidUsername);
    }
    let trimmed = username.trim();
    if trimmed.is_empty() {
        return Err(EnigmaNodeTypesError::InvalidUsername);
    }
    if trimmed.len() > 64 {
        return Err(EnigmaNodeTypesError::InvalidUsername);
    }
    Ok(trimmed.to_string())
}

impl Serialize for UserId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

struct UserIdVisitor;

impl<'de> serde::de::Visitor<'de> for UserIdVisitor {
    type Value = UserId;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("32-byte hex string")
    }

    fn visit_str<E>(self, v: &str) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        UserId::from_hex(v).map_err(|_| E::custom("invalid user id hex"))
    }
}

impl<'de> Deserialize<'de> for UserId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(UserIdVisitor)
    }
}
