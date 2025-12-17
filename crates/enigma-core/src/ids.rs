use blake3::Hasher;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserId {
    bytes: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationId {
    pub value: String,
}

pub type DeviceId = Uuid;

impl UserId {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    pub fn from_hex(hex_str: &str) -> Option<Self> {
        if hex_str.len() % 2 != 0 {
            return None;
        }
        let mut bytes = [0u8; 32];
        let mut idx = 0;
        let mut i = 0;
        while i + 1 < hex_str.len() && idx < 32 {
            let pair = &hex_str[i..i + 2];
            if let Ok(value) = u8::from_str_radix(pair, 16) {
                bytes[idx] = value;
                idx += 1;
            } else {
                return None;
            }
            i += 2;
        }
        if idx != 32 {
            return None;
        }
        Some(Self { bytes })
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl Display for UserId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl ConversationId {
    pub fn new(value: String) -> Self {
        Self { value }
    }
}

pub fn conversation_id_for_dm(a: &UserId, b: &UserId) -> ConversationId {
    let (left, right) = if a.as_bytes() <= b.as_bytes() {
        (a, b)
    } else {
        (b, a)
    };
    let mut hasher = Hasher::new();
    hasher.update(b"enigma:conv:dm:v1");
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    let hash = hasher.finalize();
    ConversationId::new(hash.to_hex().to_string())
}
