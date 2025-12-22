use serde::{Deserialize, Serialize};

use crate::error::{EnigmaNodeTypesError, Result};
use crate::user_id::UserId;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Presence {
    pub user_id: UserId,
    pub addr: String,
    pub ts_ms: u64,
}

impl Presence {
    pub fn validate(&self) -> Result<()> {
        let trimmed = self.addr.trim();
        if trimmed.is_empty() || trimmed.len() > 256 {
            return Err(EnigmaNodeTypesError::InvalidField("addr"));
        }
        if self.ts_ms == 0 {
            return Err(EnigmaNodeTypesError::InvalidField("ts_ms"));
        }
        Ok(())
    }
}
