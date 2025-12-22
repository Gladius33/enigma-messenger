use serde::{Deserialize, Serialize};

use crate::error::{EnigmaNodeTypesError, Result};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NodeInfo {
    pub base_url: String,
}

impl NodeInfo {
    pub fn validate(&self) -> Result<()> {
        let trimmed = self.base_url.trim();
        if trimmed.is_empty() || trimmed.len() > 256 {
            return Err(EnigmaNodeTypesError::InvalidField("base_url"));
        }
        if !(trimmed.starts_with("http://") || trimmed.starts_with("https://")) {
            return Err(EnigmaNodeTypesError::InvalidField("base_url"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NodesPayload {
    pub nodes: Vec<NodeInfo>,
}

impl NodesPayload {
    pub fn validate(&self) -> Result<()> {
        for node in &self.nodes {
            node.validate()?;
        }
        Ok(())
    }
}
