use std::convert::TryFrom;

use serde::{Deserialize, Serialize};

use enigma_api::identity_envelope::{
    compute_blind_index, BlindIndex, IdentityEnvelope, KeyId, RegistryEnvelopePublicKey,
};

use crate::error::{EnigmaNodeTypesError, Result};
use crate::user_id::{normalize_username, UserId};

pub const MAX_IDENTITY_CIPHERTEXT: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PublicIdentity {
    pub user_id: UserId,
    pub username_hint: Option<String>,
    pub signing_public_key: Vec<u8>,
    pub encryption_public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub created_at_ms: u64,
}

impl PublicIdentity {
    pub fn validate(&self) -> Result<()> {
        if self.signing_public_key.is_empty() {
            return Err(EnigmaNodeTypesError::InvalidField("signing_public_key"));
        }
        if self.encryption_public_key.is_empty() {
            return Err(EnigmaNodeTypesError::InvalidField("encryption_public_key"));
        }
        if self.signature.is_empty() {
            return Err(EnigmaNodeTypesError::InvalidField("signature"));
        }
        if self.created_at_ms == 0 {
            return Err(EnigmaNodeTypesError::InvalidField("created_at_ms"));
        }
        if let Some(hint) = &self.username_hint {
            normalize_username(hint)?;
        }
        Ok(())
    }
}

pub fn signed_payload(
    username_hint: &str,
    signing_public_key: &[u8],
    encryption_public_key: &[u8],
) -> Vec<u8> {
    let hint_bytes = username_hint.as_bytes();
    let hint_len = match u32::try_from(hint_bytes.len()) {
        Ok(v) => v,
        Err(_) => u32::MAX,
    };
    let signing_len = match u32::try_from(signing_public_key.len()) {
        Ok(v) => v,
        Err(_) => u32::MAX,
    };
    let encryption_len = match u32::try_from(encryption_public_key.len()) {
        Ok(v) => v,
        Err(_) => u32::MAX,
    };
    let mut payload = Vec::with_capacity(
        hint_bytes.len()
            .saturating_add(signing_public_key.len())
            .saturating_add(encryption_public_key.len())
            .saturating_add(12),
    );
    payload.extend_from_slice(&hint_len.to_be_bytes());
    payload.extend_from_slice(hint_bytes);
    payload.extend_from_slice(&signing_len.to_be_bytes());
    payload.extend_from_slice(signing_public_key);
    payload.extend_from_slice(&encryption_len.to_be_bytes());
    payload.extend_from_slice(encryption_public_key);
    payload
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EnvelopePubKey {
    pub kid: KeyId,
    pub public_key: RegistryEnvelopePublicKey,
    #[serde(default)]
    pub blind_salt: Option<[u8; 32]>,
}

impl EnvelopePubKey {
    pub fn validate(&self) -> Result<()> {
        if self.public_key.0.iter().all(|b| *b == 0) {
            return Err(EnigmaNodeTypesError::InvalidField("public_key"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RegisterRequest {
    pub handle: String,
    pub envelope: IdentityEnvelope,
}

impl RegisterRequest {
    pub fn validate(&self, max_ciphertext_len: usize) -> Result<()> {
        normalize_username(&self.handle)?;
        self.envelope
            .validate(max_ciphertext_len)
            .map_err(|_| EnigmaNodeTypesError::InvalidField("envelope"))
    }

    pub fn blind_index(&self, pepper: &[u8; 32]) -> BlindIndex {
        compute_blind_index(&self.handle, pepper)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RegisterResponse {
    pub ok: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ResolveRequest {
    pub handle: String,
    pub requester_ephemeral_public_key: [u8; 32],
}

impl ResolveRequest {
    pub fn validate(&self) -> Result<()> {
        normalize_username(&self.handle)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ResolveResponse {
    pub envelope: Option<IdentityEnvelope>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CheckUserResponse {
    pub exists: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SyncRequest {
    pub entries: Vec<RegisterRequest>,
}

impl SyncRequest {
    pub fn validate(&self, max_ciphertext_len: usize) -> Result<()> {
        for entry in &self.entries {
            entry.validate(max_ciphertext_len)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SyncResponse {
    pub merged: usize,
}
