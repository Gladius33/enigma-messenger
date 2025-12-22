use blake3::Hasher;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlindIndex(pub [u8; 32]);

impl std::fmt::Display for BlindIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyId(pub [u8; 8]);

impl std::fmt::Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryEnvelopePublicKey(pub [u8; 32]);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityEnvelope {
    pub version: u8,
    pub kid: KeyId,
    pub blind_index: BlindIndex,
    pub ephemeral_public_key: [u8; 32],
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
    pub signature: Option<Vec<u8>>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IdentityEnvelopeError {
    #[error("invalid version")]
    InvalidVersion,
    #[error("invalid ciphertext")]
    InvalidCiphertext,
    #[error("invalid signature")]
    InvalidSignature,
}

impl IdentityEnvelope {
    pub fn validate(&self, max_ciphertext_len: usize) -> Result<(), IdentityEnvelopeError> {
        if self.version == 0 {
            return Err(IdentityEnvelopeError::InvalidVersion);
        }
        if self.ciphertext.is_empty() || self.ciphertext.len() > max_ciphertext_len {
            return Err(IdentityEnvelopeError::InvalidCiphertext);
        }
        if self
            .signature
            .as_ref()
            .map(|s| s.is_empty())
            .unwrap_or(false)
        {
            return Err(IdentityEnvelopeError::InvalidSignature);
        }
        Ok(())
    }
}

pub fn canonical_handle(input: &str) -> String {
    let trimmed = input.trim();
    let stripped = trimmed.trim_start_matches('@');
    stripped.to_lowercase()
}

pub fn compute_blind_index(handle: &str, pepper: &[u8; 32]) -> BlindIndex {
    let canonical = canonical_handle(handle);
    let mut hasher = Hasher::new_keyed(pepper);
    hasher.update(canonical.as_bytes());
    let hash = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(hash.as_bytes());
    BlindIndex(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes_handle() {
        assert_eq!(canonical_handle("  @Alice "), "alice");
        assert_eq!(canonical_handle("Bob"), "bob");
    }

    #[test]
    fn computes_blind_index_deterministically() {
        let pepper = [7u8; 32];
        let first = compute_blind_index("@User", &pepper);
        let second = compute_blind_index("user", &pepper);
        assert_eq!(first, second);
        let third = compute_blind_index("other", &pepper);
        assert_ne!(first, third);
    }

    #[test]
    fn validates_envelope() {
        let env = IdentityEnvelope {
            version: 1,
            kid: KeyId([1; 8]),
            blind_index: BlindIndex([2; 32]),
            ephemeral_public_key: [3; 32],
            nonce: [4; 24],
            ciphertext: vec![5, 6],
            signature: None,
        };
        assert!(env.validate(16).is_ok());
        let mut bad = env.clone();
        bad.ciphertext.clear();
        assert!(bad.validate(16).is_err());
        let mut bad_sig = env.clone();
        bad_sig.signature = Some(Vec::new());
        assert!(bad_sig.validate(16).is_err());
    }
}
