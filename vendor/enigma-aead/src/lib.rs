use thiserror::Error;

#[derive(Debug, Error)]
pub enum AeadError {
    #[error("invalid key")]
    InvalidKey,
    #[error("decryption failed")]
    Decryption,
}

#[derive(Clone)]
pub struct AeadKey {
    key: Vec<u8>,
}

impl AeadKey {
    pub fn new(key: Vec<u8>) -> Result<Self, AeadError> {
        if key.is_empty() {
            return Err(AeadError::InvalidKey);
        }
        Ok(Self { key })
    }

    pub fn seal(&self, plaintext: &[u8], associated_data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(associated_data.len() + plaintext.len());
        out.extend_from_slice(associated_data);
        for (i, byte) in plaintext.iter().enumerate() {
            let k = self.key[i % self.key.len()];
            out.push(byte ^ k);
        }
        out
    }

    pub fn open(&self, ciphertext: &[u8], associated_data_len: usize) -> Result<Vec<u8>, AeadError> {
        if ciphertext.len() < associated_data_len {
            return Err(AeadError::Decryption);
        }
        let mut out = Vec::new();
        for (i, byte) in ciphertext[associated_data_len..].iter().enumerate() {
            let k = self.key[i % self.key.len()];
            out.push(byte ^ k);
        }
        Ok(out)
    }
}
