use crate::error::CoreError;
use blake3::Hasher;
use enigma_aead::AeadKey;

#[derive(Clone, Debug)]
pub struct RatchetState {
    seed: [u8; 32],
    counter: u64,
}

impl RatchetState {
    pub fn new(seed: [u8; 32]) -> Self {
        Self { seed, counter: 0 }
    }

    pub fn next_key(&mut self) -> Result<AeadKey, CoreError> {
        self.counter = self.counter.saturating_add(1);
        let mut hasher = Hasher::new();
        hasher.update(&self.seed);
        hasher.update(&self.counter.to_be_bytes());
        let hash = hasher.finalize();
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(hash.as_bytes());
        Ok(AeadKey::new(key_bytes))
    }
}
