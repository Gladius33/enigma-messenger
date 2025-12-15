use crate::error::CoreError;
use crate::ids::UserId;
use crate::ratchet::RatchetState;
use blake3::Hasher;
use enigma_aead::AeadKey;
use std::collections::HashMap;

pub struct SessionManager {
    local: UserId,
    peers: HashMap<String, RatchetState>,
}

impl SessionManager {
    pub fn new(local: UserId) -> Self {
        Self {
            local,
            peers: HashMap::new(),
        }
    }

    pub fn next_key(&mut self, peer: &UserId) -> Result<AeadKey, CoreError> {
        let key = peer.to_hex();
        let entry = self.peers.entry(key).or_insert_with(|| RatchetState::new(derive_seed(&self.local, peer)));
        entry.next_key()
    }
}

fn derive_seed(local: &UserId, peer: &UserId) -> [u8; 32] {
    let (left, right) = if local.as_bytes() <= peer.as_bytes() { (local, peer) } else { (peer, local) };
    let mut hasher = Hasher::new();
    hasher.update(b"session_seed:v1");
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    hasher.finalize().into()
}
