use crate::error::CoreError;
use enigma_aead::AeadKey;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RatchetHeader {
    pub dh_pub: [u8; 32],
    pub pn: u32,
    pub n: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageCiphertext {
    pub header: RatchetHeader,
    pub ciphertext: Vec<u8>,
    pub associated_data: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RatchetState {
    pub version: u8,
    root_key: [u8; 32],
    dh_self: [u8; 32],
    dh_self_private: [u8; 32],
    dh_remote: [u8; 32],
    sending_chain: Option<ChainState>,
    receiving_chain: Option<ChainState>,
    sending_n: u32,
    receiving_n: u32,
    previous_sending_n: u32,
    skipped: HashMap<([u8; 32], u32), [u8; 32]>,
    max_skipped: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainState {
    key: [u8; 32],
    index: u32,
}

impl RatchetState {
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            version: 1,
            root_key: seed,
            dh_self: [0u8; 32],
            dh_self_private: [0u8; 32],
            dh_remote: [0u8; 32],
            sending_chain: Some(ChainState {
                key: seed,
                index: 0,
            }),
            receiving_chain: None,
            sending_n: 0,
            receiving_n: 0,
            previous_sending_n: 0,
            skipped: HashMap::new(),
            max_skipped: 2000,
        }
    }

    pub fn next_key(&mut self) -> Result<AeadKey, CoreError> {
        let chain = self.sending_chain.get_or_insert(ChainState {
            key: self.root_key,
            index: 0,
        });
        let (next_ck, mk) = kdf_chain(chain.key)?;
        chain.key = next_ck;
        chain.index = chain.index.saturating_add(1);
        Ok(AeadKey::new(mk))
    }

    pub fn new_initiator(root_key: [u8; 32], dh_self: StaticSecret, dh_remote: [u8; 32]) -> Self {
        let dh_out = dh_self.diffie_hellman(&X25519Public::from(dh_remote));
        let (root, send_ck, _) = kdf_root(root_key, dh_out.as_bytes());
        Self {
            version: 2,
            root_key: root,
            dh_self: X25519Public::from(&dh_self).to_bytes(),
            dh_self_private: dh_self.to_bytes(),
            dh_remote,
            sending_chain: Some(ChainState {
                key: send_ck,
                index: 0,
            }),
            receiving_chain: None,
            sending_n: 0,
            receiving_n: 0,
            previous_sending_n: 0,
            skipped: HashMap::new(),
            max_skipped: 2000,
        }
    }

    pub fn new_responder(root_key: [u8; 32], dh_self: StaticSecret, dh_remote: [u8; 32]) -> Self {
        let dh_out = dh_self.diffie_hellman(&X25519Public::from(dh_remote));
        let (root, recv_ck, send_ck) = kdf_root(root_key, dh_out.as_bytes());
        Self {
            version: 2,
            root_key: root,
            dh_self: X25519Public::from(&dh_self).to_bytes(),
            dh_self_private: dh_self.to_bytes(),
            dh_remote,
            sending_chain: Some(ChainState {
                key: send_ck,
                index: 0,
            }),
            receiving_chain: Some(ChainState {
                key: recv_ck,
                index: 0,
            }),
            sending_n: 0,
            receiving_n: 0,
            previous_sending_n: 0,
            skipped: HashMap::new(),
            max_skipped: 2000,
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8], ad: &[u8]) -> Result<MessageCiphertext, CoreError> {
        if self.sending_chain.is_none() {
            self.ratchet_step_sending()?;
        }
        let chain = self.sending_chain.as_mut().ok_or(CoreError::Crypto)?;
        let (next_ck, mk) = kdf_chain(chain.key)?;
        chain.key = next_ck;
        let header = RatchetHeader {
            dh_pub: self.dh_self,
            pn: self.previous_sending_n,
            n: chain.index,
        };
        chain.index = chain.index.saturating_add(1);
        self.sending_n = chain.index;
        let aead = enigma_aead::AeadBox::new(mk);
        let ciphertext = aead.encrypt(plaintext, ad).map_err(|_| CoreError::Crypto)?;
        Ok(MessageCiphertext {
            header,
            ciphertext,
            associated_data: ad.to_vec(),
        })
    }

    pub fn decrypt(&mut self, message: &MessageCiphertext) -> Result<Vec<u8>, CoreError> {
        if let Some(skipped) = self
            .skipped
            .remove(&(message.header.dh_pub, message.header.n))
        {
            let aead = enigma_aead::AeadBox::new(skipped);
            return aead
                .decrypt(&message.ciphertext, &message.associated_data)
                .map_err(|_| CoreError::Crypto);
        }
        if message.header.dh_pub != self.dh_remote {
            self.skip_message_keys(message.header.pn)?;
            self.ratchet_step_receiving(message.header.dh_pub)?;
        }
        self.skip_message_keys(message.header.n)?;
        let recv_chain = self.receiving_chain.as_mut().ok_or(CoreError::Crypto)?;
        let (next_ck, mk) = kdf_chain(recv_chain.key)?;
        recv_chain.key = next_ck;
        recv_chain.index = recv_chain.index.saturating_add(1);
        self.receiving_n = recv_chain.index;
        let aead = enigma_aead::AeadBox::new(mk);
        aead.decrypt(&message.ciphertext, &message.associated_data)
            .map_err(|_| CoreError::Crypto)
    }

    fn ratchet_step_receiving(&mut self, remote_pub: [u8; 32]) -> Result<(), CoreError> {
        self.previous_sending_n = self.sending_chain.as_ref().map(|c| c.index).unwrap_or(0);
        self.dh_remote = remote_pub;
        let dh_self = StaticSecret::from(self.dh_self_private);
        let dh_out = dh_self.diffie_hellman(&X25519Public::from(self.dh_remote));
        let (root, recv_ck) = {
            let (rk, recv_ck, _) = kdf_root(self.root_key, dh_out.as_bytes());
            (rk, recv_ck)
        };
        self.root_key = root;
        self.receiving_chain = Some(ChainState {
            key: recv_ck,
            index: 0,
        });
        let new_dh = StaticSecret::random_from_rng(rand::rngs::OsRng);
        self.dh_self = X25519Public::from(&new_dh).to_bytes();
        self.dh_self_private = new_dh.to_bytes();
        let dh_out_send = new_dh.diffie_hellman(&X25519Public::from(self.dh_remote));
        let (root_after, send_ck, _) = kdf_root(self.root_key, dh_out_send.as_bytes());
        self.root_key = root_after;
        self.sending_chain = Some(ChainState {
            key: send_ck,
            index: 0,
        });
        self.sending_n = 0;
        Ok(())
    }

    fn ratchet_step_sending(&mut self) -> Result<(), CoreError> {
        let dh_self = StaticSecret::from(self.dh_self_private);
        let dh_out = dh_self.diffie_hellman(&X25519Public::from(self.dh_remote));
        let (root, send_ck, _) = kdf_root(self.root_key, dh_out.as_bytes());
        self.root_key = root;
        self.sending_chain = Some(ChainState {
            key: send_ck,
            index: 0,
        });
        self.sending_n = 0;
        Ok(())
    }

    fn skip_message_keys(&mut self, until: u32) -> Result<(), CoreError> {
        let mut chain = match self.receiving_chain.clone() {
            Some(c) => c,
            None => return Ok(()),
        };
        if chain.index + self.max_skipped as u32 <= until {
            return Err(CoreError::Crypto);
        }
        while chain.index < until {
            let (next_ck, mk) = kdf_chain(chain.key)?;
            if self.skipped.len() >= self.max_skipped {
                return Err(CoreError::Crypto);
            }
            self.skipped.insert((self.dh_remote, chain.index), mk);
            chain.key = next_ck;
            chain.index = chain.index.saturating_add(1);
        }
        self.receiving_chain = Some(chain);
        Ok(())
    }

    pub fn dh_self(&self) -> [u8; 32] {
        self.dh_self
    }
}

fn kdf_root(root_key: [u8; 32], dh_out: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(&root_key), dh_out);
    let mut okm = [0u8; 96];
    let _ = hk.expand(b"rk", &mut okm);
    let mut rk = [0u8; 32];
    let mut ck1 = [0u8; 32];
    let mut ck2 = [0u8; 32];
    rk.copy_from_slice(&okm[0..32]);
    ck1.copy_from_slice(&okm[32..64]);
    ck2.copy_from_slice(&okm[64..96]);
    (rk, ck1, ck2)
}

fn kdf_chain(chain_key: [u8; 32]) -> Result<([u8; 32], [u8; 32]), CoreError> {
    let hk = Hkdf::<Sha256>::new(Some(&chain_key), &[]);
    let mut okm = [0u8; 64];
    hk.expand(b"ck", &mut okm).map_err(|_| CoreError::Crypto)?;
    let mut next_ck = [0u8; 32];
    let mut mk = [0u8; 32];
    next_ck.copy_from_slice(&okm[0..32]);
    mk.copy_from_slice(&okm[32..64]);
    Ok((next_ck, mk))
}
