use crate::identity::{parse_identity_bundle, IdentityBundleV2};
use blake3::Hasher;
use enigma_node_registry::envelope::{EnvelopePublicKey, IdentityEnvelope};
use enigma_node_types::{PublicIdentity, UserId};
use rand::RngCore;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EnvelopeCryptoError {
    #[error("invalid envelope")]
    InvalidEnvelope,
    #[error("invalid key")]
    InvalidKey,
    #[error("aead")]
    Aead,
}

pub fn requester_keypair() -> ([u8; 32], [u8; 32]) {
    let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public = PublicKey::from(&secret);
    (secret.to_bytes(), public.to_bytes())
}

pub fn encrypt_identity_envelope(
    pepper: [u8; 32],
    key: &EnvelopePublicKey,
    identity: &PublicIdentity,
) -> Result<IdentityEnvelope, EnvelopeCryptoError> {
    identity
        .validate()
        .map_err(|_| EnvelopeCryptoError::InvalidEnvelope)?;
    let (kid, registry_pub) = parse_public_key(key)?;
    let sender_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let shared = sender_secret.diffie_hellman(&PublicKey::from(registry_pub));
    let aead_key = derive_aead_key(pepper, identity.user_id.as_bytes(), shared.as_bytes());
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let plaintext =
        serde_json::to_vec(identity).map_err(|_| EnvelopeCryptoError::InvalidEnvelope)?;
    let ciphertext = enigma_aead::seal(aead_key, nonce, &plaintext, identity.user_id.as_bytes())
        .map_err(|_| EnvelopeCryptoError::Aead)?;
    Ok(IdentityEnvelope {
        kid,
        sender_pubkey: PublicKey::from(&sender_secret).to_bytes(),
        nonce,
        ciphertext,
    })
}

pub fn decrypt_identity_envelope(
    pepper: [u8; 32],
    envelope: &IdentityEnvelope,
    requester_secret: [u8; 32],
    handle: &UserId,
) -> Result<ResolvedIdentity, EnvelopeCryptoError> {
    let requester = StaticSecret::from(requester_secret);
    let shared = requester.diffie_hellman(&PublicKey::from(envelope.sender_pubkey));
    let aead_key = derive_aead_key(pepper, handle.as_bytes(), shared.as_bytes());
    let plaintext = enigma_aead::open(
        aead_key,
        envelope.nonce,
        &envelope.ciphertext,
        handle.as_bytes(),
    )
    .map_err(|_| EnvelopeCryptoError::Aead)?;
    let identity: PublicIdentity =
        serde_json::from_slice(&plaintext).map_err(|_| EnvelopeCryptoError::InvalidEnvelope)?;
    identity
        .validate()
        .map_err(|_| EnvelopeCryptoError::InvalidEnvelope)?;
    Ok(ResolvedIdentity {
        public: identity.clone(),
        bundle: parse_identity_bundle(&identity),
    })
}

pub struct ResolvedIdentity {
    pub public: PublicIdentity,
    pub bundle: Option<IdentityBundleV2>,
}

fn parse_public_key(key: &EnvelopePublicKey) -> Result<([u8; 8], [u8; 32]), EnvelopeCryptoError> {
    let kid_bytes = hex::decode(&key.kid_hex).map_err(|_| EnvelopeCryptoError::InvalidKey)?;
    if kid_bytes.len() != 8 {
        return Err(EnvelopeCryptoError::InvalidKey);
    }
    let pub_bytes =
        hex::decode(&key.x25519_public_key_hex).map_err(|_| EnvelopeCryptoError::InvalidKey)?;
    if pub_bytes.len() != 32 {
        return Err(EnvelopeCryptoError::InvalidKey);
    }
    let mut kid = [0u8; 8];
    kid.copy_from_slice(&kid_bytes);
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&pub_bytes);
    Ok((kid, pubkey))
}

fn derive_aead_key(pepper: [u8; 32], handle: &[u8; 32], shared: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"enigma:registry:envelope:v1");
    hasher.update(&pepper);
    hasher.update(handle);
    hasher.update(shared);
    let digest = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(digest.as_bytes());
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use enigma_node_registry::envelope::{EnvelopeCrypto, EnvelopeKey};

    fn test_key() -> EnvelopeKey {
        EnvelopeKey {
            kid: [7u8; 8],
            private: [9u8; 32],
            public: PublicKey::from(&StaticSecret::from([9u8; 32])).to_bytes(),
            active: true,
            not_after: None,
        }
    }

    #[test]
    fn roundtrip_identity_envelope() {
        let key = test_key();
        let pub_key = EnvelopePublicKey {
            kid_hex: hex::encode(key.kid),
            x25519_public_key_hex: hex::encode(key.public),
            active: true,
            not_after_epoch_ms: None,
        };
        let identity = PublicIdentity {
            user_id: UserId::from_hex(
                "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            )
            .unwrap(),
            username_hint: Some("alice".to_string()),
            signing_public_key: vec![1, 2, 3],
            encryption_public_key: vec![4, 5, 6],
            signature: vec![7, 8, 9],
            created_at_ms: 1,
        };
        let pepper = [5u8; 32];
        let envelope = encrypt_identity_envelope(pepper, &pub_key, &identity).expect("encrypt");
        assert_eq!(envelope.kid, key.kid);
    }

    #[test]
    fn decrypts_resolved_identity() {
        let key = test_key();
        let identity = PublicIdentity {
            user_id: UserId::from_hex(
                "101112131415161718191a1b1c1d1e1f0102030405060708090a0b0c0d0e0f10",
            )
            .unwrap(),
            username_hint: Some("bob".to_string()),
            signing_public_key: vec![10, 11, 12],
            encryption_public_key: vec![13, 14, 15],
            signature: vec![16, 17, 18],
            created_at_ms: 2,
        };
        let (req_secret, req_pub) = requester_keypair();
        let crypto = EnvelopeCrypto::new([3u8; 32]);
        let envelope = crypto
            .encrypt_identity_for_peer(&key, &identity.user_id, &identity, req_pub, None, 0)
            .expect("server encrypt");
        let decrypted =
            decrypt_identity_envelope([3u8; 32], &envelope, req_secret, &identity.user_id)
                .expect("decrypt");
        assert_eq!(decrypted.public.user_id, identity.user_id);
    }
}
