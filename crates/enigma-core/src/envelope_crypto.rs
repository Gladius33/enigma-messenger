use blake3::Hasher;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use ed25519_dalek::{Signer, Verifier};
use enigma_api::identity_envelope::{canonical_handle, BlindIndex, IdentityEnvelope, KeyId};
use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

const CONTEXT: &[u8] = b"enigma:identity-envelope:v1";
pub const ENVELOPE_VERSION: u8 = 1;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EnvelopeCryptoError {
    #[error("invalid envelope")]
    InvalidEnvelope,
    #[error("key mismatch")]
    KeyMismatch,
    #[error("derive")]
    Derive,
    #[error("aead")]
    Aead,
    #[error("signature")]
    Signature,
}

pub fn derive_aead_key(shared_secret: [u8; 32], context: &[u8]) -> Result<[u8; 32], EnvelopeCryptoError> {
    let hkdf = Hkdf::<Sha256>::new(None, &shared_secret);
    let mut out = [0u8; 32];
    hkdf.expand(context, &mut out)
        .map_err(|_| EnvelopeCryptoError::Derive)?;
    Ok(out)
}

fn envelope_ad(
    version: u8,
    kid: &KeyId,
    blind_index: &BlindIndex,
    ephemeral_public_key: &[u8; 32],
    nonce: &[u8; 24],
    handle: &str,
) -> Vec<u8> {
    let canonical = canonical_handle(handle);
    let mut ad = Vec::with_capacity(1 + 8 + 32 + 32 + 24 + canonical.len());
    ad.push(version);
    ad.extend_from_slice(&kid.0);
    ad.extend_from_slice(&blind_index.0);
    ad.extend_from_slice(ephemeral_public_key);
    ad.extend_from_slice(nonce);
    ad.extend_from_slice(canonical.as_bytes());
    ad
}

fn signature_message(aad: &[u8], ciphertext: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(aad);
    hasher.update(ciphertext);
    *hasher.finalize().as_bytes()
}

fn sign_envelope(ad: &[u8], ciphertext: &[u8], signer: &SigningKey) -> Vec<u8> {
    let digest = signature_message(ad, ciphertext);
    signer.sign(&digest).to_bytes().to_vec()
}

fn verify_signature(
    ad: &[u8],
    ciphertext: &[u8],
    signature: &[u8],
    verifier: &VerifyingKey,
) -> Result<(), EnvelopeCryptoError> {
    let digest = signature_message(ad, ciphertext);
    let sig = Signature::from_slice(signature).map_err(|_| EnvelopeCryptoError::Signature)?;
    verifier
        .verify(&digest, &sig)
        .map_err(|_| EnvelopeCryptoError::Signature)
}

pub fn encrypt_identity_envelope(
    registry_public_key: [u8; 32],
    kid: KeyId,
    blind_index: BlindIndex,
    nonce: [u8; 24],
    handle: &str,
    plaintext: &[u8],
    signer: Option<&SigningKey>,
) -> Result<IdentityEnvelope, EnvelopeCryptoError> {
    let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let shared = secret
        .diffie_hellman(&PublicKey::from(registry_public_key))
        .to_bytes();
    let key = derive_aead_key(shared, CONTEXT)?;
    let ephemeral_public_key = PublicKey::from(&secret).to_bytes();
    let ad = envelope_ad(ENVELOPE_VERSION, &kid, &blind_index, &ephemeral_public_key, &nonce, handle);
    let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|_| EnvelopeCryptoError::InvalidEnvelope)?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &ad,
            },
        )
        .map_err(|_| EnvelopeCryptoError::Aead)?;
    let signature = signer.map(|s| sign_envelope(&ad, &ciphertext, s));
    Ok(IdentityEnvelope {
        version: ENVELOPE_VERSION,
        kid,
        blind_index,
        ephemeral_public_key,
        nonce,
        ciphertext,
        signature,
    })
}

pub fn decrypt_identity_envelope(
    registry_private_key: [u8; 32],
    expected_kid: Option<&KeyId>,
    envelope: &IdentityEnvelope,
    handle: &str,
    max_ciphertext_len: usize,
    verifier: Option<&VerifyingKey>,
) -> Result<Vec<u8>, EnvelopeCryptoError> {
    if let Some(kid) = expected_kid {
        if kid != &envelope.kid {
            return Err(EnvelopeCryptoError::KeyMismatch);
        }
    }
    envelope
        .validate(max_ciphertext_len)
        .map_err(|_| EnvelopeCryptoError::InvalidEnvelope)?;
    if envelope.version != ENVELOPE_VERSION {
        return Err(EnvelopeCryptoError::InvalidEnvelope);
    }
    let secret = StaticSecret::from(registry_private_key);
    let shared = secret
        .diffie_hellman(&PublicKey::from(envelope.ephemeral_public_key))
        .to_bytes();
    let key = derive_aead_key(shared, CONTEXT)?;
    let ad = envelope_ad(
        envelope.version,
        &envelope.kid,
        &envelope.blind_index,
        &envelope.ephemeral_public_key,
        &envelope.nonce,
        handle,
    );
    if let (Some(signature), Some(vk)) = (&envelope.signature, verifier) {
        verify_signature(&ad, &envelope.ciphertext, signature, vk)?;
    }
    let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|_| EnvelopeCryptoError::InvalidEnvelope)?;
    cipher
        .decrypt(
            XNonce::from_slice(&envelope.nonce),
            Payload {
                msg: envelope.ciphertext.as_slice(),
                aad: &ad,
            },
        )
        .map_err(|_| EnvelopeCryptoError::Aead)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn envelope_roundtrip() {
        let registry_secret = [9u8; 32];
        let registry_public = PublicKey::from(&StaticSecret::from(registry_secret)).to_bytes();
        let blind_index = BlindIndex([1; 32]);
        let kid = KeyId([2; 8]);
        let nonce = [3u8; 24];
        let plaintext = b"identity-bytes";
        let signer = SigningKey::from_bytes(&[4u8; 32]);
        let verifier = VerifyingKey::from(&signer);
        let envelope = encrypt_identity_envelope(
            registry_public,
            kid.clone(),
            blind_index.clone(),
            nonce,
            "@Alice",
            plaintext,
            Some(&signer),
        )
        .expect("encrypt");
        assert_eq!(envelope.kid, kid);
        assert_eq!(envelope.blind_index, blind_index);
        let decrypted = decrypt_identity_envelope(
            registry_secret,
            Some(&kid),
            &envelope,
            "alice",
            1024,
            Some(&verifier),
        )
        .expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn rejects_wrong_kid() {
        let registry_secret = [5u8; 32];
        let registry_public = PublicKey::from(&StaticSecret::from(registry_secret)).to_bytes();
        let kid = KeyId([7; 8]);
        let envelope = encrypt_identity_envelope(
            registry_public,
            kid.clone(),
            BlindIndex([8; 32]),
            [9; 24],
            "user",
            b"body",
            None,
        )
        .expect("encrypt");
        let wrong = KeyId([1; 8]);
        let err = decrypt_identity_envelope(registry_secret, Some(&wrong), &envelope, "user", 128, None)
            .unwrap_err();
        assert_eq!(err, EnvelopeCryptoError::KeyMismatch);
    }

    #[test]
    fn detects_tampering() {
        let registry_secret = [11u8; 32];
        let registry_public = PublicKey::from(&StaticSecret::from(registry_secret)).to_bytes();
        let signer = SigningKey::from_bytes(&[12u8; 32]);
        let verifier = VerifyingKey::from(&signer);
        let mut envelope = encrypt_identity_envelope(
            registry_public,
            KeyId([2; 8]),
            BlindIndex([3; 32]),
            [4; 24],
            "user",
            b"body",
            Some(&signer),
        )
        .expect("encrypt");
        envelope.ciphertext[0] ^= 0xFF;
        let err = decrypt_identity_envelope(
            registry_secret,
            None,
            &envelope,
            "user",
            128,
            Some(&verifier),
        )
        .unwrap_err();
        assert_eq!(err, EnvelopeCryptoError::Signature);
    }
}
