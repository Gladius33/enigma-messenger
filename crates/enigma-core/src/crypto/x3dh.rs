use crate::ids::DeviceId;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum X3dhError {
    InvalidSignedPrekey,
}

#[derive(Clone)]
pub struct IdentityKeyPair {
    pub dh_private: StaticSecret,
    pub dh_public: [u8; 32],
    pub signing: SigningKey,
}

#[derive(Clone)]
pub struct SignedPreKeyPair {
    pub id: u32,
    pub private: StaticSecret,
    pub public: [u8; 32],
    pub signature: Signature,
}

#[derive(Clone)]
pub struct OneTimePreKeyPair {
    pub private: StaticSecret,
    pub public: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreKeyBundlePublic {
    pub version: u8,
    pub device_id: DeviceId,
    pub identity_dh: [u8; 32],
    pub identity_signing: [u8; 32],
    pub signed_prekey: [u8; 32],
    pub signed_prekey_signature: [u8; 64],
    pub one_time_prekey: Option<[u8; 32]>,
    pub signed_prekey_id: u32,
}

#[derive(Clone)]
pub struct EphemeralKeyPair {
    pub private: StaticSecret,
    pub public: [u8; 32],
}

pub struct X3dhOutput {
    pub root_key: [u8; 32],
    pub associated_data: Vec<u8>,
}

pub fn generate_identity_keypair() -> IdentityKeyPair {
    let dh_private = StaticSecret::random_from_rng(OsRng);
    let dh_public = X25519Public::from(&dh_private).to_bytes();
    let signing = SigningKey::generate(&mut OsRng);
    IdentityKeyPair {
        dh_private,
        dh_public,
        signing,
    }
}

pub fn generate_signed_prekey(ik_signing: &SigningKey, id: u32) -> SignedPreKeyPair {
    let private = StaticSecret::random_from_rng(OsRng);
    let public = X25519Public::from(&private).to_bytes();
    let signature = ik_signing.sign(&public);
    SignedPreKeyPair {
        id,
        private,
        public,
        signature,
    }
}

pub fn generate_opk_set(n: usize) -> Vec<OneTimePreKeyPair> {
    (0..n)
        .map(|_| {
            let private = StaticSecret::random_from_rng(OsRng);
            let public = X25519Public::from(&private).to_bytes();
            OneTimePreKeyPair { private, public }
        })
        .collect()
}

pub fn make_prekey_bundle(
    device_id: DeviceId,
    identity: &IdentityKeyPair,
    signed_prekey: &SignedPreKeyPair,
    one_time_prekey: Option<&OneTimePreKeyPair>,
) -> PreKeyBundlePublic {
    PreKeyBundlePublic {
        version: 2,
        device_id,
        identity_dh: identity.dh_public,
        identity_signing: VerifyingKey::from(&identity.signing).to_bytes(),
        signed_prekey: signed_prekey.public,
        signed_prekey_signature: signed_prekey.signature.to_bytes(),
        one_time_prekey: one_time_prekey.map(|k| k.public),
        signed_prekey_id: signed_prekey.id,
    }
}

pub fn x3dh_initiator(
    initiator_identity: &IdentityKeyPair,
    ephemeral: &EphemeralKeyPair,
    recipient_bundle: &PreKeyBundlePublic,
) -> Result<X3dhOutput, X3dhError> {
    verify_signed_prekey(recipient_bundle)?;
    let dh1 = initiator_identity
        .dh_private
        .diffie_hellman(&X25519Public::from(recipient_bundle.signed_prekey));
    let dh2 = ephemeral
        .private
        .diffie_hellman(&X25519Public::from(recipient_bundle.identity_dh));
    let dh3 = ephemeral
        .private
        .diffie_hellman(&X25519Public::from(recipient_bundle.signed_prekey));
    let dh4 = recipient_bundle
        .one_time_prekey
        .map(|opk| ephemeral.private.diffie_hellman(&X25519Public::from(opk)));
    let secret = kdf_x3dh(&[
        dh1.as_bytes(),
        dh2.as_bytes(),
        dh3.as_bytes(),
        dh4.as_ref().map(|d| d.as_bytes()).map_or(&[], |v| v),
    ]);
    let ad = build_ad(
        &recipient_bundle.identity_dh,
        &VerifyingKey::from(&initiator_identity.signing).to_bytes(),
        &initiator_identity.dh_public,
    );
    Ok(X3dhOutput {
        root_key: secret,
        associated_data: ad,
    })
}

pub fn x3dh_responder(
    recipient_identity: &IdentityKeyPair,
    signed_prekey: &SignedPreKeyPair,
    one_time_prekey: Option<&OneTimePreKeyPair>,
    initiator_identity_signing: [u8; 32],
    initiator_identity_dh: [u8; 32],
    initiator_ephemeral: [u8; 32],
) -> Result<X3dhOutput, X3dhError> {
    let dh1 = signed_prekey
        .private
        .diffie_hellman(&X25519Public::from(initiator_identity_dh));
    let dh2 = recipient_identity
        .dh_private
        .diffie_hellman(&X25519Public::from(initiator_ephemeral));
    let dh3 = signed_prekey
        .private
        .diffie_hellman(&X25519Public::from(initiator_ephemeral));
    let dh4 = one_time_prekey.map(|opk| {
        opk.private
            .diffie_hellman(&X25519Public::from(initiator_ephemeral))
    });
    let secret = kdf_x3dh(&[
        dh1.as_bytes(),
        dh2.as_bytes(),
        dh3.as_bytes(),
        dh4.as_ref().map(|d| d.as_bytes()).map_or(&[], |v| v),
    ]);
    let ad = build_ad(
        &recipient_identity.dh_public,
        &initiator_identity_signing,
        &initiator_identity_dh,
    );
    Ok(X3dhOutput {
        root_key: secret,
        associated_data: ad,
    })
}

fn verify_signed_prekey(bundle: &PreKeyBundlePublic) -> Result<(), X3dhError> {
    let verifying = VerifyingKey::from_bytes(&bundle.identity_signing)
        .map_err(|_| X3dhError::InvalidSignedPrekey)?;
    let sig = Signature::from_bytes(&bundle.signed_prekey_signature);
    verifying
        .verify_strict(&bundle.signed_prekey, &sig)
        .map_err(|_| X3dhError::InvalidSignedPrekey)
}

fn kdf_x3dh(inputs: &[&[u8]]) -> [u8; 32] {
    let mut accum = Vec::new();
    for input in inputs {
        accum.extend_from_slice(input);
    }
    let hkdf = Hkdf::<Sha256>::new(None, &accum);
    let mut okm = [0u8; 32];
    let _ = hkdf.expand(b"x3dh", &mut okm);
    okm
}

fn build_ad(
    recipient_identity: &[u8; 32],
    initiator_signing: &[u8; 32],
    initiator_dh: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(recipient_identity);
    out.extend_from_slice(initiator_signing);
    out.extend_from_slice(initiator_dh);
    out
}
