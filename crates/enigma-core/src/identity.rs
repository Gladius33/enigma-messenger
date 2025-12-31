use crate::crypto::x3dh::{generate_identity_keypair, generate_signed_prekey};
use crate::error::CoreError;
use crate::ids::{DeviceId, UserId};
use crate::time::now_ms;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use enigma_node_types::{PublicIdentity, UserId as NodeUserId};
use enigma_storage::EncryptedStore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use x25519_dalek::StaticSecret;

#[derive(Clone, Debug)]
pub struct LocalIdentity {
    pub device_id: DeviceId,
    pub username_hint: Option<String>,
    pub user_id: UserId,
    pub public_identity: PublicIdentity,
    pub bundle: Option<IdentityBundleV2>,
    signing_secret: Option<[u8; 32]>,
    identity_dh_secret: Option<[u8; 32]>,
    signed_prekey_secret: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityBundleV2 {
    pub user_id_hex: String,
    pub device_id: Uuid,
    pub identity_dh_pub: [u8; 32],
    pub identity_sig_pub: [u8; 32],
    pub signed_prekey_id: u32,
    pub signed_prekey_pub: [u8; 32],
    pub signed_prekey_sig: Vec<u8>,
    pub created_ms: u64,
    pub expires_ms: Option<u64>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "version")]
enum StoredIdentity {
    V1 {
        device_id: Uuid,
        username_hint: Option<String>,
        user_id_hex: String,
    },
    V2(Box<StoredIdentityV2>),
}

impl LocalIdentity {
    pub fn load_or_create(store: &EncryptedStore, user_handle: String) -> Result<Self, CoreError> {
        if let Some(bytes) = store.get("identity").map_err(|_| CoreError::Storage)? {
            if let Ok(stored) = serde_json::from_slice::<StoredIdentity>(&bytes) {
                return Self::from_stored(stored);
            }
            let legacy: StoredIdentityV1 =
                serde_json::from_slice(&bytes).map_err(|_| CoreError::Storage)?;
            return Self::from_stored(StoredIdentity::V1 {
                device_id: legacy.device_id,
                username_hint: legacy.username_hint,
                user_id_hex: legacy.user_id_hex,
            });
        }
        let identity = Self::create_v2(user_handle)?;
        identity.persist(store)?;
        Ok(identity)
    }

    fn create_v2(user_handle: String) -> Result<Self, CoreError> {
        let device_id = Uuid::new_v4();
        let normalized = enigma_node_types::normalize_username(&user_handle)
            .map_err(|_| CoreError::Validation("handle".to_string()))?;
        let node_user = NodeUserId::from_username(&normalized)
            .map_err(|_| CoreError::Validation("handle".to_string()))?;
        let user_hex = node_user.to_hex();
        let user_id =
            UserId::from_hex(&user_hex).ok_or(CoreError::Validation("handle".to_string()))?;
        let identity_keys = generate_identity_keypair();
        let signing_public_key = VerifyingKey::from(&identity_keys.signing).to_bytes();
        let signed_prekey = generate_signed_prekey(&identity_keys.signing, 1);
        let spk_sig = sign_prekey(&identity_keys.signing, &signed_prekey.public).to_vec();
        let bundle = IdentityBundleV2 {
            user_id_hex: user_hex.clone(),
            device_id,
            identity_dh_pub: identity_keys.dh_public,
            identity_sig_pub: signing_public_key,
            signed_prekey_id: signed_prekey.id,
            signed_prekey_pub: signed_prekey.public,
            signed_prekey_sig: spk_sig,
            created_ms: now_ms(),
            expires_ms: None,
        };
        Ok(Self {
            device_id: DeviceId::new(device_id),
            username_hint: Some(normalized.clone()),
            user_id,
            public_identity: PublicIdentity {
                user_id: node_user,
                username_hint: Some(normalized),
                signing_public_key: signing_public_key.to_vec(),
                encryption_public_key: identity_keys.dh_public.to_vec(),
                signature: encode_v2_signature(&bundle)?,
                created_at_ms: bundle.created_ms,
            },
            bundle: Some(bundle),
            signing_secret: Some(identity_keys.signing.to_bytes()),
            identity_dh_secret: Some(identity_keys.dh_private.to_bytes()),
            signed_prekey_secret: Some(signed_prekey.private.to_bytes()),
        })
    }

    pub fn persist(&self, store: &EncryptedStore) -> Result<(), CoreError> {
        let stored = if let Some(bundle) = &self.bundle {
            StoredIdentity::V2(Box::new(StoredIdentityV2 {
                device_id: self.device_id.as_uuid(),
                username_hint: self.username_hint.clone(),
                user_id_hex: self.user_id.to_hex(),
                identity_dh_private: self.identity_dh_secret.ok_or(CoreError::Storage)?,
                identity_dh_public: bundle.identity_dh_pub,
                identity_signing_private: self.signing_secret.ok_or(CoreError::Storage)?,
                identity_signing_public: bundle.identity_sig_pub,
                signed_prekey_id: bundle.signed_prekey_id,
                signed_prekey_private: self.signed_prekey_secret.ok_or(CoreError::Storage)?,
                signed_prekey_public: bundle.signed_prekey_pub,
                signed_prekey_signature: bundle.signed_prekey_sig.clone(),
                created_ms: bundle.created_ms,
                expires_ms: bundle.expires_ms,
            }))
        } else {
            StoredIdentity::V1 {
                device_id: self.device_id.as_uuid(),
                username_hint: self.username_hint.clone(),
                user_id_hex: self.user_id.to_hex(),
            }
        };
        let bytes = serde_json::to_vec(&stored).map_err(|_| CoreError::Storage)?;
        store
            .put("identity", &bytes)
            .map_err(|_| CoreError::Storage)
    }

    fn from_stored(stored: StoredIdentity) -> Result<Self, CoreError> {
        match stored {
            StoredIdentity::V1 {
                device_id,
                username_hint,
                user_id_hex,
            } => {
                let user_id = UserId::from_hex(&user_id_hex).ok_or(CoreError::Storage)?;
                let node_user =
                    NodeUserId::from_hex(&user_id_hex).map_err(|_| CoreError::Storage)?;
                let signing_public_key = user_id.as_bytes().to_vec();
                Ok(Self {
                    device_id: DeviceId::new(device_id),
                    username_hint: username_hint.clone(),
                    user_id,
                    public_identity: PublicIdentity {
                        user_id: node_user,
                        username_hint,
                        signing_public_key: signing_public_key.clone(),
                        encryption_public_key: signing_public_key.clone(),
                        signature: signing_public_key,
                        created_at_ms: now_ms(),
                    },
                    bundle: None,
                    signing_secret: None,
                    identity_dh_secret: None,
                    signed_prekey_secret: None,
                })
            }
            StoredIdentity::V2(data) => {
                let username_hint_clone = data.username_hint.clone();
                let user_id = UserId::from_hex(&data.user_id_hex).ok_or(CoreError::Storage)?;
                let node_user =
                    NodeUserId::from_hex(&data.user_id_hex).map_err(|_| CoreError::Storage)?;
                let bundle = IdentityBundleV2 {
                    user_id_hex: data.user_id_hex.clone(),
                    device_id: data.device_id,
                    identity_dh_pub: data.identity_dh_public,
                    identity_sig_pub: data.identity_signing_public,
                    signed_prekey_id: data.signed_prekey_id,
                    signed_prekey_pub: data.signed_prekey_public,
                    signed_prekey_sig: data.signed_prekey_signature.clone(),
                    created_ms: data.created_ms,
                    expires_ms: data.expires_ms,
                };
                Ok(Self {
                    device_id: DeviceId::new(data.device_id),
                    username_hint: data.username_hint,
                    user_id,
                    public_identity: PublicIdentity {
                        user_id: node_user,
                        username_hint: username_hint_clone,
                        signing_public_key: data.identity_signing_public.to_vec(),
                        encryption_public_key: data.identity_dh_public.to_vec(),
                        signature: encode_v2_signature(&bundle)?,
                        created_at_ms: data.created_ms,
                    },
                    bundle: Some(bundle),
                    signing_secret: Some(data.identity_signing_private),
                    identity_dh_secret: Some(data.identity_dh_private),
                    signed_prekey_secret: Some(data.signed_prekey_private),
                })
            }
        }
    }

    pub fn x3dh_bundle(&self) -> Option<IdentityBundleV2> {
        self.bundle.clone()
    }

    pub fn signing_key(&self) -> Option<SigningKey> {
        self.signing_secret.as_ref().map(SigningKey::from_bytes)
    }

    pub fn identity_dh_private(&self) -> Option<StaticSecret> {
        self.identity_dh_secret.map(StaticSecret::from)
    }

    pub fn signed_prekey_private(&self) -> Option<StaticSecret> {
        self.signed_prekey_secret.map(StaticSecret::from)
    }
}

#[derive(Serialize, Deserialize)]
struct StoredIdentityV1 {
    device_id: Uuid,
    username_hint: Option<String>,
    user_id_hex: String,
}

#[derive(Serialize, Deserialize)]
struct StoredIdentityV2 {
    device_id: Uuid,
    username_hint: Option<String>,
    user_id_hex: String,
    identity_dh_private: [u8; 32],
    identity_dh_public: [u8; 32],
    identity_signing_private: [u8; 32],
    identity_signing_public: [u8; 32],
    signed_prekey_id: u32,
    signed_prekey_private: [u8; 32],
    signed_prekey_public: [u8; 32],
    signed_prekey_signature: Vec<u8>,
    created_ms: u64,
    expires_ms: Option<u64>,
}

const BUNDLE_PREFIX: &[u8] = b"enigma-id-v2:";
pub const SIGN_CONTEXT: &[u8] = b"enigma:x3dh:spk:v1";

fn encode_v2_signature(bundle: &IdentityBundleV2) -> Result<Vec<u8>, CoreError> {
    let mut out = Vec::with_capacity(BUNDLE_PREFIX.len() + 256);
    out.extend_from_slice(BUNDLE_PREFIX);
    let payload = serde_json::to_vec(bundle).map_err(|_| CoreError::Crypto)?;
    out.extend_from_slice(&payload);
    Ok(out)
}

pub fn parse_identity_bundle(identity: &PublicIdentity) -> Option<IdentityBundleV2> {
    if identity.signature.len() < BUNDLE_PREFIX.len() {
        return None;
    }
    if identity.signature[..BUNDLE_PREFIX.len()] != *BUNDLE_PREFIX {
        return None;
    }
    let payload = &identity.signature[BUNDLE_PREFIX.len()..];
    let parsed: IdentityBundleV2 = serde_json::from_slice(payload).ok()?;
    if parsed.user_id_hex != identity.user_id.to_hex() {
        return None;
    }
    Some(parsed)
}

pub fn verify_signed_prekey(bundle: &IdentityBundleV2) -> bool {
    let vk = match VerifyingKey::from_bytes(&bundle.identity_sig_pub) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let sig_bytes: [u8; 64] = match bundle.signed_prekey_sig.clone().try_into() {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    let sig = Signature::from_bytes(&sig_bytes);
    let message = sign_context_message(&bundle.signed_prekey_pub);
    vk.verify_strict(&message, &sig).is_ok()
}

fn sign_context_message(spk_pub: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(SIGN_CONTEXT.len() + spk_pub.len());
    out.extend_from_slice(SIGN_CONTEXT);
    out.extend_from_slice(spk_pub);
    out
}

pub fn sign_prekey(signing: &SigningKey, spk_pub: &[u8; 32]) -> [u8; 64] {
    let message = sign_context_message(spk_pub);
    signing.sign(&message).to_bytes()
}
