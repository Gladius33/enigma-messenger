use crate::crypto::x3dh::{
    x3dh_initiator, x3dh_responder, EphemeralKeyPair, IdentityKeyPair, PreKeyBundlePublic,
    SignedPreKeyPair, X3dhOutput,
};
use crate::error::CoreError;
use crate::identity::{IdentityBundleV2, LocalIdentity};
use crate::ids::{DeviceId, UserId};
use crate::ratchet::{MessageCiphertext, RatchetHeader, RatchetState};
use ed25519_dalek::{Signature, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DrHeader {
    pub version: u8,
    pub dh_pub: [u8; 32],
    pub pn: u32,
    pub n: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrekeyHeader {
    pub version: u8,
    pub spk_id: u32,
    pub ek_pub: [u8; 32],
    pub ik_pub: [u8; 32],
    pub sig_pub: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PacketV2 {
    pub conversation_id: String,
    pub message_id: uuid::Uuid,
    pub kind: String,
    pub header: DrHeader,
    pub prekey: Option<PrekeyHeader>,
    pub ciphertext: Vec<u8>,
    pub associated_data: Vec<u8>,
    pub device_id: Option<uuid::Uuid>,
    pub target_device_id: Option<uuid::Uuid>,
    pub sender: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DrSession {
    pub state: RatchetState,
    pub ad: Vec<u8>,
}

pub struct ProtoV2Manager {
    local_identity: LocalIdentity,
    store: Arc<Mutex<enigma_storage::EncryptedStore>>,
    sessions: HashMap<SessionKey, DrSession>,
}

impl ProtoV2Manager {
    pub fn new(identity: LocalIdentity, store: Arc<Mutex<enigma_storage::EncryptedStore>>) -> Self {
        Self {
            local_identity: identity,
            store,
            sessions: HashMap::new(),
        }
    }

    pub async fn encrypt(
        &mut self,
        recipient: &UserId,
        device: &DeviceId,
        bundle: &IdentityBundleV2,
        plaintext: &[u8],
        ad: &[u8],
    ) -> Result<(MessageCiphertext, Option<PrekeyHeader>), CoreError> {
        let key = SessionKey {
            user_id: recipient.to_hex(),
            device_id: device.clone(),
        };
        if !self.sessions.contains_key(&key) {
            if let Some(session) = self.load_session(&key).await? {
                self.sessions.insert(key.clone(), session);
            }
        }

        if !self.sessions.contains_key(&key) {
            let session = self.bootstrap_initiator(bundle)?;
            self.sessions.insert(key.clone(), session);
        }

        let session = self.sessions.get_mut(&key).ok_or(CoreError::Crypto)?;
        let mut full_ad = session.ad.clone();
        full_ad.extend_from_slice(ad);
        let cipher = session.state.encrypt(plaintext, &full_ad)?;
        let stored = session.clone();
        self.save_session(&key, &stored).await?;
        let prekey = if cipher.header.pn == 0 && cipher.header.n == 0 {
            stored.prekey_header(bundle, &self.local_identity)
        } else {
            None
        };
        Ok((cipher, prekey))
    }

    pub async fn decrypt(
        &mut self,
        sender: &UserId,
        device: &DeviceId,
        packet: &PacketV2,
    ) -> Result<Vec<u8>, CoreError> {
        let key = SessionKey {
            user_id: sender.to_hex(),
            device_id: device.clone(),
        };

        if !self.sessions.contains_key(&key) {
            if let Some(session) = self.load_session(&key).await? {
                self.sessions.insert(key.clone(), session);
            }
        }

        if !self.sessions.contains_key(&key) {
            let prekey = packet.prekey.as_ref().ok_or(CoreError::Crypto)?;
            let session = self.bootstrap_responder(prekey)?;
            self.sessions.insert(key.clone(), session);
        }

        let session = self.sessions.get_mut(&key).ok_or(CoreError::Crypto)?;
        let mut full_ad = session.ad.clone();
        full_ad.extend_from_slice(&packet.associated_data);
        let attempts = vec![full_ad, packet.associated_data.clone()];
        for ad in attempts.into_iter() {
            let cipher = MessageCiphertext {
                header: RatchetHeader {
                    dh_pub: packet.header.dh_pub,
                    pn: packet.header.pn,
                    n: packet.header.n,
                },
                ciphertext: packet.ciphertext.clone(),
                associated_data: ad.clone(),
            };
            let mut state = session.state.clone();
            if let Ok(plaintext) = state.decrypt(&cipher) {
                session.state = state;
                let stored = session.clone();
                self.save_session(&key, &stored).await?;
                return Ok(plaintext);
            }
        }
        Err(CoreError::Crypto)
    }

    fn bootstrap_initiator(&self, bundle: &IdentityBundleV2) -> Result<DrSession, CoreError> {
        let local_keys = self.identity_keypair()?;
        let spk_bytes: [u8; 64] = bundle
            .signed_prekey_sig
            .clone()
            .try_into()
            .map_err(|_| CoreError::Crypto)?;
        let spk_sig = Signature::from_bytes(&spk_bytes);
        let bundle_public = PreKeyBundlePublic {
            version: 2,
            device_id: DeviceId::new(bundle.device_id),
            identity_dh: bundle.identity_dh_pub,
            identity_signing: bundle.identity_sig_pub,
            signed_prekey: bundle.signed_prekey_pub,
            signed_prekey_signature: spk_sig.to_bytes(),
            one_time_prekey: None,
            signed_prekey_id: bundle.signed_prekey_id,
        };
        let eph_secret = StaticSecret::random_from_rng(OsRng);
        let eph_public = X25519Public::from(&eph_secret).to_bytes();
        let eph = EphemeralKeyPair {
            private: eph_secret,
            public: eph_public,
        };
        let X3dhOutput {
            root_key,
            associated_data,
        } = x3dh_initiator(&local_keys, &eph, &bundle_public).map_err(|_| CoreError::Crypto)?;
        let state = RatchetState::new_initiator(root_key, eph.private, bundle.signed_prekey_pub);
        Ok(DrSession {
            state,
            ad: associated_data,
        })
    }

    fn bootstrap_responder(&self, header: &PrekeyHeader) -> Result<DrSession, CoreError> {
        let local_keys = self.identity_keypair()?;
        let signed_prekey = self.signed_prekey_pair()?;
        let X3dhOutput {
            root_key,
            associated_data,
        } = x3dh_responder(
            &local_keys,
            &signed_prekey,
            None,
            header.sig_pub,
            header.ik_pub,
            header.ek_pub,
        )
        .map_err(|_| CoreError::Crypto)?;
        let state = RatchetState::new_responder(root_key, signed_prekey.private, header.ek_pub);
        Ok(DrSession {
            state,
            ad: associated_data,
        })
    }

    async fn load_session(&self, key: &SessionKey) -> Result<Option<DrSession>, CoreError> {
        let guard = self.store.lock().await;
        if let Some(bytes) = guard
            .get(&key.storage_key())
            .map_err(|_| CoreError::Storage)?
        {
            let state: DrSession =
                serde_json::from_slice(&bytes).map_err(|_| CoreError::Storage)?;
            return Ok(Some(state));
        }
        Ok(None)
    }

    async fn save_session(&self, key: &SessionKey, state: &DrSession) -> Result<(), CoreError> {
        let guard = self.store.lock().await;
        let bytes = serde_json::to_vec(state).map_err(|_| CoreError::Storage)?;
        guard
            .put(&key.storage_key(), &bytes)
            .map_err(|_| CoreError::Storage)
    }

    fn identity_keypair(&self) -> Result<IdentityKeyPair, CoreError> {
        let signing = self.local_identity.signing_key().ok_or(CoreError::Crypto)?;
        let dh = self
            .local_identity
            .identity_dh_private()
            .ok_or(CoreError::Crypto)?;
        let dh_public = X25519Public::from(&dh).to_bytes();
        Ok(IdentityKeyPair {
            dh_private: dh,
            dh_public,
            signing,
        })
    }

    fn signed_prekey_pair(&self) -> Result<SignedPreKeyPair, CoreError> {
        let private = self
            .local_identity
            .signed_prekey_private()
            .ok_or(CoreError::Crypto)?;
        let public = X25519Public::from(&private).to_bytes();
        let sig = self
            .local_identity
            .bundle
            .as_ref()
            .ok_or(CoreError::Crypto)?
            .signed_prekey_sig
            .clone();
        let sig_bytes: [u8; 64] = sig.try_into().map_err(|_| CoreError::Crypto)?;
        Ok(SignedPreKeyPair {
            id: self
                .local_identity
                .bundle
                .as_ref()
                .map(|b| b.signed_prekey_id)
                .unwrap_or(0),
            private,
            public,
            signature: Signature::from_bytes(&sig_bytes),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct SessionKey {
    user_id: String,
    device_id: DeviceId,
}

impl SessionKey {
    fn storage_key(&self) -> String {
        format!("sess:v2:{}:{}", self.user_id, self.device_id.as_uuid())
    }
}

impl DrSession {
    fn prekey_header(
        &self,
        bundle: &IdentityBundleV2,
        identity: &LocalIdentity,
    ) -> Option<PrekeyHeader> {
        let signing = identity.signing_key()?;
        let sig_pub = VerifyingKey::from(&signing).to_bytes();
        let dh_priv = identity.identity_dh_private()?;
        let ik_pub = X25519Public::from(&dh_priv).to_bytes();
        Some(PrekeyHeader {
            version: 2,
            spk_id: bundle.signed_prekey_id,
            ek_pub: self.state.dh_self(),
            ik_pub,
            sig_pub,
        })
    }
}
