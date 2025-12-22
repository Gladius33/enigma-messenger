#![cfg(feature = "sender-keys")]

use crate::error::CoreError;
use crate::ids::DeviceId;
use crate::time::now_ms;
use blake3::Hasher;
use enigma_storage::EncryptedStore;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SenderKeyId(pub u32);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupEpoch(pub u32);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SenderKeyState {
    pub group_id: String,
    pub sender_user_id: String,
    pub sender_key_id: u32,
    pub epoch: GroupEpoch,
    pub chain_key: [u8; 32],
    pub msg_index: u32,
    pub created_at_ms: u64,
    #[serde(default = "zero_fingerprint")]
    pub members_fingerprint: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistributionMessage {
    pub target_user_id: String,
    pub target_device_id: DeviceId,
    pub payload: Vec<u8>,
    pub sender_key_id: u32,
}

fn random_chain_key() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

fn zero_fingerprint() -> [u8; 32] {
    [0u8; 32]
}

pub fn membership_fingerprint(member_user_ids: &[String]) -> [u8; 32] {
    let mut ids = member_user_ids.to_vec();
    ids.sort();
    let mut hasher = Hasher::new();
    for (idx, id) in ids.iter().enumerate() {
        if idx > 0 {
            hasher.update(&[0]);
        }
        hasher.update(id.as_bytes());
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_bytes());
    out
}

fn state_key(group_id: &str, sender: &str) -> String {
    format!("gsk:state:{}:{}", group_id, sender)
}

fn dist_key(
    group_id: &str,
    sender: &str,
    target_user: &str,
    target_device: &DeviceId,
    sender_key_id: u32,
) -> String {
    format!(
        "gsk:dist:{}:{}:{}:{}:{}",
        group_id,
        sender,
        target_user,
        target_device.as_uuid(),
        sender_key_id
    )
}

pub async fn load_or_create_sender_state(
    store: Arc<Mutex<EncryptedStore>>,
    group_id: &str,
    sender_user_id: &str,
    now: u64,
    members_fingerprint: [u8; 32],
) -> Result<SenderKeyState, CoreError> {
    if let Some(state) = load_state(store.clone(), group_id, sender_user_id).await? {
        return Ok(state);
    }
    let state = SenderKeyState {
        group_id: group_id.to_string(),
        sender_user_id: sender_user_id.to_string(),
        sender_key_id: 1,
        epoch: GroupEpoch(1),
        chain_key: random_chain_key(),
        msg_index: 0,
        created_at_ms: now,
        members_fingerprint,
    };
    save_state(store, &state).await?;
    Ok(state)
}

pub async fn rotate_sender_state(
    store: Arc<Mutex<EncryptedStore>>,
    state: &SenderKeyState,
    now: u64,
    members_fingerprint: [u8; 32],
) -> Result<SenderKeyState, CoreError> {
    let rotated = SenderKeyState {
        group_id: state.group_id.clone(),
        sender_user_id: state.sender_user_id.clone(),
        sender_key_id: state.sender_key_id.saturating_add(1),
        epoch: GroupEpoch(state.epoch.0.saturating_add(1)),
        chain_key: random_chain_key(),
        msg_index: 0,
        created_at_ms: now,
        members_fingerprint,
    };
    save_state(store, &rotated).await?;
    Ok(rotated)
}

pub async fn save_state(
    store: Arc<Mutex<EncryptedStore>>,
    state: &SenderKeyState,
) -> Result<(), CoreError> {
    let key = state_key(&state.group_id, &state.sender_user_id);
    let bytes = serde_json::to_vec(state).map_err(|_| CoreError::Storage)?;
    let guard = store.lock().await;
    guard.put(&key, &bytes).map_err(|_| CoreError::Storage)
}

pub async fn load_state(
    store: Arc<Mutex<EncryptedStore>>,
    group_id: &str,
    sender_user_id: &str,
) -> Result<Option<SenderKeyState>, CoreError> {
    let key = state_key(group_id, sender_user_id);
    let guard = store.lock().await;
    if let Some(bytes) = guard.get(&key).map_err(|_| CoreError::Storage)? {
        let state: SenderKeyState = serde_json::from_slice(&bytes).map_err(|_| CoreError::Storage)?;
        return Ok(Some(state));
    }
    Ok(None)
}

pub async fn store_distribution_marker(
    store: Arc<Mutex<EncryptedStore>>,
    group_id: &str,
    sender_user_id: &str,
    target_user_id: &str,
    target_device_id: &DeviceId,
    sender_key_id: u32,
) -> Result<(), CoreError> {
    let key = dist_key(
        group_id,
        sender_user_id,
        target_user_id,
        target_device_id,
        sender_key_id,
    );
    let guard = store.lock().await;
    guard.put(&key, &[]).map_err(|_| CoreError::Storage)
}

pub async fn distribution_sent(
    store: Arc<Mutex<EncryptedStore>>,
    group_id: &str,
    sender_user_id: &str,
    target_user_id: &str,
    target_device_id: &DeviceId,
    sender_key_id: u32,
) -> Result<bool, CoreError> {
    let key = dist_key(
        group_id,
        sender_user_id,
        target_user_id,
        target_device_id,
        sender_key_id,
    );
    let guard = store.lock().await;
    Ok(guard.get(&key).map_err(|_| CoreError::Storage)?.is_some())
}

fn kdf(chain_key: &[u8; 32], msg_index: u32) -> ([u8; 32], [u8; 32]) {
    let mut hasher = Hasher::new();
    hasher.update(chain_key);
    hasher.update(&msg_index.to_be_bytes());
    let derived = hasher.finalize();
    let mut next = [0u8; 32];
    let mut msg = [0u8; 32];
    next.copy_from_slice(derived.as_bytes());
    msg.copy_from_slice(derived.as_bytes());
    (next, msg)
}

fn nonce(sender_key_id: u32, epoch: u32, msg_index: u32) -> [u8; 24] {
    let mut hasher = Hasher::new();
    hasher.update(&sender_key_id.to_be_bytes());
    hasher.update(&epoch.to_be_bytes());
    hasher.update(&msg_index.to_be_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 24];
    out.copy_from_slice(&digest.as_bytes()[..24]);
    out
}

fn ad(
    group_id: &str,
    sender_user_id: &str,
    sender_key_id: u32,
    epoch: GroupEpoch,
    msg_index: u32,
) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(group_id.as_bytes());
    data.push(0);
    data.extend_from_slice(sender_user_id.as_bytes());
    data.push(0);
    data.extend_from_slice(&sender_key_id.to_be_bytes());
    data.extend_from_slice(&epoch.0.to_be_bytes());
    data.extend_from_slice(&msg_index.to_be_bytes());
    data
}

pub fn build_distribution_payload(state: &SenderKeyState) -> Vec<u8> {
    serde_json::to_vec(&state.clone()).unwrap_or_default()
}

pub fn parse_distribution_payload(bytes: &[u8]) -> Result<SenderKeyState, CoreError> {
    let mut state: SenderKeyState = serde_json::from_slice(bytes).map_err(|_| CoreError::Storage)?;
    state.msg_index = 0;
    state.created_at_ms = now_ms();
    Ok(state)
}

pub fn encrypt_group_message(
    state: &SenderKeyState,
    plaintext: &[u8],
) -> Result<(SenderKeyState, u32, Vec<u8>, Vec<u8>), CoreError> {
    let (next_chain, msg_key) = kdf(&state.chain_key, state.msg_index);
    let ad_bytes = ad(
        &state.group_id,
        &state.sender_user_id,
        state.sender_key_id,
        state.epoch.clone(),
        state.msg_index,
    );
    let nonce_bytes = nonce(state.sender_key_id, state.epoch.0, state.msg_index);
    let aead = enigma_aead::AeadBox::new(msg_key);
    let ciphertext = aead
        .encrypt_with_nonce(plaintext, &ad_bytes, nonce_bytes)
        .map_err(|_| CoreError::Crypto)?;
    let mut updated = state.clone();
    updated.chain_key = next_chain;
    updated.msg_index = state.msg_index.saturating_add(1);
    Ok((updated, state.msg_index, ciphertext, ad_bytes))
}

pub fn decrypt_group_message(
    state: &SenderKeyState,
    sender_key_id: u32,
    msg_index: u32,
    ciphertext: &[u8],
    ad_bytes: &[u8],
) -> Result<(SenderKeyState, Vec<u8>), CoreError> {
    if state.sender_key_id != sender_key_id {
        return Err(CoreError::Crypto);
    }
    let (next_chain, msg_key) = kdf(&state.chain_key, msg_index);
    let aead = enigma_aead::AeadBox::new(msg_key);
    let plaintext = aead
        .decrypt(ciphertext, ad_bytes)
        .map_err(|_| CoreError::Crypto)?;
    let mut updated = state.clone();
    updated.chain_key = next_chain;
    updated.msg_index = msg_index.saturating_add(1);
    Ok((updated, plaintext))
}

fn pending_index_key(group_id: &str, sender: &str, sender_key_id: u32) -> String {
    format!("gsk:pending:index:{}:{}:{}", group_id, sender, sender_key_id)
}

fn pending_item_key(
    group_id: &str,
    sender: &str,
    sender_key_id: u32,
    msg_index: u32,
) -> String {
    format!(
        "gsk:pending:{}:{}:{}:{}",
        group_id, sender, sender_key_id, msg_index
    )
}

pub async fn store_pending_message(
    store: Arc<Mutex<EncryptedStore>>,
    group_id: &str,
    sender: &str,
    sender_key_id: u32,
    msg_index: u32,
    bytes: &[u8],
) -> Result<(), CoreError> {
    let guard = store.lock().await;
    let mut index: HashSet<u32> = if let Some(data) = guard
        .get(&pending_index_key(group_id, sender, sender_key_id))
        .map_err(|_| CoreError::Storage)?
    {
        serde_json::from_slice(&data).map_err(|_| CoreError::Storage)?
    } else {
        HashSet::new()
    };
    index.insert(msg_index);
    let idx_bytes = serde_json::to_vec(&index).map_err(|_| CoreError::Storage)?;
    guard
        .put(
            &pending_index_key(group_id, sender, sender_key_id),
            &idx_bytes,
        )
        .map_err(|_| CoreError::Storage)?;
    guard
        .put(
            &pending_item_key(group_id, sender, sender_key_id, msg_index),
            bytes,
        )
        .map_err(|_| CoreError::Storage)
}

pub async fn take_pending_messages(
    store: Arc<Mutex<EncryptedStore>>,
    group_id: &str,
    sender: &str,
    sender_key_id: u32,
) -> Result<Vec<(u32, Vec<u8>)>, CoreError> {
    let guard = store.lock().await;
    let idx_key = pending_index_key(group_id, sender, sender_key_id);
    let Some(bytes) = guard.get(&idx_key).map_err(|_| CoreError::Storage)? else {
        return Ok(Vec::new());
    };
    let mut index: HashSet<u32> = serde_json::from_slice(&bytes).map_err(|_| CoreError::Storage)?;
    let mut pending = Vec::new();
    let mut removed = Vec::new();
    for msg_index in index.iter() {
        let key = pending_item_key(group_id, sender, sender_key_id, *msg_index);
        if let Some(data) = guard.get(&key).map_err(|_| CoreError::Storage)? {
            pending.push((*msg_index, data));
            removed.push(key);
        }
    }
    for key in removed.iter() {
        let _ = guard.delete(key);
    }
    index.clear();
    let idx_bytes = serde_json::to_vec(&index).map_err(|_| CoreError::Storage)?;
    guard
        .put(&idx_key, &idx_bytes)
        .map_err(|_| CoreError::Storage)?;
    pending.sort_by_key(|(i, _)| *i);
    Ok(pending)
}
