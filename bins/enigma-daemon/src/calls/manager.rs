use crate::calls::types::{
    CallParticipantState, CallRole, CallRoomId, CallRoomState, SignalingRecord,
};
use enigma_sfu::{ParticipantId, ParticipantMeta, RoomId, Sfu, SfuError};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IceDirection {
    Local,
    Remote,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallManagerError {
    RoomNotFound,
    ParticipantExists,
    ParticipantNotFound,
    StateUnavailable,
    SfuError(SfuError),
}

impl std::fmt::Display for CallManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallManagerError::RoomNotFound => write!(f, "room not found"),
            CallManagerError::ParticipantExists => write!(f, "participant exists"),
            CallManagerError::ParticipantNotFound => write!(f, "participant not found"),
            CallManagerError::StateUnavailable => write!(f, "state unavailable"),
            CallManagerError::SfuError(err) => write!(f, "{err}"),
        }
    }
}

pub type CallManagerResult<T> = Result<T, CallManagerError>;

#[derive(Clone)]
pub struct CallManager {
    rooms: Arc<RwLock<HashMap<RoomId, CallRoomState>>>,
}

impl CallManager {
    pub fn new() -> Self {
        Self {
            rooms: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    #[allow(dead_code)]
    pub fn ensure_room(&self, room_id: RoomId, now_ms: u64) -> CallManagerResult<CallRoomState> {
        let mut rooms = self
            .rooms
            .write()
            .map_err(|_| CallManagerError::StateUnavailable)?;
        let room = rooms
            .entry(room_id.clone())
            .or_insert_with(|| CallRoomState {
                room_id: CallRoomId::new(room_id.clone()),
                participants: HashMap::new(),
                created_at_ms: now_ms,
            });
        Ok(room.clone())
    }

    pub fn join_room(
        &self,
        sfu: &Arc<Sfu>,
        room_id: RoomId,
        participant_id: ParticipantId,
        display_name: Option<String>,
        role: CallRole,
        now_ms: u64,
    ) -> CallManagerResult<CallParticipantState> {
        let rooms_read = self
            .rooms
            .read()
            .map_err(|_| CallManagerError::StateUnavailable)?;
        if let Some(room) = rooms_read.get(&room_id) {
            if room.participants.contains_key(&participant_id) {
                return Err(CallManagerError::ParticipantExists);
            }
        }
        drop(rooms_read);
        let meta = ParticipantMeta {
            display_name,
            tags: HashMap::new(),
        };
        sfu.join(room_id.clone(), participant_id.clone(), meta, now_ms)
            .map_err(CallManagerError::SfuError)?;
        let mut rooms = self
            .rooms
            .write()
            .map_err(|_| CallManagerError::StateUnavailable)?;
        let room = rooms
            .entry(room_id.clone())
            .or_insert_with(|| CallRoomState {
                room_id: CallRoomId::new(room_id.clone()),
                participants: HashMap::new(),
                created_at_ms: now_ms,
            });
        if room.participants.contains_key(&participant_id) {
            return Err(CallManagerError::ParticipantExists);
        }
        let signaling = SignalingRecord {
            updated_at_ms: now_ms,
            ..SignalingRecord::default()
        };
        let state = CallParticipantState {
            participant_id: participant_id.clone(),
            role,
            signaling,
        };
        room.participants.insert(participant_id, state.clone());
        Ok(state)
    }

    pub fn leave_room(
        &self,
        sfu: &Arc<Sfu>,
        room_id: RoomId,
        participant_id: ParticipantId,
    ) -> CallManagerResult<()> {
        let mut rooms = self
            .rooms
            .write()
            .map_err(|_| CallManagerError::StateUnavailable)?;
        let room = rooms
            .get_mut(&room_id)
            .ok_or(CallManagerError::RoomNotFound)?;
        if !room.participants.contains_key(&participant_id) {
            return Err(CallManagerError::ParticipantNotFound);
        }
        sfu.leave(room_id.clone(), participant_id.clone())
            .map_err(CallManagerError::SfuError)?;
        room.participants.remove(&participant_id);
        if room.participants.is_empty() {
            rooms.remove(&room_id);
        }
        Ok(())
    }

    pub fn upsert_offer(
        &self,
        room_id: RoomId,
        participant_id: ParticipantId,
        sdp: String,
        now_ms: u64,
    ) -> CallManagerResult<SignalingRecord> {
        let mut rooms = self
            .rooms
            .write()
            .map_err(|_| CallManagerError::StateUnavailable)?;
        let room = rooms
            .get_mut(&room_id)
            .ok_or(CallManagerError::RoomNotFound)?;
        let participant = room
            .participants
            .get_mut(&participant_id)
            .ok_or(CallManagerError::ParticipantNotFound)?;
        participant.signaling.offer_sdp = Some(sdp);
        participant.signaling.updated_at_ms = now_ms;
        Ok(participant.signaling.clone())
    }

    pub fn upsert_answer(
        &self,
        room_id: RoomId,
        participant_id: ParticipantId,
        sdp: String,
        now_ms: u64,
    ) -> CallManagerResult<SignalingRecord> {
        let mut rooms = self
            .rooms
            .write()
            .map_err(|_| CallManagerError::StateUnavailable)?;
        let room = rooms
            .get_mut(&room_id)
            .ok_or(CallManagerError::RoomNotFound)?;
        let participant = room
            .participants
            .get_mut(&participant_id)
            .ok_or(CallManagerError::ParticipantNotFound)?;
        participant.signaling.answer_sdp = Some(sdp);
        participant.signaling.updated_at_ms = now_ms;
        Ok(participant.signaling.clone())
    }

    pub fn add_ice(
        &self,
        room_id: RoomId,
        participant_id: ParticipantId,
        candidate: String,
        direction: IceDirection,
        now_ms: u64,
    ) -> CallManagerResult<SignalingRecord> {
        let mut rooms = self
            .rooms
            .write()
            .map_err(|_| CallManagerError::StateUnavailable)?;
        let room = rooms
            .get_mut(&room_id)
            .ok_or(CallManagerError::RoomNotFound)?;
        let participant = room
            .participants
            .get_mut(&participant_id)
            .ok_or(CallManagerError::ParticipantNotFound)?;
        match direction {
            IceDirection::Local => participant.signaling.ice_local.push(candidate),
            IceDirection::Remote => participant.signaling.ice_remote.push(candidate),
        }
        participant.signaling.updated_at_ms = now_ms;
        Ok(participant.signaling.clone())
    }

    pub fn get_signaling(
        &self,
        room_id: RoomId,
        participant_id: ParticipantId,
    ) -> CallManagerResult<SignalingRecord> {
        let rooms = self
            .rooms
            .read()
            .map_err(|_| CallManagerError::StateUnavailable)?;
        let room = rooms.get(&room_id).ok_or(CallManagerError::RoomNotFound)?;
        let participant = room
            .participants
            .get(&participant_id)
            .ok_or(CallManagerError::ParticipantNotFound)?;
        Ok(participant.signaling.clone())
    }

    pub fn room_state(&self, room_id: RoomId) -> CallManagerResult<CallRoomState> {
        let rooms = self
            .rooms
            .read()
            .map_err(|_| CallManagerError::StateUnavailable)?;
        let room = rooms.get(&room_id).ok_or(CallManagerError::RoomNotFound)?;
        Ok(room.clone())
    }
}
