use enigma_sfu::{ParticipantId, RoomId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CallRoomId(RoomId);

impl CallRoomId {
    pub fn new(room_id: RoomId) -> Self {
        Self(room_id)
    }

    pub fn as_room_id(&self) -> &RoomId {
        &self.0
    }

    pub fn into_room_id(self) -> RoomId {
        self.0
    }
}

impl From<RoomId> for CallRoomId {
    fn from(value: RoomId) -> Self {
        CallRoomId::new(value)
    }
}

impl From<CallRoomId> for RoomId {
    fn from(value: CallRoomId) -> Self {
        value.into_room_id()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CallRole {
    Publisher,
    Subscriber,
    #[default]
    Both,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SignalingRecord {
    pub offer_sdp: Option<String>,
    pub answer_sdp: Option<String>,
    pub ice_local: Vec<String>,
    pub ice_remote: Vec<String>,
    pub updated_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallParticipantState {
    pub participant_id: ParticipantId,
    pub role: CallRole,
    pub signaling: SignalingRecord,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallRoomState {
    pub room_id: CallRoomId,
    pub participants: HashMap<ParticipantId, CallParticipantState>,
    pub created_at_ms: u64,
}
