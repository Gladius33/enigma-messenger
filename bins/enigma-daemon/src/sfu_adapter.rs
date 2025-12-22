use enigma_sfu::{ParticipantId, RoomId, SfuTransportAdapter, TrackId, TrackKind};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct DaemonSfuAdapter {
    publishers: Arc<Mutex<HashMap<RoomId, HashMap<TrackId, PublishedTrack>>>>,
    subscriptions: Arc<Mutex<HashMap<RoomId, HashMap<ParticipantId, HashSet<TrackId>>>>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishedTrack {
    pub publisher: ParticipantId,
    pub kind: TrackKind,
}

impl DaemonSfuAdapter {
    pub fn new() -> Self {
        Self {
            publishers: Arc::new(Mutex::new(HashMap::new())),
            subscriptions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn publisher_count(&self, room_id: &RoomId, participant_id: &ParticipantId) -> usize {
        if let Ok(locked) = self.publishers.lock() {
            if let Some(room) = locked.get(room_id) {
                return room
                    .values()
                    .filter(|track| &track.publisher == participant_id)
                    .count();
            }
        }
        0
    }

    pub fn subscription_count(&self, room_id: &RoomId, participant_id: &ParticipantId) -> usize {
        if let Ok(locked) = self.subscriptions.lock() {
            if let Some(room) = locked.get(room_id) {
                if let Some(list) = room.get(participant_id) {
                    return list.len();
                }
            }
        }
        0
    }
}

impl Default for DaemonSfuAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl SfuTransportAdapter for DaemonSfuAdapter {
    fn on_track_published(&self, room_id: &RoomId, track: &enigma_sfu::state::TrackState) {
        if let Ok(mut locked) = self.publishers.lock() {
            let room = locked.entry(room_id.clone()).or_insert_with(HashMap::new);
            room.insert(
                track.track_id.clone(),
                PublishedTrack {
                    publisher: track.publisher.clone(),
                    kind: track.kind,
                },
            );
        }
    }

    fn on_track_unpublished(&self, room_id: &RoomId, track_id: &TrackId) {
        if let Ok(mut locked) = self.publishers.lock() {
            if let Some(room) = locked.get_mut(room_id) {
                room.remove(track_id);
            }
        }
        if let Ok(mut locked) = self.subscriptions.lock() {
            if let Some(room) = locked.get_mut(room_id) {
                for (_, set) in room.iter_mut() {
                    set.remove(track_id);
                }
            }
        }
    }

    fn on_subscribe(&self, room_id: &RoomId, participant_id: &ParticipantId, track_id: &TrackId) {
        if let Ok(mut locked) = self.subscriptions.lock() {
            let room = locked.entry(room_id.clone()).or_insert_with(HashMap::new);
            let set = room
                .entry(participant_id.clone())
                .or_insert_with(HashSet::new);
            set.insert(track_id.clone());
        }
    }

    fn on_unsubscribe(&self, room_id: &RoomId, participant_id: &ParticipantId, track_id: &TrackId) {
        if let Ok(mut locked) = self.subscriptions.lock() {
            if let Some(room) = locked.get_mut(room_id) {
                if let Some(set) = room.get_mut(participant_id) {
                    set.remove(track_id);
                }
            }
        }
    }
}
